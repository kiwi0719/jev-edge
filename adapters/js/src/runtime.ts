// Runtime shared by every host: options -> runtime, Request -> verdict,
// verdict -> headers or 403. Hosts (cloudflare.ts, frameworks.ts, aws.ts) only
// adapt their request shape and pick the stores. evaluate() itself is the
// core held to the golden vectors in core/golden/.
//
// Fail-open contract, same as edge.lua access(): everything between "we have a
// Request" and "we have a verdict" runs under one try/catch; a throw anywhere
// (body read, subject store, judge, onVerdict, block response) passes the
// request with X-Jev-Verdict: error and X-Jev-Source: adapter, and is logged.

import * as core from "./core/index.js";
import { decodeBody } from "./decode.js";
import { resolve as resolveRule, type RuleSpec } from "./rules/index.js";
import { shouldSample, buildSample, type Sample } from "./sampling.js";
import * as subjectMod from "./core/subject.js";
import { load as loadProvider, type Provider, type ProviderRequestInfo } from "./providers/index.js";
import {
  kvStore, memoryStore, durableStore, durableBreaker, durableAdaptive, isStateTarget, stateStub,
  type KVLike, type StateTarget,
} from "./cf/stores.js";
import { Adaptive, type AdaptiveLike } from "./cf/adaptive.js";
import type { Store, BreakerLike } from "./core/breaker.js";
import { bestEffortStore, bestEffortBreaker, bestEffortAdaptive } from "./besteffort.js";

type DeepPartial<T> = { [K in keyof T]?: T[K] extends object ? DeepPartial<T[K]> : T[K] };

export interface Options {
  /** Same shape as the Lua config file: jev, rules, policy, cache, breaker. */
  config?: DeepPartial<core.Config> & { rules?: string[] };
  /** Rule sets by id, complete Rule objects, or `{ id, extends, watch_paths, deployment_context, ... }` (defaults to config.rules). */
  rules?: RuleSpec[];
  /** Overrides config.jev.provider with an instance. */
  provider?: Provider;
  /** KV namespace for the fingerprint / reputation cache. Memory (per isolate) if absent. The JevState
   *  Durable Object (namespace, `{ namespace, name }` or stub, as for `state`) is taken too, as
   *  durableStore: one object for every lookup, and entries kept until overwritten. */
  cache?: KVLike | StateTarget | Store;
  /** Breaker + adaptive timeout state: the JevState Durable Object namespace (env.JEV_STATE), the namespace
   *  and an object name (`{ namespace: env.JEV_STATE, name: "staging" }`), a stub, or any Store. Memory (per
   *  isolate) if absent. With the Durable Object the breaker and adaptive read-modify-write run inside it,
   *  one fetch per operation.
   *  Pass the namespace: the runtime makes a stub per operation (`idFromName("jev-edge")`, or the name
   *  given), so it can be kept at module scope. workerd binds a stub to the request that created it; a
   *  runtime kept across requests with a stub logs that once per stub and isolate, and from then on keeps
   *  breaker and adaptive state in that isolate's memory, one operation at a time (cf/stores.ts). Anything
   *  with a `fetch` method is taken for a stub, idFromName + get without one for a namespace, and an object
   *  with a `namespace` key and no `get` for `{ namespace, name }`, so a Store must have no `fetch` and not
   *  both idFromName and get. */
  state?: StateTarget | Store;
  /** Store for per-subject trajectories: KV, the JevState Durable Object (namespace, `{ namespace, name }`
   *  or stub, as for `state`; its incr is atomic) or any Store. Memory (per isolate) if absent. Only used
   *  with config.subject.enabled. */
  subjectStore?: KVLike | StateTarget | Store;
  /** Header carrying the client IP, set by a proxy you trust to overwrite it.
   *  Default: cf-connecting-ip on Cloudflare (a preset, or a request with the
   *  platform's `cf` object), none elsewhere, where it is a client header.
   *  Without one the IP is X-Forwarded-For element `client_ip.trusted_hops`
   *  from the right, as on the OpenResty adapter. */
  clientIpHeader?: string;
  /** Called once per judged request with the verdict; wire to console.log or an analytics binding. */
  onVerdict?: (v: core.Verdict, req: Request) => void;
  /** Receives sampled decisions (normalized text, fingerprint, score, verdict) when config.sampling.enabled; storage is yours. */
  onSample?: (s: Sample, req: Request) => void;
  /** Serve GET /_jev/health from the Worker (default true). */
  health?: boolean;
  /** Set by the Cloudflare presets. Only then is `cf-ray` trusted as the request id; elsewhere it is a client header like any other. */
  platform?: "cloudflare";
}

export interface Runtime {
  config: core.Config;
  rules: core.Rule[];
  provider: Provider;
  cache: Store;
  state: Store;
  subjectStore: Store;
  breaker: BreakerLike;
  adaptive: AdaptiveLike;
  opts: Options;
}

/** Per-request host facilities. `waitUntil` (Workers, Pages) keeps the
 *  writes made once the verdict is decided (subject trajectory and
 *  reputation, verdict cache, breaker and adaptive bookkeeping) alive after
 *  the response is sent, so the response does not wait for them. */
export interface RequestCtx {
  waitUntil?: (p: Promise<unknown>) => void;
}

/** Hand `p` to the host's waitUntil. false when there is none or it refused
 *  the promise: the caller then awaits it, or lets it run on its own. */
function keepAlive(rctx: RequestCtx | undefined, p: Promise<unknown>): boolean {
  if (!rctx?.waitUntil) return false;
  try {
    rctx.waitUntil(p);
    return true;
  } catch {
    return false;
  }
}

function isKV(x: unknown): x is KVLike {
  return typeof x === "object" && x !== null && "put" in x && typeof (x as KVLike).put === "function";
}

/**
 * The Store behind a cache or subjectStore option. The Durable Object is
 * tested first: a workerd stub answers every property name, `put` included,
 * and would pass for KV; a namespace has `get` and would pass for a Store,
 * and fail on every request.
 */
function storeOption(x: KVLike | StateTarget | Store | undefined, clock: () => number): Store {
  if (isStateTarget(x)) return durableStore(x);
  if (isKV(x)) return kvStore(x);
  return (x as Store | undefined) ?? memoryStore(clock);
}
export function createRuntime(opts: Options): Runtime {
  const config = core.defaults.merge(core.defaults.config, opts.config ?? {});
  const [ok, err] = core.defaults.validate(config);
  if (!ok) throw new Error("jev-edge config: " + err);
  const rules = ((opts.rules ?? config.rules) as RuleSpec[]).map(resolveRule);
  const provider = opts.provider ?? loadProvider(config.jev.provider ?? "jev");
  const clock = () => Date.now() / 1000;
  const cache = storeOption(opts.cache, clock);
  const subjectStore = storeOption(opts.subjectStore, clock);
  let state: Store;
  let breaker: BreakerLike;
  let adaptive: AdaptiveLike;
  if (isStateTarget(opts.state)) {
    // One hop per operation: the Durable Object runs the same Breaker and
    // Adaptive classes against its own storage, so the read-modify-write is
    // atomic there instead of three or four round trips from here. The stub
    // is made per call from a namespace (and name); a stub given as is is
    // guarded against use past its request (cf/stores.ts), one guard for all
    // three.
    const stub = stateStub(opts.state);
    state = durableStore(stub);
    breaker = durableBreaker(stub, config.breaker);
    adaptive = durableAdaptive(stub, config.jev);
  } else {
    state = (opts.state as Store | undefined) ?? memoryStore(clock);
    breaker = new core.breaker.Breaker(state, clock, config.breaker);
    adaptive = new Adaptive(state, config.jev);
  }
  return {
    config, rules, provider, state, opts,
    cache: bestEffortStore(cache, "cache"),
    subjectStore: bestEffortStore(subjectStore, "subject store"),
    breaker: bestEffortBreaker(breaker),
    adaptive: bestEffortAdaptive(adaptive),
  };
}

const HEADER_NAMES = ["X-Jev-Verdict", "X-Jev-Score", "X-Jev-Source", "X-Jev-Reason", "X-Jev-Request-Id"];
const SUBJECT_HEADER = "x-jev-subject";

/** Is the inbound X-Jev-Subject header the one this deployment consumes (hashed id from another jev-edge)? */
function consumesSubjectHeader(cfg: core.Config): boolean {
  const s = cfg.subject;
  return !!(s?.enabled && s.from === "header" && typeof s.name === "string" && s.name.toLowerCase() === SUBJECT_HEADER);
}

/**
 * Is this a path nginx would take? Every '%' must start a two-digit hex
 * escape and none may be %00: nginx answers anything else with 400 before
 * jev-edge runs. The runtime cannot tell what the origin makes of such a
 * path (cpp-httplib, under llama.cpp, reads the IIS-style %u0063 as 'c', so
 * /v1/%u0063ompletions is /v1/completions there), so evaluate() refuses it
 * with 400 as nginx does, never passes it unjudged. An escape of a byte
 * that is not UTF-8 (%FF, the overlong %C0%AE) is well formed: nginx takes
 * it, and normalizePath keeps it as sent.
 */
export function wellFormedPath(pathname: string): boolean {
  return !/%(?![0-9A-Fa-f]{2})|%00/.test(pathname);
}

/**
 * The path the origin will route on, the way nginx builds $uri: %XX decoded,
 * duplicate slashes collapsed, `.` / `..` resolved. Watch patterns anchored at
 * `^/v1/` must not miss `/v1/%63hat/completions` or `//v1/chat/completions`.
 */
export function normalizePath(pathname: string): string {
  let decoded: string;
  try {
    decoded = decodeURIComponent(pathname);
  } catch {
    // escapes that are not UTF-8 (or malformed ones, which evaluate()
    // refuses before this): decode the valid ASCII ones, leave the rest
    decoded = pathname.replace(/%([0-7][0-9a-fA-F])/g, (_, h: string) => String.fromCharCode(parseInt(h, 16)));
  }
  const out: string[] = [];
  for (const seg of decoded.split("/")) {
    if (seg === "" || seg === ".") continue;
    if (seg === "..") out.pop();
    else out.push(seg);
  }
  let p = "/" + out.join("/");
  if (decoded.endsWith("/") && p !== "/") p += "/";
  return p;
}

/** Does any rule watch this path and method? Decides whether the body is worth reading at all. */
function isCandidate(rt: Runtime, path: string, method: string): boolean {
  const m = method.toUpperCase();
  return rt.rules.some((r) => core.rules.pathMatches(path, r.watch_paths, r.paths_case_sensitive) && (!r.methods || r.methods[m]));
}

/** Requests an adapter built from a body it only had the start of
 *  (Lambda@Edge `bodyTruncated`): the body is a head, never the whole. */
const truncatedBodies = new WeakSet<Request>();
export function markTruncated(request: Request): Request {
  truncatedBodies.add(request);
  return request;
}

/** How far past max_body_bytes the stream is read looking for the tail. */
const SCAN_FACTOR = 4;

interface BodyRead { head: Uint8Array; tail: Uint8Array | null; size: number; complete: boolean }

/**
 * Read a clone of the request body: whole up to `maxBytes`; past it the
 * first `maxBytes` and a ring of the last TAIL_BYTES, reading on to at most
 * SCAN_FACTOR x maxBytes, so a missing or lying Content-Length cannot make
 * the edge buffer an unbounded body. `complete` is false when the read
 * stopped before the end (the tail is then the last bytes read, not the
 * body's). The original request is untouched.
 */
async function readBounded(request: Request, maxBytes: number): Promise<BodyRead> {
  const body = request.clone().body;
  if (!body) return { head: new Uint8Array(0), tail: null, size: 0, complete: true };
  const reader = body.getReader();
  const headChunks: Uint8Array[] = [];
  let headLen = 0;
  const TAIL = core.rules.TAIL_BYTES;
  let ring = new Uint8Array(0);
  let size = 0;
  let complete = true;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      let v = value;
      if (headLen < maxBytes) {
        const take = Math.min(maxBytes - headLen, v.byteLength);
        headChunks.push(v.subarray(0, take));
        headLen += take;
        v = v.subarray(take);
      }
      if (v.byteLength > 0) {
        const joined = new Uint8Array(Math.min(TAIL, ring.byteLength + v.byteLength));
        const fromV = Math.min(v.byteLength, joined.byteLength);
        const fromRing = joined.byteLength - fromV;
        joined.set(ring.subarray(ring.byteLength - fromRing), 0);
        joined.set(v.subarray(v.byteLength - fromV), fromRing);
        ring = joined;
      }
      if (size > maxBytes * SCAN_FACTOR) {
        // Not awaited: the clone is one branch of a tee, and a tee branch's
        // cancel() only settles once the other branch (the request the app
        // will read) is cancelled as well.
        reader.cancel().catch(() => {});
        complete = false;
        break;
      }
    }
  } finally {
    reader.releaseLock();
  }
  const head = new Uint8Array(headLen);
  let off = 0;
  for (const c of headChunks) {
    head.set(c, off);
    off += c.byteLength;
  }
  return { head, tail: ring.byteLength > 0 ? ring : null, size, complete };
}

const utf8 = new TextDecoder("utf-8", { fatal: false });

/** The request as core sees it, what the provider may use of it, and
 *  whether a rule watches its path and method (isCandidate). */
async function readReq(request: Request, rt: Runtime): Promise<[core.Req, ProviderRequestInfo, boolean]> {
  const url = new URL(request.url);
  const path = normalizePath(url.pathname);
  const headers: Record<string, string> = {};
  request.headers.forEach((v, k) => (headers[k] = v));
  // A client-supplied X-Jev-Subject is only meaningful when this deployment
  // is configured to consume it (from = "header", name = "x-jev-subject",
  // usually with hashed = true behind a thin Worker). Otherwise it is noise
  // that must not reach core, the provider or the upstream.
  if (!consumesSubjectHeader(rt.config)) delete headers[SUBJECT_HEADER];
  const clientIp = clientIpOf(request, rt);
  const maxBytes = Math.max(...rt.rules.map((r) => r.max_body_bytes ?? core.rules.MAX_BODY_BYTES));
  const lenHeader = request.headers.get("content-length");
  const len = lenHeader === null ? NaN : Number(lenHeader);
  const req: core.Req = { method: request.method, path, headers, client_ip: clientIp, body_size: Number.isFinite(len) ? len : 0 };
  let body: string | null = null;
  // the body's length in bytes as read (or decoded): TextDecoder turns each
  // invalid byte into U+FFFD, three bytes once re-encoded, so the decoded
  // string's UTF-8 length is not the body's size (Lua's #body is)
  let bodyBytes = 0;
  const candidate = isCandidate(rt, path, request.method);
  // The body is only read for a request some rule would judge; everything
  // else passes at L1 on path or method without touching the stream.
  if (request.body && candidate) {
    const r = await readBounded(request, maxBytes);
    const whole = r.complete && r.size <= maxBytes && !truncatedBodies.has(request);
    req.body_size = Math.max(req.body_size ?? 0, r.size, truncatedBodies.has(request) ? maxBytes + 1 : 0);
    const ce = core.rules.contentEncoding(headers);
    if (ce !== "") {
      // decode only a body read whole: a cut compressed stream is corrupt
      if (whole) {
        const d = await decodeBody(r.head, ce, maxBytes);
        if (d[0]) {
          req.decoded = true;
          if (d[1]) {
            req.body_head = utf8.decode(d[0].subarray(0, maxBytes));
            req.body_size = maxBytes + 1;
          } else {
            body = utf8.decode(d[0]);
            bodyBytes = d[0].byteLength;
          }
        }
      }
    } else if (whole) {
      body = utf8.decode(r.head);
      bodyBytes = r.head.byteLength;
    } else {
      req.body_head = utf8.decode(r.head);
      if (r.tail) req.body_tail = utf8.decode(r.tail);
    }
  }
  if (body !== null) {
    req.body = body;
    req.body_size = bodyBytes;
    req.body_bytes = bodyBytes;
  }
  return [req, { method: request.method, path, headers: request.headers, body, clientIp }, candidate];
}

let warnedLong = false;

/** Subject context for this request, or undefined: hashed id, the history
 *  (read only for a request a rule watches), a sink that writes without being
 *  awaited. */
async function subjectCtx(
  rt: Runtime, request: Request, clientIp: string, candidate: boolean, rctx?: RequestCtx,
): Promise<subjectMod.SubjectCtx | undefined> {
  const scfg = rt.config.subject;
  if (!scfg?.enabled) return undefined;
  // every candidate value (a cookie sent twice, quoted or not): reputation
  // checks and charges each id, the first one names the trajectory
  const raws = subjectMod.extractAll(scfg, {
    ip: clientIp,
    ipv6Prefix: rt.config.client_ip?.ipv6_prefix,
    header: (n) => request.headers.get(n),
    cookieHeader: request.headers.get("cookie"),
  }, (why) => {
    // once per isolate: a subject value past the limit names no trajectory
    if (warnedLong) return;
    warnedLong = true;
    console.warn(`jev-edge: ${why}, dropped (subject.from = ${scfg.from ?? "ip"})`);
  });
  const ids = await subjectMod.hashIds(scfg, raws, subjectMod.sha256Hex);
  const id = ids[0];
  if (!id) return undefined;
  const store = rt.subjectStore;
  // Core ignores the history in this version, and a request no rule watches
  // passes at L1 before it could look: only a candidate pays the read (one
  // counter get, then the slots at once). A read that fails is no history,
  // never an adapter error that fails the request open.
  let history: unknown;
  if (candidate) {
    try {
      history = await subjectMod.loadHistory(store, id, scfg.max_entries);
    } catch (e) {
      console.warn("jev-edge: subject history read failed: " + describe(e));
      history = null;
    }
  }
  return {
    id,
    ids,
    // ring layout (incr + one key per entry) when the store has incr, so
    // concurrent requests do not lose entries; the one-list layout otherwise
    history,
    // reputation counters (subject.reputation); atomic where the store has incr
    store,
    record: (e) => {
      const p = subjectMod.appendHistory(store, id, e, scfg.max_entries, scfg.history_ttl ?? 3600).catch(() => {});
      // On Workers the isolate may be torn down right after the response;
      // waitUntil keeps the write alive. Elsewhere (or refused) it is plain
      // fire-and-forget.
      keepAlive(rctx, p);
    },
  };
}

/**
 * The client address. A named header only when it is one the platform
 * overwrites (cf-connecting-ip on Cloudflare) or the operator configured;
 * otherwise X-Forwarded-For read from the right: proxies append, so the
 * leftmost value is whatever the client typed. Element `trusted_hops` from
 * the right (1 = last), as client_ip_from does on OpenResty.
 */
export function clientIpOf(request: Request, rt: Pick<Runtime, "opts" | "config">): string {
  const onCf = rt.opts.platform === "cloudflare" || "cf" in request;
  const ipHeader = rt.opts.clientIpHeader ?? (onCf ? "cf-connecting-ip" : undefined);
  const named = ipHeader ? request.headers.get(ipHeader)?.trim() : undefined;
  if (named) return named;
  const hops = (request.headers.get("x-forwarded-for") ?? "").split(",").map((s) => s.trim()).filter((s) => s !== "");
  const n = rt.config.client_ip?.trusted_hops ?? 1;
  return hops[hops.length - n] ?? "";
}

function requestIdFor(request: Request, rt: Runtime): string {
  // cf-ray is set by Cloudflare on its own edge and is a plain client header
  // anywhere else, so only a Cloudflare preset (or a request that carries the
  // platform's `cf` object) gets to use it.
  const onCf = rt.opts.platform === "cloudflare" || "cf" in request;
  const ray = onCf ? request.headers.get("cf-ray") : null;
  return ray && ray !== "" ? ray : crypto.randomUUID();
}

export interface Evaluation {
  verdict: core.Verdict;
  /** Present when the verdict must be returned as-is (a block). */
  response?: Response;
  requestId: string;
  /** Hashed subject id when config.subject produced one; forwarded upstream as X-Jev-Subject. */
  subjectId?: string;
}

function errorVerdict(): core.Verdict {
  return core.verdict.newVerdict({ verdict: core.verdict.ERROR, source: core.verdict.SRC_ADAPTER, reason: "adapter error" });
}

function describe(e: unknown): string {
  return e instanceof Error ? (e.stack ?? e.message) : String(e);
}

/**
 * A path that is not well formed (wellFormedPath): refused with 400 and the
 * block body, whatever policy.mode and policy.unjudgeable say, as nginx
 * answers it inline and the Envoy shim and HAProxy agent do. It is the
 * client's error, not a verdict, so it never fails open. The client sees
 * X-Jev-Verdict: skipped and the request id (clientHeaders); the log says
 * why.
 */
function badPath(rt: Runtime, requestId: string, pathname: string): Evaluation {
  console.warn("jev-edge: refusing malformed path " + JSON.stringify(pathname.slice(0, 256)) + " with 400");
  const verdict = core.verdict.newVerdict({
    action: core.verdict.ACTION_BLOCK, verdict: core.verdict.SKIPPED, source: core.verdict.SRC_ADAPTER, reason: "invalid path",
  });
  const response = new Response(rt.config.policy.block_body ?? '{"error":"request rejected"}', {
    status: 400,
    headers: { "Content-Type": "application/json", ...core.verdict.clientHeaders(verdict), "X-Jev-Request-Id": requestId },
  });
  return { verdict, response, requestId };
}

/**
 * Evaluate one request. Never throws: any failure in the pipeline yields a
 * pass with verdict "error" and source "adapter" (see the header comment).
 * A path that is not well formed is refused with 400 (badPath), never passed.
 */
export async function evaluate(request: Request, rt: Runtime, rctx?: RequestCtx): Promise<Evaluation> {
  let requestId: string;
  try {
    requestId = requestIdFor(request, rt);
  } catch {
    requestId = String(Date.now());
  }
  try {
    const pathname = new URL(request.url).pathname;
    if (!wellFormedPath(pathname)) return badPath(rt, requestId, pathname);
    return await evaluateInner(request, rt, requestId, rctx);
  } catch (e) {
    console.error("jev-edge: adapter error, failing open: " + describe(e));
    return { verdict: errorVerdict(), requestId };
  }
}

async function evaluateInner(request: Request, rt: Runtime, requestId: string, rctx?: RequestCtx): Promise<Evaluation> {
  const [req, info, candidate] = await readReq(request, rt);
  const subject = await subjectCtx(rt, request, info.clientIp, candidate, rctx);
  if (subject?.id) info.subjectId = subject.id;
  const judgeOnce = async (prompt: core.Prompt): Promise<core.JudgeResult> => {
    const timeoutMs = await rt.adaptive.current();
    const t0 = Date.now();
    const r = await rt.provider.call(prompt, rt.config.jev, timeoutMs, info);
    const elapsed = Date.now() - t0;
    if (r[0]) {
      // the sample only serves later requests: past the response where the host can keep it alive
      const p = rt.adaptive.success(elapsed).catch(() => {});
      if (!keepAlive(rctx, p)) await p;
    }
    else if (String(r[1]).includes("timeout")) await rt.adaptive.timeout(timeoutMs);
    return r;
  };
  const ctx: core.Ctx = {
    config: rt.config,
    rules: rt.rules,
    cache: rt.cache,
    breaker: rt.breaker,
    subject,
    clock: () => Date.now() / 1000,
    // sha256, not djb2: the fingerprint keys the verdict cache and the trust
    // store, and a linear hash lets a few appended bytes hit a chosen value.
    hash: core.sha256Hex,
    // JSON.parse, and NaN, Infinity and -Infinity as Python's json.loads
    // and cjson take them (normalize.jsonDecode)
    json_decode: core.normalize.jsonDecode,
    re_find: core.rules.reFind,
    judge: {
      call: judgeOnce,
      // chunks and other parts judged in parallel
      call_many: (prompts) => Promise.all(prompts.map((p) => judgeOnce(p))),
      // The backend provider asks the origin about the whole request: the
      // body when it was read whole, else every chunk and part in one text,
      // which the origin chunks itself. One call, and its answer is kept
      // under the whole request's key only, never a part's.
      whole: rt.provider.name === "backend",
    },
    log: (level, msg) => console[level === "error" ? "error" : "warn"](msg),
  };
  // the writes core makes once the verdict is decided go past the response
  // where the host keeps promises alive; awaited everywhere else
  if (rctx?.waitUntil) ctx.defer = (p) => rctx.waitUntil!(p);
  let verdict: core.Verdict;
  try {
    verdict = await core.evaluate(req, ctx);
  } catch (e) {
    console.error("jev-edge: evaluate error, failing open: " + describe(e));
    verdict = errorVerdict();
  }
  if (rt.opts.onVerdict) {
    try {
      rt.opts.onVerdict(verdict, request);
    } catch (e) {
      console.warn("jev-edge: onVerdict failed: " + describe(e));
    }
  }
  if (rt.opts.onSample && shouldSample(rt.config, verdict)) {
    try {
      rt.opts.onSample(buildSample(rt.config, verdict, req, rt.rules, requestId), request);
    } catch (e) {
      console.warn("jev-edge: onSample failed: " + describe(e));
    }
  }
  const out: Evaluation = { verdict, requestId, subjectId: subject?.id };
  if (verdict.action === core.verdict.ACTION_BLOCK) {
    // the client sees the verdict and the request id, never the score, the
    // reason or the source (core.verdict.clientHeaders): those go to logs
    out.response = new Response(rt.config.policy.block_body ?? '{"error":"request rejected"}', {
      status: rt.config.policy.block_status ?? 403,
      headers: { "Content-Type": "application/json", ...core.verdict.clientHeaders(verdict), "X-Jev-Request-Id": requestId },
    });
  }
  return out;
}

/**
 * The request to forward upstream: original plus X-Jev-* headers. Every
 * client-supplied X-Jev-* header is dropped, including X-Jev-Subject; when
 * this runtime computed a subject id it is forwarded as X-Jev-Subject so an
 * origin jev-edge configured with `hashed = true` sees the same trajectory.
 */
export function withVerdictHeaders(request: Request, verdict: core.Verdict, requestId: string, subjectId?: string): Request {
  const headers = new Headers(request.headers);
  for (const h of HEADER_NAMES) headers.delete(h);
  headers.delete(SUBJECT_HEADER);
  for (const [k, v] of Object.entries(core.verdict.headers(verdict))) headers.set(k, v);
  headers.set("X-Jev-Request-Id", requestId);
  if (subjectId) headers.set("X-Jev-Subject", subjectId);
  return new Request(request, { headers });
}

export function healthResponse(rt: Runtime): Response {
  return Response.json({
    ok: true, adapter: rt.opts.platform ?? "js", core: core.VERSION,
    provider: rt.provider.name, model: rt.config.jev.model ?? null, mode: rt.config.policy.mode,
    endpoint: rt.config.jev.endpoint ?? null,
  });
}

/**
 * Generic handler: evaluate, then either return the block or call `next` with
 * the request carrying X-Jev-* headers. Works for any framework that gives
 * you a Request and a way to continue. A throw anywhere before `next` fails
 * open: `next` is still called, with X-Jev-Verdict: error / X-Jev-Source: adapter.
 */
export async function handle(request: Request, rt: Runtime, next: (req: Request) => Promise<Response>, rctx?: RequestCtx): Promise<Response> {
  let forwarded: Request;
  try {
    const url = new URL(request.url);
    if (rt.opts.health !== false && url.pathname === "/_jev/health" && request.method === "GET") return healthResponse(rt);
    const { verdict, response, requestId, subjectId } = await evaluate(request, rt, rctx);
    if (response) return response;
    forwarded = withVerdictHeaders(request, verdict, requestId, subjectId);
  } catch (e) {
    console.error("jev-edge: handle error, failing open: " + describe(e));
    let rid = "";
    try {
      rid = crypto.randomUUID();
    } catch {
      rid = String(Date.now());
    }
    try {
      forwarded = withVerdictHeaders(request, errorVerdict(), rid);
    } catch {
      forwarded = request;
    }
  }
  return next(forwarded);
}
