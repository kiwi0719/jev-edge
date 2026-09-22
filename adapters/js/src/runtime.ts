// Runtime shared by every host: options -> runtime, Request -> verdict,
// verdict -> headers or 403. Hosts (cloudflare.ts, frameworks.ts, aws.ts) only
// adapt their request shape and pick the stores. evaluate() itself is the
// core held to the golden vectors in core/golden/.
//
// Fail-open contract, same as edge.lua access(): everything between "we have a
// Request" and "we have a verdict" runs under one try/catch; a throw anywhere
// (body read, subject store, judge, onVerdict, block response) passes the
// request with X-Jev-Verdict: error and X-Jev-Source: adapter, and is logged.

import * as core from "./core";
import { resolve as resolveRule, type RuleSpec } from "./rules";
import { shouldSample, buildSample, type Sample } from "./sampling";
import * as subjectMod from "./core/subject";
import { load as loadProvider, type Provider, type ProviderRequestInfo } from "./providers";
import { kvStore, memoryStore, durableStore, durableBreaker, durableAdaptive, type KVLike, type DOStubLike } from "./cf/stores";
import { Adaptive, type AdaptiveLike } from "./cf/adaptive";
import type { Store, BreakerLike } from "./core/breaker";

type DeepPartial<T> = { [K in keyof T]?: T[K] extends object ? DeepPartial<T[K]> : T[K] };

export interface Options {
  /** Same shape as the Lua config file: jev, rules, policy, cache, breaker. */
  config?: DeepPartial<core.Config> & { rules?: string[] };
  /** Rule sets by id, complete Rule objects, or `{ id, extends, watch_paths, deployment_context, ... }` (defaults to config.rules). */
  rules?: RuleSpec[];
  /** Overrides config.jev.provider with an instance. */
  provider?: Provider;
  /** KV namespace for the fingerprint / reputation cache. Memory (per isolate) if absent. */
  cache?: KVLike | Store;
  /** Durable Object stub (JevState) or any Store for breaker + adaptive timeout. Memory (per isolate) if absent.
   *  With a stub the breaker and adaptive read-modify-write run inside the Durable Object, one fetch per operation. */
  state?: DOStubLike | Store;
  /** Store for per-subject trajectories (KV or memory). Memory (per isolate) if absent. Only used with config.subject.enabled. */
  subjectStore?: KVLike | Store;
  /** Header carrying the client IP (Cloudflare sets cf-connecting-ip). */
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

/** Per-request host facilities. `waitUntil` (Workers, Pages) keeps the subject write alive after the response is sent. */
export interface RequestCtx {
  waitUntil?: (p: Promise<unknown>) => void;
}

function isKV(x: unknown): x is KVLike {
  return typeof x === "object" && x !== null && "put" in x && typeof (x as KVLike).put === "function";
}
function isStub(x: unknown): x is DOStubLike {
  return typeof x === "object" && x !== null && "fetch" in x && !("get" in x);
}

export function createRuntime(opts: Options): Runtime {
  const config = core.defaults.merge(core.defaults.config, opts.config ?? {});
  const [ok, err] = core.defaults.validate(config);
  if (!ok) throw new Error("jev-edge config: " + err);
  const rules = ((opts.rules ?? config.rules) as RuleSpec[]).map(resolveRule);
  const provider = opts.provider ?? loadProvider(config.jev.provider ?? "jev");
  const clock = () => Date.now() / 1000;
  const cache: Store = isKV(opts.cache) ? kvStore(opts.cache) : (opts.cache as Store | undefined) ?? memoryStore(clock);
  const subjectStore: Store = isKV(opts.subjectStore) ? kvStore(opts.subjectStore, "jev:") : (opts.subjectStore as Store | undefined) ?? memoryStore(clock);
  let state: Store;
  let breaker: BreakerLike;
  let adaptive: AdaptiveLike;
  if (isStub(opts.state)) {
    // One hop per operation: the Durable Object runs the same Breaker and
    // Adaptive classes against its own storage, so the read-modify-write is
    // atomic there instead of three or four round trips from here.
    state = durableStore(opts.state);
    breaker = durableBreaker(opts.state, config.breaker);
    adaptive = durableAdaptive(opts.state, config.jev);
  } else {
    state = (opts.state as Store | undefined) ?? memoryStore(clock);
    breaker = new core.breaker.Breaker(state, clock, config.breaker);
    adaptive = new Adaptive(state, config.jev);
  }
  return { config, rules, provider, cache, state, subjectStore, breaker, adaptive, opts };
}

const HEADER_NAMES = ["X-Jev-Verdict", "X-Jev-Score", "X-Jev-Source", "X-Jev-Reason", "X-Jev-Request-Id"];
const SUBJECT_HEADER = "x-jev-subject";

/** Is the inbound X-Jev-Subject header the one this deployment consumes (hashed id from another jev-edge)? */
function consumesSubjectHeader(cfg: core.Config): boolean {
  const s = cfg.subject;
  return !!(s?.enabled && s.from === "header" && typeof s.name === "string" && s.name.toLowerCase() === SUBJECT_HEADER);
}

/** Does any rule watch this path and method? Decides whether the body is worth reading at all. */
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
    // malformed escapes: decode the valid ASCII ones, leave the rest
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

function isCandidate(rt: Runtime, path: string, method: string): boolean {
  const m = method.toUpperCase();
  return rt.rules.some((r) => core.rules.pathMatches(path, r.watch_paths) && (!r.methods || r.methods[m]));
}

/**
 * Read at most `maxBytes` of a body from a clone of the request. Returns the
 * text, or null when the body is larger than that: the clone's stream is
 * cancelled at maxBytes + 1 so a missing or lying Content-Length cannot make
 * the edge buffer an unbounded body. The original request is untouched.
 */
async function readBounded(request: Request, maxBytes: number): Promise<[string | null, number]> {
  const body = request.clone().body;
  if (!body) return ["", 0];
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maxBytes) {
        // Not awaited: the clone is one branch of a tee, and a tee branch's
        // cancel() only settles once the other branch (the request the app
        // will read) is cancelled as well.
        reader.cancel().catch(() => {});
        return [null, size];
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const all = new Uint8Array(size);
  let off = 0;
  for (const c of chunks) {
    all.set(c, off);
    off += c.byteLength;
  }
  return [new TextDecoder("utf-8", { fatal: false }).decode(all), size];
}

async function readReq(request: Request, rt: Runtime): Promise<[core.Req, ProviderRequestInfo]> {
  const url = new URL(request.url);
  const path = normalizePath(url.pathname);
  const headers: Record<string, string> = {};
  request.headers.forEach((v, k) => (headers[k] = v));
  // A client-supplied X-Jev-Subject is only meaningful when this deployment
  // is configured to consume it (from = "header", name = "x-jev-subject",
  // usually with hashed = true behind a thin Worker). Otherwise it is noise
  // that must not reach core, the provider or the upstream.
  if (!consumesSubjectHeader(rt.config)) delete headers[SUBJECT_HEADER];
  const ipHeader = rt.opts.clientIpHeader ?? "cf-connecting-ip";
  const clientIp = request.headers.get(ipHeader) ?? (request.headers.get("x-forwarded-for") ?? "").split(",")[0].trim();
  const maxBytes = Math.max(...rt.rules.map((r) => r.max_body_bytes ?? 65536));
  const lenHeader = request.headers.get("content-length");
  const len = lenHeader === null ? NaN : Number(lenHeader);
  let body: string | null = null;
  let size = Number.isFinite(len) ? len : 0;
  // The body is only read for a request some rule would judge; everything
  // else passes at L1 on path or method without touching the stream.
  if (request.body && isCandidate(rt, path, request.method) && !(Number.isFinite(len) && len > maxBytes)) {
    const [text, seen] = await readBounded(request, maxBytes);
    body = text;
    size = Math.max(size, seen);
  }
  const req: core.Req = {
    method: request.method,
    path,
    headers,
    body: body ?? undefined,
    body_size: body !== null ? core.normalize.byteLength(body) : size,
    client_ip: clientIp,
  };
  return [req, { method: request.method, path, headers: request.headers, body, clientIp }];
}

/** Subject context for this request, or undefined: hashed id, one history read, a sink that writes without being awaited. */
async function subjectCtx(rt: Runtime, request: Request, clientIp: string, rctx?: RequestCtx): Promise<subjectMod.SubjectCtx | undefined> {
  const scfg = rt.config.subject;
  if (!scfg?.enabled) return undefined;
  const raw = subjectMod.extract(scfg, {
    ip: clientIp,
    header: (n) => request.headers.get(n),
    cookie: (n) => subjectMod.cookieValue(request.headers.get("cookie"), n),
  });
  const id = await subjectMod.hashId(scfg, raw, subjectMod.sha256Hex);
  if (!id) return undefined;
  const store = rt.subjectStore;
  const k = subjectMod.key(id);
  return {
    id,
    history: await store.get(k),
    record: (e) => {
      const p = (async () => {
        const h = subjectMod.append(await store.get(k), e, scfg.max_entries);
        await store.set(k, h, scfg.history_ttl ?? 3600);
      })().catch(() => {});
      // On Workers the isolate may be torn down right after the response;
      // waitUntil keeps the write alive. Elsewhere it is plain fire-and-forget.
      if (rctx?.waitUntil) {
        try {
          rctx.waitUntil(p);
        } catch {
          /* a host that refuses the promise still gets the fire-and-forget write */
        }
      }
    },
  };
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
 * Evaluate one request. Never throws: any failure in the pipeline yields a
 * pass with verdict "error" and source "adapter" (see the header comment).
 */
export async function evaluate(request: Request, rt: Runtime, rctx?: RequestCtx): Promise<Evaluation> {
  let requestId: string;
  try {
    requestId = requestIdFor(request, rt);
  } catch {
    requestId = String(Date.now());
  }
  try {
    return await evaluateInner(request, rt, requestId, rctx);
  } catch (e) {
    console.error("jev-edge: adapter error, failing open: " + describe(e));
    return { verdict: errorVerdict(), requestId };
  }
}

async function evaluateInner(request: Request, rt: Runtime, requestId: string, rctx?: RequestCtx): Promise<Evaluation> {
  const [req, info] = await readReq(request, rt);
  const subject = await subjectCtx(rt, request, info.clientIp, rctx);
  if (subject?.id) info.subjectId = subject.id;
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
    json_decode: (s) => JSON.parse(s),
    re_find: core.rules.reFind,
    judge: {
      call: async (prompt) => {
        const timeoutMs = await rt.adaptive.current();
        const t0 = Date.now();
        const r = await rt.provider.call(prompt, rt.config.jev, timeoutMs, info);
        const elapsed = Date.now() - t0;
        if (r[0]) await rt.adaptive.success(elapsed);
        else if (String(r[1]).includes("timeout")) await rt.adaptive.timeout(timeoutMs);
        return r;
      },
    },
    log: (level, msg) => console[level === "error" ? "error" : "warn"](msg),
  };
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
    out.response = new Response(rt.config.policy.block_body ?? '{"error":"request rejected"}', {
      status: rt.config.policy.block_status ?? 403,
      headers: { "Content-Type": "application/json", ...core.verdict.headers(verdict), "X-Jev-Request-Id": requestId },
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
