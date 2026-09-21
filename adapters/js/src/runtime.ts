// Runtime shared by every host: options -> runtime, Request -> verdict,
// verdict -> headers or 403. Hosts (cloudflare.ts, frameworks.ts, aws.ts) only
// adapt their request shape and pick the stores. evaluate() itself is the
// core held to the golden vectors in core/golden/.

import * as core from "./core";
import { resolve as resolveRule, type RuleSpec } from "./rules";
import { shouldSample, buildSample, type Sample } from "./sampling";
import * as subjectMod from "./core/subject";
import { load as loadProvider, type Provider, type ProviderRequestInfo } from "./providers";
import { kvStore, memoryStore, durableStore, type KVLike, type DOStubLike } from "./cf/stores";
import { Adaptive } from "./cf/adaptive";
import type { Store } from "./core/breaker";

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
  /** Durable Object stub (or any Store) for breaker + adaptive timeout. Memory (per isolate) if absent. */
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
}

export interface Runtime {
  config: core.Config;
  rules: core.Rule[];
  provider: Provider;
  cache: Store;
  state: Store;
  subjectStore: Store;
  breaker: core.breaker.Breaker;
  adaptive: Adaptive;
  opts: Options;
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
  const state: Store = isStub(opts.state) ? durableStore(opts.state) : (opts.state as Store | undefined) ?? memoryStore(clock);
  const subjectStore: Store = isKV(opts.subjectStore) ? kvStore(opts.subjectStore, "jev:") : (opts.subjectStore as Store | undefined) ?? memoryStore(clock);
  const breaker = new core.breaker.Breaker(state, clock, config.breaker);
  const adaptive = new Adaptive(state, config.jev);
  return { config, rules, provider, cache, state, subjectStore, breaker, adaptive, opts };
}

const HEADER_NAMES = ["X-Jev-Verdict", "X-Jev-Score", "X-Jev-Source", "X-Jev-Reason", "X-Jev-Request-Id"];

async function readReq(request: Request, rt: Runtime): Promise<[core.Req, ProviderRequestInfo]> {
  const url = new URL(request.url);
  const headers: Record<string, string> = {};
  request.headers.forEach((v, k) => (headers[k] = v));
  const ipHeader = rt.opts.clientIpHeader ?? "cf-connecting-ip";
  const clientIp = request.headers.get(ipHeader) ?? (request.headers.get("x-forwarded-for") ?? "").split(",")[0].trim();
  let body: string | null = null;
  const maxBytes = Math.max(...rt.rules.map((r) => r.max_body_bytes ?? 65536));
  const len = Number(request.headers.get("content-length"));
  if (request.body && !(Number.isFinite(len) && len > maxBytes)) {
    body = await request.clone().text();
  }
  const req: core.Req = {
    method: request.method,
    path: url.pathname,
    headers,
    body: body ?? undefined,
    body_size: body !== null ? core.normalize.byteLength(body) : Number.isFinite(len) ? len : 0,
    client_ip: clientIp,
  };
  return [req, { method: request.method, path: url.pathname, headers: request.headers, body, clientIp }];
}

/** Subject context for this request, or undefined: hashed id, one history read, a sink that writes without being awaited. */
async function subjectCtx(rt: Runtime, request: Request, clientIp: string): Promise<subjectMod.SubjectCtx | undefined> {
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
      void (async () => {
        const h = subjectMod.append(await store.get(k), e, scfg.max_entries);
        await store.set(k, h, scfg.history_ttl ?? 3600);
      })().catch(() => {});
    },
  };
}

/** Evaluate one request. Returns the verdict and, when it must be returned as-is, a Response. */
export async function evaluate(request: Request, rt: Runtime): Promise<{ verdict: core.Verdict; response?: Response; requestId: string }> {
  const requestId = request.headers.get("cf-ray") ?? crypto.randomUUID();
  const [req, info] = await readReq(request, rt);
  const subject = await subjectCtx(rt, request, info.clientIp);
  if (subject?.id) info.subjectId = subject.id;
  const ctx: core.Ctx = {
    config: rt.config,
    rules: rt.rules,
    cache: rt.cache,
    breaker: rt.breaker,
    subject,
    clock: () => Date.now() / 1000,
    hash: core.normalize.djb2,
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
    console.error("jev-edge: evaluate error, failing open: " + (e instanceof Error ? e.message : String(e)));
    verdict = core.verdict.newVerdict({ verdict: core.verdict.ERROR, source: core.verdict.SRC_L2, reason: "adapter error" });
  }
  if (rt.opts.onVerdict) rt.opts.onVerdict(verdict, request);
  if (rt.opts.onSample && shouldSample(rt.config, verdict)) {
    try {
      rt.opts.onSample(buildSample(rt.config, verdict, req, rt.rules, requestId), request);
    } catch (e) {
      console.warn("jev-edge: onSample failed: " + (e instanceof Error ? e.message : String(e)));
    }
  }
  if (verdict.action === core.verdict.ACTION_BLOCK) {
    return {
      verdict, requestId,
      response: new Response(rt.config.policy.block_body ?? '{"error":"request rejected"}', {
        status: rt.config.policy.block_status ?? 403,
        headers: { "Content-Type": "application/json", ...core.verdict.headers(verdict), "X-Jev-Request-Id": requestId },
      }),
    };
  }
  return { verdict, requestId };
}

/** The request to forward upstream: original plus X-Jev-* headers (client-supplied ones stripped). */
export function withVerdictHeaders(request: Request, verdict: core.Verdict, requestId: string): Request {
  const headers = new Headers(request.headers);
  for (const h of HEADER_NAMES) headers.delete(h);
  for (const [k, v] of Object.entries(core.verdict.headers(verdict))) headers.set(k, v);
  headers.set("X-Jev-Request-Id", requestId);
  return new Request(request, { headers });
}

export function healthResponse(rt: Runtime): Response {
  return Response.json({
    ok: true, adapter: "cloudflare", core: core.VERSION,
    provider: rt.provider.name, model: rt.config.jev.model ?? null, mode: rt.config.policy.mode,
    endpoint: rt.config.jev.endpoint ?? null,
  });
}

/**
 * Generic handler: evaluate, then either return the block or call `next` with
 * the request carrying X-Jev-* headers. Works for any framework that gives
 * you a Request and a way to continue.
 */
export async function handle(request: Request, rt: Runtime, next: (req: Request) => Promise<Response>): Promise<Response> {
  const url = new URL(request.url);
  if (rt.opts.health !== false && url.pathname === "/_jev/health" && request.method === "GET") return healthResponse(rt);
  const { verdict, response, requestId } = await evaluate(request, rt);
  if (response) return response;
  return next(withVerdictHeaders(request, verdict, requestId));
}

