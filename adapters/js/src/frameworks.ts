// Framework middlewares on the same runtime: Next.js, Node (Express / Connect /
// Fastify raw), Hono. All V8 hosts, so the golden vectors already cover them;
// only the request shape and the stores differ (memory per process unless you
// pass a Store).
import { createRuntime, evaluate, withVerdictHeaders, healthResponse, type Options, type Runtime } from "./runtime";
import { headers as verdictHeaders, newVerdict, ERROR, SRC_ADAPTER, type Verdict } from "./core/verdict";

const HEADERS = ["x-jev-verdict", "x-jev-score", "x-jev-source", "x-jev-reason", "x-jev-request-id", "x-jev-subject"];

function runtimeOnce(opts: Options): () => Runtime {
  let rt: Runtime | undefined;
  return () => (rt ??= createRuntime(opts));
}

// ---------------------------------------------------------------------------
// Next.js
// ---------------------------------------------------------------------------

/** The subset of NextResponse this module needs; pass the real class in. */
export interface NextResponseLike {
  next(init?: { request?: { headers?: Headers } }): Response;
}

/** The subset of NextFetchEvent (middleware's second argument) this module needs. */
export interface NextFetchEventLike {
  waitUntil(p: Promise<unknown>): void;
}

/**
 * middleware.ts:
 *
 *   import { NextResponse } from "next/server";
 *   import { nextMiddleware } from "@jev-edge/js";
 *   export const middleware = nextMiddleware({ config: { ... } }, NextResponse);
 *   export const config = { matcher: ["/api/chat/:path*", "/v1/:path*"] };
 *
 * Allowed requests continue with X-Jev-* on the request headers (read them in
 * the route handler); blocked ones get the 403 from the middleware. Next
 * buffers the body for middleware, so `request.text()` works on the edge and
 * Node runtimes alike. Next passes a `NextFetchEvent` as the second
 * argument; its `waitUntil` keeps the subject write alive after the response.
 */
export function nextMiddleware(opts: Options, NextResponse: NextResponseLike) {
  const rt = runtimeOnce(opts);
  return async (request: Request, event?: NextFetchEventLike): Promise<Response> => {
    const r = rt();
    const url = new URL(request.url);
    if (r.opts.health !== false && url.pathname === "/_jev/health" && request.method === "GET") return healthResponse(r);
    // the event is a RequestCtx as is: evaluate calls event.waitUntil(p)
    const { verdict, response, requestId, subjectId } = await evaluate(request, r, event); // never throws: fails open
    if (response) return response;
    const forwarded = withVerdictHeaders(request, verdict, requestId, subjectId);
    return NextResponse.next({ request: { headers: forwarded.headers } });
  };
}

// ---------------------------------------------------------------------------
// Node (Express / Connect style)
// ---------------------------------------------------------------------------

export interface NodeRequestLike {
  method?: string;
  url?: string;
  headers: Record<string, string | string[] | undefined>;
  socket?: { remoteAddress?: string };
  /** set by express.json() / body-parser; used instead of the stream when present */
  body?: unknown;
  on(event: "data" | "end" | "error", cb: (arg?: any) => void): unknown;
  /** node:http IncomingMessage flags: when the stream is already finished (a
   *  previous middleware consumed it) there is nothing to read and waiting
   *  for "end" would hang forever. */
  readableEnded?: boolean;
  complete?: boolean;
  readable?: boolean;
  /** body-parser's flag: true once it has read and parsed the stream. */
  _body?: boolean;
}

export interface NodeResponseLike {
  statusCode: number;
  setHeader(name: string, value: string): unknown;
  end(body?: string): unknown;
}

function isEmptyObject(v: unknown): boolean {
  return typeof v === "object" && v !== null && !Buffer.isBuffer(v) && Object.keys(v).length === 0;
}

/** A parsed body back in the wire format its Content-Type names, so the
 *  extractor reads it the way it would read the raw body. */
function reencode(body: object, contentType: string): string {
  if (contentType.toLowerCase().includes("application/x-www-form-urlencoded")) {
    const p = new URLSearchParams();
    for (const [k, v] of Object.entries(body)) {
      for (const x of Array.isArray(v) ? v : [v]) {
        p.append(k, typeof x === "object" && x !== null ? JSON.stringify(x) : String(x));
      }
    }
    return p.toString();
  }
  return JSON.stringify(body);
}

/**
 * The request body as text plus its size in bytes. From `req.body` when a
 * parser actually read the stream (body-parser sets `req._body`; any parser
 * that left the stream ended counts too), re-encoded in the request's own
 * content type; otherwise the stream is read to completion and buffered
 * whole, because the app behind this middleware still needs it. Express 4's
 * json() sets `req.body = {}` for a body it does not parse without reading
 * it: that placeholder is not the body. A body over `max` is still buffered
 * and handed on as `req.body` unchanged; only the evaluation drops it (L1
 * passes it as "body too large"). Cap the size before this middleware (a
 * proxy limit, or a body parser with `limit`) if unbounded uploads can reach
 * this route. Returns [null, 0] when there is no body to read: no stream, or
 * a stream something else already consumed.
 */
async function readNodeBody(req: NodeRequestLike): Promise<[string | null, number]> {
  // `complete` is not "consumed": node sets it once the whole body has
  // arrived, often before anyone reads it. Only an ended stream is gone.
  const streamGone = typeof req.on !== "function" || req.readableEnded === true || req.readable === false;
  const parsed = req._body === true || streamGone;
  if (req.body !== undefined && req.body !== null && parsed) {
    if (typeof req.body === "string") return [req.body, Buffer.byteLength(req.body)];
    if (Buffer.isBuffer(req.body)) return [req.body.toString("utf8"), req.body.length];
    if (typeof req.body === "object") {
      const ct = req.headers["content-type"];
      const s = reencode(req.body, Array.isArray(ct) ? ct.join(", ") : ct ?? "");
      return [s, Buffer.byteLength(s)];
    }
  }
  if (streamGone) return [null, 0];
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (c: Buffer) => {
      size += c.length;
      chunks.push(c);
    });
    req.on("end", () => resolve([Buffer.concat(chunks).toString("utf8"), size]));
    req.on("error", reject);
  });
}

/**
 * app.use(nodeMiddleware({ config: { ... } }))
 *
 * Mount before the routes that carry natural language. If you use
 * express.json() first, the parsed body is re-serialised for evaluation; if
 * not, the stream is read here (whole, see readNodeBody) and re-exposed as
 * `req.body` (string) and `req.jev` (the verdict). X-Jev-* are set on
 * `req.headers` for the handlers; client-supplied ones are removed first.
 * Any error fails open with x-jev-verdict: error, x-jev-source: adapter.
 */
export function nodeMiddleware(opts: Options) {
  const rt = runtimeOnce(opts);
  return async (req: NodeRequestLike & { jev?: Verdict }, res: NodeResponseLike, next: (err?: unknown) => void): Promise<void> => {
    try {
      const r = rt();
      const max = Math.max(...r.rules.map((x) => x.max_body_bytes ?? 65536));
      const host = (req.headers.host as string) ?? "localhost";
      const url = new URL(req.url ?? "/", "http://" + host);
      const headers = new Headers();
      for (const [k, v] of Object.entries(req.headers)) {
        if (v === undefined) continue;
        headers.set(k, Array.isArray(v) ? v.join(", ") : v);
      }
      // Append the peer like any proxy does: with trusted_hops = 1 the client
      // IP is the socket's address, never a value the client wrote.
      if (req.socket?.remoteAddress) {
        const xff = headers.get("x-forwarded-for");
        headers.set("x-forwarded-for", xff ? xff + ", " + req.socket.remoteAddress : req.socket.remoteAddress);
      }
      const method = req.method ?? "GET";
      const [body, size] = method === "GET" || method === "HEAD" ? [null, 0] : await readNodeBody(req);
      if (body !== null && (req.body === undefined || (req._body !== true && isEmptyObject(req.body)))) req.body = body;
      // Over the limit the body stays on req.body for the app but is not
      // handed to the evaluation: Content-Length alone lets L1 pass it as
      // "body too large", the same fail-open as the other hosts.
      const tooLarge = body !== null && size > max;
      if (tooLarge) headers.set("content-length", String(size));
      const request = new Request(url.toString(), { method, headers, body: tooLarge ? undefined : body ?? undefined });
      if (r.opts.health !== false && url.pathname === "/_jev/health" && method === "GET") {
        const h = healthResponse(r);
        res.statusCode = 200;
        res.setHeader("Content-Type", "application/json");
        res.end(await h.text());
        return;
      }
      const { verdict, response, requestId, subjectId } = await evaluate(request, r);
      req.jev = verdict;
      if (response) {
        res.statusCode = response.status;
        response.headers.forEach((v, k) => res.setHeader(k, v));
        res.end(await response.text());
        return;
      }
      const forwarded = withVerdictHeaders(request, verdict, requestId, subjectId);
      for (const h of HEADERS) delete req.headers[h];
      forwarded.headers.forEach((v, k) => {
        if (k.startsWith("x-jev-")) req.headers[k] = v;
      });
      next();
    } catch (e) {
      console.error("jev-edge: middleware error, failing open: " + (e instanceof Error ? e.message : String(e)));
      for (const h of HEADERS) delete req.headers[h];
      const v = newVerdict({ verdict: ERROR, source: SRC_ADAPTER, reason: "adapter error" });
      for (const [k, val] of Object.entries(verdictHeaders(v))) req.headers[k.toLowerCase()] = val;
      req.jev = v;
      next();
    }
  };
}

// ---------------------------------------------------------------------------
// Hono (and any framework with a Request in the context)
// ---------------------------------------------------------------------------

export interface HonoContextLike {
  req: { raw: Request };
  set(key: string, value: unknown): void;
  header(name: string, value: string): void;
}

/**
 * app.use("/v1/*", honoMiddleware({ config: { ... } }))
 *
 * `c.get("jev")` is the verdict in handlers. The request handlers see is
 * `c.req.raw` with every client-supplied X-Jev-* removed and the verdict's
 * X-Jev-* set (Hono's `raw` is a plain property, so it is replaced in
 * place); the same X-Jev-* are set on the response. Blocked requests return
 * the 403 from the middleware; an adapter error fails open.
 */
export function honoMiddleware(opts: Options) {
  const rt = runtimeOnce(opts);
  return async (c: HonoContextLike, next: () => Promise<void>): Promise<Response | void> => {
    let verdict: Verdict;
    let forwarded: Request | undefined;
    try {
      const r = rt();
      const url = new URL(c.req.raw.url);
      if (r.opts.health !== false && url.pathname === "/_jev/health" && c.req.raw.method === "GET") return healthResponse(r);
      const ev = await evaluate(c.req.raw, r);
      verdict = ev.verdict;
      if (ev.response) {
        c.set("jev", verdict);
        return ev.response;
      }
      forwarded = withVerdictHeaders(c.req.raw, verdict, ev.requestId, ev.subjectId);
    } catch (e) {
      console.error("jev-edge: hono middleware error, failing open: " + (e instanceof Error ? e.message : String(e)));
      verdict = newVerdict({ verdict: ERROR, source: SRC_ADAPTER, reason: "adapter error" });
    }
    c.set("jev", verdict);
    if (forwarded) {
      try {
        c.req.raw = forwarded;
      } catch {
        /* a context with a read-only raw keeps the original request */
      }
    }
    const outHeaders: Record<string, string> = {};
    if (forwarded) forwarded.headers.forEach((v, k) => { if (k.startsWith("x-jev-")) outHeaders[k] = v; });
    else Object.assign(outHeaders, verdictHeaders(verdict));
    for (const [k, v] of Object.entries(outHeaders)) {
      try {
        c.header(k, v);
      } catch {
        /* response headers are best effort */
      }
    }
    await next();
  };
}
