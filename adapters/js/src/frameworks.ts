// Framework middlewares on the same runtime: Next.js, Node (Express / Connect /
// Fastify raw), Hono. All V8 hosts, so the golden vectors already cover them;
// only the request shape and the stores differ (memory per process unless you
// pass a Store).
import { createRuntime, evaluate, withVerdictHeaders, healthResponse, type Options, type Runtime } from "./runtime";
import type { Verdict } from "./core/verdict";

const HEADERS = ["x-jev-verdict", "x-jev-score", "x-jev-source", "x-jev-reason", "x-jev-request-id"];

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
 * Node runtimes alike.
 */
export function nextMiddleware(opts: Options, NextResponse: NextResponseLike) {
  const rt = runtimeOnce(opts);
  return async (request: Request): Promise<Response> => {
    const r = rt();
    const url = new URL(request.url);
    if (r.opts.health !== false && url.pathname === "/_jev/health" && request.method === "GET") return healthResponse(r);
    const { verdict, response, requestId } = await evaluate(request, r);
    if (response) return response;
    const forwarded = withVerdictHeaders(request, verdict, requestId);
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
}

export interface NodeResponseLike {
  statusCode: number;
  setHeader(name: string, value: string): unknown;
  end(body?: string): unknown;
}

async function readNodeBody(req: NodeRequestLike, max: number): Promise<string | null> {
  if (req.body !== undefined) {
    if (typeof req.body === "string") return req.body;
    if (Buffer.isBuffer(req.body)) return req.body.toString("utf8");
    if (typeof req.body === "object" && req.body !== null) return JSON.stringify(req.body);
  }
  if (!("on" in req)) return null;
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (c: Buffer) => {
      size += c.length;
      if (size <= max + 1) chunks.push(c);
    });
    req.on("end", () => resolve(size > max ? "x".repeat(max + 1) : Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

/**
 * app.use(nodeMiddleware({ config: { ... } }))
 *
 * Mount before the routes that carry natural language. If you use
 * express.json() first, the parsed body is re-serialised for evaluation; if
 * not, the stream is read here and re-exposed as `req.body` (string) and
 * `req.jev` (the verdict). X-Jev-* are set on `req.headers` for the handlers.
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
      if (!headers.has("x-forwarded-for") && req.socket?.remoteAddress) headers.set("x-forwarded-for", req.socket.remoteAddress);
      const method = req.method ?? "GET";
      const body = method === "GET" || method === "HEAD" ? null : await readNodeBody(req, max);
      if (body !== null && req.body === undefined) req.body = body;
      const request = new Request(url.toString(), { method, headers, body: body ?? undefined });
      if (r.opts.health !== false && url.pathname === "/_jev/health" && method === "GET") {
        const h = healthResponse(r);
        res.statusCode = 200;
        res.setHeader("Content-Type", "application/json");
        res.end(await h.text());
        return;
      }
      const { verdict, response, requestId } = await evaluate(request, r);
      req.jev = verdict;
      if (response) {
        res.statusCode = response.status;
        response.headers.forEach((v, k) => res.setHeader(k, v));
        res.end(await response.text());
        return;
      }
      const forwarded = withVerdictHeaders(request, verdict, requestId);
      for (const h of HEADERS) delete req.headers[h];
      forwarded.headers.forEach((v, k) => {
        if (k.startsWith("x-jev-")) req.headers[k] = v;
      });
      next();
    } catch (e) {
      console.error("jev-edge: middleware error, failing open: " + (e instanceof Error ? e.message : String(e)));
      req.headers["x-jev-verdict"] = "error";
      req.headers["x-jev-source"] = "adapter";
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
 * `c.get("jev")` is the verdict in handlers; X-Jev-* are also set on the
 * response so the client can see them if you want that. Blocked requests
 * return the 403 from the middleware.
 */
export function honoMiddleware(opts: Options) {
  const rt = runtimeOnce(opts);
  return async (c: HonoContextLike, next: () => Promise<void>): Promise<Response | void> => {
    const r = rt();
    const { verdict, response } = await evaluate(c.req.raw, r);
    c.set("jev", verdict);
    if (response) return response;
    await next();
  };
}
