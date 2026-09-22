// Lambda@Edge (CloudFront viewer-request or origin-request) on the same
// runtime. The one AWS entry point that sees the body: with "Include Body"
// on the trigger, CloudFront hands it over base64-encoded, truncated at 40 KB
// (viewer-request) or 1 MB (origin-request) with `bodyTruncated` set. A
// truncated body is passed at L1 as "body too large", the same fail-open the
// other adapters apply, and the full body still reaches the origin.
//
//   import { lambdaEdgeHandler } from "@jev-edge/js/aws";
//   export const handler = lambdaEdgeHandler({ config: { ... } });
//
// Lambda@Edge has no environment variables, no VPC and no KV: the cache,
// breaker and adaptive timeout are per execution environment (memory) unless
// you pass Store implementations (DynamoDB Global Tables is the usual
// choice; it costs a round trip per lookup). Read the API key from Secrets
// Manager at cold start and pass it in `config.jev.api_key`.
import { createRuntime, evaluate, type Options, type Runtime } from "./runtime";
import { headers as verdictHeaders, newVerdict, ERROR, SRC_ADAPTER } from "./core/verdict";

export interface CfHeader { key?: string; value: string }
export interface CfRequest {
  method: string;
  uri: string;
  querystring?: string;
  clientIp: string;
  headers: Record<string, CfHeader[]>;
  body?: { inputTruncated?: boolean; bodyTruncated?: boolean; action?: string; encoding: "base64" | "text"; data: string };
}
export interface CfEvent { Records: { cf: { config?: { eventType?: string }; request: CfRequest } }[] }
export interface CfResponse {
  status: string;
  statusDescription?: string;
  headers?: Record<string, CfHeader[]>;
  body?: string;
}

const HEADER_NAMES = ["x-jev-verdict", "x-jev-score", "x-jev-source", "x-jev-reason", "x-jev-request-id", "x-jev-subject"];

function toRequest(cf: CfRequest, maxBytes: number): Request {
  const headers = new Headers();
  for (const [name, values] of Object.entries(cf.headers ?? {})) {
    for (const v of values) headers.append(values[0]?.key ?? name, v.value);
  }
  for (const h of HEADER_NAMES) headers.delete(h);
  headers.set("x-forwarded-for", cf.clientIp);
  const host = headers.get("host") ?? "edge.local";
  const url = "https://" + host + cf.uri + (cf.querystring ? "?" + cf.querystring : "");
  let body: string | undefined;
  if (cf.body?.data) {
    if (cf.body.bodyTruncated || cf.body.inputTruncated) {
      headers.set("content-length", String(maxBytes + 1)); // L1: body too large, fail-open
      body = undefined;
    } else {
      body = cf.body.encoding === "base64" ? Buffer.from(cf.body.data, "base64").toString("utf8") : cf.body.data;
    }
  }
  return new Request(url, { method: cf.method, headers, body: cf.method === "GET" || cf.method === "HEAD" ? undefined : body });
}

const STATUS_TEXT: Record<number, string> = {
  400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found", 406: "Not Acceptable",
  418: "I'm a teapot", 422: "Unprocessable Entity", 429: "Too Many Requests", 451: "Unavailable For Legal Reasons",
  500: "Internal Server Error", 503: "Service Unavailable",
};

function setJevHeaders(cf: CfRequest, hdrs: Record<string, string>, requestId: string, subjectId?: string): void {
  for (const h of HEADER_NAMES) delete cf.headers[h];
  for (const [k, v] of Object.entries(hdrs)) cf.headers[k.toLowerCase()] = [{ key: k, value: v }];
  cf.headers["x-jev-request-id"] = [{ key: "X-Jev-Request-Id", value: requestId }];
  if (subjectId) cf.headers["x-jev-subject"] = [{ key: "X-Jev-Subject", value: subjectId }];
}

export function lambdaEdgeHandler(opts: Options): (event: CfEvent) => Promise<CfRequest | CfResponse> {
  let rt: Runtime | undefined;
  return async (event) => {
    const cf = event.Records[0].cf.request;
    try {
      rt ??= createRuntime(opts);
      const maxBytes = Math.max(...rt.rules.map((r) => r.max_body_bytes ?? 65536));
      const { verdict, response, requestId, subjectId } = await evaluate(toRequest(cf, maxBytes), rt);
      if (response) {
        const headers: Record<string, CfHeader[]> = {};
        response.headers.forEach((v, k) => (headers[k] = [{ key: k, value: v }]));
        const status = rt.config.policy.block_status ?? response.status;
        return { status: String(status), statusDescription: STATUS_TEXT[status] ?? "Blocked", headers, body: await response.text() };
      }
      setJevHeaders(cf, verdictHeaders(verdict), requestId, subjectId);
      return cf;
    } catch (e) {
      // Same shape as every other host: pass, and every X-Jev-* header says so,
      // so a client-supplied X-Jev-Verdict: safe cannot survive an adapter error.
      console.error("jev-edge: lambda@edge error, failing open: " + (e instanceof Error ? e.message : String(e)));
      const v = newVerdict({ verdict: ERROR, source: SRC_ADAPTER, reason: "adapter error" });
      let rid: string;
      try {
        rid = crypto.randomUUID();
      } catch {
        rid = String(Date.now());
      }
      setJevHeaders(cf, verdictHeaders(v), rid);
      return cf;
    }
  };
}
