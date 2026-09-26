// middleware.ts at the root of a Next.js project, run on the Node runtime
// (`runtime: "nodejs"` in `config` below, Next 15.5 and later). On Next 16 the
// file is proxy.ts: export the same function as `proxy` and drop `runtime`,
// since a proxy always runs on Node. Middleware left on the edge runtime
// (middleware.ts's default) judges plain bodies the same way, but there
// DecompressionStream is a stub that throws, so a gzip or deflate request
// body cannot be decoded: it is unjudgeable and policy.unjudgeable decides
// (pass by default). Next calls it as `middleware(request, event)`; the
// event's waitUntil keeps the subject write (config.subject) alive after the
// response.
import { NextResponse } from "next/server";
import { nextMiddleware } from "@jev-edge/js";

export const middleware = nextMiddleware(
  {
    config: {
      jev: {
        provider: "jev",
        api_key: process.env.TYPESAFE_API_KEY,
        deployment_context:
          "A support assistant on Acme's billing website. It answers customers' " +
          "questions about invoices, subscription plans, refunds and payment methods. " +
          "Users are Acme customers. It does not write code, adopt personas, discuss " +
          "other companies' products, or produce essays, stories or marketing copy.",
        timeout_ms: 400,
        timeout_max_ms: 1000,
      },
      policy: { mode: "monitor", block_threshold: 0.7, suspect_threshold: 0.5 },
    },
    onVerdict: (v, req) => console.log(JSON.stringify({ path: new URL(req.url).pathname, ...v })),
  },
  NextResponse,
);

// The AI SDK's useChat posts to /api/chat and useCompletion to /api/completion
// by default. Next runs the middleware only on these paths: list every route
// of the app that takes a prompt.
export const config = {
  runtime: "nodejs",
  matcher: ["/api/chat/:path*", "/api/completion/:path*", "/api/completions/:path*", "/v1/:path*"],
};
