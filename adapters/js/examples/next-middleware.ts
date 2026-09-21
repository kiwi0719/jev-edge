// middleware.ts at the root of a Next.js project. Runs on the edge runtime on
// Vercel and on the Node runtime elsewhere; both are V8, both are covered by
// the golden vectors.
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

export const config = { matcher: ["/api/chat/:path*", "/v1/:path*"] };
