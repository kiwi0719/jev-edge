// Deno Deploy (or `deno run --allow-net --allow-env --unstable-kv examples/deno.ts`).
// The whole core runs in the isolate; allowed requests go to `upstream`.
//
//   deployctl deploy --entrypoint=examples/deno.ts
//   (set TYPESAFE_API_KEY in the project's environment variables)
import { denoHandler } from "npm:@jev-edge/js/deno";

Deno.serve(
  denoHandler({
    upstream: "https://app.internal.example.com",
    // Optional. Cache, breaker / adaptive state and the subject ring in Deno
    // KV, shared by every isolate; memory per isolate without it.
    kv: await Deno.openKv(),
    config: {
      jev: {
        provider: "jev",
        model: "jev-latest",
        api_key: Deno.env.get("TYPESAFE_API_KEY"),
        // One paragraph on what the protected assistant is for; see the README
        // section "Writing the deployment context".
        deployment_context:
          "A support assistant on Acme's billing website. It answers customers' " +
          "questions about invoices, subscription plans, refunds and payment methods. " +
          "Users are Acme customers. It does not write code, adopt personas, discuss " +
          "other companies' products, or produce essays, stories or marketing copy.",
        timeout_ms: 400,
        timeout_max_ms: 1000,
      },
      rules: ["llm-endpoints"],
      policy: { mode: "monitor", block_threshold: 0.7, suspect_threshold: 0.5 },
    },
    onVerdict: (v, req) => console.log(JSON.stringify({ path: new URL(req.url).pathname, ...v })),
  }),
);
