// Full Worker: no gateway of your own. The whole core runs here.
//
//   wrangler kv namespace create JEV_CACHE
//   wrangler secret put TYPESAFE_API_KEY
//   wrangler deploy -c wrangler.full.toml
import { fullWorker, JevState } from "@jev-edge/js";

export { JevState }; // Durable Object holding breaker + adaptive timeout state

export default fullWorker({
  upstream: "https://app.internal.example.com",
  config: {
    jev: {
      provider: "jev",
      model: "jev-latest",
      // One paragraph on what the protected assistant is for. The setting that
      // decides accuracy; see the README section "Writing the deployment context".
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
});
