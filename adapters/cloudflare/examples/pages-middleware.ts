// Pages Functions: functions/_middleware.ts
// Same engine as the full Worker, applied to every route of the Pages project.
// Bind JEV_CACHE (KV) and JEV_STATE (Durable Object) in the Pages settings and
// add TYPESAFE_API_KEY as a secret.
import { pagesMiddleware, JevState } from "@jev-edge/cloudflare";

export { JevState };

export const onRequest = pagesMiddleware({
  config: {
    jev: { provider: "jev", deployment_context: "…", timeout_ms: 400 },
    policy: { mode: "monitor" },
  },
});
