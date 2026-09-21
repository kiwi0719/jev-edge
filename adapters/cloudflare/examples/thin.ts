// Thin Worker: Cloudflare in front of a jev-edge you already run.
// L1 rules and the fingerprint cache run at the edge; the judgment, the
// thresholds and the deployment context stay at the origin's /_jev/authz.
//
//   wrangler deploy -c wrangler.thin.toml
//   wrangler secret put JEV_ORIGIN      # https://gateway.example.com
import { thinWorker } from "@jev-edge/cloudflare";

export default thinWorker({
  // origin: "https://gateway.example.com",   // or env.JEV_ORIGIN
  // upstream defaults to origin; set it when the app is not behind the same host
  config: {
    policy: { mode: "enforce" }, // the origin decides the score; this decides what the edge does with it
    cache: { fp_ttl: 300 },
  },
});
