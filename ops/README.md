# Operating jev-edge: dashboard and alerts

[中文](README.zh-CN.md)

| File | What it is |
|---|---|
| [grafana/jev-edge.json](grafana/jev-edge.json) | Grafana 10+ dashboard (uid `jev-edge`) |
| [prometheus/jev-edge-rules.yml](prometheus/jev-edge-rules.yml) | Prometheus alert rules, group `jev-edge` |
| [prometheus/jev-edge-rules.test.yml](prometheus/jev-edge-rules.test.yml) | `promtool test rules` unit tests for those rules |

## What the gateway must expose

Metrics live in one shared dict and are rendered as Prometheus text by `/_jev/metrics`. Without the dict every metric call is a no-op and the endpoint answers `# jev_metrics shared dict not defined`.

```nginx
http {
    lua_shared_dict jev_metrics 4m;   # a few dozen keys; 1m is already plenty

    server {
        location = /_jev/metrics {
            allow 10.0.0.0/8;   # your Prometheus, nothing else
            deny all;
            content_by_lua_block { require("resty.jev.edge").metrics() }
        }
    }
}
```

Scrape it like any target. The dashboard and the rules key everything on `job` and `instance`:

```yaml
scrape_configs:
  - job_name: jev-edge
    metrics_path: /_jev/metrics
    static_configs:
      - targets: ["gw1.internal:8080", "gw2.internal:8080"]
```

No extra config is needed for the metrics themselves. The alerts read these settings: `jev.timeout_ms` / `jev.timeout_max_ms` (adaptive timeout floor and ceiling), `breaker.*`, `async.max_async`, `policy.unjudgeable`, `feedback.enabled` / `feedback.token`.

### Metrics

All of these come from `adapters/openresty/lib/resty/jev/metrics.lua`:

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `jev_requests_total` | counter | `source` (l1, trust, cache, l2, breaker), `verdict` (safe, suspicious, malicious, error, skipped) | every evaluated request |
| `jev_actions_total` | counter | `action` (pass, block) | what the gateway did with it |
| `jev_cache_hits_total` | counter | `kind` (fp) | verdict-cache hits |
| `jev_l2_latency_ms` | histogram | `le` (25, 50, 100, 200, 300, 500, 1000, +Inf) | L2 call time, including failed calls |
| `jev_tokens_total` | counter | `direction` (input, output) | provider tokens |
| `jev_breaker_state` | gauge | | 0 closed, 1 open, 2 half-open (`core/breaker.lua`) |
| `jev_async_dropped_total` | counter | | async (L3) jobs not scheduled |
| `jev_l2_timeout_ms` | gauge | | adaptive L2 timeout in use |
| `jev_l2_timeout_max_ms` | gauge | | ceiling it is clamped to (`jev.timeout_max_ms`) |
| `jev_unjudged_total` | counter | `reason` (body, binary, content-encoding) | watched requests nobody could read |
| `jev_window_total` | counter | | L2 scores given for a window of a long text |
| `jev_feedback_total` | counter | `label` (benign, attack, other), `result` (trusted, refused, revoked, invalid) | `POST /_jev/feedback` calls that passed the token check |

Things to know when reading them:

- **One dict per nginx instance.** Workers share it, so one scrape covers the whole instance. Aggregate across instances in PromQL, as the dashboard does.
- **A series appears on its first increment.** `jev_async_dropped_total` is absent until something is dropped, and `increase()` does not count that first step from nothing to 1. A single drop right after a restart may therefore not fire `JevAsyncDropped`. A sustained problem will.
- **Gauges are written per request.** `jev_breaker_state` and `jev_l2_timeout_ms` are refreshed when a request is judged. With no traffic they hold their last value.
- **Restart and reload behave differently.** A restart clears the dict and counters reset, which `rate()` handles. A `nginx -s reload` keeps it.
- **Feedback labels are normalized.** `ok`, `good`, `fp` and the others count as `benign`, and `bad`, `malicious` and the others count as `attack`. Anything else counts as `other`/`invalid` and gets a 400. Calls that fail the token check are not counted. That keeps the label set bounded no matter what callers send.

## Importing the dashboard

**UI.** Go to Dashboards → New → Import, then upload `ops/grafana/jev-edge.json`. After import, pick the Prometheus data source in the **Prometheus** variable at the top of the dashboard.

**Provisioning.** Copy the file into a folder a dashboard provider watches:

```yaml
# /etc/grafana/provisioning/dashboards/jev-edge.yml
apiVersion: 1
providers:
  - name: jev-edge
    folder: jev-edge
    type: file
    options:
      path: /var/lib/grafana/dashboards/jev-edge
```

The data source is a dashboard variable (`DS_PROMETHEUS`, type datasource), so the same file works for import and for provisioning. The `job` and `instance` variables come from `label_values(jev_requests_total, …)`.

Panels:

- **Overview row:** request rate, block ratio, cache hit ratio and L2 error ratio.
- **Traffic row:** requests by verdict and source, actions, cache hit ratio over time, and windowed scores.
- **L2 row:** latency p50/p95/p99 and mean, adaptive timeout against its ceiling, breaker state timeline, and L2 calls by outcome.
- **Cost and async row:** tokens per second and dropped async jobs.
- **Coverage row:** unjudgeable requests by reason, and operator feedback by label and result over the dashboard's time range.

## Loading the alert rules

```yaml
# prometheus.yml
rule_files:
  - /etc/prometheus/rules/jev-edge-rules.yml
```

Check and test the rules before you deploy them. With Docker, from the repo root:

```sh
docker run --rm -v "$PWD/ops":/ops --entrypoint promtool prom/prometheus \
  check rules /ops/prometheus/jev-edge-rules.yml
docker run --rm -v "$PWD/ops":/ops --entrypoint promtool prom/prometheus \
  test rules /ops/prometheus/jev-edge-rules.test.yml
```

Every rule is evaluated per `(job, instance)`. Route on `severity` (`critical` or `warning`). Each alert carries `summary`, `description` and `runbook` annotations.

## Alerts: what they mean and what to do

### JevBreakerOpen (critical)

`min_over_time(jev_breaker_state[1m]) >= 1` for 2m: the L2 circuit breaker has not been closed for about three minutes.

A provider that stays down cycles through open (30 s), half-open (one probe) and open again, so the rule looks for "never closed", not for `== 1` on every sample.

While the breaker is open, requests that would go to L2 pass with `verdict=skipped, source=breaker`. Only L1, trusted fingerprints and the verdict cache are protecting traffic.

What to do:

1. Run `curl <gw>/_jev/health` and grep the error log for `L2 failed`.
2. If the cause is a provider outage or a revoked or wrong key (`TYPESAFE_API_KEY`), fix it. The breaker closes on the next successful half-open probe with no restart.
3. If the failures are timeouts, see JevL2TimeoutAtCeiling.

### JevL2ErrorRatioHigh (warning)

More than 10% of L2 calls have returned `verdict=error` for 10m. That covers timeouts, provider errors and answers without scores. Those requests pass (failing open) and are queued for an async re-judge.

What to do:

1. Read the reason in `jev-edge: L2 failed: <reason>` in the error log.
2. For timeouts, compare the L2 latency quantiles with the timeout panel. If the provider is healthy but slower, raise `jev.timeout_max_ms`.
3. For 401/403, rotate the key.
4. For 5xx, it is a provider incident.

If the error rate reaches `breaker.fail_ratio`, JevBreakerOpen follows.

### JevUnjudgeableRatioHigh (warning)

More than 5% of watched requests could not be read for 15m. Watched requests are those that were not a plain L1 "not watched" pass. With `policy.unjudgeable = "pass"` (the default), these requests go through unjudged. With `"block"` in enforce mode, they are rejected, so this alert then also means client errors.

Break the ratio down with `sum by (reason) (rate(jev_unjudged_total[5m]))`:

- **`body`:** the body is over the rule's `max_body_bytes` and the head and tail held no text. Raise the limit, or confirm the client really sends such bodies.
- **`content-encoding`:** the body is compressed and this build could not decode it. Either zlib or libbrotlidec is missing, or the data is corrupt or too large to inflate. Install the library, or have the client stop compressing requests.
- **`binary`:** a non-text body on an LLM route. Check that the rule's path match is not catching uploads.

### JevL2TimeoutAtCeiling (warning)

`jev_l2_timeout_ms >= jev_l2_timeout_max_ms` for 10m. The adaptive timeout has climbed to the operator ceiling, so provider latency has outgrown the budget and slow calls are being cut and counted as errors.

If the provider is healthy but slower, raise `jev.timeout_max_ms`, either in the config file or with `PUT /_jev/config`. The judge is rebuilt on reload. If the provider is getting worse, expect JevL2ErrorRatioHigh and then JevBreakerOpen.

When `timeout_max_ms == timeout_ms`, the timeout has no adaptive range and sits at the ceiling permanently. Silence this alert for such instances.

`jev_l2_timeout_max_ms` is exported next to `jev_l2_timeout_ms` for this rule. It is the ceiling after defaulting (2.5 × `timeout_ms` when `timeout_max_ms` is unset).

### JevAsyncDropped (warning)

Async (L3) re-judge jobs were dropped in the last 10m. Either more than `async.max_async` were in flight, or a timer could not be created. `async.enabled = false` is not counted.

Suspicious and errored requests are not getting their second look, and reputation blocking does not learn from them.

Raise `async.max_async` if the provider has headroom. Otherwise look for a burst of suspicious or error verdicts, or a slow provider holding async slots (`async.timeout_ms`).

### JevL2Starved (critical)

For 10m, requests have reached the L2 stage (`source=breaker`) and no L2 call has produced a verdict. This is the traffic-based twin of JevBreakerOpen: it still fires when the breaker-state gauge happens to be sampled while half-open.

Handle it the same way as JevBreakerOpen. The verdict cache keeps serving texts it has already judged. New texts pass unjudged until L2 recovers.

## CI

The rule check and the unit tests need nothing but Docker. The step is:

```yaml
- name: promtool check + test rules
  run: |
    docker run --rm -v "$PWD/ops":/ops --entrypoint promtool prom/prometheus:v3.5.0 \
      check rules /ops/prometheus/jev-edge-rules.yml
    docker run --rm -v "$PWD/ops":/ops --entrypoint promtool prom/prometheus:v3.5.0 \
      test rules /ops/prometheus/jev-edge-rules.test.yml
```
