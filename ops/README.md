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

    server {                          # the admin listener, never the traffic server
        listen <monitoring-network-ip>:9180;
        location = /_jev/metrics {
            allow <prometheus-host>;  # your Prometheus, nothing else
            deny all;
            content_by_lua_block { require("resty.jev.edge").metrics() }
        }
    }
}
```

This is the admin server of [example.nginx.conf](../adapters/openresty/conf/example.nginx.conf) (which binds it to `127.0.0.1:9180`), on an address your Prometheus reaches. Keep it off the traffic server: behind a load balancer an `allow` list sees the balancer's address, not Prometheus's, unless `realip` is configured, so a listener of its own is what makes the allow list mean something.

Scrape it like any target. The dashboard and the rules key everything on `job` and `instance`:

```yaml
scrape_configs:
  - job_name: jev-edge
    metrics_path: /_jev/metrics
    static_configs:
      - targets: ["gw1.internal:9180", "gw2.internal:9180"]
```

No extra config is needed for the metrics themselves. The alerts read these settings: `jev.timeout_ms` / `jev.timeout_max_ms` (adaptive timeout floor and ceiling), `breaker.*`, `async.max_async`, `policy.unjudgeable`, `feedback.enabled` / `feedback.token`.

### Metrics

All of these come from `adapters/openresty/lib/resty/jev/metrics.lua`:

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `jev_requests_total` | counter | `source` (l1, trust, cache, l2, breaker, adapter), `verdict` (safe, suspicious, malicious, error, skipped) | every evaluated request |
| `jev_actions_total` | counter | `action` (pass, block) | what the gateway did with it |
| `jev_cache_hits_total` | counter | `kind` (fp) | verdict-cache hits |
| `jev_l2_errors_total` | counter | `kind` (transport, timeout, unavailable, rejected, unusable, busy, other) | L2 calls that ended in `verdict=error`, by what they ran into |
| `jev_l2_latency_ms` | histogram | `le` (25, 50, 100, 200, 300, 500, 1000, 2000, 3000, 5000, 10000, 30000, +Inf) | L2 call time, including failed calls; not a `max_inflight` refusal (no call) nor a verdict every part of which was a cache hit. Every bucket is written once there has been a call, and a bucket is never lower than the one below it (right after an upgrade the new buckets start from the old `le="1000"`) |
| `jev_tokens_total` | counter | `direction` (input, output) | provider tokens |
| `jev_breaker_state` | gauge | | 0 closed, 1 open, 2 half-open (`core/breaker.lua`) |
| `jev_async_dropped_total` | counter | | async (L3) jobs not scheduled |
| `jev_async_total` | counter | `result` (ok, failed, busy, no_scores, error) | async (L3) jobs that ran, by outcome |
| `jev_l2_timeout_ms` | gauge | | adaptive L2 timeout in use |
| `jev_l2_timeout_max_ms` | gauge | | ceiling it is clamped to (`jev.timeout_max_ms`) |
| `jev_unjudged_total` | counter | `reason` (body, binary, content-encoding, invalid, json, partial, text, multipart, token) | watched requests nobody could read |
| `jev_window_total` | counter | | L2 scores given for a window of a long text |
| `jev_feedback_total` | counter | `label` (benign, attack, other), `result` (trusted, refused, revoked, invalid) | `POST /_jev/feedback` calls that passed the token check |
| `jev_subject_blocks_total` | counter | | requests blocked by subject reputation |
| `jev_authz_events_total` | counter | `event` (no_client_ip, cut_at_cap) | `/_jev/authz` requests with no client address it can trust (no `X-Forwarded-For`, or fewer hops than `trusted_hops`), and bodies at or past `max_body_bytes` taken as cut |
| `jev_adapter_errors_total` | counter | `entry` (access, authz, forward_auth) | requests failed open because judging threw; each also counts in `jev_requests_total{source="adapter",verdict="error"}` |

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
- **Coverage row:** unjudgeable requests by reason, operator feedback by label and result over the dashboard's time range, subject reputation blocks, adapter errors (requests passed unjudged), async re-judges by result, L2 errors by kind, and the share of L2 traffic refused at `max_inflight`.

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

1. Run `curl 127.0.0.1:9180/_jev/health` on the gateway (the admin listener) and grep the error log for `L2 failed`.
2. If the cause is a provider outage or a revoked or wrong key (`TYPESAFE_API_KEY`), fix it. The breaker closes on the next successful half-open probe with no restart.
3. If the failures are timeouts, see JevL2TimeoutAtCeiling.

### JevL2ErrorRatioHigh (warning)

More than 10% of L2 calls have returned `verdict=error` for 10m. That covers timeouts, provider errors and answers without scores. Those requests pass (failing open) and are queued for an async re-judge.

What to do:

1. Break the errors down with `sum by (kind) (rate(jev_l2_errors_total[5m]))` and read the reason in `jev-edge: L2 failed: <reason>` in the error log.
2. `timeout`: compare the L2 latency quantiles with the timeout panel. If the provider is healthy but slower, raise `jev.timeout_max_ms`.
3. `unavailable`: a 5xx or 429 is a provider incident, a 401 a bad or revoked key, a 404 or 405 a wrong endpoint or model name.
4. `rejected` (any other 4xx) or `unusable` (a 2xx with no scores in it): if it is near 100%, the provider refuses every call. That usually means a parameter the model does not take, the key's permissions, or a WAF in front of it (see JevL2NoVerdicts).

Only `transport`, `timeout` and `unavailable` count toward the breaker. If they reach `breaker.fail_ratio`, JevBreakerOpen follows. `rejected` and `unusable` never open it, because the judged text can provoke them (a content filter's 400, a WAF's 403, a refusal) and a client must not be able to switch L2 off. `busy` is the gateway's own `jev.max_inflight` being full.

### JevUnjudgeableRatioHigh (warning)

More than 5% of watched requests could not be read for 15m. Watched requests are those that were not a plain L1 "not watched" pass. With `policy.unjudgeable = "pass"` (the default), these requests go through unjudged. With `"block"` in enforce mode, they are rejected, so this alert then also means client errors.

Break the ratio down with `sum by (reason) (rate(jev_unjudged_total[5m]))`:

- **`body`:** the body is over the rule's `max_body_bytes` and the head and tail held no text. Raise the limit, or confirm the client really sends such bodies.
- **`content-encoding`:** the body is compressed and this build could not decode it. Either zlib or libbrotlidec is missing, or the data is corrupt or too large to inflate. Install the library, or have the client stop compressing requests.
- **`binary`:** a non-text body on an LLM route. Check that the rule's path match is not catching uploads.
- **`invalid`:** declared JSON the decoder refused, with no text field the tolerant scanner could find. A broken client, or JSON in an encoding other than UTF-8.
- **`json`:** a JSON body past the walk's bounds (20,000 nodes, 1000 levels) with too little left to judge. Usually a crafted body.
- **`partial`:** the gateway in front cut the body and `policy.partial = "unjudgeable"`. Raise the gateway's body limit to `max_body_bytes`, or refuse larger bodies there.
- **`text`:** text over `max_judge_chunks` with `policy.unjudgeable = "block"` in enforce mode. Raise `max_judge_chunks` or `max_judge_bytes` if such requests are legitimate.
- **`multipart`:** a multipart body with more than 8 distinct boundary parameters.
- **`token`:** a prompt sent as token ids, which L1 cannot read. Normal SDKs send text; `token_prompts = "block"` in the rule refuses them.

### JevL2TimeoutAtCeiling (warning)

`jev_l2_timeout_ms >= jev_l2_timeout_max_ms` for 10m. The adaptive timeout has climbed to the operator ceiling, so provider latency has outgrown the budget and slow calls are being cut and counted as errors.

If the provider is healthy but slower, raise `jev.timeout_max_ms`, either in the config file or with `PUT /_jev/config`. The judge is rebuilt on reload. If the provider is getting worse, expect JevL2ErrorRatioHigh and then JevBreakerOpen.

When `timeout_max_ms == timeout_ms`, the timeout has no adaptive range and sits at the ceiling permanently. Silence this alert for such instances.

`jev_l2_timeout_max_ms` is exported next to `jev_l2_timeout_ms` for this rule. It is `jev.timeout_max_ms`, 1000 by default (`core/defaults.lua`). Raising `timeout_ms` above 1000 means raising `timeout_max_ms` too, or the config is refused (`jev.timeout_max_ms must be >= jev.timeout_ms`), the previous one stays in force and the refusal is logged and shown as `config_error`. The 2.5 × `timeout_ms` fallback applies only to a config that has no `timeout_max_ms` key at all.

### JevAsyncDropped (warning)

Async (L3) re-judge jobs were dropped in the last 10m. Either more than `async.max_async` were in flight, or a timer could not be created. `async.enabled = false` is not counted.

Suspicious and errored requests are not getting their second look, and reputation blocking does not learn from them.

Raise `async.max_async` if the provider has headroom. Otherwise look for a burst of suspicious or error verdicts, or a slow provider holding async slots (`async.timeout_ms`).

### JevL2Saturated (critical)

For 5m, more than 10% of the requests reaching L2 have been refused by the gateway's own `jev.max_inflight` cap (`jev_l2_errors_total{kind="busy"}`, reason `max_inflight exceeded`): no call was made, they pass with `verdict=error`, and the breaker never counts them, so nothing else pages.

Raise `jev.max_inflight` if the provider has headroom (its rate limits, the L2 latency panel), or scale the provider. A slow provider holds each slot longer: check the latency quantiles and JevL2TimeoutAtCeiling first, since a higher cap on a provider that is timing out only turns `busy` into `timeout`. With the Laya profile, `max_inflight = 1` is deliberate; raise it only after `make conformance` passes at the new `CONCURRENCY`.

### JevAsyncFailing (warning)

More than half of the async (L3) re-judge jobs that ran in 10m got no answer, for 5m. Suspicious and errored requests are not getting their second look: no cached verdict, and reputation blocking does not learn from them.

Break it down with `sum by (result) (increase(jev_async_total[10m]))`. `failed`: read the error log for `L3 judge failed` (provider errors, or an L3 timeout too short for the provider). `no_scores`: the provider answers without the scores asked for (model, template). `busy`: a custom judge's own cap. `error`: `L3 error` in the error log, a bug.

### JevAdapterErrors (critical)

Requests through an entry (`access`, `authz`, `forward_auth`) passed unjudged in the last 5m because judging threw: `verdict=error`, `source=adapter`. While every request fails this way the ratio alerts above see no L2 traffic at all, which is why this one exists.

Read the error log for `jev-edge: <entry> error, failing open`. After a config change: `GET /_jev/config` (see `config_error`), then `DELETE /_jev/config` to drop the override, or fix the file. Otherwise it is a bug: report the log line.

### JevL2Starved (critical)

For 10m, requests have reached the L2 stage (`source=breaker`) and no L2 call has produced a verdict. This is the traffic-based twin of JevBreakerOpen: it still fires when the breaker-state gauge happens to be sampled while half-open.

Handle it the same way as JevBreakerOpen. The verdict cache keeps serving texts it has already judged. New texts pass unjudged until L2 recovers.

### JevL2NoVerdicts (critical)

For 10m, every L2 call has ended in `verdict=error` and none has given a verdict, whatever the breaker says. A provider that refuses every call for a reason the breaker does not count (a 400 for a model parameter, a WAF's 403, answers with no scores) leaves the breaker closed, so JevBreakerOpen and JevL2Starved stay quiet while nothing past L1 is judged.

What to do:

1. Break it down with `sum by (kind) (rate(jev_l2_errors_total[5m]))` and read `jev-edge: L2 failed: <reason>` in the error log.
2. `rejected`: the provider refuses the call. Check the model's parameters, the key's permissions and anything in front of the provider.
3. `unusable`: the provider answers, but not in the judge's format. Check the model name and the templates.
4. `busy`: `jev.max_inflight` is full; raise it or add capacity.
5. `unavailable`, `transport` or `timeout`: handle it as JevBreakerOpen.

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
