# 运维 jev-edge：仪表盘与告警

[English](README.md)

| 文件 | 内容 |
|---|---|
| [grafana/jev-edge.json](grafana/jev-edge.json) | Grafana 10+ 仪表盘（uid `jev-edge`） |
| [prometheus/jev-edge-rules.yml](prometheus/jev-edge-rules.yml) | Prometheus 告警规则，规则组 `jev-edge` |
| [prometheus/jev-edge-rules.test.yml](prometheus/jev-edge-rules.test.yml) | 这些规则的 `promtool test rules` 单元测试 |

## 网关需要暴露什么

指标存在一个 shared dict 里，由 `/_jev/metrics` 渲染成 Prometheus 文本格式。没有声明这个 dict 时，所有指标调用都是空操作，端点返回 `# jev_metrics shared dict not defined`。

```nginx
http {
    lua_shared_dict jev_metrics 4m;   # 只有几十个 key，1m 就足够

    server {
        location = /_jev/metrics {
            allow 10.0.0.0/8;   # 只放行你的 Prometheus
            deny all;
            content_by_lua_block { require("resty.jev.edge").metrics() }
        }
    }
}
```

像普通 target 一样抓取即可。仪表盘和规则都按 `job`、`instance` 区分：

```yaml
scrape_configs:
  - job_name: jev-edge
    metrics_path: /_jev/metrics
    static_configs:
      - targets: ["gw1.internal:8080", "gw2.internal:8080"]
```

指标本身不需要额外配置。告警会用到这些配置项：`jev.timeout_ms` / `jev.timeout_max_ms`（自适应超时的下限和上限）、`breaker.*`、`async.max_async`、`policy.unjudgeable`、`feedback.enabled` / `feedback.token`。

### 指标

全部来自 `adapters/openresty/lib/resty/jev/metrics.lua`：

| 指标 | 类型 | 标签 | 含义 |
|---|---|---|---|
| `jev_requests_total` | counter | `source`（l1、trust、cache、l2、breaker），`verdict`（safe、suspicious、malicious、error、skipped） | 每个被评估的请求 |
| `jev_actions_total` | counter | `action`（pass、block） | 网关最终怎么处理 |
| `jev_cache_hits_total` | counter | `kind`（fp） | 判定缓存命中 |
| `jev_l2_latency_ms` | histogram | `le`（25、50、100、200、300、500、1000、+Inf） | L2 调用耗时，失败的调用也计入 |
| `jev_tokens_total` | counter | `direction`（input、output） | 模型服务消耗的 token |
| `jev_breaker_state` | gauge | | 0 闭合，1 打开，2 半开（见 `core/breaker.lua`） |
| `jev_async_dropped_total` | counter | | 没能调度的异步（L3）任务 |
| `jev_l2_timeout_ms` | gauge | | 当前生效的自适应 L2 超时 |
| `jev_l2_timeout_max_ms` | gauge | | 自适应超时被夹住的上限（`jev.timeout_max_ms`） |
| `jev_unjudged_total` | counter | `reason`（body、binary、content-encoding） | 被监控但读不了的请求 |
| `jev_window_total` | counter | | 长文本只对一个窗口给出 L2 分数的次数 |
| `jev_feedback_total` | counter | `label`（benign、attack、other），`result`（trusted、refused、revoked、invalid） | 通过 token 校验的 `POST /_jev/feedback` 调用 |

读这些指标时要注意：

- **每个 nginx 实例一个 dict。** 同一实例的 worker 共享它，所以抓一次就覆盖整个实例。跨实例的汇总在 PromQL 里做，仪表盘就是这样做的。
- **序列在第一次递增时才出现。** 在第一次丢弃之前，`jev_async_dropped_total` 不存在，而 `increase()` 不计从无到 1 的这一步。所以重启后的单次丢弃可能不会触发 `JevAsyncDropped`，持续的问题会触发。
- **gauge 随请求写入。** `jev_breaker_state` 和 `jev_l2_timeout_ms` 在有请求被判定时才刷新，没有流量时保持最后的值。
- **重启和 reload 不一样。** 重启会清空 dict，计数器归零，`rate()` 能处理。`nginx -s reload` 会保留 dict。
- **反馈标签会先归一化。** `ok`、`good`、`fp` 等记为 `benign`，`bad`、`malicious` 等记为 `attack`。其他值记为 `other`/`invalid`，并返回 400。没通过 token 校验的调用不计数，所以不管调用方发什么，标签集合都是有界的。

## 导入仪表盘

**界面导入。** 进入 Dashboards → New → Import，上传 `ops/grafana/jev-edge.json`。导入后在仪表盘顶部的 **Prometheus** 变量里选择数据源。

**Provisioning。** 把文件放进某个 dashboard provider 监视的目录：

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

数据源是一个仪表盘变量（`DS_PROMETHEUS`，datasource 类型），所以同一个文件既能导入也能 provisioning。`job` 和 `instance` 变量来自 `label_values(jev_requests_total, …)`。

面板：

- **Overview 行：** 请求速率、拦截比例、缓存命中率、L2 错误率。
- **Traffic 行：** 按判定结果和来源分的请求、动作、缓存命中率随时间的变化、窗口评分。
- **L2 行：** 延迟 p50/p95/p99 和均值、自适应超时与上限对比、熔断器状态时间线、按结果分的 L2 调用。
- **Cost and async 行：** 每秒 token 数、被丢弃的异步任务。
- **Coverage 行：** 按原因分的不可判定请求，以及仪表盘时间范围内按标签和结果分的运营者反馈。

## 加载告警规则

```yaml
# prometheus.yml
rule_files:
  - /etc/prometheus/rules/jev-edge-rules.yml
```

部署前先检查并测试规则。在仓库根目录用 Docker 运行：

```sh
docker run --rm -v "$PWD/ops":/ops --entrypoint promtool prom/prometheus \
  check rules /ops/prometheus/jev-edge-rules.yml
docker run --rm -v "$PWD/ops":/ops --entrypoint promtool prom/prometheus \
  test rules /ops/prometheus/jev-edge-rules.test.yml
```

所有规则都按 `(job, instance)` 求值。按 `severity`（`critical` 或 `warning`）路由。每条告警都带 `summary`、`description` 和 `runbook` 注解。

## 告警：含义与处置

### JevBreakerOpen（critical）

`min_over_time(jev_breaker_state[1m]) >= 1` 持续 2 分钟，也就是 L2 熔断器大约三分钟没有闭合过。

模型服务一直不可用时，熔断器会在打开（30 秒）、半开（放一个探测）、再打开之间循环。所以规则看的是“从未闭合”，而不是每个样本都 `== 1`。

熔断器打开期间，本该送到 L2 的请求会以 `verdict=skipped, source=breaker` 放行。这时只有 L1、受信指纹和判定缓存在保护流量。

处置：

1. 执行 `curl <gw>/_jev/health`，并在错误日志里搜 `L2 failed`。
2. 如果原因是模型服务故障，或密钥（`TYPESAFE_API_KEY`）被吊销或填错，修好它。下一次半开探测成功后熔断器就会闭合，不需要重启。
3. 如果失败是超时，看 JevL2TimeoutAtCeiling。

### JevL2ErrorRatioHigh（warning）

超过 10% 的 L2 调用返回 `verdict=error`，持续 10 分钟。这包括超时、模型服务报错、应答里没有分数。这些请求会放行（fail open），并排队等异步复判。

处置：

1. 看错误日志里 `jev-edge: L2 failed: <原因>` 的原因。
2. 如果是超时，对比 L2 延迟分位数和超时面板。模型服务健康只是变慢时，调高 `jev.timeout_max_ms`。
3. 如果是 401/403，轮换密钥。
4. 如果是 5xx，属于模型服务故障。

错误率达到 `breaker.fail_ratio` 后，JevBreakerOpen 会接着触发。

### JevUnjudgeableRatioHigh（warning）

超过 5% 的被监控请求读不了，持续 15 分钟。被监控的请求指没有在 L1 被当作“不监控”直接放行的请求。`policy.unjudgeable = "pass"`（默认）时，这些请求不经判定直接通过。enforce 模式下设为 `"block"` 时它们会被拒绝，这时这条告警也意味着客户端在报错。

用 `sum by (reason) (rate(jev_unjudged_total[5m]))` 按原因拆开看：

- **`body`：** 请求体超过规则的 `max_body_bytes`，而且头尾部分里没有文本。调高这个上限，或者确认客户端确实会发这么大的请求体。
- **`content-encoding`：** 请求体是压缩过的，而这个构建解不开。可能缺 zlib 或 libbrotlidec，也可能数据损坏或解压后太大。装上对应的库，或者让客户端别压缩请求。
- **`binary`：** LLM 路由上出现了非文本请求体。检查规则的路径匹配是不是把上传接口也匹配进来了。

### JevL2TimeoutAtCeiling（warning）

`jev_l2_timeout_ms >= jev_l2_timeout_max_ms` 持续 10 分钟。自适应超时已经涨到运营者设的上限，说明模型服务的延迟超出了预算，慢的调用正在被掐断并计为错误。

模型服务健康只是变慢时，调高 `jev.timeout_max_ms`，改配置文件或用 `PUT /_jev/config` 都可以，reload 时 judge 会重建。如果模型服务在持续变差，接下来会看到 JevL2ErrorRatioHigh，然后是 JevBreakerOpen。

`timeout_max_ms == timeout_ms` 时，超时没有自适应空间，会一直停在上限。这类实例请静默这条告警。

为了这条规则，`jev_l2_timeout_max_ms` 和 `jev_l2_timeout_ms` 一起导出。它是应用默认值之后的上限：没设 `timeout_max_ms` 时为 2.5 × `timeout_ms`。

### JevAsyncDropped（warning）

最近 10 分钟内有异步（L3）复判任务被丢弃。原因是在途任务超过了 `async.max_async`，或者没能创建定时器。`async.enabled = false` 的情况不计数。

可疑和出错的请求没有得到第二次判定，信誉拦截也学不到它们。

模型服务还有余量时，调高 `async.max_async`。否则检查是否有一波 suspicious/error 判定，或者模型服务变慢占住了异步名额（`async.timeout_ms`）。

### JevL2Starved（critical）

10 分钟内有请求到达 L2 阶段（`source=breaker`），但没有任何 L2 调用给出判定。它是 JevBreakerOpen 基于流量的对应告警：即使熔断器状态 gauge 恰好在半开时被采样，它也能触发。

处置同 JevBreakerOpen。判定缓存会继续为已经判定过的文本服务，新文本在 L2 恢复前不经判定直接放行。

## CI

规则检查和单元测试只需要 Docker。步骤如下：

```yaml
- name: promtool check + test rules
  run: |
    docker run --rm -v "$PWD/ops":/ops --entrypoint promtool prom/prometheus:v3.5.0 \
      check rules /ops/prometheus/jev-edge-rules.yml
    docker run --rm -v "$PWD/ops":/ops --entrypoint promtool prom/prometheus:v3.5.0 \
      test rules /ops/prometheus/jev-edge-rules.test.yml
```
