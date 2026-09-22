# jev-edge 运维：仪表盘与告警

[English](README.md) | **简体中文**

| 文件 | 说明 |
|---|---|
| [grafana/jev-edge.json](grafana/jev-edge.json) | Grafana 10+ 仪表盘（uid 为 `jev-edge`） |
| [prometheus/jev-edge-rules.yml](prometheus/jev-edge-rules.yml) | Prometheus 告警规则，规则组名 `jev-edge` |
| [prometheus/jev-edge-rules.test.yml](prometheus/jev-edge-rules.test.yml) | 上面这些规则的 `promtool test rules` 单元测试 |

## 网关要暴露哪些东西

所有指标都放在同一个 shared dict 里，访问 `/_jev/metrics` 时渲染成 Prometheus 文本格式输出。如果没声明这个 dict，每次记指标都什么也不做，访问端点只会得到 `# jev_metrics shared dict not defined`。

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

抓取方式和普通 target 没有区别。仪表盘和告警规则都以 `job` 和 `instance` 作为区分维度：

```yaml
scrape_configs:
  - job_name: jev-edge
    metrics_path: /_jev/metrics
    static_configs:
      - targets: ["gw1.internal:8080", "gw2.internal:8080"]
```

指标本身不用额外配置。告警会读取下面这些配置项：`jev.timeout_ms` / `jev.timeout_max_ms`（自适应超时的下限和上限）、`breaker.*`、`async.max_async`、`policy.unjudgeable`、`feedback.enabled` / `feedback.token`。

### 指标

下面这些指标都定义在 `adapters/openresty/lib/resty/jev/metrics.lua` 里：

| 指标 | 类型 | 标签 | 含义 |
|---|---|---|---|
| `jev_requests_total` | counter | `source`（l1、trust、cache、l2、breaker），`verdict`（safe、suspicious、malicious、error、skipped） | 每个经过评估的请求 |
| `jev_actions_total` | counter | `action`（pass、block） | 网关最终对请求做了什么 |
| `jev_cache_hits_total` | counter | `kind`（fp） | 判定结果缓存的命中次数 |
| `jev_l2_latency_ms` | histogram | `le`（25、50、100、200、300、500、1000、+Inf） | L2 调用耗时，失败的调用也算在内 |
| `jev_tokens_total` | counter | `direction`（input、output） | provider 消耗的 token 数 |
| `jev_breaker_state` | gauge | | 0 表示关闭，1 表示打开，2 表示半开（见 `core/breaker.lua`） |
| `jev_async_dropped_total` | counter | | 没能调度起来的异步（L3）任务 |
| `jev_l2_timeout_ms` | gauge | | 当前生效的 L2 自适应超时 |
| `jev_l2_timeout_max_ms` | gauge | | 自适应超时的上限（`jev.timeout_max_ms`） |
| `jev_unjudged_total` | counter | `reason`（body、binary、content-encoding） | 需要检查、但谁都读不了内容的请求 |
| `jev_window_total` | counter | | 长文本按送审窗口切分后，L2 给出的窗口评分数 |
| `jev_feedback_total` | counter | `label`（benign、attack、other），`result`（trusted、refused、revoked、invalid） | 通过 token 校验的 `POST /_jev/feedback` 调用 |

看这些指标时要注意几点：

- **每个 nginx 实例一个 dict。** 同一实例的各个 worker 共用这个 dict，所以抓一次就覆盖整个实例。跨实例的汇总放在 PromQL 里做，仪表盘就是这么做的。
- **序列在第一次递增时才出现。** `jev_async_dropped_total` 在真正丢弃任务之前根本不存在，而 `increase()` 不会把从无到 1 的这一步算进去。所以重启后紧接着只丢了一次任务，`JevAsyncDropped` 可能不会触发；问题持续存在的话，告警一定会触发。
- **gauge 按请求更新。** `jev_breaker_state` 和 `jev_l2_timeout_ms` 只在有请求送审时刷新。没有流量时，它们停留在最后一次写入的值。
- **重启和 reload 的效果不一样。** 重启会清空 dict，counter 归零，这种情况 `rate()` 能正确处理。`nginx -s reload` 则会保留 dict 里的数据。
- **反馈标签会做归一化。** `ok`、`good`、`fp` 等算作 `benign`，`bad`、`malicious` 等算作 `attack`。其他取值记为 `other`/`invalid`，并返回 400。没通过 token 校验的调用不计数。这样不管调用方传什么，标签的取值范围都是有限的。

## 导入仪表盘

**通过界面导入。** 进入 Dashboards → New → Import，上传 `ops/grafana/jev-edge.json`。导入完成后，在仪表盘顶部的 **Prometheus** 变量里选好 Prometheus 数据源。

**通过 provisioning。** 把文件复制到某个 dashboard provider 监听的目录：

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

数据源是一个仪表盘变量（`DS_PROMETHEUS`，类型为 datasource），所以导入和 provisioning 用的是同一个文件。`job` 和 `instance` 两个变量的取值来自 `label_values(jev_requests_total, …)`。

面板分为以下几行：

- **概览：** 请求速率、拦截比例、缓存命中率和 L2 错误率。
- **流量：** 按判定结果和来源拆分的请求数、网关动作、缓存命中率随时间的变化，以及窗口评分。
- **L2：** 延迟的 p50/p95/p99 和均值、自适应超时与其上限的对比、熔断器状态时间线，以及按结果拆分的 L2 调用数。
- **成本与异步：** 每秒 token 数和被丢弃的异步任务。
- **覆盖情况：** 按原因拆分的无法判定请求，以及仪表盘时间范围内按标签和结果拆分的运维人员反馈。

## 加载告警规则

```yaml
# prometheus.yml
rule_files:
  - /etc/prometheus/rules/jev-edge-rules.yml
```

上线前先检查并测试规则。有 Docker 的话，在仓库根目录执行：

```sh
docker run --rm -v "$PWD/ops":/ops --entrypoint promtool prom/prometheus \
  check rules /ops/prometheus/jev-edge-rules.yml
docker run --rm -v "$PWD/ops":/ops --entrypoint promtool prom/prometheus \
  test rules /ops/prometheus/jev-edge-rules.test.yml
```

所有规则都按 `(job, instance)` 分别计算。告警路由按 `severity`（`critical` 或 `warning`）来配。每条告警都带有 `summary`、`description` 和 `runbook` 三个 annotation。

## 告警含义与处理方法

### JevBreakerOpen（critical）

`min_over_time(jev_breaker_state[1m]) >= 1` 持续 2m：L2 熔断器已经大约三分钟没有处于关闭状态了。

provider 一直不可用时，熔断器会在打开（30 s）、半开（放一个探测请求）、再打开之间来回切换。所以这条规则判断的是“一直没关闭过”，而不是要求每个样本都 `== 1`。

熔断器打开期间，本该送到 L2 的请求会直接放行，记为 `verdict=skipped, source=breaker`。这时保护流量的只剩 L1、可信指纹和判定结果缓存。

处理步骤：

1. 执行 `curl <gw>/_jev/health`，并在错误日志里 grep `L2 failed`。
2. 如果原因是 provider 故障，或者 key（`TYPESAFE_API_KEY`）被吊销、配错了，就把它修好。下一次半开探测成功后熔断器会自动关闭，不需要重启。
3. 如果失败都是超时，参考 JevL2TimeoutAtCeiling。

### JevL2ErrorRatioHigh（warning）

10m 内超过 10% 的 L2 调用返回了 `verdict=error`，包括超时、provider 报错和没有返回分数的响应。这些请求会按失败放行处理，同时排进队列等待异步重新判定。

处理步骤：

1. 在错误日志里找 `jev-edge: L2 failed: <reason>`，看具体原因。
2. 如果是超时，把 L2 延迟分位数和超时面板对照着看。provider 本身正常、只是变慢了，就调大 `jev.timeout_max_ms`。
3. 如果是 401/403，轮换 key。
4. 如果是 5xx，那是 provider 那边出了故障。

错误率达到 `breaker.fail_ratio` 后，接着就会触发 JevBreakerOpen。

### JevUnjudgeableRatioHigh（warning）

15m 内超过 5% 的受检请求无法读取内容。受检请求指的是除了 L1 直接以“无需检查”放行之外的请求。`policy.unjudgeable = "pass"`（默认值）时，这些请求不经判定直接放行；如果设成 `"block"` 并处于 enforce 模式，这些请求会被拒绝，这时这条告警同时也意味着客户端在报错。

用 `sum by (reason) (rate(jev_unjudged_total[5m]))` 按原因拆开看：

- **`body`：** 请求体超过了规则的 `max_body_bytes`，而且头部和尾部都没有文本。要么调大这个限制，要么确认客户端是不是真的会发这么大的请求体。
- **`content-encoding`：** 请求体经过压缩，而当前构建解不开。可能是缺少 zlib 或 libbrotlidec，也可能是数据损坏或者解压后太大。装上对应的库，或者让客户端别再压缩请求。
- **`binary`：** LLM 路由上出现了非文本的请求体。检查规则的路径匹配是不是把上传接口也包进来了。

### JevL2TimeoutAtCeiling（warning）

`jev_l2_timeout_ms >= jev_l2_timeout_max_ms` 持续 10m。自适应超时已经涨到运维人员设定的上限，说明 provider 的延迟超出了预算，慢的调用会被截断并计为错误。

provider 本身正常、只是变慢了，就调大 `jev.timeout_max_ms`，改配置文件或者调用 `PUT /_jev/config` 都行，reload 时会重建判定器。如果 provider 在持续恶化，接下来会先后触发 JevL2ErrorRatioHigh 和 JevBreakerOpen。

如果 `timeout_max_ms == timeout_ms`，超时没有自适应的空间，会一直停在上限。这种实例请把这条告警静默掉。

`jev_l2_timeout_max_ms` 就是为这条规则才和 `jev_l2_timeout_ms` 一起导出的。它的值是套用默认值之后的上限：没设置 `timeout_max_ms` 时为 2.5 × `timeout_ms`。

### JevAsyncDropped（warning）

最近 10m 内有异步（L3）重新判定任务被丢弃。原因要么是同时在跑的任务超过了 `async.max_async`，要么是 timer 创建失败。`async.enabled = false` 的情况不计入。

这意味着可疑和出错的请求得不到二次检查，基于信誉的拦截也没法从这些请求中学习。

如果 provider 还有余量，就调大 `async.max_async`。否则就排查是不是突然出现了一批 suspicious 或 error 判定结果，或者 provider 太慢、一直占着异步槽位（`async.timeout_ms`）。

### JevL2Starved（critical）

10m 内一直有请求走到 L2 阶段（`source=breaker`），但没有任何一次 L2 调用给出判定结果。这条告警和 JevBreakerOpen 是一对，区别在于它依据的是流量：即使抓取熔断器状态 gauge 时恰好处在半开状态，它照样会触发。

处理方法和 JevBreakerOpen 相同。判定结果缓存会继续为已经判定过的文本提供结果，新文本在 L2 恢复前都不经判定直接放行。

## CI

检查规则和跑单元测试只需要 Docker。对应的步骤如下：

```yaml
- name: promtool check + test rules
  run: |
    docker run --rm -v "$PWD/ops":/ops --entrypoint promtool prom/prometheus:v3.5.0 \
      check rules /ops/prometheus/jev-edge-rules.yml
    docker run --rm -v "$PWD/ops":/ops --entrypoint promtool prom/prometheus:v3.5.0 \
      test rules /ops/prometheus/jev-edge-rules.test.yml
```
