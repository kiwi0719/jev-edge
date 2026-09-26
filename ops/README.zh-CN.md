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

这就是 [example.nginx.conf](../adapters/openresty/conf/example.nginx.conf) 里的管理 server（那里绑定在 `127.0.0.1:9180`），只是换成你的 Prometheus 能访问到的地址。不要放在承载业务流量的 server 上：在负载均衡后面，`allow` 列表看到的是负载均衡的地址，而不是 Prometheus 的地址，除非配置了 `realip`；给它单独开一个监听端口，`allow` 列表才真正起作用。

抓取方式和普通 target 没有区别。仪表盘和告警规则都以 `job` 和 `instance` 作为区分维度：

```yaml
scrape_configs:
  - job_name: jev-edge
    metrics_path: /_jev/metrics
    static_configs:
      - targets: ["gw1.internal:9180", "gw2.internal:9180"]
```

指标本身不用额外配置。告警会读取下面这些配置项：`jev.timeout_ms` / `jev.timeout_max_ms`（自适应超时的下限和上限）、`breaker.*`、`async.max_async`、`policy.unjudgeable`、`feedback.enabled` / `feedback.token`。

### 指标

下面这些指标都定义在 `adapters/openresty/lib/resty/jev/metrics.lua` 里：

| 指标 | 类型 | 标签 | 含义 |
|---|---|---|---|
| `jev_requests_total` | counter | `source`（l1、trust、cache、l2、breaker、adapter），`verdict`（safe、suspicious、malicious、error、skipped） | 每个经过评估的请求 |
| `jev_actions_total` | counter | `action`（pass、block） | 网关最终对请求做了什么 |
| `jev_cache_hits_total` | counter | `kind`（fp） | 判定结果缓存的命中次数 |
| `jev_l2_errors_total` | counter | `kind`（transport、timeout、unavailable、rejected、unusable、busy、other） | 以 `verdict=error` 收场的 L2 调用，按失败原因分类 |
| `jev_l2_latency_ms` | histogram | `le`（25、50、100、200、300、500、1000、2000、3000、5000、10000、30000、+Inf） | L2 调用耗时，失败的调用也算在内；被 `max_inflight` 拒掉的（根本没发出调用）和每个部分都命中缓存的判定不算。有过一次调用之后每个桶都会输出，而且一个桶的值不会低于它下面那个桶（刚升级完时，新增的桶从旧的 `le="1000"` 起算） |
| `jev_tokens_total` | counter | `direction`（input、output） | provider 消耗的 token 数 |
| `jev_breaker_state` | gauge | | 0 表示关闭，1 表示打开，2 表示半开（见 `core/breaker.lua`） |
| `jev_async_dropped_total` | counter | | 没能调度起来的异步（L3）任务 |
| `jev_async_total` | counter | `result`（ok、failed、busy、no_scores、error） | 跑过的异步（L3）任务，按结果分类 |
| `jev_l2_timeout_ms` | gauge | | 当前生效的 L2 自适应超时 |
| `jev_l2_timeout_max_ms` | gauge | | 自适应超时的上限（`jev.timeout_max_ms`） |
| `jev_unjudged_total` | counter | `reason`（body、binary、content-encoding、invalid、json、partial、text、multipart、token） | 需要检查、但谁都读不了内容的请求 |
| `jev_window_total` | counter | | 长文本按送审窗口切分后，L2 给出的窗口评分数 |
| `jev_feedback_total` | counter | `label`（benign、attack、other），`result`（trusted、refused、revoked、invalid） | 通过 token 校验的 `POST /_jev/feedback` 调用 |
| `jev_subject_blocks_total` | counter | | 因主体信誉被拦截的请求 |
| `jev_authz_events_total` | counter | `event`（no_client_ip、cut_at_cap） | `/_jev/authz` 收到的、找不到可信客户端地址的请求（没有 `X-Forwarded-For`，或者跳数少于 `trusted_hops`），以及达到或超过 `max_body_bytes`、被当作截断处理的请求体 |
| `jev_adapter_errors_total` | counter | `entry`（access、authz、forward_auth） | 因为判定过程抛异常而失败放行的请求；每一个也会计入 `jev_requests_total{source="adapter",verdict="error"}` |

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
- **覆盖情况：** 按原因拆分的无法判定请求、仪表盘时间范围内按标签和结果拆分的运维人员反馈、主体信誉拦截、适配器错误（未经判定就放行的请求）、按结果拆分的异步重判、按类别拆分的 L2 错误，以及在 `max_inflight` 被拒的 L2 流量占比。

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

1. 在网关上执行 `curl 127.0.0.1:9180/_jev/health`（管理监听端口），并在错误日志里 grep `L2 failed`。
2. 如果原因是 provider 故障，或者 key（`TYPESAFE_API_KEY`）被吊销、配错了，就把它修好。下一次半开探测成功后熔断器会自动关闭，不需要重启。
3. 如果失败都是超时，参考 JevL2TimeoutAtCeiling。

### JevL2ErrorRatioHigh（warning）

10m 内超过 10% 的 L2 调用返回了 `verdict=error`，包括超时、provider 报错和没有返回分数的响应。这些请求会按失败放行处理，同时排进队列等待异步重新判定。

处理步骤：

1. 先用 `sum by (kind) (rate(jev_l2_errors_total[5m]))` 按类别拆开，再到错误日志里找 `jev-edge: L2 failed: <reason>` 看具体原因。
2. `timeout`：把 L2 延迟分位数和超时面板对照着看。provider 本身正常、只是变慢了，就调大 `jev.timeout_max_ms`。
3. `unavailable`：5xx 或 429 是 provider 那边出了故障；401 说明 key 错了或被吊销；404、405 说明 endpoint 或模型名写错了。
4. `rejected`（其余 4xx）或 `unusable`（返回 2xx 却没有分数）：比例接近 100% 就说明 provider 拒绝了每一次调用，常见原因是模型不接受某个参数、key 权限不够，或者前面有 WAF 拦着（参考 JevL2NoVerdicts）。

只有 `transport`、`timeout` 和 `unavailable` 计入熔断，达到 `breaker.fail_ratio` 后接着就会触发 JevBreakerOpen。`rejected` 和 `unusable` 永远不会让熔断打开：送审文本本身就能引出这类失败（内容过滤返回的 400、WAF 返回的 403、模型拒答），不能让客户端借此把 L2 关掉。`busy` 表示网关自己的 `jev.max_inflight` 满了。

### JevUnjudgeableRatioHigh（warning）

15m 内超过 5% 的受检请求无法读取内容。受检请求指的是除了 L1 直接以“无需检查”放行之外的请求。`policy.unjudgeable = "pass"`（默认值）时，这些请求不经判定直接放行；如果设成 `"block"` 并处于 enforce 模式，这些请求会被拒绝，这时这条告警同时也意味着客户端在报错。

用 `sum by (reason) (rate(jev_unjudged_total[5m]))` 按原因拆开看：

- **`body`：** 请求体超过了规则的 `max_body_bytes`，而且头部和尾部都没有文本。要么调大这个限制，要么确认客户端是不是真的会发这么大的请求体。
- **`content-encoding`：** 请求体经过压缩，而当前构建解不开。可能是缺少 zlib 或 libbrotlidec，也可能是数据损坏或者解压后太大。装上对应的库，或者让客户端别再压缩请求。
- **`binary`：** LLM 路由上出现了非文本的请求体。检查规则的路径匹配是不是把上传接口也包进来了。
- **`invalid`：** 声明为 JSON、却被解码器拒收，容错扫描器也找不到任何文本字段。多半是客户端有问题，或者 JSON 用的不是 UTF-8 编码。
- **`json`：** JSON 请求体超出了遍历上限（20,000 个节点、1000 层），剩下的内容不够判定。通常是精心构造的请求体。
- **`partial`：** 前面那层网关截断了请求体，而 `policy.partial = "unjudgeable"`。把网关的请求体上限调到 `max_body_bytes`，或者在网关上直接拒绝更大的请求体。
- **`text`：** enforce 模式下设了 `policy.unjudgeable = "block"`，而文本超出了 `max_judge_chunks`。如果这类请求是正常的，就调大 `max_judge_chunks` 或 `max_judge_bytes`。
- **`multipart`：** multipart 请求体里有超过 8 个不同的 boundary 参数。
- **`token`：** 用 token id 写的提示词，L1 读不懂。正常的 SDK 发的是文本；在规则里设 `token_prompts = "block"` 可以拒绝它们。

### JevL2TimeoutAtCeiling（warning）

`jev_l2_timeout_ms >= jev_l2_timeout_max_ms` 持续 10m。自适应超时已经涨到运维人员设定的上限，说明 provider 的延迟超出了预算，慢的调用会被截断并计为错误。

provider 本身正常、只是变慢了，就调大 `jev.timeout_max_ms`，改配置文件或者调用 `PUT /_jev/config` 都行，reload 时会重建判定器。如果 provider 在持续恶化，接下来会先后触发 JevL2ErrorRatioHigh 和 JevBreakerOpen。

如果 `timeout_max_ms == timeout_ms`，超时没有自适应的空间，会一直停在上限。这种实例请把这条告警静默掉。

`jev_l2_timeout_max_ms` 就是为这条规则才和 `jev_l2_timeout_ms` 一起导出的。它就是 `jev.timeout_max_ms`，默认 1000（见 `core/defaults.lua`）。把 `timeout_ms` 调到 1000 以上时，`timeout_max_ms` 也要一起调高，否则配置会被拒绝（`jev.timeout_max_ms must be >= jev.timeout_ms`），之前的配置继续生效，拒绝原因会记日志并显示为 `config_error`。2.5 × `timeout_ms` 这个兜底值只用于配置里根本没有 `timeout_max_ms` 这个键的情况。

### JevAsyncDropped（warning）

最近 10m 内有异步（L3）重新判定任务被丢弃。原因要么是同时在跑的任务超过了 `async.max_async`，要么是 timer 创建失败。`async.enabled = false` 的情况不计入。

这意味着可疑和出错的请求得不到二次检查，基于信誉的拦截也没法从这些请求中学习。

如果 provider 还有余量，就调大 `async.max_async`。否则就排查是不是突然出现了一批 suspicious 或 error 判定结果，或者 provider 太慢、一直占着异步槽位（`async.timeout_ms`）。

### JevL2Saturated（critical）

5m 内，走到 L2 的请求里有超过 10% 被网关自己的 `jev.max_inflight` 上限拒掉（`jev_l2_errors_total{kind="busy"}`，原因 `max_inflight exceeded`）：根本没有发出调用，请求以 `verdict=error` 放行，而熔断器从不计这类拒绝，所以没有别的告警会响。

如果 provider 还有余量（看它的限流和 L2 延迟面板），就调大 `jev.max_inflight`，或者给 provider 扩容。provider 变慢时每个槽位占用得更久：先看延迟分位数和 JevL2TimeoutAtCeiling，因为 provider 本身在超时的话，调高上限只会把 `busy` 变成 `timeout`。用 Laya profile 时，`max_inflight = 1` 是有意为之的；要等 `make conformance` 在新的 `CONCURRENCY` 下通过之后再调高。

### JevAsyncFailing（warning）

最近 10m 里跑过的异步（L3）重判任务，一半以上没有拿到答复，并且持续了 5m。suspicious 和出错的请求得不到第二次判定：不会有缓存下来的判定结果，信誉封禁也学不到东西。

用 `sum by (result) (increase(jev_async_total[10m]))` 拆开看。`failed`：在错误日志里找 `L3 judge failed`（provider 出错，或者 L3 超时对这个 provider 来说太短）。`no_scores`：provider 有答复，但没给要求的分数（模型或模板不对）。`busy`：自定义判定器自己的上限。`error`：错误日志里的 `L3 error`，是 bug。

### JevAdapterErrors（critical）

最近 5m 里，有请求经某个入口（`access`、`authz`、`forward_auth`）未经判定就放行了，因为判定过程抛了异常：`verdict=error`，`source=adapter`。所有请求都这样失败时，上面那些按比例计算的告警根本看不到 L2 流量，这条告警就是为此而设的。

在错误日志里找 `jev-edge: <entry> error, failing open`。如果是刚改过配置：先 `GET /_jev/config`（看 `config_error`），再用 `DELETE /_jev/config` 去掉覆盖，或者修好配置文件。否则就是 bug：请报告这行日志。

### JevL2Starved（critical）

10m 内一直有请求走到 L2 阶段（`source=breaker`），但没有任何一次 L2 调用给出判定结果。这条告警和 JevBreakerOpen 是一对，区别在于它依据的是流量：即使抓取熔断器状态 gauge 时恰好处在半开状态，它照样会触发。

处理方法和 JevBreakerOpen 相同。判定结果缓存会继续为已经判定过的文本提供结果，新文本在 L2 恢复前都不经判定直接放行。

### JevL2NoVerdicts（critical）

10m 内每一次 L2 调用都以 `verdict=error` 收场，没有一次给出判定结果，不管熔断器处于什么状态。provider 如果因为熔断不计入的原因拒绝每一次调用（模型参数不对返回 400、WAF 返回 403、响应里没有分数），熔断器就一直关着，JevBreakerOpen 和 JevL2Starved 都不会响，可实际上 L1 之后已经什么都没在判定了。

处理步骤：

1. 用 `sum by (kind) (rate(jev_l2_errors_total[5m]))` 按类别拆开，再到错误日志里找 `jev-edge: L2 failed: <reason>`。
2. `rejected`：provider 拒绝了调用。检查模型参数、key 的权限，以及 provider 前面有没有别的东西拦着。
3. `unusable`：provider 有响应，但格式不是判定器要的。检查模型名和模板。
4. `busy`：`jev.max_inflight` 满了，调大它或者扩容。
5. `unavailable`、`transport` 或 `timeout`：按 JevBreakerOpen 处理。

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
