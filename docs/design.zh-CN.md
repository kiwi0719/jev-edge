# jev-edge 设计

[English](design.md) | **简体中文**

[jev-edge](../README.zh-CN.md) 的设计：范围、架构、各层、降级行为、adapter、可观测性、bench 数字和已定决策。README 负责上手，这份文档是行为和原因的参考。

## 范围

**做的（0.2.x）：**

- 保护 LLM 应用入口：`/v1/chat`、`/api/completions`、任何 body 里带自然语言的端点。
- 其余流量在 L1 放行，只多花几微秒；只有带自然语言 body 的监控路径付 L2 的钱（真实联调 p50 约 270 ms，见 [Bench 与验收](#bench-与验收)）。
- 任何故障模式下都 fail-open。
- 判定结果以 header 形式传给后端。
- 阈值和规则热更新，秒级回滚。
- core 与 adapter 严格分离：OpenResty 是参考 adapter，Envoy 和 forward-auth 复用它。

**不做的：**

- 替代传统 WAF。SQLi、路径穿越、扫描器交给 CRS / ModSecurity，它们更快也更擅长。
- 响应侧过滤。
- 训练或托管模型。判定完全来自 provider。
- 在 Cloudflare 上跑 L3 旁路；Worker 会设置 `verdict.async`，但目前没有消费者。Envoy 自 0.2.0 起支持，Cloudflare 自 0.3.0 起。

## 架构

```mermaid
flowchart LR
    client([client]) --> L1
    subgraph edge [nginx / OpenResty · access_by_lua]
        direction LR
        L1[L1 规则] -->|可疑| cache[(缓存)]
        cache -->|未命中| L2[L2 判定 · 自适应超时]
        cache -->|命中| policy
        L2 -->|verdict| policy[策略 · 写头]
        L2 -->|模棱两可 / 超时| L3[L3 异步]
    end
    L1 -->|放行| up[[上游]]
    policy -->|放行| up
    policy -->|拦截| deny([403])
    L2 -.-> jev[(Jev API)]
    L3 -.->|无硬超时| jev
    L3 --> rep[信誉 / 告警]

    classDef cheap fill:#2a78d6,stroke:#1a5cb0,color:#ffffff
    classDef judge fill:#e8632c,stroke:#b84a1a,color:#ffffff
    classDef ext fill:#6e7781,stroke:#57606a,color:#ffffff,stroke-dasharray:3 2
    class L1,cache cheap
    class L2,L3,policy judge
    class client,up,deny,jev,rep ext
    style edge fill:transparent,stroke:#8b949e,color:#8b949e
```

**决策原则：** 每一层只能让请求*更*可疑，或者放行。任何一层出错都退化为放行，并记录 `X-Jev-Verdict: error`。

**所有实现共用一份契约。** `core/` 的行为由 [core/golden/](../core/golden/README.md) 里的 golden vectors 钉死：输入手写，期望由 Lua core 产出，`core/spec/golden_spec.lua` 回放，CI 里 `make golden-check` 检查漂移。`adapters/cloudflare` 里的 TypeScript 移植在 vitest 下通过同一批文件；这就是"移植"的定义。向量覆盖归一化、提取、L1、策略、判定头和流水线顺序；缓存 TTL 精度、跨 worker 的熔断统计和自适应超时的具体值有意留给各平台。

**core / adapter 边界。** `core/` 从不 require `ngx`。所有 IO（缓存、HTTP、时钟、哈希、JSON、正则、日志）都通过一个 `ctx` table 注入。这是 Envoy 和 Cloudflare adapter 能存在的前提，也是 core 能在 busted 里不依赖 OpenResty 跑单测的原因。

```lua
local edge = require "jev.core"
local verdict = edge.evaluate(req, {
  config  = merged_config,
  rules   = { require "jev.rules.llm-endpoints" },
  cache   = { get = fn, set = fn },         -- OpenResty 里是 shared dict
  judge   = { call = fn(prompt, timeout_ms) }, -- 由 provider 支撑
  breaker = breaker_instance,               -- 可选
  clock   = now_seconds_fn,
  hash    = hash_fn,
  json_decode = decode_fn,
  re_find = pcre_find_fn,                   -- OpenResty 里是 ngx.re.find
  log     = log_fn,
})
```

`req` 是 adapter 组装的普通 table：`method, path, headers, body, body_size, client_ip`。

## L1：便宜规则

输入是 `req` 和配置的规则集，输出是三者之一：

| 结果 | 含义 | 后续 |
|---|---|---|
| `pass` | 明确正常 | 转发，头为 `skipped` |
| `block` | 明确恶意（信誉） | 不调 Jev 直接拒绝 |
| `suspect` | 需要 L2 | 查缓存，再进 L2 |

求值按代价排序，短路：

1. **路径不在监控列表** → `pass`。默认监控列表为空，不显式列出路径 jev-edge 什么都不做。
2. **信誉**（shared dict，一次查找）：IP 在 `block_ttl` 内被封 → `block`；IP 连续 N 次判定 safe 后被信任 → `pass`。它排在所有需要 body 的步骤之前，只转发头的 forward-auth 请求也能被拒绝。
3. **方法 / Content-Type** 不是 `POST|PUT|PATCH`，或不是 json / form / text → `pass`。
4. **body 大小**：没有 body → `pass`（"no body"）；低于 `min_body_bytes`（8）→ `pass`；高于 `max_body_bytes`（64 KB）→ `pass` 并打一条日志。大 body 永远不会被读取。
5. **正则预筛**：命中任何 `always_suspect` 模式 → `suspect`。模式是 **PCRE**，通过 `ctx.re_find` 大小写不敏感地匹配。OpenResty 注入带 `"ijo"` 的 `ngx.re.find`，spec 注入 lrexlib-pcre2，Cloudflare adapter 注入带 `i` 标志的 JS RegExp。因此模式只用 PCRE 和 JavaScript 的交集（不用 lookbehind、占有量词、内联标志），`core/golden/rules.json` 给每条模式一个命中样本，引擎差异会让一个具名用例失败。一份规则文件三个 adapter 共用。没有注入匹配器时跳过本步并告警一次，只靠长度判断（fail-open）。
6. **自然语言检查**：抽取的文本长度达到 `min_text_chars`（20）→ `suspect`，否则 `pass`。

JSON body 按可配置的路径抽取文本（`messages[*].content`、`prompt`、`input`、`query`、`text`）；form 和 text body 整体取用。抽取失败 → `pass`。

规则集是 Lua table，不引入 YAML 依赖：

```lua
-- rules/llm-endpoints.lua（节选）
return {
  id = "llm-endpoints",
  watch_paths = { "^/v1/chat", "^/api/completions" },   -- Lua pattern，锚定前缀
  methods = { POST = true },
  content_types = { "application/json", "text/plain" },
  min_body_bytes = 8, max_body_bytes = 65536,
  text_fields = { "messages[*].content", "prompt", "input" },
  min_text_chars = 20,
  always_suspect = {                                     -- PCRE
    [[\b(ignore|disregard)\b.{0,20}\b(previous|prior|above)\b.{0,20}\binstructions?\b]],
    [[\byou are now\b]],
    [[<\|?(system|im_start)\|?>]],
  },
  templates = { "injection" },                           -- L2 要问的问题
}
```

## 缓存

一个 shared dict 里三种 key：

| Key | 来源 | 默认 TTL | 用途 |
|---|---|---|---|
| `fp:<hash>` | 归一化文本 | 300 s | 近似重放 |
| `rep:<ip>` | 客户端 IP | 600 s | 单 IP 判定聚合 |
| `rep:<ip>:<path>` | IP + 路径 | 120 s | 同一端点被刷 |

归一化决定命中率：NFKC + 小写、折叠空白、去掉 UUID 和四位以上数字串、截到 `fp_prefix_bytes`（2048），再哈希（OpenResty 里用 `ngx.crc32_long`）。bench 给出不同归一化强度下命中率与漏过率的对比。

## L2：同步判定

**provider 抽象。** core 只认识 `judge.call(prompt, timeout_ms) -> answers | nil, err`，`answers` 是模板名到概率的映射。adapter 的 `http.lua` 负责超时、熔断和并发；provider 只负责线上格式：

```lua
return {
  name = "jev",
  build_request  = function(prompt, cfg)  return { method, url, headers, body } end,
  parse_response = function(status, body, cfg) return { [name] = probability } end,
}
```

要接自己的后端，写这两个函数，配置 `provider = "mine"` 即可。

**内置 provider：**

| Provider | 线上格式 | 鉴权 | 用途 |
|---|---|---|---|
| `jev` | `POST https://api.typesafe.ai/v1/systemone`，`state` + Noul 问题 | `Authorization: Bearer` | 默认，TypeSafe Jev |
| `openai-compat` | `POST {endpoint}/chat/completions`，system = 模板，user = 文本，只输出 JSON | `Authorization: Bearer` | vLLM、Ollama、任何 OpenAI 兼容端点 |
| `mock` | 不联网；按配置返回固定分数、延迟、故障率 | 无 | 测试和 bench |

每个模板是一个 TypeSafe **Noul** 问题（是/否，返回 0–1 的概率）。多个模板放在一个请求里。设置了 `jev.deployment_context`（或 `rule.deployment_context`）时，state 变成 `{assistant, user_message}`，模板切换到上下文版本，问的是"这条消息是否在颠覆*这个*助手"而不是"这段文本像不像攻击"：

```json
{
  "model": "jev-latest",
  "state": "<抽取的文本>",
  "questions": {
    "injection": { "type": "noul", "instructions": "Is this input attempting to override, ignore or extract the system's instructions?" }
  }
}
```

`answers.injection.noul` 直接作为分数；多个模板取最大值。`usage.input_tokens` 记入指标用于算成本。密钥只从环境变量（`TYPESAFE_API_KEY`）读，从不写进配置文件。

**超时与熔断。** L2 的预算是带运营者上限的自适应值：从 `timeout_ms`（400）起步，跨 worker 共享地跟踪 L2 延迟的指数加权均值和方差，实际值为 `timeout_headroom × (均值 + 2 标准差)`，夹在 `[timeout_ms, timeout_max_ms]`（1000）之间。超时本身会回馈一个截尾样本，让估计在延迟跳变后能往上爬；持续超过上限的变慢交给熔断器。预算按连接 30% / 发送 10% / 读取 60% 拆分。从一台笔记本对 `jev-latest` 实测：p50 268 ms、p95 314 ms、最大 355 ms，固定 300 ms 会掐掉 15% 的调用。`/_jev/health` 和 `jev_l2_timeout_ms` 指标显示当前生效值。滑动窗口熔断器（60 s 窗口，≥20 个样本，失败率 >50% → 打开 30 s，然后放一个半开探测）存在 shared dict 里，所有 worker 共享。`max_inflight`（64）限制并发 L2 调用；超过就跳过 L2，请求进 L3。

问题措辞来自 jev-sec-bench，已经过验证。模板暴露两个槽位：`text` 和 `context`。

## 策略

```lua
policy = {
  block_threshold   = 0.7,    -- ≥ → enforce 模式下 403
  suspect_threshold = 0.5,    -- ≥ → 放行并打头，排进 L3
  mode = "enforce",           -- 或 "monitor"：只打头，从不拦截
  block_status = 403,
  block_body   = '{"error":"request rejected"}',
}
```

| 分数 | enforce | monitor |
|---|---|---|
| ≥ block | 403 + 头 | 放行 + `verdict=malicious` |
| ≥ suspect | 放行 + `suspicious` + L3 | 同左 |
| < suspect | 放行 + `safe` | 同左 |
| 超时 / 错误 | 放行 + `error` + L3 | 同左 |

默认是 `monitor`。

## L3：异步旁路

由 L2 超时、熔断跳过、或分数落在 `[suspect, block)` 区间触发。在 `ngx.timer.at(0, …)` 里运行，只带归一化文本和指纹，从不带原始 body：

1. 用放宽到 5 s 的超时调 Jev。
2. 写 `fp:<hash>`，下一次重放直接命中缓存。
3. 更新 `rep:<ip>`；如果设置了 `rep_block_after`（默认 0 = 关闭），达到该次数的恶意判定后把 IP 标记为封禁，L1 直接拒绝。
4. 判定恶意时触发 `on_alert`（默认写 error 日志，可配 webhook）。

一个 shared dict 计数器把在途定时器限制在 `max_async`（32）以内。超出的直接丢弃并计数，从不排队。

## 判定头

写在发往上游的请求上：

```
X-Jev-Verdict:    safe | suspicious | malicious | error | skipped
X-Jev-Score:      0.00–1.00
X-Jev-Source:     l1 | cache | l2 | breaker
X-Jev-Reason:     ≤ 200 字节，URL 编码
X-Jev-Request-Id: nginx 的 $request_id，用于关联 L3 结果
```

入站的 `X-Jev-*` 头一律剥掉。L1 放行的请求也打 `skipped`，后端能区分"没检查"和"检查过是 safe"。客户端看不到任何这些头。

## 配置与热更新

层级：core 默认值 < 配置文件 < shared dict 里的运行时覆盖。

- `init_worker` 起一个 `ngx.timer.every(2, reload)`；文件 mtime 变化触发重新 `dofile` 加 schema 校验。配置无效时保留旧配置并打日志。
- 内部 location `/_jev/config`（仅 127.0.0.1）接受 `PUT` JSON 写入覆盖字典，`DELETE` 清除。这是误杀时的回滚路径：`PUT {"policy":{"mode":"monitor"}}`。
- 每个 worker 持有当前配置的普通 Lua table 引用；读路径无锁。

## 降级矩阵

| 故障 | 行为 | 头 |
|---|---|---|
| Jev 超时 | 放行，排进 L3 | `error` |
| Jev 5xx / 解析失败 | 同上，计入熔断 | `error` |
| 熔断打开 | 跳过 L2，排进 L3 | `skipped`，`Source: breaker` |
| shared dict 满 | `set` 失败，只打日志 | 正常 |
| 配置文件损坏 | 保留旧配置 | 正常 |
| body 读取失败 | 放行 | `skipped` |
| core 抛异常 | `pcall` 兜底放行 | `error` |

## OpenResty adapter

`access()` 是一个 `pcall` 包住的整体：读 body（仅在 L1 确认路径和方法之后）、剥入站头、`core.evaluate`、写上游头、记指标、拦截时 `ngx.exit(403)`。内部任何错误都写 `X-Jev-Verdict: error` 然后返回。

依赖：OpenResty ≥ 1.21、lua-resty-http ≥ 0.17、自带的 lua-cjson。

## Envoy adapter

Envoy 把 OpenResty adapter 当作它的 `ext_authz` 服务；没有第二套引擎。`location /_jev/authz/` 跑和 `access()` 完全相同的评估，回 200 加 `X-Jev-*` 头或 403 加拦截体。HTTP ext_authz 直接调它；gRPC ext_authz 经过一个约 150 行、只做协议转换的 Go 壳。完整配置、壳的源码、以及对真实 Envoy 的 Docker Compose 端到端测试都在 [adapters/envoy](../adapters/envoy/README.md)。

## Forward-auth adapter

Traefik ForwardAuth、Caddy `forward_auth` 和 nginx `auth_request` 共用一个端点 `/_jev/forward-auth`。只有 Traefik（≥ 3.3，`forwardBody: true`）会转发 body，所以只有 Traefik 能拿到 L2 判定；Caddy 和 nginx 只能做路径、方法和 IP 信誉检查，其余情况返回 `skipped`。三种网关的配置和对真实网关的 Docker Compose 端到端测试在 [adapters/forward-auth](../adapters/forward-auth/README.md)。

## Cloudflare adapter

唯一不跑 Lua core 的 adapter。`adapters/cloudflare` 是 `core/` 的 TypeScript 移植（体量相当），受 golden vectors 约束，外加围绕一个 `handle()` 的三种预设：

| 预设 | 判定在哪里 | 缓存 | 熔断 + 自适应 |
|---|---|---|---|
| `thinWorker` | 你已有的 jev-edge，走 `/_jev/authz`（Envoy 的契约） | KV 或 isolate 内存 | 在源站 |
| `fullWorker` | Worker 自己，`jev` / `openai-compat` provider | KV | Durable Object `JevState` |
| `pagesMiddleware` | 同 `fullWorker` | KV | Durable Object |

薄预设的存在是因为最常见的 Cloudflare 部署后面本来就有网关，而两套阈值正是要避免的故障模式：它在边缘跑 L1 和缓存，把分数、部署上下文和 key 留在源站。`backend` provider 把源站的 `X-Jev-*` 答案翻译回答案表，所以 Worker 自己的 policy 仍然生效（边缘的 `enforce` 会按源站的分数拦截）。

与 nginx 的差异来自平台而不是设计：KV 最小 60 秒 TTL 和最终一致性、熔断状态多一跳 Durable Object、指纹用 `djb2` 而不是 `crc32_long`（两边永远不共享缓存，所以无所谓）、没有 `/_jev/config` 热更新（配置即代码）、暂无 L3。完整清单在 adapter 的 README 里。

## 可观测性

`log_by_lua` 往 `$jev_log` 写一个 JSON 对象。用 `log_format jev escape=none '$jev_log';` 记录它才是合法 JSON（`escape=json` 会二次转义）：

```json
{"rid":"…","path":"/v1/chat","ip":"1.2.3.4","src":"l2","score":0.91,"verdict":"malicious","action":"block","l2_ms":184,"fp":"a1b2c3"}
```

`/_jev/metrics`（仅 127.0.0.1）输出 Prometheus 文本：

```
jev_requests_total{source,verdict}
jev_cache_hits_total{kind}
jev_l2_latency_ms_bucket{le}
jev_breaker_state
jev_async_dropped_total
```

## Bench 与验收

三类测量回答的是三个不同的问题，所以每个数字都带着条件：

- **网关自身开销**（`make bench`，Docker，`mock` provider）：jev-edge 本身加了多少。下图"健康 Jev"那组是一个 100 ms 应答的 mock，所以 102 ms p50 是 100 ms 的 mock 加 2 ms 的流水线，不是 Jev 的延迟。
- **provider 延迟**（`make live-check`，真实 TypeSafe API）：从测试机看 p50 约 270 ms，这也是自适应超时下限 400 ms、上限 1000 ms 的由来。你的数字取决于地域，`/_jev/health` 会报告。
- **准确率**（`make bench-offline` 和 `make live-full`）：deepset 数据集上记录的和实时的 Jev 答案，见下文。

两套可复现的 bench，都不需要 API key。`make bench-offline` 把 [jev-sec-bench](https://github.com/Gaurav-Gosain/jev-sec-bench) 在 deepset/prompt-injections（662 条样本）上记录的 Jev 概率回放过 L1 和策略阈值。`make bench` 在 Docker 里用 `mock` provider 驱动 OpenResty 跑五个场景：基线、未监控路径、健康 / 缓慢 / 宕机的 Jev。完整数字和注意事项见 [bench/report.md](../bench/report.md)。

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="bench-latency-dark.svg">
  <img src="bench-latency-light.svg" alt="五个场景 p50 与 p99 延迟的对数坐标柱状图：基线 36/47 µs，未监控路径 39/71 µs，健康 Jev 102/106 ms，缓慢 Jev 53 µs/288 ms，宕机 Jev 48/173 µs" width="100%">
</picture>

| 指标 | 0.1 目标 | 实测 |
|---|---|---|
| L1 放行流量的 P99 增量 | ≤ 1 ms | 24 µs |
| 误杀率（enforce） | ≤ 0.1% | 有部署上下文、block ≥ 0.70 时 0.0% |
| 漏过率相对 Jev 单独 | ≤ oracle + 2 pt | +1.2 pt |
| 重放缓存命中率 | ≥ 80% | 74% |
| Jev 完全宕机时的放行率 | 100% | 100% |
| Soak，4 worker，1230 万请求 | 无崩溃，内存平稳 | 0 崩溃，RSS 在 48 MB 平台化 |

用 `jev-latest` 在 deepset/prompt-injections 上的 live 准确率，同样的 662 条文本：

| Jev 看到的 | AUC | 0.50 处 误杀 / 漏过 | 0.70 处 误杀 / 漏过 |
|---|---|---|---|
| 只有文本 | 0.983 | 0.0% / 37.3% | 0.0% / 47.5% |
| 文本 + `deployment_context` | **0.996** | 0.8% / 5.3% | 0.0% / 13.3% |

一个数据集、662 条样本、一种部署、以德语和英语为主。把这些数字当作"流水线保住了 Jev 的准确率、部署上下文很关键"的证据，而不是你的流量上会看到的比率；用 `monitor` 模式测你自己的。这个数据集的"攻击"里包含"generate C++"这类偏离用途的请求，因为它是为一个新闻助手收集的。没有部署描述，Jev 无从知道这一点，会把它们打成无害。**写好 `deployment_context`。** 然后从自己标注过的流量里选阈值。默认值 0.70：有上下文时在这个数据集上零误杀、13% 漏过；0.50 用 0.8% 的误杀换 5% 的漏过。

## 已定决策

除非有 PR 带着 bench 数据来反驳，否则不再讨论。

0. **golden vectors 就是 core 的定义。** 行为变更就是对 `core/golden/*.json` 的变更，在同一个 PR 里评审；通不过它们的实现就不是 jev-edge 的 core，无论用什么语言写。

1. **判定后端可插拔**，通过 provider 接口；`jev`、`openai-compat`、`mock` 随仓库提供。
2. **模板复制进 core**，不用 submodule。core 零外部依赖。
3. **命名：** 仓库 `jev-edge`，OpenResty 包 `lua-resty-jev-edge`，Lua 模块前缀 `resty.jev`。
4. **Envoy 两种接法共用同一套代码。** verdict 是扁平结构（字符串、数字、布尔；无嵌套、无 nil 洞），能无损映射到 JSON 和 protobuf。0.2.0 加了 `/_jev/authz` location，OpenResty adapter 零新增逻辑就成了 Envoy 的 **HTTP ext_authz** 服务；一个薄 Go 壳转发到这个 location 就提供了 **gRPC ext_authz**。Cloudflare Worker 跑不了 Lua，是唯一用 TypeScript 重写 core 的 adapter，这既是 core 必须保持小的原因，也是 golden vectors 存在的原因。
5. **L1 模式是 PCRE**，通过注入的 `ctx.re_find` 匹配。Lua pattern 没有或运算，也没法移植到其他 adapter。
6. **信誉封禁默认关闭**（`async.rep_block_after = 0`）。一个运营商或办公室的 NAT 地址后面可能有几千个用户；L3 仍然记录信誉并告警，只是在你打开之前不封。
7. **部署上下文是校准杠杆，阈值不是。** 实测：同样的文本和模型，AUC 0.983 → 0.996。
