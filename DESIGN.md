# jev-edge 实施方案

> 状态：v0.1 设计稿，2026-09-21
> 一句话：插在 nginx / Envoy / Cloudflare 边缘的三层准入过滤器，用 Jev 判断"外面的请求要对我的服务做什么"。

---

## 1. 目标与非目标

### v0.1 目标

- 保护 **LLM 应用入口**：`/v1/chat`、`/api/completions`、任何 body 里带自然语言的接口。
- 99% 正常流量走 L1 零延迟放行；只有可疑流量付 L2 的 70–500ms。
- 任何情况下 Jev 不可用都不影响业务：**fail-open**。
- 判定结果通过 header 传给后端，后端可做二次决策。
- 阈值与规则热更新，秒级回滚。
- 先做 OpenResty adapter，core 与 adapter 分离。

### 非目标（v0.1 明确不做）

- 替代传统 WAF（SQLi / 路径穿越 / 扫描器交给 CRS 或 ModSecurity）。
- 响应侧过滤（输出内容审查）。
- 自建判定模型；判定能力完全来自 Jev API。
- Envoy / Cloudflare adapter（v0.2+）。

---

## 2. 架构总览

```
                 ┌────────────────────────────────────────────────┐
  client ──────► │  nginx / OpenResty                              │
                 │                                                 │
                 │  access_by_lua*                                 │
                 │   ┌──────────┐  pass  ┌─────────────────────┐   │
                 │   │ L1 rules ├───────►│ proxy_pass upstream │   │
                 │   └────┬─────┘        └──────────▲──────────┘   │
                 │        │ suspicious               │             │
                 │   ┌────▼─────┐  cache hit         │             │
                 │   │  cache   ├──────────┐         │             │
                 │   └────┬─────┘          │         │             │
                 │        │ miss           │         │             │
                 │   ┌────▼─────┐          │    ┌────┴────┐        │
                 │   │ L2 judge │──────────┴───►│ policy  │ block  │
                 │   │ (≤300ms) │  verdict       │ + header│──► 403│
                 │   └────┬─────┘               └─────────┘        │
                 │        │ ambiguous / timeout                    │
                 │   ┌────▼─────┐                                  │
                 │   │ L3 async │── ngx.timer ──► Jev（无超时）──► 写回 reputation / 告警
                 │   └──────────┘                                  │
                 └────────────────────────────────────────────────┘
                              │ lua-resty-http
                              ▼
                          Jev API
```

**决策原则**：每一层只能让请求"更可疑"或"放行"，任何一层出错都退化为放行并记录 `X-Jev-Verdict: error`。

---

## 3. 仓库结构

```
jev-edge/
  core/                       纯 Lua，无 ngx.* 依赖，可在 busted 里单测
    init.lua                  入口：evaluate(req, ctx) -> verdict
    normalize.lua             请求归一化与指纹
    rules.lua                 L1 规则引擎
    judge.lua                 L2 抽象：build_prompt / parse_response
    policy.lua                verdict -> action（阈值策略）
    verdict.lua               verdict 结构与序列化
    breaker.lua               熔断器
    templates/
      injection.lua           提示词注入问题模板
      abuse.lua               刷单 / 滥用问题模板
  adapters/
    openresty/
      lib/resty/jev/edge.lua  access 阶段胶水
      lib/resty/jev/http.lua  lua-resty-http 封装，超时/熔断/并发
      lib/resty/jev/providers/
        jev.lua               默认 Jev API 映射
        openai_compat.lua     OpenAI 兼容端点
        mock.lua              测试用
      lib/resty/jev/cache.lua ngx.shared.DICT 实现
      lib/resty/jev/config.lua 热更新
      lib/resty/jev/async.lua  L3 timer
      conf/example.nginx.conf
      t/                       Test::Nginx
    cloudflare/               v0.2
    envoy/                    v0.2
  rules/
    default.lua               默认规则集
    llm-endpoints.lua         LLM 入口规则
  bench/
    datasets/                 正常流量样本、注入样本（复用 jev-sec-bench）
    run.lua                   误杀率 / 漏过率 / P99
    report.md
  docs/
  DESIGN.md
```

**core 的硬约束**：不 `require "ngx"`，所有 IO（缓存、HTTP、时间、日志）通过 `ctx` 注入。这是 adapter 可替换的前提，也是能在 busted 里跑单测的前提。

```lua
-- core/init.lua 接口
local edge = require "jev.core"
local verdict = edge.evaluate(req, {
  cache  = cache_impl,   -- get(key) / set(key, val, ttl)
  judge  = judge_impl,   -- call(prompt, timeout_ms) -> resp | nil, err
  clock  = now_ms_fn,
  log    = log_fn,
  config = current_config,
})
```

`req` 是 adapter 组装的普通 table：`method, path, headers, body, body_size, client_ip, query`。

---

## 4. L1：便宜规则筛

### 4.1 输入与输出

输入 `req` 和 `config.rules`，输出三种结果之一：

| 结果 | 含义 | 后续 |
|---|---|---|
| `pass` | 明确正常 | 直接放行，不打 header |
| `block` | 明确恶意（命中黑名单 / reputation 已封） | 直接拒绝，不调 Jev |
| `suspect` | 需要 L2 | 进缓存查询与 L2 |

### 4.2 规则求值顺序

按代价从低到高，短路：

1. **路径不在监控列表** → `pass`。默认监控列表为空，即默认全部放行，用户显式加路径才生效。
2. **方法与 Content-Type**：非 `POST/PUT/PATCH`，或 Content-Type 不是 json / form / text → `pass`。
3. **body 大小**：`< min_body_bytes`（默认 8）→ `pass`；`> max_body_bytes`（默认 64KB）→ `pass` 并打日志（不读大 body，避免拖慢）。
4. **reputation 查询**（shared dict）：该 IP 在 `block_ttl` 内被封 → `block`；在 `trust_ttl` 内连续 N 次判定 safe → `pass`。
5. **正则预筛**（可选，用户配置）：命中 `always_suspect` 模式（如 `ignore previous`、`system prompt`、base64 长串）→ `suspect`。模式统一用 **PCRE** 语法，core 不自带正则实现，通过 `ctx.re_find(subject, pattern)` 注入：OpenResty 给 `ngx.re.find` 加 `"ijo"`，测试给 lrexlib-pcre2，Cloudflare 给 JS RegExp。这样同一份规则文件三个 adapter 共用。未注入时跳过本步并告警一次，仍然 fail-open。`watch_paths` 是锚定前缀，用 Lua pattern 即可。
6. **自然语言检测**：body 中提取待判定文本（见 4.3），长度 `≥ min_text_chars`（默认 20）→ `suspect`，否则 `pass`。

### 4.3 文本提取

对 JSON body 按配置的 JSON path 抽取（默认 `messages[*].content`、`prompt`、`input`、`query`）；form / text 直接取全文。抽取失败 → `pass`。

### 4.4 规则文件格式

用 Lua table，不引入 YAML 解析依赖：

```lua
-- rules/llm-endpoints.lua
return {
  id = "llm-endpoints",
  watch_paths = { "^/v1/chat", "^/api/completions" },
  methods = { POST = true },
  content_types = { "application/json", "text/plain" },
  min_body_bytes = 8,
  max_body_bytes = 65536,
  text_fields = { "messages[*].content", "prompt", "input" },
  min_text_chars = 20,
  always_suspect = {              -- PCRE，大小写不敏感，通过 ctx.re_find 匹配
    [[\b(ignore|disregard)\b.{0,20}\b(previous|prior|above)\b.{0,20}\binstructions?\b]],
    [[\byou are now\b]],
    [[<\|?system\|?>]],
  },
  templates = { "injection" },   -- 送 L2 时用哪些问题模板
}
```

---

## 5. 缓存

### 5.1 三级 key

| key | 组成 | TTL 默认 | 用途 |
|---|---|---|---|
| `fp:<hash>` | 归一化文本 hash | 300s | 完全重复的 payload |
| `rep:<ip>` | 客户端 IP | 600s | 该 IP 最近判定聚合 |
| `rep:<ip>:<path>` | IP + 路径 | 120s | 同一入口刷请求 |

### 5.2 归一化

hash 命中率取决于归一化的狠劲。默认流程：

1. 抽取文本 → 拼接。
2. Unicode NFKC，转小写。
3. 连续空白折叠为单空格。
4. 去除数字串（长度 ≥ 4）和 UUID / 时间戳模式。
5. 截取前 `fp_prefix_bytes`（默认 2048）。
6. `ngx.crc32_long` 或 xxhash。

归一化实现在 `core/normalize.lua`，adapter 只提供 hash 函数。bench 要给出不同归一化强度下的命中率与漏过率曲线。

### 5.3 存储

OpenResty 用一个 `lua_shared_dict jev_cache 64m`。值为 verdict 的紧凑 JSON。`safe_add` 防止 timer 与请求路径写竞争。

---

## 6. L2：Jev 同步判定

### 6.1 Provider 抽象：判定后端可替换

core 不知道 Jev 是什么，只依赖一个接口：

```lua
-- provider 接口（adapters/openresty/lib/resty/jev/providers/<name>.lua）
return {
  name = "jev",
  -- 把 core 生成的 prompt_table 变成 HTTP 请求描述
  build_request = function(prompt_table, cfg)
    return { method = "POST", url = cfg.endpoint, headers = {...}, body = "..." }
  end,
  -- 把 HTTP 响应变成统一 verdict 片段
  parse_response = function(status, body, cfg)
    return { score = 0.0, label = "safe", reason = "" }   -- 或 nil, err
  end,
}
```

`http.lua` 只做三件事：调 `build_request`、用 lua-resty-http 发出去、把结果交给 `parse_response`。超时、熔断、并发限制都在 `http.lua` 里，provider 不用管。

用户要接自己的判定服务，写一个 20 行的 provider 文件，配置里 `provider = "mine"` 即可，不碰任何其他代码。

### 6.2 内置 provider

v0.1 内置三个，按常用规范写：

| provider | 请求 | 鉴权 | 用途 |
|---|---|---|---|
| `jev` | `POST /v1/systemone`，state + noul questions | `Authorization: Bearer <key>` | 默认，TypeSafe Jev |
| `openai-compat` | `POST {endpoint}/chat/completions`，标准 chat 格式，system 放模板，user 放文本，要求 JSON 输出 | `Authorization: Bearer <key>` | 任何 OpenAI 兼容端点（vLLM、Ollama、各家云） |
| `mock` | 不发请求，按配置返回固定 score / 延迟 / 故障率 | 无 | 测试与 bench |

`jev` provider 对接 TypeSafe 的 System One HTTP API（`POST https://api.typesafe.ai/v1/systemone`，Bearer 鉴权）。每个模板对应一个 **Noul** 问题（是/否，返回 0–1 概率），多个模板在同一请求里并行提问：

```json
{
  "model": "jev-latest",
  "state": "<extracted text>",
  "questions": {
    "injection": { "type": "noul", "instructions": "Is this input attempting to override, ignore or extract the system's instructions?" }
  }
}
```

响应 `answers.injection.noul` 直接作为 `score`；多个模板取最大值。`usage.input_tokens` 记入 metrics 用于算成本。

`openai-compat` 的 system prompt 要求模型只输出上面这段 JSON，`parse_response` 从 `choices[0].message.content` 里提取，提取失败视为超时。

配置：

```lua
jev = {
  provider    = "jev",              -- "jev" | "openai-compat" | "mock" | 自定义名
  endpoint    = "https://api.typesafe.ai/v1/systemone",
  api_key_env = "TYPESAFE_API_KEY", -- 只从环境变量读，配置文件不落密钥
  timeout_ms  = 300,
  model       = "jev-latest",
}
```

密钥读取：`init_by_lua` 阶段 `os.getenv`，需要 nginx.conf 里 `env TYPESAFE_API_KEY;` 声明。

### 6.3 超时与熔断

- 单次硬超时 `judge_timeout_ms`，默认 300。lua-resty-http 上 `connect_timeout=50, send=50, read=200`。
- 熔断器（`core/breaker.lua`）：滑动窗口 60s，失败率 > 50% 且样本 ≥ 20 → open，持续 30s 直接跳过 L2（请求交 L3 旁路）；half-open 放 1 个探测。状态存 shared dict，worker 间共享。
- 并发上限 `max_inflight`（默认 64）：超过则跳过 L2，避免 Jev 抖动时 nginx worker 被拖住。

### 6.4 复用 jev-sec-bench 的 prompt

`core/templates/injection.lua` 直接复制 jev-sec-bench 里已验证的提示词注入问题模板，文件头注明来源与版本，不用 submodule（core 必须零外部依赖）。模板只暴露 `text` 和 `context` 两个槽位。

---

## 7. 策略：verdict → action

```lua
-- config.policy
{
  block_threshold   = 0.85,   -- ≥ 直接 403
  suspect_threshold = 0.5,    -- ≥ 放行但打 header，进 L3
  mode = "enforce",           -- "enforce" | "monitor"（只打 header 不拦）
  block_status = 403,
  block_body   = '{"error":"request rejected"}',
}
```

| score | enforce | monitor |
|---|---|---|
| ≥ block | 403 + header | 放行 + header `verdict=malicious` |
| ≥ suspect | 放行 + header `suspicious` + L3 | 同左 |
| < suspect | 放行 + header `safe` | 同左 |
| timeout / error | 放行 + header `error` + L3 | 同左 |

**上线默认 `monitor`**，跑够一周 bench 数据再切 enforce。

---

## 8. L3：异步旁路

触发条件：L2 超时、熔断跳过、或 verdict 落在 `[suspect, block)` 区间。

实现：`ngx.timer.at(0, fn, payload)`，payload 只带归一化文本和指纹，不带原始 body。

timer 内：

1. 调 Jev，超时放宽到 5s。
2. 结果写 `fp:<hash>`，下一个同指纹请求直接命中。
3. 更新 `rep:<ip>`：malicious 计数 +1；达到 `rep_block_after`（默认 3）→ 写 `block` 标记，后续该 IP 在 L1 直接拒绝。
4. 若 malicious，调用 `on_alert` 钩子（默认写 error log，可配 webhook）。

保护：timer 有上限（`lua_max_pending_timers`），用一个 shared dict 计数器限制 L3 并发 `max_async`（默认 32），超过直接丢弃并计数，不排队。

---

## 9. Verdict header 协议

网关向上游追加：

```
X-Jev-Verdict:    safe | suspicious | malicious | error | skipped
X-Jev-Score:      0.00-1.00
X-Jev-Source:     l1 | cache | l2 | breaker
X-Jev-Reason:     短文本，≤ 200 字节，URL-encoded
X-Jev-Request-Id: 与 nginx $request_id 一致，方便追 L3 结果
```

规则：

- 入站请求带的这些 header 一律剥掉，防伪造。
- L1 `pass` 的请求也打 `skipped`，让后端能区分"没检查"和"检查过是 safe"。
- 客户端响应不暴露任何 X-Jev 头。

---

## 10. 配置与热更新

### 10.1 配置分层

```
默认值（core）  <  文件 jev-edge.conf.lua  <  shared dict 覆盖（运行时）
```

### 10.2 热更新机制

- `init_worker_by_lua` 起一个 `ngx.timer.every(2, reload)`。
- reload 检查配置文件 mtime，变了就重新 `dofile` 并校验（schema 校验失败保留旧配置并告警）。
- 运行时覆盖：提供一个内部 location `/_jev/config`（限 127.0.0.1），`PUT` JSON 写入 `jev_config` dict；`DELETE` 清除覆盖回落文件。这是"线上误杀秒级回滚"的路径：`PUT {"policy":{"mode":"monitor"}}`。
- 每个 worker 各自持有当前配置的 Lua table 引用，读路径无锁。

### 10.3 配置示例

```lua
-- /etc/nginx/jev-edge.conf.lua
return {
  jev = {
    endpoint = "https://api.typesafe.ai/v1/systemone",
    api_key_env = "TYPESAFE_API_KEY",
    model = "jev-latest",
    timeout_ms = 300,
  },
  rules = { "llm-endpoints" },
  policy = { mode = "monitor", block_threshold = 0.85, suspect_threshold = 0.5 },
  cache  = { fp_ttl = 300, rep_ttl = 600, fp_prefix_bytes = 2048 },
  async  = { enabled = true, max_async = 32, rep_block_after = 3 },
  breaker = { window_s = 60, min_samples = 20, fail_ratio = 0.5, open_s = 30 },
}
```

---

## 11. 降级矩阵

| 故障 | 行为 | header |
|---|---|---|
| Jev 超时 | 放行，进 L3 | `error` |
| Jev 5xx / 解析失败 | 同上，计入熔断 | `error` |
| 熔断 open | 跳过 L2，进 L3 | `skipped` + `Source: breaker` |
| shared dict 满 | `set` 失败仅打日志，继续 | 正常 |
| 配置文件损坏 | 保留旧配置 | 正常 |
| body 读取失败 | 放行 | `skipped` |
| core 抛异常 | `pcall` 兜底放行 | `error` |

整个 access 阶段用 `pcall` 包住，任何未预期错误都是放行。

---

## 12. OpenResty adapter

### 12.1 nginx.conf

```nginx
http {
    lua_package_path "/usr/local/jev-edge/?.lua;;";
    lua_shared_dict jev_cache   64m;
    lua_shared_dict jev_config  1m;
    lua_shared_dict jev_metrics 4m;

    init_by_lua_block        { require("resty.jev.edge").init("/etc/nginx/jev-edge.conf.lua") }
    init_worker_by_lua_block { require("resty.jev.edge").init_worker() }

    server {
        location /v1/ {
            access_by_lua_block { require("resty.jev.edge").access() }
            log_by_lua_block    { require("resty.jev.edge").log() }
            proxy_pass http://llm_backend;
        }
        location = /_jev/config {
            allow 127.0.0.1; deny all;
            content_by_lua_block { require("resty.jev.edge").config_api() }
        }
        location = /_jev/metrics {
            allow 127.0.0.1; deny all;
            content_by_lua_block { require("resty.jev.edge").metrics() }
        }
    }
}
```

### 12.2 access() 伪代码

```lua
function M.access()
  local ok, err = pcall(function()
    local cfg = config.current()
    local req = build_req(cfg)            -- 读 body 用 ngx.req.read_body，超 max 不读
    strip_inbound_headers()
    local v = core.evaluate(req, ctx(cfg))
    set_upstream_headers(v)
    metrics.record(v)
    if v.action == "block" then
      return ngx.exit(cfg.policy.block_status)
    end
  end)
  if not ok then
    ngx.log(ngx.ERR, "jev-edge: ", err)
    ngx.req.set_header("X-Jev-Verdict", "error")
  end
end
```

注意 `ngx.req.read_body()` 只在 L1 判断路径与方法命中之后才调用，避免为无关请求读 body。

### 12.3 依赖

- OpenResty ≥ 1.21
- lua-resty-http ≥ 0.17
- lua-cjson（自带）

---

## 13. 可观测

### 13.1 日志

`log_by_lua` 输出一行 JSON 到 access log 变量 `$jev_log`：

```json
{"rid":"...","path":"/v1/chat","ip":"1.2.3.4","src":"l2","score":0.91,"verdict":"malicious","action":"block","l2_ms":184,"fp":"a1b2c3"}
```

### 13.2 指标（`/_jev/metrics`，Prometheus 文本格式）

```
jev_requests_total{stage="l1",result="pass"}
jev_requests_total{stage="l2",result="malicious"}
jev_cache_hits_total{kind="fp"}
jev_l2_latency_ms_bucket{le="100"}
jev_breaker_state  0|1|2
jev_async_dropped_total
```

---

## 14. Bench

### 14.1 数据集

| 集合 | 来源 | 用途 |
|---|---|---|
| normal | 脱敏的真实 chat 请求 + 合成正常对话 | 误杀率、L1 放行率、P99 |
| injection | jev-sec-bench 的注入样本 | 漏过率 |
| replay | injection 各样本做 5 种变体（改数字、换空白、大小写） | 缓存命中率 |

### 14.2 指标与验收线

| 指标 | v0.1 验收 |
|---|---|
| L1 放行的正常流量 P99 增量 | ≤ 1 ms |
| 正常流量被送 L2 的比例 | ≤ 2% |
| 误杀率（enforce，normal 集）| ≤ 0.1% |
| 漏过率（injection 集）| ≤ jev-sec-bench 基线 + 2% |
| replay 集缓存命中率 | ≥ 80% |
| Jev 完全宕机时的放行率 | 100% |

### 14.3 方法

`bench/run.lua` 用 wrk 打本地 OpenResty，Jev 端用 mock（可配延迟与故障率），跑三种场景：正常、Jev 慢（500ms）、Jev 挂。输出 `bench/report.md`。

---

## 15. 测试

- **core**：busted 单测，全部 IO mock。规则求值、归一化、策略、熔断状态机各一套用例。
- **adapter**：Test::Nginx，覆盖 header 注入、剥离、fail-open、配置热更新、L3 写回。
- **CI**：GitHub Actions，`openresty/openresty:alpine` 镜像跑两套测试，另加 luacheck。

---

## 16. 里程碑

| 阶段 | 内容 | 产出 |
|---|---|---|
| M1 骨架 | core 接口 + normalize + rules + policy，busted 通过 | `core/` 可独立 require |
| M2 OpenResty 通路 | access 胶水、mock Jev、header、fail-open | 一个 nginx.conf 跑通 |
| M3 缓存与熔断 | shared dict、breaker、L3 timer | Jev 挂了业务无感 |
| M4 热更新与观测 | config API、metrics、日志 | 能秒级切 monitor |
| M5 bench | 数据集、三场景、报告 | 验收数字 |
| M6 发布 | README、opm 包 `lua-resty-jev-edge`、示例 | v0.1.0 |

---

## 17. 已定决策

1. **判定后端可替换**：见 6.1，provider 接口，默认 `jev`，附带 `openai-compat` 与 `mock`。
2. **模板复制进 core**，不用 submodule。
3. **仓库名 `jev-edge`**，OpenResty 包名 `lua-resty-jev-edge`，Lua 模块前缀 `resty.jev`。
4. **Envoy 两种接法都兼容，共用一套判定代码**：
   - verdict 保持扁平结构（string / number / bool，无嵌套、无 nil 洞），JSON 与 protobuf 无损映射。
   - v0.2：OpenResty adapter 增加 `/_jev/authz` location，直接充当 Envoy **HTTP ext_authz** 服务，返回 200/403 加 X-Jev 头，零新逻辑。
   - 之后按需：一个 Go/Rust 薄壳实现 **gRPC ext_authz** 的 `Authorization.Check`，内部转发到 `/_jev/authz`，只做协议转换。
   - Cloudflare Worker 无法复用 Lua，是唯一需要用 JS 重写 core 的 adapter，因此 core 必须保持小。
