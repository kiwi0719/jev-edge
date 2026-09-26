# 现成配置：任何能发子请求的网关

[English](recipes.md) | **简体中文**

jev-edge 的整套判定只通过一个 HTTP 端点对外提供，就是 OpenResty 适配器上的 `/_jev/authz`。Envoy 把它当作 `ext_authz` 来用；其实任何网关，只要能把请求连同请求体转发给一个旁路服务，再根据答复决定放行还是拦截，都能按同一套约定接入。下面这些都不用新写适配器，只要在你现有的网关上加一段配置。

## 接口约定

发给 jev-edge 的请求：

- `POST /_jev/authz/<original path>`（用什么方法发都可以，L1 检查的是原始请求的方法）
- 原始请求的 `Content-Type`、`Content-Encoding` 和请求体（压缩过的请求体会先解码，缺了 `Content-Encoding` 头就读不出来）
- 客户端地址放在 `X-Forwarded-For` 里。代理都是往这个头的后面追加地址，所以 jev-edge 从右往左数，取第 `client_ip.trusted_hops` 个（默认是最后一个，也就是你的网关追加的那个），从不取第一个，因为第一个是客户端自己随便写的。网关如果发了 Envoy 的 `x-envoy-external-address`，jev-edge 改用它。两个头都没有，或者 `X-Forwarded-For` 里的地址不够 `trusted_hops` 个，就当作没有客户端地址（这时连过来的是网关，不是客户端）：IP 信誉和 `subject.from = "ip"` 都不生效，并在 `jev_authz_events_total{event="no_client_ip"}` 里计一次。

jev-edge 的答复：

| 状态码 | 响应头 | 含义 |
|---|---|---|
| 200 | `X-Jev-Verdict`、`X-Jev-Score`、`X-Jev-Source`、`X-Jev-Reason`、`X-Jev-Request-Id` | 放行；把这些头拷到发往上游的请求上 |
| >= 400 且带 `X-Jev-Verdict`（状态码取 `policy.block_status`，默认 403） | 同上，外加 JSON 响应体 | 拦截；把状态码和响应体原样返回给客户端 |
| 200 且 `X-Jev-Verdict: error` | | jev-edge 没能判定（provider 挂了、熔断器打开）；放行 |
| 其他任何情况 | 没有 `X-Jev-Verdict` | 不是判定结果：要么是 jev-edge 前面的 nginx 拒绝了这个请求，要么答复根本不是 jev-edge 给的（比如 404，或者中间某个代理返回的 5xx）；见下文 |

每份现成配置都必须守住两点：

- **失败放行。** jev-edge 连不上或者响应太慢时，照常放行请求，并标上 `X-Jev-Verdict: error`。下面每个网关都有对应的开关，每段配置里都已经打开了。
- **请求体大小。** 请求体不超过 `rules.max_body_bytes`（1 MiB）时，jev-edge 会完整解析；超过这个大小，就只在前 `max_body_bytes` 字节和最后 64 KiB 里找文本字段。网关那边也要设同样的上限。如果网关遇到大请求体只转发一部分，必须明确标出来：Envoy 开了 `allow_partial_message`（Istio 里叫 `allowPartialMessage`）会带上 `x-envoy-auth-partial-body: true`，HAProxy 的 agent 会带上 `X-Jev-Body-Partial: 1`，jev-edge 看到标记，就把收到的内容当作请求体的开头来扫描。这个标记只能由网关来打，不能让客户端自己带进来（见 Istio 一节的“超过 `maxRequestBytes` 的请求体”）。另外，请求体只要达到 `max_body_bytes`，不管有没有标记，jev-edge 都当它被截断了。比这短、又没有标记的截断请求体会被当作完整的来读：截断的 JSON 交给容错扫描器，截断处之前的文本字段照样能找出来；一个文本字段都没有的，判为 `unjudgeable: invalid json`。Envoy Gateway 从来不会只转发一部分请求体，超过上限直接回 413。详见[请求体大小与 L1 读取范围](design.zh-CN.md#请求体大小与-l1-读取范围)。

nginx 这边只需要一个 location：

```nginx
location /_jev/authz/ { content_by_lua_block { require("resty.jev.edge").authz() } }
```

## 薄适配器的约定

有些适配器自己不做判定，只负责把请求转给 `/_jev/authz`，比如 Envoy、gRPC shim、HAProxy 的 agent、LiteLLM 护栏，以及下面这些现成配置。它们拿到答复后都必须这样处理：

- **200** 表示已经有了判定，判定结果在响应头里，把这些头拷到上游请求上。
- **>= 400 且带 `X-Jev-Verdict`** 表示拦截，把这个状态码和响应体返回给客户端。
- **其他任何情况**都不是判定结果。没有答复（超时、连接出错）、没有 `X-Jev-Verdict` 的 5xx，或者带了 `X-Jev-Verdict` 但状态码既不是 200 也不是 >= 400，说明 jev-edge 没能答复：失败放行，标上 `X-Jev-Verdict: error`；适配器能设的话，再加上 `X-Jev-Source: adapter`。没有 `X-Jev-Verdict`、状态码又低于 500 的答复（400、413、414），是 jev-edge 前面的 nginx 在 jev-edge 运行之前就把请求拒了，也就是没人判定过它：gRPC shim 和 HAProxy 的 agent 会把它标成 `skipped`，原因是 `unjudgeable: authz answered <状态码>`，再按各自的 `-unjudged` 参数放行或拒绝，和 `policy.unjudgeable` 的做法一样。Envoy 的 HTTP `ext_authz`（Istio、Envoy Gateway）则会把这个答复直接交给客户端。
- **清掉客户端带进来的 `X-Jev-*` 头**（verdict、score、source、reason、request-id、subject、body-partial），要在上游看到请求之前清掉，免得客户端自己预先填一个判定结果。如果适配器会把客户端的请求头转给 `/_jev/authz`，转之前也要清掉：jev-edge 会把 `X-Jev-Body-Partial` 当作 HAProxy 的截断标记来读。写这些头时要覆盖，不要追加。
- **管理端点不要挂在网关路径上。** `/_jev/config`、`/_jev/samples`、`/_jev/feedback`、`/_jev/health` 和 `/_jev/metrics` 跟 `/_jev/authz` 挨在一起，要用单独的 server block 或端口来提供；路径里含 `..`、`%2e` 或 `//` 的请求一律不转发。

## Istio

一共五样东西：集群里跑着的 jev-edge；一个指向它的 mesh 扩展 provider；一条 `action: CUSTOM` 的 `AuthorizationPolicy`，把它挂到 LLM 工作负载上；一个 `EnvoyFilter`，在检查之前清掉伪造的 `X-Jev-*` 头；还有一个能看到客户端地址的入口网关。下面的策略和过滤器在 Istio 1.31 上验证过。

**jev-edge。** 装好适配器的 OpenResty（`luarocks install lua-resty-jev-edge`）、你的 `jev-edge.conf.lua`、[example.nginx.conf](../adapters/openresty/conf/example.nginx.conf) 里的 `http` 块，再加一个专门接 authz 这一跳的 server。Envoy 放进来的每个请求，这个 server 都必须接得住：否则 nginx 会在 jev-edge 运行之前就回 400、413 或 414，而 Envoy 会把这个答复原样交给客户端（见下文的 `failOpen`）。Envoy 限制的是整个请求头块（包括路径）不超过 60 KiB，请求体不超过 `maxRequestBytes`：

```nginx
server {
    listen 8080;
    large_client_header_buffers 4 64k;
    client_max_body_size 1m;            # at least maxRequestBytes
    location /_jev/authz/ { content_by_lua_block { require("resty.jev.edge").authz() } }
}
# /_jev/metrics, /_jev/config and the other admin endpoints: another server on
# another port, not in the Service
```

```yaml
apiVersion: apps/v1
kind: Deployment
metadata: { name: jev-edge, namespace: jev }
spec:
  replicas: 2
  selector: { matchLabels: { app: jev-edge } }
  template:
    metadata: { labels: { app: jev-edge } }
    spec:
      containers:
        - name: jev-edge
          image: registry.example.com/jev-edge:0.6.2   # your OpenResty image with the files above
          ports: [{ containerPort: 8080 }]
          env:
            - name: TYPESAFE_API_KEY                  # jev.api_key_env; `env TYPESAFE_API_KEY;` in nginx.conf
              valueFrom: { secretKeyRef: { name: jev-edge, key: api-key } }
---
apiVersion: v1
kind: Service
metadata: { name: jev-edge, namespace: jev }
spec:
  selector: { app: jev-edge }
  ports: [{ name: http, port: 8080, targetPort: 8080 }]
```

**Mesh config。** `default` profile 会装上 `istio-ingressgateway`；`minimal` 不会，那种情况下要另外装一个网关（`gateway` Helm chart）。同样的配置项也可以写进 Helm values。

```yaml
# istioctl install -f jev-istio.yaml
apiVersion: install.istio.io/v1alpha1
kind: IstioOperator
spec:
  profile: default
  components:
    ingressGateways:
      - name: istio-ingressgateway
        enabled: true
        k8s:
          service:
            externalTrafficPolicy: Local   # the gateway sees the client's address, not a node's
  meshConfig:
    extensionProviders:
      - name: jev-edge
        envoyExtAuthzHttp:
          service: jev-edge.jev.svc.cluster.local
          port: 8080
          pathPrefix: /_jev/authz
          timeout: 2s                      # above jev.timeout_max_ms
          failOpen: true
          includeRequestHeadersInCheck: ["content-type", "content-encoding", "content-length", "x-forwarded-for"]
          includeRequestBodyInCheck:
            maxRequestBytes: 1048576       # see "Bodies past maxRequestBytes"
            allowPartialMessage: true
          headersToUpstreamOnAllow: ["x-jev-*"]
          headersToDownstreamOnDeny: ["content-type"]
```

istiod 从 mesh config（`istio-system` 里名为 `istio` 的 ConfigMap）读取 `extensionProviders`，改动会推送给各个代理，不用重启。推送要几秒到一分钟：等推送完成再测，不要一 apply 完就测（`istioctl proxy-config listener <pod>.<namespace> -o json | grep -c ext_authz` 能看出过滤器是否已经生效）。只有设了 `includeRequestBodyInCheck`，Istio 才会把请求体发过来；不设的话，jev-edge 会返回 `skipped`，原因是 `no body`。不要把 `x-jev-*` 加进 `includeRequestHeadersInCheck`。

**策略。**

```yaml
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: jev-edge
  namespace: llm
spec:
  selector:
    matchLabels:
      app: llm-api
  action: CUSTOM
  provider:
    name: jev-edge
  rules:
    - to:
        - operation:
            notMethods: ["GET", "HEAD", "OPTIONS"]
```

这里不列路径：凡是可能带请求体的请求都交给 jev-edge，判不判定由规则的 `watch_paths` 决定。`watch_paths` 的匹配方式和后端路由一致：ASCII 大小写不敏感、去掉 `;` 参数、解析掉点号路径段，并且覆盖了各家服务接受的所有别名。要是在这里列路径，就得把 `rules/llm-endpoints.lua` 里的每个别名（`/chat/completions`、`/engines/<model>/...`、`/openai/deployments/<name>/...`、`/api/generate`、`/completion`、`/infill` 等等）的每种写法都列全，漏掉一个，走那个路径的请求就永远不会被检查。jev-edge 不监控的请求只多花一次往返，答复是 `skipped`。

**伪造的 `X-Jev-*` 头。** jev-edge 自己设的那几个头，会被 `headersToUpstreamOnAllow` 替换掉；其余的 `X-Jev-*` 头（`X-Jev-Subject`、`X-Jev-Body-Partial`），jev-edge 会在 `x-envoy-auth-headers-to-remove` 里一一列出，Envoy 放行请求时把它们删掉。但检查失败放行时，这两件事都不会发生，所以还要在检查之前先清一遍。清的位置放在工作负载的入站 listener 上，这样从网关进来的流量和网格内部的流量都能覆盖到：

```yaml
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: jev-strip-inbound
  namespace: llm
spec:
  workloadSelector:
    labels:
      app: llm-api
  configPatches:
    - applyTo: HTTP_FILTER
      match:
        context: SIDECAR_INBOUND
        listener:
          filterChain:
            filter:
              name: envoy.filters.network.http_connection_manager
              subFilter:
                name: envoy.filters.http.ext_authz
      patch:
        operation: INSERT_BEFORE
        value:
          name: jev-strip-inbound
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.http.header_mutation.v3.HeaderMutation
            mutations:
              request_mutations:
                - remove: x-jev-verdict
                - remove: x-jev-score
                - remove: x-jev-reason
                - remove: x-jev-source
                - remove: x-jev-request-id
                - remove: x-jev-subject
                - remove: x-jev-body-partial
```

**客户端地址。** jev-edge 从 `X-Forwarded-For` 里取客户端地址，从右往左数第 `client_ip.trusted_hops` 个。入口网关会追加它看到的地址，但只有在 `externalTrafficPolicy: Local` 下这才是客户端的地址；如果是 `Cluster`，kube-proxy 会把它换成某个节点的地址，所有客户端就共用一份 IP 信誉。如果网关前面还有一个会自己写 `X-Forwarded-For` 的负载均衡器，网关会在客户端地址后面再追加负载均衡器的地址：这时把 `client_ip.trusted_hops` 设为 2（同时在网关的 `proxy.istio.io/config` 里设 `numTrustedProxies: 1`，让 Istio 自己的策略也能看到客户端）。网格内部直接调用这个服务的工作负载不会发 `X-Forwarded-For`，它的 sidecar 也不会加：这时 jev-edge 没有客户端地址，对它既不用 IP 信誉，也不用 `subject.from = "ip"`，并在 `jev_authz_events_total{event="no_client_ip"}` 里计数。要跟踪这类调用方，就用 `subject.from = "header"`，选一个每个调用方都会带、后端也会校验的头，比如它的 API key，这样调用方没法靠换个值来甩掉自己的记录。这个头要加进 `includeRequestHeadersInCheck`：Istio 只转发那里列出的头，不加的话，网格内部的请求都没有主体。头的名字不要用 `X-Jev-*`：上面的 `EnvoyFilter` 会在检查之前删掉 `x-jev-subject`，jev-edge 根本看不到它；而且 `includeRequestHeadersInCheck` 里不能有 `x-jev-*`。自己设 `X-Forwarded-For` 的调用方，等于自己挑了自己的地址。

**`failOpen`。** jev-edge 连不上、超时或者回 5xx 时，Envoy 放行请求。除此之外，任何不是 200 的答复都算拒绝，原样交给客户端，所以上面那个 nginx server 必须接得住 Envoy 放进来的每个请求。这样放行的请求到达后端时根本没有 `X-Jev-Verdict`（Istio 没有开放 Envoy 的 `failure_mode_allow_header_add`）：没有判定头，就当作没判定过。拦截时，客户端拿到的是状态码、拦截响应体和它的 `content-type`，拿不到分数和原因；想把某次拦截和 jev-edge 的日志对上，就把 `x-jev-request-id` 加进 `headersToDownstreamOnDeny`。

**超过 `maxRequestBytes` 的请求体。** 设了 `allowPartialMessage: true`，遇到更大的请求体，Envoy 只发前 `maxRequestBytes` 字节，并带上 `x-envoy-auth-partial-body: true`；jev-edge 把它当作一个更大请求体的开头来扫描，剩下的部分永远不会被判定。monitor 模式下这样就够了。enforce 模式下，二选一：

- `allowPartialMessage: false`，同时把 `maxRequestBytes` 和 nginx 的 `client_max_body_size` 设成后端自己的请求体上限。更大的请求 Envoy 直接回 413，所以 jev-edge 看到的请求体都是完整的；超过 `rules.max_body_bytes` 的，按开头和结尾两段扫描。
- `allowPartialMessage: true`，`maxRequestBytes` 等于 `rules.max_body_bytes`，再设 `policy.partial = "unjudgeable"`。被截断的请求体会判为 `skipped`，原因是 `unjudgeable: partial body`，再由 `policy.unjudgeable = "block"` 拒掉。

`policy.partial = "unjudgeable"` 把截断标记的意思变成了“不判定”，所以这个标记只能来自 Envoy，不能来自客户端；如果 `policy.unjudgeable = "pass"`，一个伪造的标记就能跳过判定。Envoy 只要转发请求体，就会用自己的值覆盖客户端带来的 `x-envoy-auth-partial-body`；而 Istio 只转发 `includeRequestHeadersInCheck` 里列出的头，所以客户端带的 `X-Jev-Body-Partial`（HAProxy 的标记，jev-edge 也认）到不了 jev-edge。按上面的做法配上 `policy.unjudgeable = "block"`，伪造的标记最多只能让客户端自己的请求被拒。不用 Istio、通过 gRPC shim 接 Envoy 的情况也有保护：shim 会把客户端的请求头全部转过来，但它总会带上 `x-envoy-external-address`，而 jev-edge 会忽略和这个头一起出现的 `X-Jev-Body-Partial`。

请求体只要达到 `max_body_bytes`，不管标记怎么说，jev-edge 都当它被截断了：Envoy 恰好在 `maxRequestBytes` 处截断的请求体，可能被它报成完整的，而截断点可以由客户端靠停顿来控制。`jev_authz_events_total{event="cut_at_cap"}` 统计的就是这样被当作截断的请求体，不管它实际有没有被截断：一个被 Envoy 截断却报成完整的请求体，和一个恰好这么长的完整请求体，jev-edge 分不出来。选第一种做法时，Envoy 超限直接回 413、不会截断，每一次计数都是一个达到或超过 `max_body_bytes` 的完整请求体。这也是 `policy.partial = "unjudgeable"` 只能配第二种做法的原因：配第一种的话，超过 `max_body_bytes` 的完整请求体也会被算作截断。

## Envoy Gateway（Gateway API）

```yaml
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: SecurityPolicy
metadata:
  name: jev-edge
spec:
  targetRefs:
    - group: gateway.networking.k8s.io
      kind: HTTPRoute
      name: llm-api
  extAuth:
    failOpen: true
    headersToExtAuth: ["content-type", "content-encoding", "content-length", "x-forwarded-for"]
    bodyToExtAuth:
      maxRequestBytes: 1048576
    http:
      backendRefs:
        - name: jev-edge
          port: 8080
      path: /_jev/authz
      headersToBackend: ["x-jev-verdict", "x-jev-score", "x-jev-source", "x-jev-reason", "x-jev-request-id"]
```

`path` 会以路径前缀的形式交给 Envoy，这正是 jev-edge 需要的：jev-edge 先去掉 `/_jev/authz`，再拿剩下的路径做判定。第一个请求过来时就验证一下：如果聊天端点上出现 `X-Jev-Reason: path+not+watched`，说明你用的 Envoy Gateway 版本把路径整个替换掉了，而不是加前缀。遇到这种情况，就别设 `path`，改用 `EnvoyPatchPolicy` 来设前缀。这条策略覆盖路由上的所有路径，判定哪些交给 `watch_paths`，和 Istio 一样。

注意，请求体超过 `bodyToExtAuth.maxRequestBytes` 时，网关会直接回 413，而不是跳过检查；如果同一条路由上还要接收更大的上传，就把它和 jev-edge 那边 nginx 的 `client_max_body_size` 都设成实际的上限，不要设成 1 MiB。这里不会截断，所以 `policy.partial` 保持 `"judge"`：请求体达到 `rules.max_body_bytes` 时，jev-edge 会当它被截断了（见 Istio 一节；在这里，每一次 `cut_at_cap` 计数都是一个完整的请求体），而设成 `"unjudgeable"` 会让超过这个大小的完整请求体全都无法判定。完整送到 jev-edge、但超过 `rules.max_body_bytes` 的请求体，按开头和结尾两段判定。nginx 的大小设置和 `failOpen` 的行为，都和 Istio 一节说的一样。

请求被放行时，jev-edge 的 `x-envoy-auth-headers-to-remove` 会清掉客户端带来的其余 `X-Jev-*` 头；为了覆盖失败放行的情况，还要在 `ext_authz` 之前先清一遍，用 Gateway 上的 `ClientTrafficPolicy`（`headers.earlyRequestHeaders.remove`，名单和 Istio 的 `EnvoyFilter` 一样是那七个）。主体头（`subject.from = "header"`）要加进 `headersToExtAuth`，名字也不要用 `X-Jev-*`，原因见 Istio 一节。客户端地址是 Envoy Gateway 追加到 `X-Forwarded-For` 里的最后一个；如果前面还有一个会写这个头的负载均衡器，就把 `client_ip.trusted_hops` 加一。

## Azure API Management

在 API 上，或者在承载自然语言的那几个 operation 上，加一段 inbound 策略。失败放行靠两处实现：`send-request` 设了 `ignore-error="true"`，后面再判断一次响应是否为空。

```xml
<inbound>
  <base />
  <set-variable name="jevBody" value="@(context.Request.Body.As<string>(preserveContent: true))" />
  <send-request mode="new" response-variable-name="jev" timeout="2" ignore-error="true">
    <set-url>@("https://jev-edge.internal.example.com/_jev/authz" + context.Request.OriginalUrl.Path)</set-url>
    <set-method>@(context.Request.Method)</set-method>
    <set-header name="Content-Type" exists-action="override">
      <value>@(context.Request.Headers.GetValueOrDefault("Content-Type", "application/json"))</value>
    </set-header>
    <set-header name="X-Forwarded-For" exists-action="override">
      <value>@(context.Request.IpAddress)</value>
    </set-header>
    <set-body>@((string)context.Variables["jevBody"])</set-body>
  </send-request>
  <choose>
    <when condition="@(context.Variables["jev"] != null && ((IResponse)context.Variables["jev"]).StatusCode == 403)">
      <return-response>
        <set-status code="403" reason="Forbidden" />
        <set-header name="Content-Type" exists-action="override"><value>application/json</value></set-header>
        <set-header name="X-Jev-Verdict" exists-action="override">
          <value>@(((IResponse)context.Variables["jev"]).Headers.GetValueOrDefault("X-Jev-Verdict", "malicious"))</value>
        </set-header>
        <set-body>{"error":"request rejected"}</set-body>
      </return-response>
    </when>
    <when condition="@(context.Variables["jev"] != null)">
      <set-header name="X-Jev-Verdict" exists-action="override">
        <value>@(((IResponse)context.Variables["jev"]).Headers.GetValueOrDefault("X-Jev-Verdict", "error"))</value>
      </set-header>
      <set-header name="X-Jev-Score" exists-action="override">
        <value>@(((IResponse)context.Variables["jev"]).Headers.GetValueOrDefault("X-Jev-Score", "0.00"))</value>
      </set-header>
      <set-header name="X-Jev-Source" exists-action="override">
        <value>@(((IResponse)context.Variables["jev"]).Headers.GetValueOrDefault("X-Jev-Source", "l2"))</value>
      </set-header>
      <set-header name="X-Jev-Reason" exists-action="override">
        <value>@(((IResponse)context.Variables["jev"]).Headers.GetValueOrDefault("X-Jev-Reason", ""))</value>
      </set-header>
    </when>
    <otherwise>
      <set-header name="X-Jev-Verdict" exists-action="override"><value>error</value></set-header>
      <set-header name="X-Jev-Source" exists-action="override"><value>adapter</value></set-header>
    </otherwise>
  </choose>
</inbound>
```

`preserveContent: true` 不能省：不加的话，在策略表达式里读一次请求体就会把它消耗掉，后端什么也收不到。jev-edge 要放在私有端点或 APIM 的 VNet 后面，这段策略自己不带任何凭证。

## Google Apigee

在代理的请求流上挂三个策略：一个 `ServiceCallout` 负责调用 jev-edge，一个 `AssignMessage` 把判定头拷到请求上，一个 `RaiseFault` 在返回 403 时触发。callout 失败时，`<Response>` 对应的状态变量是空的，fault 条件不成立，请求照常往下走，这就是失败放行。

```xml
<ServiceCallout name="SC-JevEdge">
  <Request variable="jevRequest">
    <Set>
      <Verb>POST</Verb>
      <Path>/_jev/authz{proxy.pathsuffix}</Path>
      <Headers>
        <Header name="Content-Type">{request.header.Content-Type}</Header>
        <Header name="X-Forwarded-For">{client.ip}</Header>
      </Headers>
      <Payload contentType="application/json">{request.content}</Payload>
    </Set>
    <IgnoreUnresolvedVariables>true</IgnoreUnresolvedVariables>
  </Request>
  <Response>jevResponse</Response>
  <Timeout>2000</Timeout>
  <HTTPTargetConnection>
    <URL>https://jev-edge.internal.example.com</URL>
  </HTTPTargetConnection>
</ServiceCallout>
```

```xml
<AssignMessage name="AM-JevHeaders">
  <Set>
    <Headers>
      <Header name="X-Jev-Verdict">{jevResponse.header.X-Jev-Verdict}</Header>
      <Header name="X-Jev-Score">{jevResponse.header.X-Jev-Score}</Header>
      <Header name="X-Jev-Source">{jevResponse.header.X-Jev-Source}</Header>
      <Header name="X-Jev-Reason">{jevResponse.header.X-Jev-Reason}</Header>
    </Headers>
  </Set>
  <IgnoreUnresolvedVariables>true</IgnoreUnresolvedVariables>
  <AssignTo createNew="false" type="request" />
</AssignMessage>
```

```xml
<RaiseFault name="RF-JevBlock">
  <FaultResponse>
    <Set>
      <StatusCode>403</StatusCode>
      <ReasonPhrase>Forbidden</ReasonPhrase>
      <Headers>
        <Header name="Content-Type">application/json</Header>
        <Header name="X-Jev-Verdict">{jevResponse.header.X-Jev-Verdict}</Header>
      </Headers>
      <Payload contentType="application/json">{"error":"request rejected"}</Payload>
    </Set>
  </FaultResponse>
</RaiseFault>
```

在流程里按这个顺序排：

```xml
<Step><Name>SC-JevEdge</Name><Condition>request.verb = "POST" and (proxy.pathsuffix MatchesPath "/v1/**")</Condition></Step>
<Step><Name>RF-JevBlock</Name><Condition>jevResponse.status.code = 403</Condition></Step>
<Step><Name>AM-JevHeaders</Name><Condition>jevResponse.status.code = 200</Condition></Step>
```

`<Timeout>` 要设得比代理自己的 target 超时短。调用 jev-edge 失败时，`servicecallout.SC-JevEdge.failed` 为 `true`；如果你希望像其他适配器那样在请求上标出 `X-Jev-Verdict: error`，就按这个条件再加一个 `AssignMessage`。

## 其他网关

做法永远是这三步：把请求体连同 `X-Forwarded-For` 转发到 `/_jev/authz` 加原始路径；把答复里的 `X-Jev-*` 拷到上游请求上；jev-edge 回 403，网关就回 403。Traefik、Caddy 和 nginx `auth_request` 用 forward-auth 适配器；HAProxy 在 `adapters/haproxy` 里有自己的 agent。如果你的网关只能转发请求头、转发不了请求体，能得到的检查也就和其他只转发请求头的接入一样：只有路径、方法和信誉检查，其余一律返回 `skipped`，原因是 `no body`。
