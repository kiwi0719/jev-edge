# 现成配置：任何能发子请求的网关

[English](recipes.md) | **简体中文**

jev-edge 的整套判定只通过一个 HTTP 端点对外提供，就是 OpenResty 适配器上的 `/_jev/authz`。Envoy 把它当作 `ext_authz` 来用；其实任何网关，只要能把请求连同请求体转发给一个旁路服务，再根据答复决定放行还是拦截，都能按同一套约定接入。下面这些都不用新写适配器，只要在你现有的网关上加一段配置。

## 接口约定

发给 jev-edge 的请求：

- `POST /_jev/authz/<original path>`（用什么方法发都可以，L1 检查的是原始请求的方法）
- 原始请求的 `Content-Type`、`Content-Encoding` 和请求体（压缩过的请求体会先解码，缺了 `Content-Encoding` 头就读不出来）
- 客户端地址放在 `X-Forwarded-For` 里（取第一个值）

jev-edge 的答复：

| 状态码 | 响应头 | 含义 |
|---|---|---|
| 200 | `X-Jev-Verdict`、`X-Jev-Score`、`X-Jev-Source`、`X-Jev-Reason`、`X-Jev-Request-Id` | 放行；把这些头拷到发往上游的请求上 |
| >= 400 且带 `X-Jev-Verdict`（状态码取 `policy.block_status`，默认 403） | 同上，外加 JSON 响应体 | 拦截；把状态码和响应体原样返回给客户端 |
| 200 且 `X-Jev-Verdict: error` | | jev-edge 没能判定（provider 挂了、熔断器打开）；放行 |
| 其他任何情况 | 没有 `X-Jev-Verdict` | 不是 jev-edge 给的答复（比如 404，或者中间某个代理返回的 5xx）；放行，见下文 |

每份现成配置都必须守住两点：

- **失败放行。** jev-edge 连不上或者响应太慢时，照常放行请求，并标上 `X-Jev-Verdict: error`。下面每个网关都有对应的开关，每段配置里都已经打开了。
- **请求体大小。** 请求体不超过 `rules.max_body_bytes`（1 MiB）时，jev-edge 会完整解析；超过这个大小，就只在前 `max_body_bytes` 字节和最后 64 KiB 里找文本字段。网关那边也要设同样的上限。如果网关遇到大请求体只转发一部分，必须明确标出来：基于 Envoy 的网关（Istio、Envoy Gateway）开启 `allowPartialMessage` 后会带上 `x-envoy-auth-partial-body: true`，jev-edge 看到这个标记，就把收到的内容当作请求体的开头来扫描。如果请求体被截断了却没有标记，jev-edge 会把它当作完整的请求体解析，而截断的 JSON 解析不出任何文本。详见[请求体大小与 L1 读取范围](design.zh-CN.md#请求体大小与-l1-读取范围)。

nginx 这边只需要一个 location：

```nginx
location /_jev/authz/ { content_by_lua_block { require("resty.jev.edge").authz() } }
```

## 薄适配器的约定

有些适配器自己不做判定，只负责把请求转给 `/_jev/authz`，比如 Envoy、gRPC shim、HAProxy 的 agent、LiteLLM 护栏，以及下面这些现成配置。它们拿到答复后都必须这样处理：

- **200** 表示已经有了判定，判定结果在响应头里，把这些头拷到上游请求上。
- **>= 400 且带 `X-Jev-Verdict`** 表示拦截，把这个状态码和响应体返回给客户端。
- **其他任何情况**（没有 `X-Jev-Verdict`、3xx、超时、连接出错）都算没有判定：失败放行，标上 `X-Jev-Verdict: error`；适配器能设的话，再加上 `X-Jev-Source: adapter`。
- **清掉客户端带进来的 `X-Jev-*` 头**（verdict、score、source、reason、request-id、subject），要在上游看到请求之前清掉，免得客户端自己预先填一个判定结果。写这些头时要覆盖，不要追加。
- **管理端点不要挂在网关路径上。** `/_jev/config`、`/_jev/samples`、`/_jev/feedback`、`/_jev/health` 和 `/_jev/metrics` 跟 `/_jev/authz` 挨在一起，要用单独的 server block 或端口来提供；路径里含 `..`、`%2e` 或 `//` 的请求一律不转发。

## Istio

先在 mesh config 的 `extensionProviders` 里声明一次 jev-edge，再用 `action: CUSTOM` 的 `AuthorizationPolicy` 把它挂到具体的工作负载和路径上。

```yaml
# istio operator / helm values
meshConfig:
  extensionProviders:
    - name: jev-edge
      envoyExtAuthzHttp:
        service: jev-edge.jev.svc.cluster.local
        port: 8080
        pathPrefix: /_jev/authz
        timeout: 2s
        failOpen: true
        includeRequestHeadersInCheck: ["content-type", "content-encoding", "content-length", "x-forwarded-for"]
        includeRequestBodyInCheck:
          maxRequestBytes: 1048576
          allowPartialMessage: true
        headersToUpstreamOnAllow: ["x-jev-*"]
        headersToDownstreamOnDeny: ["content-type", "x-jev-*"]
```

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
            paths: ["/v1/*", "/api/chat*"]
```

只有设了 `includeRequestBodyInCheck`，Istio 才会把请求体发过来；不设的话，jev-edge 会返回 `skipped`，原因是 `no body`。`allowPartialMessage: true` 也不能少：有了它，超过上限的请求体会截断后送过来，并带上 `x-envoy-auth-partial-body: true`，而不是直接让检查失败。jev-edge 会把这样的请求体当作一个更大请求体的开头来扫描。

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

`path` 会以路径前缀的形式交给 Envoy，这正是 jev-edge 需要的：jev-edge 先去掉 `/_jev/authz`，再拿剩下的路径做判定。第一个请求过来时就验证一下：如果聊天端点上出现 `X-Jev-Reason: path+not+watched`，说明你用的 Envoy Gateway 版本把路径整个替换掉了，而不是加前缀。遇到这种情况，就别设 `path`，改用 `EnvoyPatchPolicy` 来设前缀。还要注意，请求体超过 `bodyToExtAuth.maxRequestBytes` 时，网关会直接返回 413，而不是跳过检查；如果同一条路由上还要接收更大的上传，就把它设成实际的上限，不要设成 1 MiB。请求体完整送到了 jev-edge、但超过 `rules.max_body_bytes` 的，按开头和结尾两段来判定。

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
