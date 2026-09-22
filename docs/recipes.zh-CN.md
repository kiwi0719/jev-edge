# 配方：任何能发子请求的网关

[English](recipes.md) | **简体中文**

jev-edge 把整套判定暴露成 OpenResty adapter 上的一个 HTTP 端点 `/_jev/authz`。Envoy 把它当 `ext_authz` 用；同一份契约适用于所有能把请求连 body 转发给旁路服务、再按答复行动的网关。下面的每一条都不需要新 adapter，只需要在你已有的网关上加一段配置。

## 契约

发给 jev-edge 的请求：

- `POST /_jev/authz/<原始路径>`（任何方法；L1 检查的是原始方法）
- 原始 `Content-Type`、`Content-Encoding` 和 body（压缩的 body 会被解码；缺了这个头就读不了）
- 客户端地址放在 `X-Forwarded-For`（取第一个值）

答复：

| 状态 | 头 | 含义 |
|---|---|---|
| 200 | `X-Jev-Verdict`、`X-Jev-Score`、`X-Jev-Source`、`X-Jev-Reason`、`X-Jev-Request-Id` | 放行；把这些头拷到上游请求 |
| >= 400 且带 `X-Jev-Verdict`（`policy.block_status`，默认 403） | 同样的头，JSON body | 拦截；把状态和 body 原样返回客户端 |
| 200 且 `X-Jev-Verdict: error` | | jev-edge 无法判定（provider 挂了、熔断打开）；放行 |
| 其他 | 没有 `X-Jev-Verdict` | 不是 jev-edge 的答复（404、某个代理的 5xx）；放行，见下文 |

每条配方都必须保住的两个性质：

- **Fail-open。** jev-edge 不可达或慢了，放行并标 `X-Jev-Verdict: error`。下面每个网关都有这个开关，每段配置里都设了。
- **body 大小。** jev-edge 对不超过 `rules.max_body_bytes`（1 MiB）的 body 整体解析；超过的只扫描前 `max_body_bytes` 字节和最后 64 KiB 里的文本字段。给网关同样的上限。只转发大 body 一部分的网关必须标明：基于 Envoy 的（Istio、Envoy Gateway）在 `allowPartialMessage` 下发送 `x-envoy-auth-partial-body: true`，jev-edge 把这样的 body 当作开头扫描。没有标记的截断 body 会被当作完整 body 解析，截断的 JSON 抽不出文本。详见 README 的 [body 大小与 L1 读什么](../README.zh-CN.md#body-大小与-l1-读什么)。

nginx 这边只有一个 location：

```nginx
location /_jev/authz/ { content_by_lua_block { require("resty.jev.edge").authz() } }
```

## 薄 adapter 契约

所有只转发 `/_jev/authz` 的 adapter（Envoy、gRPC shim、HAProxy 的 agent、LiteLLM guardrail、下面的配方）对答复必须这样处理：

- **200** = 判定结果在头里，拷到上游。
- **>= 400 且带 `X-Jev-Verdict`** = 拦截；把该状态和 body 返回客户端。
- **其他**（没有 `X-Jev-Verdict`、3xx、超时、连接错误）= 未判定；fail-open，标 `X-Jev-Verdict: error`，能设的话再加 `X-Jev-Source: adapter`。
- **剥掉入站 `X-Jev-*`**（verdict、score、source、reason、request-id、subject），上游看到的必须是网关设的，客户端不能预填；用覆盖，不要追加。
- **管理端点不能经过网关路径。** `/_jev/config`、`/_jev/samples`、`/_jev/feedback`、`/_jev/health`、`/_jev/metrics` 就在 `/_jev/authz` 旁边；用单独的 server block 或端口暴露，含 `..`、`%2e` 或 `//` 的路径一律不转发。

## Istio

mesh config 的 `extensionProviders` 声明一次 jev-edge；`action: CUSTOM` 的 `AuthorizationPolicy` 把它挂到工作负载和路径上。

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

只有设了 `includeRequestBodyInCheck` Istio 才会发 body；不设的话 jev-edge 回 `skipped`，理由是 `no body`。`allowPartialMessage: true` 让超过上限的 body 被截断送达并带上 `x-envoy-auth-partial-body: true`，而不是让检查失败；jev-edge 把它当作更大 body 的开头扫描。

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

`path` 会作为路径前缀传给 Envoy，这正是 jev-edge 期望的（它剥掉 `/_jev/authz` 再判定剩余部分）。第一个请求就验证一下：聊天端点上出现 `X-Jev-Reason: path+not+watched`，说明你这个版本的 Envoy Gateway 是替换路径而不是加前缀；那就去掉 `path`，改用 `EnvoyPatchPolicy` 设前缀。注意 `bodyToExtAuth.maxRequestBytes` 对更大的 body 返回 413 而不是跳过检查；同一路由上如果接受更大的上传，把它设成真实上限而不是 1 MiB。完整送达 jev-edge 但超过 `rules.max_body_bytes` 的 body 按开头和结尾判定。

## Azure API Management

放在 API 或承载自然语言的 operation 的 inbound 策略里。`send-request` 的 `ignore-error="true"` 加空值判断就是 fail-open。

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

`preserveContent: true` 很关键：不加的话策略表达式里读 body 会把它消耗掉，后端什么都收不到。把 jev-edge 放在私有端点或 APIM 的 VNet 后面；这段策略本身不带凭证。

## Google Apigee

代理请求流上三个策略：调 jev-edge 的 `ServiceCallout`、把判定头拷到请求上的 `AssignMessage`、按 403 触发的 `RaiseFault`。callout 失败时 `<Response>` 的状态变量为空，fault 条件为假，请求继续：fail-open。

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

流程，按顺序：

```xml
<Step><Name>SC-JevEdge</Name><Condition>request.verb = "POST" and (proxy.pathsuffix MatchesPath "/v1/**")</Condition></Step>
<Step><Name>RF-JevBlock</Name><Condition>jevResponse.status.code = 403</Condition></Step>
<Step><Name>AM-JevHeaders</Name><Condition>jevResponse.status.code = 200</Condition></Step>
```

`<Timeout>` 要小于代理自身的目标超时。callout 失败时 `servicecallout.SC-JevEdge.failed` 为 `true`；想像其他 adapter 那样在请求上标 `X-Jev-Verdict: error`，就按这个条件再加一个 `AssignMessage`。

## 其他网关

模式永远是这三行：把 body 连同 `X-Forwarded-For` 转发到 `/_jev/authz` 加原始路径，把答复里的 `X-Jev-*` 拷到上游请求，把 403 变成 403。forward-auth adapter 覆盖 Traefik、Caddy 和 nginx `auth_request`；HAProxy 在 `adapters/haproxy` 里有自己的 agent。如果你的网关只能发头不能发 body，你得到的就是它们得到的：路径、方法和信誉检查，其余一律 `skipped`，理由 `no body`。
