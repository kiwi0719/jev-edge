# Recipes: any gateway that can make a subrequest

**English** | [简体中文](recipes.zh-CN.md)

jev-edge exposes its whole evaluation as one HTTP endpoint, `/_jev/authz`, on the OpenResty adapter. Envoy uses it as `ext_authz`; the same contract works for every gateway that can forward a request with its body to a side service and act on the answer. Nothing below needs a new adapter, only a configuration on the gateway you already run.

## The contract

Request to jev-edge:

- `POST /_jev/authz/<original path>` (any method; the original method is what L1 checks)
- the original `Content-Type`, `Content-Encoding` and body (a compressed body is decoded; without the header it cannot be read)
- the client address in `X-Forwarded-For` (first value is used)

Answer:

| status | headers | meaning |
|---|---|---|
| 200 | `X-Jev-Verdict`, `X-Jev-Score`, `X-Jev-Source`, `X-Jev-Reason`, `X-Jev-Request-Id` | allow; copy the headers to the upstream request |
| >= 400 with `X-Jev-Verdict` (`policy.block_status`, 403 by default) | same headers, JSON body | block; return the status and body to the client |
| 200 with `X-Jev-Verdict: error` | | jev-edge could not judge (provider down, breaker open); allow |
| anything else | no `X-Jev-Verdict` | not jev-edge (a 404, a 5xx from a proxy); allow, see below |

Two properties every recipe must keep:

- **Fail-open.** If jev-edge is unreachable or slow, allow the request and mark it `X-Jev-Verdict: error`. Every gateway below has a switch for this; it is set in every snippet.
- **Body size.** jev-edge parses a body up to `rules.max_body_bytes` (1 MiB) whole; past it, it scans the first `max_body_bytes` and the last 64 KiB for the text fields. Give the gateway the same cap. A gateway that forwards only part of a larger body must say so: Envoy-based ones (Istio, Envoy Gateway) send `x-envoy-auth-partial-body: true` with `allowPartialMessage`, and jev-edge scans that body as a head. A cut body with no flag is parsed as if whole, and truncated JSON yields no text. Details in the operating guide, [Body size and what L1 reads](design.md#body-size-and-what-l1-reads).

The nginx side is one location:

```nginx
location /_jev/authz/ { content_by_lua_block { require("resty.jev.edge").authz() } }
```

## Thin-adapter contract

What every adapter that only relays `/_jev/authz` (Envoy, the gRPC shim, HAProxy's agent, the LiteLLM guardrail, the recipes below) must do with the answer:

- **200** = a decision; the verdict is in the headers, copy them upstream.
- **>= 400 with `X-Jev-Verdict`** = a block; return that status and body to the client.
- **Anything else** (no `X-Jev-Verdict`, a 3xx, a timeout, a connection error) = not judged; fail open with `X-Jev-Verdict: error` and, if the adapter can, `X-Jev-Source: adapter`.
- **Strip inbound `X-Jev-*`** (verdict, score, source, reason, request-id, subject) before the upstream sees the request, so a client cannot pre-fill a verdict. Overwrite, do not append.
- **Keep the admin endpoints off the gateway path.** `/_jev/config`, `/_jev/samples`, `/_jev/feedback`, `/_jev/health` and `/_jev/metrics` sit next to `/_jev/authz`; serve them from a separate server block or port, and refuse to forward paths containing `..`, `%2e` or `//`.

## Istio

`extensionProviders` in the mesh config declares jev-edge once; an `AuthorizationPolicy` with `action: CUSTOM` attaches it to workloads and paths.

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

Istio sends the body only when `includeRequestBodyInCheck` is set; without it jev-edge answers `skipped` with reason `no body`. `allowPartialMessage: true` is what makes a body over the cap arrive truncated, flagged `x-envoy-auth-partial-body: true`, instead of failing the check; jev-edge scans it as the head of a larger body.

## Envoy Gateway (Gateway API)

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

`path` is forwarded to Envoy as a path prefix, which is what jev-edge expects (it strips `/_jev/authz` and evaluates the rest). Verify on the first request: an `X-Jev-Reason: path+not+watched` on a chat endpoint means your Envoy Gateway version replaced the path instead of prefixing it; pin `path` off and set the prefix through an `EnvoyPatchPolicy` in that case. Note `bodyToExtAuth.maxRequestBytes` returns 413 for larger bodies rather than skipping the check; set it to your real upper bound, not to 1 MiB, if you accept larger uploads on the same route. A body that reaches jev-edge whole but exceeds `rules.max_body_bytes` is judged on its head and tail.

## Azure API Management

An inbound policy on the API or the operations that carry natural language. `send-request` with `ignore-error="true"` and the null check are the fail-open.

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

`preserveContent: true` matters: without it reading the body in a policy expression consumes it and the backend receives nothing. Put jev-edge behind a private endpoint or the APIM VNet; the policy carries no credential of its own.

## Google Apigee

Three policies on the proxy request flow: a `ServiceCallout` to jev-edge, an `AssignMessage` that copies the verdict headers onto the request, and a `RaiseFault` conditioned on a 403. `<Response>` on a failed callout leaves the status variable empty, so the fault condition is false and the request continues: fail-open.

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

Flow, in order:

```xml
<Step><Name>SC-JevEdge</Name><Condition>request.verb = "POST" and (proxy.pathsuffix MatchesPath "/v1/**")</Condition></Step>
<Step><Name>RF-JevBlock</Name><Condition>jevResponse.status.code = 403</Condition></Step>
<Step><Name>AM-JevHeaders</Name><Condition>jevResponse.status.code = 200</Condition></Step>
```

Set `<Timeout>` below the proxy's own target timeout. If a callout to jev-edge fails, `servicecallout.SC-JevEdge.failed` is `true`; add an `AssignMessage` on that condition if you want `X-Jev-Verdict: error` on the request as the other adapters set it.

## Anything else

The pattern is always the same three lines: forward the body with `X-Forwarded-For` to `/_jev/authz` plus the original path, copy `X-Jev-*` from the answer to the upstream request, turn a 403 into a 403. The forward-auth adapter covers Traefik, Caddy and nginx `auth_request`; HAProxy has its own agent in `adapters/haproxy`. If your gateway can only send headers and not the body, you get what those get: path, method and reputation checks, and `skipped` with reason `no body` for the rest.
