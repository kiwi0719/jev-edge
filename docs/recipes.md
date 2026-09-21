# Recipes: any gateway that can make a subrequest

**English** | [简体中文](recipes.zh-CN.md)

jev-edge exposes its whole evaluation as one HTTP endpoint, `/_jev/authz`, on the OpenResty adapter. Envoy uses it as `ext_authz`; the same contract works for every gateway that can forward a request with its body to a side service and act on the answer. Nothing below needs a new adapter, only a configuration on the gateway you already run.

## The contract

Request to jev-edge:

- `POST /_jev/authz/<original path>` (any method; the original method is what L1 checks)
- the original `Content-Type` and body
- the client address in `X-Forwarded-For` (first value is used)

Answer:

| status | headers | meaning |
|---|---|---|
| 200 | `X-Jev-Verdict`, `X-Jev-Score`, `X-Jev-Source`, `X-Jev-Reason`, `X-Jev-Request-Id` | allow; copy the headers to the upstream request |
| 403 | same headers, JSON body | block; return the status and body to the client |
| 200 with `X-Jev-Verdict: error` | | jev-edge could not judge (provider down, breaker open); allow |

Two properties every recipe must keep:

- **Fail-open.** If jev-edge is unreachable or slow, allow the request and mark it `X-Jev-Verdict: error`. Every gateway below has a switch for this; it is set in every snippet.
- **Body size.** jev-edge reads at most `rules.max_body_bytes` (64 KB). Give the gateway the same cap so a large body does not stall the subrequest; L1 passes it as `body too large` either way.

The nginx side is one location:

```nginx
location /_jev/authz/ { content_by_lua_block { require("resty.jev.edge").authz() } }
```

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
        includeRequestHeadersInCheck: ["content-type", "content-length", "x-forwarded-for"]
        includeRequestBodyInCheck:
          maxRequestBytes: 65536
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

Istio sends the body only when `includeRequestBodyInCheck` is set; without it jev-edge answers `skipped` with reason `no body`. `allowPartialMessage: true` is what makes a body over the cap arrive truncated instead of failing the check.

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
    headersToExtAuth: ["content-type", "content-length", "x-forwarded-for"]
    bodyToExtAuth:
      maxRequestBytes: 65536
    http:
      backendRefs:
        - name: jev-edge
          port: 8080
      path: /_jev/authz
      headersToBackend: ["x-jev-verdict", "x-jev-score", "x-jev-source", "x-jev-reason", "x-jev-request-id"]
```

`path` is forwarded to Envoy as a path prefix, which is what jev-edge expects (it strips `/_jev/authz` and evaluates the rest). Verify on the first request: an `X-Jev-Reason: path+not+watched` on a chat endpoint means your Envoy Gateway version replaced the path instead of prefixing it; pin `path` off and set the prefix through an `EnvoyPatchPolicy` in that case. Note `bodyToExtAuth.maxRequestBytes` returns 413 for larger bodies rather than skipping the check; set it to your real upper bound, not to 64 KB, if you accept larger uploads on the same route.

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
