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

Five pieces: jev-edge running in the cluster, a mesh extension provider that points at it, an `AuthorizationPolicy` with `action: CUSTOM` that attaches it to the LLM workload, an `EnvoyFilter` that strips forged `X-Jev-*` headers before the check, and an ingress gateway that sees the client's address. The policy and the filter below were checked on Istio 1.31.

**jev-edge.** OpenResty with the adapter installed (`luarocks install lua-resty-jev-edge`), your `jev-edge.conf.lua`, the `http` block of [example.nginx.conf](../adapters/openresty/conf/example.nginx.conf), and a server for the authz hop. Every request Envoy accepts must fit it: otherwise nginx answers 400, 413 or 414 before jev-edge runs, and Envoy hands that answer to the client (see `failOpen` below). Envoy caps the header block, path included, at 60 KiB, and the body at `maxRequestBytes`:

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
          image: registry.example.com/jev-edge:0.6.1   # your OpenResty image with the files above
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

**Mesh config.** The `default` profile installs `istio-ingressgateway`; `minimal` does not, so install a gateway separately there (the `gateway` Helm chart). The same keys go into Helm values.

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

istiod reads `extensionProviders` from the mesh config (the `istio` ConfigMap in `istio-system`) and pushes a change to the proxies without restarting them. That takes seconds to a minute: test after the push, not right after the apply (`istioctl proxy-config listener <pod>.<namespace> -o json | grep -c ext_authz` shows when the filter is there). Istio sends the body only when `includeRequestBodyInCheck` is set; without it jev-edge answers `skipped` with reason `no body`. Do not add `x-jev-*` to `includeRequestHeadersInCheck`.

**The policy.**

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

No path list: every request that can carry a body goes to jev-edge, and the rule's `watch_paths` decide what is judged. They are matched the way the backend routes, ASCII case folded, `;` parameters dropped and dot segments resolved, and they cover every alias the servers accept. A path list here would have to name every alias in `rules/llm-endpoints.lua` (`/chat/completions`, `/engines/<model>/...`, `/openai/deployments/<name>/...`, `/api/generate`, `/completion`, `/infill`, and more) in every spelling, and a request on one it misses is never checked. A request jev-edge does not watch costs one round trip and is answered `skipped`.

**Forged `X-Jev-*` headers.** `headersToUpstreamOnAllow` replaces the headers jev-edge sets, and jev-edge names every other `X-Jev-*` header (`X-Jev-Subject`, `X-Jev-Body-Partial`) in `x-envoy-auth-headers-to-remove`, which Envoy applies when it allows the request. Neither happens when the check fails open, so strip them before the check as well, on the workload's inbound listener, which covers traffic from the gateway and from inside the mesh:

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

**Client address.** jev-edge takes the client from `X-Forwarded-For`, element `client_ip.trusted_hops` from the right. The ingress gateway appends the address it sees, which is the client's only with `externalTrafficPolicy: Local`; with `Cluster`, kube-proxy replaces it with a node address and every client shares one IP reputation. Behind a load balancer that writes `X-Forwarded-For` itself, the gateway appends the balancer's address after the client's: set `client_ip.trusted_hops = 2` (and `numTrustedProxies: 1` in the gateway's `proxy.istio.io/config`, so Istio's own policies see the client too). A workload inside the mesh that calls the service directly sends no `X-Forwarded-For`, and its sidecar adds none: jev-edge then has no client address, applies no IP reputation and no `subject.from = "ip"` to it, and counts it in `jev_authz_events_total{event="no_client_ip"}`. Follow those callers with `subject.from = "header"`. A caller that sets `X-Forwarded-For` itself picks its own address.

**`failOpen`.** Envoy allows the request when jev-edge cannot be reached, times out, or answers 5xx. Any other answer that is not 200 is a denial and goes to the client as it is, which is why the nginx server above must take every request Envoy accepts. A request allowed that way reaches the backend with no `X-Jev-Verdict` at all (Istio does not expose Envoy's `failure_mode_allow_header_add`): treat a missing verdict as not judged. On a block the client gets the status, the block body and its `content-type`, not the score or the reason; add `x-jev-request-id` to `headersToDownstreamOnDeny` to match a block to jev-edge's log.

**Bodies past `maxRequestBytes`.** With `allowPartialMessage: true` Envoy sends the first `maxRequestBytes` of a larger body with `x-envoy-auth-partial-body: true`; jev-edge scans it as the head of a larger body, and the rest is never judged. That is enough in monitor mode. In enforce mode, pick one:

- `allowPartialMessage: false`, with `maxRequestBytes` and nginx's `client_max_body_size` set to the backend's own body limit. Envoy answers 413 to anything larger, so every body jev-edge sees is whole; past `rules.max_body_bytes` it is scanned head and tail.
- `allowPartialMessage: true`, with `maxRequestBytes` equal to `rules.max_body_bytes`, and `policy.partial = "unjudgeable"`. A cut body is then `skipped` with reason `unjudgeable: partial body`, and `policy.unjudgeable = "block"` refuses it.

jev-edge takes any body that reaches `max_body_bytes` as cut, whatever the flag says: Envoy can report a body it cut exactly at `maxRequestBytes` as whole, and a client can place that cut with a pause. `jev_authz_events_total{event="cut_at_cap"}` counts these. That is also why `policy.partial = "unjudgeable"` goes with the second option only: with the first, a whole body past `max_body_bytes` would count as cut.

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

`path` is forwarded to Envoy as a path prefix, which is what jev-edge expects (it strips `/_jev/authz` and evaluates the rest). Verify on the first request: an `X-Jev-Reason: path+not+watched` on a chat endpoint means your Envoy Gateway version replaced the path instead of prefixing it; pin `path` off and set the prefix through an `EnvoyPatchPolicy` in that case. The policy covers every path of the route; leave the choice of what to judge to `watch_paths`, as with Istio.

Note `bodyToExtAuth.maxRequestBytes` returns 413 for larger bodies rather than skipping the check: set it, and the `client_max_body_size` of jev-edge's nginx, to your real upper bound, not to 1 MiB, if you accept larger uploads on the same route. Nothing is cut, so leave `policy.partial` at `"judge"`: jev-edge takes a body that reaches `rules.max_body_bytes` as cut (see Istio), and `"unjudgeable"` would make every whole body past it unjudgeable. A body that reaches jev-edge whole but exceeds `rules.max_body_bytes` is judged on its head and tail. The nginx sizing and the `failOpen` behaviour are the ones described for Istio.

jev-edge's `x-envoy-auth-headers-to-remove` clears a client's other `X-Jev-*` headers when the request is allowed; strip them before `ext_authz` as well for the fail-open case, with a `ClientTrafficPolicy` on the Gateway (`headers.earlyRequestHeaders.remove`, the same seven names as the Istio `EnvoyFilter`). The client address is the last `X-Forwarded-For` element Envoy Gateway appends; behind a load balancer that writes the header, raise `client_ip.trusted_hops` by one.

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
