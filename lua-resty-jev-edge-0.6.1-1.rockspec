rockspec_format = "3.0"
package = "lua-resty-jev-edge"
version = "0.6.1-1"

source = {
   url = "git+https://github.com/kiwi0719/jev-edge",
   tag = "v0.6.1",
}

description = {
   summary = "Typed-judgment admission control for LLM endpoints at the traffic edge.",
   detailed = [[
jev-edge sits in nginx / OpenResty or Apache APISIX and asks one question about
incoming requests: what is this request trying to do to my service? It uses a
System One model that returns probabilities instead of prose to catch prompt
injection and abuse at the entry point of LLM-backed applications, before the
request reaches the backend.

Three filters ordered by cost: cheap L1 rules (~25us), an L2 sync judgment with
an adaptive timeout, and an L3 async side-path that never blocks the response.
Fail-open, shared-dict cache, circuit breaker, verdict headers passed upstream
and hot-reloadable thresholds.
]],
   homepage = "https://github.com/kiwi0719/jev-edge",
   license = "Apache-2.0",
   labels = { "openresty", "nginx", "apisix", "llm", "security", "prompt-injection", "gateway" },
}

dependencies = {
   "lua-resty-http >= 0.17",
}

build = {
   type = "builtin",
   modules = {
      -- OpenResty adapter: the entry point is resty.jev.edge
      ["resty.jev.edge"]     = "adapters/openresty/lib/resty/jev/edge.lua",
      ["resty.jev.adaptive"] = "adapters/openresty/lib/resty/jev/adaptive.lua",
      ["resty.jev.async"]    = "adapters/openresty/lib/resty/jev/async.lua",
      ["resty.jev.body"]     = "adapters/openresty/lib/resty/jev/body.lua",
      ["resty.jev.cache"]    = "adapters/openresty/lib/resty/jev/cache.lua",
      ["resty.jev.config"]   = "adapters/openresty/lib/resty/jev/config.lua",
      ["resty.jev.decode"]   = "adapters/openresty/lib/resty/jev/decode.lua",
      ["resty.jev.http"]     = "adapters/openresty/lib/resty/jev/http.lua",
      ["resty.jev.loader"]   = "adapters/openresty/lib/resty/jev/loader.lua",
      ["resty.jev.metrics"]  = "adapters/openresty/lib/resty/jev/metrics.lua",

      ["resty.jev.providers.jev"]            = "adapters/openresty/lib/resty/jev/providers/jev.lua",
      ["resty.jev.providers.laya"]           = "adapters/openresty/lib/resty/jev/providers/laya.lua",
      ["resty.jev.providers.mock"]           = "adapters/openresty/lib/resty/jev/providers/mock.lua",
      ["resty.jev.providers.openai_compat"]  = "adapters/openresty/lib/resty/jev/providers/openai_compat.lua",

      -- Kong Gateway plugin (KONG_PLUGINS=bundled,jev-edge); see adapters/kong/README.md
      ["kong.plugins.jev-edge.handler"] = "adapters/kong/kong/plugins/jev-edge/handler.lua",
      ["kong.plugins.jev-edge.schema"]  = "adapters/kong/kong/plugins/jev-edge/schema.lua",

      -- Gateway-independent core, flattened the same way `make dist` does it.
      ["jev.core"]           = "core/init.lua",
      ["jev.core.breaker"]   = "core/breaker.lua",
      ["jev.core.defaults"]  = "core/defaults.lua",
      ["jev.core.judge"]     = "core/judge.lua",
      ["jev.core.normalize"] = "core/normalize.lua",
      ["jev.core.policy"]    = "core/policy.lua",
      ["jev.core.rules"]     = "core/rules.lua",
      ["jev.core.sampling"]  = "core/sampling.lua",
      ["jev.core.subject"]   = "core/subject.lua",
      ["jev.core.trust"]     = "core/trust.lua",
      ["jev.core.verdict"]   = "core/verdict.lua",

      ["jev.core.templates.abuse"]     = "core/templates/abuse.lua",
      ["jev.core.templates.untrusted"] = "core/templates/untrusted.lua",
      ["jev.core.templates.injection"] = "core/templates/injection.lua",

      ["jev.rules.default"]        = "rules/default.lua",
      ["jev.rules.llm-endpoints"]  = "rules/llm-endpoints.lua",
   },
   copy_directories = { "docs" },
}
