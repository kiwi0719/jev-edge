-- scripts/invariants.lua
-- Repository invariants: tripwires for bug classes the 0.3.1 -> 0.4.0 audit
-- found, cheap enough to run on every push (plain Lua 5.1+, no rocks).
--
--   lua scripts/invariants.lua        (from the repo root; `make invariants`)
--
-- Each rule names the bug it guards against. They are text checks, so they
-- can be fooled; the behavioural tests are the real guard, these catch the
-- regression before a reviewer has to.

local failures, checked = {}, 0

local function read(path)
  local f = io.open(path, "rb")
  if not f then return nil end
  local s = f:read("*a")
  f:close()
  return s
end

local function fail(rule, msg)
  failures[#failures + 1] = rule .. ": " .. msg
end

local function lines(cmd)
  local out = {}
  local p = io.popen(cmd)
  for l in p:lines() do out[#out + 1] = l end
  p:close()
  return out
end

-- files tracked by git under a directory, matching a Lua pattern
local function tracked(dir, pat)
  local out = {}
  for _, f in ipairs(lines("git ls-files " .. dir)) do
    if f:match(pat) then out[#out + 1] = f end
  end
  return out
end

-- source without comment lines (Lua `--`, JS / Go `//`, Python and shell `#`),
-- so a comment explaining why djb2 is gone does not trip the djb2 rule
local function code(path)
  local out = {}
  for l in ((read(path) or "") .. "\n"):gmatch("([^\n]*)\n") do
    local t = l:match("^%s*(.-)$")
    if not (t:sub(1, 2) == "--" or t:sub(1, 2) == "//" or t:sub(1, 1) == "#" or t:sub(1, 1) == "*") then
      out[#out + 1] = l
    end
  end
  return table.concat(out, "\n")
end

local function rule(name, fn)
  checked = checked + 1
  local ok, err = pcall(fn, name)
  if not ok then fail(name, "check raised: " .. tostring(err)) end
end

-- 1. One version everywhere --------------------------------------------------
rule("version", function(r)
  local want = (read("dist.ini") or ""):match("\nversion = ([%d%.]+)")
  if not want then return fail(r, "no version in dist.ini") end
  local found = {
    ["core/init.lua"] = (read("core/init.lua") or ""):match('_VERSION = "([^"]+)"'),
    ["adapters/openresty/lib/resty/jev/edge.lua"] =
      (read("adapters/openresty/lib/resty/jev/edge.lua") or ""):match('_VERSION = "([^"]+)"'),
    ["adapters/js/package.json"] = (read("adapters/js/package.json") or ""):match('"version": "([^"]+)"'),
    ["adapters/js/src/core/index.ts"] = (read("adapters/js/src/core/index.ts") or ""):match('VERSION = "([^"]+)"'),
  }
  for file, v in pairs(found) do
    if v ~= want then fail(r, file .. " says " .. tostring(v) .. ", dist.ini says " .. want) end
  end
  local spec = "lua-resty-jev-edge-" .. want .. "-1.rockspec"
  local s = read(spec)
  if not s then return fail(r, spec .. " missing (rockspec not renamed?)") end
  if not s:find('version = "' .. want .. '-1"', 1, true) then fail(r, spec .. ": version field") end
  if not s:find('tag = "v' .. want .. '"', 1, true) then fail(r, spec .. ": source tag") end
  if #tracked(".", "%.rockspec$") ~= 1 then fail(r, "exactly one rockspec expected at the root") end
end)

-- 2. The rockspec ships every module (0.4.0 nearly shipped without decode.lua)
rule("rockspec-modules", function(r)
  local specs = tracked(".", "^[^/]+%.rockspec$")
  local s = specs[1] and read(specs[1])
  if not s then return fail(r, "no rockspec") end
  local listed = {}
  for file in s:gmatch('=%s*"([^"]+%.lua)"') do
    listed[file] = true
    if not read(file) then fail(r, "listed but missing: " .. file) end
  end
  local want = {}
  for _, f in ipairs(tracked("adapters/openresty/lib", "%.lua$")) do want[#want + 1] = f end
  for _, f in ipairs(tracked("core", "^core/[^/]+%.lua$")) do want[#want + 1] = f end
  for _, f in ipairs(tracked("core/templates", "%.lua$")) do want[#want + 1] = f end
  for _, f in ipairs(tracked("rules", "%.lua$")) do want[#want + 1] = f end
  for _, f in ipairs(tracked("adapters/kong/kong", "%.lua$")) do want[#want + 1] = f end
  for _, f in ipairs(want) do
    if not listed[f] then fail(r, "not in the rockspec: " .. f) end
  end
end)

-- 3. Request headers are read without the 100-header default (a Content-Type
--    after 100 junk headers read as absent and L1 passed the request)
rule("get-headers-limit", function(r)
  local files = tracked("adapters/openresty/lib", "%.lua$")
  files[#files + 1] = "adapters/apisix/apisix/plugins/jev-edge.lua"
  files[#files + 1] = "adapters/kong/kong/plugins/jev-edge/handler.lua"
  for _, f in ipairs(files) do
    local s = code(f)
    local n = 0
    for _ in s:gmatch("get_headers%(%s*%)") do n = n + 1 end
    if n > 0 then fail(r, f .. ": ngx.req.get_headers() without max_headers (use get_headers(0))") end
  end
  local ap = read("adapters/apisix/apisix/plugins/jev-edge.lua") or ""
  if ap:find("core%.request%.headers%(") then
    fail(r, "APISIX plugin reads core.request.headers (default header limit); use ngx.req.get_headers(0)")
  end
end)

-- 4. Verdict-cache keys only through core.cache_key (a bare "fp:" .. fp key
--    replayed one tenant's SAFE on another)
rule("cache-key", function(r)
  local allowed = { ["core/init.lua"] = true, ["adapters/js/src/core/index.ts"] = true }
  local files = tracked("adapters/openresty/lib", "%.lua$")
  for _, f in ipairs(tracked("core", "^core/[^/]+%.lua$")) do files[#files + 1] = f end
  for _, f in ipairs(tracked("adapters/js/src", "%.ts$")) do files[#files + 1] = f end
  files[#files + 1] = "adapters/apisix/apisix/plugins/jev-edge.lua"
  files[#files + 1] = "adapters/kong/kong/plugins/jev-edge/handler.lua"
  for _, f in ipairs(files) do
    if not allowed[f] then
      local s = read(f) or ""
      if s:find('"fp:"%s*%.%.') or s:find('"fp:"%s*%+') then
        fail(r, f .. ': builds an "fp:" key by hand; use core.cache_key / cacheKey')
      end
    end
  end
end)

-- 5. Fingerprints are SHA-256 in production code (djb2 let a few appended
--    bytes collide with a cached SAFE)
rule("fingerprint-hash", function(r)
  for _, f in ipairs(tracked("adapters/js/src", "%.ts$")) do
    if f ~= "adapters/js/src/core/normalize.ts" and code(f):find("djb2") then
      fail(r, f .. ": djb2 outside the golden reference")
    end
  end
  for _, f in ipairs({ "adapters/openresty/lib/resty/jev/edge.lua", "adapters/apisix/apisix/plugins/jev-edge.lua",
                       "adapters/kong/kong/plugins/jev-edge/handler.lua" }) do
    local s = code(f)
    if s:find("djb2") or s:find("crc32") then fail(r, f .. ": weak fingerprint hash") end
    if not s:find("hash%s*=%s*sha256_hex") then fail(r, f .. ": ctx.hash is not sha256_hex") end
  end
end)

-- 6. The client never picks its IP: X-Forwarded-For is read from the right
--    (leftmost is what the client typed)
rule("client-ip", function(r)
  local files = tracked("adapters/js/src", "%.ts$")
  files[#files + 1] = "adapters/litellm/jev_edge_guardrail.py"
  for _, f in ipairs(files) do
    for l in (read(f) or ""):gmatch("[^\n]+") do
      if l:lower():find("forwarded%-for") and l:find('split%(%s*","%s*%)%[0%]') then
        fail(r, f .. ": leftmost X-Forwarded-For entry: " .. l:match("^%s*(.-)%s*$"))
      end
    end
  end
end)

-- 7. Forward URLs keep the upstream host (new URL("//evil/x", upstream) leaves it)
rule("upstream-url", function(r)
  for _, f in ipairs(tracked("adapters/js/src", "%.ts$")) do
    local s = read(f) or ""
    if s:find("new URL%([^)]*pathname%s*%+") then
      fail(r, f .. ": new URL(pathname + ..., base) resolves //host paths to another host")
    end
  end
end)

-- 8. Gateway reference configs never pass client-forged identity headers
rule("gateway-headers", function(r)
  local caddy = read("adapters/forward-auth/Caddyfile") or ""
  for _, h in ipairs({ "X-Envoy-External-Address", "X-Real-IP", "X-Jev-Verdict", "X-Jev-Subject" }) do
    if not caddy:find("request_header%s+%-" .. h:gsub("%-", "%%-")) then
      fail(r, "Caddyfile does not strip " .. h)
    end
  end
  local ngx_conf = read("adapters/forward-auth/nginx-auth-request.conf") or ""
  for _, h in ipairs({ "X-Forwarded-Uri", "X-Forwarded-Method", "X-Envoy-External-Address", "X-Real-IP",
                       "X-Jev-Verdict", "X-Jev-Subject" }) do
    if not ngx_conf:find("proxy_set_header%s+" .. h:gsub("%-", "%%-") .. "%s") then
      fail(r, "nginx-auth-request.conf does not set or clear " .. h .. " on the auth sub-request")
    end
  end
  local spoa = (read("adapters/haproxy/spoa/main.go") or ""):lower()
  for _, h in ipairs({ "x-envoy-external-address", "x-real-ip", "x-forwarded-for", "x-jev-verdict",
                       "x-jev-subject", "x-jev-body-partial" }) do
    if not spoa:find('"' .. h:gsub("%-", "%%-") .. '": true', 1) then
      fail(r, "HAProxy SPOA skipHeader lacks " .. h)
    end
  end
  local traefik = read("adapters/forward-auth/traefik.yml") or ""
  local fwd = traefik:match("authRequestHeaders:(.-)\n%s*%a[%w]*:") or traefik:match("authRequestHeaders:(.*)$") or ""
  if not fwd:find("Content%-Encoding") then fail(r, "traefik.yml does not forward Content-Encoding") end
  for _, h in ipairs({ "X-Real-IP", "X-Envoy-External-Address" }) do
    if fwd:find(h:gsub("%-", "%%-")) then fail(r, "traefik.yml forwards client " .. h) end
  end
  if traefik:find("\n%s*maxBodySize:") then
    fail(r, "traefik.yml sets maxBodySize (Traefik denies past it instead of letting jev-edge judge)")
  end
  local envoy = read("adapters/envoy/envoy-http.yaml") or ""
  if not envoy:find("exact:%s*content%-encoding") then fail(r, "envoy-http.yaml does not forward content-encoding") end
  for _, f in ipairs({ "adapters/envoy/envoy-http.yaml", "adapters/envoy/envoy-grpc.yaml" }) do
    local n = tonumber((read(f) or ""):match("max_request_bytes:%s*(%d+)"))
    if not n or n < 1048576 then fail(r, f .. ": max_request_bytes below rules.max_body_bytes (1 MiB)") end
  end
end)

-- 9. Makefile Docker mounts use $(CURDIR) ($$(PWD) is a command substitution
--    that only works on case-insensitive filesystems)
rule("makefile", function(r)
  if (read("Makefile") or ""):find("%$%$%(PWD%)") then fail(r, "Makefile uses $$(PWD); use $(CURDIR)") end
end)

-- 10. The shipped rule set is the same in Lua and TypeScript
rule("rule-parity", function(r)
  local lua = read("rules/llm-endpoints.lua") or ""
  local ts = read("adapters/js/src/rules/index.ts") or ""
  local tsrule = ts:match("export const llmEndpoints: Rule = (%b{})") or ""
  for _, k in ipairs({ "max_body_bytes", "max_judge_bytes", "max_judge_chunks", "min_body_bytes", "min_text_chars" }) do
    local a = lua:match("\n%s*" .. k .. "%s*=%s*(%d+)")
    local b = tsrule:match(k .. ":%s*(%d+)")
    if a ~= b then fail(r, k .. ": Lua " .. tostring(a) .. " vs TS " .. tostring(b)) end
  end
  local function list(s, key, open, close)
    local body = s:match(key .. "%s*[=:]%s*%" .. open .. "(.-)%" .. close) or ""
    local out = {}
    for v in body:gmatch('"([^"]+)"') do out[#out + 1] = v end
    return table.concat(out, ",")
  end
  if list(lua, "skip_content_types", "{", "}") ~= list(tsrule, "skip_content_types", "[", "]") then
    fail(r, "skip_content_types differ between rules/llm-endpoints.lua and src/rules/index.ts")
  end
  if lua:find("\n%s*content_types%s*=") then
    fail(r, "llm-endpoints lists content_types again (the allow list L1 used to pass requests on)")
  end
  -- always_suspect: the same patterns, in the same order (the golden rules
  -- cases name the first pattern that fires)
  local chunk = loadfile("rules/llm-endpoints.lua")
  local luarule = chunk and chunk() or {}
  local luapats = luarule.always_suspect or {}
  -- watch_paths and text_fields: the same entries in the same order (a route
  -- left out of one copy is "path not watched" on that runtime only; the
  -- order of text_fields is the order of the judged text). resolve() fills
  -- in the same text_fields for an inline rule that lists none.
  local function strings(s)
    local out = {}
    for v in (s or ""):gmatch('"([^"]*)"') do out[#out + 1] = v end
    return out
  end
  local want = table.concat(luarule.text_fields or {}, ",")
  for _, k in ipairs({ "watch_paths", "text_fields" }) do
    if table.concat(luarule[k] or {}, ",") ~= table.concat(strings(tsrule:match(k .. ":%s*(%b[])")), ",") then
      fail(r, k .. " differ between rules/llm-endpoints.lua and src/rules/index.ts")
    end
  end
  if table.concat(strings((read("core/rules.lua") or ""):match("out%.text_fields = (%b{})")), ",") ~= want
     or table.concat(strings(ts:match("out%.text_fields %?%?= (%b[])")), ",") ~= want then
    fail(r, "resolve() default text_fields differ from llm-endpoints (core/rules.lua, src/rules/index.ts)")
  end
  local tspats = {}
  for p in (tsrule:match("always_suspect:%s*%[(.-)\n%s*%],") or ""):gmatch("String%.raw`([^`]*)`") do
    tspats[#tspats + 1] = p
  end
  if #luapats ~= #tspats then
    fail(r, ("always_suspect: %d patterns in Lua, %d in TS"):format(#luapats, #tspats))
  end
  for i = 1, math.max(#luapats, #tspats) do
    if luapats[i] ~= tspats[i] then
      fail(r, "always_suspect[" .. i .. "] differs between rules/llm-endpoints.lua and src/rules/index.ts")
    end
    -- PCRE and JS agree only on their intersection
    local p = luapats[i] or ""
    if p:find("%(%?<[=!]") or p:find("[%*%+%?}]%+") or p:find("%(%?[imsxU%-]+[%):]") then
      fail(r, "always_suspect[" .. i .. "] uses lookbehind, a possessive quantifier or an inline flag")
    end
  end
end)

-- 11. The judge templates are the same in Lua and TypeScript: the provider
--     request body is built from these strings
rule("template-parity", function(r)
  local ts = code("adapters/js/src/core/templates.ts")
  for _, name in ipairs({ "injection", "abuse" }) do
    local lua = code("core/templates/" .. name .. ".lua")
    local a, b = {}, {}
    for s in lua:gmatch('"([^"\n]*)"') do a[#a + 1] = s end
    local body = ts:match("export const " .. name .. ": Template = (%b{})") or ""
    for s in body:gmatch('"([^"\n]*)"') do b[#b + 1] = s end
    if #a == 0 then fail(r, name .. ": no strings found in the Lua template") end
    if table.concat(a) ~= table.concat(b) then
      fail(r, name .. ": wording differs between core/templates/" .. name .. ".lua and src/core/templates.ts")
    end
  end
  -- the openai-compat system prompt header and input markers
  local lp = code("adapters/openresty/lib/resty/jev/providers/openai_compat.lua")
  local tp = code("adapters/js/src/providers/index.ts")
  local function strings(s)
    local out = {}
    for v in (s or ""):gmatch('"([^"\n]*)"') do out[#out + 1] = v end
    return table.concat(out, "|")
  end
  local la = strings(lp:match("local lines = (%b{})")) .. "#" .. strings(lp:match("local function user_message.-\nend"))
  local ta = strings(tp:match("const lines = (%b[])")) .. "#"
    .. strings(tp:match("export function openaiUserMessage.-\n}"))
  if la == "#" or la ~= ta then
    fail(r, "openai-compat prompt strings differ between openai_compat.lua and src/providers/index.ts")
  end
end)

-- 12. The ruleset's one required check covers every CI job: `ci-ok` needs
--     all of them (a job left out could fail and still let a PR merge)
rule("ci-ok", function(r)
  local ci = read(".github/workflows/ci.yml") or ""
  local jobs_block = ci:match("\njobs:\n(.*)$") or ""
  local jobs = {}
  for name in jobs_block:gmatch("\n  ([%w_%-]+):") do jobs[#jobs + 1] = name end
  local first = jobs_block:match("^  ([%w_%-]+):")
  if first then table.insert(jobs, 1, first) end
  local needs = ci:match("\n  ci%-ok:.-\n    needs:%s*%[([^%]]*)%]")
  if not needs then return fail(r, "ci.yml has no ci-ok job with a needs list") end
  local listed = {}
  for n in needs:gmatch("[%w_%-]+") do listed[n] = true end
  for _, j in ipairs(jobs) do
    if j ~= "ci-ok" and not listed[j] then fail(r, "ci-ok does not need job " .. j) end
  end
end)

-- 13. Only a provider that is failing counts against the breaker: core
--     reports through settle(), with judge.counts deciding, and the Lua HTTP
--     client classifies by status (a 200 the judged text made unusable, or a
--     4xx it provoked, let a client switch L2 off for every tenant)
rule("breaker-failures", function(r)
  local core_files = { ["core/init.lua"] = true, ["adapters/js/src/core/index.ts"] = true }
  for f in pairs(core_files) do
    local s = code(f)
    local n = select(2, s:gsub("[:%.]failure%(%)", ""))
    if n ~= 1 then fail(r, f .. ": " .. n .. " breaker failure() calls; report through settle() only") end
    if not s:find("judge%.counts%(") then fail(r, f .. ": failed calls are not classified with judge.counts") end
  end
  local own = { ["core/breaker.lua"] = true, ["adapters/js/src/core/breaker.ts"] = true,
                ["adapters/js/src/cf/stores.ts"] = true }  -- the breaker and its Durable Object proxy
  local files = tracked("adapters/openresty/lib", "%.lua$")
  for _, f in ipairs(tracked("adapters/js/src", "%.ts$")) do files[#files + 1] = f end
  files[#files + 1] = "adapters/apisix/apisix/plugins/jev-edge.lua"
  files[#files + 1] = "adapters/kong/kong/plugins/jev-edge/handler.lua"
  for _, f in ipairs(files) do
    if not core_files[f] and not own[f] and code(f):find("[:%.]failure%(%)") then
      fail(r, f .. ": feeds the breaker outside core")
    end
  end
  if not code("adapters/openresty/lib/resty/jev/http.lua"):find("judge%.status_kind%(res%.status%)") then
    fail(r, "resty/jev/http.lua: a failed parse is not classified by the provider's status")
  end
end)

-- ---------------------------------------------------------------------------
if #failures > 0 then
  io.stderr:write(("invariants: %d problem(s) across %d rules\n"):format(#failures, checked))
  for _, m in ipairs(failures) do io.stderr:write("  - " .. m .. "\n") end
  os.exit(1)
end
print(("invariants ok (%d rules)"):format(checked))
