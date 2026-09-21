-- bench/context_lint.lua
-- Lint a deployment_context before it costs you accuracy.
--
-- The README's guidance ("write it like a job description with a refusal
-- list") as checks. Measured on the deepset dataset, a good context moved AUC
-- from 0.983 to 0.996; a generic one ("a helpful assistant") gives Jev nothing
-- to defend and is worse than none. This script catches the generic one.
--
-- Usage (from the repo root, or `make context-lint CONF=... | TEXT=...`):
--   lua bench/context_lint.lua /etc/nginx/jev-edge.conf.lua   # every context in the file
--   lua bench/context_lint.lua --text "A support assistant ..."
--   lua bench/context_lint.lua --json ...
--
-- Exit status: 0 all pass, 1 any FAIL, 2 usage. WARNs do not fail.
-- Pure Lua, no dependencies.

local args = { ... }
local conf_path, text, as_json
do
  local i = 1
  while i <= #args do
    local a = args[i]
    if a == "--text" then text = args[i + 1]; i = i + 1
    elseif a == "--json" then as_json = true
    elseif a == "-h" or a == "--help" then
      io.stderr:write("usage: lua bench/context_lint.lua [<conf.lua>] [--text <context>] [--json]\n"); os.exit(0)
    elseif a ~= "" and not conf_path then conf_path = a
    end
    i = i + 1
  end
end
if not conf_path and not text then
  io.stderr:write("usage: lua bench/context_lint.lua [<conf.lua>] [--text <context>] [--json]\n")
  os.exit(2)
end

-- ---------------------------------------------------------------------------
-- checks: each returns level ("pass"|"warn"|"fail"), message
-- ---------------------------------------------------------------------------

local function count_sentences(s)
  local n = 0
  for _ in s:gmatch("[^%.%!%?]+[%.%!%?]") do n = n + 1 end
  if n == 0 and s:match("%S") then n = 1 end
  return n
end

local function count_words(s)
  local n = 0
  for _ in s:gmatch("%S+") do n = n + 1 end
  return n
end

local function has(s, patterns)
  local l = s:lower()
  for _, p in ipairs(patterns) do
    if l:find(p) then return p end
  end
  return nil
end

local GENERIC = {
  "helpful assistant", "helpful ai", "general[%s%-]purpose", "answers? any question", "answers? all questions",
  "can help with anything", "assist with anything", "a chatbot", "an ai assistant%.", "^an? assistant%.",
}
local REFUSAL = { "does not", "doesn't", "never", "will not", "won't", "must not", "is not for", "outside" }
local AUDIENCE = {
  "users are", "customers", "employees", "developers", "staff", "patients", "students", "visitors", "members",
  "clients", "operators", "agents", "engineers", "readers", "subscribers", "anonymous", "authenticated", "public",
}
local ANTI = {
  "be safe", "stay safe", "refuse attacks", "refuse malicious", "prompt injection", "jailbreak", "block attacks",
  "detect attacks", "security guard", "is secure",
}

local checks = {
  { id = "length", run = function(s)
      local sent, words = count_sentences(s), count_words(s)
      if words < 20 then return "fail", string.format("%d words: too short to describe a purpose; aim for 3-6 sentences, 40-150 words", words) end
      if sent < 3 then return "warn", string.format("%d sentence(s): add what it does not do and who talks to it", sent) end
      if sent > 8 or words > 220 then return "warn", string.format("%d sentences / %d words: long contexts dilute the purpose and cost tokens on every call", sent, words) end
      return "pass", string.format("%d sentences, %d words", sent, words)
    end },
  { id = "generic", run = function(s)
      local hit = has(s, GENERIC)
      if hit then return "fail", "generic phrasing (\"" .. hit:gsub("%%", "") .. "\"): says what every assistant is, not what this one is for" end
      return "pass", "no generic phrasing"
    end },
  { id = "refusal", run = function(s)
      if has(s, REFUSAL) then return "pass", "has a refusal list" end
      return "fail", "no refusal list: add what a hijacked version would be asked for (personas, unrelated writing, code, other products)"
    end },
  { id = "audience", run = function(s)
      if has(s, AUDIENCE) then return "pass", "names who talks to it" end
      return "warn", "does not say who the users are; that is what sets the baseline for normal"
    end },
  { id = "anti", run = function(s)
      local hit = has(s, ANTI)
      if hit then return "warn", "tells Jev to be safe or refuse attacks (\"" .. hit .. "\"); it already knows what an attack is, describe what normal is instead" end
      return "pass", "describes the service, not the threat"
    end },
  { id = "specific", run = function(s)
      -- capitalised words that are not sentence-initial: product, company, place names
      local n = 0
      for prev, w in s:gmatch("(%S+)%s+(%u%l+)") do
        if not prev:match("[%.%!%?]$") and not w:match("^It$") and not w:match("^Users$") then n = n + 1 end
      end
      if n == 0 then return "warn", "no proper nouns: name the product or company so off-purpose requests have something to be off from" end
      return "pass", string.format("%d proper noun(s)", n)
    end },
}

local function lint(s)
  local results, worst = {}, "pass"
  for _, c in ipairs(checks) do
    local level, msg = c.run(s)
    results[#results + 1] = { id = c.id, level = level, message = msg }
    if level == "fail" then worst = "fail" elseif level == "warn" and worst ~= "fail" then worst = "warn" end
  end
  return worst, results
end

-- ---------------------------------------------------------------------------
-- collect contexts
-- ---------------------------------------------------------------------------

local contexts = {}
if text then contexts[#contexts + 1] = { where = "--text", text = text } end
if conf_path then
  local chunk, err = loadfile(conf_path)
  if not chunk then io.stderr:write("cannot load " .. conf_path .. ": " .. tostring(err) .. "\n"); os.exit(2) end
  local ok, conf = pcall(chunk)
  if not ok or type(conf) ~= "table" then io.stderr:write(conf_path .. " did not return a table\n"); os.exit(2) end
  if type(conf.jev) == "table" and type(conf.jev.deployment_context) == "string" then
    contexts[#contexts + 1] = { where = "jev.deployment_context", text = conf.jev.deployment_context }
  end
  for _, r in ipairs(type(conf.rules) == "table" and conf.rules or {}) do
    if type(r) == "table" and type(r.deployment_context) == "string" then
      contexts[#contexts + 1] = { where = "rule " .. tostring(r.id or "?") .. ".deployment_context", text = r.deployment_context }
    end
  end
  if #contexts == 0 then
    contexts[#contexts + 1] = { where = "jev.deployment_context", text = "", missing = true }
  end
end

-- ---------------------------------------------------------------------------
-- output
-- ---------------------------------------------------------------------------

local exit = 0
local report = {}
for _, c in ipairs(contexts) do
  local worst, results
  if c.missing then
    worst, results = "fail", { { id = "present", level = "fail",
      message = "no deployment_context set: Jev is judging \"does this look like an attack\" instead of \"is this a misuse of this service\"" } }
  else
    worst, results = lint(c.text)
  end
  if worst == "fail" then exit = 1 end
  report[#report + 1] = { where = c.where, result = worst, checks = results }
  if not as_json then
    io.write(string.format("%s: %s\n", c.where, worst:upper()))
    for _, r in ipairs(results) do
      io.write(string.format("  %-4s %-9s %s\n", r.level == "pass" and "ok" or r.level:upper(), r.id, r.message))
    end
    io.write("\n")
  end
end

if as_json then
  -- minimal encoder, no dependency
  local function q(s) return '"' .. tostring(s):gsub('[%c"\\]', function(ch)
    if ch == '"' then return '\\"' elseif ch == "\\" then return "\\\\" end
    return string.format("\\u%04x", ch:byte()) end) .. '"' end
  local parts = {}
  for _, r in ipairs(report) do
    local cs = {}
    for _, k in ipairs(r.checks) do
      cs[#cs + 1] = string.format('{"id":%s,"level":%s,"message":%s}', q(k.id), q(k.level), q(k.message))
    end
    parts[#parts + 1] = string.format('{"where":%s,"result":%s,"checks":[%s]}', q(r.where), q(r.result), table.concat(cs, ","))
  end
  io.write("[" .. table.concat(parts, ",") .. "]\n")
end

os.exit(exit)
