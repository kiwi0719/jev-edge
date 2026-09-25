-- scripts/invariants_test.lua
-- Mutation tests for scripts/invariants.lua. Each case edits a copy of a real
-- file in memory (the working tree is never written), runs the invariants
-- against it and expects the rule that guards that edit to fail, and no other.
--
--   lua scripts/invariants_test.lua [invariants.lua]   (from the repo root)
--
-- The unmodified tree must pass `make invariants` first; a case whose edit no
-- longer applies to the real file fails, so the cases cannot go stale.

local SCRIPT = arg and arg[1] or "scripts/invariants.lua"

local function read(path)
  local f = assert(io.open(path, "rb"))
  local s = f:read("*a")
  f:close()
  return s
end

-- s with the one match of Lua pattern pat replaced
local function edit(s, pat, repl)
  local out, n = s:gsub(pat, repl)
  if n ~= 1 then error(("stale case: %q matched %d times"):format(pat, n), 2) end
  return out
end

-- run the invariants with some files' contents replaced; returns the
-- exit code and everything it printed
local function run(files)
  local out, exited = {}, {}
  local env = setmetatable({
    io = setmetatable({
      open = function(path, mode)
        local s = files[path]
        if s == nil then return io.open(path, mode) end
        return { read = function() return s end, close = function() return true end }
      end,
      stderr = { write = function(_, s) out[#out + 1] = s end },
    }, { __index = io }),
    os = setmetatable({ exit = function(code) exited.code = code; error(exited, 0) end }, { __index = os }),
    print = function(s) out[#out + 1] = tostring(s) .. "\n" end,
  }, { __index = _G })
  local chunk
  if setfenv then
    chunk = assert(loadfile(SCRIPT))
    setfenv(chunk, env)
  else
    chunk = assert(loadfile(SCRIPT, "t", env))
  end
  local ok, err = pcall(chunk)
  if not ok and err ~= exited then error(err, 0) end
  return exited.code or 0, table.concat(out)
end

local spec
local p = io.popen("git ls-files")
for f in p:lines() do
  if f:match("^[^/]+%.rockspec$") then spec = f end
end
p:close()
assert(spec, "no rockspec at the repo root")
local rs = read(spec)

local breaker = '%["jev%.core%.breaker"%][^\n]*'

-- { name, { [path] = contents }, rule expected to fail (nil: all pass), text in its message }
local cases = {
  { "unmodified tree", {} },

  -- rockspec-modules (audit ci-release#4)
  { "rockspec: module line deleted", { [spec] = edit(rs, "\n%s*" .. breaker, "") },
    "rockspec-modules", "not in the rockspec: core/breaker.lua" },
  { "rockspec: module line commented out", { [spec] = edit(rs, "(" .. breaker .. ")", "-- %1") },
    "rockspec-modules", "not in the rockspec: core/breaker.lua" },
  { "rockspec: module line in a block comment", { [spec] = edit(rs, "(" .. breaker .. ")", "--[[ %1 ]]") },
    "rockspec-modules", "not in the rockspec: core/breaker.lua" },
  { "rockspec: module under a misspelt name",
    { [spec] = edit(rs, '%["jev%.core%.sampling"%]', '["jev.core.sampler"]') },
    "rockspec-modules", "the module name for that file is jev.core.sampling" },
  { "rockspec: duplicate key hides a module",
    { [spec] = edit(rs, '%["jev%.core%.breaker"%]', '["jev.core.defaults"]') },
    "rockspec-modules", "not in the rockspec: core/breaker.lua" },
  { "rockspec: one file under two names",
    { [spec] = edit(rs, "(" .. breaker .. ")", '%1\n      ["jev.core.breaker2"] = "core/breaker.lua",') },
    "rockspec-modules", "listed 2 times: core/breaker.lua" },
  { "rockspec: file that does not exist",
    { [spec] = edit(rs, "(" .. breaker .. ")", '%1\n      ["jev.core.gone"] = "core/gone.lua",') },
    "rockspec-modules", "listed but missing: core/gone.lua" },
  { "rockspec: does not load", { [spec] = edit(rs, "\nbuild = {", "\nbuild = {{") },
    "rockspec-modules", "does not load" },

}

local bad = 0
for _, c in ipairs(cases) do
  local name, files, want_rule, want_msg = c[1], c[2], c[3], c[4]
  local code, out = run(files)
  local why
  if not want_rule then
    if code ~= 0 then why = "expected the invariants to pass" end
  elseif code ~= 1 then
    why = "expected rule " .. want_rule .. " to fail"
  else
    local seen = false
    for failed, msg in out:gmatch("\n  %- ([%w%-]+): ([^\n]*)") do
      if failed ~= want_rule then why = "unrelated rule failed: " .. failed end
      seen = seen or msg:find(want_msg, 1, true)
    end
    if not seen then why = why or ("expected " .. want_rule .. ": ... " .. want_msg) end
  end
  if why then
    bad = bad + 1
    io.stderr:write("FAIL ", name, ": ", why, "\n", (out:gsub("[^\n]+", "    %0")))
  end
end
if bad > 0 then
  io.stderr:write(("invariants_test: %d of %d cases failed\n"):format(bad, #cases))
  os.exit(1)
end
print(("invariants_test ok (%d cases)"):format(#cases))
