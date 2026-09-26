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
local CI = ".github/workflows/ci.yml"
local TSRULES = "adapters/js/src/rules/index.ts"
local rs, ci, tsr = read(spec), read(CI), read(TSRULES)

local function with_newjob(s)
  return edit(s, "\n  ci%-ok:\n",
    "\n  newjob:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: exit 1\n\n  ci-ok:\n")
end
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

  -- ci-ok: every job, whatever the jobs: line looks like (audit ci-release#5)
  { "ci.yml: new job not in needs", { [CI] = with_newjob(ci) }, "ci-ok", "ci-ok does not need job newjob" },
  { "ci.yml: jobs: with a comment, new job not in needs",
    { [CI] = with_newjob(edit(ci, "\njobs:\n", "\njobs: # every job below\n")) },
    "ci-ok", "ci-ok does not need job newjob" },
  { "ci.yml: jobs: with a trailing space, new job not in needs",
    { [CI] = with_newjob(edit(ci, "\njobs:\n", "\njobs: \n")) },
    "ci-ok", "ci-ok does not need job newjob" },
  { "ci.yml: CRLF, new job not in needs", { [CI] = (with_newjob(ci):gsub("\n", "\r\n")) },
    "ci-ok", "ci-ok does not need job newjob" },
  { "ci.yml: CRLF, unchanged otherwise", { [CI] = (ci:gsub("\n", "\r\n")) } },
  { "ci.yml: job dropped from needs", { [CI] = edit(ci, "(\n    needs: %[[^%]\n]*)e2e, ", "%1") },
    "ci-ok", "ci-ok does not need job e2e" },
  { "ci.yml: no jobs found", { [CI] = edit(ci, "\njobs:\n", "\njobs_:\n") }, "ci-ok", "found 0 jobs in ci.yml" },
  { "ci.yml: ci-ok without needs", { [CI] = edit(ci, "(\n  ci%-ok:\n    if: [^\n]*)\n    needs: [^\n]*", "%1") },
    "ci-ok", "ci-ok has no needs" },

  -- ci-ok: runs when a job failed and fails unless all succeeded (audit ci-release#6)
  { "ci.yml: ci-ok without if: always()", { [CI] = edit(ci, "(\n  ci%-ok:)\n    if: always%(%)", "%1") },
    "ci-ok", "ci-ok has no `if: always()`" },
  { "ci.yml: ci-ok with if: success()", { [CI] = edit(ci, "(\n  ci%-ok:\n    if: )always%(%)", "%1success()") },
    "ci-ok", "ci-ok has no `if: always()`" },
  { "ci.yml: ci-ok with if: ${{ always() }}",
    { [CI] = edit(ci, "(\n  ci%-ok:\n    if: )always%(%)", "%1${{ always() }}") } },
  { "ci.yml: ci-ok with if: 'always()' # comment",
    { [CI] = edit(ci, "(\n  ci%-ok:\n    if: )always%(%)", "%1'always()'  # runs whatever the jobs did") } },
  { "ci.yml: ci-ok with if: !cancelled() (skipped, so passing, in a cancelled run)",
    { [CI] = edit(ci, "(\n  ci%-ok:\n    if: )always%(%)", "%1${{ !cancelled() }}") },
    "ci-ok", "ci-ok has no `if: always()`" },
  { "ci.yml: ci-ok with if: !cancelled() && !failure() (skipped when a job failed)",
    { [CI] = edit(ci, "(\n  ci%-ok:\n    if: )always%(%)", "%1${{ !cancelled() && !failure() }}") },
    "ci-ok", "ci-ok has no `if: always()`" },
  { "ci.yml: ci-ok with if: always() && !failure()",
    { [CI] = edit(ci, "(\n  ci%-ok:\n    if: )always%(%)", "%1always() && !failure()") },
    "ci-ok", "ci-ok has no `if: always()`" },
  { "ci.yml: ci-ok with always() only in a comment",
    { [CI] = edit(ci, "(\n  ci%-ok:\n    if: )always%(%)", "%1success() # not always()") },
    "ci-ok", "ci-ok has no `if: always()`" },
  { "ci.yml: jq test weakened", { [CI] = edit(ci, '%.result == "success"', '.result != "failure"') },
    "ci-ok", "ci-ok does not run jq -e" },
  { "ci.yml: jq test replaced by true", { [CI] = edit(ci, "jq %-e 'all[^\n]*'", "jq -e 'true'") },
    "ci-ok", "ci-ok does not run jq -e" },
  { "ci.yml: jq without -e", { [CI] = edit(ci, "jq %-e 'all", "jq 'all") }, "ci-ok", "ci-ok does not run jq -e" },
  { "ci.yml: jq line removed", { [CI] = edit(ci, "\n[^\n]*jq %-e 'all[^\n]*", "") },
    "ci-ok", "ci-ok does not run jq -e" },
  { "ci.yml: jq line commented out", { [CI] = edit(ci, "\n(%s*)(echo[^\n]*jq %-e 'all)", "\n%1# %2") },
    "ci-ok", "ci-ok does not run jq -e" },

  -- rule-parity: a path watched for any body on one runtime only
  { "rules: json_only_paths emptied in the TS copy",
    { [TSRULES] = edit(tsr, 'json_only_paths: %["%^/%$"%]', "json_only_paths: []") },
    "rule-parity", "json_only_paths differ" },
  -- rule-parity: token prompts refused on one runtime only
  { "rules: token_prompts differs in the TS copy",
    { [TSRULES] = edit(tsr, 'token_prompts: "unjudgeable"', 'token_prompts: "block"') },
    "rule-parity", "token_prompts: Lua unjudgeable vs TS block" },
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
