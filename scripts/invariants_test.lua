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
        if s == false then return nil, path .. ": No such file or directory" end
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
local SEC = ".github/workflows/security.yml"
local REL = ".github/workflows/release-npm.yml"
local PKG = "adapters/js/package.json"
local WS = "adapters/js/pnpm-workspace.yaml"
local TSRULES = "adapters/js/src/rules/index.ts"
local ENVOY = "adapters/envoy/envoy-http.yaml"
local rs, ci, tsr, envoy = read(spec), read(CI), read(TSRULES), read(ENVOY)
local sec, rel, pkg, ws = read(SEC), read(REL), read(PKG), read(WS)

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

  -- grafana-state-timeline (audit lead-github-ops#33)
  { "grafana: the breaker panel colours by thresholds again",
    { ["ops/grafana/jev-edge.json"] = edit(read("ops/grafana/jev-edge.json"),
        '("title": "Breaker state".-"color": {%s*"mode": )"fixed"', '%1"thresholds"') },
    "grafana-state-timeline", "state timeline Breaker state has value mappings and color mode thresholds" },
  { "grafana: no state timeline left to check",
    { ["ops/grafana/jev-edge.json"] = edit(read("ops/grafana/jev-edge.json"),
        '"type": "state%-timeline"', '"type": "timeseries"') },
    "grafana-state-timeline", "no state-timeline panel found" },

  -- grafana-legend (audit lead-github-ops#34)
  { "grafana: the subject blocks panel sums the instance away again",
    { ["ops/grafana/jev-edge.json"] = edit(read("ops/grafana/jev-edge.json"),
        '"sum by %(instance%) %((rate%(jev_subject_blocks_total)', '"sum(%1') },
    "grafana-legend", "legend {{instance}} names instance, which sum drops" },
  { "grafana: a by clause that keeps another label",
    { ["ops/grafana/jev-edge.json"] = edit(read("ops/grafana/jev-edge.json"),
        '"sum by %(action%)', '"sum by (verdict)') },
    "grafana-legend", "legend {{action}} names action, which sum drops" },
  { "grafana: max by after the parentheses keeps the label",
    { ["ops/grafana/jev-edge.json"] = edit(read("ops/grafana/jev-edge.json"),
        '"max by %(instance%) %((jev_breaker_state{[^}]*})%)', '"max(%1) by (instance)') } },

  -- gateway-headers: Traefik must not relay the client's X-Forwarded-Uri (audit openresty-edge#8)
  { "traefik: trustForwardHeader true",
    { ["adapters/forward-auth/traefik.yml"] = edit(read("adapters/forward-auth/traefik.yml"),
        "trustForwardHeader: false", "trustForwardHeader: true") },
    "gateway-headers", "traefik.yml sets trustForwardHeader: true" },
  { "traefik: trustForwardHeader true with a comment",
    { ["adapters/forward-auth/traefik.yml"] = edit(read("adapters/forward-auth/traefik.yml"),
        "trustForwardHeader: false", "trustForwardHeader: true  # behind the LB") },
    "gateway-headers", "traefik.yml sets trustForwardHeader: true" },
  { "traefik: trustForwardHeader left to Traefik's default (false)",
    { ["adapters/forward-auth/traefik.yml"] = edit(read("adapters/forward-auth/traefik.yml"),
        "\n%s*trustForwardHeader: false", "") } },

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

  -- pnpm-pin: one exact pnpm, read by every workflow (audit ci-release#10)
  { "package.json: no packageManager", { [PKG] = edit(pkg, ',\n%s*"packageManager": "[^"]*"', "") },
    "pnpm-pin", 'has no "packageManager"' },
  { "package.json: packageManager is a range",
    { [PKG] = edit(pkg, '"packageManager": "pnpm@[^"]*"', '"packageManager": "pnpm@^11.9.0"') },
    "pnpm-pin", "not an exact pnpm@X.Y.Z" },
  { "package.json: packageManager is a major",
    { [PKG] = edit(pkg, '"packageManager": "pnpm@[^"]*"', '"packageManager": "pnpm@11"') },
    "pnpm-pin", "not an exact pnpm@X.Y.Z" },
  { "package.json: packageManager with its hash",
    { [PKG] = edit(pkg, '("packageManager": "pnpm@[%d%.]+)"', '%1+sha512.0123abcdef"') } },
  { "ci.yml: pnpm/action-setup back on version: 9",
    { [CI] = edit(ci, "package_json_file: adapters/js/package%.json", "version: 9") },
    "pnpm-pin", "ci.yml: pnpm/action-setup does not read the version from adapters/js/package.json" },
  { "security.yml: pnpm/action-setup with a version as well",
    { [SEC] = edit(sec, "(\n(%s*)package_json_file: adapters/js/package%.json)", "%1\n%2version: 11") },
    "pnpm-pin", "security.yml: pnpm/action-setup sets a pnpm version of its own" },
  { "release-npm.yml: pnpm/action-setup reads the root package.json",
    { [REL] = edit(rel, "package_json_file: adapters/js/package%.json", "package_json_file: package.json") },
    "pnpm-pin", "release-npm.yml: pnpm/action-setup does not read the version" },
  { "ci.yml: pnpm/action-setup as `uses:` under `- name:`, with a version",
    { [CI] = edit(ci, "\n(%s*)%- (uses: pnpm/action%-setup@[^\n]*)\n(%s*)with:\n",
        "\n%1- name: pnpm\n%1  %2\n%3with:\n%3  version: 9\n") },
    "pnpm-pin", "ci.yml: pnpm/action-setup sets a pnpm version of its own" },
  { "pnpm-workspace.yaml: missing", { [WS] = false }, "pnpm-pin", "pnpm-workspace.yaml is missing" },
  { "pnpm-workspace.yaml: what a newer pnpm writes, undecided",
    { [WS] = edit(ws, "esbuild: false", "esbuild: set this to true or false") },
    "pnpm-pin", "allowBuilds esbuild is set this to true or false" },
  { "pnpm-workspace.yaml: esbuild's build script runs", { [WS] = edit(ws, "esbuild: false", "esbuild: true") },
    "pnpm-pin", "allowBuilds esbuild is true" },
  { "pnpm-workspace.yaml: esbuild with a comment",
    { [WS] = edit(ws, "esbuild: false", "esbuild: false # see above") } },
  { "pnpm-workspace.yaml: no decisions", { [WS] = edit(ws, "\nallowBuilds:\n[^\n]*\n", "\n") },
    "pnpm-pin", "has no allowBuilds decisions" },
  { "pnpm-workspace.yaml: every build script allowed", { [WS] = ws .. "dangerouslyAllowAllBuilds: true\n" },
    "pnpm-pin", "dangerouslyAllowAllBuilds" },

  -- release-token: only the publish job holds the OIDC token, and it runs no
  -- repository or dependency code (audit ci-release#1)
  { "release-npm.yml: id-token for the whole workflow again",
    { [REL] = edit(rel, "\npermissions:\n  contents: read\n",
        "\npermissions:\n  contents: read\n  id-token: write\n") },
    "release-token", "workflow-level permissions are not just `contents: read`" },
  { "release-npm.yml: write-all for the whole workflow",
    { [REL] = edit(rel, "\npermissions:\n  contents: read\n", "\npermissions: write-all\n") },
    "release-token", "workflow-level permissions are not just `contents: read` (write-all)" },
  { "release-npm.yml: the build job holds the token too",
    { [REL] = edit(rel, "(\n  build:\n    runs%-on: [^\n]*\n)",
        "%1    permissions:\n      contents: read\n      id-token: write\n") },
    "release-token", "2 jobs hold the OIDC token (build, publish)" },
  { "release-npm.yml: publish outside the npm environment",
    { [REL] = edit(rel, "\n    environment: [^\n]*", "") },
    "release-token", "job publish holds the OIDC token outside the npm environment" },
  { "release-npm.yml: publish in the environment object form",
    { [REL] = edit(rel, "\n    environment: [^\n]*",
        "\n    environment:\n      name: npm\n      url: https://www.npmjs.com/package/@jev-edge/js") } },
  { "release-npm.yml: publish checks out the repository",
    { [REL] = edit(rel, "(\n(%s*)%- uses: actions/download%-artifact@)", "\n%2- uses: actions/checkout@v7%1") },
    "release-token", "job publish holds the OIDC token and checks out the repository" },
  { "release-npm.yml: publish installs the dependencies",
    { [REL] = edit(rel, "(\n(%s*)%- name: npm for trusted publishing)", "\n%2- run: npm ci%1") },
    "release-token", "installs or runs packages: - run: npm ci" },
  { "release-npm.yml: publish runs pnpm",
    { [REL] = edit(rel, "(\n(%s*)%- name: npm for trusted publishing)",
        "\n%2- run: pnpm install --frozen-lockfile --ignore-scripts%1") },
    "release-token", "installs or runs packages: - run: pnpm install" },
  { "release-npm.yml: npm for publishing is a range",
    { [REL] = edit(rel, "npm install %-g npm@[%d%.]+", 'npm install -g "npm@>=11.5.1"') },
    "release-token", "publishes with npm@>=11.5.1, not an exact version" },
  { "release-npm.yml: npm publish from the working directory",
    { [REL] = edit(rel, 'npm publish "%./%$TARBALL"', "npm publish") },
    "release-token", "npm publish is not given the packed tarball" },
  { "release-npm.yml: npm publish runs lifecycle scripts",
    { [REL] = edit(rel, "(npm publish [^\n]*) %-%-ignore%-scripts", "%1") },
    "release-token", "npm publish runs lifecycle scripts" },
  { "release-npm.yml: no npm publish",
    { [REL] = edit(rel, "\n[^\n]*run: npm publish [^\n]*", "\n        run: echo") },
    "release-token", "runs no npm publish" },
  { "release-npm.yml: build runs dependency scripts",
    { [REL] = edit(rel, "pnpm install %-%-frozen%-lockfile %-%-ignore%-scripts", "pnpm install --frozen-lockfile") },
    "release-token", "job build: pnpm install runs dependency scripts" },

  -- release-on-main: both jobs check that a tag's commit is on main (lead-github-ops#32)
  { "release-npm.yml: build does not check main",
    { [REL] = edit(rel, "\n        run: |\n          if ! git merge%-base[^\n]*\n[^\n]*\n[^\n]*\n          fi\n",
        "\n        run: echo skipped\n") },
    "release-on-main", "job build does not check that a tag's commit is on main" },
  { "release-npm.yml: publish does not check main",
    { [REL] = edit(rel, "compare/main%.%.%.%$GITHUB_SHA", "compare/$GITHUB_SHA...$GITHUB_SHA") },
    "release-on-main", "job publish does not check that a tag's commit is on main" },
  { "release-npm.yml: build checks a release branch instead of main",
    { [REL] = edit(rel, '(%-%-is%-ancestor "%$GITHUB_SHA" origin/)main', "%1release/0.6") },
    "release-on-main", "job build does not check that a tag's commit is on main" },
  { "release-npm.yml: build's check never runs",
    { [REL] = edit(rel, "(\n      %- name: A tag's commit is on main\n        if: )github%.ref_type == 'tag'"
        .. "(\n        working%-directory: %.)", "%1false%2") },
    "release-on-main", "job build: the check that a tag's commit is on main runs only if false" },
  { "release-npm.yml: publish's check runs on dry runs only",
    { [REL] = edit(rel, "(\n      %- name: A tag's commit is on main\n        if: )github%.ref_type == 'tag'"
        .. "(\n        env:\n          GH_TOKEN)", "%1${{ inputs.dry_run }}%2") },
    "release-on-main", "job publish: the check that a tag's commit is on main runs only if inputs.dry_run" },
  { "release-npm.yml: build's check as ${{ }}",
    { [REL] = edit(rel, "(\n      %- name: A tag's commit is on main\n        if: )github%.ref_type == 'tag'"
        .. "(\n        working%-directory: %.)", "%1${{ github.ref_type == 'tag' }}%2") } },
  { "release-npm.yml: shallow checkout",
    { [REL] = edit(rel, "\n          fetch%-depth: 0[^\n]*", "") },
    "release-on-main", "job build: checks main's history without fetching it" },
  { "security.yml: package_json_file with a trailing comment",
    { [SEC] = edit(sec, "(package_json_file: adapters/js/package%.json)", "%1 # the pin") } },

  -- npm-exports: every export loads from require() as well (audit packaging#6)
  { "package.json: ./core without default",
    { [PKG] = edit(pkg, '(\n%s*"import": "%./dist/core/index%.js"),\n%s*"default": "[^"]*"', "%1") },
    "npm-exports", 'exports ./core: "default" is nil' },
  { "package.json: default names another file",
    { [PKG] = edit(pkg, '"default": "%./dist/aws%.js"', '"default": "./dist/aws.cjs"') },
    "npm-exports", 'exports ./aws: "default" is ./dist/aws.cjs, not the "import" file ./dist/aws.js' },
  { "package.json: default before types",
    { [PKG] = edit(pkg,
        '(\n%s*)"types": "%./dist/deno%.d%.ts",(\n%s*"import": "%./dist/deno%.js"),\n%s*"default": "%./dist/deno%.js"',
        '%1"default": "./dist/deno.js",%1"types": "./dist/deno.d.ts",%2') },
    "npm-exports", 'exports ./deno: "default" is not the last condition' },
  { "package.json: a new export CI does not load",
    { [PKG] = edit(pkg, '(\n%s*)"%./package%.json": "%./package%.json"',
        '%1"./node": {%1  "types": "./dist/node.d.ts",%1  "import": "./dist/node.js",'
          .. '%1  "default": "./dist/node.js"%1},%1"./package.json": "./package.json"') },
    "npm-exports", "ci.yml does not require() exports ./node" },
  { "ci.yml: no require() smoke", { [CI] = edit(ci, "\n[^\n]*require%('@jev%-edge/js' %+ s%)[^\n]*", "") },
    "npm-exports", "ci.yml does not require() exports ." },
  { "ci.yml: require() smoke skips /frameworks",
    { [CI] = edit(ci, "(%[''[^%]\n]*)'/frameworks', ([^%]\n]*%]%) require)", "%1%2") },
    "npm-exports", "ci.yml does not require() exports ./frameworks" },

  -- gateway-headers: Envoy passes a client's x-envoy-external-address from an
  -- internal peer (audit g1-proxy-forwarded-metadata-live#1)
  { "envoy-http.yaml: x-envoy-external-address allow-listed again",
    { [ENVOY] = edit(envoy, "(\n(%s*)%- exact: x%-forwarded%-for\n)", "%1%2- exact: x-envoy-external-address\n") },
    "gateway-headers", "forwards a client's x-envoy-external-address" },
  { "envoy-http.yaml: x-envoy-external-address as a prefix pattern",
    { [ENVOY] = edit(envoy, "(\n(%s*)%- exact: x%-forwarded%-for\n)", "%1%2- prefix: X-Envoy-External\n") },
    "gateway-headers", "forwards a client's x-envoy-external-address" },

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
