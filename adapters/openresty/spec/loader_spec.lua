-- resty/jev/loader.lua maps jev.core.* / jev.rules.* onto core/ and rules/ for
-- the repo layout. An installed copy (rock, opm, make install) must win over
-- any core/*.lua or rules/*.lua that happens to sit on package.path: the
-- searcher only fills in when the real module does not resolve.

local LIB = "./adapters/openresty/lib/?.lua"

local function sh(cmd)
  local ok = os.execute(cmd)
  assert(ok == true or ok == 0, cmd)
end

local function write(path, src)
  local f = assert(io.open(path, "w"))
  f:write(src)
  f:close()
end

describe("resty.jev.loader", function()
  if not package.searchpath then
    pending("needs package.searchpath (LuaJIT or Lua 5.2+)")
    return
  end

  local loader, root, inst, foreign, saved_path

  -- inst/ is an installed layout (jev/core, jev/rules), foreign/ an app's own
  -- core/ and rules/ with the same names: the repo layout's shape.
  setup(function()
    saved_path = package.path
    package.path = LIB .. ";" .. saved_path
    package.loaded["resty.jev.loader"] = nil
    loader = require "resty.jev.loader"
    package.path = saved_path

    root = os.tmpname()
    os.remove(root)
    inst, foreign = root .. "/inst", root .. "/foreign"
    sh(("mkdir -p '%s/jev/core' '%s/jev/rules' '%s/core' '%s/rules'"):format(inst, inst, foreign, foreign))
    for _, dir in ipairs({ { inst, "jev/", "installed" }, { foreign, "", "foreign" } }) do
      local base, sub, tag = dir[1], dir[2], dir[3]
      write(base .. "/" .. sub .. "rules/llm-endpoints.lua", ("return { id = %q }"):format(tag))
      write(base .. "/" .. sub .. "rules/zz-loader-spec.lua", ("return { id = %q }"):format(tag))
      write(base .. "/" .. sub .. "core/policy.lua", ("return { id = %q }"):format(tag))
      write(base .. "/" .. sub .. "core/init.lua", ("return { id = %q }"):format(tag))
    end
  end)

  teardown(function()
    package.path = saved_path
    package.loaded["resty.jev.loader"] = nil
    if root then sh(("rm -rf '%s'"):format(root)) end
  end)

  local function with_path(dirs, fn)
    local parts = {}
    for _, d in ipairs(dirs) do
      parts[#parts + 1] = d .. "/?.lua"
      parts[#parts + 1] = d .. "/?/init.lua"
    end
    local saved = package.path
    package.path = table.concat(parts, ";")
    local ok, a, b = pcall(fn)
    package.path = saved
    assert(ok, a)
    return a, b
  end

  it("steps aside when the installed module resolves, whatever the path order", function()
    for _, order in ipairs({ { inst, foreign }, { foreign, inst } }) do
      with_path(order, function()
        assert.is_nil(loader.searcher("jev.rules.llm-endpoints"))
        assert.is_nil(loader.searcher("jev.core.policy"))
        assert.is_nil(loader.searcher("jev.core"))
      end)
    end
  end)

  it("fills in for the repo layout: core/ and rules/ directly on the path", function()
    with_path({ foreign }, function()
      local chunk, path = loader.searcher("jev.rules.llm-endpoints")
      assert.equal("function", type(chunk))
      assert.equal(foreign .. "/rules/llm-endpoints.lua", path)
      assert.equal("foreign", chunk().id)
      chunk, path = loader.searcher("jev.core")
      assert.equal(foreign .. "/core/init.lua", path)
      assert.equal("foreign", chunk().id)
      assert.equal("foreign", loader.searcher("jev.core.policy")().id)
    end)
  end)

  it("ignores names outside jev.core / jev.rules", function()
    with_path({ foreign }, function()
      assert.is_nil(loader.searcher("core.policy"))
      assert.is_nil(loader.searcher("rules.llm-endpoints"))
      assert.is_nil(loader.searcher("jev.other"))
    end)
  end)

  it("installs once when called, and require then loads the installed copy", function()
    local searchers = package.searchers or package.loaders -- luacheck: ignore 143
    local n = #searchers
    loader()
    loader()
    assert.equal(n + 1, #searchers)
    assert.equal(loader.searcher, searchers[2])
    local ok, mod = pcall(with_path, { foreign, inst }, function()
      package.loaded["jev.rules.zz-loader-spec"] = nil
      return require("jev.rules.zz-loader-spec")
    end)
    package.loaded["jev.rules.zz-loader-spec"] = nil
    table.remove(searchers, 2)
    assert(ok, mod)
    assert.equal("installed", mod.id)
  end)
end)
