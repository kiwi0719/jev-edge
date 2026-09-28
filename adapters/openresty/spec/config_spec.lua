local H = require "core.spec.helper"

-- resty/jev/config.lua's runtime override against a stand-in jev_config dict
-- that can refuse a write (no memory), as a full lua_shared_dict does. dkjson
-- stands in for cjson.safe, as in openai_compat_spec.lua.
package.path = "./adapters/openresty/lib/?.lua;" .. package.path
package.preload["cjson.safe"] = function()
  return {
    encode = function(v) return H.json.encode(v) end,
    decode = function(s)
      local ok, v = pcall(H.json.decode, s, 1, H.json.null)
      if ok then return v end
      return nil
    end,
  }
end

describe("config: set_override", function()
  local config, saved_ngx, data, refuse

  setup(function()
    saved_ngx = _G.ngx
  end)
  teardown(function()
    _G.ngx = saved_ngx
    package.loaded["resty.jev.config"] = nil
  end)
  before_each(function()
    data, refuse = {}, {}
    local dict = {
      get = function(_, k) return data[k] end,
      set = function(_, k, v)
        if refuse.set then return false, "no memory" end
        data[k] = v
        return true
      end,
      safe_set = function(_, k, v)
        if refuse.set then return nil, "no memory" end
        data[k] = v
        return true
      end,
      delete = function(_, k) data[k] = nil end,
      incr = function(_, k, by, init)
        if refuse.incr then return nil, "no memory" end
        if data[k] == nil then
          if init == nil then return nil, "not found" end
          data[k] = init
        end
        data[k] = data[k] + by
        return data[k]
      end,
    }
    _G.ngx = { shared = { jev_config = dict }, log = function() end, ERR = 4, WARN = 5, NOTICE = 6 }
    package.loaded["resty.jev.config"] = nil
    config = require "resty.jev.config"
    config.init(nil)
  end)

  it("stores the override, bumps the version and puts it in force", function()
    assert.is_true(config.set_override({ cache = { fp_ttl = 30 } }))
    assert.equal(1, data.override_version)
    assert.same({ cache = { fp_ttl = 30 } }, config.get_override())
    assert.equal(30, config.current().cache.fp_ttl)
  end)

  it("reports a write the dict refuses, and changes nothing", function()
    local before = config.current().cache.fp_ttl
    refuse.set = true
    local ok, err, internal = config.set_override({ cache = { fp_ttl = 30 } })
    assert.is_nil(ok)
    assert.matches("cannot store the override in lua_shared_dict jev_config: no memory", err, 1, true)
    assert.is_true(internal)
    assert.is_nil(data.override_version)
    assert.is_nil(config.get_override())
    assert.equal(before, config.current().cache.fp_ttl)
  end)

  it("reports a version the dict cannot bump, and puts back the override in force", function()
    assert.is_true(config.set_override({ cache = { fp_ttl = 30 } }))
    refuse.incr = true
    local ok, err, internal = config.set_override({ cache = { fp_ttl = 60 } })
    assert.is_nil(ok)
    assert.matches("cannot bump override_version", err, 1, true)
    assert.is_true(internal)
    assert.equal(1, data.override_version)
    assert.same({ cache = { fp_ttl = 30 } }, config.get_override())
    assert.equal(30, config.current().cache.fp_ttl)

    -- a DELETE the version cannot announce leaves the override too
    local dok, _, dinternal = config.set_override(nil)
    assert.is_nil(dok)
    assert.is_true(dinternal)
    assert.same({ cache = { fp_ttl = 30 } }, config.get_override())
  end)

  it("refuses an invalid override without the internal flag (422, not 500)", function()
    local ok, err, internal = config.set_override({ policy = { mode = "sometimes" } })
    assert.is_nil(ok)
    assert.is_string(err)
    assert.is_nil(internal)
  end)
end)
