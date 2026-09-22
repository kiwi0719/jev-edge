local H = require "core.spec.helper"
local subject = require "jev.core.subject"
local defaults = require "jev.core.defaults"

local function hash(s) return "H(" .. s .. ")" end

describe("subject extraction and hashing", function()
  it("is off by default", function()
    assert.is_nil(subject.extract(defaults.config.subject, { ip = "1.2.3.4" }))
  end)

  it("extracts ip, header or cookie and trims", function()
    assert.equals("1.2.3.4", subject.extract({ enabled = true, from = "ip" }, { ip = "1.2.3.4" }))
    local view = { header = function(n) return n == "x-api-key" and " key-1 " or nil end,
                   cookie = function(n) return n == "sid" and "s-9" or nil end }
    assert.equals("key-1", subject.extract({ enabled = true, from = "header", name = "x-api-key" }, view))
    assert.equals("s-9", subject.extract({ enabled = true, from = "cookie", name = "sid" }, view))
    assert.is_nil(subject.extract({ enabled = true, from = "header", name = "missing" }, view))
    assert.is_nil(subject.extract({ enabled = true, from = "header", name = "x" },
      { header = function() return "  " end }))
  end)

  it("hashes with the salt and never exposes the raw value", function()
    local id = subject.hash_id({ from = "header", salt = "pepper" }, "key-1", hash)
    assert.equals("header:H(pepper\0key-1)", id)
    assert.is_nil(subject.hash_id({ from = "header" }, "key-1", hash), "no salt, no id")
    assert.equals("header:abc123", subject.hash_id({ hashed = true }, "header:abc123", hash))
    assert.is_nil(subject.hash_id({ hashed = true }, "not a hash; drop table", hash),
      "hashed = true only accepts our own id shape")
    assert.is_nil(subject.extract({ enabled = true, from = "header", name = "x" },
      { header = function() return string.rep("k", 600) end }), "oversize values are dropped")
    assert.equals("cookie:abc", subject.hash_id({ from = "header", hashed = true }, "cookie:abc", hash))
    assert.is_nil(subject.hash_id({ from = "ip", salt = "x" }, nil, hash))
  end)

  it("keeps a bounded history in the store", function()
    local store = H.store()
    local h
    for i = 1, 5 do
      h = subject.append(subject.load(store, "ip:1"), { at = i, score = i / 10 }, 3)
      subject.save(store, "ip:1", h, 60)
    end
    local got = subject.load(store, "ip:1")
    assert.equals(3, #got)
    assert.same({ 3, 4, 5 }, { got[1].at, got[2].at, got[3].at })
    assert.is_nil(subject.load(store, "ip:2"))
    assert.is_nil(subject.load(nil, "ip:1"))
  end)

  it("validates the config", function()
    local function v(over) return defaults.validate(defaults.merge(defaults.config, { subject = over })) end
    assert.is_true((v({ enabled = true, from = "ip", salt = "s" })))
    local _, e1 = v({ enabled = true, from = "header" }); assert.matches("subject.name", e1)
    local _, e2 = v({ enabled = true, from = "header", name = "x" }); assert.matches("salt", e2)
    assert.is_true((v({ enabled = true, from = "header", name = "x", hashed = true })))
    local _, e3 = v({ from = "jwt" }); assert.matches("ip|header|cookie", e3)
    local _, e4 = v({ max_entries = 0 }); assert.matches("max_entries", e4)
  end)
end)
