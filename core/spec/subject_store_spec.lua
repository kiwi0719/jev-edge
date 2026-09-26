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

  -- The same table is in adapters/js/test/subject.test.ts: both cores must
  -- give these candidates, so a Worker and its origin agree on the ids.
  local COOKIES = {
    { "SID=x; sid=REAL", { "REAL" } },                       -- names are case-sensitive
    { "sid=x; sid=REAL", { "x", "REAL" } },                  -- duplicates: every one
    { "sid=REAL; sid=x", { "REAL", "x" } },
    { { "sid=REAL", "sid=x" }, { "REAL", "x" } },            -- the header sent twice
    { 'sid="REAL"', { "REAL" } },                            -- one pair of DQUOTEs stripped
    { 'sid="RE\\AL"', { "RE\\AL", "REAL" } },                 -- and the unescaped form
    { 'sid="\\122EAL"', { "\\122EAL", "REAL" } },             -- octal escape
    { 'sid="\\351t\\351"', { "\\351t\\351", "\195\169t\195\169" } }, -- a code point past ASCII, UTF-8
    { " sid = REAL ;other=1", { "REAL" } },
    { "sid=; sid=\"\"; foo=REAL", {} },
    { "sid=a; sid=b; sid=c; sid=d; sid=e; sid=f", { "a", "b", "e", "f" } },   -- capped: first two, last two
  }

  it("reads every value a Cookie header gives the name, as the backend may (g1-subject-id-evasion#1)", function()
    local scfg = { enabled = true, from = "cookie", name = "sid", salt = "pepper" }
    for _, c in ipairs(COOKIES) do
      assert.same(c[2], subject.cookie_values(c[1], "sid"))
      assert.same(c[2], subject.extract_all(scfg, { cookie_header = c[1] }))
      local ids = subject.hash_ids(scfg, subject.extract_all(scfg, { cookie_header = c[1] }), hash)
      assert.equals(#c[2], #ids)
      if c[2][1] then assert.equals("cookie:H(pepper\0" .. c[2][1] .. ")", ids[1]) end
    end
    -- whoever the backend picks, REAL is among the ids once it is sent
    local real = subject.hash_id(scfg, "REAL", hash)
    for _, h in ipairs({ "SID=x; sid=REAL", "sid=x; sid=REAL", "sid=REAL; sid=x", 'sid="REAL"' }) do
      local ids = subject.hash_ids(scfg, subject.extract_all(scfg, { cookie_header = h }), hash)
      local found = false
      for _, id in ipairs(ids) do found = found or id == real end
      assert.is_true(found, h)
    end
    -- an older adapter's single value still works
    assert.same({ "s-9" }, subject.extract_all(scfg, { cookie = function() return "s-9" end }))
  end)

  -- The same table is in adapters/js/test/subject.test.ts.
  local AUTH = {
    { "Bearer k", "bearer k" }, { "bearer k", "bearer k" }, { "BEARER k", "bearer k" },
    { "Bearer  k", "bearer k" }, { "Bearer\tk", "bearer k" }, { " Bearer \t k ", "bearer k" },
    { "Bearer K", "bearer K" },                       -- the credentials are kept byte for byte
    { "Basic QWxhZGRpbjpvcGVu", "basic QWxhZGRpbjpvcGVu" },
    { "sk-no-scheme", "sk-no-scheme" },               -- no scheme: as is
    { "Digest a=1,  b=2", "digest a=1,  b=2" },
  }

  it("canonicalises the scheme of Authorization and Proxy-Authorization (g1-subject-id-evasion#4)", function()
    for _, name in ipairs({ "authorization", "Authorization", "proxy-authorization", "Proxy-Authorization" }) do
      local scfg = { enabled = true, from = "header", name = name, salt = "pepper" }
      for _, c in ipairs(AUTH) do
        assert.equals(c[2], subject.extract(scfg, { header = function() return c[1] end }), name .. " " .. c[1])
      end
      local one = subject.hash_id(scfg, subject.extract(scfg, { header = function() return "Bearer k" end }), hash)
      for _, v in ipairs({ "bearer k", "BEARER k", "Bearer  k", "Bearer\tk" }) do
        assert.equals(one, subject.hash_id(scfg, subject.extract(scfg, { header = function() return v end }), hash))
      end
    end
    -- any other header is kept as sent
    assert.equals("Bearer  K", subject.extract({ enabled = true, from = "header", name = "x-api-key" },
      { header = function() return "Bearer  K" end }))
  end)

  it("ids_of: id first, then the distinct ids, at most MAX_IDS", function()
    assert.same({}, subject.ids_of({ subject = { ids = { "a" } } }))
    assert.same({ "a" }, subject.ids_of({ subject = { id = "a" } }))
    assert.same({ "a", "b", "c", "d" },
      subject.ids_of({ subject = { id = "a", ids = { "a", "b", "", 7, "b", "c", "d", "e" } } }))
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

describe("subject ring store (no compare-and-swap needed)", function()
  it("appends with incr + set and loads the newest max_entries in order", function()
    local store = H.store()
    assert.is_nil(subject.ring_load(store, "ip:a", 3))
    for i = 1, 5 do subject.ring_append(store, "ip:a", { score = i / 10 }, 3, 60) end
    local h = subject.ring_load(store, "ip:a", 3)
    assert.equals(3, #h)
    assert.equals(0.3, h[1].score)
    assert.equals(0.5, h[3].score)
    assert.equals(5, store:get("subj:ip:a:n"))
    assert.is_nil(store:get("subj:ip:a"), "no list key: nothing is ever read-modified-written")
  end)

  it("skips evicted slots instead of failing", function()
    local store = H.store()
    for i = 1, 3 do subject.ring_append(store, "ip:b", { score = i }, 3, 60) end
    store:set("subj:ip:b:1", nil)
    local h = subject.ring_load(store, "ip:b", 3)
    assert.equals(2, #h)
    assert.equals(1, h[1].score)
    assert.equals(3, h[2].score)
  end)

  it("drops a slot still holding the previous lap instead of reading it as the newest", function()
    local store = H.store()
    for i = 1, 3 do subject.ring_append(store, "ip:c", { score = i }, 3, 60) end
    -- another worker has incr'd to 4 but not yet written slot (4-1)%3 = 0
    store:incr("subj:ip:c:n", 1, 60)
    local h = subject.ring_load(store, "ip:c", 3)
    assert.equals(2, #h)
    assert.equals(2, h[1].score)
    assert.equals(3, h[2].score)
  end)

  it("reads no misplaced entries after max_entries changes", function()
    local store = H.store()
    for i = 1, 5 do subject.ring_append(store, "ip:d", { score = i }, 3, 60) end
    -- max 3 put seq 4 in slot 0 and seq 5 in slot 1; read with max 4 those
    -- slots are expected to hold seq 5 and 2, so both are holes
    local h = subject.ring_load(store, "ip:d", 4)
    assert.equals(1, #h)
    assert.equals(3, h[1].score)
  end)

  it("extends the counter ttl on every append", function()
    local store = H.store()
    local seen = {}
    store.expire = function(_, k, ttl) seen[#seen + 1] = k .. "=" .. ttl; return true end
    subject.ring_append(store, "ip:e", { score = 1 }, 3, 60)
    subject.ring_append(store, "ip:e", { score = 2 }, 3, 60)
    assert.same({ "subj:ip:e:n=60", "subj:ip:e:n=60" }, seen)
  end)

  it("is a no-op on a store without incr", function()
    assert.is_false(subject.ring_append({ get = function() end, set = function() end }, "x", {}, 3, 60))
  end)
end)
