-- core/subject.lua
-- Subject trajectory: the contract slot for per-subject scoring.
--
-- A single request can look harmless and still be the sixth step of an attack
-- that is being assembled one message at a time. Catching that needs a score
-- per subject over time, not per request. This module is the half of that we
-- can build without traffic: the shape of one trajectory entry, and where the
-- core hands it over.
--
-- What 0.2.x does: records. `ctx.subject.history` is accepted and IGNORED, so
-- evaluate() behaves exactly as it did before, byte for byte -- the golden
-- vectors assert that. No window length, decay factor or "six 0.4s in a row"
-- threshold is chosen, because there is no traffic to calibrate one against
-- and a guess dressed as a default is worse than an absent feature.
--
-- What a later version does: reads `history`, folds it into the score, and
-- returns a verdict that a single request could not have earned. That is an
-- implementation change in two places. The contract below does not move, so
-- adapters and golden vectors are written once.
--
-- Where the IO goes, and why the split is not negotiable:
--   read   ctx.subject.history   one store lookup, on the request path, may
--                                be nil (cold subject, evicted entry, a store
--                                that lost it) -- nil is always a valid answer
--                                and never an error.
--   write  ctx.subject.record    a sink, off the request path. The core hands
--                                over a value and returns; it never waits for
--                                the write. Handing over instead of returning
--                                is what makes that structural rather than a
--                                rule adapters have to remember.

local _M = {}

_M.FORMAT = 1

--- One trajectory entry: flat, so it maps 1:1 onto JSON, a log line and a
--- dict value, and can be replayed later as calibration input.
-- Carries the raw score, not only the label: a stream of 0.4s is the signal a
-- later version has to be able to see, and a label throws it away.
-- @param id  subject identifier, as the adapter extracted it
-- @param v   the verdict this request produced
-- @param now seconds, from ctx.clock
function _M.entry(id, v, now)
  return {
    at          = tonumber(now) or 0,
    subject     = tostring(id or ""),
    verdict     = v.verdict,
    score       = v.score,
    source      = v.source,
    reason      = v.reason,
    fingerprint = v.fingerprint,
  }
end

--- The subject id for this request, or nil when there is none.
-- nil is the normal case: an adapter that does not extract a subject, or a
-- request that carries no identity, both land here and both mean "no
-- trajectory", never "error".
function _M.id_of(ctx)
  local s = ctx.subject
  if type(s) ~= "table" then return nil end
  local id = s.id
  if type(id) ~= "string" or id == "" then return nil end
  return id
end

--- Every id this request names, ctx.subject.id first, then the distinct
-- ctx.subject.ids (at most MAX_IDS in all). An adapter that found several
-- candidate values (a cookie sent twice under one name, quoted or not)
-- passes them all: which one the backend reads is its choice, not ours, so
-- reputation checks and charges every one.
function _M.ids_of(ctx)
  local id = _M.id_of(ctx)
  if not id then return {} end
  local out, seen = { id }, { [id] = true }
  local ids = ctx.subject.ids
  if type(ids) == "table" then
    for _, x in ipairs(ids) do
      if #out >= _M.MAX_IDS then break end
      if type(x) == "string" and x ~= "" and not seen[x] then seen[x], out[#out + 1] = true, x end
    end
  end
  return out
end

--- Hand one entry to the sink, if there is a subject and a sink.
-- Returns the entry it recorded, or nil. Errors in the sink are swallowed:
-- a trajectory write must never be able to fail a request.
function _M.record(ctx, v)
  local id = _M.id_of(ctx)
  if not id then return nil end
  local sink = ctx.subject.record
  if type(sink) ~= "function" then return nil end
  local e = _M.entry(id, v, ctx.clock and ctx.clock() or 0)
  pcall(sink, e)
  return e
end

-- ---------------------------------------------------------------------------
-- Subject reputation. What IP reputation does per address, per subject: the
-- judged verdicts of one subject (a user header, a cookie, or an IP) add
-- points over a sliding window, and past `block_at` points the subject is
-- blocked at L1 for `block_ttl` seconds. It catches one user probing variants
-- across sessions and addresses, and APIs that do not resend history, and it
-- needs no dataset: `make calibrate` reads the points per subject from
-- monitor-mode logs. Off unless cfg.subject.reputation.block_at > 0.
--
-- store: ctx.subject.store, { get, set, incr = fn(self, key, by, ttl) }
-- (incr optional: without it the count is a get + set, best effort).
-- Keys: srep:<id>:b:<bucket> (points in one window-sized bucket),
--       srep:<id>:until      (blocked until, seconds).
-- The sliding window is the current bucket plus the previous one weighted by
-- how much of it still overlaps the window: two counters, no list.
-- ---------------------------------------------------------------------------

_M.REP_PREFIX = "srep:"

local function rep_cfg(ctx)
  local c = ctx.config and ctx.config.subject
  local r = type(c) == "table" and c.reputation
  if type(r) ~= "table" then return nil end
  local at = tonumber(r.block_at)
  if not at or at <= 0 then return nil end
  return r, at
end

local function rep_store(ctx)
  local s = ctx.subject
  if type(s) == "table" and type(s.store) == "table" then return s.store end
  return nil
end

--- true when the subject of this request is blocked by its reputation:
-- any of its ids (ids_of).
function _M.rep_blocked(ctx)
  if not rep_cfg(ctx) then return false end
  local store = rep_store(ctx)
  if not store then return false end
  local now = ctx.clock and ctx.clock() or 0
  for _, id in ipairs(_M.ids_of(ctx)) do
    local ok, untl = pcall(store.get, store, _M.REP_PREFIX .. id .. ":until")
    if ok and tonumber(untl) ~= nil and tonumber(untl) > now then return true end
  end
  return false
end

local function incr(store, key, by, ttl)
  if type(store.incr) == "function" then return tonumber(store:incr(key, by, ttl)) end
  local n = (tonumber(store:get(key)) or 0) + by
  store:set(key, n, ttl)
  return n
end

--- Add this verdict's points and block the subject when it crosses block_at.
-- Only judged verdicts count (L2, cache): an L1 block is the consequence, and
-- counting it would extend the block by itself. Errors are swallowed.
-- Reputation charges the subject for its own text only: a request whose
-- score came from retrieved content or the tool definitions (which an agent
-- loads from pages, mailboxes and servers the user may not control) is
-- charged at `charge`, the label its own text earned, and with
-- `charge == false` (none of its own text judged, which with untrusted
-- judging on includes a text that holds retrieved content) not at all.
-- Every id of the request is charged (ids_of).
-- One request can reach an adapter twice: a thin Worker asks the origin's
-- /_jev/authz, then forwards the request to that same origin. Two optional
-- hooks on ctx.subject let the adapter charge it once:
--   counted(fp)     true: the other leg already added these points, add none
--   on_counted(fp)  called after the points are added
-- (fp: the verdict's fingerprint). Errors in either are swallowed.
-- @param charge optional: the label to charge instead of v.verdict, or false
-- @return the highest points total among the ids, or nil
function _M.rep_record(ctx, v, charge)
  local r, at = rep_cfg(ctx)
  if not r or v.source == "l1" or charge == false then return nil end
  local store = rep_store(ctx)
  local ids = _M.ids_of(ctx)
  if #ids == 0 or not store then return nil end
  local label = charge or v.verdict
  local w = 0
  if label == "malicious" then w = tonumber(r.malicious) or 3
  elseif label == "suspicious" then w = tonumber(r.suspicious) or 1 end
  if w <= 0 then return nil end
  local s = ctx.subject
  if type(s.counted) == "function" then
    local ok, done = pcall(s.counted, v.fingerprint)
    if ok and done then return nil end
  end
  local best
  for _, id in ipairs(ids) do
    local ok, points = pcall(function()
      local win = tonumber(r.window_s) or 600
      local now = ctx.clock and ctx.clock() or 0
      local b = math.floor(now / win)
      local key = _M.REP_PREFIX .. id .. ":b:"
      local cur = incr(store, key .. b, w, win * 2) or 0
      local prev = tonumber(store:get(key .. (b - 1))) or 0
      local p = cur + prev * (1 - (now - b * win) / win)
      if p >= at then
        local ttl = tonumber(r.block_ttl) or 600
        store:set(_M.REP_PREFIX .. id .. ":until", now + ttl, ttl)
      end
      return p
    end)
    if ok and points and (not best or points > best) then best = points end
  end
  if type(s.on_counted) == "function" then pcall(s.on_counted, v.fingerprint) end
  return best
end

-- ---------------------------------------------------------------------------
-- Extraction, hashing and the bounded history. Pure; adapters supply the
-- request view, the hash function and the store.
-- ---------------------------------------------------------------------------

_M.KEY_PREFIX = "subj:"

--- Most ids one request can name (ids_of), and most candidate values one
--- Cookie header yields (cookie_values).
_M.MAX_IDS = 4

local trim = require("jev.core.normalize").trim
local ip_key = require("jev.core.normalize").ip_key

-- Python's http.cookies unquoting of a quoted value's inside: \ooo (octal
-- 000-377) is that code point, UTF-8 encoded, and \x is x.
local function unescape(s)
  if not s:find("\\", 1, true) then return s end
  local out, i, n = {}, 1, #s
  while i <= n do
    local c = s:sub(i, i)
    if c == "\\" and i < n then
      local oct = s:match("^[0-3][0-7][0-7]", i + 1)
      if oct then
        local cp = tonumber(oct, 8)
        if cp < 0x80 then out[#out + 1] = string.char(cp)
        else out[#out + 1] = string.char(0xC0 + math.floor(cp / 64), 0x80 + cp % 64) end
        i = i + 4
      else
        out[#out + 1] = s:sub(i + 1, i + 1)
        i = i + 2
      end
    else
      out[#out + 1] = c
      i = i + 1
    end
  end
  return table.concat(out)
end

--- The values a Cookie header gives cookie `name`, as the backend may read
-- them: every `name=value` pair (the name matched exactly, case-sensitive,
-- RFC 6265), the value trimmed and a pair of surrounding DQUOTEs stripped,
-- plus its backslash-unescaped form (what Python's http.cookies makes of a
-- quoted value) when that differs. Distinct and non-empty; past MAX_IDS the
-- first two and the last two, since backends read the first or the last.
-- @param header the Cookie header: a string, or a list of them (sent more
-- than once), joined with "; "
function _M.cookie_values(header, name)
  if type(header) == "table" then
    local parts = {}
    for _, h in ipairs(header) do
      if type(h) == "string" then parts[#parts + 1] = h end
    end
    header = table.concat(parts, "; ")
  end
  if type(header) ~= "string" or header == "" or type(name) ~= "string" or name == "" then return {} end
  local all, seen = {}, {}
  local function add(v)
    if v ~= "" and not seen[v] then seen[v], all[#all + 1] = true, v end
  end
  for part in (header .. ";"):gmatch("([^;]*);") do
    local eq = part:find("=", 1, true)
    if eq and trim(part:sub(1, eq - 1)) == name then
      local v = trim(part:sub(eq + 1))
      if #v >= 2 and v:sub(1, 1) == '"' and v:sub(-1) == '"' then
        v = v:sub(2, -2)
        add(v)
        add(unescape(v))
      else
        add(v)
      end
    end
  end
  if #all <= _M.MAX_IDS then return all end
  return { all[1], all[2], all[#all - 1], all[#all] }
end

-- Authorization and Proxy-Authorization: the auth scheme is
-- case-insensitive and any run of spaces or tabs may follow it (RFC 9110
-- 11.1), so "Bearer k", "bearer k" and "Bearer\tk" are one credential to the
-- backend. The scheme is lowercased and the run becomes one space; the
-- credentials are kept byte for byte, and a value with no scheme as is.
local CREDENTIAL_HEADERS = { authorization = true, ["proxy-authorization"] = true }

local function canonical_credentials(v)
  local scheme, rest = v:match("^(%S+)[ \t]+(.-)$")
  if not scheme then return v end
  return scheme:lower() .. " " .. rest
end

--- Every raw subject value for this request: one for `ip` and `header`,
-- up to MAX_IDS for `cookie` (cookie_values), trimmed, distinct, none empty
-- or too long: MAX_VALUE_BYTES with `hashed = true`, where the value is the
-- id, MAX_SALTED_BYTES otherwise, where it is hashed (an RS256 bearer token
-- or a session cookie is often past 512 bytes, and dropping it left the
-- request with no subject at all). Empty when there is none; then, or
-- beside the rest, TOO_LONG when a value was dropped for its length, so the
-- adapter can say so once.
-- @param scfg cfg.subject
-- @param view { ip = string|nil, header = fn(name) -> string|list|nil,
--   cookie_header = the raw Cookie header(s), string|list|nil;
--   or, from an older adapter, cookie = fn(name) -> string|nil;
--   ipv6_prefix = cfg.client_ip.ipv6_prefix: an IPv6 `ip` is its network
--   (normalize.ip_key, 64 bits when unset), the key IP reputation uses }
function _M.extract_all(scfg, view)
  if type(scfg) ~= "table" or not scfg.enabled then return {} end
  local from = scfg.from or "ip"
  local raw = {}
  if from == "ip" then
    raw[1] = ip_key(view.ip, view.ipv6_prefix)
  elseif from == "header" then
    raw[1] = view.header and view.header(scfg.name)
  elseif from == "cookie" then
    if view.cookie_header ~= nil then
      raw = _M.cookie_values(view.cookie_header, scfg.name)
    else
      raw[1] = view.cookie and view.cookie(scfg.name)
    end
  end
  if type(raw[1]) == "table" then raw[1] = raw[1][1] end
  local creds = from == "header" and CREDENTIAL_HEADERS[tostring(scfg.name):lower()]
  local max = scfg.hashed and _M.MAX_VALUE_BYTES or _M.MAX_SALTED_BYTES
  local out, seen, long = {}, {}, nil
  for i = 1, #raw do
    local v = raw[i]
    if type(v) == "string" then
      v = trim(v)
      if creds then v = canonical_credentials(v) end
      if #v > max then
        long = _M.TOO_LONG
      elseif v ~= "" and not seen[v] then
        seen[v], out[#out + 1] = true, v
      end
    end
  end
  return out, long
end

--- The raw subject value for this request, or nil and TOO_LONG when the
-- value was dropped for its length: the first of extract_all.
function _M.extract(scfg, view)
  local all, long = _M.extract_all(scfg, view)
  if all[1] then return all[1] end
  return nil, long
end

--- Longest raw subject value accepted with `hashed = true`: the value IS
--- the key and the log field, so an unbounded header would be an unbounded
--- dict key.
_M.MAX_VALUE_BYTES = 512
--- Longest raw subject value accepted otherwise: it is hashed, so its
--- length does not reach the store; the bound only caps the hashing work.
_M.MAX_SALTED_BYTES = 65536
_M.TOO_LONG = "subject value too long"

--- The id core and the store see: `<from>:<hash(salt .. value)>`. The raw
-- value never leaves this function. With `hashed = true` the value is used as
-- is: it is the complete id another jev-edge computed (a thin Worker's
-- X-Jev-Subject), prefix included.
-- @param hash fn(string) -> string, a one-way function (sha1 / sha256 hex)
function _M.hash_id(scfg, value, hash)
  if value == nil then return nil end
  local from = scfg.from or "ip"
  if scfg.hashed then
    -- Already `<from>:<hex>` from another jev-edge. Anything else is not an
    -- id computed by us and does not get to name a trajectory.
    if value:match("^[a-z]+:[0-9a-f]+$") then return value end
    return nil
  end
  if type(scfg.salt) ~= "string" or scfg.salt == "" then return nil end
  return from .. ":" .. tostring(hash(scfg.salt .. "\0" .. value))
end

--- hash_id over every value, distinct ids in order (the first is the
-- request's `id`, the whole list its `ids`). Empty when none gives an id.
function _M.hash_ids(scfg, values, hash)
  local out, seen = {}, {}
  for _, v in ipairs(values or {}) do
    local id = _M.hash_id(scfg, v, hash)
    if id and not seen[id] then seen[id], out[#out + 1] = true, id end
  end
  return out
end

--- Append an entry to a history list, keeping the newest `max_entries`.
function _M.append(history, e, max_entries)
  local out = {}
  if type(history) == "table" then
    for _, x in ipairs(history) do out[#out + 1] = x end
  end
  out[#out + 1] = e
  local max = tonumber(max_entries) or 20
  while #out > max do table.remove(out, 1) end
  return out
end

function _M.key(id) return _M.KEY_PREFIX .. tostring(id) end

-- ---------------------------------------------------------------------------
-- Ring layout for stores without compare-and-swap (nginx shared dicts).
-- `load`/`save` above keep one list per subject; appending to it is a
-- read-modify-write, and two workers doing it at once lose an entry. The ring
-- keeps one counter per subject (`incr`, atomic) and one key per entry,
-- `subj:<id>:<n % max>`, so a write is two atomic dict operations and needs
-- neither a lock nor a timer. Reading is `max` gets, newest last.
-- Each slot holds `{ n = <sequence>, e = <entry> }`; a reader keeps a slot
-- only when its sequence is the one it expects there, so a slot still holding
-- the previous lap (read between another worker's incr and set) or written
-- under a different max_entries is a hole, not a misplaced entry.
-- store: { get, set, incr = fn(self, key, by, ttl) -> new value|nil,
--          expire = fn(self, key, ttl) (optional) }
-- `incr` sets the ttl only when it creates the counter; `expire` extends it
-- on every append so an active subject keeps its history for `ttl` after
-- its last request, not after its first.
-- ---------------------------------------------------------------------------

function _M.ring_append(store, id, e, max_entries, ttl)
  if not store or not id or type(store.incr) ~= "function" then return false end
  local max = tonumber(max_entries) or 20
  local t = tonumber(ttl) or 3600
  local key = _M.key(id)
  local n = store:incr(key .. ":n", 1, t)
  if not n then return false end
  if type(store.expire) == "function" then store:expire(key .. ":n", t) end
  return store:set(key .. ":" .. ((n - 1) % max), { n = n, e = e }, t)
end

function _M.ring_load(store, id, max_entries)
  if not store or not id then return nil end
  local max = tonumber(max_entries) or 20
  local key = _M.key(id)
  local n = tonumber(store:get(key .. ":n")) or 0
  if n == 0 then return nil end
  local out = {}
  local first = math.max(1, n - max + 1)
  for i = first, n do
    local s = store:get(key .. ":" .. ((i - 1) % max))
    -- an evicted, expired, stale or foreign slot is a hole, not an error
    if type(s) == "table" and s.n == i and type(s.e) == "table" then out[#out + 1] = s.e end
  end
  if #out == 0 then return nil end
  return out
end

--- Read a subject's history from a store. nil when absent, always valid.
function _M.load(store, id)
  if not store or not id then return nil end
  local h = store:get(_M.key(id))
  if type(h) ~= "table" then return nil end
  return h
end

--- Write a subject's history. Adapters call this from the sink, off the request path.
function _M.save(store, id, history, ttl)
  if not store or not id then return false end
  return store:set(_M.key(id), history, tonumber(ttl) or 3600)
end

return _M
