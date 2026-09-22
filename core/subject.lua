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
-- Extraction, hashing and the bounded history. Pure; adapters supply the
-- request view, the hash function and the store.
-- ---------------------------------------------------------------------------

_M.KEY_PREFIX = "subj:"

--- The raw subject value for this request, or nil.
-- @param scfg cfg.subject
-- @param view { ip = string|nil, header = fn(name) -> string|nil, cookie = fn(name) -> string|nil }
function _M.extract(scfg, view)
  if type(scfg) ~= "table" or not scfg.enabled then return nil end
  local from = scfg.from or "ip"
  local v
  if from == "ip" then
    v = view.ip
  elseif from == "header" then
    v = view.header and view.header(scfg.name)
  elseif from == "cookie" then
    v = view.cookie and view.cookie(scfg.name)
  end
  if type(v) == "table" then v = v[1] end
  if type(v) ~= "string" then return nil end
  v = v:match("^%s*(.-)%s*$")
  if v == "" or #v > _M.MAX_VALUE_BYTES then return nil end
  return v
end

--- Longest raw subject value accepted. Hashing makes the length irrelevant
--- for the store, but with `hashed = true` the value IS the key and the log
--- field, so an unbounded header would be an unbounded dict key.
_M.MAX_VALUE_BYTES = 512

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
-- store: { get, set, incr = fn(self, key, by, ttl) -> new value|nil }
-- ---------------------------------------------------------------------------

function _M.ring_append(store, id, e, max_entries, ttl)
  if not store or not id or type(store.incr) ~= "function" then return false end
  local max = tonumber(max_entries) or 20
  local t = tonumber(ttl) or 3600
  local key = _M.key(id)
  local n = store:incr(key .. ":n", 1, t)
  if not n then return false end
  return store:set(key .. ":" .. ((n - 1) % max), e, t)
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
    local e = store:get(key .. ":" .. ((i - 1) % max))
    -- an evicted or expired slot is a hole, not an error; skip it
    if type(e) == "table" then out[#out + 1] = e end
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
