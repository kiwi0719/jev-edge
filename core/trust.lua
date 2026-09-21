-- core/trust.lua
-- Fingerprint trust: the write side of the false-positive feedback loop.
--
-- An operator who marks a request "not an attack" puts that request's
-- fingerprint here, and L1.5 lets every later request with the same text
-- through without paying for L2. Three properties matter more than the
-- lookup itself:
--
--   * trust always expires. A permanent entry is a rule that is never
--     reviewed again, and a fingerprint is derived from attacker-visible
--     text: one mislabelled template would be a standing bypass.
--   * traffic may refresh it, but only `max_renewals` times. A template
--     that keeps firing after five weeks is a rule or context bug; it
--     should come back as a false positive, not live on in the cache.
--   * the record says who trusted it and why, so the same decision can be
--     replayed from the log into the calibration labels.
--
-- Pure: the store ({ get, set } — the shared cache by default, anything
-- else the adapter injects) and the clock come from the caller.

local _M = {}

_M.PREFIX = "trust:"

_M.DEFAULT_TTL      = 7 * 24 * 3600
_M.DEFAULT_RENEWALS = 4

function _M.key(fp)
  return _M.PREFIX .. tostring(fp or "")
end

--- Is the feedback loop on? Absent config means off; `enabled = false` means off.
function _M.enabled(fcfg)
  return type(fcfg) == "table" and fcfg.enabled == true
end

local function ttl_of(fcfg)
  return tonumber(fcfg and fcfg.trust_ttl) or _M.DEFAULT_TTL
end

local function max_renewals_of(fcfg)
  local n = tonumber(fcfg and fcfg.max_renewals)
  if not n or n < 0 then n = _M.DEFAULT_RENEWALS end
  return n
end

--- The live trust record for a fingerprint, or nil. Expired records read as nil
-- even when the store still holds them (a store without TTL support, a clock skew).
function _M.get(store, fp, now)
  if not store or not fp or fp == "" then return nil end
  local rec = store:get(_M.key(fp))
  if type(rec) ~= "table" then return nil end
  if type(rec.trusted_until) ~= "number" or rec.trusted_until <= (now or 0) then return nil end
  return rec
end

--- Extend a live record that is past half its life. At most `max_renewals`
-- extensions ever, so a fingerprint cannot be kept alive indefinitely by the
-- traffic it was granted for. Returns false plus a reason when nothing was
-- written; writes are therefore bounded to max_renewals per fingerprint.
function _M.touch(store, fp, rec, now, fcfg)
  local ttl  = ttl_of(fcfg)
  local maxr = max_renewals_of(fcfg)
  local renewals = tonumber(rec.renewals) or 0
  if renewals >= maxr then return false, "renewal cap" end
  if now < rec.trusted_until - ttl / 2 then return false, "not due" end
  local out = {
    trusted_until = now + ttl,
    renewals      = renewals + 1,
    first_seen    = tonumber(rec.first_seen) or now,
    by            = rec.by,
    rid           = rec.rid,
  }
  store:set(_M.key(fp), out, ttl)
  return true, out
end

--- Trust a fingerprint on an operator's say-so.
-- @param meta { by = "who reported it", rid = "the request they looked at" }
-- @return record, or nil plus an error when the renewal cap is reached.
function _M.grant(store, fp, now, fcfg, meta)
  if not store then return nil, "no trust store" end
  if not fp or fp == "" then return nil, "empty fingerprint" end
  meta = meta or {}
  local ttl  = ttl_of(fcfg)
  local maxr = max_renewals_of(fcfg)

  local existing = _M.get(store, fp, now)
  local renewals = 0
  if existing then
    renewals = (tonumber(existing.renewals) or 0) + 1
    if renewals > maxr then
      return nil, "renewal cap reached: this fingerprint has been trusted for " ..
                  math.floor((now - (tonumber(existing.first_seen) or now)) / 86400) ..
                  " days; fix the rule or the deployment context instead"
    end
  end

  local rec = {
    trusted_until = now + ttl,
    renewals      = renewals,
    first_seen    = existing and tonumber(existing.first_seen) or now,
    by            = meta.by and tostring(meta.by) or nil,
    rid           = meta.rid and tostring(meta.rid) or nil,
  }
  store:set(_M.key(fp), rec, ttl)
  return rec
end

--- Drop a fingerprint's trust. Undoing a mislabel must be as cheap as making it.
function _M.revoke(store, fp)
  if not store or not fp or fp == "" then return false end
  store:set(_M.key(fp), nil)
  return true
end

return _M
