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

return _M
