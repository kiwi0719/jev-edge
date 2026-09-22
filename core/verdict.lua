-- core/verdict.lua
-- Flat verdict structure. Every field always present, no nested tables,
-- so it maps 1:1 onto JSON, protobuf and HTTP headers.

local _M = {}

_M.ACTION_PASS  = "pass"
_M.ACTION_BLOCK = "block"

_M.SAFE       = "safe"
_M.SUSPICIOUS = "suspicious"
_M.MALICIOUS  = "malicious"
_M.ERROR      = "error"
_M.SKIPPED    = "skipped"

_M.SRC_L1      = "l1"
_M.SRC_CACHE   = "cache"
_M.SRC_TRUST   = "trust"
_M.SRC_L2      = "l2"
_M.SRC_BREAKER = "breaker"

local function clamp01(n)
  if type(n) ~= "number" or n ~= n then return 0 end
  if n < 0 then return 0 end
  if n > 1 then return 1 end
  return n
end

--- Build a verdict with defaults filled in.
-- @param t table with any of: action, verdict, score, source, reason, fingerprint, l2_ms, async
function _M.new(t)
  t = t or {}
  return {
    action      = t.action or _M.ACTION_PASS,
    verdict     = t.verdict or _M.SKIPPED,
    score       = clamp01(t.score or 0),
    source      = t.source or _M.SRC_L1,
    reason      = tostring(t.reason or ""),
    fingerprint = tostring(t.fingerprint or ""),
    l2_ms       = tonumber(t.l2_ms) or 0,
    async       = t.async == true,
  }
end

--- Headers to set on the upstream request.
function _M.headers(v)
  return {
    ["X-Jev-Verdict"] = v.verdict,
    ["X-Jev-Score"]   = string.format("%.2f", v.score),
    ["X-Jev-Source"]  = v.source,
    ["X-Jev-Reason"]  = _M.encode_reason(v.reason),
  }
end

--- URL-encode and truncate a reason for header transport (<= 200 bytes of
--- encoded output, never cut inside a %XX escape).
_M.REASON_MAX = 200
function _M.encode_reason(s)
  s = tostring(s or "")
  local enc = s:gsub("[^%w%-%._~ ]", function(c)
    return string.format("%%%02X", string.byte(c))
  end):gsub(" ", "+")
  if #enc > _M.REASON_MAX then
    enc = enc:sub(1, _M.REASON_MAX):gsub("%%%x?$", "")
  end
  return enc
end

return _M
