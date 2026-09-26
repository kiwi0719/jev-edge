-- Test-only Kong vault for the e2e: {vault://e2efile/<name>} reads
-- /secrets/<name>, with a 1 s ttl so Kong's rotation timer reads it again on
-- every cycle, the way a rotating vault (aws, gcp, hcv, azure) would change.
local function get(_, resource)
  local f = io.open("/secrets/" .. resource, "r")
  if not f then return nil, "no such secret" end
  local v = f:read("*a")
  f:close()
  return (v:gsub("%s+$", "")), nil, 1
end

return { VERSION = "0.0.1", get = get }
