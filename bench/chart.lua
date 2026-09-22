-- Render docs/bench-latency-{light,dark}.svg from a bench results.txt.
--
--   lua bench/chart.lua [bench/out/results.txt] [docs]
--
-- Input lines are what bench/run.sh writes:
--   <scenario> requests=N errors=N p50_us=N p99_us=N max_us=N rps=N
-- Output is a static two-series bar chart (p50, p99) on a log scale, one file
-- per GitHub colour scheme; README.md picks them with <picture>.

local src = arg[1] or "bench/out/results.txt"
local dst = arg[2] or "docs"

local names = { baseline = "baseline", unwatched = "unwatched",
                healthy = "healthy Jev", slow = "slow Jev", dead = "dead Jev" }
local order = { "baseline", "unwatched", "healthy", "slow", "dead" }

local rows = {}
for line in io.lines(src) do
  local key, p50, p99 = line:match("^(%S+) .-p50_us=(%d+) p99_us=(%d+)")
  if key then rows[key] = { p50 = tonumber(p50), p99 = tonumber(p99) } end
end

local function fmt(us)
  if us >= 1000 then return string.format("%.0f ms", us / 1000) end
  return string.format("%d µs", us)
end

local themes = {
  light = { s1 = "#2a78d6", s2 = "#eb6834", txt = "#1f2328", mut = "#59636e", grid = "#d0d7de" },
  dark  = { s1 = "#3987e5", s2 = "#d95926", txt = "#e6edf3", mut = "#9198a1", grid = "#3d444d" },
}

local W, H, L, R, T, B = 760, 340, 70, 20, 50, 60
local pw, ph = W - L - R, H - T - B
local lo, hi = 1, 6 -- log10(µs): 10 µs .. 1 s
local function y(v) return T + ph - (math.log(v, 10) - lo) / (hi - lo) * ph end

local function render(mode, c)
  local o = {}
  local function w(s) o[#o + 1] = s end
  w('<?xml version="1.0" encoding="UTF-8"?>')
  w(string.format('<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d" font-family="-apple-system,Segoe UI,Helvetica,Arial,sans-serif" font-size="12">', W, H, W, H))
  w(string.format('<text x="%d" y="22" font-size="14" font-weight="600" fill="%s">Request latency by scenario, 4 connections, log scale</text>', L, c.txt))
  w(string.format('<text x="%d" y="38" fill="%s">wrk against OpenResty in Docker, mock provider. timeout_ms = 300 is the adaptive floor, not a cut.</text>', L, c.mut))
  for e = lo, hi do
    local v, yy = 10 ^ e, y(10 ^ e)
    w(string.format('<line x1="%d" x2="%d" y1="%.1f" y2="%.1f" stroke="%s" stroke-width="1"/>', L, L + pw, yy, yy, c.grid))
    w(string.format('<text x="%d" y="%.1f" text-anchor="end" fill="%s">%s</text>', L - 8, yy + 4, c.mut, v < 1e6 and fmt(v) or "1 s"))
  end
  local yc = y(300000)
  w(string.format('<line x1="%d" x2="%d" y1="%.1f" y2="%.1f" stroke="%s" stroke-width="1" stroke-dasharray="4 3"/>', L, L + pw, yc, yc, c.mut))
  w(string.format('<text x="%d" y="%.1f" text-anchor="end" fill="%s">timeout_ms = 300 (floor)</text>', L + pw, yc - 5, c.mut))
  local n = #order
  local gw = pw / n
  local bw = math.min(34, gw * 0.28)
  local base = y(10)
  for i, key in ipairs(order) do
    local r = rows[key]
    if r then
      local cx = L + gw * (i - 0.5)
      for j, s in ipairs({ { r.p50, c.s1, -5 }, { r.p99, c.s2, 5 } }) do
        local v, col, dx = s[1], s[2], s[3]
        local x = j == 1 and cx - bw - 1 or cx + 1
        local top = y(v)
        w(string.format('<path d="M%.1f,%.1f V%.1f a4,4 0 0 1 4,-4 h%.1f a4,4 0 0 1 4,4 V%.1f Z" fill="%s"/>', x, base, top + 4, bw - 8, base, col))
        w(string.format('<text x="%.1f" y="%.1f" text-anchor="middle" fill="%s" font-size="11">%s</text>', x + bw / 2 + dx, top - 5, c.txt, fmt(v)))
      end
      w(string.format('<text x="%.1f" y="%.1f" text-anchor="middle" fill="%s">%s</text>', cx, base + 18, c.txt, names[key]))
    end
  end
  w(string.format('<line x1="%d" x2="%d" y1="%.1f" y2="%.1f" stroke="%s" stroke-width="1"/>', L, L + pw, base, base, c.mut))
  local ly = H - 14
  w(string.format('<rect x="%d" y="%d" width="12" height="12" rx="2" fill="%s"/><text x="%d" y="%d" fill="%s">p50</text>', L, ly - 9, c.s1, L + 18, ly, c.txt))
  w(string.format('<rect x="%d" y="%d" width="12" height="12" rx="2" fill="%s"/><text x="%d" y="%d" fill="%s">p99</text>', L + 60, ly - 9, c.s2, L + 78, ly, c.txt))
  w('</svg>')
  local path = dst .. "/bench-latency-" .. mode .. ".svg"
  local f = assert(io.open(path, "w"))
  f:write(table.concat(o, "\n"), "\n")
  f:close()
  print("wrote " .. path)
end

for mode, c in pairs(themes) do render(mode, c) end
