-- Render docs/bench-accuracy-{light,dark}.svg from the committed live results.
--
--   lua bench/chart_accuracy.lua [docs]      (make bench-chart)
--
-- One horizontal bar per slice: attacks flagged at the 0.5 threshold, with the
-- false-positive rate of the same slice beside it. Every number is computed
-- here from bench/datasets/*, the same files the reports are built from.

package.path = "./?.lua;./?/init.lua;" .. package.path
local json = require "dkjson"
local dst = arg[1] or "docs"
local T = 0.5

local function jsonl(path)
  local t = {}
  for line in io.lines(path) do
    local r = json.decode(line)
    if r then t[#t + 1] = r end
  end
  return t
end

local function rates(rows, score, keep)
  local pos, hit, neg, fp = 0, 0, 0, 0
  for _, r in ipairs(rows) do
    if keep(r) then
      local s = tonumber(score(r)) or 0
      if r.label == 1 then pos = pos + 1; if s >= T then hit = hit + 1 end
      else neg = neg + 1; if s >= T then fp = fp + 1 end end
    end
  end
  return { det = pos > 0 and hit / pos or 0, fp = neg > 0 and fp / neg or 0, pos = pos, neg = neg }
end

local function deepset(path)
  local f = assert(io.open(path, "rb"))
  local d = json.decode(f:read("*a"))
  f:close()
  return d.samples
end

local inj = function(r) return r.injection end
local bare = jsonl("bench/datasets/live-suite-jev-latest-bare.jsonl")
local held = jsonl("bench/datasets/live-heldout-jev-latest.jsonl")
local function cat(...)
  local set = {}
  for _, c in ipairs({ ... }) do set[c] = true end
  return function(r) return set[r.category] end
end

local bars = {
  { group = "deepset/prompt-injections, single turn, en/de" },
  { "text only", rates(deepset("bench/datasets/live-jev-latest.json"), inj, function() return true end) },
  { "text + deployment_context", rates(deepset("bench/datasets/live-jev-latest-ctx.json"), inj, function() return true end) },
  { group = "suite v1, text only" },
  { "Chinese instruction override", rates(bare, inj, cat("zh:Goal_Hijacking", "zh:benign_instruction")) },
  { "multi-turn, attack spliced in", rates(bare, inj, function(r) return r.shape == "multi" end) },
  { "indirect: LLMail-Inject emails", rates(bare, inj, function(r) return r.source == "LLMail-Inject" end) },
  { "indirect: BIPIA emails", rates(bare, inj, function(r) return r.source == "BIPIA" end) },
  { group = "held-out tool results, the shipped core" },
  { "untrusted off", rates(held, function(r) return r.score end, function(r) return r.mode == "off" end) },
  { "untrusted on", rates(held, function(r) return r.score end, function(r) return r.mode == "on" end), hi = true },
}

local themes = {
  light = { s1 = "#2a78d6", s2 = "#eb6834", txt = "#1f2328", mut = "#59636e", grid = "#d0d7de", track = "#eaeef2" },
  dark  = { s1 = "#3987e5", s2 = "#d95926", txt = "#e6edf3", mut = "#9198a1", grid = "#3d444d", track = "#21262d" },
}

local W, L, R, TOP = 760, 250, 110, 58
local ROW, GAP = 26, 24
local pw = W - L - R

local function pc(v) return string.format("%.0f%%", v * 100) end
local function pc1(v) return v == 0 and "0%" or string.format("%.1f%%", v * 100) end

local function render(mode, c)
  local o = {}
  local function w(s) o[#o + 1] = s end
  local h = TOP
  for _, b in ipairs(bars) do h = h + (b.group and GAP or ROW) end
  h = h + 40
  w('<?xml version="1.0" encoding="UTF-8"?>')
  w(string.format('<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d" '
    .. 'font-family="-apple-system,Segoe UI,Helvetica,Arial,sans-serif" font-size="12">', W, h, W, h))
  w(string.format('<text x="20" y="22" font-size="14" font-weight="600" fill="%s">Attacks flagged at threshold 0.5, '
    .. 'and false positives on the same slice</text>', c.txt))
  w(string.format('<text x="20" y="38" fill="%s">jev-latest, live runs committed under bench/datasets. '
    .. 'Longer bar = more attacks caught; FP = benign requests flagged.</text>', c.mut))
  local y = TOP
  for _, g in ipairs({ 0, 0.25, 0.5, 0.75, 1 }) do
    local x = L + pw * g
    w(string.format('<line x1="%.1f" x2="%.1f" y1="%d" y2="%d" stroke="%s" stroke-width="1"/>', x, x, TOP - 6, h - 34, c.grid))
    w(string.format('<text x="%.1f" y="%d" text-anchor="middle" fill="%s">%s</text>', x, h - 20, c.mut, pc(g)))
  end
  w(string.format('<text x="%d" y="%d" text-anchor="middle" fill="%s">FP</text>', W - R + 55, TOP - 8, c.mut))
  for _, b in ipairs(bars) do
    if b.group then
      w(string.format('<text x="20" y="%d" font-weight="600" fill="%s">%s</text>', y + 16, c.txt, b.group))
      y = y + GAP
    else
      local r = b[2]
      local by = y + 5
      w(string.format('<text x="%d" y="%d" text-anchor="end" fill="%s">%s</text>', L - 10, by + 12, c.txt, b[1]))
      w(string.format('<rect x="%d" y="%d" width="%d" height="16" rx="3" fill="%s"/>', L, by, pw, c.track))
      local bw = math.max(2, pw * r.det)
      w(string.format('<rect x="%d" y="%d" width="%.1f" height="16" rx="3" fill="%s"/>', L, by, bw, b.hi and c.s2 or c.s1))
      local inside = r.det > 0.12
      w(string.format('<text x="%.1f" y="%d" text-anchor="%s" fill="%s" font-weight="600">%s</text>',
        inside and (L + bw - 6) or (L + bw + 6), by + 12, inside and "end" or "start",
        inside and "#ffffff" or c.txt, pc(r.det)))
      w(string.format('<text x="%d" y="%d" text-anchor="middle" fill="%s">%s</text>', W - R + 55, by + 12, c.mut, pc1(r.fp)))
      y = y + ROW
    end
  end
  w('</svg>')
  local path = dst .. "/bench-accuracy-" .. mode .. ".svg"
  local f = assert(io.open(path, "w"))
  f:write(table.concat(o, "\n"), "\n")
  f:close()
  print("wrote " .. path)
  return bars
end

for _, mode in ipairs({ "light", "dark" }) do render(mode, themes[mode]) end
for _, b in ipairs(bars) do
  if not b.group then
    io.stderr:write(string.format("%-34s det %5.1f%%  fp %4.1f%%  (%d / %d)\n", b[1], b[2].det * 100, b[2].fp * 100,
      b[2].pos, b[2].neg))
  end
end
