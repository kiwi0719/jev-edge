-- bench/calibrate.lua
-- Pick thresholds from your own traffic instead of from the README.
--
-- Input 1: a jev-edge access log written with `log_format jev escape=none '$jev_log';`
--          (one JSON object per line: rid, path, ip, src, score, verdict, action,
--          l2_ms, fp, reason). Lines without an L2 or cache score are counted
--          and ignored.
-- Input 2 (optional): labels, one per line, CSV or whitespace separated:
--            <rid or fp>,<label>
--          label is 1 / attack / bad / malicious for an attack and 0 / benign /
--          ok / good for legitimate traffic. A label keyed by fingerprint
--          applies to every request with that fingerprint, which is the cheap
--          way to label: one line covers every replay of the same text.
--
-- Without labels: score distribution and what each threshold would have
-- blocked. With labels: ROC / AUC, false-positive and miss rates per
-- threshold, and a recommended block_threshold / suspect_threshold under a
-- false-positive budget.
--
-- Subject reputation: when the log lines carry `subject` and `ts` (0.5.0+),
-- the judged verdicts are replayed per subject with the same sliding window
-- as core/subject.lua, and the report shows the highest points each subject
-- reached and what each `subject.reputation.block_at` would have blocked
-- (with labels: benign subjects vs subjects that sent a labelled attack).
--
-- Usage (from the repo root, or via `make calibrate LOG=... LABELS=...`):
--   lua bench/calibrate.lua <jev.log> [labels.csv] [--max-fp 0.001] [--json]
--       [--rep-window 600] [--rep-suspicious 1] [--rep-malicious 3]
--
-- No dependencies beyond dkjson. Never reads request bodies; the log does not
-- contain them.

package.path = "./?.lua;./?/init.lua;" .. package.path
local json = require "dkjson"

-- ---------------------------------------------------------------------------
-- args
-- ---------------------------------------------------------------------------

local log_path, labels_path
local max_fp, as_json = 0.001, false
local rep_window, rep_w_susp, rep_w_mal = 600, 1, 3
do
  local i = 1
  while i <= #arg do
    local a = arg[i]
    if a == "--max-fp" then max_fp = assert(tonumber(arg[i + 1]), "--max-fp needs a number"); i = i + 1
    elseif a == "--json" then as_json = true
    elseif a == "--rep-window" then rep_window = assert(tonumber(arg[i + 1]), "--rep-window needs seconds"); i = i + 1
    elseif a == "--rep-suspicious" then rep_w_susp = assert(tonumber(arg[i + 1])); i = i + 1
    elseif a == "--rep-malicious" then rep_w_mal = assert(tonumber(arg[i + 1])); i = i + 1
    elseif a == "-h" or a == "--help" then
      io.stderr:write("usage: lua bench/calibrate.lua <jev.log> [labels] [--max-fp 0.001] [--json]\n")
      os.exit(0)
    elseif not log_path then log_path = a
    elseif not labels_path and a ~= "" then labels_path = a
    end
    i = i + 1
  end
end
if not log_path then
  io.stderr:write("usage: lua bench/calibrate.lua <jev.log> [labels] [--max-fp 0.001] [--json]\n")
  os.exit(2)
end

-- ---------------------------------------------------------------------------
-- read the log
-- ---------------------------------------------------------------------------

local rows, skipped, bad = {}, 0, 0
local by_src = {}
local by_subject, n_subject_lines = {}, 0
do
  local f = assert(io.open(log_path, "rb"), "cannot open " .. log_path)
  for raw in f:lines() do
    local line = raw:match("^%s*(.-)%s*$")
    if line ~= "" then
      local obj = json.decode(line)
      if type(obj) ~= "table" then
        bad = bad + 1
      else
        by_src[obj.src or "?"] = (by_src[obj.src or "?"] or 0) + 1
        if type(obj.subject) == "string" and obj.subject ~= "" and tonumber(obj.ts) then
          local list = by_subject[obj.subject]
          if not list then list = {}; by_subject[obj.subject] = list end
          list[#list + 1] = { ts = tonumber(obj.ts), verdict = obj.verdict, src = obj.src, rid = obj.rid, fp = obj.fp }
          n_subject_lines = n_subject_lines + 1
        end
        local score = tonumber(obj.score)
        if (obj.src == "l2" or obj.src == "cache") and score then
          rows[#rows + 1] = { rid = obj.rid, fp = obj.fp, score = score, path = obj.path,
            verdict = obj.verdict, action = obj.action }
        else
          skipped = skipped + 1
        end
      end
    end
  end
  f:close()
end

if #rows == 0 then
  io.stderr:write("no scored requests in " .. log_path .. " (need src=l2 or src=cache lines)\n")
  os.exit(1)
end

-- ---------------------------------------------------------------------------
-- read labels (optional)
-- ---------------------------------------------------------------------------

local ATTACK = { ["1"] = true, attack = true, bad = true, malicious = true, injection = true, ["true"] = true }
local BENIGN = { ["0"] = true, benign = true, ok = true, good = true, safe = true, ["false"] = true }

local labels_by_key, n_labels = {}, 0
if labels_path then
  local f = assert(io.open(labels_path, "rb"), "cannot open " .. labels_path)
  for line in f:lines() do
    local key, lab = line:match("^%s*([^,%s#]+)[,%s]+([^,%s]+)")
    if key and lab then
      lab = lab:lower()
      if ATTACK[lab] then labels_by_key[key] = 1; n_labels = n_labels + 1
      elseif BENIGN[lab] then labels_by_key[key] = 0; n_labels = n_labels + 1
      else io.stderr:write("warning: unknown label '" .. lab .. "' for " .. key .. "\n") end
    end
  end
  f:close()
end

local labelled = {}
for _, r in ipairs(rows) do
  local lab = (r.rid and labels_by_key[r.rid]) or (r.fp and r.fp ~= "" and labels_by_key[r.fp])
  if lab ~= nil then
    r.label = lab
    labelled[#labelled + 1] = r
  end
end

-- ---------------------------------------------------------------------------
-- unlabelled statistics: distribution and what thresholds would do
-- ---------------------------------------------------------------------------

local function pct(n, d) return d > 0 and (100 * n / d) or 0 end

local bins = {}
for i = 0, 9 do bins[i] = 0 end
for _, r in ipairs(rows) do
  local b = math.floor(r.score * 10)
  if b > 9 then b = 9 end
  bins[b] = bins[b] + 1
end

local thresholds = { 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95 }
local share_above = {}
for _, t in ipairs(thresholds) do
  local n = 0
  for _, r in ipairs(rows) do if r.score >= t then n = n + 1 end end
  share_above[t] = n
end

-- ---------------------------------------------------------------------------
-- labelled statistics: ROC, AUC, per-threshold FP / miss, recommendation
-- ---------------------------------------------------------------------------

local n_pos, n_neg = 0, 0
for _, r in ipairs(labelled) do
  if r.label == 1 then n_pos = n_pos + 1 else n_neg = n_neg + 1 end
end

-- AUC as the Mann-Whitney statistic with ties counted half, no library needed
local function auc()
  if n_pos == 0 or n_neg == 0 then return nil end
  local sorted = {}
  for i, r in ipairs(labelled) do sorted[i] = r end
  table.sort(sorted, function(a, b) return a.score < b.score end)
  local i, rank_sum_pos = 1, 0
  while i <= #sorted do
    local j = i
    while j < #sorted and sorted[j + 1].score == sorted[i].score do j = j + 1 end
    local avg_rank = (i + j) / 2
    for k = i, j do
      if sorted[k].label == 1 then rank_sum_pos = rank_sum_pos + avg_rank end
    end
    i = j + 1
  end
  return (rank_sum_pos - n_pos * (n_pos + 1) / 2) / (n_pos * n_neg)
end

local function rates_at(t)
  local fp, tp = 0, 0
  for _, r in ipairs(labelled) do
    if r.score >= t then
      if r.label == 1 then tp = tp + 1 else fp = fp + 1 end
    end
  end
  return (n_neg > 0 and fp / n_neg or 0), (n_pos > 0 and (n_pos - tp) / n_pos or 0), fp, n_pos - tp
end

-- candidate thresholds: every distinct score seen, so the recommendation is
-- an operating point that exists in the data rather than a round number
local function recommend(budget)
  if n_pos == 0 or n_neg == 0 then return nil end
  local seen, cands = {}, {}
  for _, r in ipairs(labelled) do
    if not seen[r.score] then seen[r.score] = true; cands[#cands + 1] = r.score end
  end
  table.sort(cands)
  local best
  for _, t in ipairs(cands) do
    local fpr, miss = rates_at(t)
    if fpr <= budget and (not best or miss < best.miss_rate) then
      best = { threshold = t, fp_rate = fpr, miss_rate = miss }
    end
  end
  return best
end

-- ---------------------------------------------------------------------------
-- subject reputation: replay core/subject.lua's sliding window per subject
-- ---------------------------------------------------------------------------

local subj_stats = {}   -- { max_points, label = 1 | 0 | nil }
do
  for sid, entries in pairs(by_subject) do
    table.sort(entries, function(a, b) return a.ts < b.ts end)
    local buckets, best, label = {}, 0, nil
    for _, e in ipairs(entries) do
      local lab = (e.rid and labels_by_key[e.rid]) or (e.fp and e.fp ~= "" and labels_by_key[e.fp])
      if lab == 1 then label = 1 elseif lab == 0 and label == nil then label = 0 end
      local w = 0
      if e.src ~= "l1" then
        if e.verdict == "malicious" then w = rep_w_mal elseif e.verdict == "suspicious" then w = rep_w_susp end
      end
      if w > 0 then
        local b = math.floor(e.ts / rep_window)
        buckets[b] = (buckets[b] or 0) + w
        local pts = buckets[b] + (buckets[b - 1] or 0) * (1 - (e.ts - b * rep_window) / rep_window)
        if pts > best then best = pts end
      end
    end
    subj_stats[#subj_stats + 1] = { id = sid, max_points = best, label = label }
  end
end

local rep_cands = { 3, 4, 5, 6, 8, 10, 12, 15, 20, 30, 50 }
local function rep_at(at)
  local all, benign, attackers, n_benign, n_att = 0, 0, 0, 0, 0
  for _, s in ipairs(subj_stats) do
    local hit = s.max_points >= at
    if hit then all = all + 1 end
    if s.label == 0 then n_benign = n_benign + 1; if hit then benign = benign + 1 end end
    if s.label == 1 then n_att = n_att + 1; if hit then attackers = attackers + 1 end end
  end
  return all, benign, attackers, n_benign, n_att
end

local rep_rec
do
  local _, _, _, n_benign, n_att = rep_at(1)
  if n_benign > 0 and n_att > 0 then
    -- lowest block_at that keeps benign subjects blocked within the budget
    for _, at in ipairs(rep_cands) do
      local _, b, a = rep_at(at)
      if b / n_benign <= max_fp then
        rep_rec = { block_at = at, benign_blocked = b, attackers_blocked = a, basis = "labels" }
        break
      end
    end
  elseif #subj_stats > 0 then
    -- no labels: above what 99.9% of subjects ever reached
    local pts = {}
    for i, s in ipairs(subj_stats) do pts[i] = s.max_points end
    table.sort(pts)
    local q = pts[math.max(1, math.ceil(#pts * 0.999))]
    for _, at in ipairs(rep_cands) do
      if at > q then rep_rec = { block_at = at, p999 = q, basis = "p99.9 of subjects" } break end
    end
  end
end

local the_auc = auc()
local rec_block = recommend(max_fp)
local rec_suspect = recommend(math.min(0.05, max_fp * 10))

-- ---------------------------------------------------------------------------
-- output
-- ---------------------------------------------------------------------------

if as_json then
  local per_t = {}
  for _, t in ipairs(thresholds) do
    local fpr, miss = rates_at(t)
    per_t[#per_t + 1] = { threshold = t, would_block = share_above[t],
      fp_rate = n_labels > 0 and fpr or nil, miss_rate = n_labels > 0 and miss or nil }
  end
  print(json.encode({
    scored = #rows, skipped = skipped, malformed = bad, by_source = by_src,
    labelled = #labelled, attacks = n_pos, benign = n_neg, auc = the_auc,
    thresholds = per_t, max_fp = max_fp,
    recommended = { block_threshold = rec_block, suspect_threshold = rec_suspect, subject_block_at = rep_rec },
    subjects = #subj_stats, subject_lines = n_subject_lines,
  }, { indent = true }))
  os.exit(0)
end

local function p(...) io.write(string.format(...), "\n") end

p("# jev-edge calibration")
p("")
p("log: %s", log_path)
p("scored requests (src=l2 or cache): %d   ignored (l1 / breaker / error): %d   malformed lines: %d", #rows, skipped, bad)
do
  local parts = {}
  for src, n in pairs(by_src) do parts[#parts + 1] = src .. "=" .. n end
  table.sort(parts)
  p("by source: %s", table.concat(parts, "  "))
end
p("")
p("## score distribution")
p("")
p("| score | requests | share |")
p("|---|---|---|")
for i = 0, 9 do
  local lo, hi = i / 10, (i + 1) / 10
  p("| %.1f – %.1f | %d | %.1f%% |", lo, hi, bins[i], pct(bins[i], #rows))
end
p("")
p("## what each block_threshold would have blocked")
p("")
p("| threshold | requests ≥ | share |")
p("|---|---|---|")
for _, t in ipairs(thresholds) do
  p("| %.2f | %d | %.2f%% |", t, share_above[t], pct(share_above[t], #rows))
end
p("")

if #subj_stats > 0 then
  p("## subject reputation (`subject.reputation.block_at`)")
  p("")
  p("%d subjects, %d lines with subject and ts; window %ds, suspicious = %g, malicious = %g points",
    #subj_stats, n_subject_lines, rep_window, rep_w_susp, rep_w_mal)
  p("")
  p("| block_at | subjects blocked | benign subjects blocked | attacking subjects blocked |")
  p("|---|---|---|---|")
  for _, at in ipairs(rep_cands) do
    local all, b, a, nb, na = rep_at(at)
    p("| %g | %d | %s | %s |", at, all, nb > 0 and (b .. " / " .. nb) or "-", na > 0 and (a .. " / " .. na) or "-")
  end
  p("")
  if rep_rec and rep_rec.basis == "labels" then
    p("- `subject.reputation.block_at = %g`: blocks %d benign and %d attacking subjects on this sample",
      rep_rec.block_at, rep_rec.benign_blocked, rep_rec.attackers_blocked)
  elseif rep_rec then
    p("- `subject.reputation.block_at = %g`: above the %.3g points 99.9%% of subjects reached (no subject labels;",
      rep_rec.block_at, rep_rec.p999)
    p("  label the subjects that sent attacks to get a number with a false-positive budget)")
  end
  p("")
end

if n_labels == 0 then
  p("No labels given, so no accuracy numbers. Label some of these requests (by rid or fp,")
  p("one per line: `<rid or fp>,<0|1>`) and run again to get ROC / AUC and a recommended threshold.")
  p("Start with the ones scored 0.4 – 0.8: that is where a threshold moves.")
  os.exit(0)
end

p("## accuracy on labelled traffic")
p("")
p("labels read: %d   matched to scored requests: %d   attacks: %d   benign: %d", n_labels, #labelled, n_pos, n_neg)
if the_auc then p("AUC: %.4f", the_auc) else p("AUC: needs at least one attack and one benign label") end
p("")
p("| threshold | false positives | misses | fp rate | miss rate |")
p("|---|---|---|---|---|")
for _, t in ipairs(thresholds) do
  local fpr, miss, fp, m = rates_at(t)
  p("| %.2f | %d | %d | %.2f%% | %.2f%% |", t, fp, m, 100 * fpr, 100 * miss)
end
p("")
p("## recommendation (false-positive budget %.3g%%)", 100 * max_fp)
p("")
if rec_block then
  p("- `block_threshold = %.2f`: %.2f%% false positives, %.1f%% misses on this sample", rec_block.threshold,
    100 * rec_block.fp_rate, 100 * rec_block.miss_rate)
else
  p("- no threshold keeps false positives within %.3g%% on this sample; raise --max-fp or label more benign traffic", 100 * max_fp)
end
if rec_suspect then
  p("- `suspect_threshold = %.2f`: %.2f%% false positives, %.1f%% misses (suspicious traffic is passed and sent to L3, so a looser budget is fine)",
    rec_suspect.threshold, 100 * rec_suspect.fp_rate, 100 * rec_suspect.miss_rate)
end
p("")
if #labelled < 200 or n_pos < 20 then
  p("Sample is small (%d labelled, %d attacks). Treat the rates as a direction, not a measurement;", #labelled, n_pos)
  p("a single mislabelled request moves them by %.1f points.", pct(1, math.max(1, math.min(n_pos, n_neg))))
end
p("Apply without a reload:")
p("")
p("```bash")
p("curl -X PUT localhost:8080/_jev/config -d '{\"policy\":{\"block_threshold\":%.2f,\"suspect_threshold\":%.2f}}'",
  rec_block and rec_block.threshold or 0.7, rec_suspect and rec_suspect.threshold or 0.5)
p("```")
