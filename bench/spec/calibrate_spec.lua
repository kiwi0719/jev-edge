local json = require "dkjson"

-- bench/calibrate.lua run as `make calibrate` runs it, on a log and labels
-- written here: the threshold it recommends is the one it prints, and its
-- rates are measured at that value.

local function write(path, lines)
  local f = assert(io.open(path, "w"))
  f:write(table.concat(lines, "\n"), "\n")
  f:close()
end

local function run(args)
  local p = assert(io.popen("lua bench/calibrate.lua " .. args .. " 2>&1"))
  local out = p:read("*a")
  p:close()
  return out
end

describe("calibrate: recommended threshold", function()
  local dir, log, labels

  setup(function()
    dir = os.tmpname()
    os.remove(dir)
    assert(os.execute("mkdir -p '" .. dir .. "'"))
    log, labels = dir .. "/jev.log", dir .. "/labels.csv"
    -- a benign request scored 0.631 and an attack scored 0.635: at the raw
    -- 0.635 nothing benign is blocked, but 0.635 prints as 0.63 (or 0.64),
    -- and at 0.63 the benign one is
    local rows, labs = {}, {}
    for i, r in ipairs({ { 0.631, 0 }, { 0.635, 1 }, { 0.9, 1 }, { 0.1, 0 } }) do
      rows[i] = json.encode({ rid = "r" .. i, src = "l2", score = r[1], verdict = "safe", action = "pass" })
      labs[i] = "r" .. i .. "," .. r[2]
    end
    write(log, rows)
    write(labels, labs)
  end)
  teardown(function()
    os.execute("rm -rf '" .. dir .. "'")
  end)

  it("gives a threshold of two decimals, with the rates measured at it", function()
    local out = run(("'%s' '%s' --max-fp 0 --json"):format(log, labels))
    local res = assert(json.decode(out), out)
    local rec = res.recommended.block_threshold
    assert.equal(0.64, rec.threshold)
    assert.equal(("%.2f"):format(rec.threshold) + 0, rec.threshold)
    assert.equal(0, rec.fp_rate)
    assert.equal(0.5, rec.miss_rate)  -- the attack at 0.635 is below 0.64
  end)

  it("prints the same threshold and rates in the report and the curl line", function()
    local out = run(("'%s' '%s' --max-fp 0"):format(log, labels))
    assert.matches("`block_threshold = 0.64`: 0.00% false positives, 50.0% misses", out, 1, true)
    assert.matches('"block_threshold":0.64,', out, 1, true)
  end)
end)
