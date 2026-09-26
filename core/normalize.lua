-- core/normalize.lua
-- Text extraction from request bodies and normalization for fingerprinting.
-- Pure Lua 5.1 / LuaJIT. No ngx.* usage.

local _M = {}

-- ---------------------------------------------------------------------------
-- Path extraction: "messages[*].content", "prompt", "input.text"
-- A last segment "**" reads every key and string below the value, whatever
-- its shape: tool-call arguments are a string of JSON in OpenAI's APIs (read
-- decoded) and an object in Ollama's and Anthropic's; see deep_value.
-- ---------------------------------------------------------------------------

local function split_path(path)
  local segs = {}
  for seg in path:gmatch("[^%.]+") do
    local name = seg:match("^([^%[]*)%[%*%]$")
    if seg == "**" then
      segs[#segs + 1] = { key = seg, deep = true }
    elseif name then
      segs[#segs + 1] = { key = name, each = true }
    else
      segs[#segs + 1] = { key = seg, each = false }
    end
  end
  return segs
end

--- Why `path` (a text_fields or tool_fields entry) is not one, or nil.
function _M.path_error(path)
  if type(path) ~= "string" or path == "" then return "must be a non-empty string" end
  local segs = split_path(path)
  for i, s in ipairs(segs) do
    if s.deep and i < #segs then return "\"**\" must be the last segment" end
  end
  return nil
end

-- A leaf that is not a string is a "content parts" value: the array form of
-- `messages[*].content` every current chat API accepts
-- (`[{type="text", text="..."}, {type="image_url", ...}]`), the Responses API's
-- `input_text`, and Anthropic's `tool_result` whose `content` nests once more.
-- Collect every string, every part's `text`, and recurse into `content`, to a
-- bounded depth. Two parts keep their text elsewhere: an Anthropic `document`
-- block under `source.data` (source type "text") or `source.content` (type
-- "content"), and a Responses `file_search_call` under `results[*].text`.
-- The depth leaves room for a content document inside a tool_result. Anything
-- else (numbers, images, JSON null) contributes nothing. A decoder that keeps
-- null as a value (cjson.null) is assumed: `[null, {...}]` goes on past the
-- null, as the backend's parser does.
local LEAF_DEPTH = 6
local function collect(node, out, depth)
  if type(node) == "string" then
    out[#out + 1] = node
    return
  end
  if type(node) ~= "table" or depth > LEAF_DEPTH then return end
  if node[1] ~= nil then
    for _, item in ipairs(node) do collect(item, out, depth + 1) end
    return
  end
  if type(node.text) == "string" then out[#out + 1] = node.text end
  if node.content ~= nil then collect(node.content, out, depth + 1) end
  local src = node.source
  if type(src) == "table" then
    if src.type == "text" and type(src.data) == "string" then out[#out + 1] = src.data end
    if src.type == "content" and src.content ~= nil then collect(src.content, out, depth + 1) end
  end
  if node.type == "file_search_call" and type(node.results) == "table" then
    collect(node.results, out, depth + 1)
  end
end

-- Go's encoding/json (Ollama's /api/chat, a default watched path) matches an
-- object key to a field without regard to case, and folds U+017F (long s) to
-- s and U+212A (Kelvin sign) to k: {"MESSAGES": ...} reaches the model. A
-- path key is matched the same way, and every key that folds to it is read,
-- since with several the backend may take any one: the exact key first, the
-- others in byte order.
local function fold(s)
  if not s:find("[A-Z\128-\255]") then return s end
  return (s:lower():gsub("\197\191", "s"):gsub("\226\132\170", "k"))
end
_M.fold = fold

-- A folded key starts with the folded name's first byte, or with that
-- letter's other case, or with the first byte of U+017F / U+212A.
local FIRST = { s = 0xC5, k = 0xE2 }

-- Marks in `first` the bytes a key that folds to `name` can start with.
local function first_bytes(name, first)
  local want = fold(name)
  local b = want:byte(1)
  if not b then return end
  first[b] = true
  if b >= 0x61 and b <= 0x7A then first[b - 32] = true end
  local extra = FIRST[want:sub(1, 1)]
  if extra then first[extra] = true end
end

-- ---------------------------------------------------------------------------
-- Bounded walks over JSON of any shape: tool-call arguments ("**") and tool
-- definitions (rule.tool_fields). The client picks the shape, so the walk is
-- bounded: DEEP_NODES object keys and array items per extraction (sorting
-- the keys of one big object is what costs: 20k keys take about 5 ms under
-- LuaJIT and in Node), and DEEP_DEPTH levels below the path's value, which is
-- cjson's own nesting limit: JSON either core decodes is never cut by depth,
-- the bound only guards the recursion. Object keys are read in byte order: a
-- Lua table has none, and both cores must produce the same text. One
-- oversized node must not starve what comes after it, whether its own keys
-- and items are too many or only what is below them (an enum of small
-- arrays, a list of small objects): before a node is read, the nodes below
-- it are counted, up to what the budget has left. A node that fits is read
-- whole. One that does not spends at most half of what is left, so what
-- follows it keeps the other half: an array its newest items that fit whole
-- (the last ones) and, with what remains, the one before them; an object
-- its keys, unless they alone are more than its half (reading any of them
-- means sorting all of them, so it is skipped whole), then each value in
-- key order by the same rule. Counting is bounded too, or a chain of
-- nodes over the budget would be counted again at every level: past
-- DEEP_COUNT times DEEP_NODES nodes counted, a node is taken not to fit.
-- Whatever a bound leaves out, `capped` says so. An empty object or array
-- (and a decoder's null, which may be an empty table) adds nothing and is
-- not counted.
-- ---------------------------------------------------------------------------

_M.DEEP_DEPTH = 1000
_M.DEEP_NODES = 20000
_M.DEEP_COUNT = 4

-- @param decode json_decode, for "**" values that are a string of JSON
local function new_state(decode)
  return { out = {}, nodes = _M.DEEP_NODES, counts = _M.DEEP_COUNT * _M.DEEP_NODES, capped = false,
           decode = decode, defer = {} }
end

-- The string keys of object `node` in byte order, counted against the node
-- budget; nil (and nothing spent) when there are more than it has left.
local function keys_of(node, st)
  local keys, n = {}, 0
  for k in pairs(node) do
    if type(k) == "string" then
      n = n + 1
      if n > st.nodes then
        st.capped = true
        return nil
      end
      keys[n] = k
    end
  end
  st.nodes = st.nodes - n
  table.sort(keys)
  return keys
end

local function take(st, s)
  if s ~= "" then st.out[#st.out + 1] = s end
end

-- The values of a JSON Schema `type` a tool definition's walk leaves out: the
-- seven type names, a fixed vocabulary that carries no instruction (a
-- template renders "type": "string" for every parameter). Any other value of
-- `type`, and every other key and string, is read.
_M.SCHEMA_TYPES = { string = true, number = true, integer = true, boolean = true, object = true,
                    array = true, null = true }

local function schema_type(v)
  if type(v) == "string" then return _M.SCHEMA_TYPES[v] == true end
  if type(v) ~= "table" or v[1] == nil then return false end
  for _, t in ipairs(v) do
    if type(t) ~= "string" or not _M.SCHEMA_TYPES[t] then return false end
  end
  return true
end

-- The nodes the walk spends below `node` (at `depth`): its keys or items,
-- and theirs, as keys_of and every_string count them. The count stops as
-- soon as it is over `limit`, and returns a number over it: that only says
-- the node does not fit.
local function nodes_below(node, limit, depth, schema)
  if type(node) ~= "table" or next(node) == nil or depth > _M.DEEP_DEPTH then return 0 end
  local n = 0
  if node[1] ~= nil then
    n = #node
    if n > limit then return n end
    for i = 1, #node do
      local v = node[i]
      if type(v) == "table" then
        n = n + nodes_below(v, limit - n, depth + 1, schema)
        if n > limit then return n end
      end
    end
    return n
  end
  for k, v in pairs(node) do
    if type(k) == "string" then
      n = n + 1
      if n > limit then return n end
      if type(v) == "table" and not (schema and k == "type" and schema_type(v)) then
        n = n + nodes_below(v, limit - n, depth + 1, schema)
        if n > limit then return n end
      end
    end
  end
  return n
end

-- nodes_below(), charged to the walk's counting allowance (st.counts) at what it
-- counted, or limit + 1 when it stopped: the same charge whatever order the
-- keys come in. Once the allowance is spent a table does not fit.
local function counted(st, node, limit, depth, schema)
  if type(node) ~= "table" or next(node) == nil or depth > _M.DEEP_DEPTH then return 0 end
  if st.counts <= 0 then return limit + 1 end
  local n = nodes_below(node, limit, depth, schema)
  st.counts = st.counts - math.min(n, limit + 1)
  return n
end

local partial

--- Every key and string value below `node`, keys in byte order: what a
-- template that renders the value as JSON shows the model. With `schema`
-- (tool definitions) a `type` whose value is a JSON Schema type name is
-- left out, key and value. `fits`: the caller counted this node and it fits
-- the budget, so nothing below it is counted again. `last`: nothing after
-- it in its object needs the budget, so a node over it may spend all of it.
local function every_string(node, st, depth, schema, fits, last)
  if type(node) == "string" then return take(st, node) end
  if type(node) ~= "table" or next(node) == nil then return end
  if depth > _M.DEEP_DEPTH then
    st.capped = true
    return
  end
  if not fits and counted(st, node, st.nodes, depth, schema) > st.nodes then
    -- over the budget: at most half of what is left, the rest kept for what follows
    st.capped = true
    local keep = last and 0 or st.nodes - math.floor(st.nodes / 2)
    st.nodes = st.nodes - keep
    partial(node, st, depth, schema)
    st.nodes = st.nodes + keep
    return
  end
  if node[1] ~= nil then
    st.nodes = st.nodes - #node
    for i = 1, #node do every_string(node[i], st, depth + 1, schema, true) end
    return
  end
  for _, k in ipairs(keys_of(node, st)) do
    local v = node[k]
    if not (schema and k == "type" and schema_type(v)) then
      take(st, k)
      every_string(v, st, depth + 1, schema, true)
    end
  end
end

-- A node over the budget (st.nodes, its share), read as far as it goes. An
-- array: its newest items that fit whole, walking back from the last, and
-- the one before them with what is left (a table, over it by then). An
-- object: its keys, unless there are more than the budget has left, then
-- each value as every_string reads one; the values after the last table
-- among them are strings and scalars, which cost nothing, so that table
-- keeps nothing back for them.
partial = function(node, st, depth, schema)
  if node[1] ~= nil then
    local n, left = #node, st.nodes
    local first = n + 1
    while first > 1 and left > 0 do
      local c = 1 + counted(st, node[first - 1], left - 1, depth + 1, schema)
      if c > left then break end
      left, first = left - c, first - 1
    end
    local whole = st.nodes - left
    st.nodes = left
    if first > 1 and left > 0 then
      st.nodes = left - 1
      partial(node[first - 1], st, depth + 1, schema)
    end
    st.nodes = st.nodes + whole
    for i = first, n do
      st.nodes = st.nodes - 1
      every_string(node[i], st, depth + 1, schema, true)
    end
    return
  end
  local keys = keys_of(node, st)
  if not keys then return end
  local last = 0
  for i, k in ipairs(keys) do
    local v = node[k]
    if type(v) == "table" and next(v) ~= nil and not (schema and k == "type" and schema_type(v)) then last = i end
  end
  for i, k in ipairs(keys) do
    local v = node[k]
    if not (schema and k == "type" and schema_type(v)) then
      take(st, k)
      every_string(v, st, depth + 1, schema, false, i == last)
    end
  end
end

-- The value a tool_fields path ends at: a string whole, anything else (a
-- tool definition, a JSON Schema, a list of them) every key and string in
-- it but JSON Schema type names. vLLM, llama.cpp and SGLang render tools
-- with `tojson`, so the model reads extension keys, $comment, pattern,
-- required entries and $defs names as much as a description.
local function tool_leaf(node, st)
  if type(node) == "string" then return take(st, node) end
  every_string(node, st, 1, true)
end

-- The value a "**" path ends at. A string that holds a JSON object or array
-- (OpenAI tool-call arguments) is read decoded, as the chat templates that
-- render arguments read it: its keys and strings, escapes resolved, and no
-- "{}" of an empty call. Anything else, and JSON the decoder refuses, is
-- read as it is.
local function deep_value(node, st)
  if type(node) == "string" and st.decode and node:find("^[ \t\n\r]*[%[{]") then
    local ok, v = pcall(st.decode, _M.lone_surrogates(node))
    if ok and type(v) == "table" then return every_string(v, st, 1) end
  end
  every_string(node, st, 1)
end

-- ---------------------------------------------------------------------------
-- Field paths are walked together, not one after another: the paths that go
-- through the same key go through it once, and an array one of them goes
-- through item by item is read item by item for all of them. The values come
-- out in document order, a message's content and its tool calls together,
-- so the judging window (newest first) keeps the newest turn whole, tool
-- calls included. Each "**" value is read after the walk, newest first, so
-- the node budget goes to the most recent tool calls and a bound cuts the
-- oldest.
--
-- A list of paths is compiled once into a plan (plan_of), so the walk itself
-- allocates nothing but the "**" slots: at a node, what to do there, in the
-- order the first path for it comes. An op is a path that ends here
-- ({ kind = END, depth }: collect()'s depth, 2 for a path that ends at an
-- array read item by item), a "**" here ({ kind = DEEP }), or a key the
-- paths go on through ({ kind = KEY, key, whole, whole_arr, items_arr }):
-- the plan for the value under the key when it is not an array (`whole`),
-- and when it is, the plans for the array itself and for each of its items.
-- ---------------------------------------------------------------------------

local END, DEEP, KEY = 1, 2, 3

-- `cursors`: the paths at one node, { segs, i (the next segment), depth }.
-- `leaf`: tool_fields, whose paths read an array that ends them whole.
local function compile(cursors, leaf)
  local ops, groups = {}, {}
  for _, c in ipairs(cursors) do
    local seg = c.segs[c.i]
    if not seg then
      ops[#ops + 1] = { kind = END, depth = c.depth or 1 }
    elseif seg.deep then
      ops[#ops + 1] = { kind = DEEP }
    else
      local g = groups[seg.key]
      if not g then
        g = { kind = KEY, key = seg.key, cursors = {} }
        groups[seg.key] = g
        ops[#ops + 1] = g
      end
      g.cursors[#g.cursors + 1] = c
    end
  end
  for i, op in ipairs(ops) do
    if op.kind == KEY then
      local whole, whole_arr, items_arr = {}, {}, {}
      for _, c in ipairs(op.cursors) do
        local nxt = { segs = c.segs, i = c.i + 1 }
        if c.segs[c.i].each then
          items_arr[#items_arr + 1] = nxt
        else
          whole[#whole + 1] = nxt
          if c.i == #c.segs and not leaf then
            -- a path that ends at an array: collect() reads it item by item, one level down
            items_arr[#items_arr + 1] = { segs = c.segs, i = c.i + 1, depth = 2 }
          else
            whole_arr[#whole_arr + 1] = nxt
          end
        end
      end
      op.cursors = nil
      if #whole > 0 then op.whole = compile(whole, leaf) end
      if #whole_arr > 0 then op.whole_arr = compile(whole_arr, leaf) end
      if #items_arr > 0 then op.items_arr = compile(items_arr, leaf) end
      if op.key ~= "" then
        -- for variants_of: the ops by folded key, the bytes a key can start
        -- with, and the lengths an ASCII key can have (U+017F and U+212A
        -- take 2 and 3 bytes for one)
        ops.folded, ops.first, ops.lens = ops.folded or {}, ops.first or {}, ops.lens or {}
        local f = fold(op.key)
        local list = ops.folded[f] or {}
        list[#list + 1] = i
        ops.folded[f] = list
        first_bytes(op.key, ops.first)
        ops.lens[#f] = true
        ops.maxlen = math.max(ops.maxlen or 0, 3 * #f)
      end
    end
  end
  if ops.folded then
    -- a key that is an op's own, and that no other op's key folds to, needs no look
    ops.exact = {}
    for _, op in ipairs(ops) do
      if op.kind == KEY and op.key ~= "" then
        local same = true
        for _, j in ipairs(ops.folded[fold(op.key)]) do
          if ops[j].key ~= op.key then same = false end
        end
        if same then ops.exact[op.key] = true end
      end
    end
  end
  return ops
end

-- The keys of object `node` that fold to an op's key without being it, by
-- op index, each list in byte order; nil when there are none (nearly
-- always). One pass over the keys, for all the plan's keys at once.
local function variants_of(node, plan)
  local first, folded, exact, lens, maxlen, found = plan.first, plan.folded, plan.exact, plan.lens, plan.maxlen, nil
  for k in pairs(node) do
    if type(k) == "string" and not exact[k] and first[k:byte(1) or 0]
       and (lens[#k] or (#k <= maxlen and k:find("[\128-\255]"))) then
      local ops = folded[fold(k)]
      if ops then
        for _, i in ipairs(ops) do
          if plan[i].key ~= k then
            found = found or {}
            local list = found[i] or {}
            list[#list + 1] = k
            found[i] = list
          end
        end
      end
    end
  end
  if found then
    for _, list in pairs(found) do table.sort(list) end
  end
  return found
end

-- Plans by list of paths; a rule's lists are few, and the cache starts over
-- past PLANS_MAX rather than grow with lists a caller makes per request.
local PLANS, NPLANS, PLANS_MAX = {}, 0, 64
local NONE = {}

local function plan_of(fields, leaf)
  fields = fields or NONE
  local key = (leaf and "t" or "c") .. "\0" .. table.concat(fields, "\0")
  local plan = PLANS[key]
  if not plan then
    local cursors = {}
    for i, f in ipairs(fields) do cursors[i] = { segs = split_path(f), i = 1 } end
    plan = compile(cursors, leaf)
    if NPLANS >= PLANS_MAX then PLANS, NPLANS = {}, 0 end
    PLANS[key], NPLANS = plan, NPLANS + 1
  end
  return plan
end

local walk

-- `child`, the value under one key (or the node itself for "[*]"), for the
-- paths that go on through that key.
local function through(child, op, st)
  if child == nil then return end
  if type(child) == "table" and child[1] ~= nil then
    if op.whole_arr then walk(child, op.whole_arr, st) end
    local items = op.items_arr
    if items then
      for _, item in ipairs(child) do walk(item, items, st) end
    end
  elseif op.whole then
    walk(child, op.whole, st)
  end
end

-- st.out collects the values; st.leaf, when set, reads the value a path
-- ends at (tool_fields), collect() otherwise. A "**" value leaves a slot
-- for settle() to fill.
walk = function(node, plan, st)
  if node == nil then return end
  local found = plan.folded and type(node) == "table" and node[1] == nil and variants_of(node, plan)
  for i = 1, #plan do
    local op = plan[i]
    local kind = op.kind
    if kind == END then
      if st.leaf then st.leaf(node, st) else collect(node, st.out, op.depth) end
    elseif kind == DEEP then
      local slot = { node = node }
      st.out[#st.out + 1] = slot
      st.defer[#st.defer + 1] = slot
    elseif op.key == "" then
      through(node, op, st)
    elseif type(node) == "table" then
      through(node[op.key], op, st)
      local others = found and found[i]
      if others then
        for _, k in ipairs(others) do through(node[k], op, st) end
      end
    end
  end
end

-- Reads the "**" values, newest first, and returns every value in document order.
local function settle(st)
  for k = #st.defer, 1, -1 do
    local slot, saved = st.defer[k], st.out
    st.out = {}
    deep_value(slot.node, st)
    slot.values, st.out = st.out, saved
  end
  if #st.defer == 0 then return st.out end
  local out = {}
  for _, v in ipairs(st.out) do
    if type(v) == "table" then
      for _, s in ipairs(v.values) do out[#out + 1] = s end
    else
      out[#out + 1] = v
    end
  end
  return out
end

--- Extract candidate text from a decoded JSON value using the given field paths.
-- @param decoded     table (decoded JSON)
-- @param fields      list of path strings
-- @param json_decode optional: reads a "**" value that is a string of JSON
-- @return string (joined with "\n"), may be ""; the list of strings found,
--         in document order; and true when a "**" walk hit a bound and left
--         something out
function _M.extract_json(decoded, fields, json_decode)
  local st = new_state(json_decode)
  walk(decoded, plan_of(fields, false), st)
  local out = settle(st)
  return table.concat(out, "\n"), out, st.capped
end

--- Tool definitions in a decoded JSON body (rule.tool_fields): what the
-- model reads of the tools it may call and of the schema its answer must
-- follow. A path ending at a string takes it; one ending at a table reads
-- every key and string in it but JSON Schema type names (tool_leaf). A "**"
-- path reads everything below it.
-- @param decoded     table (decoded JSON)
-- @param fields      list of path strings (text_fields syntax)
-- @param json_decode optional, as for extract_json
-- @return string (joined with "\n"), may be ""; the list of strings; and
--         true when a bound (depth, nodes) left something out
function _M.extract_tools(decoded, fields, json_decode)
  local st = new_state(json_decode)
  st.leaf = tool_leaf
  if type(decoded) == "table" then walk(decoded, plan_of(fields, true), st) end
  local out = settle(st)
  return table.concat(out, "\n"), out, st.capped
end

-- Tool results in the chat shapes gateways see:
--   OpenAI Chat Completions  messages[*] with role "tool" (or legacy "function"): content
--   Anthropic Messages       messages[*].content[*] with type "tool_result": content
--   OpenAI Responses         input[*] with a type ending in "_call_output"
--                            (function_call_output, custom_tool_call_output,
--                            local_shell_call_output, ...) or "mcp_call": output;
--                            "file_search_call": results[*].text
--   AI SDK 5 UIMessages      messages[*].parts[*] with type "tool-<name>" or
--                            "dynamic-tool": output, whatever its state (the
--                            client sets it), read as a "**" path reads it
local function responses_result(item)
  local t = item.type
  return type(t) == "string" and (t:sub(-12) == "_call_output" or t == "mcp_call")
end

local function sdk_tool_part(part)
  local t = part.type
  return type(t) == "string" and (t:sub(1, 5) == "tool-" or t == "dynamic-tool")
end

-- `st`: a walk state; a tool part's output leaves a slot for settle() to fill.
local function tool_results(decoded, st)
  local out = st.out
  local msgs = decoded.messages
  if type(msgs) == "table" then
    for _, m in ipairs(msgs) do
      if type(m) == "table" then
        if m.role == "tool" or m.role == "function" then
          collect(m.content, out, 1)
        elseif type(m.content) == "table" then
          for _, block in ipairs(m.content) do
            if type(block) == "table" and block.type == "tool_result" then collect(block.content, out, 1) end
          end
        end
        if type(m.parts) == "table" then
          for _, part in ipairs(m.parts) do
            if type(part) == "table" and part.output ~= nil and sdk_tool_part(part) then
              local slot = { node = part.output }
              out[#out + 1] = slot
              st.defer[#st.defer + 1] = slot
            end
          end
        end
      end
    end
  end
  local input = decoded.input
  if type(input) == "table" then
    for _, item in ipairs(input) do
      if type(item) == "table" then
        if responses_result(item) then
          collect(item.output, out, 1)
        elseif item.type == "file_search_call" and type(item.results) == "table" then
          collect(item.results, out, 1)
        end
      end
    end
  end
end

--- Retrieved content in a decoded JSON body: tool results (when
-- `spec.tool_results`) and the values of `spec.fields`, in that order.
-- @param decoded     table
-- @param spec        { tool_results = bool, fields = { path, ... } }
-- @param json_decode optional, as for extract_json ("**" fields)
-- @return string (joined with "\n"), may be ""; the list of strings found;
--         and true when a "**" field hit a bound and left something out
function _M.extract_untrusted(decoded, spec, json_decode)
  local st = new_state(json_decode)
  if type(decoded) ~= "table" or type(spec) ~= "table" then return "", st.out, false end
  if spec.tool_results ~= false then tool_results(decoded, st) end
  walk(decoded, plan_of(spec.fields, false), st)
  local out = settle(st)
  return table.concat(out, "\n"), out, st.capped
end

-- ---------------------------------------------------------------------------
-- Format detection. The Content-Type a client sends is a hint, not a fact:
-- Ollama decodes JSON whatever the header says, and FastAPI parses a body
-- without one as JSON. So the body decides: JSON when it parses as JSON,
-- scanned when it starts like JSON and the decoder refuses it (under a form
-- or multipart type read that way as well), form or multipart when declared
-- (or form-shaped with no header), text when it reads as text, and "binary"
-- otherwise, which L1 reports as unjudgeable instead of letting it through
-- as "no text".
-- ---------------------------------------------------------------------------

local BOM = "\239\187\191"

--- True when `s` reads as text: no NUL, and control bytes other than tab,
-- newline and carriage return under 1% of the bytes.
function _M.is_text(s)
  if s:find("%z") then return false end
  local _, ctl = s:gsub("[\1-\8\11\12\14-\31\127]", "")
  return ctl * 100 <= #s
end

-- The value of every `name=value` pair: in each `&`-separated piece, the text
-- after the first `=` that follows a non-empty name (leading `=` are skipped).
-- Plain finds, linear in the body: the pattern this replaces,
-- gmatch("([^&=]+)=([^&]*)"), gives the same values but backtracks from every
-- byte of a long run without `&` or `=`, quadratic in the access phase.
local function form_values(body, out)
  local i, n = 1, #body
  while i <= n do
    local amp = body:find("&", i, true) or n + 1
    local piece = body:sub(i, amp - 1)
    local name = piece:find("[^=]")
    local eq = name and piece:find("=", name, true)
    if eq then
      local v = piece:sub(eq + 1)
      v = v:gsub("+", " "):gsub("%%(%x%x)", function(h) return string.char(tonumber(h, 16)) end)
      out[#out + 1] = v
    end
    i = amp + 1
  end
end

-- multipart/form-data: every field without a filename, and file parts whose
-- own Content-Type is text or JSON (a prompt uploaded as prompt.txt). Binary
-- files contribute nothing. At most MAX_PARTS parts are read.
local MAX_PARTS = 100
local function multipart_values(body, content_type, out)
  local boundary = content_type:match('[Bb][Oo][Uu][Nn][Dd][Aa][Rr][Yy]="([^"]+)"')
    or content_type:match("[Bb][Oo][Uu][Nn][Dd][Aa][Rr][Yy]=([^;%s,]+)")
  if not boundary then return end
  local delim = "--" .. boundary
  local pos = body:find(delim, 1, true)
  local parts = 0
  while pos and parts < MAX_PARTS do
    local after = pos + #delim
    if body:sub(after, after + 1) == "--" then break end   -- closing delimiter
    local next_pos = body:find(delim, after, true)
    local part = body:sub(after, (next_pos or #body + 1) - 1)
    part = part:gsub("^\r?\n", ""):gsub("\r?\n$", "")
    local hs, he = part:find("\r?\n\r?\n")
    if hs then
      local head, value = part:sub(1, hs - 1):lower(), part:sub(he + 1)
      local has_file = head:find("filename%*?=") ~= nil
      local pct = head:match("content%-type:%s*([^\r\n;]+)") or ""
      if (not has_file or pct:find("^text/") or pct:find("json", 1, true)) and _M.is_text(value) then
        out[#out + 1] = value
      end
    end
    parts = parts + 1
    pos = next_pos
  end
end

--- `s` with every \uD800-\uDFFF escape that is not half of a valid pair
-- written as \uFFFD. cjson refuses a lone surrogate; Python, Node and Go
-- accept it (Go reads U+FFFD), so the rest of the body reaches the model.
function _M.lone_surrogates(s)
  if not s:find("\\u[dD][89a-fA-F]") then return s end
  local out, last, i = {}, 1, 1
  while true do
    local j = s:find("\\", i, true)
    if not j then break end
    i = j + 2   -- any other escape is two bytes
    local cp = s:sub(j + 1, j + 1) == "u" and tonumber(s:match("^%x%x%x%x", j + 2) or "", 16)
    if cp then
      i = j + 6
      if cp >= 0xD800 and cp <= 0xDFFF then
        local lo = cp <= 0xDBFF and tonumber(s:match("^\\u(%x%x%x%x)", i) or "", 16)
        if lo and lo >= 0xDC00 and lo <= 0xDFFF then
          i = i + 6
        else
          out[#out + 1] = s:sub(last, j - 1)
          out[#out + 1] = "\\ufffd"
          last = i
        end
      end
    end
  end
  if last == 1 then return s end
  out[#out + 1] = s:sub(last)
  return table.concat(out)
end

--- Extract text from a raw body.
-- @param body         string
-- @param content_type string (may be nil)
-- @param fields       list of JSON paths
-- @param json_decode  function(string) -> table|nil
-- @return text string (the values joined with "\n"),
--         kind ("json"|"scan"|"invalid"|"form"|"multipart"|"text"|"binary"|"none"),
--         list of the values found (newest last), for window(),
--         the decoded JSON value when kind is "json", and true when a "**"
--         walk hit a bound and left something out
function _M.extract(body, content_type, fields, json_decode)
  if type(body) ~= "string" or body == "" then return "", "none", {} end
  local raw_ct = type(content_type) == "string" and content_type or ""
  local ct = raw_ct:lower()
  -- A UTF-8 BOM is not JSON (cjson rejects it) but Python's json.loads on
  -- bytes and Express's body-parser skip it: judge what the backend reads.
  if body:sub(1, 3) == BOM then body = body:sub(4) end
  -- declared JSON: a JSON media type (application/json, text/json,
  -- application/*+json), not "json" in a parameter such as a multipart
  -- boundary or "text/plain; profile=json"
  local declared_json = ct:match("^[^;]*"):find("json", 1, true) ~= nil
  local form = ct:find("application/x-www-form-urlencoded", 1, true)
    or (ct == "" and body:find("^[%w%.%-_~%%%+%[%]]+=[^%s]*$"))
  local multipart = ct:find("multipart/form-data", 1, true)
  local first = body:match("^%s*(.)")
  if first == "{" or first == "[" or declared_json then
    if not json_decode then return "", "none", {} end
    local ok, decoded = pcall(json_decode, _M.lone_surrogates(body))
    if ok and type(decoded) == "table" then
      local text, out, capped = _M.extract_json(decoded, fields, json_decode)
      return text, "json", out, decoded, capped
    end
    -- a JSON scalar has no text fields
    if declared_json and ok and decoded ~= nil then return "", "none", {} end
    -- The decoder refused it; the backend's parser may not (cjson refuses
    -- nesting past 1000 and bytes after the value, Go and Node do not, and
    -- Ollama decodes JSON whatever the Content-Type says: curl -d sends
    -- form-urlencoded). So the tolerant scanner past max_body_bytes uses
    -- reads it, declared JSON or not: the text fields' string values and the
    -- objects under a "**" path's key. Under a form or multipart type the
    -- values that reading gives follow, since a backend of that kind reads
    -- the body so. Declared JSON with nothing to scan is unjudgeable, never
    -- "no text"; any other body with nothing to scan is read as before.
    local out = _M.scan_strings(body, _M.field_keys(fields), {}, _M.deep_keys(fields))
    if #out > 0 then
      if form and not declared_json then
        form_values(body, out)
      elseif multipart and not declared_json then
        multipart_values(body, raw_ct, out)
      end
      return table.concat(out, "\n"), "scan", out
    end
    if declared_json then return "", "invalid", {} end
  end
  local out = {}
  if form then
    form_values(body, out)
    return table.concat(out, "\n"), "form", out
  end
  if multipart then
    multipart_values(body, raw_ct, out)
    return table.concat(out, "\n"), "multipart", out
  end
  if _M.is_text(body) then return body, "text", { body } end
  return "", "binary", {}
end

-- ---------------------------------------------------------------------------
-- Partial bodies. Past max_body_bytes the body is not parsed; the adapter
-- hands over the bytes it has (the head, and the tail where it can seek) and
-- this tolerant scanner pulls the JSON string values of the text-field keys
-- out of them, truncated JSON included, and every key and string of an
-- object under a "**" path's key (tool-call arguments that are an object).
-- It is linear in the bytes: no value is read twice.
-- ---------------------------------------------------------------------------

local function utf8_char(cp)
  if cp < 0x80 then return string.char(cp) end
  if cp < 0x800 then return string.char(0xC0 + math.floor(cp / 0x40), 0x80 + cp % 0x40) end
  if cp < 0x10000 then
    return string.char(0xE0 + math.floor(cp / 0x1000), 0x80 + math.floor(cp / 0x40) % 0x40, 0x80 + cp % 0x40)
  end
  return string.char(0xF0 + math.floor(cp / 0x40000), 0x80 + math.floor(cp / 0x1000) % 0x40,
    0x80 + math.floor(cp / 0x40) % 0x40, 0x80 + cp % 0x40)
end

local ESC = { ['"'] = '"', ["\\"] = "\\", ["/"] = "/", b = "\b", f = "\f", n = "\n", r = "\r", t = "\t" }

-- Decode one JSON string body starting at `i` (just after the opening quote);
-- returns the value and the index after the closing quote (or #s + 1).
local function read_string(s, i)
  local buf, n = {}, #s
  while i <= n do
    local j = s:find('["\\]', i)
    if not j then buf[#buf + 1] = s:sub(i); return table.concat(buf), n + 1 end
    buf[#buf + 1] = s:sub(i, j - 1)
    if s:sub(j, j) == '"' then return table.concat(buf), j + 1 end
    local e = s:sub(j + 1, j + 1)
    if e == "u" then
      local hex = s:match("^%x%x%x%x", j + 2)
      if not hex then return table.concat(buf), n + 1 end
      local cp = tonumber(hex, 16)
      i = j + 6
      if cp >= 0xD800 and cp <= 0xDBFF then
        local lo = s:match("^\\u(%x%x%x%x)", i)
        local lcp = lo and tonumber(lo, 16)
        if lcp and lcp >= 0xDC00 and lcp <= 0xDFFF then
          cp = 0x10000 + (cp - 0xD800) * 0x400 + (lcp - 0xDC00)
          i = i + 6
        end
      end
      -- a lone surrogate is U+FFFD, as in lone_surrogates()
      if cp >= 0xD800 and cp <= 0xDFFF then cp = 0xFFFD end
      buf[#buf + 1] = utf8_char(cp)
    elseif e == "" then
      return table.concat(buf), n + 1
    else
      buf[#buf + 1] = ESC[e] or e
      i = j + 2
    end
  end
  return table.concat(buf), n + 1
end

--- The last key of each text-field path, folded (see fold):
-- "messages[*].content" -> "content".
function _M.field_keys(fields)
  local keys = {}
  for _, f in ipairs(fields or {}) do
    -- "arguments.**": the strings under "arguments"
    local last = f:gsub("%.%*%*$", ""):match("([^%.%[%]%*]+)[%[%]%*]*$")
    if last then keys[fold(last)] = true end
  end
  -- content parts carry their text under "text"
  if keys.content then keys.text = true end
  return keys
end

--- The last key of each "**" text-field path, folded, for scan_strings:
-- "messages[*].tool_calls[*].function.arguments.**" -> arguments = "any";
-- "object" instead when a path without "**" ends at the same key too
-- ("input": a tool_use input, and the Responses input list).
function _M.deep_keys(fields)
  local deep, plain = {}, {}
  for _, f in ipairs(fields or {}) do
    local last = f:gsub("%.%*%*$", ""):match("([^%.%[%]%*]+)[%[%]%*]*$")
    if last then
      if f:find("%.%*%*$") then deep[fold(last)] = true else plain[fold(last)] = true end
    end
  end
  local out = {}
  for k in pairs(deep) do out[k] = plain[k] and "object" or "any" end
  return out
end

-- True when `key` is ASCII word characters, U+017F and U+212A only: the
-- byte class scan_strings finds keys with also matches other sequences of
-- those bytes (U+0144 is \197\132), which are not keys to either core.
local function key_chars(key)
  if not key:find("[\128-\255]") then return true end
  return key:gsub("\197\191", "s"):gsub("\226\132\170", "k"):find("^[%w_%-]+$") ~= nil
end

local scan_value

--- Collect the string values of `keys` (from field_keys) from possibly
-- truncated JSON. Keys match the way walk() matches them: folded, so every
-- spelling a case-insensitive backend reads is collected. With `deep` (from
-- deep_keys), the value of a "**" path's key is read as the walk reads it,
-- every key and string in it, in the order they come: an object (Ollama and
-- Anthropic tool-call arguments), and an array when no other path ends at
-- that key; otherwise the scan goes on inside it, as for any other key.
function _M.scan_strings(s, keys, out, deep)
  local i = 1
  while true do
    -- key bytes: ASCII word characters and the bytes of U+017F and U+212A;
    -- `b` is the value's first byte (a number or a literal is passed over)
    local a, b, key = s:find('"([%w_%-\197\191\226\132\170]+)"%s*:%s*["{%[]', i)
    if not a then break end
    local c = s:byte(b)
    if not key_chars(key) then
      i = a + 1   -- not a key: look again from the next byte
    elseif c == 34 then
      local value, nexti = read_string(s, b + 1)
      if keys[fold(key)] and value ~= "" then out[#out + 1] = value end
      i = nexti
    else
      local d = deep and deep[fold(key)]
      if d and (c == 123 or d == "any") then
        i = scan_value(s, b, out, false)
      else
        i = b + 1
      end
    end
  end
  return out
end

-- The index after a JSON Schema type name, or a list of them, that starts
-- at or after `i` (past the colon of a "type" key); nil when the value is
-- anything else.
local function type_names(s, i)
  local q = s:find("[^ \t\n\r]", i)
  if not q then return nil end
  local c = s:sub(q, q)
  if c == '"' then
    local v, after = read_string(s, q + 1)
    return _M.SCHEMA_TYPES[v] and after or nil
  end
  if c ~= "[" then return nil end
  local p, any = q + 1, false
  while true do
    p = s:find("[^ \t\n\r]", p)
    if not p then return nil end
    c = s:sub(p, p)
    if c == "]" then return any and p + 1 or nil end
    if c ~= '"' then return nil end
    local v, after = read_string(s, p + 1)
    if not _M.SCHEMA_TYPES[v] then return nil end
    any = true
    p = s:find("[^ \t\n\r]", after)
    if not p then return nil end
    c = s:sub(p, p)
    if c == "," then
      p = p + 1
    elseif c ~= "]" then
      return nil
    end
  end
end

-- Every key and string of the JSON value that starts at `i` (a `{` or `[`),
-- to its end or the end of `s`, in the order they come; with `schema` (tool
-- definitions) a "type" key whose value is a JSON Schema type name is left
-- out with it, as tool_leaf does. Returns the index after the value.
scan_value = function(s, i, out, schema)
  local depth, n = 0, #s
  while true do
    local j = s:find('[{}%[%]"]', i)
    if not j then return n + 1 end
    local c = s:byte(j)
    if c == 34 then
      local v, nexti = read_string(s, j + 1)
      local k = s:find("[^ \t\n\r]", nexti)
      local skip = schema and v == "type" and k and s:byte(k) == 58 and type_names(s, k + 1)
      if skip then
        i = skip
      else
        if v ~= "" then out[#out + 1] = v end
        i = nexti
      end
    elseif c == 123 or c == 91 then
      depth, i = depth + 1, j + 1
    else
      depth, i = depth - 1, j + 1
      if depth <= 0 then return i end
    end
  end
end

--- The tool definitions (rule.tool_fields) in possibly truncated JSON, past
-- max_body_bytes: every key and string of the value of each key that folds
-- to a tool_fields path's last key (see field_keys), JSON Schema type names
-- left out, in the order they come. There is no structure to walk, so a key
-- is found wherever it is, and keys are not sorted.
function _M.scan_tools(s, keys, out)
  local i = 1
  while true do
    local a, b, key = s:find('"([%w_%-\197\191\226\132\170]+)"%s*:%s*', i)
    if not a then break end
    if not key_chars(key) then
      i = a + 1
    elseif not keys[fold(key)] then
      i = b + 1
    else
      local c = s:sub(b + 1, b + 1)
      if c == '"' then
        local v, nexti = read_string(s, b + 2)
        if v ~= "" then out[#out + 1] = v end
        i = nexti
      elseif c == "{" or c == "[" then
        i = scan_value(s, b + 1, out, true)
      else
        i = b + 1
      end
    end
  end
  return out
end

-- ---------------------------------------------------------------------------
-- Judging window. Text over the budget is cut down before it is fingerprinted
-- and sent to L2: the always_suspect hit (if any) with 1 KiB on each side,
-- then values newest first, the one that does not fit kept as head + tail.
-- Chat APIs resend the whole history every turn; the turns before the newest
-- were judged when they were the newest. Cuts never split a UTF-8 sequence.
-- ---------------------------------------------------------------------------

local function cont(s, i)
  local c = s:byte(i)
  return c ~= nil and c >= 0x80 and c < 0xC0
end

--- `s` cut to at most `n` bytes at a character boundary, from the front.
function _M.head(s, n)
  if n <= 0 then return "" end
  if #s <= n then return s end
  local e = n
  while e > 0 and cont(s, e + 1) do e = e - 1 end
  return s:sub(1, e)
end

--- `s` cut to at most `n` bytes at a character boundary, from the back.
function _M.tail(s, n)
  if n <= 0 then return "" end
  if #s <= n then return s end
  local b = #s - n + 1
  while b <= #s and cont(s, b) do b = b + 1 end
  return s:sub(b)
end

_M.HIT_CONTEXT = 1024

--- Split `text` into consecutive pieces of at most `budget` bytes covering
-- all of it, for judging in chunks (rule.max_judge_chunks). A cut prefers the
-- last newline in the second half of a piece (the newline itself is dropped,
-- it joined two values) and never splits a UTF-8 sequence.
-- @return pieces, and the byte offset in `text` where each piece starts
function _M.chunks(text, budget)
  local pieces, starts = {}, {}
  local i, n = 1, #text
  local half = math.floor(budget / 2)
  while i <= n do
    if n - i + 1 <= budget then
      pieces[#pieces + 1], starts[#starts + 1] = text:sub(i), i
      break
    end
    local e, nexti = i + budget - 1, nil
    for j = e, i + half + 1, -1 do
      if text:byte(j) == 10 then e, nexti = j - 1, j + 1 break end
    end
    if not nexti then
      -- back to a character boundary: at most 3 bytes, the longest run of
      -- continuation bytes in valid UTF-8. A longer run is invalid UTF-8 and
      -- is cut where it is; walking it back byte by byte made a 1-byte piece
      -- per step, O(n x budget) on a body of continuation bytes.
      local cut, k = e, 0
      while k < 3 and e > i and cont(text, e + 1) do e, k = e - 1, k + 1 end
      if e > i and cont(text, e + 1) then e = cut end
      nexti = e + 1
    end
    pieces[#pieces + 1], starts[#starts + 1] = text:sub(i, e), i
    i = nexti
  end
  return pieces, starts
end

--- @param text   the joined values
-- @param values the values, in order (newest last)
-- @param budget max bytes
-- @param from,to byte span of an always_suspect hit in `text`, or nil
-- @return the text to judge, true when it was cut
function _M.window(text, values, budget, from, to)
  if #text <= budget then return text, false end
  local out, rem = {}, budget
  if from and to then
    -- the hit and up to HIT_CONTEXT bytes each side, in at most half the budget
    local half = math.floor(budget / 2)
    local ctxb = math.max(0, math.min(_M.HIT_CONTEXT, math.floor((half - (to - from + 1)) / 2)))
    local a = math.max(1, from - ctxb)
    while a > 1 and cont(text, a) do a = a - 1 end
    local piece = _M.head(text:sub(a), math.min(math.min(to + ctxb, #text) - a + 1, half))
    out[1] = piece
    rem = rem - #piece - 1
  end
  local chosen = {}
  for i = #values, 1, -1 do
    if rem <= 0 then break end
    local v = values[i]
    if #v + 1 <= rem then
      chosen[i] = v
      rem = rem - #v - 1
    else
      local h = _M.head(v, math.floor((rem - 1) / 2))
      chosen[i] = h .. "\n" .. _M.tail(v, rem - 1 - #h - 1)
      rem = 0
    end
  end
  for i = 1, #values do
    if chosen[i] then out[#out + 1] = chosen[i] end
  end
  return table.concat(out, "\n"), true
end

-- ---------------------------------------------------------------------------
-- Well-formed text for the judge. cjson keeps a string's bytes as sent, so
-- invalid UTF-8 from the client reaches the provider request, and a strict
-- judge server refuses the call (an L2 error, which passes the request).
-- ---------------------------------------------------------------------------

local FFFD = "\239\191\189"

--- `s` with every ill-formed UTF-8 sequence replaced by U+FFFD, one per
-- maximal subpart: what TextDecoder (the JavaScript core's body decoding),
-- Go and Node make of the same bytes.
function _M.valid_utf8(s)
  local i = s:find("[\128-\255]")
  if not i then return s end
  local out, last = {}, 1
  while i do
    local c = s:byte(i)
    -- bytes the lead byte needs, and the range of the first one after it
    local need, lo, hi = 0, 0x80, 0xBF
    if c >= 0xC2 and c <= 0xDF then need = 1
    elseif c == 0xE0 then need, lo = 2, 0xA0
    elseif c == 0xED then need, hi = 2, 0x9F
    elseif c >= 0xE1 and c <= 0xEF then need = 2
    elseif c == 0xF0 then need, lo = 3, 0x90
    elseif c == 0xF4 then need, hi = 3, 0x8F
    elseif c >= 0xF1 and c <= 0xF3 then need = 3
    end
    local j, bad = i + 1, need == 0
    while need > 0 do
      local d = s:byte(j)
      if not d or d < lo or d > hi then bad = true break end
      need, lo, hi, j = need - 1, 0x80, 0xBF, j + 1
    end
    if bad then
      out[#out + 1] = s:sub(last, i - 1)
      out[#out + 1] = FFFD
      last = j
    end
    i = s:find("[\128-\255]", j)
  end
  if last == 1 then return s end
  out[#out + 1] = s:sub(last)
  return table.concat(out)
end

-- ---------------------------------------------------------------------------
-- Normalization
-- ---------------------------------------------------------------------------

local DEFAULTS = {
  prefix_bytes   = 2048,
  strip_digits   = true,   -- remove digit runs >= 4
  strip_uuid     = true,
}

--- Normalize text so that trivially varied payloads share a fingerprint.
-- Steps: lowercase, strip UUIDs / long digit runs, collapse whitespace, truncate.
function _M.normalize(text, opts)
  opts = opts or DEFAULTS
  local s = tostring(text or ""):lower()
  if opts.strip_uuid ~= false then
    s = s:gsub("%x%x%x%x%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%x%x%x%x%x%x%x%x", "")
  end
  if opts.strip_digits ~= false then
    s = s:gsub("%d%d%d%d+", "")
  end
  s = s:gsub("%s+", " ")
  s = s:gsub("^ ", ""):gsub(" $", "")
  local n = opts.prefix_bytes or DEFAULTS.prefix_bytes
  if #s > n then s = s:sub(1, n) end
  return s
end

--- Fingerprint = hash(normalize(text)) over the WHOLE normalized text.
-- `opts.prefix_bytes` is deliberately ignored here: a fingerprint that only
-- covers a prefix lets any text that shares the prefix reuse a cached or
-- trusted verdict (0.3.0 hashed the first 2048 bytes; fixed in 0.3.1).
-- Text that normalizes to nothing (digit runs, UUIDs) is hashed as typed, so
-- it still gets a cache entry instead of a judge call per request; text that
-- is only whitespace is hashed as one space, one entry for every such body.
--
-- `hash` is injected by the adapter and MUST be collision-resistant
-- (sha256 hex or better). The fingerprint keys the verdict cache and the
-- operator trust store, both of which turn a hit into a verdict without a
-- judge call, so an attacker who can forge a hash forges a verdict. CRC32
-- and djb2 are linear and let a few appended bytes hit any chosen value;
-- `djb2` below exists for the golden vectors only.
function _M.fingerprint(text, opts, hash)
  local o = { strip_digits = opts and opts.strip_digits, strip_uuid = opts and opts.strip_uuid,
              prefix_bytes = math.huge }
  local norm = _M.normalize(text, o)
  if norm == "" then
    norm = _M.normalize(text, { strip_digits = false, strip_uuid = false, prefix_bytes = math.huge })
  end
  if norm == "" and text ~= nil and tostring(text) ~= "" then norm = " " end
  if norm == "" then return "" end
  return tostring(hash(norm))
end

--- Reference hash for tests and non-OpenResty adapters (djb2, hex).
function _M.djb2(s)
  local h = 5381
  for i = 1, #s do
    h = (h * 33 + s:byte(i)) % 4294967296
  end
  return string.format("%08x", h)
end

return _M
