// Port of core/normalize.lua. Lua works on bytes and its %s / %d / %x classes
// and lower() are ASCII-only under the C locale; this file reproduces that on
// UTF-8 so the golden vectors match byte for byte.

const enc = new TextEncoder();
const dec = new TextDecoder("utf-8", { fatal: false });

export function utf8Bytes(s: string): Uint8Array {
  return enc.encode(s);
}

export function byteLength(s: string): number {
  return enc.encode(s).length;
}

/**
 * Truncate to at most n UTF-8 bytes on a code point boundary: the output
 * never exceeds n bytes and never contains a U+FFFD from a split code point
 * (the partial code point is dropped). Lua's `s:sub(1, n)` keeps the partial
 * bytes; see the README parity notes for the (logged, sampled-text-only)
 * difference. The fingerprint never truncates, so it is unaffected.
 */
export function truncateBytes(s: string, n: number): string {
  const b = enc.encode(s);
  if (b.length <= n) return s;
  let end = n;
  // step back over continuation bytes (10xxxxxx) to the start of the code
  // point that straddles the cut, then drop it
  while (end > 0 && (b[end] & 0xc0) === 0x80) end--;
  return dec.decode(b.subarray(0, end));
}

/** Lua's string.lower under the C locale: ASCII letters only. */
export function asciiLower(s: string): string {
  return s.replace(/[A-Z]+/g, (m) => m.toLowerCase());
}

export type JsonValue = null | boolean | number | string | JsonValue[] | { [k: string]: JsonValue };

// ---------------------------------------------------------------------------
// Path extraction: "messages[*].content", "prompt", "input.text"
// A last segment "**" reads every key and string below the value, whatever
// its shape: tool-call arguments are a string of JSON in OpenAI's APIs (read
// decoded) and an object in Ollama's and Anthropic's; see deepValue.
// ---------------------------------------------------------------------------

interface Seg { key: string; each: boolean; deep?: boolean }

function splitPath(path: string): Seg[] {
  const segs: Seg[] = [];
  for (const seg of path.split(".")) {
    if (seg === "") continue; // Lua's gmatch("[^%.]+") skips empty segments
    const m = /^([^[]*)\[\*\]$/.exec(seg);
    if (seg === "**") segs.push({ key: seg, each: false, deep: true });
    else if (m) segs.push({ key: m[1], each: true });
    else segs.push({ key: seg, each: false });
  }
  return segs;
}

/** Port of normalize.path_error: why `path` (a text_fields or tool_fields entry) is not one, or null. */
export function pathError(path: unknown): string | null {
  if (typeof path !== "string" || path === "") return "must be a non-empty string";
  const segs = splitPath(path);
  for (let i = 0; i < segs.length; i++) {
    if (segs[i].deep && i < segs.length - 1) return '"**" must be the last segment';
  }
  return null;
}

function isObj(v: unknown): v is { [k: string]: JsonValue } | JsonValue[] {
  return typeof v === "object" && v !== null;
}

// A leaf that is not a string is a "content parts" value: the array form of
// `messages[*].content` every current chat API accepts
// (`[{type:"text", text:"..."}, {type:"image_url", ...}]`), the Responses API's
// `input_text`, and Anthropic's `tool_result` whose `content` nests once more.
// Collect every string, every part's `text`, and recurse into `content`, to a
// bounded depth. Two parts keep their text elsewhere: an Anthropic `document`
// block under `source.data` (source type "text") or `source.content` (type
// "content"), and a Responses `file_search_call` under `results[*].text`.
// The depth leaves room for a content document inside a tool_result.
// Anything else (numbers, images) contributes nothing.
// Mirrors collect() in core/normalize.lua, including Lua's "array if [1] is
// set" test: an empty array is a table with no array part and yields nothing.
const LEAF_DEPTH = 6;
function collect(node: JsonValue | undefined, out: string[], depth: number): void {
  if (typeof node === "string") {
    out.push(node);
    return;
  }
  if (!isObj(node) || depth > LEAF_DEPTH) return;
  if (Array.isArray(node)) {
    // JSON null contributes nothing and does not end the array (Lua under
    // cjson: cjson.null is a value, ipairs goes on past it)
    for (const item of node) {
      if (item === null || item === undefined) continue;
      collect(item, out, depth + 1);
    }
    return;
  }
  if (typeof node.text === "string") out.push(node.text);
  if (node.content !== undefined && node.content !== null) collect(node.content, out, depth + 1);
  const src = node.source;
  if (isObj(src) && !Array.isArray(src)) {
    if (src.type === "text" && typeof src.data === "string") out.push(src.data);
    if (src.type === "content" && src.content !== undefined && src.content !== null) collect(src.content, out, depth + 1);
  }
  if (node.type === "file_search_call" && isObj(node.results)) collect(node.results, out, depth + 1);
}

/**
 * Port of fold() in core/normalize.lua. Go's encoding/json (Ollama's
 * /api/chat) matches an object key to a field without regard to case, and
 * folds U+017F (long s) to s and U+212A (Kelvin sign) to k: {"MESSAGES": ...}
 * reaches the model. ASCII letters only otherwise, as Lua's lower().
 */
export function fold(s: string): string {
  if (!/[A-Z\u0080-\uFFFF]/.test(s)) return s;
  return asciiLower(s).replace(/\u017F/g, "s").replace(/\u212A/g, "k");
}

// The keys of object `node` other than `key` itself that fold to `key`, in
// byte order (UTF-16 order is the same for the characters that can fold to
// a field name); undefined when there are none (nearly always).
function variants(node: { [k: string]: JsonValue }, key: string): string[] | undefined {
  const want = fold(key);
  const b = want.charCodeAt(0);
  let others: string[] | undefined;
  for (const k of Object.keys(node)) {
    if (k === key) continue;
    const c = k.charCodeAt(0);
    if ((c === b || (c >= 0x41 && c <= 0x5a && c + 32 === b) || (b === 0x73 && c === 0x17f) || (b === 0x6b && c === 0x212a))
      && fold(k) === want) (others ??= []).push(k);
  }
  return others?.sort();
}

// ---------------------------------------------------------------------------
// Bounded walks over JSON of any shape (port of the Lua ones): tool-call
// arguments ("**") and tool definitions (rule.tool_fields). The client picks
// the shape, so the walk is bounded: DEEP.nodes object keys and array items
// per extraction, and DEEP.depth levels below the path's value (cjson's
// nesting limit, which tooDeep() applies here: JSON either core decodes is
// never cut by depth). Object keys are read in UTF-8 byte order, as Lua's
// table.sort orders them. One oversized node must not starve what comes
// after it: an object with more keys than the budget has left is skipped
// whole, and an array with more items than that keeps its newest ones (the
// last), half as many as the budget has left; `capped` says so. An empty
// object or array (and null) adds nothing and is not counted. Tests lower
// the bounds.
// ---------------------------------------------------------------------------

export const DEEP = { depth: 1000, nodes: 20000 };

type Decode = (s: string) => JsonValue;

/** A "**" value's place in the output, filled after the walk (settle). */
interface Slot { node: JsonValue; values: string[] }

interface WalkState {
  out: (string | Slot)[];
  /** reads the value a path ends at (tool_fields); collect() otherwise */
  leaf?: (node: JsonValue, st: WalkState) => void;
  nodes: number;
  capped: boolean;
  /** json_decode, for "**" values that are a string of JSON */
  decode?: Decode;
  /** the "**" values, in document order */
  defer: Slot[];
}

function newState(decode?: Decode): WalkState {
  return { out: [], nodes: DEEP.nodes, capped: false, decode, defer: [] };
}

/** Lua string order (bytes): UTF-16 order except that a character above U+FFFF sorts after all others. */
export function byteOrder(a: string, b: string): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const x = a.charCodeAt(i);
    const y = b.charCodeAt(i);
    if (x !== y) {
      const xs = x >= 0xd800 && x <= 0xdfff;
      const ys = y >= 0xd800 && y <= 0xdfff;
      if (xs !== ys) return xs ? 1 : -1;
      return x - y;
    }
  }
  return a.length - b.length;
}

const SURROGATE = /[\ud800-\udfff]/;

// Port of keys_of: the keys of object `node` in byte order, counted against
// the node budget; undefined (and nothing spent) when there are more than it
// has left. Without a character above U+FFFF, UTF-16 order is byte order and
// the engine's own sort (no comparator) is the cheap one.
function keysOf(node: { [k: string]: JsonValue }, st: WalkState): string[] | undefined {
  // Object.keys is linear in the object, as JSON.parse was; the sort is what the bound caps
  const keys = Object.keys(node);
  if (keys.length > st.nodes) {
    st.capped = true;
    return undefined;
  }
  st.nodes -= keys.length;
  return keys.some((k) => SURROGATE.test(k)) ? keys.sort(byteOrder) : keys.sort();
}

// Port of first_item: the index of the first item of array `node` the walk
// reads, counted against the node budget: 0 when all of them fit; else the
// newest items (the last ones), half as many as the budget has left.
function firstItem(node: JsonValue[], st: WalkState): number {
  const n = node.length;
  if (n <= st.nodes) {
    st.nodes -= n;
    return 0;
  }
  st.capped = true;
  const k = Math.floor(st.nodes / 2);
  st.nodes -= k;
  return n - k;
}

function take(st: WalkState, s: string): void {
  if (s !== "") st.out.push(s);
}

function hasKey(o: object): boolean {
  for (const _ in o) return true;
  return false;
}

/** Port of SCHEMA_TYPES: the values of a JSON Schema `type` a tool definition's walk leaves out. */
export const SCHEMA_TYPES: ReadonlySet<string> = new Set(["string", "number", "integer", "boolean", "object", "array", "null"]);

function schemaType(v: JsonValue | undefined): boolean {
  if (typeof v === "string") return SCHEMA_TYPES.has(v);
  if (!Array.isArray(v) || v.length === 0) return false;
  return v.every((t) => typeof t === "string" && SCHEMA_TYPES.has(t));
}

// Port of every_string: every key and string value below `node`, keys in
// byte order; with `schema` (tool definitions) a `type` whose value is a JSON
// Schema type name is left out, key and value.
function everyString(node: JsonValue | undefined, st: WalkState, depth: number, schema = false): void {
  if (typeof node === "string") return take(st, node);
  if (!isObj(node)) return;
  if (Array.isArray(node) ? node.length === 0 : !hasKey(node)) return;
  if (depth > DEEP.depth) {
    st.capped = true;
    return;
  }
  if (Array.isArray(node)) {
    for (let i = firstItem(node, st); i < node.length; i++) everyString(node[i], st, depth + 1, schema);
    return;
  }
  const keys = keysOf(node, st);
  if (!keys) return;
  for (const k of keys) {
    const v = node[k];
    if (schema && k === "type" && schemaType(v)) continue;
    take(st, k);
    everyString(v, st, depth + 1, schema);
  }
}

// Port of tool_leaf: a string whole, anything else every key and string in
// it but JSON Schema type names.
function toolLeaf(node: JsonValue, st: WalkState): void {
  if (typeof node === "string") return take(st, node);
  everyString(node, st, 1, true);
}

// Port of deep_value: the value a "**" path ends at; a string holding a JSON
// object or array is read decoded, anything else (and JSON the decoder
// refuses, cjson's depth limit included) as it is.
function deepValue(node: JsonValue, st: WalkState): void {
  if (typeof node === "string" && st.decode && /^[ \t\n\r]*[[{]/.test(node) && !tooDeep(node)) {
    let v: JsonValue | undefined;
    try {
      v = st.decode(loneSurrogates(node));
    } catch {
      v = undefined;
    }
    if (isObj(v)) return everyString(v, st, 1);
  }
  everyString(node, st, 1);
}

// ---------------------------------------------------------------------------
// Field paths walked together (port of the Lua walk): the paths that go
// through the same key go through it once, and an array one of them goes
// through item by item is read item by item for all of them, so the values
// come out in document order (a message's content and its tool calls
// together). Each "**" value is read after the walk, newest first, so the
// node budget goes to the most recent tool calls.
// ---------------------------------------------------------------------------

/** One path from a node: its segments and the next one's index; `depth`: collect()'s, for a path read item by item. */
interface Cursor { segs: Seg[]; i: number; depth?: number }
interface Group { key: string; cursors: Cursor[] }

function cursorsOf(fields: string[] | undefined): Cursor[] {
  return (fields ?? []).map((f) => ({ segs: splitPath(f), i: 0 }));
}

// Port of through: `child`, the value under one key (or the node itself for
// "[*]"), for the cursors going through that key. Lua ipairs over a cjson
// array: null is a value, skipped, not the end.
function through(child: JsonValue | undefined, cursors: Cursor[], st: WalkState): void {
  if (child === undefined || child === null) return;
  const whole: Cursor[] = [];
  const items: Cursor[] = [];
  const array = Array.isArray(child) && child.length > 0;
  for (const c of cursors) {
    if (c.segs[c.i].each) {
      if (isObj(child)) items.push({ segs: c.segs, i: c.i + 1 });
    } else if (array && c.i === c.segs.length - 1 && !st.leaf) {
      // a path that ends at the array: collect() reads it item by item, one level down
      items.push({ segs: c.segs, i: c.i + 1, depth: 2 });
    } else {
      whole.push({ segs: c.segs, i: c.i + 1 });
    }
  }
  if (whole.length > 0) walk(child, whole, st);
  if (items.length > 0 && Array.isArray(child)) {
    for (const item of child) {
      if (item === null || item === undefined) continue;
      walk(item, items, st);
    }
  }
}

// Port of walk: a path that ends here, a "**" here, or the cursors that go on
// through one key, in the order the first cursor for each comes. A key is
// matched the way fold() says, and every key that folds to it is read: the
// exact key first, the others in byte order.
function walk(node: JsonValue | undefined, cursors: Cursor[], st: WalkState): void {
  if (node === undefined || node === null) return;
  const ops: (Cursor | Group)[] = [];
  const groups = new Map<string, Group>();
  for (const c of cursors) {
    const seg = c.segs[c.i];
    if (seg === undefined || seg.deep) {
      ops.push(c);
    } else {
      let g = groups.get(seg.key);
      if (!g) {
        g = { key: seg.key, cursors: [] };
        groups.set(seg.key, g);
        ops.push(g);
      }
      g.cursors.push(c);
    }
  }
  for (const op of ops) {
    if ("segs" in op) {
      if (op.segs[op.i] === undefined) {
        if (st.leaf) st.leaf(node, st);
        else collect(node, st.out as string[], op.depth ?? 1);
      } else {
        const slot: Slot = { node, values: [] };
        st.out.push(slot);
        st.defer.push(slot);
      }
    } else if (op.key === "") {
      through(node, op.cursors, st);
    } else if (isObj(node) && !Array.isArray(node)) {
      through(node[op.key], op.cursors, st);
      for (const k of variants(node, op.key) ?? []) through(node[k], op.cursors, st);
    }
  }
}

// Port of settle: reads the "**" values, newest first, and returns every value in document order.
function settle(st: WalkState): string[] {
  for (let k = st.defer.length - 1; k >= 0; k--) {
    const slot = st.defer[k];
    const saved = st.out;
    st.out = [];
    deepValue(slot.node, st);
    slot.values = st.out as string[];
    st.out = saved;
  }
  if (st.defer.length === 0) return st.out as string[];
  const out: string[] = [];
  for (const v of st.out) {
    if (typeof v === "string") out.push(v);
    else for (const s of v.values) out.push(s);
  }
  return out;
}

export function extractJson(decoded: JsonValue, fields: string[], jsonDecode?: Decode): string {
  return extractJsonValues(decoded, fields, jsonDecode).join("\n");
}

/** The strings extractJson joins, in document order (newest last), for window(). */
export function extractJsonValues(decoded: JsonValue, fields: string[], jsonDecode?: Decode): string[] {
  return extractJsonState(decoded, fields, jsonDecode).out;
}

function extractJsonState(decoded: JsonValue, fields: string[], jsonDecode?: Decode): { out: string[]; capped: boolean } {
  const st = newState(jsonDecode);
  walk(decoded, cursorsOf(fields), st);
  return { out: settle(st), capped: st.capped };
}

/**
 * Port of extract_tools: tool definitions in a decoded JSON body
 * (rule.tool_fields), what the model reads of the tools it may call and of
 * the schema its answer must follow: every key and string but JSON Schema
 * type names. Returns the strings (in order), and true when a bound (depth,
 * nodes) left something out.
 */
export function extractTools(decoded: JsonValue | undefined, fields: string[] | undefined, jsonDecode?: Decode): [string[], boolean] {
  const st = newState(jsonDecode);
  st.leaf = toolLeaf;
  if (isObj(decoded)) walk(decoded, cursorsOf(fields), st);
  return [settle(st), st.capped];
}

// Port of tool_results() in core/normalize.lua. Tool results in the chat shapes
// gateways see:
//   OpenAI Chat Completions  messages[*] with role "tool" (or legacy "function"): content
//   Anthropic Messages       messages[*].content[*] with type "tool_result": content
//   OpenAI Responses         input[*] with a type ending in "_call_output"
//                            (function_call_output, custom_tool_call_output,
//                            local_shell_call_output, ...) or "mcp_call": output;
//                            "file_search_call": results[*].text
const responsesResult = (t: unknown) => typeof t === "string" && (t.endsWith("_call_output") || t === "mcp_call");

function toolResults(decoded: JsonValue, out: string[]): void {
  if (!isObj(decoded) || Array.isArray(decoded)) return;
  const msgs = decoded.messages;
  if (Array.isArray(msgs)) {
    for (const m of msgs) {
      if (!isObj(m) || Array.isArray(m)) continue;
      if (m.role === "tool" || m.role === "function") {
        collect(m.content, out, 1);
      } else if (Array.isArray(m.content)) {
        for (const block of m.content) {
          if (isObj(block) && !Array.isArray(block) && block.type === "tool_result") collect(block.content, out, 1);
        }
      }
    }
  }
  const input = decoded.input;
  if (Array.isArray(input)) {
    for (const item of input) {
      if (!isObj(item) || Array.isArray(item)) continue;
      if (responsesResult(item.type)) collect(item.output, out, 1);
      else if (item.type === "file_search_call" && isObj(item.results)) collect(item.results, out, 1);
    }
  }
}

/**
 * Port of extract_untrusted: retrieved content in a decoded JSON body, tool
 * results (unless `spec.tool_results` is false) and the values of
 * `spec.fields`, in that order. Returns the values (newest last).
 */
export function extractUntrustedValues(
  decoded: JsonValue | undefined, spec: { tool_results?: boolean; fields?: string[] }, jsonDecode?: Decode,
): string[] {
  const st = newState(jsonDecode);
  if (!isObj(decoded)) return [];
  if (spec.tool_results !== false) toolResults(decoded, st.out as string[]);
  walk(decoded, cursorsOf(spec.fields), st);
  return settle(st);
}

export type ExtractKind = "json" | "scan" | "invalid" | "text" | "form" | "multipart" | "binary" | "none";

/** Lua's tonumber(h, 16) + string.char: bytes, so %C3%BC is two bytes not one char. */
function formDecode(v: string): string {
  const bytes: number[] = [];
  const s = v.replace(/\+/g, " ");
  const b = enc.encode(s);
  for (let i = 0; i < b.length; i++) {
    if (b[i] === 0x25 && i + 2 < b.length) {
      const hex = String.fromCharCode(b[i + 1], b[i + 2]);
      if (/^[0-9a-fA-F]{2}$/.test(hex)) {
        bytes.push(parseInt(hex, 16));
        i += 2;
        continue;
      }
    }
    bytes.push(b[i]);
  }
  return dec.decode(new Uint8Array(bytes));
}

// ---------------------------------------------------------------------------
// Format detection (port of normalize.extract in core/normalize.lua): the
// body decides, the Content-Type is a hint. JSON when it parses as JSON, form
// or multipart when declared (or form-shaped with no header), text when it
// reads as text, "binary" otherwise.
// ---------------------------------------------------------------------------

/** Lua is_text: no NUL, control bytes other than \t \n \r under 1% of the bytes. */
export function isText(s: string): boolean {
  if (s.includes("\0")) return false;
  const ctl = (s.match(/[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]/g) ?? []).length;
  return ctl * 100 <= byteLength(s);
}

// Port of form_values(): the value of every `name=value` pair, in each
// `&`-separated piece the text after the first `=` that follows a non-empty
// name (leading `=` are skipped). The same values as the regex
// /([^&=]+)=([^&]*)/g, which backtracks quadratically on a long run without
// `&` or `=`; this is linear.
function formValues(body: string, out: string[]): void {
  let i = 0;
  while (i < body.length) {
    let amp = body.indexOf("&", i);
    if (amp === -1) amp = body.length;
    const piece = body.slice(i, amp);
    let name = 0;
    while (name < piece.length && piece[name] === "=") name++;
    const eq = name < piece.length ? piece.indexOf("=", name) : -1;
    if (eq !== -1) out.push(formDecode(piece.slice(eq + 1)));
    i = amp + 1;
  }
}

const MAX_PARTS = 100;
function multipartValues(body: string, contentType: string, out: string[]): void {
  const bm = /boundary="([^"]+)"/i.exec(contentType) ?? /boundary=([^;\s,]+)/i.exec(contentType);
  if (!bm) return;
  const delim = "--" + bm[1];
  let pos = body.indexOf(delim);
  let parts = 0;
  while (pos !== -1 && parts < MAX_PARTS) {
    const after = pos + delim.length;
    if (body.slice(after, after + 2) === "--") break; // closing delimiter
    const next = body.indexOf(delim, after);
    let part = body.slice(after, next === -1 ? body.length : next);
    part = part.replace(/^\r?\n/, "").replace(/\r?\n$/, "");
    const hm = /\r?\n\r?\n/.exec(part);
    if (hm) {
      const head = asciiLower(part.slice(0, hm.index));
      const value = part.slice(hm.index + hm[0].length);
      const hasFile = /filename\*?=/.test(head);
      const pct = /content-type:[ \t\n\v\f\r]*([^\r\n;]+)/.exec(head)?.[1] ?? "";
      if ((!hasFile || pct.startsWith("text/") || pct.includes("json")) && isText(value)) out.push(value);
    }
    parts++;
    pos = next;
  }
}

/**
 * Port of lone_surrogates(): `s` with every \uD800-\uDFFF escape that is not
 * half of a valid pair written as \uFFFD, before decoding. cjson refuses a
 * lone surrogate and JSON.parse keeps it; both cores read U+FFFD, as Go does.
 */
export function loneSurrogates(s: string): string {
  if (!/\\u[dD][89a-fA-F]/.test(s)) return s;
  let out = "";
  let last = 0;
  let i = 0;
  for (;;) {
    const j = s.indexOf("\\", i);
    if (j === -1) break;
    i = j + 2; // any other escape is two characters
    if (s[j + 1] !== "u") continue;
    const hex = /^[0-9a-fA-F]{4}/.exec(s.slice(j + 2, j + 6))?.[0];
    if (!hex) continue;
    const cp = parseInt(hex, 16);
    i = j + 6;
    if (cp < 0xd800 || cp > 0xdfff) continue;
    const lo = cp <= 0xdbff ? /^\\u([0-9a-fA-F]{4})/.exec(s.slice(i, i + 6))?.[1] : undefined;
    const lcp = lo ? parseInt(lo, 16) : NaN;
    if (lcp >= 0xdc00 && lcp <= 0xdfff) {
      i += 6;
      continue;
    }
    out += s.slice(last, j) + "\\ufffd";
    last = i;
  }
  return last === 0 ? s : out + s.slice(last);
}

// cjson, the Lua adapters' decoder, refuses JSON nested deeper than 1000;
// JSON.parse does not. A body that deep is read by the scanner in both cores.
const MAX_JSON_DEPTH = 1000;
function tooDeep(s: string): boolean {
  if (s.length < 2 * (MAX_JSON_DEPTH + 1)) return false;
  let depth = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 0x22) {
      // to the closing quote, past escapes
      for (i++; i < s.length; i++) {
        const d = s.charCodeAt(i);
        if (d === 0x5c) i++;
        else if (d === 0x22) break;
      }
    } else if (c === 0x5b || c === 0x7b) {
      if (++depth > MAX_JSON_DEPTH) return true;
    } else if (c === 0x5d || c === 0x7d) {
      depth--;
    }
  }
  return false;
}

/**
 * Extract text from a raw body. Returns the text (values joined with "\n"),
 * the kind, the values in order (newest last) for window(), the decoded
 * JSON value when the kind is "json", and true when a "**" walk hit a bound
 * and left something out.
 */
export function extract(
  body: string | undefined | null,
  contentType: string | undefined | null,
  fields: string[],
  jsonDecode: (s: string) => JsonValue = (s) => JSON.parse(s) as JsonValue,
): [string, ExtractKind, string[], JsonValue?, boolean?] {
  if (typeof body !== "string" || body === "") return ["", "none", []];
  const rawCt = typeof contentType === "string" ? contentType : "";
  const ct = asciiLower(rawCt);
  // A UTF-8 BOM is not JSON, but Python's json.loads on bytes and Express's
  // body-parser skip it: judge what the backend reads.
  if (body.startsWith("﻿")) body = body.slice(1);
  // declared JSON: a JSON media type (application/json, text/json,
  // application/*+json), not "json" in a parameter such as a multipart
  // boundary or "text/plain; profile=json"
  const declaredJson = ct.split(";")[0].includes("json");
  const first = /^[ \t\n\v\f\r]*([\s\S])/.exec(body)?.[1];
  if (first === "{" || first === "[" || declaredJson) {
    let decoded: JsonValue | undefined;
    let ok = true;
    try {
      decoded = jsonDecode(loneSurrogates(body));
    } catch {
      ok = false;
    }
    if (ok && isObj(decoded) && tooDeep(body)) ok = false;
    if (ok && isObj(decoded)) {
      const st = extractJsonState(decoded as JsonValue, fields, jsonDecode);
      return [st.out.join("\n"), "json", st.out, decoded as JsonValue, st.capped];
    }
    if (declaredJson) {
      // a JSON scalar has no text fields
      if (ok && decoded !== undefined) return ["", "none", []];
      // The decoder refused it; the backend's parser may not (cjson refuses
      // nesting past 1000 and bytes after the value, Go and Node do not).
      // The text fields' string values, read by the tolerant scanner past
      // max_body_bytes uses, are judged; a body with none is unjudgeable,
      // never "no text".
      const out = scanStrings(body, fieldKeys(fields), []);
      if (out.length === 0) return ["", "invalid", []];
      return [out.join("\n"), "scan", out];
    }
  }
  const out: string[] = [];
  if (ct.includes("application/x-www-form-urlencoded") || (ct === "" && /^[A-Za-z0-9._~%+[\]-]+=[^ \t\n\v\f\r]*$/.test(body))) {
    formValues(body, out);
    return [out.join("\n"), "form", out];
  }
  if (ct.includes("multipart/form-data")) {
    multipartValues(body, rawCt, out);
    return [out.join("\n"), "multipart", out];
  }
  if (isText(body)) return [body, "text", [body]];
  return ["", "binary", []];
}

// ---------------------------------------------------------------------------
// Partial bodies: tolerant scan of JSON string values (port of scan_strings)
// ---------------------------------------------------------------------------

const ESC: Record<string, string> = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" };

function readString(s: string, i: number): [string, number] {
  let buf = "";
  const n = s.length;
  while (i < n) {
    let j = i;
    while (j < n && s[j] !== '"' && s[j] !== "\\") j++;
    if (j >= n) return [buf + s.slice(i), n];
    buf += s.slice(i, j);
    if (s[j] === '"') return [buf, j + 1];
    const e = s[j + 1];
    if (e === "u") {
      const hex = /^[0-9a-fA-F]{4}/.exec(s.slice(j + 2, j + 6))?.[0];
      if (!hex) return [buf, n];
      let cp = parseInt(hex, 16);
      i = j + 6;
      if (cp >= 0xd800 && cp <= 0xdbff) {
        const lo = /^\\u([0-9a-fA-F]{4})/.exec(s.slice(i, i + 6))?.[1];
        const lcp = lo ? parseInt(lo, 16) : NaN;
        if (lcp >= 0xdc00 && lcp <= 0xdfff) {
          cp = 0x10000 + (cp - 0xd800) * 0x400 + (lcp - 0xdc00);
          i += 6;
        }
      }
      // a lone surrogate is U+FFFD, as in loneSurrogates()
      if (cp >= 0xd800 && cp <= 0xdfff) cp = 0xfffd;
      buf += String.fromCodePoint(cp);
    } else if (e === undefined) {
      return [buf, n];
    } else {
      buf += ESC[e] ?? e;
      i = j + 2;
    }
  }
  return [buf, n];
}

/** The last key of each text-field path, folded: "messages[*].content" -> "content". */
export function fieldKeys(fields: string[] | undefined): Set<string> {
  const keys = new Set<string>();
  // Lua: f:match("([^%.%[%]%*]+)[%[%]%*]*$") -- the last run of name
  // characters before any trailing "[", "]" or "*". A linear scan, not a
  // regex: the unanchored pattern backtracks quadratically on long input.
  const special = (c: string) => c === "." || c === "[" || c === "]" || c === "*";
  for (let f of fields ?? []) {
    // "arguments.**": the strings under "arguments"
    if (f.endsWith(".**")) f = f.slice(0, -3);
    let end = f.length;
    while (end > 0 && (f[end - 1] === "[" || f[end - 1] === "]" || f[end - 1] === "*")) end--;
    let start = end;
    while (start > 0 && !special(f[start - 1])) start--;
    if (end > start) keys.add(fold(f.slice(start, end)));
  }
  // content parts carry their text under "text"
  if (keys.has("content")) keys.add("text");
  return keys;
}

/**
 * Collect the string values of `keys` (from fieldKeys) from possibly
 * truncated JSON. Keys match the way walk() matches them: folded.
 */
export function scanStrings(s: string, keys: Set<string>, out: string[]): string[] {
  // key characters: ASCII word characters, U+017F and U+212A
  const re = /"([A-Za-z0-9_\-\u017F\u212A]+)"[ \t\n\v\f\r]*:[ \t\n\v\f\r]*"/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(s)) !== null) {
    const [value, next] = readString(s, m.index + m[0].length);
    if (keys.has(fold(m[1])) && value !== "") out.push(value);
    re.lastIndex = next;
  }
  return out;
}

// The first index at or after `i` of a character other than JSON white space, or -1.
function nonSpace(s: string, i: number): number {
  for (; i < s.length; i++) {
    const c = s[i];
    if (c !== " " && c !== "\t" && c !== "\n" && c !== "\r") return i;
  }
  return -1;
}

// Port of type_names: the index after a JSON Schema type name, or a list of
// them, that starts at or after `i`; undefined for anything else.
function typeNames(s: string, i: number): number | undefined {
  const q = nonSpace(s, i);
  if (q === -1) return undefined;
  if (s[q] === '"') {
    const [v, after] = readString(s, q + 1);
    return SCHEMA_TYPES.has(v) ? after : undefined;
  }
  if (s[q] !== "[") return undefined;
  let p = q + 1;
  let any = false;
  for (;;) {
    p = nonSpace(s, p);
    if (p === -1) return undefined;
    if (s[p] === "]") return any ? p + 1 : undefined;
    if (s[p] !== '"') return undefined;
    const [v, after] = readString(s, p + 1);
    if (!SCHEMA_TYPES.has(v)) return undefined;
    any = true;
    p = nonSpace(s, after);
    if (p === -1) return undefined;
    if (s[p] === ",") p++;
    else if (s[p] !== "]") return undefined;
  }
}

// Port of scan_value: every key and string of the JSON value that starts at
// `i` (a `{` or `[`), to its end or the end of `s`; a "type" key whose value
// is a JSON Schema type name is left out with it. Returns the index after it.
function scanValue(s: string, i: number, out: string[]): number {
  let depth = 0;
  const re = /[{}[\]"]/g;
  for (;;) {
    re.lastIndex = i;
    const m = re.exec(s);
    if (!m) return s.length;
    const j = m.index;
    const c = s[j];
    if (c === '"') {
      const [v, next] = readString(s, j + 1);
      const k = nonSpace(s, next);
      const skip = v === "type" && k !== -1 && s[k] === ":" ? typeNames(s, k + 1) : undefined;
      if (skip !== undefined) {
        i = skip;
      } else {
        if (v !== "") out.push(v);
        i = next;
      }
    } else if (c === "{" || c === "[") {
      depth++;
      i = j + 1;
    } else {
      depth--;
      i = j + 1;
      if (depth <= 0) return i;
    }
  }
}

/**
 * Port of scan_tools: the tool definitions (rule.tool_fields) in possibly
 * truncated JSON, past max_body_bytes: every key and string of the value of
 * each key that folds to a tool_fields path's last key, JSON Schema type
 * names left out, in the order they come.
 */
export function scanTools(s: string, keys: Set<string>, out: string[]): string[] {
  const re = /"([A-Za-z0-9_\-ſK]+)"[ \t\n\v\f\r]*:[ \t\n\v\f\r]*/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(s)) !== null) {
    const at = m.index + m[0].length;
    if (!keys.has(fold(m[1]))) continue;
    if (s[at] === '"') {
      const [v, next] = readString(s, at + 1);
      if (v !== "") out.push(v);
      re.lastIndex = next;
    } else if (s[at] === "{" || s[at] === "[") {
      re.lastIndex = scanValue(s, at, out);
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Judging window (port of normalize.window). Byte arithmetic on UTF-8, cuts
// at code point boundaries, so the output matches Lua byte for byte.
// ---------------------------------------------------------------------------

const isCont = (b: Uint8Array, i: number) => i < b.length && (b[i] & 0xc0) === 0x80;

/** `s` cut to at most `n` bytes at a code point boundary, from the front. */
export function head(s: string, n: number): string {
  if (n <= 0) return "";
  const b = enc.encode(s);
  if (b.length <= n) return s;
  let e = n;
  while (e > 0 && isCont(b, e)) e--;
  return dec.decode(b.subarray(0, e));
}

/** `s` cut to at most `n` bytes at a code point boundary, from the back. */
export function tail(s: string, n: number): string {
  if (n <= 0) return "";
  const b = enc.encode(s);
  if (b.length <= n) return s;
  let st = b.length - n;
  while (st < b.length && isCont(b, st)) st++;
  return dec.decode(b.subarray(st));
}

export const HIT_CONTEXT = 1024;

/**
 * Port of normalize.chunks: consecutive pieces of at most `budget` UTF-8
 * bytes covering all of `text`; a cut prefers the last newline in the second
 * half of a piece (dropped) and never splits a code point. Returns the pieces
 * and each one's 1-based byte offset, as in Lua.
 */
export function chunks(text: string, budget: number): [string[], number[]] {
  const b = enc.encode(text);
  const n = b.length;
  const half = Math.floor(budget / 2);
  const pieces: string[] = [];
  const starts: number[] = [];
  let i = 1;
  while (i <= n) {
    if (n - i + 1 <= budget) {
      pieces.push(dec.decode(b.subarray(i - 1)));
      starts.push(i);
      break;
    }
    let e = i + budget - 1;
    let next: number | undefined;
    for (let j = e; j >= i + half + 1; j--) {
      if (b[j - 1] === 10) {
        e = j - 1;
        next = j + 1;
        break;
      }
    }
    if (next === undefined) {
      // back to a character boundary, at most 3 bytes (valid UTF-8); a
      // longer run of continuation bytes is cut where it is, as in Lua
      const cut = e;
      for (let k = 0; k < 3 && e > i && isCont(b, e); k++) e--;
      if (e > i && isCont(b, e)) e = cut;
      next = e + 1;
    }
    pieces.push(dec.decode(b.subarray(i - 1, e)));
    starts.push(i);
    i = next;
  }
  return [pieces, starts];
}

/**
 * @param from,to 1-based inclusive byte span of an always_suspect hit, or undefined
 * @returns the text to judge, and true when it was cut
 */
export function window(text: string, values: string[], budget: number, from?: number, to?: number): [string, boolean] {
  const tb = enc.encode(text);
  if (tb.length <= budget) return [text, false];
  const out: string[] = [];
  let rem = budget;
  if (from !== undefined && to !== undefined) {
    const half = Math.floor(budget / 2);
    const ctxb = Math.max(0, Math.min(HIT_CONTEXT, Math.floor((half - (to - from + 1)) / 2)));
    let a = Math.max(1, from - ctxb);
    while (a > 1 && isCont(tb, a - 1)) a--;
    const piece = head(dec.decode(tb.subarray(a - 1)), Math.min(Math.min(to + ctxb, tb.length) - a + 1, half));
    out.push(piece);
    rem = rem - byteLength(piece) - 1;
  }
  const chosen = new Map<number, string>();
  for (let i = values.length - 1; i >= 0; i--) {
    if (rem <= 0) break;
    const v = values[i];
    const vl = byteLength(v);
    if (vl + 1 <= rem) {
      chosen.set(i, v);
      rem = rem - vl - 1;
    } else {
      const h = head(v, Math.floor((rem - 1) / 2));
      chosen.set(i, h + "\n" + tail(v, rem - 1 - byteLength(h) - 1));
      rem = 0;
    }
  }
  for (let i = 0; i < values.length; i++) {
    const c = chosen.get(i);
    if (c !== undefined) out.push(c);
  }
  return [out.join("\n"), true];
}

// ---------------------------------------------------------------------------
// Well-formed text for the judge (port of valid_utf8). A string decoded from
// bytes with TextDecoder is already well formed, invalid UTF-8 replaced the
// way valid_utf8 does in Lua; a lone surrogate can still come from a caller's
// string, and a provider would serialise it as "\ud800", which a strict judge
// server refuses (an L2 error, which passes the request).
// ---------------------------------------------------------------------------

/** `s` with every lone surrogate replaced by U+FFFD (String.prototype.toWellFormed). */
export function wellFormed(s: string): string {
  return s.replace(/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g, "\uFFFD");
}

// ---------------------------------------------------------------------------
// Normalization
// ---------------------------------------------------------------------------

export interface NormalizeOpts {
  prefix_bytes?: number;
  strip_digits?: boolean;
  strip_uuid?: boolean;
}

const DEFAULTS: Required<NormalizeOpts> = { prefix_bytes: 2048, strip_digits: true, strip_uuid: true };

// Lua %s: space, \t \n \v \f \r (C isspace). Not Unicode spaces.
const LUA_SPACE = /[ \t\n\v\f\r]+/g;

export function normalize(text: string | null | undefined, opts?: NormalizeOpts | null): string {
  const o = opts ?? DEFAULTS;
  let s = asciiLower(String(text ?? ""));
  if (o.strip_uuid !== false) {
    s = s.replace(/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/g, "");
  }
  if (o.strip_digits !== false) {
    s = s.replace(/[0-9]{4,}/g, "");
  }
  s = s.replace(LUA_SPACE, " ");
  s = s.replace(/^ /, "").replace(/ $/, "");
  const n = o.prefix_bytes ?? DEFAULTS.prefix_bytes;
  if (byteLength(s) > n) s = truncateBytes(s, n);
  return s;
}

/**
 * Fingerprint = hash(normalize(text)) over the WHOLE normalized text.
 * `opts.prefix_bytes` is deliberately ignored here: a fingerprint that only
 * covers a prefix lets any text that shares the prefix reuse a cached or
 * trusted verdict (0.3.0 hashed the first 2048 bytes; fixed in 0.3.1).
 * Text that normalizes to nothing (digit runs, UUIDs) is hashed as typed, so
 * it still gets a cache entry instead of a judge call per request.
 *
 * `hash` is injected by the adapter and MUST be collision-resistant
 * (sha256 hex or better). The fingerprint keys the verdict cache and the
 * operator trust store, both of which turn a hit into a verdict without a
 * judge call, so an attacker who can forge a hash forges a verdict. CRC32
 * and djb2 are linear and let a few appended bytes hit any chosen value;
 * `djb2` below exists for the golden vectors only.
 */
export function fingerprint(
  text: string | null | undefined,
  opts: NormalizeOpts | null | undefined,
  hash: (s: string) => string,
): string {
  const o: NormalizeOpts = { strip_digits: opts?.strip_digits, strip_uuid: opts?.strip_uuid, prefix_bytes: Infinity };
  let norm = normalize(text, o);
  if (norm === "") norm = normalize(text, { strip_digits: false, strip_uuid: false, prefix_bytes: Infinity });
  // whitespace-only text: one fingerprint for all of it, never none (Lua: tostring(text) ~= "")
  if (norm === "" && text !== null && text !== undefined && String(text) !== "") norm = " ";
  if (norm === "") return "";
  return String(hash(norm));
}

/** Reference hash (djb2 over UTF-8 bytes, 8 hex digits), same as normalize.djb2 in Lua. */
export function djb2(s: string): string {
  let h = 5381;
  for (const b of enc.encode(s)) {
    h = (Math.imul(h, 33) + b) >>> 0;
  }
  return h.toString(16).padStart(8, "0");
}
