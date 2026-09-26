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
 * `s` as Lua and PCRE without UTF see it: one character (U+0000..U+00FF) per
 * UTF-8 byte. ASCII comes back as it is.
 */
export function byteString(s: string): string {
  if (!/[^\x00-\x7f]/.test(s)) return s;
  const b = enc.encode(s);
  let out = "";
  for (let i = 0; i < b.length; i += 8192) out += String.fromCharCode(...b.subarray(i, i + 8192));
  return out;
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
/** A field path's segments; `whole` when its value is read whole (WHOLE_FIELDS), `keyed` when an object value is read by its keys too (KEY_FIELDS). */
type Segs = Seg[] & { whole?: boolean; keyed?: boolean };

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

// Port of read_whole() in core/normalize.lua. Values the model reads whole: a
// Gemini function response, a Cohere document (WHOLE_FIELDS below). Every key
// and string below the value, object keys in byte order
// (as Lua sorts them), arrays in order, empty strings left out. Bounded:
// WHOLE_DEPTH levels below the value (cjson's nesting limit), and sorting:
// one extraction sorts WHOLE_SORT keys in all, and an object with more keys
// than it has left is read in the object's own order instead (all of the
// text, in an order the two cores do not share).
const WHOLE_DEPTH = 1000;
const WHOLE_SORT = 20000;
// keys one extraction may still sort; extractJsonValues and
// extractUntrustedValues reset it (extraction is synchronous)
let sortLeft = WHOLE_SORT;

// Port of object_keys() in core/normalize.lua: the keys of object `node`, in
// byte order while the extraction's sort budget lasts, in the object's own
// order past it.
function objectKeys(node: { [k: string]: JsonValue }): string[] {
  const keys = Object.keys(node);
  if (keys.length <= sortLeft) {
    sortLeft -= keys.length;
    keys.sort(byteOrder);
  }
  return keys;
}

function readWhole(node: JsonValue | undefined, out: string[], depth: number): void {
  if (typeof node === "string") {
    if (node !== "") out.push(node);
    return;
  }
  if (!isObj(node) || depth > WHOLE_DEPTH) return;
  if (Array.isArray(node)) {
    for (const v of node) readWhole(v, out, depth + 1);
    return;
  }
  for (const k of objectKeys(node)) {
    if (k !== "") out.push(k);
    readWhole(node[k], out, depth + 1);
  }
}

// A Gemini part's function result: `functionResponse`, or `function_response`
// as the REST API also takes it.
function functionResponses(part: { [k: string]: JsonValue }, out: string[]): void {
  for (const k of ["functionResponse", "function_response"]) {
    const fr = part[k];
    if (isObj(fr) && !Array.isArray(fr) && fr.response !== undefined) readWhole(fr.response, out, 1);
  }
}

// A leaf that is not a string is a "content parts" value: the array form of
// `messages[*].content` every current chat API accepts
// (`[{type:"text", text:"..."}, {type:"image_url", ...}]`), the Responses API's
// `input_text`, and Anthropic's `tool_result` whose `content` nests once more.
// Collect every string, every part's `text`, and recurse into `content`, to a
// bounded depth. Some parts keep their text elsewhere: an Anthropic `document`
// block under `source.data` (source type "text") or `source.content` (type
// "content"), a Responses `file_search_call` under `results[*].text`, a
// Gemini part's function result under `functionResponse.response` and a
// Cohere v2 `document` part (a tool result's) under `document`; the last two
// are read whole (readWhole).
// The depth leaves room for a content document inside a tool_result.
// Anything else (images, null) contributes nothing. A number contributes no
// text either, but it is noted (`st.tokenIds`, when the caller passes a walk
// state): a prompt given as token ids reaches the model as the text they
// decode to, which L1 never sees (see the Lua original).
// Mirrors collect() in core/normalize.lua, including Lua's "array if [1] is
// set" test: an empty array is a table with no array part and yields nothing.
const LEAF_DEPTH = 6;
function collect(node: JsonValue | undefined, out: string[], depth: number, st?: WalkState): void {
  if (typeof node === "string") {
    out.push(node);
    return;
  }
  if (typeof node === "number") {
    if (st && depth <= LEAF_DEPTH) st.tokenIds = true;
    return;
  }
  if (!isObj(node) || depth > LEAF_DEPTH) return;
  if (Array.isArray(node)) {
    // JSON null contributes nothing and does not end the array (Lua under
    // cjson: cjson.null is a value, ipairs goes on past it)
    for (const item of node) {
      if (item === null || item === undefined) continue;
      collect(item, out, depth + 1, st);
    }
    return;
  }
  if (typeof node.text === "string") out.push(node.text);
  if (node.content !== undefined && node.content !== null) collect(node.content, out, depth + 1, st);
  const src = node.source;
  if (isObj(src) && !Array.isArray(src)) {
    if (src.type === "text" && typeof src.data === "string") out.push(src.data);
    if (src.type === "content" && src.content !== undefined && src.content !== null) collect(src.content, out, depth + 1, st);
  }
  if (node.type === "file_search_call" && isObj(node.results)) collect(node.results, out, depth + 1, st);
  functionResponses(node, out);
  if (node.type === "document" && node.document !== undefined) readWhole(node.document, out, 1);
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

// Lua's %s: space, \t, \n, \v, \f, \r (String.prototype.trim also strips
// Unicode spaces, which Lua keeps).
function luaSpace(c: number): boolean {
  return c === 32 || (c >= 9 && c <= 13);
}

/**
 * Port of trim() in core/normalize.lua: s without Lua's %s at either end.
 * Linear: /^[ \t\n\v\f\r]+|[ \t\n\v\f\r]+$/g tries the second branch at
 * every position of a whitespace run inside the value and scans the run to
 * its end each time, which costs its length squared.
 */
export function trim(s: string): string {
  let i = 0, j = s.length;
  while (i < j && luaSpace(s.charCodeAt(i))) i++;
  while (j > i && luaSpace(s.charCodeAt(j - 1))) j--;
  return i === 0 && j === s.length ? s : s.slice(i, j);
}

// Port of hextets(): the 16-bit groups on one side of "::", or null when a
// group is not 1 to 4 hex digits.
function hextets(part: string): number[] | null {
  if (part === "") return [];
  const out: number[] = [];
  for (const g of part.split(":")) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
    out.push(parseInt(g, 16));
  }
  return out;
}

/**
 * Port of normalize.ip_key: the key one client address is counted under
 * (IP reputation rep:<key>, subject.from = "ip"). IPv6 is aggregated to its
 * first `prefix` bits (client_ip.ipv6_prefix, 64 by default), written as
 * eight lowercase four-digit groups and "/<prefix>"; a %zone is dropped.
 * IPv4 and IPv4-mapped IPv6 are the dotted address; anything that does not
 * parse is returned as it is. The same bytes as Lua.
 */
export function ipKey<T>(ip: T, prefix?: unknown): T | string {
  if (typeof ip !== "string" || !ip.includes(":") || byteLength(ip) > 64) return ip;
  let p = Math.floor(Number(prefix ?? 64));
  if (!(p >= 1 && p <= 128)) p = 64;
  const pct = ip.indexOf("%");
  let s = pct === -1 ? ip : ip.slice(0, pct);
  let v4: [number, number] | undefined;
  const last = s.slice(s.lastIndexOf(":") + 1);
  if (last.includes(".")) {
    const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(last);
    if (!m) return ip;
    const [a, b, c, d] = [m[1], m[2], m[3], m[4]].map(Number);
    if (a > 255 || b > 255 || c > 255 || d > 255) return ip;
    v4 = [a * 256 + b, c * 256 + d];
    s = s.slice(0, s.length - last.length);
    if (!s.endsWith("::")) {
      if (!s.endsWith(":")) return ip;
      s = s.slice(0, -1);
    }
  }
  const want = v4 ? 6 : 8;
  let h: number[];
  const dc = s.indexOf("::");
  if (dc !== -1) {
    if (s.indexOf("::", dc + 1) !== -1) return ip;
    const l = hextets(s.slice(0, dc)), r = hextets(s.slice(dc + 2));
    if (!l || !r || l.length + r.length >= want) return ip;
    h = [...l, ...new Array<number>(want - l.length - r.length).fill(0), ...r];
  } else {
    const all = hextets(s);
    if (!all || all.length !== want) return ip;
    h = all;
  }
  if (v4) h.push(v4[0], v4[1]);
  if (h[0] === 0 && h[1] === 0 && h[2] === 0 && h[3] === 0 && h[4] === 0 && h[5] === 0xffff) {
    return `${h[6] >> 8}.${h[6] & 255}.${h[7] >> 8}.${h[7] & 255}`;
  }
  const out: string[] = [];
  for (let i = 0; i < 8; i++) {
    const bits = Math.max(0, Math.min(16, p - i * 16));
    const x = h[i];
    out.push((x - (x % 2 ** (16 - bits))).toString(16).padStart(4, "0"));
  }
  return out.join(":") + "/" + p;
}

// Port of first_bytes: marks in `first` the UTF-16 units a key that folds to
// `name` can start with: the folded name's first, that letter's other case,
// U+017F for s and U+212A for k.
function firstUnits(name: string, first: Set<number>): void {
  const want = fold(name);
  if (want === "") return;
  const b = want.charCodeAt(0);
  first.add(b);
  if (b >= 0x61 && b <= 0x7a) first.add(b - 32);
  if (b === 0x73) first.add(0x17f);
  if (b === 0x6b) first.add(0x212a);
}

// ---------------------------------------------------------------------------
// Bounded walks over JSON of any shape (port of the Lua ones): tool-call
// arguments ("**") and tool definitions (rule.tool_fields). The client picks
// the shape, so the walk is bounded: DEEP.nodes object keys and array items
// per extraction, and DEEP.depth levels below the path's value (cjson's
// nesting limit, which tooDeep() applies here: JSON either core decodes is
// never cut by depth). Object keys are read in UTF-8 byte order, as Lua's
// table.sort orders them. One oversized node must not starve what comes
// after it, whether its own keys and items are too many or only what is
// below them: the nodes below a node are counted (nodesBelow) up to what the
// budget has left. A node that fits is read whole; one that does not spends
// at most half of what is left: an array its newest items that fit whole
// and, with what remains, the one before them; an object its keys (skipped
// whole when they alone are more than that), then each value by the same
// rule. Counting is bounded too: past DEEP.count times DEEP.nodes nodes
// counted, a node is taken not to fit. `capped` says so. An empty object or
// array (and null) adds nothing and is not counted. Tests lower the bounds.
// ---------------------------------------------------------------------------

export const DEEP = { depth: 1000, nodes: 20000, count: 4 };

type Decode = (s: string) => JsonValue;

/** A "**" value's place in the output, filled after the walk (settle). */
interface Slot { node: JsonValue; values: string[] }

interface WalkState {
  out: (string | Slot)[];
  /** reads the value a path ends at (tool_fields); collect() otherwise */
  leaf?: (node: JsonValue, st: WalkState) => void;
  nodes: number;
  /** what nodesBelow() may still count (see counted) */
  counts: number;
  capped: boolean;
  /** json_decode, for "**" values that are a string of JSON */
  decode?: Decode;
  /** the "**" values, in document order */
  defer: Slot[];
  /** a text field holds a number: token ids (collect) */
  tokenIds?: boolean;
}

function newState(decode?: Decode): WalkState {
  return { out: [], nodes: DEEP.nodes, counts: DEEP.count * DEEP.nodes, capped: false, decode, defer: [] };
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

// Port of nodes_below: the nodes the walk spends below `node` (at `depth`), its keys
// or items and theirs; the count stops as soon as it is over `limit` and
// returns a number over it, which only says the node does not fit.
function nodesBelow(node: JsonValue | undefined, limit: number, depth: number, schema: boolean): number {
  if (!isObj(node) || depth > DEEP.depth) return 0;
  let n = 0;
  if (Array.isArray(node)) {
    n = node.length;
    if (n > limit) return n;
    for (const v of node) {
      if (isObj(v)) {
        n += nodesBelow(v, limit - n, depth + 1, schema);
        if (n > limit) return n;
      }
    }
    return n;
  }
  for (const k of Object.keys(node)) {
    n++;
    if (n > limit) return n;
    const v = node[k];
    if (isObj(v) && !(schema && k === "type" && schemaType(v))) {
      n += nodesBelow(v, limit - n, depth + 1, schema);
      if (n > limit) return n;
    }
  }
  return n;
}

// Port of counted: nodesBelow(), charged to the walk's counting allowance at what
// it counted, or limit + 1 when it stopped (the same whatever the key order);
// once the allowance is spent a table does not fit.
function counted(st: WalkState, node: JsonValue | undefined, limit: number, depth: number, schema: boolean): number {
  if (!isObj(node) || (Array.isArray(node) ? node.length === 0 : !hasKey(node)) || depth > DEEP.depth) return 0;
  if (st.counts <= 0) return limit + 1;
  const n = nodesBelow(node, limit, depth, schema);
  st.counts -= Math.min(n, limit + 1);
  return n;
}

// Port of every_string: every key and string value below `node`, keys in
// byte order; with `schema` (tool definitions) a `type` whose value is a JSON
// Schema type name is left out, key and value. `fits`: the caller counted
// this node and it fits the budget, so nothing below it is counted again.
// `last`: nothing after it in its object needs the budget, so a node over it
// may spend all of it.
function everyString(node: JsonValue | undefined, st: WalkState, depth: number, schema = false, fits = false, last = false): void {
  if (typeof node === "string") return take(st, node);
  if (!isObj(node)) return;
  if (Array.isArray(node) ? node.length === 0 : !hasKey(node)) return;
  if (depth > DEEP.depth) {
    st.capped = true;
    return;
  }
  if (!fits && counted(st, node, st.nodes, depth, schema) > st.nodes) {
    // over the budget: at most half of what is left, the rest kept for what follows
    st.capped = true;
    const keep = last ? 0 : st.nodes - Math.floor(st.nodes / 2);
    st.nodes -= keep;
    partial(node, st, depth, schema);
    st.nodes += keep;
    return;
  }
  if (Array.isArray(node)) {
    st.nodes -= node.length;
    for (const v of node) everyString(v, st, depth + 1, schema, true);
    return;
  }
  for (const k of keysOf(node, st)!) {
    const v = node[k];
    if (schema && k === "type" && schemaType(v)) continue;
    take(st, k);
    everyString(v, st, depth + 1, schema, true);
  }
}

// Port of partial: a node over the budget (st.nodes, its share), read as far
// as it goes. An array: its newest items that fit whole, walking back from
// the last, and the one before them with what is left. An object: its keys,
// unless there are more than the budget has left, then each value as
// everyString reads one; the last table among them keeps nothing back for
// the strings and scalars after it, which cost nothing.
function partial(node: JsonValue[] | { [k: string]: JsonValue }, st: WalkState, depth: number, schema: boolean): void {
  if (Array.isArray(node)) {
    const n = node.length;
    let left = st.nodes;
    let first = n;
    while (first > 0 && left > 0) {
      const c = 1 + counted(st, node[first - 1], left - 1, depth + 1, schema);
      if (c > left) break;
      left -= c;
      first--;
    }
    const whole = st.nodes - left;
    st.nodes = left;
    if (first > 0 && left > 0) {
      st.nodes = left - 1;
      partial(node[first - 1] as JsonValue[] | { [k: string]: JsonValue }, st, depth + 1, schema);
    }
    st.nodes += whole;
    for (let i = first; i < n; i++) {
      st.nodes--;
      everyString(node[i], st, depth + 1, schema, true);
    }
    return;
  }
  const keys = keysOf(node, st);
  if (!keys) return;
  let last = -1;
  keys.forEach((k, i) => {
    const v = node[k];
    if (isObj(v) && (Array.isArray(v) ? v.length > 0 : hasKey(v)) && !(schema && k === "type" && schemaType(v))) last = i;
  });
  keys.forEach((k, i) => {
    const v = node[k];
    if (schema && k === "type" && schemaType(v)) return;
    take(st, k);
    everyString(v, st, depth + 1, schema, false, i === last);
  });
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
// node budget goes to the most recent tool calls. A list of paths is
// compiled once into a plan (planOf), so the walk allocates nothing but the
// "**" slots.
// ---------------------------------------------------------------------------

// Port of WHOLE_FIELDS in core/normalize.lua: field paths whose values are
// read whole (readWhole), whatever their shape, instead of as content parts:
// `documents`, retrieved documents (Cohere v1 maps of title, snippet, text or
// any other key, Cohere v2 strings or { id, data }, vLLM chat's `documents`),
// and `prompt.variables`, the values a Responses API stored prompt is filled
// with (strings or input_text parts, under names the client picks). The
// shipped rules read the variables as "prompt.variables.**"; the whole field
// stays for a rule that lists it.
const WHOLE_FIELDS = new Set(["documents", "prompt.variables"]);

// Port of KEY_FIELDS in core/normalize.lua: field paths whose value, when it
// is an object and not a list, is read as content parts and by its keys as
// well: Gemini's `contents` parts. The Gemini API takes one part object
// there; LiteLLM's generateContent adapter iterates `parts` without checking
// its type, so an object yields its keys, and each non-empty key reaches the
// model as a text part. The keys come after the part's own text, in byte
// order (objectKeys).
const KEY_FIELDS = new Set(["contents[*].parts", "contents.parts"]);

function fieldPath(f: string): Segs {
  const segs: Segs = splitPath(f);
  segs.whole = WHOLE_FIELDS.has(f);
  segs.keyed = KEY_FIELDS.has(f);
  return segs;
}

const OP_END = 1, OP_DEEP = 2, OP_KEY = 3;
/** A path that ends here; `depth`: collect()'s or readWhole()'s, 2 for a path that ends at an array read item by item; `whole`, `keyed`: fieldPath's flags (`keyed` only for the value the path ends at). */
interface EndOp { kind: typeof OP_END; depth: number; whole?: boolean; keyed?: boolean }
/** A "**" here. */
interface DeepOp { kind: typeof OP_DEEP }
/** A key the paths go on through: the plan for its value when that is not an array (`whole`), and when it is, the plans for the array and for each item. */
interface KeyOp { kind: typeof OP_KEY; key: string; whole?: Plan; wholeArr?: Plan; itemsArr?: Plan }
type Op = EndOp | DeepOp | KeyOp;
/** What to do at a node, in the order the first path for each op comes; `folded`, `first`, `lens`, `exact`: for variantsOf. */
interface Plan { ops: Op[]; folded?: Map<string, number[]>; first?: Set<number>; lens?: Set<number>; exact?: Set<string> }

/** One path from a node: its segments and the next one's index; `depth`: collect()'s, for a path read item by item. */
interface Cursor { segs: Segs; i: number; depth?: number }

// Port of compile: `leaf` (tool_fields) reads an array that ends a path whole.
function compile(cursors: Cursor[], leaf: boolean): Plan {
  const ops: Op[] = [];
  const groups = new Map<string, Cursor[]>();
  for (const c of cursors) {
    const seg = c.segs[c.i];
    if (seg === undefined) {
      ops.push({ kind: OP_END, depth: c.depth ?? 1, whole: c.segs.whole, keyed: c.segs.keyed && c.depth === undefined });
    } else if (seg.deep) {
      ops.push({ kind: OP_DEEP });
    } else {
      let g = groups.get(seg.key);
      if (!g) {
        g = [];
        groups.set(seg.key, g);
        ops.push({ kind: OP_KEY, key: seg.key });
      }
      g.push(c);
    }
  }
  const plan: Plan = { ops };
  ops.forEach((op, i) => {
    if (op.kind !== OP_KEY) return;
    const whole: Cursor[] = [];
    const wholeArr: Cursor[] = [];
    const itemsArr: Cursor[] = [];
    for (const c of groups.get(op.key)!) {
      const nxt = { segs: c.segs, i: c.i + 1 };
      if (c.segs[c.i].each) {
        itemsArr.push(nxt);
      } else {
        whole.push(nxt);
        // a path that ends at an array: collect() reads it item by item, one level down
        if (c.i === c.segs.length - 1 && !leaf) itemsArr.push({ segs: c.segs, i: c.i + 1, depth: 2 });
        else wholeArr.push(nxt);
      }
    }
    if (whole.length > 0) op.whole = compile(whole, leaf);
    if (wholeArr.length > 0) op.wholeArr = compile(wholeArr, leaf);
    if (itemsArr.length > 0) op.itemsArr = compile(itemsArr, leaf);
    if (op.key !== "") {
      const folded = (plan.folded ??= new Map());
      const f = fold(op.key);
      folded.set(f, [...(folded.get(f) ?? []), i]);
      firstUnits(op.key, (plan.first ??= new Set()));
      // fold() maps one UTF-16 unit to one: a key that folds to f is as long
      (plan.lens ??= new Set()).add(f.length);
    }
  });
  if (plan.folded) {
    // a key that is an op's own, and that no other op's key folds to, needs no look
    plan.exact = new Set();
    for (const op of ops) {
      if (op.kind !== OP_KEY || op.key === "") continue;
      if (plan.folded.get(fold(op.key))!.every((j) => (ops[j] as KeyOp).key === op.key)) plan.exact.add(op.key);
    }
  }
  return plan;
}

// Port of plan_of: plans by list of paths, the cache started over past PLANS_MAX.
const PLANS = new Map<string, Plan>();
const PLANS_MAX = 64;
function planOf(fields: string[] | undefined, leaf: boolean): Plan {
  const list = fields ?? [];
  const key = (leaf ? "t" : "c") + "\0" + list.join("\0");
  let plan = PLANS.get(key);
  if (!plan) {
    plan = compile(list.map((f) => ({ segs: fieldPath(f), i: 0 })), leaf);
    if (PLANS.size >= PLANS_MAX) PLANS.clear();
    PLANS.set(key, plan);
  }
  return plan;
}

// Port of variants_of: the keys of object `node` that fold to an op's key
// without being it, by op index, each list in byte order (UTF-16 order is
// the same for the characters that can fold to a field name); undefined when
// there are none (nearly always). One pass over the keys.
function variantsOf(node: { [k: string]: JsonValue }, plan: Plan): (string[] | undefined)[] | undefined {
  const { folded, first, lens, exact } = plan as Required<Plan>;
  let found: (string[] | undefined)[] | undefined;
  for (const k in node) {
    if (exact.has(k) || !first.has(k.charCodeAt(0)) || !lens.has(k.length)) continue;
    const ops = folded.get(fold(k));
    // for-in walks inherited keys too; JSON.parse makes none, but a polluted prototype could
    if (!ops || !Object.hasOwn(node, k)) continue;
    for (const i of ops) {
      if ((plan.ops[i] as KeyOp).key !== k) ((found ??= [])[i] ??= []).push(k);
    }
  }
  if (found) for (const list of found) list?.sort();
  return found;
}

// Port of through: `child`, the value under one key (or the node itself for
// "[*]"), for the paths going on through that key. Lua ipairs over a cjson
// array: null is a value, skipped, not the end.
function through(child: JsonValue | undefined, op: KeyOp, st: WalkState): void {
  if (child === undefined || child === null) return;
  if (Array.isArray(child) && child.length > 0) {
    if (op.wholeArr) walk(child, op.wholeArr, st);
    const items = op.itemsArr;
    if (items) {
      for (const item of child) {
        if (item === null || item === undefined) continue;
        walk(item, items, st);
      }
    }
  } else if (op.whole) {
    walk(child, op.whole, st);
  }
}

// Port of walk: a path that ends here, a "**" here, or the paths that go on
// through one key. A key is matched the way fold() says, and every key that
// folds to it is read: the exact key first, the others in byte order.
function walk(node: JsonValue | undefined, plan: Plan, st: WalkState): void {
  if (node === undefined || node === null) return;
  const obj = isObj(node) && !Array.isArray(node) ? node : undefined;
  const found = plan.folded && obj ? variantsOf(obj, plan) : undefined;
  const ops = plan.ops;
  for (let i = 0; i < ops.length; i++) {
    const op = ops[i];
    if (op.kind === OP_END) {
      if (st.leaf) st.leaf(node, st);
      else if (op.whole) readWhole(node, st.out as string[], op.depth);
      else {
        collect(node, st.out as string[], op.depth, st);
        if (op.keyed && isObj(node) && !Array.isArray(node)) for (const k of objectKeys(node)) take(st, k);
      }
    } else if (op.kind === OP_DEEP) {
      const slot: Slot = { node, values: [] };
      st.out.push(slot);
      st.defer.push(slot);
    } else if (op.key === "") {
      through(node, op, st);
    } else if (obj) {
      through(obj[op.key], op, st);
      const others = found?.[i];
      if (others) for (const k of others) through(obj[k], op, st);
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

function extractJsonState(decoded: JsonValue, fields: string[], jsonDecode?: Decode): { out: string[]; capped: boolean; tokenIds: boolean } {
  const st = newState(jsonDecode);
  sortLeft = WHOLE_SORT;
  walk(decoded, planOf(fields, false), st);
  return { out: settle(st), capped: st.capped, tokenIds: st.tokenIds === true };
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
  if (isObj(decoded)) walk(decoded, planOf(fields, true), st);
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
//   AI SDK 5 UIMessages      messages[*].parts[*] with type "tool-<name>" or
//                            "dynamic-tool": output, whatever its state (the
//                            client sets it), read as a "**" path reads it
//   Gemini                   contents[*].parts[*].functionResponse.response
//                            (contents and parts may each be one object, as
//                            LiteLLM takes them), read whole
// and retrieved documents, read whole: `documents` (Cohere v1 and v2, vLLM).
const responsesResult = (t: unknown) => typeof t === "string" && (t.endsWith("_call_output") || t === "mcp_call");
const sdkToolPart = (t: unknown) => typeof t === "string" && (t.startsWith("tool-") || t === "dynamic-tool");

// `st`: a walk state; a tool part's output leaves a slot for settle() to fill.
function toolResults(decoded: JsonValue, st: WalkState): void {
  if (!isObj(decoded) || Array.isArray(decoded)) return;
  const out = st.out as string[];
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
      if (Array.isArray(m.parts)) {
        for (const part of m.parts) {
          if (!isObj(part) || Array.isArray(part) || part.output === undefined || part.output === null) continue;
          if (!sdkToolPart(part.type)) continue;
          const slot: Slot = { node: part.output, values: [] };
          st.out.push(slot);
          st.defer.push(slot);
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
  const contents = decoded.contents;
  if (isObj(contents)) {
    for (const c of Array.isArray(contents) ? contents : [contents]) {
      const parts = isObj(c) && !Array.isArray(c) ? c.parts : undefined;
      if (!isObj(parts)) continue;
      for (const part of Array.isArray(parts) ? parts : [parts]) {
        if (isObj(part) && !Array.isArray(part)) functionResponses(part, out);
      }
    }
  }
  if (decoded.documents !== undefined) readWhole(decoded.documents, out, 1);
}

/**
 * Port of extract_untrusted: retrieved content in a decoded JSON body, tool
 * results (unless `spec.tool_results` is false) and the values of
 * `spec.fields`, in that order; a field value the tool results already hold
 * is not added again (see the Lua original). Returns the values (newest
 * last), and true when a "**" field hit a bound and left something out.
 */
export function extractUntrusted(
  decoded: JsonValue | undefined, spec: { tool_results?: boolean; fields?: string[] }, jsonDecode?: Decode,
): [string[], boolean] {
  const st = newState(jsonDecode);
  sortLeft = WHOLE_SORT;
  if (!isObj(decoded)) return [[], false];
  if (spec.tool_results !== false) toolResults(decoded, st);
  const fields = spec.fields ?? [];
  if (fields.length === 0) return [settle(st), st.capped];
  // the fields' values in a list of their own, "**" slots included, so that
  // settle() reads every "**" value (newest first) and the tool results'
  // values are known before the fields' are added
  const results = st.out;
  st.out = [];
  walk(decoded, planOf(fields, false), st);
  const more = st.out;
  st.out = results;
  const out = settle(st);
  const seen = new Set(out);
  for (const v of more) {
    if (typeof v === "string") {
      if (!seen.has(v)) out.push(v);
    } else {
      for (const s of v.values) if (!seen.has(s)) out.push(s);
    }
  }
  return [out, st.capped];
}

/** The values extractUntrusted finds. */
export function extractUntrustedValues(
  decoded: JsonValue | undefined, spec: { tool_results?: boolean; fields?: string[] }, jsonDecode?: Decode,
): string[] {
  return extractUntrusted(decoded, spec, jsonDecode)[0];
}

/** "boundaries": a multipart type with more boundary parameters than MAX_BOUNDARIES, nothing read. */
export type ExtractKind = "json" | "scan" | "invalid" | "text" | "form" | "multipart" | "boundaries" | "binary" | "none";

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
// body decides, the Content-Type is a hint. JSON when it parses as JSON,
// scanned when it starts like JSON and the decoder refuses it (under a form
// or multipart type read that way as well), form or multipart when declared
// (or form-shaped with no header), text when it reads as text, "binary"
// otherwise.
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

// Lua's %s: the ASCII whitespace its patterns know
const isSpace = (c: string | undefined): boolean =>
  c === " " || c === "\t" || c === "\n" || c === "\v" || c === "\f" || c === "\r";

/**
 * Port of header_params() in core/normalize.lua: the parameters of a header
 * value such as Content-Type or Content-Disposition, in order, names trimmed
 * and lowercased; split on ';' outside quoted strings, a value a quoted
 * string (backslash escapes removed) or a token that ends at ';', ',' or
 * whitespace. Linear.
 */
export function headerParams(s: string): { name: string; value: string }[] {
  const out: { name: string; value: string }[] = [];
  const n = s.length;
  let i = s.indexOf(";");
  if (i === -1) return out;
  i++;
  while (i < n) {
    let eq = i;
    while (eq < n && s[eq] !== "=" && s[eq] !== ";") eq++;
    if (eq >= n) break;
    if (s[eq] === ";") {
      i = eq + 1; // a parameter without '=': nothing to read
      continue;
    }
    let a = i;
    while (a < eq && isSpace(s[a])) a++;
    let e = eq - 1;
    while (e >= a && isSpace(s[e])) e--;
    const name = asciiLower(s.slice(a, e + 1));
    let v = eq + 1;
    while (v < n && isSpace(s[v])) v++;
    let value = "";
    let after: number;
    if (s[v] === '"') {
      // a quoted string, to its closing quote (or the end)
      let j = v + 1;
      for (;;) {
        if (j >= n) break;
        const c = s[j];
        if (c === '"') {
          j++;
          break;
        }
        if (c === "\\") {
          value += s.slice(j + 1, j + 2);
          j += 2;
        } else {
          value += c;
          j++;
        }
      }
      after = j;
    } else {
      let e2 = v;
      while (e2 < n && s[e2] !== ";" && s[e2] !== "," && !isSpace(s[e2])) e2++;
      value = s.slice(v, e2);
      after = e2;
    }
    out.push({ name, value });
    const next = s.indexOf(";", after);
    if (next === -1) break;
    i = next + 1;
  }
  return out;
}

// Port of delimiter_end(): the index just past a delimiter's line when the
// "--" + boundary that ends before `at` is a delimiter: "--" (the close:
// false), or optional space or tab and then `nl` (with no `nl` yet, "\r\n"
// or "\n", returned as well). undefined when it only starts like one.
function delimiterEnd(body: string, at: number, nl?: string): [number | false | undefined, string?] {
  if (body.startsWith("--", at)) return [false];
  let e = at;
  while (body[e] === " " || body[e] === "\t") e++;
  if (nl !== undefined) return body.startsWith(nl, e) ? [e + nl.length] : [undefined];
  if (body.startsWith("\r\n", e)) return [e + 2, "\r\n"];
  if (body[e] === "\n") return [e + 1, "\n"];
  return [undefined];
}

// Port of multipart_part(): a part is a file when its Content-Disposition
// has a filename or filename* parameter; it is read when it is not a file or
// its Content-Type (text/plain when it has none) is text or JSON, and the
// value reads as text.
// Port of text_part_type(): a file part's media type the backend may read
// as text: text/*, any JSON type, none (RFC 7578's default text/plain), and
// application/octet-stream (curl -F, openai-python, Node's FormData for a
// .jsonl or .md file). isText still keeps binary out.
function textPartType(ct: string): boolean {
  return ct === "" || ct.startsWith("text/") || ct.includes("json") || ct === "application/octet-stream";
}

function multipartPart(part: string, out: string[]): void {
  const hm = /^\r?\n/.exec(part) ?? /\r?\n\r?\n/.exec(part);
  if (!hm) return;
  const value = part.slice(hm.index + hm[0].length);
  let hasFile = false, typed = false, textType = false;
  for (const line of part.slice(0, hm.index).split(/[\r\n]+/)) {
    const colon = line.indexOf(":");
    if (colon === -1) continue;
    const name = asciiLower(/^[ \t\n\v\f\r]*([^ \t\n\v\f\r]*)/.exec(line.slice(0, colon))![1]);
    if (name === "content-disposition") {
      for (const p of headerParams(line.slice(colon + 1))) if (p.name === "filename" || p.name === "filename*") hasFile = true;
    } else if (name === "content-type") {
      const v = line.slice(colon + 1);
      const semi = v.indexOf(";");
      const ct = trim(asciiLower(semi === -1 ? v : v.slice(0, semi)));
      typed = true;
      if (textPartType(ct)) textType = true;
    }
  }
  if ((!hasFile || !typed || textType) && isText(value)) out.push(value);
}

// Port of multipart_parts(): the first delimiter at the start of the body or
// of a line, its line ending CRLF or LF; then every delimiter is that line
// ending, "--" and the boundary, followed by "--" (the close) or optional
// space or tab and the line ending. A part's value runs to the line ending
// before the next delimiter.
function multipartParts(body: string, boundary: string, out: string[]): void {
  const delim = "--" + boundary;
  let after: number | false | undefined;
  let nl: string | undefined;
  if (body.startsWith(delim)) [after, nl] = delimiterEnd(body, delim.length);
  let pos = 0;
  while (after === undefined) {
    const p = body.indexOf("\n" + delim, pos);
    if (p === -1) return;
    [after, nl] = delimiterEnd(body, p + 1 + delim.length);
    pos = p + 1;
  }
  if (after === false) return; // the close before any part
  const sep = nl! + delim;
  for (;;) {
    let stop: number | undefined;
    let nextAfter: number | false | undefined;
    let q: number = after;
    for (;;) {
      const m = body.indexOf(sep, q);
      if (m === -1) break;
      [nextAfter] = delimiterEnd(body, m + sep.length, nl);
      if (nextAfter !== undefined) {
        stop = m;
        break;
      }
      q = m + 1;
    }
    multipartPart(body.slice(after, stop ?? body.length), out);
    // undefined: no delimiter left (a body cut short); false: the close
    if (nextAfter === undefined || nextAfter === false) return;
    after = nextAfter;
  }
}

// Port of multipart_values(): every field without a filename, and file parts
// whose own Content-Type is text or JSON or that have none. Every part is
// read; each distinct boundary parameter is read, the values of all of them
// judged; past MAX_BOUNDARIES of them none is, and it returns true.
export const MAX_BOUNDARIES = 8;
function multipartValues(body: string, contentType: string, out: string[]): boolean {
  const list: string[] = [];
  const seen = new Set<string>();
  for (const p of headerParams(contentType)) {
    const b = p.value;
    if (p.name === "boundary" && b !== "" && !/[\r\n]/.test(b) && !seen.has(b)) {
      seen.add(b);
      list.push(b);
      if (list.length > MAX_BOUNDARIES) return true;
    }
  }
  for (const b of list) multipartParts(body, b, out);
  return false;
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

// declared JSON: a JSON media type (application/json, text/json,
// application/*+json), not "json" in a parameter such as a multipart
// boundary or "text/plain; profile=json". `ct` is lowercased.
const declaresJson = (ct: string): boolean => ct.split(";")[0].includes("json");

/**
 * Port of json_like() in core/normalize.lua: true when extract() tries `s` as
 * JSON, a JSON media type or a body that starts with { or [ (past a UTF-8 BOM
 * and whitespace). For the head of a body past max_body_bytes.
 */
export function jsonLike(s: string | undefined | null, contentType: string | undefined | null): boolean {
  if (declaresJson(asciiLower(typeof contentType === "string" ? contentType : ""))) return true;
  if (typeof s !== "string") return false;
  const first = /^[ \t\n\v\f\r]*([\s\S])/.exec(s.startsWith("\uFEFF") ? s.slice(1) : s)?.[1];
  return first === "{" || first === "[";
}

/**
 * Extract text from a raw body. Returns the text (values joined with "\n"),
 * the kind, the values in order (newest last) for window(), the decoded
 * JSON value when the kind is "json", true when a "**" walk hit a bound
 * and left something out, and true when a text field holds token ids (kinds
 * "json", "scan" and "invalid"; see collect and scanStrings).
 */
export function extract(
  body: string | undefined | null,
  contentType: string | undefined | null,
  fields: string[],
  jsonDecode: (s: string) => JsonValue = (s) => JSON.parse(s) as JsonValue,
): [string, ExtractKind, string[], JsonValue?, boolean?, boolean?] {
  if (typeof body !== "string" || body === "") return ["", "none", []];
  const rawCt = typeof contentType === "string" ? contentType : "";
  const ct = asciiLower(rawCt);
  // A UTF-8 BOM is not JSON, but Python's json.loads on bytes and Express's
  // body-parser skip it: judge what the backend reads.
  if (body.startsWith("﻿")) body = body.slice(1);
  const declaredJson = declaresJson(ct);
  const form = ct.includes("application/x-www-form-urlencoded") || (ct === "" && /^[A-Za-z0-9._~%+[\]-]+=[^ \t\n\v\f\r]*$/.test(body));
  const multipart = ct.includes("multipart/form-data");
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
      return [st.out.join("\n"), "json", st.out, decoded as JsonValue, st.capped, st.tokenIds];
    }
    // a JSON scalar has no text fields
    if (declaredJson && ok && decoded !== undefined) return ["", "none", []];
    // The decoder refused it; the backend's parser may not (cjson refuses
    // nesting past 1000 and bytes after the value, Go and Node do not, and
    // Ollama decodes JSON whatever the Content-Type says: curl -d sends
    // form-urlencoded). So the tolerant scanner past max_body_bytes uses
    // reads it, declared JSON or not: the text fields' string values and the
    // objects under a "**" path's key. Under a form or multipart type the
    // values that reading gives follow, since a backend of that kind reads
    // the body so. Under any other type (text/plain, none) the whole body
    // follows too, when it is text: a backend that reads it as text (a raw
    // prompt route, req.text()) reads all of it, the bytes after the JSON
    // value included. Declared JSON with nothing to scan is unjudgeable,
    // never "no text"; any other body with nothing to scan is read as before.
    const seen: { tokenIds?: boolean } = {};
    const out = scanStrings(body, fieldKeys(fields), [], deepKeys(fields), seen);
    if (out.length > 0) {
      if (!declaredJson) {
        if (form) formValues(body, out);
        else if (multipart) {
          if (multipartValues(body, rawCt, out)) return ["", "boundaries", []];
        } else if (isText(body)) out.push(body);
      }
      return [out.join("\n"), "scan", out, undefined, undefined, seen.tokenIds === true];
    }
    if (declaredJson) return ["", "invalid", [], undefined, undefined, seen.tokenIds === true];
  }
  const out: string[] = [];
  if (form) {
    formValues(body, out);
    return [out.join("\n"), "form", out];
  }
  if (multipart) {
    if (multipartValues(body, rawCt, out)) return ["", "boundaries", []];
    return [out.join("\n"), "multipart", out];
  }
  if (isText(body)) return [body, "text", [body]];
  return ["", "binary", []];
}

// ---------------------------------------------------------------------------
// Partial bodies: tolerant scan of JSON string values, and of the objects
// under a "**" path's key (port of scan_strings)
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

// The last key of a field path, folded, or undefined. Lua:
// f:gsub("%.%*%*$", ""):match("([^%.%[%]%*]+)[%[%]%*]*$") -- the last run of
// name characters before any trailing "[", "]" or "*". A linear scan, not a
// regex: the unanchored pattern backtracks quadratically on long input.
function lastKey(f: string): string | undefined {
  const special = (c: string) => c === "." || c === "[" || c === "]" || c === "*";
  // "arguments.**": the strings under "arguments"
  if (f.endsWith(".**")) f = f.slice(0, -3);
  let end = f.length;
  while (end > 0 && (f[end - 1] === "[" || f[end - 1] === "]" || f[end - 1] === "*")) end--;
  let start = end;
  while (start > 0 && !special(f[start - 1])) start--;
  return end > start ? fold(f.slice(start, end)) : undefined;
}

/** The last key of each text-field path, folded: "messages[*].content" -> "content". */
export function fieldKeys(fields: string[] | undefined): Set<string> {
  const keys = new Set<string>();
  for (const f of fields ?? []) {
    const k = lastKey(f);
    if (k !== undefined) keys.add(k);
  }
  // content parts carry their text under "text"
  if (keys.has("content")) keys.add("text");
  return keys;
}

/**
 * Port of deep_keys: the last key of each "**" text-field path, folded, for
 * scanStrings: "any", or "object" when a path without "**" ends at the same
 * key too ("input": a tool_use input, and the Responses input list).
 */
export function deepKeys(fields: string[] | undefined): Map<string, "any" | "object"> {
  const deep = new Set<string>();
  const plain = new Set<string>();
  for (const f of fields ?? []) {
    const k = lastKey(f);
    if (k !== undefined) (f.endsWith(".**") ? deep : plain).add(k);
  }
  const out = new Map<string, "any" | "object">();
  for (const k of deep) out.set(k, plain.has(k) ? "object" : "any");
  return out;
}

// Port of next_quote: the index of the first '"' at or after `i` that no
// backslash escapes (a backslash escapes the character after it), or -1.
function nextQuote(s: string, i: number): number {
  const n = s.length;
  for (;;) {
    let j = i;
    while (j < n && s[j] !== '"' && s[j] !== "\\") j++;
    if (j >= n) return -1;
    if (s[j] === '"') return j;
    i = j + 2;
  }
}

// Port of key_at: `q` is an unescaped '"'; the string it opens is a key
// when a colon follows (then, with `start`, a quote or a bracket). Returns
// the key decoded and folded and the index of the value's first character,
// or, when it opens no key, the next '"' to try (the string's closing
// quote); null at the end of the text.
function keyAt(s: string, q: number, start: boolean): { key?: string; at: number } | null {
  const e = nextQuote(s, q + 1);
  if (e === -1) return null;
  let k = e + 1;
  while (luaSpace(s.charCodeAt(k))) k++;
  if (s[k] !== ":") return { at: e };
  k++;
  while (luaSpace(s.charCodeAt(k))) k++;
  if (start && s[k] !== '"' && s[k] !== "{" && s[k] !== "[") return { at: e };
  return { key: fold(readString(s, q + 1)[0]), at: k };
}

// The index `i` ends a string value: past Lua white space, a comma, a
// closing bracket or the end of the text.
function endsValue(s: string, i: number): boolean {
  while (luaSpace(s.charCodeAt(i))) i++;
  return i >= s.length || s[i] === "," || s[i] === "}" || s[i] === "]";
}

/**
 * Collect the string values of `keys` (from fieldKeys) from possibly
 * truncated JSON (port of scan_strings). Keys match the way walk() matches
 * them: decoded and folded. With `deep` (from deepKeys), the value of a "**"
 * path's key is read as the walk reads it, every key and string in it in
 * the order they come: an object, and an array when no other path ends at
 * that key; otherwise the scan goes on inside it, as for any other key. With
 * `seen`, seen.tokenIds is set when one of `keys` holds an array that starts
 * with a number: token ids. With `opts.tail`, the text before the first
 * unescaped '"' is the end of a value cut at its start: kept when that quote
 * ends a value and it reads as natural text (white space in it, and isText).
 */
export function scanStrings(
  s: string, keys: Set<string>, out: string[], deep?: Map<string, "any" | "object">, seen?: { tokenIds?: boolean },
  opts?: { tail?: boolean },
): string[] {
  let q = nextQuote(s, 0);
  if (q !== -1 && opts?.tail && endsValue(s, q + 1)) {
    const [v] = readString(s, 0);
    if (/[ \t\n\v\f\r]/.test(v) && isText(v)) out.push(v);
  }
  while (q !== -1) {
    const k = keyAt(s, q, true);
    if (k === null) break;
    if (k.key === undefined) {
      q = k.at;
      continue;
    }
    const at = k.at;
    if (s[at] === '"') {
      const [value, next] = readString(s, at + 1);
      if (keys.has(k.key) && value !== "") out.push(value);
      q = nextQuote(s, next);
    } else {
      if (seen && s[at] === "[" && keys.has(k.key) && startsWithNumber(s, at + 1)) seen.tokenIds = true;
      const d = deep?.get(k.key);
      q = nextQuote(s, d !== undefined && (s[at] === "{" || d === "any") ? scanValue(s, at, out, false) : at + 1);
    }
  }
  return out;
}

// Lua's s:find("^[%s%[]*[%-%d]", i): past whitespace and brackets, a number
// starts at `i` (token ids: "prompt":[40 or "prompt":[[40).
function startsWithNumber(s: string, i: number): boolean {
  for (; i < s.length; i++) {
    const c = s[i];
    if (c === " " || c === "\t" || c === "\n" || c === "\v" || c === "\f" || c === "\r" || c === "[") continue;
    return c === "-" || (c >= "0" && c <= "9");
  }
  return false;
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
// `i` (a `{` or `[`), to its end or the end of `s`; with `schema` (tool
// definitions) a "type" key whose value is a JSON Schema type name is left
// out with it. Returns the index after it.
function scanValue(s: string, i: number, out: string[], schema: boolean): number {
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
      const skip = schema && v === "type" && k !== -1 && s[k] === ":" ? typeNames(s, k + 1) : undefined;
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
  let q = nextQuote(s, 0);
  while (q !== -1) {
    const k = keyAt(s, q, false);
    if (k === null) break;
    const at = k.at;
    if (k.key === undefined) q = at;
    else if (!keys.has(k.key)) q = nextQuote(s, at);
    else if (s[at] === '"') {
      const [v, next] = readString(s, at + 1);
      if (v !== "") out.push(v);
      q = nextQuote(s, next);
    } else if (s[at] === "{" || s[at] === "[") {
      q = nextQuote(s, scanValue(s, at, out, true));
    } else {
      q = nextQuote(s, at);
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

/** Port of normalize.chunk_overlap: bytes two consecutive chunks share,
 *  HIT_CONTEXT, at most a quarter of the budget, counted in each piece's budget. */
export function chunkOverlap(budget: number): number {
  return Math.max(0, Math.min(HIT_CONTEXT, Math.floor(budget / 4)));
}

/**
 * Port of normalize.chunks: consecutive pieces of at most `budget` UTF-8
 * bytes covering all of `text`; a cut prefers the last newline in the second
 * half of a piece (dropped) and never splits a code point. With `overlap`,
 * the piece after one that ends at e starts at e + 1 - overlap, moved
 * forward to a character start. `hard`: no newline preference, and every
 * piece but the last advances at least budget - overlap bytes. Returns the
 * pieces and each one's 1-based byte offset, as in Lua.
 */
export function chunks(text: string, budget: number, overlap = 0, hard = false): [string[], number[]] {
  const b = enc.encode(text);
  const n = b.length;
  const half = Math.floor(budget / 2);
  const ov = Math.floor(Number(overlap) || 0);
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
    if (!hard) {
      for (let j = e; j >= i + half + 1; j--) {
        if (b[j - 1] === 10) {
          e = j - 1;
          next = j + 1;
          break;
        }
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
    if (ov > 0) {
      let nx = Math.max(i + 1, e + 1 - ov);
      // a cut walked back to a character boundary does not eat the advance
      if (hard) nx = Math.max(nx, Math.min(e + 1, i + budget - ov));
      while (nx <= e && isCont(b, nx - 1)) nx++;
      next = nx;
    }
    i = next;
  }
  return [pieces, starts];
}

// `len` bytes at most of `tb` from byte `a` (1-based), cut back to a
// character boundary, as normalize.head(text:sub(a), len) in Lua.
function headAt(tb: Uint8Array, a: number, len: number): string {
  if (len <= 0) return "";
  const s = tb.subarray(a - 1);
  if (s.length <= len) return dec.decode(s);
  let e = len;
  while (e > 0 && isCont(s, e)) e--;
  return dec.decode(s.subarray(0, e));
}

// Port of hit_part() in core/normalize.lua: the hits' part of a window, in
// at most `half` bytes. One span: the hit and up to HIT_CONTEXT bytes each
// side. Several (in text order): overlapping ones are merged, and each gets
// its match and the same context each side, which shrinks evenly toward 0
// so that all of them fit; only when the matches alone do not fit are the
// oldest dropped. Pieces whose context meets are joined, the others are
// separated by a newline.
function hitPart(tb: Uint8Array, spans: readonly (readonly [number, number])[], half: number): string {
  const merged: [number, number][] = [];
  for (const [f, t] of spans) {
    const last = merged[merged.length - 1];
    if (last && f <= last[1] + 1) {
      if (t > last[1]) last[1] = t;
    } else {
      merged.push([f, t]);
    }
  }
  const lastIdx = merged.length - 1;
  let first = 0;
  let need = 0;
  for (;;) {
    need = lastIdx - first;
    for (let i = first; i <= lastIdx; i++) need += merged[i][1] - merged[i][0] + 1;
    if (need <= half || first === lastIdx) break;
    first++;
  }
  const n = tb.length;
  if (first === lastIdx) {
    const [from, to] = merged[first];
    const ctxb = Math.max(0, Math.min(HIT_CONTEXT, Math.floor((half - (to - from + 1)) / 2)));
    let a = Math.max(1, from - ctxb);
    while (a > 1 && isCont(tb, a - 1)) a--;
    return headAt(tb, a, Math.min(Math.min(to + ctxb, n) - a + 1, half));
  }
  const m = lastIdx - first + 1;
  const ctxb = Math.max(0, Math.min(HIT_CONTEXT, Math.floor((half - need) / (2 * m))));
  const ranges: [number, number][] = [];
  for (let i = first; i <= lastIdx; i++) {
    const [from, to] = merged[i];
    // forward to a character start: the context never grows past its share
    let a = Math.max(1, from - ctxb);
    while (a < from && isCont(tb, a - 1)) a++;
    const b = Math.min(n, to + ctxb);
    const last = ranges[ranges.length - 1];
    if (last && a <= last[1] + 1) last[1] = b;
    else ranges.push([a, b]);
  }
  return ranges.map(([a, b]) => headAt(tb, a, b - a + 1)).join("\n");
}

/**
 * @param spans 1-based inclusive byte spans of always_suspect hits, in text
 *              order, or undefined; or, as before, one span given as two
 *              numbers (from, to)
 * @returns the text to judge, and true when it was cut
 */
export function window(text: string, values: string[], budget: number,
  spans?: readonly (readonly [number, number])[] | number, to?: number): [string, boolean] {
  const tb = enc.encode(text);
  if (tb.length <= budget) return [text, false];
  if (typeof spans === "number") spans = to !== undefined ? [[spans, to]] : undefined;
  const out: string[] = [];
  let rem = budget;
  if (spans && spans.length > 0) {
    // the hits and their context, in at most half the budget
    const piece = hitPart(tb, spans, Math.floor(budget / 2));
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
 * Fingerprint = hash(normalize(text)) over the WHOLE normalized text, with
 * ASCII lowercase and whitespace collapse only. `opts` is deliberately
 * ignored: a fingerprint that only covers a prefix lets any text that shares
 * the prefix reuse a cached or trusted verdict (0.3.0 hashed the first 2048
 * bytes; fixed in 0.3.1), and one that drops digit runs and UUIDs lets
 * "transfer 12345 to acct" reuse the verdict of "transfer 99999 to acct",
 * where the digits are the payload. Only texts that are the same but for
 * case and whitespace share a verdict. Text that is only whitespace is
 * hashed as one space, one entry for every such body.
 *
 * `hash` is injected by the adapter and MUST be collision-resistant
 * (sha256 hex or better). The fingerprint keys the verdict cache and the
 * operator trust store, both of which turn a hit into a verdict without a
 * judge call, so an attacker who can forge a hash forges a verdict. CRC32
 * and djb2 are linear and let a few appended bytes hit any chosen value;
 * `djb2` below exists for the golden vectors only.
 */
const FP_OPTS: NormalizeOpts = { strip_digits: false, strip_uuid: false, prefix_bytes: Infinity };

export function fingerprint(
  text: string | null | undefined,
  _opts: NormalizeOpts | null | undefined,
  hash: (s: string) => string,
): string {
  let norm = normalize(text, FP_OPTS);
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
