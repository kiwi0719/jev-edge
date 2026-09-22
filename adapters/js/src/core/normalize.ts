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
// ---------------------------------------------------------------------------

interface Seg { key: string; each: boolean }

function splitPath(path: string): Seg[] {
  const segs: Seg[] = [];
  for (const seg of path.split(".")) {
    if (seg === "") continue; // Lua's gmatch("[^%.]+") skips empty segments
    const m = /^([^[]*)\[\*\]$/.exec(seg);
    if (m) segs.push({ key: m[1], each: true });
    else segs.push({ key: seg, each: false });
  }
  return segs;
}

function isObj(v: unknown): v is { [k: string]: JsonValue } | JsonValue[] {
  return typeof v === "object" && v !== null;
}

// A leaf that is not a string is a "content parts" value: the array form of
// `messages[*].content` every current chat API accepts
// (`[{type:"text", text:"..."}, {type:"image_url", ...}]`), the Responses API's
// `input_text`, and Anthropic's `tool_result` whose `content` nests once more.
// Collect every string, every part's `text`, and recurse into `content`, to a
// bounded depth. Anything else (numbers, images) contributes nothing.
// Mirrors collect() in core/normalize.lua, including Lua's "array if [1] is
// set" test: an empty array is a table with no array part and yields nothing.
const LEAF_DEPTH = 4;
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
}

function walk(node: JsonValue | undefined, segs: Seg[], i: number, out: string[]): void {
  if (node === undefined || node === null) return;
  if (i >= segs.length) {
    collect(node, out, 1);
    return;
  }
  const seg = segs[i];
  let child: JsonValue | undefined = node;
  if (seg.key !== "") {
    if (!isObj(node)) return;
    child = Array.isArray(node) ? undefined : node[seg.key];
  }
  if (seg.each) {
    // Lua ipairs over a cjson array: null is a value, skipped, not the end
    if (!Array.isArray(child)) return;
    for (const item of child) {
      if (item === null || item === undefined) continue;
      walk(item, segs, i + 1, out);
    }
  } else {
    walk(child, segs, i + 1, out);
  }
}

export function extractJson(decoded: JsonValue, fields: string[]): string {
  const out: string[] = [];
  for (const f of fields ?? []) walk(decoded, splitPath(f), 0, out);
  return out.join("\n");
}

export type ExtractKind = "json" | "text" | "form" | "none";

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

export function extract(
  body: string | undefined | null,
  contentType: string | undefined | null,
  fields: string[],
  jsonDecode: (s: string) => JsonValue = (s) => JSON.parse(s) as JsonValue,
): [string, ExtractKind] {
  if (typeof body !== "string" || body === "") return ["", "none"];
  const ct = asciiLower(contentType ?? "");
  if (ct.includes("application/json") || ct.includes("+json")) {
    // A UTF-8 BOM is not JSON, but Python's json.loads on bytes and Express's
    // body-parser skip it: judge what the backend reads.
    if (body.startsWith("\uFEFF")) body = body.slice(1);
    let decoded: JsonValue;
    try {
      decoded = jsonDecode(body);
    } catch {
      return ["", "none"];
    }
    if (!isObj(decoded)) return ["", "none"];
    return [extractJson(decoded, fields), "json"];
  } else if (ct.includes("application/x-www-form-urlencoded")) {
    const parts: string[] = [];
    // Lua: body:gmatch("([^&=]+)=([^&]*)")
    const re = /([^&=]+)=([^&]*)/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(body)) !== null) parts.push(formDecode(m[2]));
    return [parts.join("\n"), "form"];
  } else if (ct.includes("text/") || ct === "") {
    return [body, "text"];
  }
  return ["", "none"];
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
