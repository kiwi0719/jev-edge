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
  return extractJsonValues(decoded, fields).join("\n");
}

/** The strings extractJson joins, in order (newest last), for window(). */
export function extractJsonValues(decoded: JsonValue, fields: string[]): string[] {
  const out: string[] = [];
  for (const f of fields ?? []) walk(decoded, splitPath(f), 0, out);
  return out;
}

export type ExtractKind = "json" | "text" | "form" | "multipart" | "binary" | "none";

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

function formValues(body: string, out: string[]): void {
  // Lua: body:gmatch("([^&=]+)=([^&]*)")
  const re = /([^&=]+)=([^&]*)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(body)) !== null) out.push(formDecode(m[2]));
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
 * Extract text from a raw body. Returns the text (values joined with "\n"),
 * the kind, and the values in order (newest last) for window().
 */
export function extract(
  body: string | undefined | null,
  contentType: string | undefined | null,
  fields: string[],
  jsonDecode: (s: string) => JsonValue = (s) => JSON.parse(s) as JsonValue,
): [string, ExtractKind, string[]] {
  if (typeof body !== "string" || body === "") return ["", "none", []];
  const rawCt = typeof contentType === "string" ? contentType : "";
  const ct = asciiLower(rawCt);
  // A UTF-8 BOM is not JSON, but Python's json.loads on bytes and Express's
  // body-parser skip it: judge what the backend reads.
  if (body.startsWith("﻿")) body = body.slice(1);
  const declaredJson = ct.includes("json");
  const first = /^[ \t\n\v\f\r]*([\s\S])/.exec(body)?.[1];
  if (first === "{" || first === "[" || declaredJson) {
    let decoded: JsonValue | undefined;
    let ok = true;
    try {
      decoded = jsonDecode(body);
    } catch {
      ok = false;
    }
    if (ok && isObj(decoded)) {
      const values = extractJsonValues(decoded as JsonValue, fields);
      return [values.join("\n"), "json", values];
    }
    // declared JSON that is not: the backend rejects it too
    if (declaredJson) return ["", "none", []];
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

/** The last key of each text-field path: "messages[*].content" -> "content". */
export function fieldKeys(fields: string[] | undefined): Set<string> {
  const keys = new Set<string>();
  for (const f of fields ?? []) {
    const m = /([^.[\]*]+)[[\]*]*$/.exec(f);
    if (m) keys.add(m[1]);
  }
  // content parts carry their text under "text"
  if (keys.has("content")) keys.add("text");
  return keys;
}

/** Collect the string values of `keys` from possibly truncated JSON. */
export function scanStrings(s: string, keys: Set<string>, out: string[]): string[] {
  const re = /"([A-Za-z0-9_-]+)"[ \t\n\v\f\r]*:[ \t\n\v\f\r]*"/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(s)) !== null) {
    const [value, next] = readString(s, m.index + m[0].length);
    if (keys.has(m[1]) && value !== "") out.push(value);
    re.lastIndex = next;
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
      while (e > i && isCont(b, e)) e--;
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
