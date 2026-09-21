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

/** Truncate to at most n UTF-8 bytes (a split code point decodes as U+FFFD). */
export function truncateBytes(s: string, n: number): string {
  const b = enc.encode(s);
  if (b.length <= n) return s;
  return dec.decode(b.subarray(0, n));
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

function walk(node: JsonValue | undefined, segs: Seg[], i: number, out: string[]): void {
  if (node === undefined || node === null) return;
  if (i >= segs.length) {
    if (typeof node === "string") out.push(node);
    return;
  }
  const seg = segs[i];
  let child: JsonValue | undefined = node;
  if (seg.key !== "") {
    if (!isObj(node)) return;
    child = Array.isArray(node) ? undefined : node[seg.key];
  }
  if (seg.each) {
    // Lua ipairs: array part only, stops at the first nil
    if (!Array.isArray(child)) return;
    for (const item of child) {
      if (item === null || item === undefined) break;
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

export function fingerprint(
  text: string | null | undefined,
  opts: NormalizeOpts | null | undefined,
  hash: (s: string) => string,
): string {
  const norm = normalize(text, opts);
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
