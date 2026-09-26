// Port of core/rules.lua: L1, cheap and short-circuiting.
import { extract, extractTools, extractUntrusted, jsonLike, isText, byteLength, head, tail, fieldKeys, deepKeys, scanStrings, scanTools, window, chunks as splitChunks, chunkOverlap, utf8Bytes, byteString, trim, ipKey as normalizeIpKey, type JsonValue } from "./normalize.js";
import { untrustedSpec, type UntrustedConfig } from "./defaults.js";
import { repBlocked, type SubjectCtx, type ReputationConfig } from "./subject.js";

export type RuleResult = "pass" | "block" | "suspect" | "unjudgeable";
export const PASS: RuleResult = "pass";
export const BLOCK: RuleResult = "block";
export const SUSPECT: RuleResult = "suspect";
/** A watched request L1 cannot read; policy.unjudgeable decides (see core/rules.lua). */
export const UNJUDGEABLE: RuleResult = "unjudgeable";

export const MAX_BODY_BYTES = 1048576;
export const MAX_JUDGE_BYTES = 32768;
export const TAIL_BYTES = 65536;
export const SKIP_CONTENT_TYPES = [
  "image/", "audio/", "video/", "font/", "application/pdf", "application/zip", "application/gzip",
];

export interface Rule {
  id: string;
  /** Lua patterns, as in the rule files (luaPatternToRegExp: everything but %b and back-references). */
  watch_paths: string[];
  /** Match watch_paths without folding ASCII case (default: folded, see pathMatches). */
  paths_case_sensitive?: boolean;
  /** Watched paths (Lua patterns) watched only for a JSON body (see core/rules.lua). */
  json_only_paths?: string[];
  methods?: Record<string, boolean>;
  /** Allow list (the pre-0.4 behaviour); without it, skip_content_types applies. */
  content_types?: string[];
  /** Media types never judged; everything else is read and the body decides the format. */
  skip_content_types?: string[];
  min_body_bytes?: number;
  max_body_bytes?: number;
  max_judge_bytes?: number;
  /** Judge text over max_judge_bytes in up to this many chunks (default 1: one window). */
  max_judge_chunks?: number;
  text_fields: string[];
  /** Tool definitions judged as a part of their own (core/rules.lua tools_part); [] or absent: none. */
  tool_fields?: string[];
  min_text_chars?: number;
  always_suspect?: string[];
  templates: string[];
  deployment_context?: string;
  /** Overrides config.untrusted for this rule (core/defaults.lua `untrusted`). */
  untrusted?: Partial<UntrustedConfig>;
  /** A prompt given as token ids: "block" refuses it in enforce mode, text or not; unset, policy.unjudgeable decides (see rules/llm-endpoints.lua). */
  token_prompts?: "pass" | "block";
}

/** Retrieved content L1 found for untrusted judging, cut to its own window. `only`: the rest of the text would have passed on its own. */
export interface UntrustedPart { text: string; windowed: boolean; only?: boolean }

/** The tool definitions L1 found (rule.tool_fields), cut to their own window; `hit`: the always_suspect pattern that fired in them. `only`: the rest of the text would have passed on its own. */
export interface ToolsPart { text: string; windowed: boolean; hit?: string; only?: boolean }

export interface Req {
  method?: string;
  path?: string;
  /** A repeated header may arrive as a list (Lua's ngx.req.get_headers does this). */
  headers?: Record<string, string | string[] | undefined>;
  body?: string | null;
  /** The body's length in bytes as the adapter read it, when `body` was
   *  decoded from bytes that were not all valid UTF-8 (each invalid byte is
   *  one U+FFFD, three bytes re-encoded): core counts this, as Lua counts
   *  #body. Absent: the UTF-8 length of `body`. */
  body_bytes?: number;
  body_size?: number;
  client_ip?: string;
  /** Past max_body_bytes: the first bytes and the last bytes (not overlapping) the adapter kept. */
  body_head?: string | null;
  body_tail?: string | null;
  /** true when the adapter decoded the Content-Encoding and `body` is the decoded body. */
  decoded?: boolean;
  /** true when the gateway in front forwarded only the first part of the body: `body` (or `body_head`) is that part. */
  body_partial?: boolean;
}

export interface CacheLike {
  get(key: string): unknown | Promise<unknown>;
  set?(key: string, value: unknown, ttl: number): void | Promise<void>;
}

export interface RulesCtx {
  cache?: CacheLike;
  clock?: () => number;
  json_decode?: (s: string) => JsonValue;
  /**
   * The first case-insensitive match at or after byte `init` (1 when
   * undefined): truthy on a match; a [from, to] 1-based inclusive UTF-8 byte
   * span places the hit in the judging window. A matcher that ignores init
   * returns an earlier span again, and the walk of that pattern stops there.
   * A matcher that throws (a pattern the engine refuses, a match that runs
   * out of stack) counts that pattern as a hit with no span.
   */
  re_find?: (subject: string, pattern: string, init?: number) => boolean | readonly [number, number] | null;
  log?: (level: string, msg: string) => void;
  subject?: SubjectCtx;
  config?: {
    subject?: { reputation?: ReputationConfig }; untrusted?: UntrustedConfig; policy?: { partial?: string; unjudgeable?: string };
    async?: { rep_block_after?: number | string };
    client_ip?: { ipv6_prefix?: number };
  };
}

/**
 * Syntax check for a Lua pattern, ported from core/rules.lua pattern_error():
 * walks the pattern the way lstrlib does and reports what it would raise on
 * some subject. Returns null when the pattern is well formed. Used at rule
 * resolve time so a malformed watch path fails at startup, not per request.
 */
export function patternError(pattern: string): string | null {
  const p = luaBytes(pattern); // lstrlib walks bytes
  const n = p.length;
  let i = 0;
  // captures in opening order; true once closed (see the Lua original)
  const caps: boolean[] = [];
  while (i < n) {
    const c = p[i];
    if (c === "(") {
      if (caps.length >= 32) return "too many captures";
      caps.push(false);
      i++;
    } else if (c === ")") {
      const open = caps.lastIndexOf(false);
      if (open < 0) return "invalid pattern capture";
      caps[open] = true;
      i++;
    } else if (c === "%") {
      const d = p[i + 1];
      if (d === undefined) return "malformed pattern (ends with '%')";
      if (d >= "0" && d <= "9") {
        const l = Number(d);
        if (l === 0 || !caps[l - 1]) return "invalid capture index %" + d;
        i += 2;
      } else if (d === "b") {
        if (i + 3 >= n) return "malformed pattern (missing arguments to '%b')";
        i += 4;
      } else if (d === "f") {
        if (p[i + 2] !== "[") return "missing '[' after '%f' in pattern";
        i += 2;
      } else {
        i += 2;
      }
    } else if (c === "[") {
      let j = i + 1;
      if (p[j] === "^") j++;
      // the first ']' right after '[' or '[^' is literal
      if (p[j] === "]") j++;
      let closed = false;
      while (j < n) {
        const e = p[j];
        if (e === "%") {
          if (j + 1 >= n) return "malformed pattern (ends with '%')";
          j += 2;
        } else if (e === "]") {
          closed = true;
          break;
        } else {
          j++;
        }
      }
      if (!closed) return "malformed pattern (missing ']')";
      i = j + 1;
    } else {
      i++;
    }
  }
  if (caps.includes(false)) return "unfinished capture";
  return null;
}

// Lua's character classes (lstrlib match_class in the C locale), over bytes.
const LUA_CLASSES = new Map<string, (c: number) => boolean>([
  ["a", (c) => (c >= 65 && c <= 90) || (c >= 97 && c <= 122)],
  ["c", (c) => c < 32 || c === 127],
  ["d", (c) => c >= 48 && c <= 57],
  ["g", (c) => c >= 33 && c <= 126],
  ["l", (c) => c >= 97 && c <= 122],
  ["p", (c) => (c >= 33 && c <= 47) || (c >= 58 && c <= 64) || (c >= 91 && c <= 96) || (c >= 123 && c <= 126)],
  ["s", (c) => (c >= 9 && c <= 13) || c === 32],
  ["u", (c) => c >= 65 && c <= 90],
  ["w", (c) => (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122)],
  ["x", (c) => (c >= 48 && c <= 57) || (c >= 65 && c <= 70) || (c >= 97 && c <= 102)],
  ["z", (c) => c === 0], // LuaJIT and every Lua since 5.1 keep it
]);

// Port of match_class: does byte `c` match `%<cl>`? An upper-case class
// letter is the complement; any other character after '%' is itself.
function matchClass(c: number, cl: number): boolean {
  const upper = cl >= 65 && cl <= 90;
  const test = LUA_CLASSES.get(String.fromCharCode(upper ? cl + 32 : cl));
  if (!test) return cl === c;
  return upper ? !test(c) : test(c);
}

type Bytes = boolean[]; // which of the 256 byte values a single-char class matches

function members(test: (c: number) => boolean): Bytes {
  const m: Bytes = new Array(256);
  for (let c = 0; c < 256; c++) m[c] = test(c);
  return m;
}

// Port of classEnd and matchbracketclass for the set that opens at p[i]:
// the bytes it matches and the index past its closing ']'. The first
// character after '[' or '[^' is always a member, so '[]]' holds ']'.
function setMembers(p: string, i: number): [Bytes, number] {
  const n = p.length;
  let j = i + 1;
  if (p[j] === "^") j++;
  do {
    if (j >= n) throw new Error("malformed pattern (missing ']')");
    if (p[j++] === "%" && j < n) j++;
  } while (p[j] !== "]");
  const ec = j;
  const m: Bytes = new Array(256).fill(false);
  let q = i;
  let sig = true;
  if (p[q + 1] === "^") { sig = false; q++; }
  while (++q < ec) {
    if (p[q] === "%") {
      q++;
      const cl = p.charCodeAt(q);
      for (let c = 0; c < 256; c++) if (matchClass(c, cl)) m[c] = true;
    } else if (p[q + 1] === "-" && q + 2 < ec) {
      q += 2;
      for (let c = p.charCodeAt(q - 2); c <= p.charCodeAt(q); c++) m[c] = true;
    } else {
      m[p.charCodeAt(q)] = true;
    }
  }
  if (!sig) for (let c = 0; c < 256; c++) m[c] = !m[c];
  return [m, ec + 1];
}

const hex2 = (c: number): string => "\\x" + c.toString(16).padStart(2, "0");

// A RegExp class for exactly these bytes ("[]" when none: it never matches).
function classOf(m: Bytes): string {
  let body = "";
  for (let c = 0; c < 256; c++) {
    if (!m[c]) continue;
    let e = c;
    while (e + 1 < 256 && m[e + 1]) e++;
    body += e === c ? hex2(c) : hex2(c) + "-" + hex2(e);
    c = e;
  }
  return "[" + body + "]";
}

// One byte as a RegExp literal.
function literal(c: number): string {
  const ch = String.fromCharCode(c);
  return /[A-Za-z0-9_\/]/.test(ch) ? ch : hex2(c);
}

/**
 * `s` as Lua sees it: one character (U+0000..U+00FF) per UTF-8 byte. Lua
 * patterns work on bytes, so a subject goes through this before a RegExp from
 * luaPatternToRegExp is tested on it: `.` and a set then take one byte, as in
 * Lua, and U+2028 is three of them. ASCII comes back as it is.
 */
export function luaBytes(s: string): string {
  return byteString(s);
}

/**
 * Lua pattern -> RegExp, as string.find reads the pattern (lstrlib): '^'
 * anchors only as the first character and '$' only as the last, anywhere
 * else each is a literal; a single-char class is a literal, '.', a %-class
 * (every Lua class, upper case the complement, any other character after
 * '%' itself) or a [...] set, and only a single-char class takes a
 * quantifier ('*', '+', '?', and '-', Lua's lazy '*?'): a quantifier
 * character anywhere else (first, after '(' or ')') is a literal, so Lua's
 * '(b)?c' is a capture and a literal '?'. %f[set] is the frontier, the edges
 * of the subject counting as \0. %b and the back-references %1-%9 have no
 * translation and throw, so resolve() refuses them at load time. The RegExp
 * matches bytes, as Lua does: the pattern is translated from its UTF-8 bytes,
 * every class is spelled out over the 256 byte values, and the subject must
 * be passed through luaBytes (pathMatches does), so '.' is any one byte, line
 * terminators included.
 */
const luaPatternCache = new Map<string, RegExp>();
export function luaPatternToRegExp(pattern: string): RegExp {
  const hit = luaPatternCache.get(pattern);
  if (hit) return hit;
  const perr = patternError(pattern);
  if (perr) throw new Error(`malformed Lua pattern ${pattern}: ${perr}`);
  const p = luaBytes(pattern);
  const n = p.length;
  let out = "";
  let i = 0;
  if (p[0] === "^") {
    out += "^";
    i = 1;
  }
  while (i < n) {
    const c = p[i];
    if (c === "(" || c === ")") {
      out += c; // '()' is Lua's position capture: an empty group matches the same
      i++;
      continue;
    }
    if (c === "$" && i + 1 === n) {
      out += "$";
      i++;
      continue;
    }
    let m: Bytes;
    let next: number;
    if (c === "%") {
      const k = p[i + 1];
      if (k === "b") throw new Error("%b (balanced match) is not supported on this adapter");
      if (k >= "0" && k <= "9") throw new Error(`back-reference %${k} is not supported on this adapter`);
      if (k === "f") {
        const [f, after] = setMembers(p, i + 2);
        const not = f.map((x) => !x);
        // the character before is not in the set and the one here is; past
        // either edge of the subject Lua reads \0
        out += f[0] ? `(?<=${classOf(not)})` : `(?<!${classOf(f)})`;
        out += f[0] ? `(?!${classOf(not)})` : `(?=${classOf(f)})`;
        i = after;
        continue;
      }
      const cl = p.charCodeAt(i + 1);
      m = members((x) => matchClass(x, cl));
      next = i + 2;
    } else if (c === "[") {
      [m, next] = setMembers(p, i);
    } else if (c === ".") {
      m = members(() => true);
      next = i + 1;
    } else {
      m = members((x) => x === p.charCodeAt(i));
      next = i + 1;
    }
    const count = m.reduce((k, x) => k + (x ? 1 : 0), 0);
    let atom = count === 1 ? literal(m.indexOf(true)) : classOf(m);
    const q = p[next];
    if (q === "*" || q === "+" || q === "?") {
      atom += q;
      next++;
    } else if (q === "-") {
      atom += "*?";
      next++;
    }
    out += atom;
    i = next;
  }
  const re = new RegExp(out);
  luaPatternCache.set(pattern, re);
  return re;
}

/** Why a watch path cannot be matched on this adapter (luaPatternToRegExp
 *  throws for it), in the form pathMatches uses; null when it can. */
export function pathPatternError(pattern: string, caseSensitive?: boolean): string | null {
  try {
    luaPatternToRegExp(caseSensitive === true ? pattern : foldPattern(pattern));
    return null;
  } catch (e) {
    return e instanceof Error ? e.message : String(e);
  }
}

// Port of canonical_path() in core/rules.lua: watch paths match the path the
// backend routes on. `;` parameters leave every segment (Tomcat, Jetty and
// Spring route /v1;a=b/chat/completions as /v1/chat/completions), then empty
// and `.` segments go and `..` is resolved; ASCII letters are folded unless
// the rule matches case-sensitively (Express, Koa, ASP.NET Core and Fiber
// route /V1/Chat/Completions to /v1/chat/completions). ASCII only, as in Lua:
// toLowerCase() would fold other letters too.
const asciiLower = (s: string): string => s.replace(/[A-Z]/g, (c) => String.fromCharCode(c.charCodeAt(0) + 32));

export function canonicalPath(path: string, caseSensitive = false): string {
  let p = path.replace(/;[^/]*/g, "");
  if (p.includes("//") || p.includes("/.")) {
    const out: string[] = [];
    for (const seg of p.split("/")) {
      if (seg === "" || seg === ".") continue;
      if (seg === "..") out.pop();
      else out.push(seg);
    }
    let q = "/" + out.join("/");
    if (p.endsWith("/") && q !== "/") q += "/";
    p = q;
  }
  return caseSensitive ? p : asciiLower(p);
}

// the pattern folded the same way; a letter after `%` names a class (%S, %W)
// and keeps its case
const foldedPatterns = new Map<string, string>();
function foldPattern(p: string): string {
  let f = foldedPatterns.get(p);
  if (f === undefined) {
    f = p.replace(/%?[\s\S]/g, (t) => (t.length === 1 ? asciiLower(t) : t));
    foldedPatterns.set(p, f);
  }
  return f;
}

/**
 * Port of rules.path_matches: the first of `patterns` (a rule's watch_paths)
 * that matches `path`, or null. Every place that decides whether a rule
 * watches a path uses this one, so reading the body and judging it agree.
 * `caseSensitive` is the rule's paths_case_sensitive.
 */
export function pathMatches(path: string, patterns: string[] | undefined, caseSensitive?: boolean): string | null {
  if (!patterns || patterns.length === 0) return null;
  const cs = caseSensitive === true;
  const s = luaBytes(canonicalPath(path ?? "", cs));
  for (const p of patterns) {
    if (luaPatternToRegExp(cs ? p : foldPattern(p)).test(s)) return p;
  }
  return null;
}

// Port of text_matches() in core/rules.lua. Every pattern is run and its
// matches walked, and the latest MAX_SPANS spans in the text are kept: the
// first pattern's first match alone let a harmless decoy before the attack
// take the window's hit half, and the attack was cut out of the judged text.
// After WALK matches of one pattern the walk skips halfway to the end of the
// text (the later matches are the ones kept), so a text full of matches
// costs a bounded number of calls. Returns the first pattern in list order
// that matched (the reason names it) and the spans, at most MAX_SPANS, the
// latest in the text, in text order (none when no match gave a span). A
// matcher that throws counts that pattern as a hit with no span, logged once
// per pattern: the prefilter fails toward judging, never into a silent miss.
export const MAX_SPANS = 8;
const WALK = 64;
type Span = [number, number];
let warned = false;
const badPatterns = new Set<string>();
function textMatches(s: string, patterns: string[] | undefined, ctx: RulesCtx | undefined): [string, Span[]?] | null {
  if (!patterns || patterns.length === 0) return null;
  const reFind = ctx?.re_find;
  if (!reFind) {
    if (!warned && ctx?.log) {
      warned = true;
      ctx.log("warn", "jev-edge: ctx.re_find not provided; always_suspect prefilter disabled");
    }
    return null;
  }
  const n = byteLength(s);
  let hit: string | undefined;
  const all: Span[] = [];
  for (const p of patterns) {
    const mine: Span[] = [];
    let init = 1;
    let walked = 0;
    while (init <= n) {
      let r: ReturnType<NonNullable<RulesCtx["re_find"]>>;
      try {
        r = reFind(s, p, init);
      } catch (e) {
        // a pattern the engine refuses, or a match it cannot finish, is a
        // hit (as a failed ngx.re.find is in Lua), and the operator hears
        // about it once
        if (!badPatterns.has(p)) {
          badPatterns.add(p);
          const msg = `jev-edge: always_suspect pattern ${p} failed (${e instanceof Error ? e.message : String(e)}); it counts as a hit`;
          if (ctx?.log) ctx.log("warn", msg);
          else console.warn(msg);
        }
        hit ??= p;
        break;
      }
      if (!r) break;
      hit ??= p;
      if (!Array.isArray(r) || typeof r[0] !== "number" || typeof r[1] !== "number" || r[0] < init) break;
      mine.push([r[0], r[1]]);
      if (mine.length > MAX_SPANS) mine.shift();
      init = Math.max(r[0], r[1]) + 1;
      walked++;
      if (walked % WALK === 0) init = Math.max(init, Math.floor((init + n) / 2));
    }
    all.push(...mine);
  }
  if (hit === undefined) return null;
  if (all.length === 0) return [hit];
  all.sort((a, b) => a[0] - b[0] || a[1] - b[1]);
  return [hit, all.slice(-MAX_SPANS)];
}

/** Port of rules.content_type: the Content-Type as one string; a repeated
 *  header's values are joined so it is watched when any of them is. */
export function contentType(headers: Req["headers"]): string {
  if (!headers || typeof headers !== "object") return "";
  let ct: unknown = headers["content-type"];
  if (ct === undefined || ct === null) ct = headers["Content-Type"];
  if (Array.isArray(ct)) ct = ct.filter((v) => typeof v === "string").join(", ");
  return typeof ct === "string" ? ct : "";
}

/** Port of rules.content_encoding: the codings, lowercased, without "identity"; "" when none. */
export function contentEncoding(headers: Req["headers"]): string {
  if (!headers || typeof headers !== "object") return "";
  let ce: unknown = headers["content-encoding"];
  if (ce === undefined || ce === null) ce = headers["Content-Encoding"];
  if (Array.isArray(ce)) ce = ce.join(",");
  if (typeof ce !== "string") return "";
  return (ce.toLowerCase().match(/[^,\s]+/g) ?? []).filter((t) => t !== "identity").join(", ");
}

// Port of ct_watched() in core/rules.lua: true when the rule reads this
// content type, false when its allow list leaves it out, "media" when every
// value is a skip_content_types entry. The client picks the header and Ollama
// and llama.cpp parse JSON whatever it says, so the body is still read and
// only one that really is binary is skipped (judged()).
function ctWatched(ct: string, rule: Rule): boolean | "media" {
  const c = ct.toLowerCase();
  const allowed = rule.content_types;
  if (allowed && allowed.length > 0) {
    for (const a of allowed) if (c.includes(a)) return true;
    return false;
  }
  // deny list: watched unless every value of the header is a skipped type
  const skip = rule.skip_content_types ?? SKIP_CONTENT_TYPES;
  let any = false;
  for (const raw of c.split(",")) {
    const v = trim(raw);
    if (v === "") continue;
    any = true;
    if (!skip.some((sk) => v.startsWith(sk))) return true;
  }
  return !any || "media";
}

const CT_NOT_WATCHED = "content-type not watched";

// The body's size as core counts it: the larger of what the adapter declared
// and what it handed over (bytes as read, like Lua's #body: body_bytes when
// the adapter gave it).
function bodySize(req: Req): number {
  const declared = Number(req.body_size);
  const given = typeof req.body !== "string" ? 0 : typeof req.body_bytes === "number" ? req.body_bytes : byteLength(req.body);
  return Math.max(Number.isFinite(declared) ? declared : 0, given);
}

// Port of json_only_miss() in core/rules.lua: a json_only_paths path is
// watched only for a JSON body, one extract() reads as JSON ("json") or
// declared JSON the decoder refused whose text fields the scanner found
// ("scan"). A body extract() cannot read (past max_body_bytes, still
// encoded, empty) is decided on its first byte or JSON media type (jsonLike
// on the head the adapter kept); with no body at all, on the Content-Type
// alone. A site's own POST to TGI's root passes. Returns the extraction when
// it ran, for judged() to reuse. (Lua also falls back to the first byte when
// ctx has no json_decode; extract() here always has one.)
type Extraction = ReturnType<typeof extract>;
const NOT_JSON = "path not watched: body not JSON";
function jsonOnlyMiss(req: Req, rule: Rule, ct: string, ctx: RulesCtx | undefined): [boolean, Extraction?] {
  const jo = rule.json_only_paths;
  if (!Array.isArray(jo) || jo.length === 0 || !pathMatches(req.path ?? "", jo, rule.paths_case_sensitive)) return [false];
  const body = req.body;
  if (typeof body !== "string" || body === "" || bodySize(req) > (rule.max_body_bytes ?? MAX_BODY_BYTES)
    || (contentEncoding(req.headers) !== "" && !req.decoded)) {
    return [!jsonLike(req.body_head ?? body, ct)];
  }
  const ex = extract(body, ct, rule.text_fields, ctx?.json_decode);
  return [ex[1] !== "json" && ex[1] !== "scan", ex];
}

// PCRE without UTF (ngx.re "ijo", lrexlib) reads the pattern and the
// subject as bytes. Both run here as one code unit per UTF-8 byte: ASCII as
// it is, and a byte 0x80-0xFF as U+E080-U+E0FF (pcreBytes), code points with
// no case mapping, so the 'i' flag folds ASCII letters alone, as PCRE's
// C-locale tables do. (As U+0080-U+00FF, 'i' would fold U+00C3 with U+00E3,
// and a pattern 'é', C3 A9, would match the lead bytes of a CJK character.)
const PCRE_HIGH = 0xe000;
function pcreBytes(s: string): string {
  if (!/[^\x00-\x7f]/.test(s)) return s;
  const b = utf8Bytes(s);
  const u = new Uint16Array(b.length);
  for (let i = 0; i < b.length; i++) u[i] = b[i] < 0x80 ? b[i] : PCRE_HIGH + b[i];
  let out = "";
  for (let i = 0; i < u.length; i += 8192) out += String.fromCharCode(...u.subarray(i, i + 8192));
  return out;
}

// A byte value as a RegExp escape for the code unit pcreBytes gives it.
function byteEscape(b: number): string {
  return b < 0x80 ? "\\x" + b.toString(16).padStart(2, "0") : "\\u" + (PCRE_HIGH + b).toString(16);
}

// PCRE's \s without UTF or UCP: the six ASCII spaces only; and its complement
// spelled out over the 256 byte values, for use inside a class.
const PCRE_SPACE = "\\t\\n\\v\\f\\r ";
const PCRE_NOT_SPACE = "\\x00-\\x08\\x0e-\\x1f\\x21-\\x7f" + byteEscape(0x80) + "-" + byteEscape(0xff);

/**
 * A PCRE pattern as a RegExp that matches a subject converted by pcreBytes
 * the way PCRE without the UTF flag matches bytes. The pattern goes through
 * pcreBytes too, so a non-ASCII literal is its bytes, in a class and under a
 * quantifier as PCRE reads it, and a hex escape (\xhh, \x{hh}) names a byte
 * (past \xff it is refused, as PCRE refuses it). `\s` and `\S` are the ASCII
 * spaces and the rest, in a class too (JS's `\s` also takes U+00A0, U+3000
 * and more), `.` is any byte but \n (JS's stops at \r too), and a ']' first
 * in a class is a member, as in PCRE. `\w`, `\d` and `\b` are ASCII in both
 * already, and other syntax is left as it is.
 */
export function pcreToRegExp(pattern: string, flags = "i"): RegExp {
  const p = pcreBytes(pattern);
  let out = "";
  let inClass = false;
  for (let i = 0; i < p.length; i++) {
    const c = p[i];
    if (c === "\\") {
      const d = p[i + 1];
      i++;
      if (d === "s") out += inClass ? PCRE_SPACE : "[" + PCRE_SPACE + "]";
      else if (d === "S") out += inClass ? PCRE_NOT_SPACE : "[^" + PCRE_SPACE + "]";
      else if (d === "x") {
        // \xhh (one or two hex digits) or \x{h...}; PCRE2 refuses the rest
        const m = /^\{([0-9a-fA-F]+)\}/.exec(p.slice(i + 1)) ?? /^([0-9a-fA-F]{1,2})/.exec(p.slice(i + 1));
        if (!m) throw new SyntaxError(`digits missing after \\x: ${pattern}`);
        const v = parseInt(m[1], 16);
        if (v > 0xff) throw new SyntaxError(`character code point value in \\x{} is too large: ${pattern}`);
        i += m[0].length;
        out += byteEscape(v);
      } else if (d === undefined) out += "\\";
      else out += "\\" + d;
    } else if (inClass) {
      if (c === "]") inClass = false;
      out += c;
    } else if (c === "[") {
      inClass = true;
      out += c;
      if (p[i + 1] === "^") out += p[++i];
      // a ']' first in the class is a member in PCRE; JS would close it
      if (p[i + 1] === "]") {
        out += "\\]";
        i++;
      }
    } else if (c === ".") {
      out += "[^\\n]";
    } else {
      out += c;
    }
  }
  return new RegExp(out, flags);
}

/**
 * Case-insensitive regex search with the same contract the OpenResty adapter
 * gives core (ngx.re.find with "ijo": PCRE without UTF): the 1-based
 * inclusive UTF-8 byte span of the first match at or after byte `init` (1
 * when undefined). The pattern runs over the
 * subject's bytes (pcreBytes, pcreToRegExp), so `.`, `\b` and `{m,n}` count
 * bytes as PCRE does, and the match index is the byte offset.
 */
const reCache = new Map<string, RegExp>();
let lastSubject: string | undefined;
let lastBytes = "";
export function reFind(subject: string, pattern: string, init?: number): readonly [number, number] | null {
  let re = reCache.get(pattern);
  if (!re) {
    re = pcreToRegExp(pattern, "gi");
    reCache.set(pattern, re);
  }
  // every always_suspect pattern runs over the same text: convert it once
  if (subject !== lastSubject) {
    lastSubject = subject;
    lastBytes = pcreBytes(subject);
  }
  // the search starts at byte init, as ngx.re.find's ctx.pos
  re.lastIndex = init !== undefined && init > 1 ? init - 1 : 0;
  const m = re.exec(lastBytes);
  if (!m) return null;
  return [m.index + 1, m.index + m[0].length];
}

const untrustedOn = (rule: Rule, ctx: RulesCtx | undefined) => untrustedSpec(ctx?.config, rule).enabled === true;

// Port of untrusted_part() in core/rules.lua: retrieved content when untrusted
// judging is on for `rule`, from a body parsed whole, cut to its own window;
// true when a walk bound left some of it unread (the part is a window); and
// the values read, whole, when untrusted judging is on and the body was parsed.
function untrustedPart(
  decoded: JsonValue | undefined, rule: Rule, ctx: RulesCtx | undefined,
): [UntrustedPart | undefined, boolean, string[] | undefined] {
  const spec = untrustedSpec(ctx?.config, rule);
  if (!spec.enabled || decoded === undefined || decoded === null || typeof decoded !== "object") return [undefined, false, undefined];
  const [values, capped] = extractUntrusted(decoded, spec, ctx?.json_decode);
  const utext = values.join("\n");
  if (utext === "") return [undefined, capped, values];
  const [w, cut] = window(utext, values, rule.max_judge_bytes ?? MAX_JUDGE_BYTES);
  return [{ text: w, windowed: cut || capped }, capped, values];
}

// Port of holds_retrieved() in core/rules.lua: with untrusted judging on,
// true when the text's values hold retrieved content (one of `uvalues`, or
// some of it went unread and may be there); its score is then not the
// subject's own, and reputation charges none of it.
function holdsRetrieved(values: string[], uvalues: string[], ucut: boolean): boolean {
  if (ucut) return true;
  const seen = new Set(uvalues.filter((v) => v !== ""));
  if (seen.size === 0) return false;
  return values.some((v) => seen.has(v));
}

// Port of tools_part() in core/rules.lua: the tool definitions the model
// reads, judged as their own part: all of them scanned by always_suspect, cut
// to one window of their own. `cut`: a bound, the body's size or JSON the
// decoder refused (scanned, not walked) left some out.
function toolsPart(values: string[], cut: boolean, rule: Rule, ctx: RulesCtx | undefined): ToolsPart | undefined {
  const ttext = values.join("\n");
  if (ttext === "") return undefined;
  const hit = textMatches(ttext, rule.always_suspect, ctx);
  const [w, windowed] = window(ttext, values, rule.max_judge_bytes ?? MAX_JUDGE_BYTES, hit?.[1]);
  return { text: w, windowed: windowed || cut, hit: hit?.[0] };
}

const hasToolFields = (rule: Rule) => Array.isArray(rule.tool_fields) && rule.tool_fields.length > 0;

type Judged = {
  text: string; unj?: string; hit?: string; windowed?: boolean; chunks?: string[]; capped?: boolean;
  untrusted?: UntrustedPart; tools?: ToolsPart;
  /** a walk bound left text fields or tool definitions unread */
  bound?: boolean;
  /** untrusted judging is on and the text holds retrieved content (holdsRetrieved, or it was scanned) */
  retrieved?: boolean;
  /** a text field holds token ids */
  ids?: boolean;
};

/** Port of rules.TOKEN_REASON: a prompt given as token ids, text L1 has none of. */
export const TOKEN_REASON = "unjudgeable: token ids";

/**
 * Port of rules.token_prompts: what a request whose prompt holds token ids
 * gets under `rule`, the rule's token_prompts or policy.unjudgeable.
 */
export function tokenPrompts(rule: Pick<Rule, "token_prompts"> | undefined, pol: { unjudgeable?: string } | undefined): string {
  return rule?.token_prompts ?? pol?.unjudgeable ?? "pass";
}

// Port of judged() in core/rules.lua. `ex`: the body's extraction
// jsonOnlyMiss already has, or undefined.
async function judged(
  req: Req, rule: Rule, ctx: RulesCtx | undefined, ct: string, size: number, ex?: Extraction,
): Promise<Judged> {
  const max = rule.max_body_bytes ?? MAX_BODY_BYTES;
  // a media type is taken at its word only when the bytes agree (or there
  // are none to look at): anything that reads as JSON or text is judged
  const media = ctWatched(ct, rule) === "media";
  let values: string[];
  let text: string;
  let partial = false;
  let bound = false;
  let retrieved = false;
  let ids = false;
  let untrusted: UntrustedPart | undefined;
  let tools: ToolsPart | undefined;
  // the gateway in front forwarded only the first part of the body: what the
  // adapter has is a head, whatever its size, never a whole document
  const gatewayCut = req.body_partial === true;
  if (gatewayCut && size <= max) size = max + 1;
  if (size > max) {
    let hd = req.body_head ?? undefined;
    let tl = req.body_tail ?? undefined;
    // the body fits in its head and tail: the tail starts where the head
    // ends, and a value cut between them is read whole
    let joined = size <= max + TAIL_BYTES;
    if (hd === undefined && typeof req.body === "string") {
      hd = head(req.body, max);
      const rest = req.body.slice(hd.length);
      if (rest !== "") tl = joined ? rest : tail(rest, TAIL_BYTES);
    }
    if (media && !(hd !== undefined && isText(hd))) return { text: "", unj: CT_NOT_WATCHED };
    if (hd === undefined) return { text: "", unj: "unjudgeable: body too large" };
    // policy.partial = "unjudgeable": the part the gateway cut off counts as
    // unread, and policy.unjudgeable decides
    if (gatewayCut && ctx?.config?.policy?.partial === "unjudgeable") return { text: "", unj: "unjudgeable: partial body" };
    const keys = fieldKeys(rule.text_fields);
    const deep = deepKeys(rule.text_fields);
    const seen: { tokenIds?: boolean } = {};
    // head and tail joined are one string to scan; apart, the tail starts
    // inside a value it has only the end of (g1-chunk-seams-window-math#6)
    joined = joined && tl !== undefined;
    if (joined) {
      values = scanStrings(hd + tl, keys, [], deep, seen);
    } else {
      values = scanStrings(hd, keys, [], deep, seen);
      if (tl !== undefined) scanStrings(tl, keys, values, deep, seen, { tail: true });
    }
    ids = seen.tokenIds === true;
    if (values.length === 0) return { text: "", unj: ids ? TOKEN_REASON : "unjudgeable: body too large" };
    text = values.join("\n");
    partial = true;
    retrieved = untrustedOn(rule, ctx);
    if (hasToolFields(rule)) {
      const tkeys = fieldKeys(rule.tool_fields);
      const tvalues = scanTools(joined ? hd + tl : hd, tkeys, []);
      if (tl !== undefined && !joined) scanTools(tl, tkeys, tvalues);
      tools = toolsPart(tvalues, true, rule, ctx);
    }
  } else {
    let kind: string;
    let decoded: JsonValue | undefined;
    let cut: boolean | undefined;
    let tok: boolean | undefined;
    [text, kind, values, decoded, cut, tok] = ex ?? extract(req.body, ct, rule.text_fields, ctx?.json_decode);
    ids = tok === true;
    if (media && (kind === "binary" || kind === "none")) return { text: "", unj: CT_NOT_WATCHED };
    if (kind === "binary") return { text: "", unj: "unjudgeable: binary body" };
    if (kind === "boundaries") return { text: "", unj: "unjudgeable: multipart boundaries" };
    // declared JSON the decoder refused, with no text-field value to scan
    if (kind === "invalid") return { text: "", unj: ids ? TOKEN_REASON : "unjudgeable: invalid json" };
    // a "**" field hit its bound: the text is not all there
    if (cut) partial = bound = true;
    let ucut: boolean;
    let uvalues: string[] | undefined;
    [untrusted, ucut, uvalues] = untrustedPart(decoded, rule, ctx);
    if (ucut) bound = true;
    if (uvalues) retrieved = holdsRetrieved(values, uvalues, ucut);
    else if (kind === "scan") retrieved = untrustedOn(rule, ctx);
    if (hasToolFields(rule) && decoded !== undefined && decoded !== null && typeof decoded === "object") {
      const [tvalues, tcut] = extractTools(decoded, rule.tool_fields, ctx?.json_decode);
      tools = toolsPart(tvalues, tcut, rule, ctx);
      if (tcut) bound = true;
    } else if (hasToolFields(rule) && kind === "scan") {
      // JSON the decoder refused (nesting past 1000, bytes after the
      // value), declared or not, which the backend's parser may take:
      // scanned for the tool definitions as past max_body_bytes
      tools = toolsPart(scanTools(req.body as string, fieldKeys(rule.tool_fields), []), true, rule, ctx);
    }
  }
  if (text === "") return { text: "", untrusted, tools, bound, ids };
  const hit = textMatches(text, rule.always_suspect, ctx);
  const budget = rule.max_judge_bytes ?? MAX_JUDGE_BYTES;
  const maxc = Math.floor(Number(rule.max_judge_chunks ?? 1)) || 1;
  if (maxc > 1 && byteLength(text) > budget) {
    // port of the chunked branch of judged() in core/rules.lua: consecutive
    // chunks share chunkOverlap bytes; text up to budget + (maxc - 1) x
    // (budget - overlap) bytes is judged in full (cut hard when the newline
    // cuts take more than maxc pieces), longer text is capped
    const overlap = chunkOverlap(budget);
    const capacity = budget + (maxc - 1) * (budget - overlap);
    const textLen = byteLength(text);
    let [pieces, starts] = splitChunks(text, budget, overlap);
    if (pieces.length > maxc && textLen <= capacity) [pieces, starts] = splitChunks(text, budget, overlap, true);
    let out = pieces;
    let capped = false;
    const covered: Span[] = [];
    const spans = hit?.[1] ?? [];
    if (pieces.length <= maxc) {
      for (let k = 0; k < pieces.length; k++) covered.push([starts[k], starts[k] + byteLength(pieces[k]) - 1]);
    } else {
      const firstKept = pieces.length - (maxc - 1); // 0-based
      const tb = utf8Bytes(text);
      let older = new TextDecoder().decode(tb.subarray(0, starts[firstKept] - 1));
      if (older.endsWith("\n")) older = older.slice(0, -1);
      const olderLen = byteLength(older);
      const inside = spans.filter(([, z]) => z <= olderLen);
      const [win] = window(older, [older], budget, inside);
      out = [win];
      capped = true;
      // the window holds the hits that were inside what it covers
      covered.push(...inside);
      for (let k = firstKept; k < pieces.length; k++) {
        out.push(pieces[k]);
        covered.push([starts[k], starts[k] + byteLength(pieces[k]) - 1]);
      }
    }
    // backstop: a hit longer than the overlap can still straddle a cut;
    // such hits and up to HIT_CONTEXT bytes each side are judged as a part
    // of their own, the way window() keeps them
    const straddle = spans.filter(([f, t]) => !covered.some(([a, z]) => a <= f && t <= z));
    if (straddle.length > 0) out = [window(text, [], budget, straddle)[0], ...out];
    return { text: out.join("\n"), hit: hit?.[0], windowed: capped || partial, chunks: out, capped, untrusted, tools, bound, retrieved, ids };
  }
  const [w, cut] = window(text, values, budget, hit?.[1]);
  return { text: w, hit: hit?.[0], windowed: cut || partial, untrusted, tools, bound, retrieved, ids };
}

// Port of BOUND_REASON: a request the walk bounds cut and that would
// otherwise pass unjudged for lack of text.
const BOUND_REASON = "unjudgeable: json over the walk bounds";

/** Port of rules.judged_text: the text evaluate() judges under `rule`, in one window ("" when none); only the text, not the parts. */
export async function judgedText(req: Req, rule: Rule | undefined, ctx?: RulesCtx): Promise<string> {
  if (!rule || !req) return "";
  const size = bodySize(req);
  // one window, never chunks
  const ct = contentType(req.headers);
  const [miss, ex] = jsonOnlyMiss(req, rule, ct, ctx);
  if (miss) return "";
  const r = await judged(req, { ...rule, max_judge_chunks: 1 }, ctx, ct, size, ex);
  return r.text;
}

// Port of ip_rep_on in core/rules.lua: does the evaluating config block by
// IP reputation? true when there is no config to ask (rules-only callers).
function ipRepOn(ctx: RulesCtx): boolean {
  const cfg = ctx.config;
  if (typeof cfg !== "object" || cfg === null) return true;
  const v = cfg.async?.rep_block_after;
  const n = typeof v === "number" || typeof v === "string" ? Number(v) : 0;
  return (Number.isNaN(n) ? 0 : n) > 0;
}

/** Port of rules.ip_key: the key IP reputation counts `ip` under (rep:<key>) and subject.from = "ip" hashes: IPv6 aggregated to cfg.client_ip.ipv6_prefix bits (64 when unset). */
export function ipKey(ip: string, cfg?: { client_ip?: { ipv6_prefix?: number } } | null): string {
  return normalizeIpKey(ip, cfg?.client_ip?.ipv6_prefix);
}

/** The result, text, reason, windowed, chunks, capped, untrusted, tools, and retrieved (see rules.evaluate in core/rules.lua). */
export async function evaluate(
  req: Req, rule: Rule, ctx?: RulesCtx,
): Promise<[RuleResult, string, string, boolean?, string[]?, boolean?, UntrustedPart?, ToolsPart?, boolean?]> {
  // 1. path watch list; a json_only_paths path only for a JSON body (what
  //    extract() reads it as, or the Content-Type when there is no body)
  if (!pathMatches(req.path ?? "", rule.watch_paths, rule.paths_case_sensitive)) return [PASS, "", "path not watched"];
  const ct = contentType(req.headers);
  const [miss, ex] = jsonOnlyMiss(req, rule, ct, ctx);
  if (miss) return [PASS, "", NOT_JSON];

  // 2. reputation, before anything that needs a body. It only ever blocks:
  //    safe verdicts earn an IP nothing (see core/rules.lua); and only under
  //    a config that blocks by IP (async.rep_block_after > 0), since the rep:
  //    records are shared by every route on the store
  if (ctx?.cache && req.client_ip && ipRepOn(ctx)) {
    const rep = (await ctx.cache.get("rep:" + ipKey(req.client_ip, ctx.config))) as { blocked_until?: number } | undefined;
    if (rep && typeof rep === "object") {
      const now = ctx.clock ? ctx.clock() : 0;
      if (rep.blocked_until !== undefined && rep.blocked_until > now) return [BLOCK, "", "ip reputation"];
    }
  }
  // the same for the subject (core/subject.lua), when reputation is on
  if (ctx?.subject && (await repBlocked(ctx))) return [BLOCK, "", "subject reputation"];

  // 3. method + content type (an allow list when the rule lists
  //    content_types; the deny list of media types is only settled once the
  //    body shows it is binary, in step 6)
  if (rule.methods && !rule.methods[(req.method ?? "").toUpperCase()]) return [PASS, "", "method not watched"];
  if (!ctWatched(ct, rule)) return [PASS, "", CT_NOT_WATCHED];

  // 4. body size: the larger of what the adapter declared and what it handed
  //    over, so a wrong or missing Content-Length cannot shrink the body
  //    (bytes, like Lua's #body).
  const size = bodySize(req);
  if (size === 0 && (req.body === undefined || req.body === null) && (req.body_head === undefined || req.body_head === null)) {
    return [PASS, "", "no body"];
  }
  if (size < (rule.min_body_bytes ?? 8)) return [PASS, "", "body too small"];

  // 5. an encoded body is only readable once the adapter decoded it
  const ce = contentEncoding(req.headers);
  if (ce !== "" && !req.decoded) return [UNJUDGEABLE, "", "unjudgeable: content-encoding " + ce];

  // 6+7. extract, prefilter over all of it, judging window, length
  const j = await judged(req, rule, ctx, ct, size, ex);
  if (j.unj === CT_NOT_WATCHED) return [PASS, "", j.unj];
  if (j.unj) return [UNJUDGEABLE, "", j.unj];
  // token ids: whatever else the body holds, when the rule (or
  // policy.unjudgeable) says to block them
  if (j.ids && tokenPrompts(rule, ctx?.config?.policy) === "block") return [UNJUDGEABLE, "", TOKEN_REASON];
  const minChars = rule.min_text_chars ?? 20;
  // retrieved content is judged on its own when there is enough of it, even
  // beside a short message or none (an untrusted.fields value outside text_fields)
  let u = j.untrusted;
  if (u && byteLength(u.text) < minChars) u = undefined;
  // so are the tool definitions, and short ones an always_suspect pattern hit
  let t = j.tools;
  if (t && !t.hit && byteLength(t.text) < minChars) t = undefined;
  // token ids with nothing else to judge are unjudgeable, never "no text";
  // beside text (or parts) enough to judge, that is judged
  if (j.text === "" && !u && !t) {
    if (j.ids) return [UNJUDGEABLE, "", TOKEN_REASON];
    return j.bound ? [UNJUDGEABLE, "", BOUND_REASON] : [PASS, "", "no text"];
  }
  const judgedToo = !!j.hit || byteLength(j.text) >= minChars;
  if (!judgedToo) {
    if (!u && !t) {
      if (j.ids) return [UNJUDGEABLE, "", TOKEN_REASON];
      return j.bound ? [UNJUDGEABLE, "", BOUND_REASON] : [PASS, "", "text too short"];
    }
    // the text alone would have passed: only the retrieved content and the
    // tool definitions are judged
    if (u) u.only = true;
    if (t) t.only = true;
  }
  // a walk bound cut what is judged: the reason says so, as for any window
  const windowed = j.windowed || j.bound;
  let tag = windowed ? " (window)" : "";
  if (j.chunks && !j.capped) tag = ` (${j.chunks.length} chunks${windowed ? ", window" : ""})`;
  let why: string;
  if (j.hit) why = "pattern: " + j.hit + tag;
  else if (t?.hit) why = "pattern: " + t.hit + " (tools" + (t.windowed ? ", window" : "") + ")";
  else if (judgedToo) why = "natural language" + tag;
  else if (u) why = "retrieved content" + (u.windowed ? " (window)" : "");
  else why = "tool definitions" + (t!.windowed ? " (window)" : "");
  return [SUSPECT, j.text, why, windowed, j.chunks, j.capped, u, t, j.retrieved];
}

/**
 * Port of rules.rule_for: the first rule whose path (json_only_paths
 * included), method and content type all match. `ctx.json_decode`, as
 * evaluateAll had it, decides a json_only_paths path (JSON.parse without one).
 */
export function ruleFor(req: Req, rules: Rule[] | undefined, ctx?: Pick<RulesCtx, "json_decode">): Rule | undefined {
  const ct = contentType(req.headers);
  for (const r of rules ?? []) {
    if (pathMatches(req.path ?? "", r.watch_paths, r.paths_case_sensitive)
      && !jsonOnlyMiss(req, r, ct, ctx)[0]
      && !(r.methods && !r.methods[(req.method ?? "").toUpperCase()])
      && ctWatched(ct, r)) return r;
  }
  return undefined;
}

export async function evaluateAll(
  req: Req, rules: Rule[] | undefined, ctx?: RulesCtx,
): Promise<[RuleResult, string, string, Rule | undefined, boolean?, string[]?, boolean?, UntrustedPart?, ToolsPart?, boolean?]> {
  let lastReason = "no rules";
  for (const rule of rules ?? []) {
    const [r, text, reason, windowed, chunks, capped, untrusted, tools, retrieved] = await evaluate(req, rule, ctx);
    if (r !== PASS) return [r, text, reason, rule, windowed, chunks, capped, untrusted, tools, retrieved];
    lastReason = reason;
  }
  return [PASS, "", lastReason, undefined];
}
