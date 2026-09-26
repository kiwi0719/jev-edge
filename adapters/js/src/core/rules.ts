// Port of core/rules.lua: L1, cheap and short-circuiting.
import { extract, extractTools, extractUntrusted, isText, byteLength, head, tail, fieldKeys, deepKeys, scanStrings, scanTools, window, chunks as splitChunks, utf8Bytes, type JsonValue } from "./normalize.js";
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
  /** Lua patterns in the rule files; the subset used (anchors, literals, %-escapes) converts 1:1. */
  watch_paths: string[];
  /** Match watch_paths without folding ASCII case (default: folded, see pathMatches). */
  paths_case_sensitive?: boolean;
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
  body_size?: number;
  client_ip?: string;
  /** Past max_body_bytes: the first bytes and the last bytes (not overlapping) the adapter kept. */
  body_head?: string | null;
  body_tail?: string | null;
  /** true when the adapter decoded the Content-Encoding and `body` is the decoded body. */
  decoded?: boolean;
}

export interface CacheLike {
  get(key: string): unknown | Promise<unknown>;
  set?(key: string, value: unknown, ttl: number): void | Promise<void>;
}

export interface RulesCtx {
  cache?: CacheLike;
  clock?: () => number;
  json_decode?: (s: string) => JsonValue;
  /** Truthy on a match; a [from, to] 1-based inclusive UTF-8 byte span places the hit in the judging window. */
  re_find?: (subject: string, pattern: string) => boolean | readonly [number, number] | null;
  log?: (level: string, msg: string) => void;
  subject?: SubjectCtx;
  config?: { subject?: { reputation?: ReputationConfig }; untrusted?: UntrustedConfig };
}

/**
 * Syntax check for a Lua pattern, ported from core/rules.lua pattern_error():
 * walks the pattern the way lstrlib does and reports what it would raise on
 * some subject. Returns null when the pattern is well formed. Used at rule
 * resolve time so a malformed watch path fails at startup, not per request.
 */
export function patternError(p: string): string | null {
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

const LUA_CLASSES: Record<string, string> = {
  a: "A-Za-z", d: "0-9", s: " \\t\\n\\v\\f\\r", w: "A-Za-z0-9", x: "0-9A-Fa-f", p: "!-/:-@\\[-`{-~",
};

/**
 * Lua pattern -> RegExp for the subset rule files use: ^ $ anchors, literals,
 * %-escaped punctuation, the %a %d %s %w %x %p classes and [...] sets (with
 * those classes and ranges inside). Anything else in a watch path is
 * unsupported on this adapter and throws at load time rather than silently
 * matching differently. `-` is Lua's lazy `*?` outside a set and a plain
 * range/literal inside one.
 */
const luaPatternCache = new Map<string, RegExp>();
export function luaPatternToRegExp(p: string): RegExp {
  const hit = luaPatternCache.get(p);
  if (hit) return hit;
  const perr = patternError(p);
  if (perr) throw new Error(`malformed Lua pattern ${p}: ${perr}`);
  let out = "";
  let i = 0;
  const n = p.length;
  const classFor = (k: string, inSet: boolean): string => {
    const body = LUA_CLASSES[k];
    if (body !== undefined) return inSet ? body : "[" + body + "]";
    if (/[A-Za-z0-9]/.test(k)) throw new Error(`unsupported Lua class %${k} in ${p}`);
    return "\\" + k; // escaped punctuation is a literal in both
  };
  while (i < n) {
    const c = p[i];
    if (c === "%") {
      out += classFor(p[i + 1], false);
      i += 2;
    } else if (c === "[") {
      // copy the set through to its closing ']', translating what is inside
      let j = i + 1;
      let set = "[";
      if (p[j] === "^") { set += "^"; j++; }
      if (p[j] === "]") { set += "\\]"; j++; }
      while (p[j] !== "]") {
        const e = p[j];
        if (e === "%") {
          set += classFor(p[j + 1], true);
          j += 2;
        } else {
          if ("\\[".includes(e)) set += "\\" + e;
          else set += e; // '-' stays a range, '^' inside stays literal for JS too
          j++;
        }
      }
      out += set + "]";
      i = j + 1;
    } else if (c === "-") {
      out += "*?";
      i++;
    } else if ("\\{}|".includes(c)) {
      out += "\\" + c; // literal in Lua, special in JS
      i++;
    } else {
      out += c; // ^ $ . * + ? ( ) mean the same in both for this subset
      i++;
    }
  }
  const re = new RegExp(out);
  luaPatternCache.set(p, re);
  return re;
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
  const s = canonicalPath(path ?? "", cs);
  for (const p of patterns) {
    if (luaPatternToRegExp(cs ? p : foldPattern(p)).test(s)) return p;
  }
  return null;
}

let warned = false;
const badPatterns = new Set<string>();
function textMatches(s: string, patterns: string[] | undefined, ctx: RulesCtx | undefined): [string, number?, number?] | null {
  if (!patterns || patterns.length === 0) return null;
  const reFind = ctx?.re_find;
  if (!reFind) {
    if (!warned && ctx?.log) {
      warned = true;
      ctx.log("warn", "jev-edge: ctx.re_find not provided; always_suspect prefilter disabled");
    }
    return null;
  }
  for (const p of patterns) {
    try {
      const hit = reFind(s, p);
      if (Array.isArray(hit)) return [p, hit[0], hit[1]];
      if (hit) return [p];
    } catch (e) {
      // a pattern the engine rejects is skipped, like pcall in Lua, but an
      // operator should hear about it once instead of losing the prefilter silently
      if (!badPatterns.has(p)) {
        badPatterns.add(p);
        const msg = `jev-edge: always_suspect pattern ${JSON.stringify(p)} does not compile and is skipped: ${e instanceof Error ? e.message : String(e)}`;
        if (ctx?.log) ctx.log("warn", msg);
        else console.warn(msg);
      }
    }
  }
  return null;
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
    const v = raw.replace(/^[ \t\n\v\f\r]+|[ \t\n\v\f\r]+$/g, "");
    if (v === "") continue;
    any = true;
    if (!skip.some((sk) => v.startsWith(sk))) return true;
  }
  return !any || "media";
}

const CT_NOT_WATCHED = "content-type not watched";

/**
 * Case-insensitive regex search with the same contract the OpenResty adapter
 * gives core: the 1-based inclusive UTF-8 byte span of the first match.
 */
const reCache = new Map<string, RegExp>();
export function reFind(subject: string, pattern: string): readonly [number, number] | null {
  let re = reCache.get(pattern);
  if (!re) {
    re = new RegExp(pattern, "i");
    reCache.set(pattern, re);
  }
  const m = re.exec(subject);
  if (!m) return null;
  const from = byteLength(subject.slice(0, m.index)) + 1;
  return [from, from + byteLength(m[0]) - 1];
}

// Port of untrusted_part() in core/rules.lua: retrieved content when untrusted
// judging is on for `rule`, from a body parsed whole, cut to its own window;
// and true when a walk bound left some of it unread (the part is a window).
function untrustedPart(decoded: JsonValue | undefined, rule: Rule, ctx: RulesCtx | undefined): [UntrustedPart | undefined, boolean] {
  const spec = untrustedSpec(ctx?.config, rule);
  if (!spec.enabled || decoded === undefined || decoded === null || typeof decoded !== "object") return [undefined, false];
  const [values, capped] = extractUntrusted(decoded, spec, ctx?.json_decode);
  const utext = values.join("\n");
  if (utext === "") return [undefined, capped];
  const [w, cut] = window(utext, values, rule.max_judge_bytes ?? MAX_JUDGE_BYTES);
  return [{ text: w, windowed: cut || capped }, capped];
}

// Port of tools_part() in core/rules.lua: the tool definitions the model
// reads, judged as their own part: all of them scanned by always_suspect, cut
// to one window of their own. `cut`: a bound, the body's size or JSON the
// decoder refused (scanned, not walked) left some out.
function toolsPart(values: string[], cut: boolean, rule: Rule, ctx: RulesCtx | undefined): ToolsPart | undefined {
  const ttext = values.join("\n");
  if (ttext === "") return undefined;
  const hit = textMatches(ttext, rule.always_suspect, ctx);
  const [w, windowed] = window(ttext, values, rule.max_judge_bytes ?? MAX_JUDGE_BYTES, hit?.[1], hit?.[2]);
  return { text: w, windowed: windowed || cut, hit: hit?.[0] };
}

const hasToolFields = (rule: Rule) => Array.isArray(rule.tool_fields) && rule.tool_fields.length > 0;

type Judged = {
  text: string; unj?: string; hit?: string; windowed?: boolean; chunks?: string[]; capped?: boolean;
  untrusted?: UntrustedPart; tools?: ToolsPart;
  /** a walk bound left text fields or tool definitions unread */
  bound?: boolean;
};

// Port of judged() in core/rules.lua.
async function judged(
  req: Req, rule: Rule, ctx: RulesCtx | undefined, ct: string, size: number,
): Promise<Judged> {
  const max = rule.max_body_bytes ?? MAX_BODY_BYTES;
  // a media type is taken at its word only when the bytes agree (or there
  // are none to look at): anything that reads as JSON or text is judged
  const media = ctWatched(ct, rule) === "media";
  let values: string[];
  let text: string;
  let partial = false;
  let bound = false;
  let untrusted: UntrustedPart | undefined;
  let tools: ToolsPart | undefined;
  if (size > max) {
    let hd = req.body_head ?? undefined;
    let tl = req.body_tail ?? undefined;
    if (hd === undefined && typeof req.body === "string") {
      hd = head(req.body, max);
      const rest = req.body.slice(hd.length);
      if (rest !== "") tl = tail(rest, TAIL_BYTES);
    }
    if (media && !(hd !== undefined && isText(hd))) return { text: "", unj: CT_NOT_WATCHED };
    if (hd === undefined) return { text: "", unj: "unjudgeable: body too large" };
    const keys = fieldKeys(rule.text_fields);
    const deep = deepKeys(rule.text_fields);
    values = scanStrings(hd, keys, [], deep);
    if (tl !== undefined) scanStrings(tl, keys, values, deep);
    if (values.length === 0) return { text: "", unj: "unjudgeable: body too large" };
    text = values.join("\n");
    partial = true;
    if (hasToolFields(rule)) {
      const tkeys = fieldKeys(rule.tool_fields);
      const tvalues = scanTools(hd, tkeys, []);
      if (tl !== undefined) scanTools(tl, tkeys, tvalues);
      tools = toolsPart(tvalues, true, rule, ctx);
    }
  } else {
    let kind: string;
    let decoded: JsonValue | undefined;
    let cut: boolean | undefined;
    [text, kind, values, decoded, cut] = extract(req.body, ct, rule.text_fields, ctx?.json_decode);
    if (media && (kind === "binary" || kind === "none")) return { text: "", unj: CT_NOT_WATCHED };
    if (kind === "binary") return { text: "", unj: "unjudgeable: binary body" };
    // declared JSON the decoder refused, with no text-field value to scan
    if (kind === "invalid") return { text: "", unj: "unjudgeable: invalid json" };
    // a "**" field hit its bound: the text is not all there
    if (cut) partial = bound = true;
    let ucut: boolean;
    [untrusted, ucut] = untrustedPart(decoded, rule, ctx);
    if (ucut) bound = true;
    if (hasToolFields(rule) && decoded !== undefined && decoded !== null && typeof decoded === "object") {
      const [tvalues, tcut] = extractTools(decoded, rule.tool_fields, ctx?.json_decode);
      tools = toolsPart(tvalues, tcut, rule, ctx);
      if (tcut) bound = true;
    } else if (hasToolFields(rule) && kind === "scan") {
      // declared JSON the decoder refused (nesting past 1000, bytes after
      // the value), which the backend's parser may take: scanned for the
      // tool definitions as past max_body_bytes
      tools = toolsPart(scanTools(req.body as string, fieldKeys(rule.tool_fields), []), true, rule, ctx);
    }
  }
  if (text === "") return { text: "", untrusted, tools, bound };
  const hit = textMatches(text, rule.always_suspect, ctx);
  const budget = rule.max_judge_bytes ?? MAX_JUDGE_BYTES;
  const maxc = Math.floor(Number(rule.max_judge_chunks ?? 1)) || 1;
  if (maxc > 1 && byteLength(text) > budget) {
    // port of the chunked branch of judged() in core/rules.lua
    const [pieces, starts] = splitChunks(text, budget);
    if (pieces.length <= maxc) return { text: pieces.join("\n"), hit: hit?.[0], windowed: partial, chunks: pieces, capped: false, untrusted, tools, bound };
    const firstKept = pieces.length - (maxc - 1); // 0-based
    const tb = utf8Bytes(text);
    let older = new TextDecoder().decode(tb.subarray(0, starts[firstKept] - 1));
    if (older.endsWith("\n")) older = older.slice(0, -1);
    const olderLen = byteLength(older);
    const inside = hit?.[1] !== undefined && hit?.[2] !== undefined && hit[2] <= olderLen;
    const [win] = window(older, [older], budget, inside ? hit![1] : undefined, inside ? hit![2] : undefined);
    const out = [win, ...pieces.slice(firstKept)];
    return { text: out.join("\n"), hit: hit?.[0], windowed: true, chunks: out, capped: true, untrusted, tools, bound };
  }
  const [w, cut] = window(text, values, budget, hit?.[1], hit?.[2]);
  return { text: w, hit: hit?.[0], windowed: cut || partial, untrusted, tools, bound };
}

// Port of BOUND_REASON: a request the walk bounds cut and that would
// otherwise pass unjudged for lack of text.
const BOUND_REASON = "unjudgeable: json over the walk bounds";

/** Port of rules.judged_text: the text evaluate() judges under `rule`, in one window ("" when none); only the text, not the parts. */
export async function judgedText(req: Req, rule: Rule | undefined, ctx?: RulesCtx): Promise<string> {
  if (!rule || !req) return "";
  const declared = Number(req.body_size);
  const size = Math.max(Number.isFinite(declared) ? declared : 0, typeof req.body === "string" ? byteLength(req.body) : 0);
  // one window, never chunks
  const r = await judged(req, { ...rule, max_judge_chunks: 1 }, ctx, contentType(req.headers), size);
  return r.text;
}

export async function evaluate(
  req: Req, rule: Rule, ctx?: RulesCtx,
): Promise<[RuleResult, string, string, boolean?, string[]?, boolean?, UntrustedPart?, ToolsPart?]> {
  // 1. path watch list
  if (!pathMatches(req.path ?? "", rule.watch_paths, rule.paths_case_sensitive)) return [PASS, "", "path not watched"];

  // 2. reputation, before anything that needs a body. It only ever blocks:
  //    safe verdicts earn an IP nothing (see core/rules.lua)
  if (ctx?.cache && req.client_ip) {
    const rep = (await ctx.cache.get("rep:" + req.client_ip)) as { blocked_until?: number } | undefined;
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
  const ct = contentType(req.headers);
  if (!ctWatched(ct, rule)) return [PASS, "", CT_NOT_WATCHED];

  // 4. body size: the larger of what the adapter declared and what it handed
  //    over, so a wrong or missing Content-Length cannot shrink the body
  //    (bytes, like Lua's #body).
  const declared = Number(req.body_size);
  const size = Math.max(Number.isFinite(declared) ? declared : 0, typeof req.body === "string" ? byteLength(req.body) : 0);
  if (size === 0 && (req.body === undefined || req.body === null) && (req.body_head === undefined || req.body_head === null)) {
    return [PASS, "", "no body"];
  }
  if (size < (rule.min_body_bytes ?? 8)) return [PASS, "", "body too small"];

  // 5. an encoded body is only readable once the adapter decoded it
  const ce = contentEncoding(req.headers);
  if (ce !== "" && !req.decoded) return [UNJUDGEABLE, "", "unjudgeable: content-encoding " + ce];

  // 6+7. extract, prefilter over all of it, judging window, length
  const j = await judged(req, rule, ctx, ct, size);
  if (j.unj === CT_NOT_WATCHED) return [PASS, "", j.unj];
  if (j.unj) return [UNJUDGEABLE, "", j.unj];
  const minChars = rule.min_text_chars ?? 20;
  // retrieved content is judged on its own when there is enough of it, even
  // beside a short message or none (an untrusted.fields value outside text_fields)
  let u = j.untrusted;
  if (u && byteLength(u.text) < minChars) u = undefined;
  // so are the tool definitions, and short ones an always_suspect pattern hit
  let t = j.tools;
  if (t && !t.hit && byteLength(t.text) < minChars) t = undefined;
  if (j.text === "" && !u && !t) return j.bound ? [UNJUDGEABLE, "", BOUND_REASON] : [PASS, "", "no text"];
  const judgedToo = !!j.hit || byteLength(j.text) >= minChars;
  if (!judgedToo) {
    if (!u && !t) return j.bound ? [UNJUDGEABLE, "", BOUND_REASON] : [PASS, "", "text too short"];
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
  return [SUSPECT, j.text, why, windowed, j.chunks, j.capped, u, t];
}

/** Port of rules.rule_for: the first rule whose path, method and content type all match. */
export function ruleFor(req: Req, rules: Rule[] | undefined): Rule | undefined {
  const ct = contentType(req.headers);
  for (const r of rules ?? []) {
    if (pathMatches(req.path ?? "", r.watch_paths, r.paths_case_sensitive)
      && !(r.methods && !r.methods[(req.method ?? "").toUpperCase()])
      && ctWatched(ct, r)) return r;
  }
  return undefined;
}

export async function evaluateAll(
  req: Req, rules: Rule[] | undefined, ctx?: RulesCtx,
): Promise<[RuleResult, string, string, Rule | undefined, boolean?, string[]?, boolean?, UntrustedPart?, ToolsPart?]> {
  let lastReason = "no rules";
  for (const rule of rules ?? []) {
    const [r, text, reason, windowed, chunks, capped, untrusted, tools] = await evaluate(req, rule, ctx);
    if (r !== PASS) return [r, text, reason, rule, windowed, chunks, capped, untrusted, tools];
    lastReason = reason;
  }
  return [PASS, "", lastReason, undefined];
}
