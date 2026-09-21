// Port of core/rules.lua: L1, cheap and short-circuiting.
import { extract, byteLength, type JsonValue } from "./normalize";

export type RuleResult = "pass" | "block" | "suspect";
export const PASS: RuleResult = "pass";
export const BLOCK: RuleResult = "block";
export const SUSPECT: RuleResult = "suspect";

export interface Rule {
  id: string;
  /** Lua patterns in the rule files; the subset used (anchors, literals, %-escapes) converts 1:1. */
  watch_paths: string[];
  methods?: Record<string, boolean>;
  content_types?: string[];
  min_body_bytes?: number;
  max_body_bytes?: number;
  text_fields: string[];
  min_text_chars?: number;
  always_suspect?: string[];
  templates: string[];
  deployment_context?: string;
}

export interface Req {
  method?: string;
  path?: string;
  headers?: Record<string, string | undefined>;
  body?: string | null;
  body_size?: number;
  client_ip?: string;
}

export interface CacheLike {
  get(key: string): unknown | Promise<unknown>;
  set?(key: string, value: unknown, ttl: number): void | Promise<void>;
}

export interface RulesCtx {
  cache?: CacheLike;
  clock?: () => number;
  json_decode?: (s: string) => JsonValue;
  re_find?: (subject: string, pattern: string) => boolean;
  log?: (level: string, msg: string) => void;
}

/**
 * Lua pattern -> RegExp for the subset rule files use: ^ anchor, literals,
 * %-escaped punctuation and the %a %d %s %w %x classes. Anything else in a
 * watch path is unsupported on this adapter and throws at load time rather
 * than silently matching differently.
 */
const luaPatternCache = new Map<string, RegExp>();
export function luaPatternToRegExp(p: string): RegExp {
  const hit = luaPatternCache.get(p);
  if (hit) return hit;
  let out = "";
  for (let i = 0; i < p.length; i++) {
    const c = p[i];
    if (c === "%") {
      const n = p[++i];
      if (n === undefined) throw new Error(`malformed Lua pattern: ${p}`);
      const cls: Record<string, string> = { a: "[A-Za-z]", d: "[0-9]", s: "[ \\t\\n\\v\\f\\r]", w: "[A-Za-z0-9]", x: "[0-9A-Fa-f]", p: "[!-/:-@\\[-`{-~]" };
      if (cls[n]) out += cls[n];
      else if (/[A-Za-z0-9]/.test(n)) throw new Error(`unsupported Lua class %${n} in ${p}`);
      else out += "\\" + n;
    } else if (c === "-") {
      out += "*?";
    } else if ("\\{}|".includes(c)) {
      out += "\\" + c; // literal in Lua, special in JS
    } else {
      out += c; // ^ $ . * + ? [ ] ( ) mean the same in both for this subset
    }
  }
  const re = new RegExp(out);
  luaPatternCache.set(p, re);
  return re;
}

function pathMatches(s: string, patterns: string[] | undefined): string | null {
  for (const p of patterns ?? []) {
    if (luaPatternToRegExp(p).test(s)) return p;
  }
  return null;
}

let warned = false;
function textMatches(s: string, patterns: string[] | undefined, ctx: RulesCtx | undefined): string | null {
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
      if (reFind(s, p)) return p;
    } catch {
      // a pattern the engine rejects is skipped, like pcall in Lua
    }
  }
  return null;
}

function ctAllowed(ct: string | undefined, allowed: string[] | undefined): boolean {
  if (!allowed || allowed.length === 0) return true;
  const c = (ct ?? "").toLowerCase();
  for (const a of allowed) if (c.includes(a)) return true;
  return false;
}

/** Case-insensitive regex search with the same contract the OpenResty adapter gives core. */
const reCache = new Map<string, RegExp>();
export function reFind(subject: string, pattern: string): boolean {
  let re = reCache.get(pattern);
  if (!re) {
    re = new RegExp(pattern, "i");
    reCache.set(pattern, re);
  }
  return re.test(subject);
}

export async function evaluate(req: Req, rule: Rule, ctx?: RulesCtx): Promise<[RuleResult, string, string]> {
  // 1. path watch list
  if (!pathMatches(req.path ?? "", rule.watch_paths)) return [PASS, "", "path not watched"];

  // 2. reputation, before anything that needs a body
  if (ctx?.cache && req.client_ip) {
    const rep = (await ctx.cache.get("rep:" + req.client_ip)) as { blocked_until?: number; trusted_until?: number } | undefined;
    if (rep && typeof rep === "object") {
      const now = ctx.clock ? ctx.clock() : 0;
      if (rep.blocked_until !== undefined && rep.blocked_until > now) return [BLOCK, "", "ip reputation"];
      if (rep.trusted_until !== undefined && rep.trusted_until > now) return [PASS, "", "ip trusted"];
    }
  }

  // 3. method + content type
  if (rule.methods && !rule.methods[(req.method ?? "").toUpperCase()]) return [PASS, "", "method not watched"];
  const ct = req.headers ? (req.headers["content-type"] ?? req.headers["Content-Type"] ?? "") : "";
  if (!ctAllowed(ct, rule.content_types)) return [PASS, "", "content-type not watched"];

  // 4. body size (bytes, like Lua's #body)
  const size = typeof req.body_size === "number" ? req.body_size : (typeof req.body === "string" ? byteLength(req.body) : 0);
  if (size === 0 && (req.body === undefined || req.body === null)) return [PASS, "", "no body"];
  if (size < (rule.min_body_bytes ?? 8)) return [PASS, "", "body too small"];
  if (size > (rule.max_body_bytes ?? 65536)) return [PASS, "", "body too large"];

  // 5+6. extract text, regex prefilter, natural-language length
  const [text] = extract(req.body, ct, rule.text_fields, ctx?.json_decode);
  if (text === "") return [PASS, "", "no text"];
  const hit = textMatches(text, rule.always_suspect, ctx);
  if (hit) return [SUSPECT, text, "pattern: " + hit];
  if (byteLength(text) >= (rule.min_text_chars ?? 20)) return [SUSPECT, text, "natural language"];
  return [PASS, "", "text too short"];
}

export async function evaluateAll(
  req: Req, rules: Rule[] | undefined, ctx?: RulesCtx,
): Promise<[RuleResult, string, string, Rule | undefined]> {
  let lastReason = "no rules";
  for (const rule of rules ?? []) {
    const [r, text, reason] = await evaluate(req, rule, ctx);
    if (r !== PASS) return [r, text, reason, rule];
    lastReason = reason;
  }
  return [PASS, "", lastReason, undefined];
}
