// Port of core/verdict.lua. Flat structure: every field always present.
import { utf8Bytes } from "./normalize.js";

export type Action = "pass" | "block";
export type Label = "safe" | "suspicious" | "malicious" | "error" | "skipped";
/** "adapter" is what the host sets when its own pipeline threw and the request failed open (edge.lua access()). */
export type Source = "l1" | "cache" | "trust" | "l2" | "breaker" | "adapter";

export const ACTION_PASS: Action = "pass";
export const ACTION_BLOCK: Action = "block";
export const SAFE: Label = "safe";
export const SUSPICIOUS: Label = "suspicious";
export const MALICIOUS: Label = "malicious";
export const ERROR: Label = "error";
export const SKIPPED: Label = "skipped";
export const SRC_L1: Source = "l1";
export const SRC_CACHE: Source = "cache";
export const SRC_TRUST: Source = "trust";
export const SRC_L2: Source = "l2";
export const SRC_BREAKER: Source = "breaker";
export const SRC_ADAPTER: Source = "adapter";

export interface Verdict {
  action: Action;
  verdict: Label;
  score: number;
  source: Source;
  reason: string;
  fingerprint: string;
  l2_ms: number;
  async: boolean;
}

export interface VerdictInit {
  action?: Action;
  verdict?: Label;
  score?: number;
  source?: Source;
  reason?: unknown;
  fingerprint?: unknown;
  l2_ms?: unknown;
  async?: unknown;
}

function clamp01(n: unknown): number {
  if (typeof n !== "number" || Number.isNaN(n)) return 0;
  if (n < 0) return 0;
  if (n > 1) return 1;
  return n;
}

export function newVerdict(t?: VerdictInit | null): Verdict {
  const v = t ?? {};
  const l2 = typeof v.l2_ms === "number" ? v.l2_ms : Number(v.l2_ms);
  return {
    action: v.action ?? ACTION_PASS,
    verdict: v.verdict ?? SKIPPED,
    score: clamp01(v.score ?? 0),
    source: v.source ?? SRC_L1,
    reason: String(v.reason ?? ""),
    fingerprint: String(v.fingerprint ?? ""),
    l2_ms: Number.isFinite(l2) ? l2 : 0,
    async: v.async === true,
  };
}

/**
 * C printf("%.2f"): exact binary value, ties to even. JS toFixed rounds ties
 * away from zero on the *decimal* expansion, which differs for e.g. 0.125.
 */
export function format2(n: number): string {
  const exact = n.toFixed(20); // exact enough: doubles in [0,1] need <= 17 significant digits
  const [ip, fp = ""] = exact.split(".");
  const keep = fp.slice(0, 2).padEnd(2, "0");
  const rest = fp.slice(2);
  let carry = 0;
  if (rest.length > 0) {
    const first = rest.charCodeAt(0) - 48;
    const tail = rest.slice(1);
    if (first > 5 || (first === 5 && /[1-9]/.test(tail))) carry = 1;
    else if (first === 5) carry = (keep.charCodeAt(1) - 48) % 2 === 1 ? 1 : 0; // tie: to even
  }
  let cents = parseInt(ip, 10) * 100 + parseInt(keep, 10) + carry;
  const neg = n < 0 && cents !== 0;
  cents = Math.abs(cents);
  const s = `${Math.floor(cents / 100)}.${String(cents % 100).padStart(2, "0")}`;
  return neg ? "-" + s : s;
}

/** Longest encoded reason placed in a header, in bytes. */
export const REASON_MAX = 200;

/** URL-encode and truncate a reason for header transport (<= REASON_MAX bytes of encoded output, never cut inside a %XX escape). */
export function encodeReason(s: unknown): string {
  const str = String(s ?? "");
  // Lua: gsub("[^%w%-%._~ ]", %%XX) over bytes, then spaces to +
  let out = "";
  for (const b of utf8Bytes(str)) {
    const c = String.fromCharCode(b);
    if (/[A-Za-z0-9\-._~ ]/.test(c) && b < 128) out += c === " " ? "+" : c;
    else out += "%" + b.toString(16).toUpperCase().padStart(2, "0");
  }
  // every char of `out` is one ASCII byte, so length is bytes
  if (out.length > REASON_MAX) out = out.slice(0, REASON_MAX).replace(/%[0-9A-Fa-f]?$/, "");
  return out;
}

/** Port of verdict.client_headers: the only verdict header a client may see
 *  on a block response (with X-Jev-Request-Id, which the adapter adds).
 *  Score, reason and source go to the logs and the upstream request only. */
export function clientHeaders(v: Verdict): Record<string, string> {
  return { "X-Jev-Verdict": v.verdict };
}

export function headers(v: Verdict): Record<string, string> {
  return {
    "X-Jev-Verdict": v.verdict,
    "X-Jev-Score": format2(v.score),
    "X-Jev-Source": v.source,
    "X-Jev-Reason": encodeReason(v.reason),
  };
}
