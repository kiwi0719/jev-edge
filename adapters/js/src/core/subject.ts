// Port of core/subject.lua: the contract slot for per-subject scoring.
//
// A single request can look harmless and still be the sixth step of an attack
// assembled one message at a time. Catching that needs a score per subject over
// time, not per request. This module is the half of it that can be built
// without traffic: the shape of one trajectory entry, and where the core hands
// it over.
//
// This version records; it does not decide. `ctx.subject.history` is accepted
// and IGNORED, so evaluate() behaves exactly as it did before -- the golden
// vectors assert that. No window, decay factor or threshold is chosen, because
// there is no traffic to calibrate one against.
//
// The read/write split matters more here than on nginx: `history` is one
// lookup on the request path, and `record` is a sink the core hands a value to
// without awaiting. On Workers that keeps a Durable Object hop (or its absence)
// a deployment choice -- `record` can be dropped into waitUntil -- instead of
// something the request path has to wait for.
import type { Verdict } from "./verdict";

export const FORMAT = 1;
export const KEY_PREFIX = "subj:";

export interface SubjectConfig {
  enabled?: boolean;
  from?: "ip" | "header" | "cookie";
  name?: string | null;
  salt?: string | null;
  hashed?: boolean;
  history_ttl?: number;
  max_entries?: number;
}

export interface RequestView {
  ip?: string | null;
  header?: (name: string) => string | null | undefined;
  cookie?: (name: string) => string | null | undefined;
}

/** The raw subject value for this request, or null. Mirrors core/subject.lua extract(). */
export function extract(scfg: SubjectConfig | undefined, view: RequestView): string | null {
  if (!scfg?.enabled) return null;
  const from = scfg.from ?? "ip";
  let v: string | null | undefined;
  if (from === "ip") v = view.ip;
  else if (from === "header") v = view.header?.(scfg.name ?? "");
  else if (from === "cookie") v = view.cookie?.(scfg.name ?? "");
  if (typeof v !== "string") return null;
  v = v.trim();
  return v === "" ? null : v;
}

/** `<from>:<hash(salt \0 value)>`; the raw value never leaves this function. `hashed` means the value already is the complete id. */
export async function hashId(scfg: SubjectConfig, value: string | null, hash: (s: string) => Promise<string> | string): Promise<string | null> {
  if (value === null || value === undefined) return null;
  if (scfg.hashed) return value;
  if (typeof scfg.salt !== "string" || scfg.salt === "") return null;
  return (scfg.from ?? "ip") + ":" + String(await hash(scfg.salt + "\0" + value));
}

/** SHA-256 hex over UTF-8 with the Web Crypto API (Workers, Node 18+, browsers). */
export async function sha256Hex(s: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, "0")).join("");
}

export function append(history: unknown, e: Entry, maxEntries = 20): Entry[] {
  const out = Array.isArray(history) ? [...(history as Entry[])] : [];
  out.push(e);
  const max = Math.max(1, Number(maxEntries) || 20);
  while (out.length > max) out.shift();
  return out;
}

export function key(id: string): string {
  return KEY_PREFIX + id;
}

/** Cookie header -> one cookie's value, or null. */
export function cookieValue(header: string | null | undefined, name: string): string | null {
  if (!header) return null;
  for (const part of header.split(";")) {
    const i = part.indexOf("=");
    if (i < 0) continue;
    if (part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return null;
}

/** One trajectory entry: flat, so it maps 1:1 onto JSON, a log line and a
 *  stored value, and can be replayed later as calibration input. Carries the
 *  raw score, not only the label: a stream of 0.4s is the signal a later
 *  version has to be able to see, and a label throws it away. */
export interface Entry {
  at: number;
  subject: string;
  verdict: string;
  score: number;
  source: string;
  reason: string;
  fingerprint: string;
}

export interface SubjectCtx {
  id?: string;
  /** Accepted and ignored in this version. Always a valid nullish value: a
   *  cold subject, an evicted entry and a store that lost it all land here,
   *  and none of them is an error. */
  history?: unknown;
  /** Sink, off the request path. Not awaited, and a throw is swallowed: a
   *  trajectory write must never be able to fail a request. */
  record?: (entry: Entry) => void | Promise<void>;
}

export function entry(id: string, v: Verdict, now: number): Entry {
  return {
    at: Number.isFinite(now) ? now : 0,
    subject: String(id ?? ""),
    verdict: v.verdict,
    score: v.score,
    source: v.source,
    reason: v.reason,
    fingerprint: v.fingerprint,
  };
}

/** The subject id for this request, or null when there is none. */
export function idOf(ctx: { subject?: SubjectCtx }): string | null {
  const s = ctx.subject;
  if (!s || typeof s !== "object") return null;
  return typeof s.id === "string" && s.id !== "" ? s.id : null;
}

/** Hand one entry to the sink, if there is a subject and a sink. Returns the
 *  entry recorded, or null. Never throws, and never awaits the sink. */
export function record(ctx: { subject?: SubjectCtx; clock?: () => number }, v: Verdict): Entry | null {
  const id = idOf(ctx);
  if (!id) return null;
  const sink = ctx.subject!.record;
  if (typeof sink !== "function") return null;
  const e = entry(id, v, ctx.clock ? ctx.clock() : 0);
  try {
    const p = sink(e);
    if (p && typeof (p as Promise<void>).catch === "function") (p as Promise<void>).catch(() => {});
  } catch {
    /* a trajectory write must never be able to fail a request */
  }
  return e;
}
