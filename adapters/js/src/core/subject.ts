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
