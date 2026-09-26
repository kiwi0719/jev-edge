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
import type { Verdict } from "./verdict.js";
import type { Store } from "./breaker.js";

export const FORMAT = 1;
export const KEY_PREFIX = "subj:";
/** Longest raw subject value accepted. Hashing makes the length irrelevant
 *  for the store, but with `hashed: true` the value IS the key and the log
 *  field, so an unbounded header would be an unbounded store key. */
export const MAX_VALUE_BYTES = 512;

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
  /** The raw Cookie header (repeated ones joined with "; ", or a list of them). */
  cookieHeader?: string | string[] | null;
  /** Older adapters: one cookie's value. Used only without cookieHeader. */
  cookie?: (name: string) => string | null | undefined;
}

/** Most ids one request can name (idsOf), and most candidate values one Cookie header yields (cookieValues). */
export const MAX_IDS = 4;

const LUA_TRIM = /^[ \t\n\v\f\r]+|[ \t\n\v\f\r]+$/g; // Lua %s, not Unicode trim
const trim = (s: string) => s.replace(LUA_TRIM, "");

// Port of unescape in core/subject.lua: Python's http.cookies unquoting of a
// quoted value's inside, \ooo (octal 000-377) is that code point and \x is x.
function unescape(s: string): string {
  if (!s.includes("\\")) return s;
  let out = "";
  let i = 0;
  while (i < s.length) {
    const c = s[i];
    if (c === "\\" && i < s.length - 1) {
      const oct = /^[0-3][0-7][0-7]/.exec(s.slice(i + 1, i + 4));
      if (oct) {
        out += String.fromCharCode(parseInt(oct[0], 8));
        i += 4;
      } else {
        out += s[i + 1];
        i += 2;
      }
    } else {
      out += c;
      i += 1;
    }
  }
  return out;
}

/** Port of cookie_values in core/subject.lua: the values a Cookie header
 *  gives cookie `name` as the backend may read them. Every `name=value`
 *  pair (exact, case-sensitive name), trimmed, one pair of DQUOTEs
 *  stripped, plus the backslash-unescaped form when it differs; distinct and
 *  non-empty, past MAX_IDS the first two and the last two. */
export function cookieValues(header: string | string[] | null | undefined, name: string | null | undefined): string[] {
  const h = Array.isArray(header) ? header.filter((x) => typeof x === "string").join("; ") : header;
  if (typeof h !== "string" || h === "" || typeof name !== "string" || name === "") return [];
  const all: string[] = [];
  const add = (v: string) => {
    if (v !== "" && !all.includes(v)) all.push(v);
  };
  for (const part of h.split(";")) {
    const eq = part.indexOf("=");
    if (eq < 0 || trim(part.slice(0, eq)) !== name) continue;
    let v = trim(part.slice(eq + 1));
    if (v.length >= 2 && v.startsWith('"') && v.endsWith('"')) {
      v = v.slice(1, -1);
      add(v);
      add(unescape(v));
    } else {
      add(v);
    }
  }
  if (all.length <= MAX_IDS) return all;
  return [all[0], all[1], all[all.length - 2], all[all.length - 1]];
}

// Port of canonical_credentials in core/subject.lua: for Authorization and
// Proxy-Authorization the scheme is lowercased (ASCII, as Lua's lower) and
// the run of spaces or tabs after it becomes one space; the credentials are
// kept as sent, a value with no scheme as is.
const CREDENTIAL_HEADERS = new Set(["authorization", "proxy-authorization"]);
function canonicalCredentials(v: string): string {
  const m = /^([^ \t\n\v\f\r]+)[ \t]+([\s\S]*)$/.exec(v);
  if (!m) return v;
  return m[1].replace(/[A-Z]+/g, (c) => c.toLowerCase()) + " " + m[2];
}

/** Every raw subject value for this request (one for ip and header, up to
 *  MAX_IDS for cookie). Mirrors core/subject.lua extract_all(). */
export function extractAll(scfg: SubjectConfig | undefined, view: RequestView): string[] {
  if (!scfg?.enabled) return [];
  const from = scfg.from ?? "ip";
  let raw: (string | null | undefined)[] = [];
  if (from === "ip") raw = [view.ip];
  else if (from === "header") raw = [view.header?.(scfg.name ?? "")];
  else if (from === "cookie") {
    raw = view.cookieHeader !== undefined && view.cookieHeader !== null
      ? cookieValues(view.cookieHeader, scfg.name)
      : [view.cookie?.(scfg.name ?? "")];
  }
  const creds = from === "header" && CREDENTIAL_HEADERS.has(String(scfg.name ?? "").toLowerCase());
  const out: string[] = [];
  for (const r of raw) {
    if (typeof r !== "string") continue;
    let v = trim(r);
    if (creds) v = canonicalCredentials(v);
    if (v !== "" && new TextEncoder().encode(v).length <= MAX_VALUE_BYTES && !out.includes(v)) out.push(v);
  }
  return out;
}

/** The raw subject value for this request, or null: the first of extractAll. */
export function extract(scfg: SubjectConfig | undefined, view: RequestView): string | null {
  return extractAll(scfg, view)[0] ?? null;
}

/** `<from>:<hash(salt \0 value)>`; the raw value never leaves this function. `hashed` means the value already is the complete id. */
export async function hashId(scfg: SubjectConfig, value: string | null, hash: (s: string) => Promise<string> | string): Promise<string | null> {
  if (value === null || value === undefined) return null;
  if (scfg.hashed) {
    // Already `<from>:<hex>` from another jev-edge. Anything else is not an
    // id computed by us and does not get to name a trajectory.
    return /^[a-z]+:[0-9a-f]+$/.test(value) ? value : null;
  }
  if (typeof scfg.salt !== "string" || scfg.salt === "") return null;
  return (scfg.from ?? "ip") + ":" + String(await hash(scfg.salt + "\0" + value));
}

/** hashId over every value, distinct ids in order (the first is the request's `id`, the list its `ids`). */
export async function hashIds(scfg: SubjectConfig, values: string[], hash: (s: string) => Promise<string> | string): Promise<string[]> {
  const out: string[] = [];
  for (const v of values) {
    const id = await hashId(scfg, v, hash);
    if (id && !out.includes(id)) out.push(id);
  }
  return out;
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

// ---------------------------------------------------------------------------
// Ring layout, port of core/subject.lua ring_append / ring_load. Same keys, so
// a store shared with another implementation agrees.
// One list per subject (`append` above) is a read-modify-write, and two
// requests appending at once lose an entry. The ring keeps one counter per
// subject (`incr`, atomic in the memory and Durable Object stores) and one key
// per entry, `subj:<id>:<(n-1) % max>`, so a write is an incr and a set and
// needs no lock. Reading is `max` gets, newest last.
// Each slot holds `{ n: <sequence>, e: <entry> }`; a reader keeps a slot only
// when its sequence is the one it expects there, so a slot still holding the
// previous lap (read between another request's incr and set) or written under
// a different max_entries is a hole, not a misplaced entry.
// `incr` sets the ttl only when it creates the counter; `expire` (when the
// store has it) extends it on every append, so an active subject keeps its
// history for `ttl` after its last request, not after its first.
// ---------------------------------------------------------------------------

interface Slot { n: number; e: Entry }

/** Append one entry to the ring. false on a store without `incr`. */
export async function ringAppend(store: Store | undefined, id: string | null, e: Entry, maxEntries = 20, ttl = 3600): Promise<boolean> {
  if (!store || !id || typeof store.incr !== "function") return false;
  const max = Math.max(1, Number(maxEntries) || 20);
  const t = Number.isFinite(Number(ttl)) ? Number(ttl) : 3600;
  const k = key(id);
  const n = Number(await store.incr(k + ":n", 1, t));
  if (!Number.isFinite(n) || n < 1) return false;
  if (typeof store.expire === "function") await store.expire(k + ":n", t);
  await store.set(k + ":" + ((n - 1) % max), { n, e } satisfies Slot, t);
  return true;
}

/** The newest `maxEntries` entries, oldest first, or null when there are none. */
export async function ringLoad(store: Store | undefined, id: string | null, maxEntries = 20): Promise<Entry[] | null> {
  if (!store || !id) return null;
  const max = Math.max(1, Number(maxEntries) || 20);
  const k = key(id);
  const n = Number(await store.get(k + ":n")) || 0;
  if (n <= 0) return null;
  // the slots at once, not one round trip each (KV, a Durable Object)
  const seqs: number[] = [];
  for (let i = Math.max(1, n - max + 1); i <= n; i++) seqs.push(i);
  const slots = await Promise.all(seqs.map((i) => store.get(k + ":" + ((i - 1) % max)) as Promise<Slot | undefined> | Slot | undefined));
  const out: Entry[] = [];
  seqs.forEach((i, j) => {
    const s = slots[j];
    // an evicted, expired, stale or foreign slot is a hole, not an error
    if (s && typeof s === "object" && s.n === i && s.e && typeof s.e === "object") out.push(s.e);
  });
  return out.length ? out : null;
}

/** History for the request path: the ring when the store has `incr`, else the
 *  one-list layout (custom stores with only get/set keep working). */
export async function loadHistory(store: Store, id: string, maxEntries = 20): Promise<unknown> {
  if (typeof store.incr === "function") return ringLoad(store, id, maxEntries);
  return store.get(key(id));
}

/** The write behind `record`: ring append, or the list read-then-write on a
 *  store without `incr` (which can lose an entry to a concurrent append). */
export async function appendHistory(store: Store, id: string, e: Entry, maxEntries = 20, ttl = 3600): Promise<void> {
  if (typeof store.incr === "function") {
    await ringAppend(store, id, e, maxEntries, ttl);
    return;
  }
  await store.set(key(id), append(await store.get(key(id)), e, maxEntries), ttl);
}

/** Cookie header -> one cookie's value (the first of cookieValues), or null. */
export function cookieValue(header: string | null | undefined, name: string): string | null {
  return cookieValues(header, name)[0] ?? null;
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
  /** Every id the request names, `id` first (idsOf): reputation checks and charges each. */
  ids?: string[];
  /** Accepted and ignored in this version. Always a valid nullish value: a
   *  cold subject, an evicted entry and a store that lost it all land here,
   *  and none of them is an error. */
  history?: unknown;
  /** Sink, off the request path. Not awaited, and a throw is swallowed: a
   *  trajectory write must never be able to fail a request. */
  record?: (entry: Entry) => void | Promise<void>;
  /** Store for subject reputation counters (see repRecord); optional. */
  store?: Store;
  /** Optional, port of ctx.subject.counted in core/subject.lua: true when the
   *  other leg of this request (an origin's /_jev/authz call, then the
   *  request forwarded to it) already added its points; repRecord adds none. */
  counted?: (fp: string) => boolean | Promise<boolean>;
  /** Optional, port of ctx.subject.on_counted: called after the points are added. */
  onCounted?: (fp: string) => void | Promise<void>;
}

// ---------------------------------------------------------------------------
// Subject reputation: port of rep_blocked / rep_record in core/subject.lua.
// Judged verdicts add points over a sliding window (current bucket plus the
// previous one weighted by its overlap); at block_at the subject is blocked
// at L1 for block_ttl seconds. Off unless config.subject.reputation.block_at > 0.
// ---------------------------------------------------------------------------

export const REP_PREFIX = "srep:";

export interface ReputationConfig {
  block_at?: number;
  window_s?: number;
  block_ttl?: number;
  suspicious?: number;
  malicious?: number;
}

type RepCtx = { subject?: SubjectCtx; clock?: () => number; config?: { subject?: { reputation?: ReputationConfig } } };

function repCfg(ctx: RepCtx): [ReputationConfig, number] | null {
  const r = ctx.config?.subject?.reputation;
  if (!r || typeof r !== "object") return null;
  const at = Number(r.block_at);
  if (!Number.isFinite(at) || at <= 0) return null;
  return [r, at];
}

/** true when the subject of this request is blocked by its reputation: any of its ids. */
export async function repBlocked(ctx: RepCtx): Promise<boolean> {
  if (!repCfg(ctx)) return false;
  const store = ctx.subject?.store;
  if (!store) return false;
  const now = ctx.clock ? ctx.clock() : 0;
  for (const id of idsOf(ctx)) {
    try {
      const until = Number(await store.get(REP_PREFIX + id + ":until"));
      if (Number.isFinite(until) && until > now) return true;
    } catch {
      /* a failed read is not a block, as in Lua (pcall) */
    }
  }
  return false;
}

async function incrBy(store: Store, key: string, by: number, ttl: number): Promise<number> {
  if (typeof store.incr === "function") return Number(await store.incr(key, by, ttl));
  const n = (Number(await store.get(key)) || 0) + by;
  await store.set(key, n, ttl);
  return n;
}

/** Add this verdict's points and block the subject when it crosses block_at.
 *  Only judged verdicts count (not L1). `charge`: the label to charge instead
 *  of v.verdict (the subject's own text's, when retrieved content or the tool
 *  definitions decided), or false for nothing (none of its own text judged,
 *  which with untrusted judging on includes a text that holds retrieved
 *  content). Never throws. Returns the points, or null. */
export async function repRecord(ctx: RepCtx, v: Verdict, charge?: string | false): Promise<number | null> {
  const c = repCfg(ctx);
  if (!c || v.source === "l1" || charge === false) return null;
  const [r, at] = c;
  const ids = idsOf(ctx);
  const store = ctx.subject?.store;
  if (ids.length === 0 || !store) return null;
  // the subject is charged for its own text only (see core/subject.lua)
  const label = charge ?? v.verdict;
  let w = 0;
  if (label === "malicious") w = r.malicious ?? 3;
  else if (label === "suspicious") w = r.suspicious ?? 1;
  if (!(w > 0)) return null;
  const s = ctx.subject!;
  if (typeof s.counted === "function") {
    try {
      if (await s.counted(v.fingerprint)) return null;
    } catch {
      /* swallowed, as in Lua (pcall) */
    }
  }
  let best: number | null = null;
  // every id of the request is charged (idsOf)
  for (const id of ids) {
    try {
      const win = r.window_s ?? 600;
      const now = ctx.clock ? ctx.clock() : 0;
      const b = Math.floor(now / win);
      const key = REP_PREFIX + id + ":b:";
      const cur = (await incrBy(store, key + b, w, win * 2)) || 0;
      const prev = Number(await store.get(key + (b - 1))) || 0;
      const p = cur + prev * (1 - (now - b * win) / win);
      if (p >= at) {
        const ttl = r.block_ttl ?? 600;
        await store.set(REP_PREFIX + id + ":until", now + ttl, ttl);
      }
      if (best === null || p > best) best = p;
    } catch {
      /* swallowed, as in Lua (pcall per id) */
    }
  }
  if (typeof s.onCounted === "function") {
    try {
      await s.onCounted(v.fingerprint);
    } catch {
      /* swallowed, as in Lua (pcall) */
    }
  }
  return best;
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

/** Every id this request names, `id` first, then the distinct `ids` (at most MAX_IDS). Port of ids_of. */
export function idsOf(ctx: { subject?: SubjectCtx }): string[] {
  const id = idOf(ctx);
  if (!id) return [];
  const out = [id];
  const ids = ctx.subject!.ids;
  if (Array.isArray(ids)) {
    for (const x of ids) {
      if (out.length >= MAX_IDS) break;
      if (typeof x === "string" && x !== "" && !out.includes(x)) out.push(x);
    }
  }
  return out;
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
