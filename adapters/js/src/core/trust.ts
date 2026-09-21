// Port of core/trust.lua: fingerprint trust, the write side of the
// false-positive feedback loop. An operator marks a request "not an attack"
// and every later request with the same text passes without an L2 call.
// Trust always expires, and traffic may extend it only maxRenewals times:
// a permanent entry would be a standing bypass keyed on attacker-visible text.
import type { CacheLike } from "./rules";

export const PREFIX = "trust:";
export const DEFAULT_TTL = 7 * 24 * 3600;
export const DEFAULT_RENEWALS = 4;

export interface FeedbackConfig {
  enabled?: boolean;
  trust_ttl?: number;
  max_renewals?: number;
  token?: string | null;
}

export interface TrustRecord {
  trusted_until: number;
  renewals: number;
  first_seen: number;
  by?: string;
  rid?: string;
}

export type TrustStore = CacheLike & { set(key: string, value: unknown, ttl: number): void | Promise<void> };

export function key(fp: string): string {
  return PREFIX + (fp ?? "");
}

/** Absent config means off; only `enabled === true` turns the loop on. */
export function enabled(fcfg?: FeedbackConfig | null): boolean {
  return !!fcfg && fcfg.enabled === true;
}

function ttlOf(fcfg?: FeedbackConfig | null): number {
  const n = Number(fcfg?.trust_ttl);
  return Number.isFinite(n) && n > 0 ? n : DEFAULT_TTL;
}

function maxRenewalsOf(fcfg?: FeedbackConfig | null): number {
  const n = Number(fcfg?.max_renewals);
  return Number.isFinite(n) && n >= 0 ? n : DEFAULT_RENEWALS;
}

/** The live record for a fingerprint, or undefined. Expired records read as absent. */
export async function get(store: TrustStore | undefined, fp: string, now: number): Promise<TrustRecord | undefined> {
  if (!store || !fp) return undefined;
  const rec = (await store.get(key(fp))) as TrustRecord | undefined;
  if (!rec || typeof rec !== "object") return undefined;
  if (typeof rec.trusted_until !== "number" || rec.trusted_until <= (now ?? 0)) return undefined;
  return rec;
}

/**
 * Extend a live record that is past half its life, at most maxRenewals times.
 * Returns the reason when nothing was written, so writes stay bounded.
 */
export async function touch(
  store: TrustStore, fp: string, rec: TrustRecord, now: number, fcfg?: FeedbackConfig | null,
): Promise<[true, TrustRecord] | [false, string]> {
  const ttl = ttlOf(fcfg);
  const renewals = Number(rec.renewals) || 0;
  if (renewals >= maxRenewalsOf(fcfg)) return [false, "renewal cap"];
  if (now < rec.trusted_until - ttl / 2) return [false, "not due"];
  const out: TrustRecord = {
    trusted_until: now + ttl,
    renewals: renewals + 1,
    first_seen: Number(rec.first_seen) || now,
    ...(rec.by !== undefined ? { by: rec.by } : {}),
    ...(rec.rid !== undefined ? { rid: rec.rid } : {}),
  };
  await store.set(key(fp), out, ttl);
  return [true, out];
}

/** Trust a fingerprint on an operator's say-so. */
export async function grant(
  store: TrustStore | undefined, fp: string, now: number,
  fcfg?: FeedbackConfig | null, meta?: { by?: string; rid?: string },
): Promise<[TrustRecord, null] | [null, string]> {
  if (!store) return [null, "no trust store"];
  if (!fp) return [null, "empty fingerprint"];
  const ttl = ttlOf(fcfg);
  const maxr = maxRenewalsOf(fcfg);

  const existing = await get(store, fp, now);
  let renewals = 0;
  if (existing) {
    renewals = (Number(existing.renewals) || 0) + 1;
    if (renewals > maxr) {
      const days = Math.floor((now - (Number(existing.first_seen) || now)) / 86400);
      return [null, `renewal cap reached: this fingerprint has been trusted for ${days} days; ` +
        "fix the rule or the deployment context instead"];
    }
  }
  const rec: TrustRecord = {
    trusted_until: now + ttl,
    renewals,
    first_seen: existing ? Number(existing.first_seen) || now : now,
    ...(meta?.by !== undefined ? { by: String(meta.by) } : {}),
    ...(meta?.rid !== undefined ? { rid: String(meta.rid) } : {}),
  };
  await store.set(key(fp), rec, ttl);
  return [rec, null];
}

/** Undoing a mislabel must be as cheap as making one. */
export async function revoke(store: TrustStore | undefined, fp: string): Promise<boolean> {
  if (!store || !fp) return false;
  await store.set(key(fp), undefined, 0);
  return true;
}
