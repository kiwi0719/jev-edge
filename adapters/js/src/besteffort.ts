// Best-effort wrappers the runtime puts around its stores, breaker and
// adaptive timeout (adapters/js/src/runtime.ts). Kept in their own module so
// scripts/invariants.lua (breaker-failures) can allow this pure forwarding and
// still flag any other breaker feed in the runtime.
import { CLOSED, type Store, type BreakerLike } from "./core/breaker.js";
import type { AdaptiveLike } from "./cf/adaptive.js";

// ---------------------------------------------------------------------------
// Writes after a decision are best effort
// ---------------------------------------------------------------------------
//
// Once the judge has answered, the verdict is known; the writes that follow
// (verdict cache, breaker and adaptive bookkeeping, the subject ring and
// reputation) only serve later requests. A store that rejects one (KV over
// its per-key write rate or daily quota, a Durable Object that is overloaded
// or restarting, a Deno KV error) is logged and the verdict stands, as on
// OpenResty, where a full shared dict's `set` returns an error and never
// raises. The store reads a verdict is made from (cache, subject history) are
// not wrapped: without them there is no verdict, and the fail-open contract
// covers that.
//
// ---------------------------------------------------------------------------
// Reads before the judge are best effort too
// ---------------------------------------------------------------------------
//
// The breaker's allow() / state() and the adaptive timeout only decide
// whether L2 runs and how long it may take. A state store that fails them (a
// Durable Object overloaded or restarting, the one global jev-edge object
// over its request rate) must not fail every request open while the judge
// is healthy: the breaker then reads closed and the timeout is its floor
// (config.jev.timeout_ms), so L2 is asked as if the state were fresh. Never a
// breaker failure: the provider was not asked. Logged when the reads start
// failing and again only after they have recovered, not once per request.

function writeFailed(what: string, e: unknown): void {
  console.warn("jev-edge: " + what + " failed, verdict kept: " + (e instanceof Error ? e.message : String(e)));
}

/** `store` whose set and expire log a rejection instead of raising it. incr
 *  is logged and still raises: its callers (subject ring, reputation) need
 *  the value, and drop the write themselves when there is none. */
export function bestEffortStore(store: Store, name: string): Store {
  const out: Store = {
    get: (k) => store.get(k),
    set: async (k, v, ttl) => {
      try {
        await store.set(k, v, ttl);
      } catch (e) {
        writeFailed(name + " write", e);
      }
    },
  };
  if (typeof store.incr === "function") {
    out.incr = async (k, by, ttl) => {
      try {
        return await store.incr!(k, by, ttl);
      } catch (e) {
        writeFailed(name + " incr", e);
        throw e;
      }
    };
  }
  if (typeof store.expire === "function") {
    out.expire = async (k, ttl) => {
      try {
        await store.expire!(k, ttl);
      } catch (e) {
        writeFailed(name + " expire", e);
      }
    };
  }
  return out;
}

async function quietly(what: string, op: () => Promise<void>): Promise<void> {
  try {
    await op();
  } catch (e) {
    writeFailed(what, e);
  }
}

export interface BestEffortOptions {
  /** The reads failing now, by name. One set per runtime, shared by its
   *  wrappers (the per-request ones included), so an outage is logged once. */
  failing?: Set<string>;
  /** The timeout when current() fails: config.jev.timeout_ms (the floor). */
  floor?: number;
  /** Takes a write's promise off the request path (the host's waitUntil);
   *  false when it refused it, and the write is then awaited. */
  defer?: (p: Promise<void>) => boolean;
}

async function read<T>(failing: Set<string>, what: string, op: () => Promise<T>, fallback: T, instead: string): Promise<T> {
  try {
    const v = await op();
    failing.delete(what);
    return v;
  } catch (e) {
    if (!failing.has(what)) {
      failing.add(what);
      console.error(
        "jev-edge: " + what + " failed, judging with " + instead + ": " + (e instanceof Error ? e.message : String(e)) +
        " (logged again once it has recovered)",
      );
    }
    return fallback;
  }
}

/** state / allow decide whether L2 runs: a failed read is the breaker
 *  closed. The records made after a judge call (and trip) are best effort,
 *  and with `defer` not awaited. */
export function bestEffortBreaker(b: BreakerLike, o: BestEffortOptions = {}): BreakerLike {
  const failing = o.failing ?? new Set<string>();
  const write = (what: string, op: () => Promise<void>): Promise<void> => {
    const p = quietly(what, op);
    return o.defer?.(p) ? Promise.resolve() : p;
  };
  const wrapped: BreakerLike = {
    state: () => read(failing, "breaker read", () => b.state(), CLOSED, "the breaker closed"),
    allow: () => read(failing, "breaker read", () => b.allow(), true, "the breaker closed"),
    trip: (now) => write("breaker trip", () => b.trip(now)),
    success: () => write("breaker success", () => b.success()),
    failure: () => write("breaker failure", () => b.failure()),
  };
  // core only calls release when the breaker has one; dropping it here would
  // leave a half-open probe claimed after an error that does not count
  if (b.release) wrapped.release = () => write("breaker release", () => b.release!());
  return wrapped;
}

/** current() picks the timeout: a failed read is the floor. The samples
 *  recorded after the call are best effort. */
export function bestEffortAdaptive(a: AdaptiveLike, o: BestEffortOptions = {}): AdaptiveLike {
  const failing = o.failing ?? new Set<string>();
  const floor = o.floor ?? 400;
  return {
    current: () => read(failing, "adaptive timeout read", () => a.current(), floor, "the timeout at its floor, " + floor + " ms"),
    success: (ms) => quietly("adaptive timeout sample", () => a.success(ms)),
    timeout: (firedMs) => quietly("adaptive timeout sample", () => a.timeout(firedMs)),
  };
}
