// Best-effort wrappers the runtime puts around its stores, breaker and
// adaptive timeout (adapters/js/src/runtime.ts). Kept in their own module so
// scripts/invariants.lua (breaker-failures) can allow this pure forwarding and
// still flag any other breaker feed in the runtime.
import type { Store, BreakerLike } from "./core/breaker.js";
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
// raises. Reads are not wrapped: without them there is no verdict, and the
// fail-open contract above covers that.

function writeFailed(what: string, e: unknown): void {
  console.warn("jev-edge: " + what + " failed, verdict kept: " + (e instanceof Error ? e.message : String(e)));
}

/** `store` whose set and expire log a rejection instead of raising it. incr
 *  is logged and still raises: its callers (subject ring, reputation) need
 *  the value, and drop the write themselves when there is none. */
export function bestEffortStore(store: Store, name: string): Store {
  const out: Store = {
    get: (k) => store.get(k),
    // a read, not wrapped; kept so the subject ring reads its slots in one call
    ...(typeof store.getMany === "function" ? { getMany: (ks: string[]) => store.getMany!(ks) } : {}),
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

/** state / allow decide whether L2 runs and raise as before; the records
 *  made after a judge call (and trip) are best effort. */
export function bestEffortBreaker(b: BreakerLike): BreakerLike {
  const wrapped: BreakerLike = {
    state: () => b.state(),
    allow: () => b.allow(),
    trip: (now) => quietly("breaker trip", () => b.trip(now)),
    success: () => quietly("breaker success", () => b.success()),
    failure: () => quietly("breaker failure", () => b.failure()),
  };
  // core only calls release when the breaker has one; dropping it here would
  // leave a half-open probe claimed after an error that does not count
  if (b.release) wrapped.release = () => quietly("breaker release", () => b.release!());
  return wrapped;
}

/** current() picks the timeout and raises as before; the samples recorded
 *  after the call are best effort. */
export function bestEffortAdaptive(a: AdaptiveLike): AdaptiveLike {
  return {
    current: () => a.current(),
    success: (ms) => quietly("adaptive timeout sample", () => a.success(ms)),
    timeout: (firedMs) => quietly("adaptive timeout sample", () => a.timeout(firedMs)),
  };
}
