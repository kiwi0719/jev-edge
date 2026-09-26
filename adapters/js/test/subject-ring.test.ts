// The TypeScript twin of the ring cases in core/spec/subject_store_spec.lua,
// plus what only the JS stores can show: concurrent appends through the memory
// and Durable Object stores lose nothing, and a store without incr still works
// on the one-list layout.
import { describe, it, expect } from "vitest";
import * as subject from "../src/core/subject";
import { memoryStore as coreMemoryStore, type Store } from "../src/core/breaker";
import { memoryStore, durableStore, kvStore, JevState, type KVLike } from "../src/cf/stores";
import { createRuntime, handle } from "../src";
import { evaluate } from "../src/runtime";

const E = (score: number): subject.Entry => ({ at: score, subject: "s", verdict: "safe", score, source: "l2", reason: "", fingerprint: "" });
const scores = (h: unknown) => (h as subject.Entry[] | null)?.map((e) => e.score) ?? null;

/** A JevState behind a stub that delivers one request at a time, as a Durable
 *  Object does while its handler only awaits its own storage. */
function durable(): Store {
  const mem = new Map<string, unknown>();
  const d = new JevState({ storage: { get: async (k) => mem.get(k), put: async (k, v) => { mem.set(k, v); }, delete: async (k) => mem.delete(k) } });
  let queue: Promise<unknown> = Promise.resolve();
  const stub = {
    fetch: (i: string | Request, init?: RequestInit) => {
      const p = queue.then(() => d.fetch(new Request(i, init)));
      queue = p.catch(() => {});
      return p;
    },
  };
  return durableStore(stub);
}

describe("subject ring store", () => {
  it("appends with incr + set and loads the newest max_entries in order", async () => {
    const store = memoryStore();
    expect(await subject.ringLoad(store, "ip:a", 3)).toBeNull();
    for (let i = 1; i <= 5; i++) await subject.ringAppend(store, "ip:a", E(i / 10), 3, 60);
    expect(scores(await subject.ringLoad(store, "ip:a", 3))).toEqual([0.3, 0.4, 0.5]);
    expect(await store.get("subj:ip:a:n")).toBe(5);
    expect(await store.get("subj:ip:a")).toBeUndefined(); // no list key: nothing is read-modify-written
  });

  it("skips evicted slots instead of failing", async () => {
    const store = memoryStore();
    for (let i = 1; i <= 3; i++) await subject.ringAppend(store, "ip:b", E(i), 3, 60);
    await store.set("subj:ip:b:1", null, 0);
    expect(scores(await subject.ringLoad(store, "ip:b", 3))).toEqual([1, 3]);
  });

  it("drops a slot still holding the previous lap instead of reading it as the newest", async () => {
    const store = memoryStore();
    for (let i = 1; i <= 3; i++) await subject.ringAppend(store, "ip:c", E(i), 3, 60);
    // another request has incr'd to 4 but not yet written slot (4-1)%3 = 0
    await store.incr!("subj:ip:c:n", 1, 60);
    expect(scores(await subject.ringLoad(store, "ip:c", 3))).toEqual([2, 3]);
  });

  it("reads no misplaced entries after max_entries changes", async () => {
    const store = memoryStore();
    for (let i = 1; i <= 5; i++) await subject.ringAppend(store, "ip:d", E(i), 3, 60);
    // max 3 put seq 4 in slot 0 and seq 5 in slot 1; read with max 4 those
    // slots are expected to hold seq 5 and 2, so both are holes
    expect(scores(await subject.ringLoad(store, "ip:d", 4))).toEqual([3]);
  });

  it("extends the counter ttl on every append", async () => {
    const seen: string[] = [];
    const store: Store = { ...memoryStore(), expire: (k, ttl) => { seen.push(k + "=" + ttl); } };
    await subject.ringAppend(store, "ip:e", E(1), 3, 60);
    await subject.ringAppend(store, "ip:e", E(2), 3, 60);
    expect(seen).toEqual(["subj:ip:e:n=60", "subj:ip:e:n=60"]);
  });

  it("the memory store's counter keeps its expiry until expire extends it", async () => {
    let now = 1000;
    const store = memoryStore(() => now);
    await store.incr!("c", 1, 10);
    now = 1005;
    expect(await store.incr!("c", 1, 10)).toBe(2); // not recreated, not re-ttl'd
    now = 1011;
    expect(await store.get("c")).toBeUndefined();
    expect(await store.incr!("c", 1, 10)).toBe(1);
    await store.expire!("c", 100);
    now = 1050;
    expect(await store.get("c")).toBe(1);
  });

  it("is a no-op on a store without incr", async () => {
    expect(await subject.ringAppend({ get: () => undefined, set: () => {} }, "x", E(1), 3, 60)).toBe(false);
  });

  const stores: [string, () => Store][] = [
    ["memory (cf)", () => memoryStore()],
    ["memory (core)", () => coreMemoryStore()],
    ["Durable Object", durable],
  ];
  for (const [name, make] of stores) {
    it(`${name}: 20 concurrent appends lose no entry`, async () => {
      const store = make();
      await Promise.all(Array.from({ length: 20 }, (_, i) => subject.appendHistory(store, "ip:f", E(i + 1), 20, 60)));
      const h = await subject.loadHistory(store, "ip:f", 20);
      expect(new Set(scores(h))).toEqual(new Set(Array.from({ length: 20 }, (_, i) => i + 1)));
      expect(await store.get("subj:ip:f:n")).toBe(20);
    });
  }

  it("falls back to the one-list layout on a store without incr", async () => {
    const inner = memoryStore();
    const plain: Store = { get: (k) => inner.get(k), set: (k, v, ttl) => inner.set(k, v, ttl) };
    for (let i = 1; i <= 4; i++) await subject.appendHistory(plain, "ip:g", E(i), 3, 60);
    expect(scores(await subject.loadHistory(plain, "ip:g", 3))).toEqual([2, 3, 4]);
    expect(scores(await inner.get("subj:ip:g"))).toEqual([2, 3, 4]);
    expect(await inner.get("subj:ip:g:n")).toBeUndefined();
  });

  // js-hosts#12: a request no rule watches reads nothing from the subject
  // store, and a watched one reads the ring's slots at once, not one by one
  describe("reads on the request path", () => {
    const counting = (delayMs: number) => {
      const inner = memoryStore();
      const c = { gets: 0, inFlight: 0, maxInFlight: 0 };
      const store: Store = {
        ...inner,
        get: async (k) => {
          c.gets++;
          c.inFlight++;
          c.maxInFlight = Math.max(c.maxInFlight, c.inFlight);
          await new Promise((r) => setTimeout(r, delayMs));
          c.inFlight--;
          return inner.get(k);
        },
      };
      return { store, c };
    };
    const cfg = { jev: { provider: "mock", mock_score: 0.2, timeout_ms: 400 }, subject: { enabled: true, from: "ip" as const, salt: "pepper" } };
    const req = (method: string, path: string, body?: string) => new Request("https://edge.example" + path, {
      method, headers: { "content-type": "application/json", "x-forwarded-for": "203.0.113.9" }, body,
    });
    const up = async () => new Response("ok");

    it("an unwatched GET makes no store read, and still names its subject", async () => {
      const { store, c } = counting(0);
      const rt = createRuntime({ config: cfg, subjectStore: store });
      const { subjectId } = await evaluate(req("GET", "/static/logo.png"), rt);
      expect(subjectId).toMatch(/^ip:[0-9a-f]{64}$/);
      expect(c.gets).toBe(0);
      // a watched path with a method no rule watches: no history either
      await handle(req("GET", "/v1/chat/completions"), rt, up);
      expect(c.gets).toBe(0);
    });

    it("a watched POST reads the counter, then the slots concurrently", async () => {
      const { store, c } = counting(5);
      const id = "ip:x";
      for (let i = 1; i <= 20; i++) await subject.ringAppend(store, id, E(i), 20, 60);
      c.gets = 0;
      expect(scores(await subject.ringLoad(store, id, 20))).toEqual(Array.from({ length: 20 }, (_, i) => i + 1));
      expect(c.gets).toBe(21);
      expect(c.maxInFlight).toBe(20);
      const rt = createRuntime({ config: cfg, subjectStore: store });
      c.gets = 0;
      const body = '{"messages":[{"role":"user","content":"Please write a detailed summary of the attached quarterly report."}]}';
      await handle(req("POST", "/v1/chat/completions", body), rt, up);
      expect(c.gets).toBeGreaterThan(0);
    });
  });

  it("KV incr is a best-effort get + put that always carries the ttl", async () => {
    const puts: [string, string, unknown][] = [];
    const m = new Map<string, string>();
    const kv: KVLike = {
      get: async (k) => (m.has(k) ? JSON.parse(m.get(k)!) : null),
      put: async (k, v, opts) => { puts.push([k, v, opts]); m.set(k, v); },
      delete: async (k) => { m.delete(k); },
    };
    const store = kvStore(kv);
    expect(await store.incr!("subj:x:n", 1, 3600)).toBe(1);
    expect(await store.incr!("subj:x:n", 1, 3600)).toBe(2);
    expect(puts.map((p) => p[2])).toEqual([{ expirationTtl: 3600 }, { expirationTtl: 3600 }]);
    expect(m.get("jev:subj:x:n")).toBe("2");
  });
});
