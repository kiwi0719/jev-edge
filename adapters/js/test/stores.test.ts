// The memory store every host falls back to: bounded, and expired keys go
// even when nobody reads them again.
import { describe, it, expect } from "vitest";
import { memoryStore } from "../src/cf/stores";
import { createRuntime } from "../src";

describe("memoryStore", () => {
  it("stays under maxEntries through a flood of distinct keys never read again", () => {
    let now = 1000;
    const s = memoryStore(() => now, { maxEntries: 1000 });
    for (let i = 0; i < 200_000; i++) s.set("fp:" + i, { score: 0.1 }, 1);
    expect(s.size).toBe(1000);
    now += 5;
    for (let i = 0; i < 1000; i++) s.set("new:" + i, { score: 0.1 }, 1);
    expect(s.size).toBeLessThanOrEqual(1000);
    expect(s.get("new:999")).toEqual({ score: 0.1 });
    expect(s.get("fp:199999")).toBeUndefined(); // expired and gone
  });

  it("sweeps expired entries on write, capped or not", () => {
    let now = 1000;
    const s = memoryStore(() => now);
    for (let i = 0; i < 200_000; i++) s.set("old:" + i, 1, 1);
    expect(s.size).toBe(200_000);
    now += 2; // every old entry has expired, and none is read again
    for (let i = 0; i < 200_000; i++) s.set("new:" + i, 1, 60);
    expect(s.size).toBeLessThanOrEqual(200_000 + 8);
    // entries without a ttl never expire, and are never swept
    const t = memoryStore(() => now);
    t.set("adapt", { n: 1 }, 0);
    now += 1e6;
    for (let i = 0; i < 100; i++) t.set("k" + i, 1, 1);
    expect(t.get("adapt")).toEqual({ n: 1 });
  });

  it("evicts the least recently used: a read keeps an entry, a write refreshes it", () => {
    const s = memoryStore(() => 1000, { maxEntries: 3 });
    s.set("a", 1, 0);
    s.set("b", 2, 0);
    s.set("c", 3, 0);
    expect(s.get("a")).toBe(1); // a is now the most recent
    s.set("d", 4, 0); // b goes
    expect(s.get("b")).toBeUndefined();
    expect([s.get("a"), s.get("c"), s.get("d")]).toEqual([1, 3, 4]);
    s.set("c", 30, 0); // written: the most recent
    s.incr!("e", 1, 0); // a goes (read before c, d)
    expect(s.get("a")).toBeUndefined();
    expect([s.get("c"), s.get("d"), s.get("e")]).toEqual([30, 4, 1]);
    expect(s.size).toBe(3);
  });

  it("incr sets the ttl on creation only, and starts again once expired", () => {
    let now = 1000;
    const s = memoryStore(() => now, { maxEntries: 10 });
    expect(s.incr!("n", 1, 10)).toBe(1);
    now += 6;
    expect(s.incr!("n", 2, 10)).toBe(3); // the first ttl still runs
    now += 5;
    expect(s.get("n")).toBeUndefined();
    expect(s.incr!("n", 1, 10)).toBe(1);
    s.expire!("n", 100);
    now += 50;
    expect(s.get("n")).toBe(1);
    s.set("n", null, 0);
    expect(s.get("n")).toBeUndefined();
  });

  it("the runtime caps its default cache and leaves state uncapped", async () => {
    const rt = createRuntime({});
    for (let i = 0; i <= 20_000; i++) await rt.cache.set("fp:" + i, { score: 0.1 }, 300);
    expect(await rt.cache.get("fp:0")).toBeUndefined();
    expect(await rt.cache.get("fp:20000")).toEqual({ score: 0.1 });
    for (let i = 0; i <= 60_000; i++) await rt.state.set("s:" + i, 1, 300);
    expect(await rt.state.get("s:0")).toBe(1);
    for (let i = 0; i <= 50_000; i++) await rt.subjectStore.set("subj:" + i, 1, 300);
    expect(await rt.subjectStore.get("subj:0")).toBeUndefined();
    expect(await rt.subjectStore.get("subj:1")).toBe(1);
  });
});
