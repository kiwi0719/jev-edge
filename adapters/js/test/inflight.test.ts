// jev.max_inflight: the cap on L2 calls in flight, per isolate, as
// resty/jev/http.lua enforces it on nginx (docs/design.md, Timeouts and breaker).
import { describe, it, expect } from "vitest";
import { createRuntime, evaluate } from "../src";
import { breaker, judge } from "../src/core";
import type { Provider } from "../src/providers";

const text = (i: number) => JSON.stringify({ messages: [{ role: "user", content: "Please summarise the attached quarterly report, part " + i + "." }] });
const post = (i: number) =>
  new Request("https://edge.example/v1/chat/completions", {
    method: "POST", body: text(i), headers: { "content-type": "application/json", "x-forwarded-for": "203.0.113.7" },
  });

/** A provider whose calls wait until released, and which counts how many run at once. */
function gated(outcome: (i: number) => "answer" | "throw" | "timeout" = () => "answer") {
  const waiting: (() => void)[] = [];
  let calls = 0;
  let running = 0;
  let peak = 0;
  const provider: Provider = {
    name: "gated",
    call: async () => {
      const i = calls++;
      running++;
      peak = Math.max(peak, running);
      try {
        await new Promise<void>((r) => waiting.push(r));
        const o = outcome(i);
        if (o === "throw") throw new Error("provider blew up");
        if (o === "timeout") return [null, "timeout after 400 ms", judge.TIMEOUT];
        return [{ injection: 0.1 }, null];
      } finally {
        running--;
      }
    },
  };
  const tick = () => new Promise((r) => setTimeout(r, 5));
  return {
    provider,
    get calls() { return calls; },
    get peak() { return peak; },
    /** Wait for `n` calls to be waiting, then let them all go. */
    release: async (n: number) => {
      for (let t = 0; t < 200 && waiting.length < n; t++) await tick();
      for (const r of waiting.splice(0)) r();
    },
  };
}

describe("jev.max_inflight", () => {
  const cfg = (max: number) => ({ jev: { max_inflight: max, timeout_ms: 400 }, breaker: { min_samples: 1 }, policy: { mode: "enforce" as const } });

  it("refuses a call past the cap as busy, which passes as error and does not count against the breaker", async () => {
    const g = gated();
    const rt = createRuntime({ config: cfg(2), provider: g.provider });
    const held = [evaluate(post(0), rt), evaluate(post(1), rt)];
    // both slots taken: the third never reaches the provider
    for (let t = 0; t < 200 && g.calls < 2; t++) await new Promise((r) => setTimeout(r, 5));
    const refused = await evaluate(post(2), rt);
    expect(refused.verdict.verdict).toBe("error");
    expect(refused.verdict.reason).toBe(judge.BUSY);
    expect(refused.verdict.error_kind).toBe("busy");
    expect(refused.response).toBeUndefined(); // passed, not blocked
    expect(g.calls).toBe(2);
    await g.release(2);
    expect((await Promise.all(held)).map((e) => e.verdict.verdict)).toEqual(["safe", "safe"]);
    // min_samples 1: a counted failure would have opened it
    expect(await rt.breaker.state()).toBe(breaker.CLOSED);
    expect(rt.inflight!.held).toBe(0);
    // the slots came back: judged again
    const again = evaluate(post(3), rt);
    await g.release(1);
    expect((await again).verdict.verdict).toBe("safe");
    expect(g.peak).toBe(2);
  });

  it("gives the slot back after an error, a throw and a timeout", async () => {
    const outcomes = ["throw", "timeout", "answer"] as const;
    const g = gated((i) => outcomes[i % 3]);
    const rt = createRuntime({ config: { ...cfg(1), breaker: { min_samples: 100 } }, provider: g.provider });
    for (let i = 0; i < 3; i++) {
      const ev = evaluate(post(10 + i), rt);
      await g.release(1);
      await ev;
      expect(rt.inflight!.held).toBe(0);
    }
    expect(g.calls).toBe(3);
  });

  it("max_inflight 0 refuses every call", async () => {
    const g = gated();
    const rt = createRuntime({ config: cfg(0), provider: g.provider });
    const ev = await evaluate(post(20), rt);
    expect([ev.verdict.verdict, ev.verdict.reason]).toEqual(["error", judge.BUSY]);
    expect(g.calls).toBe(0);
  });
});
