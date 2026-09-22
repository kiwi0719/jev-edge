// Replays core/golden/*.json (the repo-level contract) against the TypeScript
// core. Semantics of `input` are documented in core/golden/README.md and
// mirrored from core/spec/golden_spec.lua.
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import * as core from "../src/core";
import { load as loadRule, resolve as resolveRule } from "../src/rules";
import { Breaker, memoryStore, OPEN, CLOSED } from "../src/core/breaker";

const GOLDEN = resolve(__dirname, "../../../core/golden");

interface Case { name: string; input: any; expect: any }
interface Doc { format_version: number; suite: string; cases: Case[] }

function load(name: string): Doc {
  const doc = JSON.parse(readFileSync(resolve(GOLDEN, name + ".json"), "utf8")) as Doc;
  expect(doc.format_version).toBe(1);
  return doc;
}

const reFind = core.rules.reFind;
const jsonDecode = (s: string) => JSON.parse(s);

function storeFrom(map: Record<string, unknown>) {
  const s = memoryStore();
  for (const [k, v] of Object.entries(map ?? {})) s.set(k, v, 0);
  return s;
}

describe("golden: normalize", () => {
  for (const c of load("normalize").cases) {
    it(c.name, () => {
      expect(core.normalize.normalize(c.input.text, c.input.opts)).toBe(c.expect.normalized);
      expect(core.normalize.fingerprint(c.input.text, c.input.opts, core.normalize.djb2)).toBe(c.expect.fingerprint);
    });
  }
});

describe("golden: extract", () => {
  for (const c of load("extract").cases) {
    it(c.name, () => {
      const [text, kind] = core.normalize.extract(c.input.body, c.input.content_type, c.input.fields, jsonDecode);
      expect({ text, kind }).toEqual(c.expect);
    });
  }
});

describe("golden: rules", () => {
  for (const c of load("rules").cases) {
    it(c.name, async () => {
      const ctx = { cache: storeFrom(c.input.cache), clock: () => c.input.clock, json_decode: jsonDecode, re_find: reFind };
      const [result, text, reason] = await core.rules.evaluate(c.input.req, loadRule(c.input.rule), ctx);
      expect({ result, text, reason }).toEqual(c.expect);
    });
  }
});

describe("golden: policy", () => {
  for (const c of load("policy").cases) {
    it(c.name, () => {
      let d: core.policy.Decision;
      if (c.input.event === "error") d = core.policy.onError();
      else if (c.input.event === "skipped") d = core.policy.onSkipped();
      else d = core.policy.decide(c.input.score, c.input.policy);
      expect({ action: d[0], label: d[1], async: d[2] }).toEqual(c.expect);
    });
  }
});

describe("golden: verdict", () => {
  for (const c of load("verdict").cases) {
    it(c.name, () => {
      const v = core.verdict.newVerdict(c.input);
      expect({ verdict: v, headers: core.verdict.headers(v) }).toEqual(c.expect);
    });
  }
});

describe("golden: evaluate", () => {
  for (const c of load("evaluate").cases) {
    it(c.name, async () => {
      const inp = c.input;
      const cache = storeFrom(inp.cache);
      const writes: Record<string, { value: unknown; ttl: number }> = {};
      let calls = 0;
      let seen: core.Prompt | undefined;
      let breaker: Breaker | undefined;
      if (inp.breaker) {
        const bstore = memoryStore();
        bstore.set("brk:state", { state: inp.breaker === "open" ? OPEN : CLOSED, until_ts: inp.clock + 30 }, 0);
        breaker = new Breaker(bstore, () => inp.clock, {});
      }
      let recorded: core.SubjectEntry | null = null;
      const swrites: Record<string, { value: unknown; ttl: number }> | null = inp.subject ? {} : null;
      const sstore = storeFrom(inp.subject?.store ?? {});
      const ctx: core.Ctx = {
        config: core.defaults.merge(core.defaults.config, inp.config),
        subject: inp.subject
          ? {
            id: inp.subject.id, history: inp.subject.history, record: (e) => { recorded = e; },
            store: {
              get: (k) => sstore.get(k),
              set: (k, v, ttl) => { swrites![k] = { value: v, ttl }; sstore.set(k, v, ttl); },
              incr: (k, by, ttl) => {
                const n = (Number(sstore.get(k)) || 0) + by;
                sstore.set(k, n, ttl);
                swrites![k] = { value: n, ttl };
                return n;
              },
            },
          }
          : undefined,
        // an id, or an inline spec resolved the way a config's `rules` list is
        rules: inp.rules.map((r: string | object) => (typeof r === "string" ? loadRule(r) : resolveRule(r as never))),
        breaker,
        cache: {
          get: (k) => cache.get(k),
          set: (k, v, ttl) => { writes[k] = { value: v, ttl }; cache.set(k, v, ttl); },
        },
        clock: () => inp.clock,
        hash: core.normalize.djb2,
        json_decode: jsonDecode,
        re_find: reFind,
        judge: {
          call: (prompt) => {
            calls++;
            seen = prompt;
            if (inp.judge.error) return [null, inp.judge.error];
            if (inp.judge.by_question) {
              // answers only the questions this prompt asked, as a provider does
              const a: Record<string, unknown> = {};
              for (const n of Object.keys(prompt.questions)) {
                if (inp.judge.by_question[n] !== undefined) a[n] = inp.judge.by_question[n];
              }
              return [a, null];
            }
            return [inp.judge.answers, null];
          },
        },
        log: () => {},
      };
      const v = await core.evaluate(inp.req, ctx);
      const prompt = seen ? { text: seen.text, context: seen.context, questions: Object.keys(seen.questions).sort() } : null;
      expect({
        verdict: v, headers: core.verdict.headers(v), judge_calls: calls, prompt,
        cache_writes: writes, subject_record: recorded, subject_store_writes: swrites,
      }).toEqual(c.expect);
    });
  }
});
