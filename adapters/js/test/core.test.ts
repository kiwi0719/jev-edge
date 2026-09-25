// Unit tests for the core behaviours that golden vectors cannot pin: pattern
// conversion, resolve() copying, byte truncation, config validation, subject
// id hygiene and the breaker's post-probe reset (twin of the Lua specs).
import { describe, it, expect, vi } from "vitest";
import * as core from "../src/core";
import { luaPatternToRegExp, patternError, evaluate as rulesEvaluate } from "../src/core/rules";
import { resolve, load } from "../src/rules";
import { truncateBytes, normalize, fingerprint, djb2 } from "../src/core/normalize";
import { encodeReason } from "../src/core/verdict";
import { Breaker, memoryStore, OPEN, CLOSED } from "../src/core/breaker";

describe("luaPatternToRegExp", () => {
  it("keeps '-' inside a set as a range/literal and makes it lazy outside", () => {
    const set = luaPatternToRegExp("^/v1/[a-z-]+/chat");
    expect(set.test("/v1/my-tenant/chat")).toBe(true);
    expect(set.test("/v1/my_tenant/chat")).toBe(false);
    const cls = luaPatternToRegExp("^/t/[a-z]+/chat");
    expect(cls.test("/t/abc/chat")).toBe(true);
    expect(cls.test("/t/ab1/chat")).toBe(false);
    expect(cls.test("/t//chat")).toBe(false);
    const lazy = luaPatternToRegExp("^/v1/.-/chat$");
    expect(lazy.test("/v1/x/y/chat")).toBe(true);
    expect(lazy.source).toContain("*?");
    const range = luaPatternToRegExp("^/v[0-9]/[%a-]+$");
    expect(range.test("/v2/ab-cd")).toBe(true);
    expect(range.test("/v2/ab.cd")).toBe(false);
  });

  it("translates %-classes and escapes JS-only metacharacters", () => {
    expect(luaPatternToRegExp("^/a%.b/%d+$").test("/a.b/42")).toBe(true);
    expect(luaPatternToRegExp("^/a%.b/%d+$").test("/aXb/42")).toBe(false);
    expect(luaPatternToRegExp("^/x{y}|z$").test("/x{y}|z")).toBe(true);
    expect(() => luaPatternToRegExp("^/%g")).toThrow(/unsupported/);
  });

  it("patternError mirrors core/rules.lua", () => {
    expect(patternError("^/v1/chat")).toBeNull();
    expect(patternError("^/v1/[a-z]+")).toBeNull();
    expect(patternError("^/v1/[")).toMatch(/missing '\]'/);
    expect(patternError("^/v1/%")).toMatch(/ends with '%'/);
    expect(patternError("%b(")).toMatch(/%b/);
    expect(patternError("%fx")).toMatch(/%f/);
    expect(patternError("[]]")).toBeNull();
    expect(patternError("[^]]")).toBeNull();
    expect(() => luaPatternToRegExp("^/v1/[")).toThrow(/malformed/);
  });

  it("patternError rejects capture errors like core/rules.lua", () => {
    expect(patternError("^/v1/(chat")).toBe("unfinished capture");
    expect(patternError("^/v1/chat)")).toBe("invalid pattern capture");
    expect(patternError("^/v1/%1")).toBe("invalid capture index %1");
    expect(patternError("^/(v1%1)")).toBe("invalid capture index %1");
    expect(patternError("^/%0")).toBe("invalid capture index %0");
    for (const ok of ["^/v1/(chat)", "^/(v1)/%1", "^/v1/()", "^/v1/[()]", "^/v1/%(", "^/%b()"]) expect(patternError(ok)).toBeNull();
  });
});

describe("rules.resolve", () => {
  it("copies a rule set loaded by id so callers cannot mutate the module", () => {
    const a = resolve("llm-endpoints");
    const b = resolve("llm-endpoints");
    expect(a).not.toBe(b);
    expect(a).not.toBe(load("llm-endpoints"));
    a.templates = ["abuse"];
    expect(b.templates).toEqual(["injection"]);
    expect(load("llm-endpoints").templates).toEqual(["injection"]);
  });

  it("rejects malformed watch_paths at resolve time", () => {
    expect(() => resolve({ id: "t", watch_paths: ["^/v1/["] })).toThrow(/watch_paths\[1\]/);
    expect(() => resolve({ id: "t", watch_paths: [42 as never] })).toThrow(/must be a string/);
    expect(() => resolve({ watch_paths: [] })).toThrow(/needs an id/);
  });

  it("llm-endpoints reads every content type but media types", () => {
    const r = load("llm-endpoints");
    expect(r.content_types).toBeUndefined();
    expect(r.skip_content_types).toContain("image/");
    expect(r.max_body_bytes).toBe(1048576);
  });
});

describe("rules.evaluate body size", () => {
  it("uses the larger of declared and actual size", async () => {
    const body = '{"messages":[{"role":"user","content":"Please write a detailed summary of the attached quarterly report."}]}';
    const req = { method: "POST", path: "/v1/chat/completions", headers: { "content-type": "application/json" }, body, body_size: 0, client_ip: "1.2.3.4" };
    const [r] = await rulesEvaluate(req, load("llm-endpoints"), { re_find: core.rules.reFind });
    expect(r).toBe("suspect");
    // past max_body_bytes the body is scanned, not passed
    const [r2, , reason] = await rulesEvaluate({ ...req, body_size: 2_000_000 }, load("llm-endpoints"), { re_find: core.rules.reFind });
    expect([r2, reason]).toEqual(["suspect", "natural language (window)"]);
    const [r3, , reason3] = await rulesEvaluate({ ...req, body: undefined, body_size: 2_000_000 }, load("llm-endpoints"), { re_find: core.rules.reFind });
    expect([r3, reason3]).toEqual(["unjudgeable", "unjudgeable: body too large"]);
  });

  it("warns once about an always_suspect pattern that does not compile", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const rule = { ...load("llm-endpoints"), id: "bad", always_suspect: ["(unclosed"] };
    const body = '{"prompt":"Please write a detailed summary of the attached quarterly report."}';
    const req = { method: "POST", path: "/v1/chat/completions", headers: { "content-type": "application/json" }, body, body_size: body.length };
    await rulesEvaluate(req, rule, { re_find: core.rules.reFind });
    await rulesEvaluate(req, rule, { re_find: core.rules.reFind });
    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn.mock.calls[0][0]).toMatch(/does not compile/);
    warn.mockRestore();
  });
});

describe("normalize.truncateBytes", () => {
  it("never exceeds n bytes and never emits U+FFFD from a split code point", () => {
    const enc = new TextEncoder();
    const s = "abcü€😀";
    for (let n = 0; n <= enc.encode(s).length; n++) {
      const t = truncateBytes(s, n);
      expect(enc.encode(t).length).toBeLessThanOrEqual(n);
      expect(t).not.toContain("�");
      expect(s.startsWith(t)).toBe(true);
    }
    expect(truncateBytes("abcü", 4)).toBe("abc");
    expect(truncateBytes("abcü", 5)).toBe("abcü");
    expect(normalize("ü".repeat(10), { prefix_bytes: 5 })).toBe("üü");
  });

  it("fingerprint ignores prefix_bytes and hashes the whole text", () => {
    const a = "x".repeat(100) + " one";
    const b = "x".repeat(100) + " two";
    expect(fingerprint(a, { prefix_bytes: 10 }, djb2)).not.toBe(fingerprint(b, { prefix_bytes: 10 }, djb2));
    expect(fingerprint(a, { prefix_bytes: 10 }, djb2)).toBe(fingerprint(a, null, djb2));
    expect(fingerprint("12345678901234567890", null, djb2)).not.toBe("");
    expect(fingerprint("", null, djb2)).toBe("");
    // whitespace-only text is cached like any other: one fingerprint for all of it
    expect(fingerprint("   ", null, djb2)).not.toBe("");
    expect(fingerprint("\n\t ".repeat(40), null, djb2)).toBe(fingerprint("   ", null, djb2));
  });

  it("extracts content parts to a bounded depth", () => {
    const deep = { messages: [{ content: [{ content: [{ content: [{ content: [{ content: [{ text: "too deep" }] }] }] }] }] }] };
    expect(core.normalize.extractJson(deep as never, ["messages[*].content"])).toBe("");
    const ok = { messages: [{ content: [{ type: "tool_result", content: [{ type: "text", text: "nested" }] }] }] };
    expect(core.normalize.extractJson(ok as never, ["messages[*].content"])).toBe("nested");
  });
});

describe("verdict.encodeReason", () => {
  it("truncates the encoded output at 200 bytes, never inside an escape", () => {
    const r = encodeReason("/".repeat(70) + "ab");
    expect(r.length).toBeLessThanOrEqual(200);
    expect(r).toMatch(/^(%2F)+$/);
    expect(encodeReason("x".repeat(250)).length).toBe(200);
    expect(encodeReason("über")).toBe("%C3%BCber");
  });
});

describe("defaults.validate", () => {
  it("rejects configs that make a gate degenerate", () => {
    for (const over of [
      { policy: { block_threshold: 5, suspect_threshold: 2 } },
      { policy: { block_status: 42 } },
      { policy: { block_status: 403.5 } },
      { breaker: { window_s: 0 } },
      { breaker: { open_s: -1 } },
      { breaker: { min_samples: 0 } },
      { breaker: { fail_ratio: 0 } },
      { breaker: { fail_ratio: 1.5 } },
      { sampling: { max_samples: 0 } },
      { cache: { fp_ttl: 0 } },
      { cache: { rep_ttl: 0 } },
      { async: { max_async: -1 } },
      { client_ip: { trusted_hops: 0 } },
      { client_ip: { trusted_hops: 1.5 } },
    ]) {
      const [ok] = core.defaults.validate(core.defaults.merge(core.defaults.config, over));
      expect(ok, JSON.stringify(over)).toBeNull();
    }
    expect(core.defaults.config.client_ip.trusted_hops).toBe(1);
    expect(core.defaults.validate(core.defaults.merge(core.defaults.config, { policy: { block_status: 429 }, client_ip: { trusted_hops: 2 } }))[0]).toBe(true);
  });
});

describe("subject id hygiene", () => {
  const hash = (s: string) => "H(" + s + ")";
  it("hashed = true only accepts our own id shape", async () => {
    expect(await core.subject.hashId({ hashed: true }, "header:abc123", hash)).toBe("header:abc123");
    expect(await core.subject.hashId({ hashed: true }, "not a hash; drop table", hash)).toBeNull();
    expect(await core.subject.hashId({ hashed: true }, "HEADER:ABC", hash)).toBeNull();
    expect(await core.subject.hashId({ from: "header", salt: "pepper" }, "key-1", hash)).toBe("header:H(pepper\0key-1)");
  });
  it("drops oversize values", () => {
    expect(core.subject.extract({ enabled: true, from: "header", name: "x" }, { header: () => "k".repeat(600) })).toBeNull();
    expect(core.subject.extract({ enabled: true, from: "header", name: "x" }, { header: () => "  k-1 \n" })).toBe("k-1");
  });
});

describe("breaker", () => {
  it("does not re-trip on the success that follows a probe inside the same window", async () => {
    let now = 960;
    const store = memoryStore();
    const b = new Breaker(store, () => now, { window_s: 60, min_samples: 4, fail_ratio: 0.5, open_s: 30 });
    await b.success(); await b.failure(); await b.failure(); await b.failure();
    expect(await b.state()).toBe(OPEN);
    now += 31;
    expect(await b.allow()).toBe(true);
    await b.success();
    expect(await b.state()).toBe(CLOSED);
    await b.success();
    expect(await b.state()).toBe(CLOSED);
  });
});

describe("in-flight cap and the breaker", () => {
  // a burst over max_inflight never reached the provider; counting it let a
  // burst of concurrent requests trip the breaker and switch L2 off for open_s
  it("a busy judge is not a breaker failure", async () => {
    const breaker = new Breaker(memoryStore(), () => 1000, { min_samples: 1, fail_ratio: 0.5 });
    for (let i = 0; i < 50; i++) {
      const body = JSON.stringify({ messages: [{ role: "user", content: "Please write a detailed summary, variant " + "x".repeat(i + 1) }] });
      const v = await core.evaluate(
        { method: "POST", path: "/v1/chat/completions", headers: { "content-type": "application/json" }, body, body_size: body.length, client_ip: "203.0.113.7" },
        {
          config: core.defaults.merge(core.defaults.config, {}),
          rules: [load("llm-endpoints")],
          cache: memoryStore(),
          breaker,
          clock: () => 1000,
          hash: djb2,
          json_decode: JSON.parse,
          judge: { call: () => [null, core.judge.BUSY] },
        } as core.Ctx,
      );
      expect(v.verdict).toBe(core.verdict.ERROR);
      expect(v.reason).toBe(core.judge.BUSY);
    }
    expect(await breaker.state()).toBe(CLOSED);
  });
});

describe("normalize.fieldKeys", () => {
  it("matches core/normalize.lua field_keys, in linear time", () => {
    const want: Record<string, string> = {
      "messages[*].content": "content,text", "prompt": "prompt", "input.text": "text", "a.": "", "[*]": "",
      "x[*]": "x", "a.b[*].c[*]": "c", "": "", "...": "", "a*b": "b", "a]b[": "b",
    };
    for (const [c, w] of Object.entries(want)) expect([...core.normalize.fieldKeys([c])].sort().join(","), c).toBe(w);
    const t0 = Date.now();
    core.normalize.fieldKeys([")".repeat(200000)]);
    expect(Date.now() - t0).toBeLessThan(200);
  });
});

// Twins of tests in core/spec/normalize_spec.lua and core/spec/judge_spec.lua.
describe("normalize.extract: form bodies", () => {
  // the regex formValues replaced; the new code gives the same values
  const old = (b: string) => [...b.matchAll(/([^&=]+)=([^&]*)/g)].map((m) => m[2]).join("\n");
  const FORM = "application/x-www-form-urlencoded";

  it("gives the values the old regex gave", () => {
    for (const b of ["a=1&b=2", "a=b=c", "=b=c", "==b=c=d", "&&a=1&&", "a", "=", "a=&b=",
      "a=1&=2&c", "x==", "=&=&a", "a&b=1", "name=v&&=&k=v2=v3"]) {
      expect(core.normalize.extract(b, FORM, [])[0], b).toBe(old(b));
    }
  });

  it("reads a 1 MiB body without & or = in linear time", () => {
    const a = "a".repeat(1 << 20);
    const t0 = Date.now();
    expect(core.normalize.extract(a, FORM, [])[0]).toBe("");
    expect(core.normalize.extract("x=1&" + a, undefined, [])[0]).toBe("1");
    // the regex took about 30 s on 256 KiB; this is milliseconds
    expect(Date.now() - t0).toBeLessThan(2000);
  });
});

describe("normalize.chunks", () => {
  it("still cuts valid UTF-8 at a character boundary", () => {
    const [pieces] = core.normalize.chunks("\u{1F600}".repeat(40), 63);
    for (const p of pieces) expect(new TextEncoder().encode(p).length % 4).toBe(0);
  });
});
