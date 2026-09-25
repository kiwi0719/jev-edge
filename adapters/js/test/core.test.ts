// Unit tests for the core behaviours that golden vectors cannot pin: pattern
// conversion, resolve() copying, byte truncation, config validation, subject
// id hygiene and the breaker's post-probe reset (twin of the Lua specs).
import { describe, it, expect, vi } from "vitest";
import * as core from "../src/core";
import { luaPatternToRegExp, patternError, pathMatches, canonicalPath, evaluate as rulesEvaluate } from "../src/core/rules";
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

describe("pathMatches (twin of core/spec/rules_spec.lua)", () => {
  const W = load("llm-endpoints").watch_paths;

  it("matches the path the backend routes on: ASCII case folded", () => {
    for (const p of ["/v1/Chat/Completions", "/V1/COMPLETIONS", "/API/chat"]) expect(pathMatches(p, W), p).not.toBeNull();
    expect(pathMatches("/Proxy/V1/Chat", W)).toBeNull();
  });

  it("drops ';' parameters from every segment and resolves what they leave", () => {
    for (const p of ["/v1;a=b/chat/completions", "/api;x/chat", "/v1/;a=b/chat/completions", "/v1/x/..;/chat/completions", "/;jsessionid=1/v1/chat"]) {
      expect(pathMatches(p, W), p).not.toBeNull();
    }
    expect(pathMatches("/static;v=1/app.js", W)).toBeNull();
  });

  it("keeps the case when the rule asks for it, and still drops parameters", () => {
    expect(pathMatches("/V1/chat/completions", W, true)).toBeNull();
    expect(pathMatches("/v1;a=b/chat/completions", W, true)).not.toBeNull();
    expect(pathMatches("/Tenant/Chat", ["^/Tenant/Chat"], true)).not.toBeNull();
    expect(pathMatches("/tenant/chat", ["^/Tenant/Chat"], true)).toBeNull();
  });

  it("folds pattern letters but not the letter after %", () => {
    expect(pathMatches("/tenants/acme/chat", ["^/Tenants/[A-Z]+/Chat"])).not.toBeNull();
    expect(pathMatches("/t/%a", ["^/t/%%A$"])).not.toBeNull();
  });

  it("folds ASCII only, like the Lua core", () => {
    expect(pathMatches("/v1/É", ["^/v1/é"])).toBeNull();
    expect(canonicalPath("/V1/É;x")).toBe("/v1/É");
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
