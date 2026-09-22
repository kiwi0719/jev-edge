// untrusted content: what the golden vectors leave out (config validation, rule
// resolution, extraction details). Twin of core/spec/untrusted_spec.lua.
import { describe, it, expect } from "vitest";
import { defaults, normalize } from "../src/core/index.js";
import { resolve } from "../src/rules/index.js";

describe("untrusted: extraction", () => {
  const spec = { tool_results: true, fields: [] as string[] };

  it("finds OpenAI tool and legacy function messages", () => {
    const v = normalize.extractUntrustedValues({ messages: [
      { role: "user", content: "hi" }, { role: "tool", content: "tool says" }, { role: "function", name: "f", content: "function says" },
    ] }, spec);
    expect(v).toEqual(["tool says", "function says"]);
  });

  it("finds Anthropic tool_result blocks, nested content included", () => {
    const v = normalize.extractUntrustedValues({ messages: [{ role: "user", content: [
      { type: "tool_result", tool_use_id: "t1", content: "plain result" },
      { type: "tool_result", tool_use_id: "t2", content: [{ type: "text", text: "block result" }] },
      { type: "text", text: "the user's own words" },
    ] }] }, spec);
    expect(v).toEqual(["plain result", "block result"]);
  });

  it("finds Responses API function_call_output items", () => {
    const v = normalize.extractUntrustedValues({ input: [
      { role: "user", content: "hi" },
      { type: "function_call", call_id: "c", name: "f", arguments: "{}" },
      { type: "function_call_output", call_id: "c", output: "the output" },
    ] }, spec);
    expect(v).toEqual(["the output"]);
  });

  it("reads fields, and skips tool results when tool_results is false", () => {
    const doc = { messages: [{ role: "tool", content: "tool" }], documents: [{ text: "d1" }, { text: "d2" }] };
    expect(normalize.extractUntrustedValues(doc, { fields: ["documents[*].text"] })).toEqual(["tool", "d1", "d2"]);
    expect(normalize.extractUntrustedValues(doc, { tool_results: false, fields: ["documents[*].text"] })).toEqual(["d1", "d2"]);
  });

  it("ignores a top-level array and a messages object", () => {
    expect(normalize.extractUntrustedValues([{ role: "tool", content: "x" }], spec)).toEqual([]);
    expect(normalize.extractUntrustedValues({ messages: { role: "tool", content: "x" } }, spec)).toEqual([]);
  });
});

describe("untrusted: config", () => {
  const check = (u: unknown) => defaults.validate(defaults.merge(defaults.config, { untrusted: u }))[1];

  it("is off by default", () => {
    expect(defaults.config.untrusted.enabled).toBe(false);
    expect(defaults.config.untrusted.templates).toEqual(["untrusted"]);
  });

  it("validates types with the Lua messages", () => {
    expect(check({ enabled: true, fields: ["documents[*].text"] })).toBeNull();
    expect(check({ enabled: "yes" })).toBe("untrusted.enabled must be true|false");
    expect(check({ fields: "documents" })).toBe("untrusted.fields must be a list of strings");
    expect(check({ fields: [""] })).toBe("untrusted.fields[1] must be a non-empty string");
    expect(check({ templates: [] })).toBe("untrusted.templates must not be empty");
  });

  it("rejects a bad untrusted table on a rule", () => {
    expect(() => resolve({ extends: "llm-endpoints", untrusted: { enabled: 1 as unknown as boolean } }))
      .toThrow("rule llm-endpoints: untrusted.enabled must be true|false");
    expect(resolve({ extends: "llm-endpoints", untrusted: { enabled: true } }).untrusted).toEqual({ enabled: true });
  });

  it("lets a rule override the config section", () => {
    const s = defaults.untrustedSpec(defaults.config, { untrusted: { enabled: true, fields: ["ctx"] } });
    expect(s).toEqual({ enabled: true, tool_results: true, fields: ["ctx"], templates: ["untrusted"] });
    expect(defaults.untrustedSpec(defaults.config, {}).enabled).toBe(false);
  });
});
