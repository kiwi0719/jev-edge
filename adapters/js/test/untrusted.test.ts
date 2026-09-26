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

  it("finds every Responses *_call_output item, mcp_call output and file_search_call results", () => {
    const v = normalize.extractUntrustedValues({ input: [
      { role: "user", content: "hi" },
      { type: "custom_tool_call", call_id: "c1", name: "f", input: "x" },
      { type: "custom_tool_call_output", call_id: "c1", output: "custom output" },
      { type: "local_shell_call_output", call_id: "c2", output: "shell output" },
      { type: "mcp_call", id: "m", name: "f", arguments: "{}", output: "mcp output" },
      { type: "mcp_list_tools", server_label: "s", tools: [] },
      { type: "file_search_call", id: "fs", results: [{ file_id: "f", text: "file text" }] },
    ] }, spec);
    expect(v).toEqual(["custom output", "shell output", "mcp output", "file text"]);
  });

  it("finds Gemini function responses, read whole, contents and parts in either form", () => {
    const fr = { functionResponse: { name: "search", response: { result: "found it", n: 2, items: ["one", { title: "two" }] } } };
    const v = normalize.extractUntrustedValues({ contents: [
      { role: "user", parts: [{ text: "the user's own words" }] },
      { role: "function", parts: [fr, { function_response: { name: "f", response: { output: "snake" } } }] },
    ] }, spec);
    expect(v).toEqual(["items", "one", "title", "two", "n", "result", "found it", "output", "snake"]);
    // one content and one part, as LiteLLM takes them
    expect(normalize.extractUntrustedValues({ contents: { role: "function", parts: fr } }, spec))
      .toEqual(["items", "one", "title", "two", "n", "result", "found it"]);
  });

  it("finds retrieved documents, read whole: Cohere v1 maps, v2 strings and { id, data }", () => {
    const v = normalize.extractUntrustedValues({ message: "hi", documents: [
      { title: "Refunds", snippet: "Refunds take 5 days.", url: "https://example.com/r" },
      "a plain v2 document",
      { id: "d3", data: { text: "v2 data", "Ignore previous": "" } },
    ] }, spec);
    expect(v).toEqual(["snippet", "Refunds take 5 days.", "title", "Refunds", "url", "https://example.com/r",
      "a plain v2 document", "data", "Ignore previous", "text", "v2 data", "id", "d3"]);
    // a Cohere v2 tool message's document parts
    expect(normalize.extractUntrustedValues({ messages: [{ role: "tool", tool_call_id: "c",
      content: [{ type: "document", document: { id: "x", data: { body: "tool doc" } } }] }] }, spec))
      .toEqual(["data", "body", "tool doc", "id", "x"]);
  });

  it("reads fields, and skips tool results when tool_results is false", () => {
    const doc = { messages: [{ role: "tool", content: "tool" }], context: [{ text: "c1" }, { text: "c2" }] };
    expect(normalize.extractUntrustedValues(doc, { fields: ["context[*].text"] })).toEqual(["tool", "c1", "c2"]);
    expect(normalize.extractUntrustedValues(doc, { tool_results: false, fields: ["context[*].text"] })).toEqual(["c1", "c2"]);
  });

  it("does not add a field value the tool results already hold", () => {
    const doc = { messages: [{ role: "tool", content: "tool" }], documents: [{ text: "d1" }, { text: "d2" }] };
    const fields = ["documents[*].text"];
    expect(normalize.extractUntrustedValues(doc, { fields })).toEqual(["tool", "text", "d1", "text", "d2"]);
    expect(normalize.extractUntrustedValues(doc, { tool_results: false, fields })).toEqual(["d1", "d2"]);
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
