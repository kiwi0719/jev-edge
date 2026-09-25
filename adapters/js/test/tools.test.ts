// Tool calls: what the golden vectors leave out (bounds a vector cannot
// reach, rule resolution). Twin of core/spec/tools_spec.lua.
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { normalize, rules } from "../src/core/index.js";
import { load, resolve } from "../src/rules/index.js";

const ARGS = ["messages[*].tool_calls[*].function.arguments.**"];
const withArgs = (v: normalize.JsonValue): normalize.JsonValue =>
  ({ messages: [{ role: "assistant", tool_calls: [{ function: { name: "f", arguments: v } }] }] });
const decode = (s: string) => JSON.parse(s) as normalize.JsonValue;

describe('tool-call arguments ("**" paths)', () => {
  const saved = { ...normalize.DEEP };
  beforeEach(() => Object.assign(normalize.DEEP, saved));
  afterEach(() => Object.assign(normalize.DEEP, saved));

  it("reads a string of JSON decoded and anything else as it is", () => {
    expect(normalize.extractJson(withArgs('{"b":"two","a":"one"}'), ARGS, decode)).toBe("a\none\nb\ntwo");
    expect(normalize.extractJson(withArgs("{not json"), ARGS, decode)).toBe("{not json");
    // no decoder: the string as it is
    expect(normalize.extractJson(withArgs('{"a":"one"}'), ARGS)).toBe('{"a":"one"}');
  });

  it("stops at the node bound and says so", () => {
    normalize.DEEP.nodes = 3;
    let [, , , , cut] = normalize.extract(JSON.stringify(withArgs(["a", "b", "c", "d"])), "application/json", ARGS);
    expect(normalize.extractJsonValues(withArgs(["a", "b", "c", "d"]), ARGS, decode)).toEqual(["a", "b", "c"]);
    expect(cut).toBe(true);
    // an object with more keys than the budget left is not read at all
    const obj = withArgs({ k1: "v", k2: "v", k3: "v", k4: "v" });
    expect(normalize.extractJsonValues(obj, ARGS, decode)).toEqual([]);
    [, , , , cut] = normalize.extract(JSON.stringify(obj), "application/json", ARGS);
    expect(cut).toBe(true);
  });

  it("stops at the depth bound and says so", () => {
    normalize.DEEP.depth = 2;
    const body = JSON.stringify(withArgs({ a: { b: { c: "deep" } } }));
    const [, , values, , cut] = normalize.extract(body, "application/json", ARGS);
    expect(values).toEqual(["a", "b"]);
    expect(cut).toBe(true);
  });

  it("counts neither empty objects nor null against the bounds", () => {
    normalize.DEEP.depth = 1;
    const body = JSON.stringify(withArgs({ x: {}, y: null, z: "v" }));
    const [, , values, , cut] = normalize.extract(body, "application/json", ARGS);
    expect(values).toEqual(["x", "y", "z", "v"]);
    expect(cut).toBeFalsy();
  });

  it("marks the text windowed when a bound cut it", async () => {
    normalize.DEEP.nodes = 2;
    const body = JSON.stringify({ messages: [{ role: "user", content: "Please summarise the attached report." },
      { role: "assistant", tool_calls: [{ function: { name: "f", arguments: ["a", "b", "c"] } }] }] });
    const [r, , reason] = await rules.evaluate({ method: "POST", path: "/v1/chat/completions",
      headers: { "content-type": "application/json" }, body, body_size: body.length }, load("llm-endpoints"),
    { json_decode: decode, re_find: rules.reFind });
    expect(r).toBe(rules.SUSPECT);
    expect(reason).toBe("natural language (window)");
  });

  it("sorts keys in UTF-8 byte order, as Lua does", () => {
    expect(["\u{1F600}", "", "é", "a", "Z"].sort(normalize.byteOrder)).toEqual(["Z", "a", "é", "", "\u{1F600}"]);
  });

  it("reads the arguments key past max_body_bytes too", () => {
    expect(normalize.fieldKeys(ARGS).has("arguments")).toBe(true);
  });
});

describe("rules.resolve: field paths", () => {
  it("fills in the tool-call argument paths for an inline rule", () => {
    expect(resolve({ id: "x", watch_paths: [] }).text_fields).toEqual(load("llm-endpoints").text_fields);
  });

  it('rejects a path "**" is not the last segment of, and paths that are not strings', () => {
    expect(() => resolve({ id: "x", extends: "llm-endpoints", text_fields: ["a.**.b"] }))
      .toThrow('rule x: text_fields[1] "**" must be the last segment');
    expect(() => resolve({ id: "x", extends: "llm-endpoints", text_fields: ["prompt", 3 as never] }))
      .toThrow("rule x: text_fields[2] must be a non-empty string");
    expect(() => resolve({ id: "x", extends: "llm-endpoints", text_fields: "prompt" as never }))
      .toThrow("rule x: text_fields must be a list of paths");
  });
});
