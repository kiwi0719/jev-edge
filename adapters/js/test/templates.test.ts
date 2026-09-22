// The provider request body is built from the template strings, and the golden
// vectors only pin the question names: this pins the wording. Every template in
// src/core/templates.ts must match core/templates/<name>.lua word for word.
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { TEMPLATES } from "../src/core/templates.js";

const dir = fileURLToPath(new URL("../../../core/templates/", import.meta.url));

// The value of `key = "..." .. "..."` in a Lua template file: string literals
// joined with `..`, across lines. Enough for these files (no long strings).
const reEscape = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

function luaString(src: string, key: string): string | undefined {
  const m = new RegExp(`(^|\\s)${reEscape(key)}\\s*=\\s*`, "m").exec(src);
  if (!m) return undefined;
  let i = m.index + m[0].length;
  let out = "";
  for (;;) {
    while (/\s/.test(src[i])) i++;
    if (src[i] !== '"') break;
    i++;
    while (src[i] !== '"') {
      if (src[i] === "\\") { out += src[i + 1]; i += 2; } else { out += src[i]; i++; }
    }
    i++;
    while (/\s/.test(src[i])) i++;
    if (src.slice(i, i + 2) !== "..") break;
    i += 2;
  }
  return out;
}

// the criteria tables: `criteria = { [true] = ..., [false] = ... }`
function luaCriteria(src: string, table: string): { true: string; false: string } | undefined {
  const start = new RegExp(`(^|\\s)${reEscape(table)}\\s*=\\s*\\{`, "m").exec(src);
  if (!start) return undefined;
  const body = src.slice(start.index + start[0].length, src.indexOf("\n  },", start.index));
  const t = luaString(body, "[true]");
  const f = luaString(body, "[false]");
  return t !== undefined && f !== undefined ? { true: t, false: f } : undefined;
}

describe("templates match core/templates/*.lua", () => {
  for (const [name, t] of Object.entries(TEMPLATES)) {
    it(name, () => {
      const src = readFileSync(dir + name + ".lua", "utf8");
      expect(t.instructions).toBe(luaString(src, "instructions"));
      expect(t.instructions_ctx).toBe(luaString(src, "instructions_ctx"));
      expect(t.criteria).toEqual(luaCriteria(src, "criteria"));
      expect(t.criteria_ctx).toEqual(luaCriteria(src, "criteria_ctx"));
    });
  }

  it("covers every Lua template", () => {
    for (const n of ["injection", "abuse", "untrusted"]) expect(TEMPLATES[n]).toBeDefined();
  });
});
