// Providers turn a core prompt into an L2 answer map. Four ship:
//   jev            TypeSafe System One HTTP API (same request as the Lua provider)
//   openai-compat  any OpenAI-style chat endpoint
//   backend        an existing jev-edge (OpenResty/Envoy) reached at /_jev/authz:
//                  the "thin Worker" mode, one set of thresholds for edge and origin
//   mock           fixed score, no network
import type { Prompt, Answers } from "../core/judge";
import type { JevConfig } from "../core/defaults";

export type JudgeResult = [Answers, null] | [null, string];

export interface Provider {
  name: string;
  call(prompt: Prompt, cfg: JevConfig, timeoutMs: number, init?: ProviderRequestInfo): Promise<JudgeResult>;
}

/** What the worker knows about the original request; only `backend` uses it. */
export interface ProviderRequestInfo {
  method: string;
  path: string;
  headers: Headers;
  body: string | null;
  clientIp: string;
  /** Hashed subject id, when config.subject is enabled; the backend provider forwards it as X-Jev-Subject. */
  subjectId?: string;
}

async function fetchWithTimeout(url: string, init: RequestInit, timeoutMs: number): Promise<Response> {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: ac.signal });
  } finally {
    clearTimeout(t);
  }
}

function errorString(e: unknown, timeoutMs: number): string {
  if (e instanceof Error && e.name === "AbortError") return `timeout after ${timeoutMs} ms`;
  return e instanceof Error ? e.message : String(e);
}

// ---------------------------------------------------------------------------

export const jev: Provider = {
  name: "jev",
  async call(prompt, cfg, timeoutMs) {
    const deployment = prompt.context.deployment || undefined;
    const questions: Record<string, unknown> = {};
    for (const [name, t] of Object.entries(prompt.questions)) {
      const instr = (deployment && t.instructions_ctx) || t.instructions;
      const crit = (deployment && t.criteria_ctx) || t.criteria;
      const q: Record<string, unknown> = { type: "noul", instructions: instr };
      if (crit) q.criteria = { true: crit.true, false: crit.false };
      questions[name] = q;
    }
    const state: unknown = deployment ? { assistant: deployment, user_message: prompt.text } : prompt.text;
    const body = JSON.stringify({ model: cfg.model ?? "jev-latest", state, questions });
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (cfg.api_key) headers.Authorization = "Bearer " + cfg.api_key;
    let res: Response;
    try {
      res = await fetchWithTimeout(cfg.endpoint ?? "https://api.typesafe.ai/v1/systemone", { method: "POST", headers, body }, timeoutMs);
    } catch (e) {
      return [null, errorString(e, timeoutMs)];
    }
    if (res.status !== 200) return [null, "jev http " + res.status];
    let decoded: { answers?: Record<string, { noul?: unknown }> };
    try {
      decoded = (await res.json()) as typeof decoded;
    } catch {
      return [null, "jev: malformed response"];
    }
    if (!decoded || typeof decoded.answers !== "object" || decoded.answers === null) return [null, "jev: malformed response"];
    const answers: Answers = {};
    for (const [name, a] of Object.entries(decoded.answers)) {
      if (a && typeof a === "object" && typeof a.noul === "number") answers[name] = a.noul;
    }
    return [answers, null];
  },
};

// ---------------------------------------------------------------------------

function systemPrompt(questions: Prompt["questions"]): string {
  const lines = [
    "You are a security classifier for an API gateway.",
    "For each question below, estimate the probability (0.0 to 1.0) that the answer is YES",
    "for the user input that follows. Reply with ONLY a JSON object whose keys are exactly the",
    "question ids and whose values are numbers between 0 and 1. No other keys, no prose.",
    "",
  ];
  const example: string[] = [];
  for (const [name, t] of Object.entries(questions)) {
    lines.push(`question id "${name}": ${t.instructions}`);
    if (t.criteria) {
      lines.push("  YES when: " + t.criteria.true);
      lines.push("  NO when: " + t.criteria.false);
    }
    example.push(`"${name}": 0.0`);
  }
  lines.push("", "Example reply: {" + example.join(", ") + "}");
  return lines.join("\n");
}

export const openaiCompat: Provider = {
  name: "openai-compat",
  async call(prompt, cfg, timeoutMs) {
    const endpoint = (cfg.endpoint ?? "http://127.0.0.1:11434/v1").replace(/\/+$/, "");
    const body = JSON.stringify({
      model: cfg.model ?? "gpt-4o-mini",
      temperature: 0,
      max_tokens: 200,
      response_format: { type: "json_object" },
      messages: [
        { role: "system", content: systemPrompt(prompt.questions) },
        { role: "user", content: prompt.text },
      ],
    });
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (cfg.api_key) headers.Authorization = "Bearer " + cfg.api_key;
    let res: Response;
    try {
      res = await fetchWithTimeout(endpoint + "/chat/completions", { method: "POST", headers, body }, timeoutMs);
    } catch (e) {
      return [null, errorString(e, timeoutMs)];
    }
    if (res.status !== 200) return [null, "openai-compat http " + res.status];
    let content: string;
    try {
      const d = (await res.json()) as { choices?: { message?: { content?: string } }[] };
      content = d.choices?.[0]?.message?.content ?? "";
    } catch {
      return [null, "openai-compat: malformed response"];
    }
    const m = /\{[\s\S]*\}/.exec(content);
    if (!m) return [null, "openai-compat: no JSON in reply"];
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(m[0]) as Record<string, unknown>;
    } catch {
      return [null, "openai-compat: invalid JSON in reply"];
    }
    const answers: Answers = {};
    for (const name of Object.keys(prompt.questions)) {
      const v = Number(parsed[name]);
      if (Number.isFinite(v)) answers[name] = Math.min(1, Math.max(0, v));
    }
    if (Object.keys(answers).length === 0) return [null, "openai-compat: no question answered"];
    return [answers, null];
  },
};

// ---------------------------------------------------------------------------

/**
 * Thin-Worker mode. Forwards the original request to an existing jev-edge's
 * `/_jev/authz` (the same endpoint Envoy uses) and turns its X-Jev-* answer
 * back into an answer map, so the Worker applies its own L1 and cache but the
 * judgment, thresholds and deployment context live in one place: the origin.
 * A 403 from the backend is reported as score 1 so the Worker's policy blocks
 * in enforce mode too; an X-Jev-Verdict: error answer is an error here as well.
 */
export const backend: Provider = {
  name: "backend",
  async call(prompt, cfg, timeoutMs, info) {
    const base = (cfg.endpoint ?? "").replace(/\/+$/, "");
    if (!base) return [null, "backend: jev.endpoint (origin jev-edge URL) not set"];
    const path = info?.path ?? prompt.context.path ?? "/";
    const headers: Record<string, string> = { "Content-Type": info?.headers.get("content-type") ?? "application/json" };
    if (info?.clientIp) headers["X-Forwarded-For"] = info.clientIp;
    if (info?.subjectId) headers["X-Jev-Subject"] = info.subjectId;
    let res: Response;
    try {
      res = await fetchWithTimeout(base + "/_jev/authz" + path, {
        method: info?.method ?? prompt.context.method ?? "POST",
        headers,
        body: info?.body ?? prompt.text,
      }, timeoutMs);
    } catch (e) {
      return [null, errorString(e, timeoutMs)];
    }
    const verdict = res.headers.get("x-jev-verdict") ?? "";
    const score = Number(res.headers.get("x-jev-score"));
    if (res.status === 403) {
      const name = (res.headers.get("x-jev-reason") ?? "backend").split("+")[0] || "backend";
      return [{ [name]: Number.isFinite(score) && score > 0 ? score : 1 }, null];
    }
    if (res.status !== 200) return [null, "backend http " + res.status];
    if (verdict === "error") return [null, "backend: " + decodeURIComponent((res.headers.get("x-jev-reason") ?? "error").replace(/\+/g, " "))];
    if (!Number.isFinite(score)) return [null, "backend: no X-Jev-Score"];
    const name = (res.headers.get("x-jev-reason") ?? "backend").split("+")[0] || "backend";
    return [{ [name]: score }, null];
  },
};

// ---------------------------------------------------------------------------

export const mock: Provider = {
  name: "mock",
  async call(prompt, cfg, timeoutMs, info) {
    const delay = Number(cfg.mock_delay_ms ?? 0);
    if (delay > 0) {
      if (delay > timeoutMs) {
        await new Promise((r) => setTimeout(r, timeoutMs));
        return [null, "timeout (mock)"];
      }
      await new Promise((r) => setTimeout(r, delay));
    }
    const ratio = Number(cfg.mock_fail_ratio ?? 0);
    if (ratio > 0 && Math.random() < ratio) return [null, "mock failure"];
    let score = Number(cfg.mock_score ?? 0.1);
    const hdr = typeof cfg.mock_header === "string" ? info?.headers.get(cfg.mock_header) : null;
    if (hdr === "fail") return [null, "mock failure (header)"];
    if (hdr !== null && hdr !== undefined && Number.isFinite(Number(hdr))) score = Number(hdr);
    const answers: Answers = {};
    for (const name of Object.keys(prompt.questions)) answers[name] = score;
    return [answers, null];
  },
};

export const PROVIDERS: Record<string, Provider> = { jev, "openai-compat": openaiCompat, backend, mock };

export function load(name: string): Provider {
  const p = PROVIDERS[name];
  if (!p) throw new Error(`unknown provider: ${name}`);
  return p;
}
