// Port of core/policy.lua.
import { ACTION_BLOCK, ACTION_PASS, ERROR, MALICIOUS, SAFE, SKIPPED, SUSPICIOUS, type Action, type Label } from "./verdict.js";

export interface Policy {
  mode?: "monitor" | "enforce" | string;
  block_threshold?: number;
  suspect_threshold?: number;
  block_status?: number;
  block_body?: string;
  /** What happens to a watched request L1 cannot read (see core/defaults.lua). */
  unjudgeable?: "pass" | "block" | string;
}

export const DEFAULTS: Required<Policy> = {
  mode: "monitor",
  block_threshold: 0.7,
  suspect_threshold: 0.5,
  block_status: 403,
  block_body: '{"error":"request rejected"}',
  unjudgeable: "pass",
};

export type Decision = [Action, Label, boolean];

export function decide(score: number, policy?: Policy | null): Decision {
  const p = policy ?? DEFAULTS;
  const blockT = p.block_threshold ?? DEFAULTS.block_threshold;
  const suspectT = p.suspect_threshold ?? DEFAULTS.suspect_threshold;
  const enforce = (p.mode ?? "monitor") === "enforce";
  if (score >= blockT) return [enforce ? ACTION_BLOCK : ACTION_PASS, MALICIOUS, false];
  if (score >= suspectT) return [ACTION_PASS, SUSPICIOUS, true];
  return [ACTION_PASS, SAFE, false];
}

export function onError(): Decision {
  return [ACTION_PASS, ERROR, true];
}

export function onSkipped(): Decision {
  return [ACTION_PASS, SKIPPED, true];
}
