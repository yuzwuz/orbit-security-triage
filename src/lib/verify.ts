import type { Ref } from './types';

// Accepts [11:L7], [11_vpn_auth_log.md:L7] and [20_log_source_coverage.md:Internal firewall].
const CITE = /\[(\d{2})(?:_[A-Za-z0-9_]+\.md)?:([^\]]+)\]/g;

export const shortRef = (key: string) => key.replace(/^(\d{2})_[^:]+/, '$1');

/** "11:L7" or full → the full ref key, or undefined if no such line, row or step exists. */
export function resolveRef(num: string, loc: string, refs: Record<string, Ref>): string | undefined {
  const hit = Object.keys(refs).find((k) => k.startsWith(num + '_') && refs[k].loc === loc.trim());
  return hit;
}

const ABSENCE = /not enough evidence in the logs|this is not covered|not covered by the (provided )?files|no .{0,30}(log|logs) (exist|is|are)/i;
const OVERCLAIM = /\b(stolen|leaked|exfiltrated)\b/i;
const HEDGE = /not enough evidence|no evidence|cannot|can't|unknown|not shown|suspected|guess|transfer/i;

export interface Verified { text: string; cites: string[]; dropped: string[] }

/**
 * The "never invent evidence" gate. A sentence survives only if every citation in it points at a real
 * line, row or step, and it has at least one (unless it is an honest statement of absence).
 * Rule 2.4: "stolen" / "leaked" are dropped unless the sentence is hedged.
 */
export function verifyAnswer(raw: string, refs: Record<string, Ref>): Verified {
  const kept: string[] = [];
  const dropped: string[] = [];
  const cites = new Set<string>();
  const sentences = raw.split(/\n+/).flatMap((line) => line.split(/(?<=[.!?])\s+(?=[A-Z\[(])/)).map((s) => s.trim()).filter(Boolean);
  for (const s of sentences) {
    const found = [...s.matchAll(CITE)].map((m) => ({ full: m[0], key: resolveRef(m[1], m[2], refs) }));
    const bad = found.some((f) => !f.key);
    if (bad) { dropped.push(s); continue; }
    if (OVERCLAIM.test(s) && !HEDGE.test(s)) { dropped.push(s); continue; }
    if (!found.length && !ABSENCE.test(s) && !/\?$/.test(s)) { dropped.push(s); continue; }
    let out = s;
    for (const f of found) { out = out.replace(f.full, `[${f.key}]`); cites.add(f.key!); }
    kept.push(out);
  }
  return { text: kept.join('\n'), cites: [...cites], dropped };
}
