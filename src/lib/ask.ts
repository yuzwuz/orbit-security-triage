import type { Evidence } from './types';
import { complete, llmConfigured, type Msg } from './llm';
import { verifyAnswer, shortRef } from './verify';
import { localAnswer } from './search';

export interface Answer { answer: string; cites: string[]; mode: 'llm' | 'local'; provider?: string; dropped: number; note?: string }

const SYSTEM = `You are the Orbit Logistics security triage assistant. Use ONLY the CONTEXT below. Never use outside knowledge.
Rules:
- Every factual sentence must end with a citation in square brackets copied from CONTEXT, like [11:L7] or [17:ALT-9002]. Cite only refs that appear in CONTEXT.
- Say whether each point is Confirmed, Suspected or Not enough evidence in the logs.
- If CONTEXT cannot answer, reply exactly: "Not enough evidence in the logs." and say what is missing. Do not guess.
- Never say data was "stolen" or "leaked". A large transfer is evidence of a transfer, not of which files were read.
- Times: UTC first, PKT (UTC+5) in brackets if useful.
- Recommend actions only if they are in CONTEXT as runbook steps, with the runbook step cited.
- Be short: at most 120 words.`;

export function buildContext(ev: Evidence): string {
  const out: string[] = ['INCIDENTS (already analysed, all cited):'];
  for (const i of ev.incidents) {
    out.push(`## ${i.id} ${i.status === 'escalate' ? i.severity : 'closed harmless'}: ${i.title}`);
    for (const p of i.parts) out.push(`severity part: ${p.name} = ${p.severity}`);
    for (const c of i.claims) out.push(`- ${c.label}: ${c.text} ${c.cites.slice(0, 4).map((x) => `[${shortRef(x)}]`).join('')}`);
    for (const a of i.actions) out.push(`- action ${a.runbook} step ${a.step}: ${a.applied} [${shortRef(a.cite)}]`);
    for (const x of i.inform) out.push(`- inform: ${x.who}, within ${x.limit}${x.deadlineUtc ? ` (by ${x.deadlineUtc})` : ''} [${shortRef(x.cite)}]`);
  }
  out.push('OBSERVATIONS:');
  for (const o of ev.observations) out.push(`- ${o.label}: ${o.text} ${o.cites.slice(0, 3).map((x) => `[${shortRef(x)}]`).join('')}`);
  out.push('MISSING DATA:');
  for (const g of ev.gaps) out.push(`- ${g.what}. ${g.impact} [${shortRef(g.cite)}]`);
  for (const m of ev.missingSources) out.push(`- not collected: ${m.text} [${shortRef(m.cite)}]`);
  out.push('ALL LOG LINES (ref | UTC time | event):');
  for (const e of ev.events) out.push(`[${shortRef(e.id)}] ${e.tsUtc.slice(11, 19)}Z ${e.action.slice(0, 110)}`);
  return out.join('\n');
}

export async function answerQuestion(question: string, history: Msg[], ev: Evidence): Promise<Answer> {
  const fallback = (note?: string): Answer => {
    const l = localAnswer(question, ev);
    return { answer: l.answer, cites: l.cites, mode: 'local', dropped: 0, note };
  };
  if (!llmConfigured()) return fallback('No LLM key set: answered by the built-in keyword search over the verified findings.');
  try {
    const messages: Msg[] = [{ role: 'system', content: `${SYSTEM}\n\nCONTEXT:\n${buildContext(ev)}` }, ...history.slice(-4), { role: 'user', content: question }];
    const { text, provider } = await complete(messages, { maxTokens: 400 });
    const v = verifyAnswer(text, ev.refs);
    if (!v.text.trim()) return fallback('The model answer had no valid citations and was rejected. Showing verified findings instead.');
    return { answer: v.text, cites: v.cites, mode: 'llm', provider, dropped: v.dropped.length };
  } catch (e) {
    return fallback(`${(e as Error).message}. Showing verified findings instead.`);
  }
}

export async function polishSummary(ev: Evidence): Promise<{ summary: string; mode: 'llm' | 'local'; provider?: string }> {
  if (!llmConfigured()) return { summary: ev.report.summary, mode: 'local' };
  try {
    const messages: Msg[] = [
      { role: 'system', content: `${SYSTEM}\n\nWrite a 3-sentence executive summary of the incident for a manager. Keep citations.\n\nCONTEXT:\n${buildContext(ev)}` },
      { role: 'user', content: 'Write the executive summary.' },
    ];
    const { text, provider } = await complete(messages, { maxTokens: 300 });
    const v = verifyAnswer(text, ev.refs);
    if (v.text.split('\n').length < 2) return { summary: ev.report.summary, mode: 'local' };
    return { summary: v.text, mode: 'llm', provider };
  } catch {
    return { summary: ev.report.summary, mode: 'local' };
  }
}
