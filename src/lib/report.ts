import type { Ev, Incident, Claim, Gap, Sev } from './types';
import { both, hhmmss } from './time';

const L: Record<string, string> = { confirmed: 'Confirmed', suspected: 'Suspected', noevidence: 'Not enough evidence in the logs' };
const cite = (cs: string[]) => cs.slice(0, 6).map((c) => `[${c}]`).join(' ');
const SEV_ORDER: Sev[] = ['P1', 'P2', 'P3', 'P4'];

export function buildReport(incidents: Incident[], observations: Claim[], gaps: Gap[], missing: { text: string; cite: string }[], events: Ev[]) {
  const live = incidents.filter((i) => i.status === 'escalate');
  const closed = incidents.filter((i) => i.status === 'closed-harmless');
  const overall = live.map((i) => i.severity!).sort((a, b) => SEV_ORDER.indexOf(a) - SEV_ORDER.indexOf(b))[0] ?? 'P4';
  const date = events[0]?.tsUtc.slice(0, 10) ?? '';

  const summary =
    `Overall severity ${overall}. ` +
    live.map((i) => `${i.id} (${i.severity}): ${i.title}.`).join(' ') +
    ` ${closed.length} alert group(s) were closed as approved activity (${closed.map((c) => c.closedBy).join(', ')}). ` +
    `Each part is scored separately (rule 4.3) and the whole incident takes the highest severity (rule 4.2).`;

  const md: string[] = [];
  md.push(`# Incident report: Orbit Logistics, logs of ${date}`, '', 'All times are UTC with PKT (UTC+5) in brackets. Every statement carries a citation: file and line for logs, file and row ID for tables, runbook file and step for actions.', '');
  md.push('## 1. Summary', '', summary, '');

  md.push('## 2. Timeline (UTC, with file and line)', '', '| Time (UTC) [PKT] | Source | Event | Incident | Citation |', '|---|---|---|---|---|');
  for (const e of events.filter((x) => x.incidents.some((i) => live.some((l) => l.id === i)))) {
    const note = e.loggedUtc ? ` (start time; line written at ${hhmmss(Date.parse(e.loggedUtc))})` : '';
    md.push(`| ${both(Date.parse(e.tsUtc))} | ${e.source} | ${e.action.replace(/\|/g, '/')}${note} | ${e.incidents.filter((i) => i.startsWith('INC')).join(', ')} | [${e.id}] |`);
  }
  md.push('');

  md.push('## 3. Affected assets and accounts', '');
  for (const i of live) {
    md.push(`**${i.id} ${i.title}**`, '');
    if (i.accounts.length) md.push(`- Accounts: ${i.accounts.join(', ')}`);
    for (const p of i.parts) for (const a of p.assets) md.push(`- ${a.host} (${a.tag}, ${a.criticality}): ${a.how} ${cite(a.cites)}`);
    md.push('');
  }

  md.push('## 4. Severity (with steps)', '');
  for (const i of live) {
    md.push(`**${i.id}: ${i.severity}** (highest of its parts)`, '');
    for (const p of i.parts) { md.push(`- ${p.name}: **${p.severity}**`); p.steps.forEach((s) => md.push(`  - ${s}`)); }
    md.push('');
  }

  for (const label of ['confirmed', 'suspected', 'noevidence'] as const) {
    md.push(`## ${label === 'confirmed' ? 5 : label === 'suspected' ? 6 : 7}. ${L[label]}`, '');
    for (const i of live) for (const c of i.claims.filter((x) => x.label === label)) md.push(`- (${i.id}) ${c.text} ${cite(c.cites)}`);
    for (const c of observations.filter((x) => x.label === label)) md.push(`- (observation) ${c.text} ${cite(c.cites)}`);
    md.push('');
  }

  md.push('## 8. Missing log sources', '');
  missing.forEach((m) => md.push(`- ${m.text} [${m.cite}]`));
  gaps.forEach((g) => md.push(`- **${g.what}.** ${g.impact} [${g.cite}]`));
  md.push('');

  md.push('## 9. Closed as harmless (with change ID)', '');
  closed.forEach((c) => { md.push(`- **${c.closedBy}**: ${c.closedReason}`); c.claims.forEach((x) => md.push(`  - ${x.text} ${cite(x.cites)}`)); });
  observations.filter((o) => /closes nothing/.test(o.text)).forEach((o) => md.push(`- ${o.text} ${cite(o.cites)}`));
  md.push('');

  md.push('## 10. Recommended actions (runbook ID and step)', '');
  for (const i of live) {
    md.push(`**${i.id}**`, '');
    i.actions.forEach((a) => md.push(`- ${a.runbook} step ${a.step}: ${a.text} → ${a.applied} [${a.cite}]`));
    md.push('');
  }

  md.push('## 11. People to inform (name and time limit)', '', 'The time limit starts when the SOC first sees the incident. Assumption used here: the time of the first IDS alert of the incident.', '');
  for (const i of live) {
    md.push(`**${i.id} (${i.severity})**: first seen ${i.firstSeenUtc}. Basis: ${i.firstSeenBasis}.`, '');
    i.inform.forEach((x) => md.push(`- ${x.who}: within ${x.limit}${x.deadlineUtc ? ` (by ${x.deadlineUtc})` : ''}, ${x.how} [${x.cite}]`));
    md.push('');
  }
  return { overall, summary, markdown: md.join('\n') };
}
