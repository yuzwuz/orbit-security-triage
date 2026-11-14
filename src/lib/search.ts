import type { Evidence } from './types';

const STOP = new Set('the a an of to in on at is are was were be been it its this that these those and or for with from by as what which who whom how why when where did do does done any there their they them has have had not no about into over after before'.split(' '));
const SYN_RAW: Record<string, string[]> = {
  stolen: ['transfer', 'exfiltration', 'bytes', 'files'], steal: ['transfer', 'exfiltration'], leaked: ['transfer', 'exfiltration'], taken: ['transfer', 'exfiltration'], data: ['transfer', 'files', 'exfiltration'],
  attacker: ['attacker', '198.51.100.77', 'vpn'], phishing: ['phishing', 'email', 'payroll'], clicked: ['click', 'connected', 'link'], click: ['connected', 'link'],
  harmless: ['approved', 'closed', 'change'], noise: ['approved', 'closed', 'change'], scan: ['scan', 'scanner', 'nessus'], severity: ['severity', 'matrix', 'p1', 'p2', 'p4'],
  inform: ['inform', 'ciso', 'limit'], escalate: ['inform', 'limit'], contact: ['inform'], missing: ['missing', 'log', 'gap', 'hole'], gap: ['hole', 'missing', 'firewall'],
  timezone: ['utc', 'pkt'], time: ['utc', 'pkt'], password: ['password', 'reset'], locked: ['lockout', 'locked'], web: ['sql', 'injection', 'web'], sql: ['injection', 'union', 'web'],
};
const stem = (w: string) => (w.length > 5 ? w.replace(/(ing|ed|es|s)$/, '') : w);
const SYN: Record<string, string[]> = Object.fromEntries(Object.entries(SYN_RAW).map(([k, v]) => [stem(k), v]));
const tok = (s: string) => s.toLowerCase().replace(/[^a-z0-9.:_\-/ ]/g, ' ').split(/\s+/).filter((w) => w.length > 1 && !STOP.has(w)).map(stem);

interface Doc { text: string; cites: string[]; tag: string }

function docs(ev: Evidence): Doc[] {
  const d: Doc[] = [];
  for (const i of ev.incidents) {
    for (const c of i.claims) d.push({ text: c.text, cites: c.cites, tag: `${c.label === 'noevidence' ? 'Not enough evidence in the logs' : c.label === 'confirmed' ? 'Confirmed' : 'Suspected'} (${i.id})` });
    for (const p of i.parts) d.push({ text: `${i.id} ${p.name}: severity ${p.severity}. ${p.steps[p.steps.length - 1].replace(/^Step \d+\. /, '')}`, cites: p.assets.flatMap((a) => a.cites).slice(0, 2), tag: 'Severity' });
    for (const a of i.actions) d.push({ text: `${i.id} ${a.runbook} step ${a.step}: ${a.text}. ${a.applied}`, cites: [a.cite], tag: 'Action' });
    for (const x of i.inform) d.push({ text: `${i.id} ${i.severity} inform ${x.who} within ${x.limit}${x.deadlineUtc ? ` by ${x.deadlineUtc}` : ''}`, cites: [x.cite], tag: 'Inform' });
  }
  for (const m of ev.matches) d.push({ text: `${m.entity}: ${m.names.map((n) => n.value).join('; ')}. ${m.how}`, cites: m.names.slice(0, 3).map((n) => n.cite), tag: 'Identity' });
  for (const o of ev.observations) d.push({ text: o.text, cites: o.cites, tag: o.label === 'suspected' ? 'Suspected' : 'Confirmed' });
  for (const g of ev.gaps) d.push({ text: `${g.what}. ${g.impact}`, cites: [g.cite], tag: 'Missing data' });
  for (const m of ev.missingSources) d.push({ text: `Log source not collected: ${m.text}`, cites: [m.cite], tag: 'Missing data' });
  for (const r of Object.values(ev.refs)) {
    if (r.kind === 'rule') d.push({ text: r.raw, cites: [r.key], tag: 'Rule' });
    else if (r.kind === 'step') d.push({ text: `${r.file.replace(/^\d+_|\.md$/g, '')} ${r.loc}: ${r.raw}`, cites: [r.key], tag: 'Runbook' });
    else if (r.kind === 'row' && /^(03|04|05|20)_/.test(r.file)) d.push({ text: r.raw, cites: [r.key], tag: 'Table' });
  }
  for (const e of ev.events) d.push({ text: `${e.tsUtc} ${e.source} ${e.action}`, cites: [e.id], tag: 'Log line' });
  return d;
}

const shortCite = (c: string) => c;

/** Deterministic fallback used when no LLM is configured or the LLM answer is rejected by the verifier. */
export function localAnswer(question: string, ev: Evidence): { answer: string; cites: string[] } {
  const q = tok(question);
  const expanded = [...q, ...q.flatMap((w) => (SYN[w] ?? []).map(stem))];
  const all = docs(ev);
  const df = new Map<string, number>();
  const bags = all.map((d) => new Set(tok(d.text + ' ' + d.tag)));
  bags.forEach((b) => b.forEach((w) => df.set(w, (df.get(w) ?? 0) + 1)));
  const scored = all.map((d, i) => {
    let s = 0;
    for (const w of expanded) if (bags[i].has(w)) s += Math.log(1 + all.length / (df.get(w) ?? 1));
    if (d.tag === 'Log line') s *= 0.6;
    return { d, s };
  }).filter((x) => x.s > 0).sort((a, b) => b.s - a.s);

  const wantsTheft = /\b(stolen|steal|leak|leaked|taken|exfil\w*)\b/i.test(question);
  const lines: string[] = [];
  const cites: string[] = [];
  if (wantsTheft) { lines.push('Rule 2.4: a large transfer is evidence of a transfer, not of which files were read. [01_company_security_rules.md:2.4]'); cites.push('01_company_security_rules.md:2.4'); }
  const best = scored[0]?.s ?? 0;
  const top = scored.slice(0, 3).filter((x) => x.s >= 2.5 && x.s >= best * 0.6); // only the answers close to the best one
  if (!top.length && !wantsTheft) return { answer: 'This is not covered by the provided files. Not enough evidence in the logs to answer that.', cites: [] };
  for (const { d } of top) {
    lines.push(`${d.tag}: ${d.text} ${d.cites.slice(0, 3).map((c) => `[${shortCite(c)}]`).join(' ')}`);
    cites.push(...d.cites.slice(0, 3));
  }
  return { answer: lines.join('\n'), cites: [...new Set(cites)] };
}
