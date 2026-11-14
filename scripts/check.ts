// npm run check  → proves the facts the judges will ask about, without needing an LLM key.
import { runPipeline, brokenCites } from '../src/lib/pipeline';
import { verifyAnswer } from '../src/lib/verify';
import { localAnswer } from '../src/lib/search';
import { complete } from '../src/lib/llm';

let fails = 0;
const ok = (name: string, cond: boolean, extra = '') => { console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${cond ? '' : '  ' + extra}`); if (!cond) fails++; };
const ev = runPipeline();
const E = (id: string) => ev.events.find((e) => e.id === id)!;

ok('82 events parsed from 8 sources', ev.events.length === 82 && ev.stats.sources === 8, String(ev.events.length));
ok('events sorted by UTC time', ev.events.every((e, i) => i === 0 || ev.events[i - 1].tsUtc <= e.tsUtc));
ok('web log +0500 → UTC', E('13_web_server_log.md:L1').tsUtc === '2026-11-04T03:10:21Z');
ok('email PKT → UTC', E('16_email_gateway_log.md:L2').tsUtc === '2026-11-04T04:12:07Z');
ok('internal firewall: PKT, logged at close, start = close − duration', E('15_firewall_internal_log.md:L6').tsUtc === '2026-11-04T06:03:12Z' && E('15_firewall_internal_log.md:L6').loggedUtc === '2026-11-04T06:21:19Z');
ok('perimeter firewall is UTC as written', E('14_firewall_perimeter_log.md:L8').tsUtc === '2026-11-04T04:19:40Z');
ok('DHCP +05:00 → UTC', E('19_dhcp_lease_log.md:L2').tsUtc === '2026-11-04T03:57:40Z');
ok('IDS alert raised time kept as UTC', E('17_ids_alert_summary.md:ALT-9005').tsUtc === '2026-11-04T06:21:20Z');
ok('VPN pool address matched to amalik', E('12_windows_dc_auth_log.md:L3').actor === 'amalik' && E('15_firewall_internal_log.md:L6').actor === 'amalik');

const inc = (id: string) => ev.incidents.find((i) => i.id === id)!;
ok('INC-1 is the credential/exfil chain with overall P1', inc('INC-1').severity === 'P1' && /amalik/.test(inc('INC-1').title));
ok('INC-1 parts: credential compromise P2 + exfiltration P1', inc('INC-1').parts.map((p) => p.severity).join() === 'P2,P1');
ok('INC-2 SQL injection from 192.0.2.150 is P2 (success suspected, Medium)', inc('INC-2').severity === 'P2' && /192\.0\.2\.150/.test(inc('INC-2').title));
ok('INC-3 external scan from 192.0.2.88 is P4', inc('INC-3').severity === 'P4' && /192\.0\.2\.88/.test(inc('INC-3').title));
ok('scan by SCAN01 closed as CHG-2026-1104-02', E('17_ids_alert_summary.md:ALT-9006').approvedBy === 'CHG-2026-1104-02');
ok('braza RDP to DC closed as CHG-2026-1104-03', E('17_ids_alert_summary.md:ALT-9007').approvedBy === 'CHG-2026-1104-03' && E('15_firewall_internal_log.md:L14').approvedBy === 'CHG-2026-1104-03');
ok('no attacker line is approved', ev.events.filter((e) => e.approvedBy && /198\.51\.100\.77|192\.0\.2\./.test(e.raw)).length === 0);
ok('postponed change CHG-2026-1104-05 approves nothing', !ev.events.some((e) => e.approvedBy === 'CHG-2026-1104-05'));
ok('P1 contacts: CISO 15 min, IT Director 30 min, Legal 1 h, data owner 1 h', inc('INC-1').inform.map((x) => x.limit).join() === '15 minutes,30 minutes,1 hour,1 hour');
ok('internal firewall gap overlaps the attacker VPN session', ev.gaps.some((g) => /Internal firewall/.test(g.what) && /VS-20433/.test(g.impact)));
ok('FS01 file access is reported as not enough evidence', inc('INC-1').claims.some((c) => c.label === 'noevidence' && /which files/i.test(c.text)));
ok('no claim says "stolen" or "leaked" unhedged', ev.incidents.every((i) => i.claims.every((c) => !/\b(stolen|leaked)\b/i.test(c.text) || /not|guess/i.test(c.text))), 'check wording');
ok('every citation points at a real line, row or step', brokenCites(ev).length === 0, brokenCites(ev).join(', '));
ok('markdown report has all 11 required sections', ['Summary', 'Timeline', 'Affected assets and accounts', 'Severity', 'Confirmed', 'Suspected', 'Not enough evidence in the logs', 'Missing log sources', 'Closed as harmless', 'Recommended actions', 'People to inform'].every((s) => ev.report.markdown.includes(s)));
const runbookText = new Set(ev.incidents.flatMap((i) => i.actions.map((a) => a.text)));
ok('every action text is a verbatim runbook step', [...runbookText].every((t) => Object.values(ev.refs).some((r) => r.kind === 'step' && r.raw === t)));

// verifier
const v = verifyAnswer('The VPN login succeeded at 05:49:12Z [11:L7]. Data was stolen by the attacker. This line is made up [11:L99]. Not enough evidence in the logs for which files were read.', ev.refs);
ok('verifier keeps a valid cited sentence', v.text.includes('[11_vpn_auth_log.md:L7]'));
ok('verifier drops uncited, invalid-cite and "stolen" sentences, keeps honest absence', v.dropped.length === 2 && v.text.includes('Not enough evidence'), JSON.stringify(v.dropped));

// local fallback answers
const a1 = localAnswer('Was data stolen from the file server?', ev);
ok('fallback applies rule 2.4 to "stolen"', /Rule 2.4/.test(a1.answer) && /transfer/i.test(a1.answer));
const a2 = localAnswer('Was the nessus scan from SCAN01 an attack?', ev);
ok('fallback finds the approved scan', /CHG-2026-1104-02/.test(a2.answer), a2.answer.slice(0, 200));
const a3 = localAnswer('What is the CEO salary?', ev);
ok('fallback says "not covered" for unrelated questions', /not covered/i.test(a3.answer));

async function llmChecks() {
// LLM client: retry on 429 then succeed, and fall back to the second provider
process.env.GROQ_API_KEY = 'x'; process.env.OPENROUTER_API_KEY = 'y';
const realFetch = globalThis.fetch;
let calls: string[] = [];
globalThis.fetch = (async (url: string) => {
  calls.push(String(url).includes('groq') ? 'groq' : 'openrouter');
  if (calls.length === 1) return new Response('{}', { status: 429, headers: { 'retry-after': '0' } });
  return new Response(JSON.stringify({ choices: [{ message: { content: 'hi [11:L7]' } }] }), { status: 200 });
}) as typeof fetch;
const r1 = await complete([{ role: 'user', content: 'x' }]);
ok('LLM client retries a 429 and then succeeds', r1.text.startsWith('hi') && calls.join() === 'groq,groq', calls.join());
calls = [];
globalThis.fetch = (async (url: string) => { calls.push(String(url).includes('groq') ? 'groq' : 'openrouter'); return String(url).includes('groq') ? new Response('{}', { status: 500 }) : new Response(JSON.stringify({ choices: [{ message: { content: 'from fallback' } }] }), { status: 200 }); }) as typeof fetch;
const r2 = await complete([{ role: 'user', content: 'x' }], { attempts: 2 });
ok('LLM client falls back to OpenRouter when Groq keeps failing', r2.provider === 'openrouter', calls.join());
globalThis.fetch = realFetch;
}

llmChecks().then(() => {
  console.log(fails ? `\n${fails} check(s) FAILED` : '\nAll checks passed');
  process.exit(fails ? 1 : 0);
});
