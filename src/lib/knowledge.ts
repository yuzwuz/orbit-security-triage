import { read, table, ipRe } from './tables';
import { pktStr } from './time';
import type { Ref } from './types';

export interface Asset { tag: string; host: string; type: string; ips: string[]; owner: string; criticality: string; cite: string }
export interface User { username: string; name: string; email: string; role: string; laptopTag: string; phone: string; manager: string; cite: string }
export interface Change {
  id: string; status: string; active: boolean; startMs: number; endMs: number;
  target: string; performer: string; description: string;
  actorIps: string[]; actorUsers: string[]; targetHosts: string[]; targetIps: string[]; targetCidrs: string[];
  cite: string;
}
export interface Runbook { id: string; file: string; title: string; steps: { n: number; text: string }[] }
export interface MatrixRow { type: string; cells: Record<string, string>; cite: string }
export interface EscRow { sev: string; who: string; limit: string; how: string; cite: string }
export interface Knowledge {
  assets: Asset[]; users: User[]; changes: Change[]; runbooks: Runbook[]; matrix: MatrixRow[]; escalation: EscRow[];
  coverage: { source: string; file: string; zone: string; coverage: string; notes: string }[];
  missingSources: { text: string; cite: string }[];
  ids: { id: string; time: string; sensor: string; desc: string }[];
  refs: Ref[];
}

const F = {
  rules: '01_company_security_rules.md', assets: '02_asset_inventory.md', matrix: '03_severity_matrix.md', esc: '04_escalation_and_contacts.md',
  changes: '05_change_calendar.md', ids: '17_ids_alert_summary.md', users: '18_user_directory.md', coverage: '20_log_source_coverage.md',
  runbooks: ['06_runbook_phishing.md', '07_runbook_credential_compromise.md', '08_runbook_web_attack.md', '09_runbook_data_exfiltration.md', '10_runbook_scanning_recon.md'],
};

export function loadKnowledge(): Knowledge {
  const refs: Ref[] = [];
  const addRef = (file: string, loc: string, raw: string, kind: Ref['kind']) => refs.push({ key: `${file}:${loc}`, file, loc, raw, kind });
  const rowRaw = (r: Record<string, string>) => Object.entries(r).map(([k, v]) => `${k}: ${v}`).join(' | ');

  const assets: Asset[] = table(read(F.assets)).map((r) => {
    const a = { tag: r['Asset tag'], host: r['Hostname'], type: r['Type'], ips: r['IP address'].match(ipRe) ?? [], owner: r['Owner'], criticality: r['Criticality'], cite: `${F.assets}:${r['Asset tag']}` };
    addRef(F.assets, a.tag, rowRaw(r), 'row');
    return a;
  });

  const users: User[] = table(read(F.users)).map((r) => {
    addRef(F.users, r['Username'], rowRaw(r), 'row');
    return { username: r['Username'], name: r['Full name'], email: r['Email'], role: r['Role'], laptopTag: r['Laptop tag'], phone: r['Registered phone'], manager: r['Manager'], cite: `${F.users}:${r['Username']}` };
  });

  const matrix: MatrixRow[] = table(read(F.matrix)).map((r) => {
    const type = r['Incident type'];
    addRef(F.matrix, type, rowRaw(r), 'row');
    return { type, cells: { Low: r['Low'], Medium: r['Medium'], High: r['High'], Critical: r['Critical'] }, cite: `${F.matrix}:${type}` };
  });

  const seen: Record<string, number> = {};
  const escalation: EscRow[] = table(read(F.esc)).map((r) => {
    const sev = r['Severity'];
    seen[sev] = (seen[sev] ?? 0) + 1;
    const loc = `${sev}-${seen[sev]}`;
    addRef(F.esc, loc, rowRaw(r), 'row');
    return { sev, who: r['Who to inform'], limit: r['Time limit'], how: r['How'], cite: `${F.esc}:${loc}` };
  });

  const changes: Change[] = table(read(F.changes)).map((r) => {
    const id = r['Change ID'];
    addRef(F.changes, id, rowRaw(r), 'row');
    const [a, b] = r['Window (PKT)'].split('-').map((s) => s.trim());
    const status = r['Status'];
    const performer = r['Performed by'];
    const target = r['System / target'];
    const ipInParens = performer.match(/\(((?:\d{1,3}\.){3}\d{1,3})\)/)?.[1];
    const userInParens = performer.match(/\((\w+)\)/);
    const targetHosts = target.match(/\bSRV-\w+\b|\bSCAN\d+\b/g) ?? [];
    return {
      id, status, active: !/postponed|not performed|cancel/i.test(status),
      startMs: pktStr(`${r['Date']} ${a}:00`), endMs: pktStr(`${r['Date']} ${b}:00`) + (b.endsWith(':59') ? 59000 : 0),
      target, performer, description: r['Description'],
      actorIps: ipInParens ? [ipInParens] : [],
      actorUsers: userInParens && !ipInParens ? [userInParens[1]] : [],
      targetHosts,
      targetIps: targetHosts.flatMap((h) => assets.find((x) => x.host === h)?.ips ?? []),
      targetCidrs: target.match(/(?:\d{1,3}\.){3}\d{1,3}\/\d+/g) ?? [],
      cite: `${F.changes}:${id}`,
    };
  });

  const runbooks: Runbook[] = F.runbooks.map((file) => {
    const t = read(file);
    const head = t.match(/^# Runbook (\S+) - (.*)$/m)!;
    const steps = [...t.matchAll(/^(\d+)\. (.*)$/gm)].map((m) => {
      addRef(file, `step${m[1]}`, m[2], 'step');
      return { n: +m[1], text: m[2] };
    });
    return { id: head[1], file, title: head[2], steps };
  });

  const matrixText = read(F.matrix);
  [...(matrixText.split('Rules:')[1] ?? '').matchAll(/^- (.*)$/gm)].forEach((m, i) => addRef(F.matrix, `rule${i + 1}`, m[1], 'rule'));

  for (const m of read(F.rules).matchAll(/^(\d+\.\d+) (.*)$/gm)) addRef(F.rules, m[1], m[2], 'rule');

  const coverage = table(read(F.coverage)).map((r) => {
    addRef(F.coverage, r['Source'], rowRaw(r), 'row');
    return { source: r['Source'], file: r['File'], zone: r['Time zone / format'], coverage: r['Coverage on 2026-11-04'], notes: r['Notes'] };
  });
  const covText = read(F.coverage);
  const missingSources = [...(covText.split('do NOT exist or are NOT collected:')[1] ?? '').matchAll(/^- (.*)$/gm)].map((m, i) => {
    addRef(F.coverage, `missing${i + 1}`, m[1], 'row');
    return { text: m[1], cite: `${F.coverage}:missing${i + 1}` };
  });

  const ids = table(read(F.ids)).map((r) => {
    addRef(F.ids, r['Alert ID'], rowRaw(r), 'row');
    return { id: r['Alert ID'], time: r['Time raised'], sensor: r['Sensor'], desc: r['Description'] };
  });

  return { assets, users, changes, runbooks, matrix, escalation, coverage, missingSources, ids, refs };
}
