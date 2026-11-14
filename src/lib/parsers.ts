import { read, codeLines, kv, table } from './tables';
import { utcStr, pktStr, offStr, webTime, iso, hhmmss } from './time';
import type { Ev, Source } from './types';
import type { Asset } from './knowledge';

type Draft = Omit<Ev, 'id' | 'incidents' | 'tags' | 'f'> & { tags?: string[]; f?: Record<string, string> };
const mk = (d: Draft): Ev => ({ ...d, id: `${d.file}:${d.loc}`, incidents: [], tags: d.tags ?? [], f: d.f ?? {} });
const num = (s?: string) => (s === undefined ? undefined : Number(s));

export function parseAll(assets: Asset[], idsRows: { id: string; time: string; sensor: string; desc: string }[]): Ev[] {
  const ipOf = (host: string) => assets.find((a) => a.host === host)?.ips[0];
  return [...vpn(), ...dc(ipOf), ...web(ipOf), ...fwEdge(), ...fwInt(), ...email(), ...ids(idsRows, ipOf), ...dhcp()];
}

function vpn(): Ev[] {
  const file = '11_vpn_auth_log.md';
  const out: Ev[] = [];
  for (const { n, text } of codeLines(read(file))) {
    const m = text.match(/^(\S+Z) vpn01 (auth|session_end) (.*)$/);
    if (!m) continue;
    const k = kv(m[3]);
    const t = Date.parse(m[1]);
    const isAuth = m[2] === 'auth';
    out.push(mk({
      source: 'vpn', file, loc: `L${n}`, tsUtc: iso(t), timeNote: 'Already UTC (Z)', raw: text, user: k.user, srcIp: k.src_ip,
      host: 'SRV-VPN01',
      action: isAuth
        ? `VPN login ${k.result}${k.reason ? ' (' + k.reason + ')' : ''}: ${k.user} from ${k.src_ip} [${k.geo}]${k.assigned_ip ? ', gets ' + k.assigned_ip : ''}`
        : `VPN session ${k.session} ended: ${k.user}, ${k.duration}, ${Number(k.bytes_to_client).toLocaleString('en-US')} bytes to client`,
      bytes: num(k.bytes_to_client), f: k,
      tags: ['vpn', isAuth ? (k.result === 'FAIL' ? 'mfa-fail' : 'login') : 'session-end', ...(k.geo && k.geo !== 'PK' ? ['foreign'] : [])],
    }));
  }
  return out;
}

function dc(ipOf: (h: string) => string | undefined): Ev[] {
  const file = '12_windows_dc_auth_log.md';
  const dcIp = ipOf('SRV-DC01');
  const out: Ev[] = [];
  for (const { n, text } of codeLines(read(file))) {
    const parts = text.split(' | ');
    const m = parts[0]?.match(/^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) UTC$/);
    if (!m) continue;
    const t = utcStr(m[1]);
    const k = kv(parts.slice(4).join(' | '));
    const user = (k.account ?? k.target ?? '').replace(/^ORBIT\\/, '') || undefined;
    const eid = parts[2].replace('EventID=', '');
    out.push(mk({
      source: 'dc', file, loc: `L${n}`, tsUtc: iso(t), timeNote: 'Already UTC (written in the line)', raw: text, user,
      srcIp: k.client, dstIp: dcIp, host: k.workstation && k.workstation !== 'unknown' ? k.workstation : undefined,
      action: `DC ${eid} ${parts[3]}: ${user ?? ''}${k.service ? ' → ' + k.service : ''}${k.result ? ' (' + k.result + ')' : ''}${k.reason ? ' (' + k.reason + ')' : ''}`,
      f: { ...k, eventId: eid, desc: parts[3] },
      tags: ['dc', `ev${eid}`],
    }));
  }
  return out;
}

function web(ipOf: (h: string) => string | undefined): Ev[] {
  const file = '13_web_server_log.md';
  const text0 = read(file);
  const host = text0.match(/SRV-\w+/)?.[0] ?? 'SRV-WEB01';
  const out: Ev[] = [];
  for (const { n, text } of codeLines(text0)) {
    const m = text.match(/^(\S+) - - \[([^\]]+)\] "(\w+) (\S+) [^"]*" (\d+) (\d+) "[^"]*" "([^"]*)"$/);
    if (!m) continue;
    const [, ip, ts, method, path, status, size, ua] = m;
    const t = webTime(ts);
    let dec = path;
    try { dec = decodeURIComponent(path); } catch { /* keep raw */ }
    const sqli = /union\s+select|'\s*or\s*'|order\s+by|waitfor|;|--/i.test(dec) || /sqlmap/i.test(ua);
    const probe = /^\/(admin|phpmyadmin|\.env)/i.test(path) && !/nessus/i.test(ua);
    out.push(mk({
      source: 'web', file, loc: `L${n}`, tsUtc: iso(t), timeNote: `Local time with offset in the line (${ts}) → UTC`, raw: text, srcIp: ip,
      dstIp: ipOf(host), host, bytes: Number(size), dstPort: 443,
      action: `${method} ${dec.length > 70 ? dec.slice(0, 70) + '…' : dec} → ${status} (${size} bytes) [${ua.split(' ')[0].split('/')[0]}]`,
      f: { status, size, ua, path: dec },
      tags: ['web', ...(sqli ? ['sqli'] : []), ...(probe ? ['probe'] : []), ...(/nessus/i.test(ua) ? ['scanner'] : [])],
    }));
  }
  return out;
}

function fwEdge(): Ev[] {
  const file = '14_firewall_perimeter_log.md';
  const out: Ev[] = [];
  for (const { n, text } of codeLines(read(file))) {
    const m = text.match(/^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) fw-edge01 (ALLOW|DENY) (\w+) ([\d.]+):(\d+) -> ([\d.]+):(\d+)\s*(.*)$/);
    if (!m) continue;
    const k = kv(m[8]);
    const t = utcStr(m[1]);
    out.push(mk({
      source: 'fw-edge', file, loc: `L${n}`, tsUtc: iso(t), timeNote: 'UTC (no zone written; coverage sheet says UTC). Logged at connection start', raw: text,
      srcIp: m[4], dstIp: m[6], dstPort: +m[7], host: 'fw-edge01', bytes: num(k.bytes),
      action: `Perimeter ${m[2]} ${m[4]} → ${m[6]}:${m[7]}${k.rule ? ' (' + k.rule + ')' : ''}${k.bytes ? ', ' + Number(k.bytes).toLocaleString('en-US') + ' bytes' : ''}`,
      f: { ...k, verdict: m[2] }, tags: ['fw-edge', m[2].toLowerCase()],
    }));
  }
  return out;
}

function fwInt(): Ev[] {
  const file = '15_firewall_internal_log.md';
  const out: Ev[] = [];
  for (const { n, text } of codeLines(read(file))) {
    const m = text.match(/^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) fw-int01 (ALLOW|DENY) (\w+) ([\d.]+):(\d+) -> ([\d.]+):(\d+)\s*(.*)$/);
    if (!m) continue;
    const k = kv(m[8]);
    const closeMs = pktStr(m[1]);
    const dur = k.duration ? parseInt(k.duration, 10) : 0;
    const startMs = closeMs - dur * 1000;
    const big = Number(k.bytes_server_to_client ?? 0);
    out.push(mk({
      source: 'fw-int', file, loc: `L${n}`, tsUtc: iso(startMs), loggedUtc: iso(closeMs),
      timeNote: `PKT (UTC+5) → UTC; logged at session CLOSE (${hhmmss(closeMs)}), so start = close − ${dur}s`, raw: text,
      srcIp: m[4], dstIp: m[6], dstPort: +m[7], host: 'fw-int01', bytes: num(k.bytes_total),
      action: `Internal ${m[2]} ${m[4]} → ${m[6]}:${m[7]}${k.bytes_total ? ', ' + Number(k.bytes_total).toLocaleString('en-US') + ' bytes' : ''}${k.rule ? ' (' + k.rule + ')' : ''}`,
      f: { ...k, verdict: m[2], closeUtc: iso(closeMs) },
      tags: ['fw-int', m[2].toLowerCase(), ...(big >= 1e9 ? ['large-transfer'] : [])],
    }));
  }
  return out;
}

function email(): Ev[] {
  const file = '16_email_gateway_log.md';
  const out: Ev[] = [];
  for (const { n, text } of codeLines(read(file))) {
    const m = text.match(/^\[(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) PKT\] (.*)$/);
    if (!m) continue;
    const k = kv(m[2]);
    const t = pktStr(m[1]);
    const rcpt = (k.to ?? '').split('@')[0];
    out.push(mk({
      source: 'email', file, loc: `L${n}`, tsUtc: iso(t), timeNote: `PKT written in the line (${m[1]}) → UTC`, raw: text, user: rcpt, host: 'email-gw',
      action: `Email ${k.msgid} "${k.subject}" from ${k.from} to ${k.to} (${k.action}, score ${k.score})`,
      f: k, tags: ['email', ...(k.spf === 'fail' ? ['spf-fail'] : [])],
    }));
  }
  return out;
}

function ids(rows: { id: string; time: string; sensor: string; desc: string }[], ipOf: (h: string) => string | undefined): Ev[] {
  const file = '17_ids_alert_summary.md';
  return rows.map((r) => {
    const t = utcStr(r.time.replace(' UTC', ''));
    const d = r.desc;
    const src = d.match(/(?:from|Host|source) ((?:\d{1,3}\.){3}\d{1,3})/)?.[1] ?? ipOf(d.match(/from (SRV-\w+)/)?.[1] ?? '');
    const dst = d.match(/(?:to|against|connected to)[^0-9]*((?:\d{1,3}\.){3}\d{1,3})/)?.[1] ?? ipOf(d.match(/to (SRV-\w+)/)?.[1] ?? '');
    const user = d.match(/(?:by|for) (\w+)(?: |$)/)?.[1];
    return mk({
      source: 'ids', file, loc: r.id, tsUtc: iso(t), timeNote: 'UTC (IDS table). Time is when the alert was RAISED', raw: `${r.id} | ${r.time} | ${r.sensor} | ${d}`,
      srcIp: src, dstIp: dst, user: user && !/^(new|a|an|the)$/.test(user) ? user : undefined, host: r.sensor, action: `${r.id}: ${d}`,
      f: { sensor: r.sensor, desc: d }, tags: ['ids'],
    });
  });
}

function dhcp(): Ev[] {
  const file = '19_dhcp_lease_log.md';
  const out: Ev[] = [];
  for (const { n, text } of codeLines(read(file))) {
    const m = text.match(/^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d \+\d\d:\d\d) DHCPACK (.*)$/);
    if (!m) continue;
    const k = kv(m[2]);
    const t = offStr(m[1]);
    out.push(mk({
      source: 'dhcp', file, loc: `L${n}`, tsUtc: iso(t), timeNote: `Local time with offset in the line (${m[1]}) → UTC`, raw: text,
      srcIp: k.ip, host: k.hostname, action: `DHCP lease ${k.ip} → ${k.hostname} (${k.lease})`, f: k, tags: ['dhcp'],
    }));
  }
  return out;
}

export const SOURCE_LABEL: Record<Source, string> = {
  vpn: 'VPN', dc: 'Domain controller', web: 'Web server', 'fw-edge': 'Perimeter firewall', 'fw-int': 'Internal firewall', email: 'Email gateway', ids: 'IDS', dhcp: 'DHCP',
};
// keep `table` import referenced for tree-shaking checks
void table;
