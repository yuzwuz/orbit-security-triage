import type { Ev, Incident, Claim, Part, AssetHit, Action, Inform, Sev, Gap, ChainNode } from './types';
import type { Knowledge, Asset, Change } from './knowledge';
import type { buildIdentity } from './identity';
import { inCidr } from './tables';
import { hhmmss, iso, fmtUtc } from './time';

type Identity = ReturnType<typeof buildIdentity>;
const t0 = (e: Ev) => Date.parse(e.tsUtc);
const T = (e: Ev) => hhmmss(t0(e));
const n = (x: number) => x.toLocaleString('en-US');
const GB = (x: number) => `${(x / 1e9).toFixed(2)} GB`;
const CRIT = ['Low', 'Medium', 'High', 'Critical'];
const SEV_ORDER: Sev[] = ['P1', 'P2', 'P3', 'P4'];
const mmss = (ms: number) => `${Math.floor(ms / 60000)} min ${Math.round((ms % 60000) / 1000)} s`;
const AUTH_ONLY_PORTS = [88]; // Kerberos: authentication traffic, not a session on the server

export interface AnalysisResult { incidents: Incident[]; observations: Claim[]; gaps: Gap[] }

export function analyze(k: Knowledge, events: Ev[], idn: Identity): AnalysisResult {
  events.sort((a, b) => t0(a) - t0(b) || a.id.localeCompare(b.id));
  const must = <T,>(label: string, v: T | undefined): T => { if (v === undefined) throw new Error(`analysis: could not find ${label}`); return v; };
  const find = (p: (e: Ev) => boolean) => events.find(p);
  const filter = (p: (e: Ev) => boolean) => events.filter(p);
  const assetOf = (ip?: string) => idn.assetByIp(ip);
  const assetByHost = (h: string) => k.assets.find((a) => a.host === h);
  const rb = (id: string) => must(`runbook ${id}`, k.runbooks.find((r) => r.id === id));
  const action = (id: string, step: number, applied: string): Action => {
    const r = rb(id);
    return { runbook: id, step, text: must(`${id} step ${step}`, r.steps.find((s) => s.n === step)).text, applied, cite: `${r.file}:step${step}` };
  };
  const miss = (re: RegExp) => must(`missing source ${re}`, k.missingSources.find((m) => re.test(m.text))).cite;
  const matrixRow = (prefix: string) => must(`matrix row ${prefix}`, k.matrix.find((r) => r.type.startsWith(prefix)));

  // ---------- 1. approved activity (change calendar) ----------
  const covers = (c: Change, e: Ev) => {
    const t = t0(e);
    if (!c.active || t < c.startMs || t > c.endMs) return false;
    const actorOk = (e.srcIp && c.actorIps.includes(e.srcIp)) || (e.actor && c.actorUsers.includes(e.actor));
    if (!actorOk) return false;
    const ipOk = e.dstIp && (c.targetIps.includes(e.dstIp) || c.targetCidrs.some((cd) => inCidr(e.dstIp!, cd)));
    const idsOk = e.source === 'ids' && (c.targetCidrs.some((cd) => e.f.desc.includes(cd)) || c.targetHosts.some((h) => e.f.desc.includes(h)));
    return Boolean(ipOk || idsOk);
  };
  const approvedBy = new Map<string, Ev[]>();
  for (const c of k.changes) for (const e of events) if (covers(c, e)) {
    e.approvedBy ??= c.id;
    approvedBy.set(c.id, [...(approvedBy.get(c.id) ?? []), e]);
  }

  const incidents: Incident[] = [];
  const observations: Claim[] = [];
  const tag = (inc: Incident, evs: Ev[]) => {
    for (const e of evs) { if (!e.incidents.includes(inc.id)) e.incidents.push(inc.id); }
    inc.eventIds = [...new Set(evs.map((e) => e.id))].sort((a, b) => t0(must(a, events.find((x) => x.id === a))) - t0(must(b, events.find((x) => x.id === b))));
  };

  // ---------- helpers for severity and people ----------
  const mkHit = (a: Asset, how: string, cites: string[]): AssetHit => ({ tag: a.tag, host: a.host, criticality: a.criticality, how, cites: [a.cite, ...cites] });
  const mkPart = (name: string, typePrefix: string, hits: AssetHit[], notes: string[] = []): Part => {
    const row = matrixRow(typePrefix);
    const top = hits.reduce((m, h) => (CRIT.indexOf(h.criticality) > CRIT.indexOf(m.criticality) ? h : m), hits[0]);
    const sev = row.cells[top.criticality] as Sev;
    return {
      name, type: row.type, severity: sev, assets: hits,
      steps: [
        `Step 1. Incident type = "${row.type}" [${row.cite}]`,
        `Step 2. Assets actually reached: ${hits.map((h) => `${h.host} (${h.criticality})`).join(', ')}. Highest = ${top.host} (${top.criticality}) [${top.cites[0]}]`,
        ...notes.map((x, i) => `Step ${3 + i}. ${x}`),
        `Step ${3 + notes.length}. Matrix: row "${row.type}", column ${top.criticality} = ${sev} [${row.cite}]`,
      ],
    };
  };
  const worst = (parts: Part[]): Sev => parts.map((p) => p.severity).sort((a, b) => SEV_ORDER.indexOf(a) - SEV_ORDER.indexOf(b))[0];
  const limitMin = (s: string) => { const m = s.match(/(\d+)\s*(minute|hour)/i); return m ? +m[1] * (m[2].toLowerCase() === 'hour' ? 60 : 1) : undefined; };
  const informFor = (sev: Sev, hits: AssetHit[], firstMs: number): Inform[] => {
    const hitAssets = hits.map((h) => must(h.host, assetByHost(h.host)));
    const out: Inform[] = [];
    for (const r of k.escalation.filter((x) => x.sev === sev)) {
      let who = r.who;
      if (/data owner/i.test(who)) {
        const owners = hitAssets.map((a) => a.owner.match(/data owner: ([^,)]+)/)?.[1]?.trim()).filter(Boolean);
        if (!owners.length) continue;
        who = `Data owner of the affected system: ${[...new Set(owners)].join(', ')} (${hitAssets.filter((a) => /data owner/.test(a.owner)).map((a) => a.host).join(', ')})`;
      } else if (/system owner/i.test(who)) {
        who = `System owner of the affected asset: ${[...new Set(hitAssets.map((a) => a.owner))].join('; ')}`;
      } else if (/legal/i.test(who)) {
        const sens = hitAssets.filter((a) => /finance|HR|customer/i.test(a.type + ' ' + a.owner));
        if (!sens.length) continue;
        who = `${who} (needed: ${sens.map((a) => a.host).join(', ')} holds finance/HR data)`;
      }
      const m = limitMin(r.limit);
      out.push({ who, limit: r.limit, how: r.how, deadlineUtc: m ? fmtUtc(firstMs + m * 60000) : undefined, cite: r.cite });
    }
    return out;
  };
  const firstSeen = (evs: Ev[]) => {
    const alerts = evs.filter((e) => e.source === 'ids');
    const first = (alerts.length ? alerts : evs).reduce((a, b) => (t0(a) <= t0(b) ? a : b));
    return { ms: t0(first), basis: alerts.length ? `first IDS alert in this incident (${first.loc}) — assumption: the SOC first sees an incident when its first alert is raised` : `earliest log line (${first.id})` };
  };

  // ---------- 2. credential compromise campaign (phishing → VPN → FS01 → exfil) ----------
  const vpnAuth = filter((e) => e.source === 'vpn' && !!e.f.result);
  const geoCount = new Map<string, number>();
  vpnAuth.filter((e) => e.f.result === 'SUCCESS').forEach((e) => geoCount.set(e.f.geo, (geoCount.get(e.f.geo) ?? 0) + 1)); // baseline = countries of successful logins, so failed attacker attempts cannot skew it
  const homeGeo = [...geoCount.entries()].sort((a, b) => b[1] - a[1])[0][0];
  const suspicious = vpnAuth.filter((s) => {
    if (s.f.result !== 'SUCCESS' || s.f.geo === homeGeo) return false;
    return vpnAuth.filter((f) => f.f.result === 'FAIL' && f.f.user === s.f.user && f.f.src_ip === s.f.src_ip && t0(s) - t0(f) > 0 && t0(s) - t0(f) <= 15 * 60000).length >= 2;
  });

  const compromisedSessions = new Set<string>();
  for (const s of suspicious) {
    const id = `INC-${incidents.length + 1}`;
    const user = s.f.user, attackerIp = s.f.src_ip, assigned = s.f.assigned_ip;
    const sess = must('vpn session', idn.sessions.find((x) => x.id === s.f.session));
    compromisedSessions.add(sess.id);
    const u = must('user', idn.userByName(user));
    const laptop = must('laptop', k.assets.find((a) => a.tag === u.laptopTag));
    const fails = vpnAuth.filter((f) => f.f.result === 'FAIL' && f.f.user === user && f.f.src_ip === attackerIp && t0(s) - t0(f) > 0 && t0(s) - t0(f) <= 15 * 60000);
    const inSess = (e: Ev) => t0(e) >= sess.startMs - 1000 && t0(e) <= (sess.endMs ?? Infinity) + 1000;
    const fromVpn = filter((e) => (e.srcIp === assigned || e.dstIp === assigned) && inSess(e) && e.source !== 'vpn');

    // phishing
    const mails = filter((e) => e.source === 'email' && e.tags.includes('spf-fail') && !!e.f.url_host && e.user !== undefined);
    const linkHost = must('link host', mails.find((m) => m.user === user)).f.url_host;
    const msg = mails.filter((m) => m.f.url_host === linkHost);
    const msgId = msg[0].f.msgid;
    const linkAlert = must('IDS alert naming the link domain', find((e) => e.source === 'ids' && e.f.desc.includes(linkHost)));
    const phishIp = must('phishing host ip', linkAlert.dstIp);
    const clickFw = must('firewall line to the phishing host', find((e) => e.source === 'fw-edge' && e.srcIp === linkAlert.srcIp && e.dstIp === phishIp));
    const sameActorIp = phishIp === attackerIp;
    const recipients = msg.map((m) => m.user!);
    const others = recipients.filter((r) => r !== user);

    // reach
    const sessionFw = fromVpn.filter((e) => e.source === 'fw-int' && e.srcIp === assigned && e.tags.includes('allow'));
    const reachedMap = new Map<string, { a: Asset; evs: Ev[] }>();
    for (const e of sessionFw) {
      const a = assetOf(e.dstIp);
      if (!a || AUTH_ONLY_PORTS.includes(e.dstPort ?? 0)) continue;
      reachedMap.set(a.tag, { a, evs: [...(reachedMap.get(a.tag)?.evs ?? []), e] });
    }
    const tickets = fromVpn.filter((e) => e.source === 'dc' && e.f.eventId === '4769');
    const tgt = must('TGT', fromVpn.find((e) => e.source === 'dc' && e.f.eventId === '4768'));
    const hitsCred: AssetHit[] = [...reachedMap.values()].map(({ a, evs }) => {
      const tk = tickets.find((x) => (x.f.service ?? '').toUpperCase().includes(a.host.replace('SRV-', '') + '.ORBIT'));
      return mkHit(a, `session from ${assigned} to port ${evs[0].dstPort}${tk ? ` and Kerberos ticket for ${tk.f.service}` : ''}`, [...evs.map((x) => x.id), ...(tk ? [tk.id] : [])]);
    });
    const dcAsset = must('DC asset', k.assets.find((a) => /domain controller/i.test(a.type)));
    const kerb = must('kerberos session', sessionFw.find((e) => e.dstIp === dcAsset.ips[0] && AUTH_ONLY_PORTS.includes(e.dstPort ?? 0)));
    const reset = must('password reset', fromVpn.find((e) => e.source === 'dc' && e.f.eventId === '4724'));
    const notice = find((e) => e.source === 'email' && e.user === user && /password was changed/i.test(e.f.subject ?? '') && t0(e) >= t0(reset));
    const bad = filter((e) => e.source === 'dc' && e.f.eventId === '4625' && e.actor === user && t0(e) > (sess.endMs ?? 0));
    const lock = find((e) => e.source === 'dc' && e.f.eventId === '4740' && e.actor === user);
    const lockAlert = find((e) => e.source === 'ids' && e.user === user && /lockout/i.test(e.f.desc));
    const loginAlert = must('VPN IDS alert', find((e) => e.source === 'ids' && e.srcIp === attackerIp && /VPN login/i.test(e.f.desc)));
    const edgeVpn = filter((e) => e.source === 'fw-edge' && e.srcIp === attackerIp && e.dstPort === 443 && e.f.rule === 'vpn-gateway');

    // exfil
    const big = must('large transfer', fromVpn.find((e) => e.source === 'fw-int' && e.tags.includes('large-transfer')));
    const bigAlert = find((e) => e.source === 'ids' && e.dstIp === assigned && /transfer/i.test(e.f.desc));
    const srcAsset = must('transfer source', assetOf(big.dstIp));
    const s2c = Number(big.f.bytes_server_to_client);
    const vpnEnd = find((e) => e.id === sess.endCite);
    const vpnBytes = vpnEnd ? Number(vpnEnd.f.bytes_to_client) : undefined;
    const bigStart = t0(big), bigClose = Date.parse(big.f.closeUtc);
    const exfilHit = mkHit(srcAsset, `source of the ${GB(s2c)} transfer`, [big.id]);

    const partCred = mkPart(`Phishing click → credential compromise of ${user}`, 'Credential compromise', hitsCred, [
      `Rule: a phishing email where a click is seen is handled as credential compromise [03_severity_matrix.md:rule1]. The only click seen is ${laptop.host} → ${phishIp} [${clickFw.id}].`,
      `Rule 4.1 uses the most critical asset the attacker actually reached (confirmed login or session) [01_company_security_rules.md:4.1]. ${dcAsset.host} (${dcAsset.criticality}) saw only Kerberos on port 88 [${kerb.id}], the TGT [${tgt.id}] and the password reset [${reset.id}] from the attacker session. There is no logon to ${dcAsset.host} by ${user}, so it is not counted as reached. If the SOC counts it, this part becomes ${matrixRow('Credential compromise').cells.Critical}; the whole incident is already P1 from the transfer part.`,
    ]);
    const partExfil = mkPart(`Large transfer from ${srcAsset.host}`, 'Data exfiltration', [exfilHit], [
      `Rule 2.4: a large transfer is evidence of a transfer, not of which files were read [01_company_security_rules.md:2.4].`,
    ]);
    const parts = [partCred, partExfil];
    const sevAll = worst(parts);
    const fs = firstSeen([linkAlert, loginAlert, ...(bigAlert ? [bigAlert] : []), ...(lockAlert ? [lockAlert] : [])]);

    const claims: Claim[] = [
      { label: 'confirmed', text: `Phishing email ${msgId} "${msg[0].f.subject}" from ${msg[0].f.from} was DELIVERED at ${T(msg[0])} to ${recipients.join(', ')} (SPF ${msg[0].f.spf}, DKIM ${msg[0].f.dkim}, score ${msg[0].f.score}, below the quarantine score of 8.0). The link domain is ${linkHost}.`, cites: [...msg.map((m) => m.id), '20_log_source_coverage.md:Email gateway'] },
      { label: 'confirmed', text: `${laptop.host} (${laptop.ips[0]}, ${user}'s laptop) connected to ${phishIp}:443 at ${T(clickFw)}, ${mmss(t0(clickFw) - t0(msg[0]))} after delivery. Threat intelligence says ${phishIp} hosts ${linkHost}, the link domain in the email.`, cites: [clickFw.id, linkAlert.id, msg[0].id] },
      { label: 'confirmed', text: `${fails.length} VPN logins for ${user} from ${attackerIp} [${s.f.geo}] failed MFA between ${T(fails[0])} and ${T(fails[fails.length - 1])} (${fails.map((f) => f.f.reason).join(', ')}). The next attempt at ${T(s)} succeeded with an approved push; session ${sess.id} got address ${assigned}. IDS raised ${loginAlert.loc} for a login from a new country.`, cites: [...fails.map((f) => f.id), s.id, loginAlert.id, ...edgeVpn.map((e) => e.id)] },
      { label: 'confirmed', text: `The same IP ${attackerIp} is both the phishing host seen from ${laptop.host} and the source of the VPN logins.`, cites: [linkAlert.id, s.id] },
      { label: 'confirmed', text: `From ${assigned} (session ${sess.id}) the account requested a Kerberos TGT at ${T(tgt)} and service tickets for ${tickets.map((x) => `${x.f.service} at ${T(x)}`).join(' and ')}. The internal firewall shows allowed sessions to ${[...reachedMap.values()].map(({ a, evs }) => `${a.host}:${evs[0].dstPort}`).join(' and ')}.`, cites: [tgt.id, ...tickets.map((x) => x.id), ...[...reachedMap.values()].flatMap((r) => r.evs.map((x) => x.id))] },
      { label: 'confirmed', text: `At ${T(big)} (UTC start time, see time note) the session ${assigned} → ${srcAsset.host}:${big.dstPort} began a transfer that closed at ${hhmmss(bigClose)}: ${n(Number(big.f.bytes_total))} bytes in total, ${n(s2c)} bytes (${GB(s2c)}) from ${srcAsset.host} to ${assigned}. ${bigAlert ? `IDS ${bigAlert.loc} also reported about 2.4 GB. ` : ''}${vpnBytes ? `The VPN log shows ${n(vpnBytes)} bytes to the client for session ${sess.id} when it ended at ${T(vpnEnd!)}.` : ''}`, cites: [big.id, ...(bigAlert ? [bigAlert.id] : []), ...(vpnEnd ? [vpnEnd.id] : [])] },
      { label: 'confirmed', text: `At ${T(reset)} the DC recorded a successful password reset of ${user}, requested by ${user} from ${assigned} (inside the attacker session).${notice ? ` The gateway sent the "password was changed" notice at ${T(notice)}.` : ''}`, cites: [reset.id, ...(notice ? [notice.id] : [])] },
      ...(lock ? [{ label: 'confirmed' as const, text: `After the session ended, ${bad.length} failed logons for ${user} from ${laptop.host} (${bad.map((b) => T(b)).join(', ')}) led to an account lockout at ${T(lock)}${lockAlert ? ` (${lockAlert.loc})` : ''}.`, cites: [...bad.map((b) => b.id), lock.id, ...(lockAlert ? [lockAlert.id] : [])] }] : []),
      { label: 'confirmed', text: `Only ${user}'s laptop connected to ${phishIp} among the recipients. ${others.join(' and ')} laptops show no connection to it in the perimeter log.`, cites: [clickFw.id, ...filter((e) => e.source === 'fw-edge' && others.some((o) => e.actor === o)).map((e) => e.id)] },

      { label: 'suspected', text: `${user} opened the link and typed the password on the fake page. Guess needed: that the ${T(clickFw)} connection was caused by the email link, and that credentials were entered there. The logs show only the connection.`, cites: [clickFw.id, linkAlert.id] },
      { label: 'suspected', text: sameActorIp ? `One attacker ran both the phishing site and the VPN login. Guess needed: that a shared IP means one actor.` : `The VPN login is linked to the phishing campaign. Guess needed.`, cites: [linkAlert.id, s.id] },
      { label: 'suspected', text: `The ${GB(s2c)} transfer was data exfiltration of finance/HR files from ${srcAsset.host} (the share holds "${srcAsset.type}"). Guess needed: that the attacker, not a process, ran the transfer, and that the files were kept.`, cites: [big.id, srcAsset.cite] },
      { label: 'suspected', text: `The attacker reset ${user}'s password to keep access and lock out the real user. Guess needed: motive. The bad-password logons at ${bad.map((b) => T(b)).join(' and ')} may be the real user typing the old password.`, cites: [reset.id, ...bad.map((b) => b.id)] },
      { label: 'suspected', text: `The approved MFA push at ${T(s)} was tapped by ${user} after ${fails.length} refusals or timeouts (MFA fatigue). Guess needed: the log says "push_approved" but not who tapped it.`, cites: [...fails.map((f) => f.id), s.id, '01_company_security_rules.md:6.1'] },

      { label: 'noevidence', text: `Which files were read or copied from ${srcAsset.host}: no file access (audit) log exists (agent not installed). Also not shown: whether the data left ${assigned} for the attacker's own machine or was used afterwards (the VPN byte count shows the tunnel carried it to the client).`, cites: [big.id, miss(/FS01/)] },
      { label: 'noevidence', text: `What was run against ${assetByHost('SRV-DB01')?.host ?? 'the database server'} in the ${T(must('db session', sessionFw.find((e) => e.dstPort === 1433)))} session (${n(Number(sessionFw.find((e) => e.dstPort === 1433)!.f.bytes_total))} bytes): its login and query log is not forwarded to the SOC.`, cites: [sessionFw.find((e) => e.dstPort === 1433)!.id, miss(/DB01/)] },
      { label: 'noevidence', text: `What ${assigned} did on the internal network between 06:32:00Z and ${sess.endMs ? hhmmss(sess.endMs) : 'session end'}: the internal firewall has no log for 11:32:00–12:28:59 PKT (06:32:00–07:28:59 UTC), and the password reset at ${T(reset)} falls inside it.`, cites: ['20_log_source_coverage.md:Internal firewall', reset.id] },
      { label: 'noevidence', text: `Whether ${others.join(' or ')} clicked the link another way (phone, home network): no web proxy log and no laptop security (EDR) log exists, so only the perimeter firewall can show a click.`, cites: [miss(/proxy/i), miss(/EDR/)] },
      { label: 'noevidence', text: `Whether ${laptop.host} is infected or what ran on it, and whether ${user} was compromised on any other day: no EDR logs, and logs exist for 2026-11-04 only.`, cites: [miss(/EDR/), miss(/dates/i)] },
    ];

    const chain: ChainNode[] = [
      { label: `Phishing email ${msgId} delivered to ${recipients.length} staff`, time: T(msg[0]), kind: 'confirmed', cite: msg[0].id },
      { label: `${laptop.host} connects to ${phishIp} (link host)`, time: T(clickFw), kind: 'confirmed', cite: clickFw.id },
      { label: `${user} clicked and entered the password`, kind: 'suspected', cite: clickFw.id },
      { label: `${fails.length} MFA pushes refused or timed out (${s.f.geo})`, time: T(fails[0]), kind: 'confirmed', cite: fails[0].id },
      { label: `VPN login approved, ${assigned} assigned`, time: T(s), kind: 'confirmed', cite: s.id },
      { label: `Kerberos, ${[...reachedMap.values()].map((r) => r.a.host).join(' + ')} sessions`, time: T(tgt), kind: 'confirmed', cite: tgt.id },
      { label: `${GB(s2c)} from ${srcAsset.host} to ${assigned}`, time: hhmmss(bigStart), kind: 'confirmed', cite: big.id },
      { label: `Password reset from the attacker session`, time: T(reset), kind: 'confirmed', cite: reset.id },
      ...(lock ? [{ label: `${user} locked out`, time: T(lock), kind: 'confirmed' as const, cite: lock.id }] : []),
      { label: 'Which files were read', kind: 'noevidence', cite: miss(/FS01/) },
    ];

    const inc: Incident = {
      id, title: `Phishing → account takeover → ${srcAsset.host} transfer (${user})`, status: 'escalate', severity: sevAll, parts, accounts: [user],
      firstSeenUtc: fmtUtc(fs.ms), firstSeenBasis: fs.basis, chain, claims, eventIds: [],
      actions: [
        action('RB-PHISH-01', 1, `Recipients in the gateway log: ${recipients.join(', ')} (${msg.map((m) => m.id).join(', ')}).`),
        action('RB-PHISH-01', 2, `Quarantine ${msgId} from all ${recipients.length} mailboxes.`),
        action('RB-PHISH-01', 3, `Block sender domain ${msg[0].f.from.split('@')[1]} and link domain ${linkHost} (${phishIp}) at the email gateway and perimeter firewall.`),
        action('RB-PHISH-01', 4, `Done from the logs: only ${laptop.host} (${user}) connected to ${phishIp} [${clickFw.id}].`),
        action('RB-PHISH-01', 5, `Click found → open RB-CRED-02 for ${user}.`),
        action('RB-PHISH-01', 6, `Send the warning to ${recipients.join(', ')}.`),
        action('RB-CRED-02', 1, `Call ${u.name} on ${u.phone} (user directory) and ask if the ${T(s)} VPN login was theirs.`),
        action('RB-CRED-02', 2, `Disable ${user} and end all sessions. Session ${sess.id} already closed at ${sess.endMs ? T(must('end', vpnEnd)) : 'n/a'} per the VPN log; still disable the account and check for other sessions.`),
        action('RB-CRED-02', 3, `Block ${attackerIp} at the perimeter firewall.`),
        action('RB-CRED-02', 4, `Reset only after step 2, through the helpdesk with identity checks, and require new MFA enrollment. The password was already changed by the attacker session at ${T(reset)}.`),
        action('RB-CRED-02', 5, `Review all logins of ${user} in the last 24 hours. Only 2026-11-04 logs exist, so earlier days cannot be reviewed. Systems reached today: ${[...reachedMap.values()].map((r) => r.a.host).join(', ')}.`),
        action('RB-CRED-02', 6, `Phishing was the source → disconnect ${laptop.host} from the network.`),
        action('RB-CRED-02', 7, `Check ${[...reachedMap.values()].map((r) => r.a.host).join(' and ')} for further activity. A large transfer was seen → open RB-EXFIL-04.`),
        action('RB-CRED-02', 8, `Keep all logs unchanged.`),
        action('RB-EXFIL-04', 1, `${n(s2c)} bytes from ${srcAsset.host} to ${assigned}, started ${T(big)}, closed ${hhmmss(bigClose)} [${big.id}].`),
        action('RB-EXFIL-04', 2, `The destination ${assigned} is an internal VPN address. Block the session's source ${attackerIp} (same as RB-CRED-02 step 3).`),
        action('RB-EXFIL-04', 3, `Copy the relevant logs. Do not reboot ${srcAsset.host}.`),
        action('RB-EXFIL-04', 4, `Ask the system owner what ${srcAsset.host} holds. Inventory: ${srcAsset.type}; owner ${srcAsset.owner}.`),
        action('RB-EXFIL-04', 5, `No file-level audit log exists for ${srcAsset.host} → record that it is unknown which files were read.`),
        action('RB-EXFIL-04', 6, `${srcAsset.host} holds finance and HR data → inform Legal and Compliance.`),
      ],
      inform: informFor(sevAll, [exfilHit, ...hitsCred.filter((h) => h.host !== srcAsset.host)], fs.ms),
    };
    incidents.push(inc);
    tag(inc, [...msg, linkAlert, clickFw, ...fails, s, loginAlert, ...edgeVpn, ...fromVpn, ...(notice ? [notice] : []), ...bad, ...(lock ? [lock] : []), ...(lockAlert ? [lockAlert] : []), ...(vpnEnd ? [vpnEnd] : [])]);
  }

  // ---------- 3. web attack (SQL injection) ----------
  const sqli = filter((e) => e.tags.includes('sqli') && !e.approvedBy);
  for (const ip of [...new Set(sqli.map((e) => e.srcIp!))]) {
    const id = `INC-${incidents.length + 1}`;
    const evs = filter((e) => e.source === 'web' && e.srcIp === ip);
    const errs = evs.filter((e) => Number(e.f.status) >= 400);
    const maxErr = Math.max(...errs.map((e) => e.bytes ?? 0), 1);
    const ok = evs.filter((e) => e.tags.includes('sqli') && e.f.status === '200' && (e.bytes ?? 0) >= maxErr * 10);
    const alert = find((e) => e.source === 'ids' && e.srcIp === ip);
    const edge = filter((e) => e.source === 'fw-edge' && e.srcIp === ip);
    const web = must('web asset', assetByHost(evs[0].host!));
    const success = ok.length > 0;
    const part = mkPart(`SQL injection against ${web.host}`, success ? 'Web application attack, success suspected' : 'Web application attack, attempts only', [mkHit(web, `${evs.length} requests answered by the web server`, evs.map((e) => e.id).slice(0, 3))], success ? [`A 200 response of ${n(ok[0].bytes!)} bytes to an injection request, while the error responses are ${n(maxErr)} bytes, suggests success [08_runbook_web_attack.md:step3].`] : []);
    const fs = firstSeen(alert ? [alert] : evs);
    const inc: Incident = {
      id, title: `SQL injection from ${ip} against ${web.host}`, status: 'escalate', severity: part.severity, parts: [part], accounts: [], firstSeenUtc: fmtUtc(fs.ms), firstSeenBasis: fs.basis, eventIds: [],
      chain: [
        { label: `sqlmap sends ${evs.filter((e) => e.tags.includes('sqli')).length} injection requests`, time: T(evs.find((e) => e.tags.includes('sqli'))!), kind: 'confirmed', cite: evs.find((e) => e.tags.includes('sqli'))!.id },
        ...ok.map((e) => ({ label: `UNION SELECT returns 200 with ${n(e.bytes!)} bytes`, time: T(e), kind: 'suspected' as const, cite: e.id })),
        { label: 'What the response contained', kind: 'noevidence' as const, cite: miss(/DB01/) },
      ],
      claims: [
        { label: 'confirmed', text: `${ip} sent ${evs.length} requests to ${web.host} between ${T(evs[0])} and ${T(evs[evs.length - 1])} with user agent ${evs[0].f.ua}; ${errs.length} were answered with an error (${errs.map((e) => e.f.status).filter((v, i, a) => a.indexOf(v) === i).join('/')}, ${n(maxErr)} bytes each).${alert ? ` IDS ${alert.loc} raised an SQL injection alert.` : ''}`, cites: [...evs.map((e) => e.id), ...(alert ? [alert.id] : []), ...edge.map((e) => e.id)] },
        ...ok.map((e): Claim => ({ label: 'confirmed', text: `The request "${e.f.path.slice(0, 80)}" at ${T(e)} got status 200 with ${n(e.bytes!)} bytes, about ${Math.round(e.bytes! / maxErr)}× the error size.`, cites: [e.id] })),
        ...(success ? [{ label: 'suspected' as const, text: `The UNION SELECT succeeded and returned rows from a users table (username, password). Guess needed: the response size is the only sign; the runbook says a large 200 to an attack request may mean success.`, cites: [ok[0].id, '08_runbook_web_attack.md:step3'] }] : []),
        { label: 'noevidence', text: `What data the 200 response carried and whether the database ran the injected queries: the database server log is not forwarded to the SOC, and the web log has no response body.`, cites: [miss(/DB01/), ...(ok[0] ? [ok[0].id] : [])] },
        { label: 'noevidence', text: `Whether ${ip} is linked to the external scan from another IP or to the VPN incident: no shared evidence in the logs, so it is scored separately (rule 4.3).`, cites: ['01_company_security_rules.md:4.3'] },
      ],
      actions: [
        action('RB-WEB-03', 1, `${ip}: ${evs.length} requests, ${evs[0].id} to ${evs[evs.length - 1].id}.`),
        action('RB-WEB-03', 2, `Block ${ip} at the perimeter firewall.`),
        action('RB-WEB-03', 3, `Response sizes checked: errors ${n(maxErr)} bytes, one 200 of ${ok[0] ? n(ok[0].bytes!) : 'n/a'} bytes [${ok[0]?.id}].`),
        action('RB-WEB-03', 4, `Ask the web team to review the code behind ${ok[0]?.f.path.split('?')[0] ?? 'the attacked page'}.`),
        action('RB-WEB-03', 5, `Database logs are not available (file 20) → record as not enough evidence.`),
        action('RB-WEB-03', 6, `Check the SQL injection rule on the web server filter; IDS ${alert?.loc ?? ''} shows the pattern was seen.`),
        action('RB-WEB-03', 7, `Record findings in the ticket.`),
      ],
      inform: [],
    };
    inc.inform = informFor(part.severity, part.assets, fs.ms);
    incidents.push(inc);
    tag(inc, [...evs, ...(alert ? [alert] : []), ...edge]);
  }

  // ---------- 4. unapproved external scan ----------
  const scanAlerts = filter((e) => e.source === 'ids' && /port scan/i.test(e.f.desc) && !e.approvedBy);
  for (const a of scanAlerts) {
    const ip = must('scan ip', a.srcIp);
    const id = `INC-${incidents.length + 1}`;
    const edge = filter((e) => e.source === 'fw-edge' && e.srcIp === ip);
    const denied = edge.filter((e) => e.tags.includes('deny'));
    const allowed = edge.filter((e) => e.tags.includes('allow'));
    const probes = filter((e) => e.source === 'web' && e.srcIp === ip);
    const target = must('scan target', assetOf(a.dstIp) ?? assetByHost(probes[0]?.host ?? ''));
    const part = mkPart(`Port scan and probing from ${ip}`, 'Unapproved scanning', [mkHit(target, `${allowed.length} connection allowed to port ${allowed[0]?.dstPort ?? '?'} and ${probes.length} web requests answered`, [...allowed.map((e) => e.id), ...probes.map((e) => e.id)])]);
    const fs = firstSeen([a]);
    const inc: Incident = {
      id, title: `Unapproved external scan from ${ip}`, status: 'escalate', severity: part.severity, parts: [part], accounts: [], firstSeenUtc: fmtUtc(fs.ms), firstSeenBasis: fs.basis, eventIds: [],
      chain: [
        { label: `${denied.length} connections denied (ports ${denied.map((e) => e.dstPort).join(', ')})`, time: T(denied[0]), kind: 'confirmed', cite: denied[0].id },
        ...(allowed[0] ? [{ label: `Port ${allowed[0].dstPort} allowed`, time: T(allowed[0]), kind: 'confirmed' as const, cite: allowed[0].id }] : []),
        ...probes.map((p) => ({ label: `${p.f.path} → ${p.f.status}`, time: T(p), kind: 'confirmed' as const, cite: p.id })),
      ],
      claims: [
        { label: 'confirmed', text: `${ip} tried ${denied.length + allowed.length} ports on ${target.host}'s public address from ${T(edge[0])} to ${T(edge[edge.length - 1])}; ${denied.length} were denied by default-deny and 1 (port ${allowed[0]?.dstPort}) was allowed. IDS ${a.loc} raised a port scan alert.`, cites: [...edge.map((e) => e.id), a.id] },
        { label: 'confirmed', text: `${probes.length} web requests followed (${probes.map((p) => p.f.path).join(', ')}); all returned ${[...new Set(probes.map((p) => p.f.status))].join('/')}, so nothing was served.`, cites: probes.map((p) => p.id) },
        { label: 'confirmed', text: `No change in the calendar lists ${ip} as a source, so the scan is not approved (rule 3.1).`, cites: ['01_company_security_rules.md:3.1', ...k.changes.map((c) => c.cite)] },
        { label: 'noevidence', text: `Whether any login attempt followed the scan: no authentication log exists for ${target.host}'s web application, and the web log shows only 404 responses.`, cites: probes.map((p) => p.id) },
      ],
      actions: [
        action('RB-SCAN-05', 1, `No change-calendar row matches ${ip}.`),
        action('RB-SCAN-05', 3, `Not approved and external → block ${ip} at the perimeter firewall.`),
        action('RB-SCAN-05', 5, `Refused (denied): ports ${denied.map((e) => e.dstPort).join(', ')}. Answered (allowed): port ${allowed[0]?.dstPort}. No login attempts seen after it.`),
        action('RB-SCAN-05', 6, `Watch ${ip} for the next 24 hours.`),
      ],
      inform: [],
    };
    inc.inform = informFor(part.severity, part.assets, fs.ms);
    incidents.push(inc);
    tag(inc, [...edge, ...probes, a]);
  }

  // ---------- 5. closed as harmless (approved) ----------
  let cl = 0;
  for (const c of k.changes) {
    const evs = approvedBy.get(c.id);
    if (!evs?.length) continue;
    const id = `CL-${++cl}`;
    const first = evs[0], last = evs[evs.length - 1];
    const alerts = evs.filter((e) => e.source === 'ids');
    const isScan = alerts.some((a) => /port scan/i.test(a.f.desc));
    const actor = c.actorIps[0] ? `source ${c.actorIps[0]}` : `user ${c.actorUsers[0]}`;
    const inc: Incident = {
      id, title: `Closed as harmless: ${c.description} (${c.id})`, status: 'closed-harmless', parts: [], accounts: c.actorUsers, firstSeenUtc: fmtUtc(t0(first)), firstSeenBasis: 'n/a (not escalated)',
      closedBy: c.id, closedReason: `Rule 3.1: the calendar lists the same system, the same ${c.actorIps.length ? 'tool' : 'person'} and a window that contains the activity.`, eventIds: [],
      chain: [
        { label: `Change ${c.id} approved`, kind: 'harmless', cite: c.cite },
        ...alerts.map((a) => ({ label: `${a.loc}: ${a.f.desc.slice(0, 60)}`, time: T(a), kind: 'harmless' as const, cite: a.id })),
      ],
      claims: [
        { label: 'confirmed', text: `${c.id}: "${c.description}" on ${c.target}, performed by ${c.performer}, window ${fmtUtc(c.startMs)} to ${fmtUtc(c.endMs)} (the calendar is in PKT), status "${c.status}".`, cites: [c.cite] },
        { label: 'confirmed', text: `${evs.length} log lines match: ${actor}, activity from ${T(first)} to ${T(last)} (UTC), target: ${c.target}. The window contains all of them.`, cites: evs.map((e) => e.id).slice(0, 12) },
        ...(alerts.length ? [{ label: 'confirmed' as const, text: `The alert${alerts.length > 1 ? 's' : ''} ${alerts.map((a) => a.loc).join(', ')} describe${alerts.length > 1 ? '' : 's'} this same activity, so no incident is opened. ${isScan ? 'RB-SCAN-05 step 2: approved scan is closed, not escalated.' : ''}`, cites: [...alerts.map((a) => a.id), ...(isScan ? ['10_runbook_scanning_recon.md:step2'] : [])] }] : []),
      ],
      actions: isScan ? [action('RB-SCAN-05', 1, `Calendar row ${c.id} matches source, target and window.`), action('RB-SCAN-05', 2, `Close the alert as approved activity. Do not escalate.`)] : [],
      inform: [],
    };
    incidents.push(inc);
    tag(inc, evs);
  }
  for (const c of k.changes.filter((x) => !approvedBy.get(x.id)?.length)) {
    const firstMs = t0(events[0]), lastMs = t0(events[events.length - 1]);
    const why = !c.active ? `status "${c.status}": it was not performed, so it approves nothing` : c.endMs < firstMs ? `its window (${fmtUtc(c.startMs)} to ${fmtUtc(c.endMs)}) is before the first log line, so no log line can match it` : c.startMs > lastMs ? `its window starts ${fmtUtc(c.startMs)}, after the last log line, so no log line can match it` : 'no log line matches its source, target and window';
    observations.push({ label: 'confirmed', text: `${c.id} (${c.description}) closes nothing: ${why}.`, cites: [c.cite] });
  }

  // ---------- 6. rule 6.2: two logins from different places at the same time ----------
  for (const s of idn.sessions) {
    if (compromisedSessions.has(s.id)) continue;
    const office = filter((e) => ['dc', 'fw-int', 'fw-edge'].includes(e.source) && e.actor === s.user && !!e.srcIp?.startsWith('10.20.') && t0(e) >= s.startMs && t0(e) <= (s.endMs ?? Infinity));
    if (!office.length) continue;
    const vpnStart = must('vpn start', find((e) => e.id === s.startCite));
    const reached = filter((e) => e.srcIp === s.assignedIp && e.source !== 'vpn' && t0(e) >= s.startMs && t0(e) <= (s.endMs ?? Infinity));
    observations.push({
      label: 'suspected',
      text: `Low confidence: ${s.user}'s VPN session ${s.id} (from ${s.srcIp} [${s.geo}], MFA approved) was open from ${T(vpnStart)} to ${s.endMs ? hhmmss(s.endMs) : 'unknown'} while ${s.user} also used the office laptop at ${T(office[0])}. Rule 6.2 treats two logins from different places at the same time as a sign of misuse. Guess needed: that both are the same person. Other signs are missing: ${s.geo === homeGeo ? 'normal country' : 'unusual country'}, no failed MFA, ${reached.length ? reached.length + ' internal sessions' : 'no internal server reached from ' + s.assignedIp}. Ask the user (RB-CRED-02 step 1); not scored as an incident.`,
      cites: [s.startCite, ...office.slice(0, 3).map((e) => e.id), '01_company_security_rules.md:6.2', '11_vpn_auth_log.md:L1'].filter((v, i, a) => a.indexOf(v) === i),
    });
  }

  // ---------- 7. log gaps ----------
  const gaps: Gap[] = [];
  const dcRow = k.coverage.find((c) => /domain controller/i.test(c.source));
  const dcWin = dcRow?.coverage.match(/(\d\d:\d\d) to (\d\d:\d\d) UTC/);
  if (dcRow && dcWin) {
    const outside = filter((e) => e.source !== 'dc' && e.source !== 'ids' && e.source !== 'dhcp' && (e.tsUtc.slice(11, 16) < dcWin[1] || e.tsUtc.slice(11, 16) > dcWin[2]));
    gaps.push({ what: 'Domain controller log covers only 03:00–19:00 UTC', window: 'before 03:00Z and after 19:00Z', impact: `Anything on the DC outside that window is invisible. ${outside.length ? `${outside.length} line(s) from other logs fall outside it (e.g. ${outside[0].id} at ${T(outside[0])}) and cannot be matched to DC events.` : ''}`, cite: `20_log_source_coverage.md:${dcRow.source}` });
  }
  const fwRow = k.coverage.find((c) => /internal firewall/i.test(c.source));
  const fwWin = fwRow?.coverage.match(/(\d\d:\d\d:\d\d) to (\d\d:\d\d:\d\d) PKT/);
  if (fwRow && fwWin) {
    const toMs = (s: string) => Date.parse(`2026-11-04T${s}+05:00`);
    const g0 = toMs(fwWin[1]), g1 = toMs(fwWin[2]);
    const overlaps = idn.sessions.map((s) => ({ s, a: Math.max(g0, s.startMs), b: Math.min(g1, s.endMs ?? Infinity) })).filter((x) => x.a < x.b);
    gaps.push({
      what: 'Internal firewall log has a hole: 11:32:00–12:28:59 PKT (06:32:00–07:28:59 UTC), device rebooted for a firmware update', window: `${hhmmss(g0)} to ${hhmmss(g1)}`,
      impact: `The firewall writes a line when a session CLOSES, so sessions that opened and closed inside the hole are missing. It overlaps ${overlaps.map((o) => `VPN session ${o.s.id} (${o.s.user}${compromisedSessions.has(o.s.id) ? ', the attacker session' : ''}) from ${hhmmss(o.a)} to ${hhmmss(o.b)}`).join('; ')}. The password reset at ${T(must('reset', find((e) => e.f.eventId === '4724')))} is inside the hole.`,
      cite: `20_log_source_coverage.md:${fwRow.source}`,
    });
  }
  const emailRow = k.coverage.find((c) => /email/i.test(c.source));
  if (emailRow) gaps.push({ what: 'Email gateway quarantines messages with score 8.0 or higher', impact: 'Quarantined mail is not in the perimeter log. The phishing message scored below 8.0 and was delivered, so it is visible in the email log.', cite: `20_log_source_coverage.md:${emailRow.source}` });
  const dhcpRow = k.coverage.find((c) => /dhcp/i.test(c.source));
  if (dhcpRow) gaps.push({ what: 'DHCP covers the office network only', impact: 'VPN addresses (10.10.3.x) are not in DHCP; they are matched through the VPN log instead.', cite: `20_log_source_coverage.md:${dhcpRow.source}` });

  return { incidents, observations, gaps };
}

export const toIso = iso;
