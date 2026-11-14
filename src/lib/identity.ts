import type { Ev, Match } from './types';
import type { Knowledge, Asset, User } from './knowledge';

export interface VpnSession { id: string; user: string; assignedIp: string; srcIp: string; geo: string; startMs: number; endMs?: number; startCite: string; endCite?: string }

export function buildIdentity(k: Knowledge, events: Ev[]) {
  const sessions: VpnSession[] = [];
  for (const e of events.filter((x) => x.source === 'vpn')) {
    if (e.f.result === 'SUCCESS' && e.f.session) {
      sessions.push({ id: e.f.session, user: e.f.user, assignedIp: e.f.assigned_ip, srcIp: e.f.src_ip, geo: e.f.geo, startMs: Date.parse(e.tsUtc), startCite: e.id });
    }
  }
  for (const e of events.filter((x) => x.source === 'vpn' && x.tags.includes('session-end'))) {
    const s = sessions.find((x) => x.id === e.f.session);
    if (s) { s.endMs = Date.parse(e.tsUtc); s.endCite = e.id; }
  }

  const assetByIp = (ip?: string): Asset | undefined => (ip ? k.assets.find((a) => a.ips.includes(ip)) : undefined);
  const userByName = (u?: string): User | undefined => k.users.find((x) => x.username === u);

  /** Who is behind this IP at this moment? VPN pool address (by session window) or a laptop owner. */
  function userOfIp(ip: string | undefined, ms: number): { user: string; via: string; cites: string[] } | undefined {
    if (!ip) return undefined;
    const s = sessions.find((x) => x.assignedIp === ip && ms >= x.startMs - 1000 && ms <= (x.endMs ?? Infinity) + 1000);
    if (s) return { user: s.user, via: `VPN session ${s.id} was given ${ip} (${s.startCite})`, cites: [s.startCite] };
    const a = assetByIp(ip);
    if (a && /laptop/i.test(a.type)) {
      const u = k.users.find((x) => x.laptopTag === a.tag);
      if (u) return { user: u.username, via: `${ip} is laptop ${a.host} (${a.cite}), owned by ${u.username} (${u.cite})`, cites: [a.cite, u.cite] };
    }
    return undefined;
  }

  // Fill in "actor" on every event: the user named in the line, or the user behind the source IP.
  for (const e of events) {
    if (e.user && e.source !== 'ids') e.actor = e.user;
    else if (e.user && e.source === 'ids') e.actor = e.user;
    else {
      const w = userOfIp(e.srcIp, Date.parse(e.tsUtc));
      if (w) e.actor = w.user;
    }
  }
  return { sessions, assetByIp, userByName, userOfIp };
}

const isPrivate = (ip: string) => /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip);

export function buildMatches(k: Knowledge, events: Ev[], id: ReturnType<typeof buildIdentity>): Match[] {
  const out: Match[] = [];
  const first = (pred: (e: Ev) => boolean) => events.find(pred);

  for (const u of k.users) {
    const laptop = k.assets.find((a) => a.tag === u.laptopTag);
    const names = [
      { value: `username ${u.username}`, cite: u.cite },
      { value: `${u.name} <${u.email}>`, cite: u.cite },
      ...(laptop ? [{ value: `laptop tag ${laptop.tag}`, cite: u.cite }, { value: `hostname ${laptop.host}`, cite: laptop.cite }, { value: `IP ${laptop.ips[0]}`, cite: laptop.cite }] : []),
    ];
    const lease = laptop && first((e) => e.source === 'dhcp' && e.srcIp === laptop.ips[0]);
    if (lease) names.push({ value: `DHCP lease ${lease.srcIp} = ${lease.host}`, cite: lease.id });
    const dcl = laptop && first((e) => e.source === 'dc' && e.srcIp === laptop.ips[0] && e.actor === u.username);
    if (dcl) names.push({ value: `DC log client ${dcl.srcIp}, account ${u.username}`, cite: dcl.id });
    out.push({ entity: `${u.username} (${u.name})`, names, how: 'Directory row gives the laptop tag. Inventory row for that tag gives hostname and IP. DHCP and DC lines confirm the same hostname and IP.' });
  }

  for (const s of id.sessions) {
    const names = [
      { value: `session ${s.id}, user ${s.user}`, cite: s.startCite },
      { value: `source ${s.srcIp} [${s.geo}]`, cite: s.startCite },
      { value: `VPN address ${s.assignedIp}`, cite: s.startCite },
    ];
    const end = s.endMs ?? Infinity;
    const seen = events.filter((e) => (e.srcIp === s.assignedIp || e.dstIp === s.assignedIp) && e.source !== 'vpn' && Date.parse(e.tsUtc) >= s.startMs && Date.parse(e.tsUtc) <= end + 1000);
    for (const e of seen.slice(0, 6)) names.push({ value: `${s.assignedIp} in ${e.source} log: ${e.action.slice(0, 60)}`, cite: e.id });
    out.push({ entity: `VPN session ${s.id}`, names, how: `The VPN log hands out ${s.assignedIp} for the length of the session. Lines in other logs that use that address inside the session window belong to ${s.user}.` });
  }

  for (const a of k.assets.filter((x) => /^SRV-/.test(x.host))) {
    const short = a.host.replace('SRV-', '');
    const names = [{ value: `asset tag ${a.tag}`, cite: a.cite }, { value: `hostname ${a.host}`, cite: a.cite }, ...a.ips.map((ip) => ({ value: `IP ${ip}`, cite: a.cite }))];
    const svc = first((e) => e.source === 'dc' && (e.f.service ?? '').toUpperCase().includes(`${short}.ORBIT.LOCAL`));
    if (svc) names.push({ value: `${short}.orbit.local (service ${svc.f.service})`, cite: svc.id });
    const idsRow = first((e) => e.source === 'ids' && e.f.desc.includes(a.host));
    if (idsRow) names.push({ value: `name ${a.host} in IDS text`, cite: idsRow.id });
    out.push({ entity: a.host, names, how: 'Inventory row ties tag, hostname and IP together. Other logs use the short or domain name, or the IP.' });
  }

  const byIp = new Map<string, Ev[]>();
  for (const e of events) for (const ip of [e.srcIp, e.dstIp]) if (ip && !isPrivate(ip) && !/^203\.0\.113\./.test(ip)) byIp.set(ip, [...(byIp.get(ip) ?? []), e]);
  for (const [ip, evs] of byIp) {
    const sources = [...new Set(evs.map((e) => e.source))];
    if (sources.length < 2) continue;
    const names = sources.map((s) => { const e = evs.find((x) => x.source === s)!; return { value: `${s}: ${e.action.slice(0, 70)}`, cite: e.id }; });
    out.push({ entity: `External IP ${ip}`, names, how: `The same address appears in ${sources.length} different logs (${sources.join(', ')}), so the lines can be joined on the IP.` });
  }
  return out;
}
