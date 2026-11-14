import { loadKnowledge } from './knowledge';
import { parseAll } from './parsers';
import { buildIdentity, buildMatches } from './identity';
import { analyze } from './analysis';
import { buildReport } from './report';
import type { Evidence, Ref } from './types';

/** Reads problem_c_data/, returns everything the UI and the API need. Pure: same files in, same result out. */
export function runPipeline(): Evidence {
  const k = loadKnowledge();
  const events = parseAll(k.assets, k.ids);
  const idn = buildIdentity(k, events);
  const { incidents, observations, gaps } = analyze(k, events, idn);
  const matches = buildMatches(k, events, idn);

  const refs: Record<string, Ref> = {};
  for (const r of k.refs) refs[r.key] = r;
  for (const e of events) refs[e.id] = { key: e.id, file: e.file, loc: e.loc, raw: e.raw, kind: e.source === 'ids' ? 'row' : 'log' };

  const report = buildReport(incidents, observations, gaps, k.missingSources, events);
  const live = incidents.filter((i) => i.status === 'escalate');
  return {
    generatedAt: new Date().toISOString(), events, refs, matches, incidents, observations, gaps, missingSources: k.missingSources, report,
    stats: { events: events.length, sources: new Set(events.map((e) => e.source)).size, incidents: live.length, closed: incidents.length - live.length },
  };
}

/** Every citation anywhere in the evidence must point at a real log line, row or step. Returns the broken ones. */
export function brokenCites(ev: Evidence): string[] {
  const all = [
    ...ev.incidents.flatMap((i) => [...i.claims.flatMap((c) => c.cites), ...i.actions.map((a) => a.cite), ...i.inform.map((x) => x.cite), ...i.parts.flatMap((p) => p.assets.flatMap((a) => a.cites)), ...i.chain.map((c) => c.cite ?? ''), ...i.eventIds]),
    ...ev.observations.flatMap((o) => o.cites), ...ev.gaps.map((g) => g.cite), ...ev.missingSources.map((m) => m.cite), ...ev.matches.flatMap((m) => m.names.map((x) => x.cite)),
  ].filter(Boolean);
  return [...new Set(all.filter((c) => !ev.refs[c]))];
}
