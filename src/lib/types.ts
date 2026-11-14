// SHARED CONTRACT. Both team members import from here. Do not change field names without telling each other.

export type Source = 'vpn' | 'dc' | 'web' | 'fw-edge' | 'fw-int' | 'email' | 'ids' | 'dhcp';
export type Label = 'confirmed' | 'suspected' | 'noevidence';
export type Sev = 'P1' | 'P2' | 'P3' | 'P4';

/** One normalised event from any log. `id` is also its citation key. */
export interface Ev {
  id: string; // "11_vpn_auth_log.md:L5"
  source: Source;
  file: string;
  loc: string; // "L5" for log lines, "ALT-9002" for IDS rows
  tsUtc: string; // event time in UTC, ISO. For logs written at session close this is the START time.
  loggedUtc?: string; // when the line was written, if different from tsUtc
  timeNote: string; // how the time was converted, shown in the UI
  action: string; // short human label
  user?: string;
  actor?: string; // user inferred from the IP (VPN pool or laptop owner)
  srcIp?: string;
  dstIp?: string;
  dstPort?: number;
  host?: string;
  bytes?: number;
  f: Record<string, string>; // raw key=value fields
  tags: string[];
  approvedBy?: string; // change ID when the change calendar covers this event
  incidents: string[]; // incident ids this event belongs to
  raw: string;
}

/** Anything that can be cited: a log line, a table row, a runbook step or a rule. */
export interface Ref {
  key: string; // "13_web_server_log.md:L9"
  file: string;
  loc: string;
  raw: string;
  kind: 'log' | 'row' | 'step' | 'rule';
}

export interface Claim {
  label: Label;
  text: string;
  cites: string[]; // ref keys
}

export interface AssetHit {
  tag: string;
  host: string;
  criticality: string;
  how: string;
  cites: string[];
}

export interface Part {
  name: string;
  type: string; // matrix row name
  severity: Sev;
  steps: string[]; // how the severity was worked out
  assets: AssetHit[];
}

export interface Action {
  runbook: string; // "RB-CRED-02"
  step: number;
  text: string; // verbatim runbook step
  applied: string; // what it means here
  cite: string;
}

export interface Inform {
  who: string;
  limit: string;
  how: string;
  deadlineUtc?: string;
  cite: string;
}

export interface ChainNode {
  label: string;
  time?: string;
  kind: Label | 'harmless';
  cite?: string;
}

export interface Incident {
  id: string;
  title: string;
  status: 'escalate' | 'closed-harmless';
  severity?: Sev;
  parts: Part[];
  accounts: string[];
  firstSeenUtc: string;
  firstSeenBasis: string;
  chain: ChainNode[];
  claims: Claim[];
  actions: Action[];
  inform: Inform[];
  closedBy?: string; // change ID
  closedReason?: string;
  eventIds: string[];
}

export interface Gap {
  what: string;
  window?: string;
  impact: string;
  cite: string;
}

export interface Match {
  entity: string;
  names: { value: string; cite: string }[];
  how: string;
}

export interface Evidence {
  generatedAt: string;
  events: Ev[];
  refs: Record<string, Ref>;
  matches: Match[];
  incidents: Incident[];
  observations: Claim[];
  gaps: Gap[];
  missingSources: { text: string; cite: string }[];
  report: { overall: Sev; summary: string; markdown: string };
  stats: { events: number; sources: number; incidents: number; closed: number };
}
