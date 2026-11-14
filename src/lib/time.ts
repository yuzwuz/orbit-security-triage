const MS_H = 3600 * 1000;
export const PKT_OFFSET = 5 * MS_H;
const MONTHS: Record<string, number> = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };

/** "2026-11-04 03:10:05" written in UTC */
export const utcStr = (s: string) => Date.parse(s.trim().replace(' ', 'T') + 'Z');
/** "2026-11-04 10:55:34" written in PKT (UTC+5) */
export const pktStr = (s: string) => Date.parse(s.trim().replace(' ', 'T') + '+05:00');
/** "2026-11-04 08:20:11 +05:00" */
export const offStr = (s: string) => Date.parse(s.trim().replace(' ', 'T').replace(' ', ''));
/** "04/Nov/2026:08:10:21 +0500" */
export function webTime(s: string): number {
  const m = s.match(/^(\d{2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})$/);
  if (!m) return NaN;
  const [, d, mon, y, hh, mm, ss, sign, oh, om] = m;
  const local = Date.UTC(+y, MONTHS[mon], +d, +hh, +mm, +ss);
  const off = (sign === '+' ? 1 : -1) * (+oh * 60 + +om) * 60000;
  return local - off;
}

const p2 = (n: number) => String(n).padStart(2, '0');
export const iso = (ms: number) => new Date(ms).toISOString().replace('.000Z', 'Z');
export const fmtUtc = (ms: number) => iso(ms).replace('T', ' ').replace('Z', ' UTC');
export function fmtPkt(ms: number) {
  const d = new Date(ms + PKT_OFFSET);
  return `${p2(d.getUTCHours())}:${p2(d.getUTCMinutes())}:${p2(d.getUTCSeconds())} PKT`;
}
/** "2026-11-04 03:10:05 UTC [08:10:05 PKT]" as the security rules ask (UTC first, PKT in brackets) */
export const both = (ms: number) => `${fmtUtc(ms)} [${fmtPkt(ms)}]`;
export const hhmmss = (ms: number) => iso(ms).slice(11, 19) + 'Z';
