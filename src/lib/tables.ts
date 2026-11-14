import fs from 'node:fs';
import path from 'node:path';

export const DATA_DIR = path.join(process.cwd(), 'problem_c_data');

export function read(file: string): string {
  return fs.readFileSync(path.join(DATA_DIR, file), 'utf8').replace(/\r\n/g, '\n');
}

/** Lines inside the first code block of the file. Line 1 is the first log line, as the data pack README says. */
export function codeLines(text: string): { n: number; text: string }[] {
  const out: { n: number; text: string }[] = [];
  let inside = false;
  let n = 0;
  for (const l of text.split('\n')) {
    if (l.trim().startsWith('```')) {
      if (inside) break;
      inside = true;
      continue;
    }
    if (inside) out.push({ n: ++n, text: l });
  }
  return out;
}

/** First markdown table in the text, as objects keyed by header. */
export function table(text: string): Record<string, string>[] {
  const lines = text.split('\n');
  const start = lines.findIndex((l) => l.trim().startsWith('|'));
  if (start < 0) return [];
  const cells = (l: string) => l.trim().replace(/^\||\|$/g, '').split('|').map((c) => c.trim());
  const head = cells(lines[start]);
  const rows: Record<string, string>[] = [];
  for (let i = start + 2; i < lines.length && lines[i].trim().startsWith('|'); i++) {
    const c = cells(lines[i]);
    const row: Record<string, string> = {};
    head.forEach((h, j) => (row[h] = c[j] ?? ''));
    rows.push(row);
  }
  return rows;
}

/** key=value or key="quoted value" */
export function kv(s: string): Record<string, string> {
  const o: Record<string, string> = {};
  for (const m of s.matchAll(/(\w+)=("[^"]*"|\S+)/g)) o[m[1]] = m[2].replace(/^"|"$/g, '');
  return o;
}

export const ipRe = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;

export function inCidr(ip: string, cidr: string): boolean {
  const [base, bits] = cidr.split('/');
  const toN = (s: string) => s.split('.').reduce((a, b) => a * 256 + +b, 0);
  const size = 2 ** (32 - +bits);
  return Math.floor(toN(ip) / size) === Math.floor(toN(base) / size);
}
