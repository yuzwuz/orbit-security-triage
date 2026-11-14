import fs from 'node:fs';
import path from 'node:path';
import { runPipeline, brokenCites } from '../src/lib/pipeline';

const ev = runPipeline();
const broken = brokenCites(ev);
if (broken.length) {
  console.error('Broken citations (no such log line, row or step):\n' + broken.join('\n'));
  process.exit(1);
}
const out = path.join(process.cwd(), 'src', 'generated', 'evidence.json');
fs.mkdirSync(path.dirname(out), { recursive: true });
fs.writeFileSync(out, JSON.stringify(ev));
console.log(`evidence.json written: ${ev.stats.events} events, ${ev.stats.incidents} incidents, ${ev.stats.closed} closed as harmless, report ${ev.report.overall}`);
