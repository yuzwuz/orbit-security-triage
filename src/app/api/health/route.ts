import { NextResponse } from 'next/server';
import evidence from '@/generated/evidence.json';
import type { Evidence } from '@/lib/types';
import { llmConfigured } from '@/lib/llm';

export const runtime = 'nodejs';
const ev = evidence as unknown as Evidence;

export async function GET() {
  return NextResponse.json({ ok: true, llmConfigured: llmConfigured(), events: ev.stats.events, incidents: ev.stats.incidents, closed: ev.stats.closed });
}
