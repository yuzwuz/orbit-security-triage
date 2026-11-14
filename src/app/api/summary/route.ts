import { NextResponse } from 'next/server';
import evidence from '@/generated/evidence.json';
import type { Evidence } from '@/lib/types';
import { polishSummary } from '@/lib/ask';

export const runtime = 'nodejs';
export const maxDuration = 30;
const ev = evidence as unknown as Evidence;
let cached: Awaited<ReturnType<typeof polishSummary>> | undefined;

export async function GET() {
  if (!cached || cached.mode === 'local') cached = await polishSummary(ev); // the data never changes, so a good answer is cached for the life of the server
  return NextResponse.json(cached);
}
