import { NextResponse } from 'next/server';
import evidence from '@/generated/evidence.json';
import type { Evidence } from '@/lib/types';
import { answerQuestion } from '@/lib/ask';
import { allow } from '@/lib/ratelimit';

export const runtime = 'nodejs';
export const maxDuration = 30;
const ev = evidence as unknown as Evidence;

export async function POST(req: Request) {
  const ip = req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ?? 'local';
  if (!allow(ip)) return NextResponse.json({ error: 'Too many questions, wait a minute.' }, { status: 429 });
  let body: { question?: unknown; history?: unknown };
  try { body = await req.json(); } catch { return NextResponse.json({ error: 'Send JSON: {"question": "..."}' }, { status: 400 }); }
  const question = typeof body.question === 'string' ? body.question.trim().slice(0, 500) : '';
  if (!question) return NextResponse.json({ error: 'Write a question first.' }, { status: 400 });
  const history = Array.isArray(body.history)
    ? (body.history as { role?: string; content?: string }[]).filter((m) => (m.role === 'user' || m.role === 'assistant') && typeof m.content === 'string').slice(-4).map((m) => ({ role: m.role as 'user' | 'assistant', content: m.content!.slice(0, 600) }))
    : [];
  return NextResponse.json(await answerQuestion(question, history, ev));
}
