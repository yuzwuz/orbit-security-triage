// Tiny in-memory limiter so a demo crowd cannot burn the free LLM quota. Per server instance, which is fine for a hackathon.
const hits = new Map<string, number[]>();
export function allow(key: string, max = 15, windowMs = 60_000): boolean {
  const now = Date.now();
  const recent = (hits.get(key) ?? []).filter((t) => now - t < windowMs);
  if (recent.length >= max) { hits.set(key, recent); return false; }
  recent.push(now);
  hits.set(key, recent);
  return true;
}
