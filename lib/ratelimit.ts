// In-memory token bucket rate limiter. Sufficient for a single-process
// localhost demo. For multi-instance production, swap to Redis/Upstash.

type Bucket = { tokens: number; updatedAt: number };

const buckets = new Map<string, Bucket>();

const SWEEP_INTERVAL_MS = 60_000;
let lastSweep = 0;

function sweep(now: number, idleMs: number) {
  if (now - lastSweep < SWEEP_INTERVAL_MS) return;
  lastSweep = now;
  for (const [k, v] of buckets) {
    if (now - v.updatedAt > idleMs) buckets.delete(k);
  }
}

export type RateLimitOptions = {
  capacity: number;
  refillPerSec: number;
};

export function rateLimit(
  key: string,
  opts: RateLimitOptions,
): { allowed: boolean; retryAfterSec: number } {
  const now = Date.now();
  sweep(now, Math.max(60_000, (opts.capacity / opts.refillPerSec) * 1000 * 4));

  const b = buckets.get(key) ?? { tokens: opts.capacity, updatedAt: now };
  const elapsed = (now - b.updatedAt) / 1000;
  b.tokens = Math.min(opts.capacity, b.tokens + elapsed * opts.refillPerSec);
  b.updatedAt = now;

  if (b.tokens >= 1) {
    b.tokens -= 1;
    buckets.set(key, b);
    return { allowed: true, retryAfterSec: 0 };
  }

  buckets.set(key, b);
  const needed = 1 - b.tokens;
  return {
    allowed: false,
    retryAfterSec: Math.ceil(needed / opts.refillPerSec),
  };
}

export function clientKey(headers: Headers): string {
  const fwd = headers.get("x-forwarded-for");
  if (fwd) return fwd.split(",")[0].trim();
  return headers.get("x-real-ip") ?? "local";
}
