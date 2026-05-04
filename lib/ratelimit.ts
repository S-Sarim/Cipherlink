// Rate limiting. Backed by Upstash Redis (sliding window) when the env vars
// are present, otherwise falls back to an in-process token bucket so local
// dev works without any Redis setup.
//
// On serverless platforms (Vercel) the in-memory fallback is per-invocation
// and effectively no limit. Production deployments MUST set
// UPSTASH_REDIS_REST_URL + UPSTASH_REDIS_REST_TOKEN.

import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";

export type RateLimitName = "create" | "read";

export type RateLimitOptions = {
  name: RateLimitName;
  capacity: number;
  windowSec: number;
};

type Decision = { allowed: boolean; retryAfterSec: number };

const upstashConfigured = !!(
  process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN
);

if (!upstashConfigured && process.env.NODE_ENV === "production") {
  console.warn(
    "[ratelimit] Upstash env vars missing in production; rate limiting is per-invocation only.",
  );
}

const limiterCache = new Map<string, Ratelimit>();
let redis: Redis | null = null;

function upstashLimiter(opts: RateLimitOptions): Ratelimit {
  const cacheKey = `${opts.name}:${opts.capacity}:${opts.windowSec}`;
  const cached = limiterCache.get(cacheKey);
  if (cached) return cached;
  if (!redis) redis = Redis.fromEnv();
  const limiter = new Ratelimit({
    redis,
    limiter: Ratelimit.slidingWindow(
      opts.capacity,
      `${opts.windowSec} s` as `${number} s`,
    ),
    prefix: `cipherlink:${opts.name}`,
    analytics: false,
  });
  limiterCache.set(cacheKey, limiter);
  return limiter;
}

// In-memory token bucket fallback for local dev.
type Bucket = { tokens: number; updatedAt: number };
const memoryBuckets = new Map<string, Bucket>();

function memoryLimit(key: string, opts: RateLimitOptions): Decision {
  const refillPerSec = opts.capacity / opts.windowSec;
  const now = Date.now();
  const bucket = memoryBuckets.get(key) ?? {
    tokens: opts.capacity,
    updatedAt: now,
  };
  const elapsed = (now - bucket.updatedAt) / 1000;
  bucket.tokens = Math.min(
    opts.capacity,
    bucket.tokens + elapsed * refillPerSec,
  );
  bucket.updatedAt = now;
  if (bucket.tokens >= 1) {
    bucket.tokens -= 1;
    memoryBuckets.set(key, bucket);
    return { allowed: true, retryAfterSec: 0 };
  }
  memoryBuckets.set(key, bucket);
  return {
    allowed: false,
    retryAfterSec: Math.ceil((1 - bucket.tokens) / refillPerSec),
  };
}

export async function rateLimit(
  key: string,
  opts: RateLimitOptions,
): Promise<Decision> {
  const fullKey = `${opts.name}:${key}`;
  if (upstashConfigured) {
    const result = await upstashLimiter(opts).limit(fullKey);
    if (result.success) return { allowed: true, retryAfterSec: 0 };
    return {
      allowed: false,
      retryAfterSec: Math.max(1, Math.ceil((result.reset - Date.now()) / 1000)),
    };
  }
  return memoryLimit(fullKey, opts);
}

export function clientKey(headers: Headers): string {
  const fwd = headers.get("x-forwarded-for");
  if (fwd) return fwd.split(",")[0].trim();
  return headers.get("x-real-ip") ?? "local";
}
