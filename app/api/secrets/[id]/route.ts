import { NextRequest } from "next/server";
import { prisma } from "@/lib/db";
import { rateLimit, clientKey } from "@/lib/ratelimit";

export const runtime = "nodejs";

const ID_PATTERN = /^[A-Za-z0-9_-]{16,32}$/;

type BurnRow = {
  ciphertext: string;
  iv: string;
  salt: string | null;
  hasPassword: boolean;
  maxViews: number;
  viewCount: number;
};

export async function GET(
  request: NextRequest,
  ctx: RouteContext<"/api/secrets/[id]">,
) {
  const ip = clientKey(request.headers);
  const rl = await rateLimit(ip, {
    name: "read",
    capacity: 30,
    windowSec: 60,
  });
  if (!rl.allowed) {
    return Response.json(
      { error: "Too many requests" },
      { status: 429, headers: { "Retry-After": String(rl.retryAfterSec) } },
    );
  }

  const { id } = await ctx.params;
  if (!ID_PATTERN.test(id)) {
    return Response.json({ error: "Not found" }, { status: 404 });
  }

  // Atomic burn-after-read.
  //
  // A single `UPDATE ... WHERE viewCount < maxViews ... RETURNING` lets
  // Postgres serialize concurrent reads on the row lock: only one transaction
  // can decrement at a time, and the predicate re-evaluates after each lock
  // release. The previous implementation used findUnique-then-update inside
  // a $transaction, which under READ COMMITTED let two simultaneous reads
  // both observe viewCount=0 and both return ciphertext.
  //
  // Note: $queryRaw escapes parameters automatically (parameterized query),
  // so the `id` interpolation is safe against SQL injection.
  const rows = await prisma.$queryRaw<BurnRow[]>`
    UPDATE "Secret"
    SET "viewCount" = "viewCount" + 1
    WHERE id = ${id}
      AND "expiresAt" > NOW()
      AND "viewCount" < "maxViews"
    RETURNING ciphertext, iv, salt, "hasPassword", "maxViews", "viewCount"
  `;

  const secret = rows[0];
  if (!secret) {
    // Same 404 for "expired", "consumed", "never existed" to avoid an oracle.
    // Expired rows are reaped by the daily /api/sweep cron; consumed rows are
    // deleted on the success path below. No cleanup needed here.
    return Response.json(
      { error: "Secret is gone or never existed" },
      { status: 404, headers: { "Cache-Control": "no-store" } },
    );
  }

  // Final view consumed → delete the row. We can't combine this with the
  // UPDATE in standard Prisma because the row needs to exist long enough to
  // RETURN. The DELETE running after we've already captured the ciphertext
  // is fine: any concurrent UPDATE on this id has already failed because the
  // viewCount predicate is now false.
  if (secret.viewCount >= secret.maxViews) {
    await prisma.secret.delete({ where: { id } }).catch(() => {});
  }

  return Response.json(
    {
      ciphertext: secret.ciphertext,
      iv: secret.iv,
      salt: secret.salt,
      hasPassword: secret.hasPassword,
      viewsRemaining: secret.maxViews - secret.viewCount,
    },
    { headers: { "Cache-Control": "no-store" } },
  );
}
