// Cron-driven cleanup of expired secrets. Without this, rows whose
// expiresAt is past but which nobody opened would accumulate forever
// (the read endpoint deletes lazily on access only).
//
// Vercel Cron sends `Authorization: Bearer ${CRON_SECRET}` automatically
// when CRON_SECRET is configured. We require that header.

import { timingSafeEqual } from "node:crypto";
import { NextRequest } from "next/server";
import { prisma } from "@/lib/db";

export const runtime = "nodejs";

// Constant-time bearer comparison. With a high-entropy random secret,
// `===` is effectively safe — the timing leak would only narrow guesses on
// a ~256-bit search space, which is hopeless. But the cost is one syscall
// per cron invocation, and the textbook fix removes "I forgot constant-time
// here" from the audit checklist permanently.
function safeBearerEquals(provided: string | null, expected: string): boolean {
  if (!provided) return false;
  const a = Buffer.from(provided);
  const b = Buffer.from(`Bearer ${expected}`);
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

export async function GET(request: NextRequest) {
  const expected = process.env.CRON_SECRET;
  if (!expected) {
    return Response.json({ error: "Unauthorized" }, { status: 401 });
  }
  const auth = request.headers.get("authorization");
  if (!safeBearerEquals(auth, expected)) {
    return Response.json({ error: "Unauthorized" }, { status: 401 });
  }

  const result = await prisma.secret.deleteMany({
    where: { expiresAt: { lt: new Date() } },
  });

  return Response.json(
    { deleted: result.count },
    { headers: { "Cache-Control": "no-store" } },
  );
}
