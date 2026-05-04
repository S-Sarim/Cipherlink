// Cron-driven cleanup of expired secrets. Without this, rows whose
// expiresAt is past but which nobody opened would accumulate forever
// (the read endpoint deletes lazily on access only).
//
// Vercel Cron sends `Authorization: Bearer ${CRON_SECRET}` automatically
// when CRON_SECRET is configured. We require that header.

import { NextRequest } from "next/server";
import { prisma } from "@/lib/db";

export const runtime = "nodejs";

export async function GET(request: NextRequest) {
  const auth = request.headers.get("authorization");
  const secret = process.env.CRON_SECRET;
  if (!secret || auth !== `Bearer ${secret}`) {
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
