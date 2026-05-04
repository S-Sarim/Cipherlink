import { NextRequest } from "next/server";
import { prisma } from "@/lib/db";
import { rateLimit, clientKey } from "@/lib/ratelimit";

export const runtime = "nodejs";

const ID_PATTERN = /^[A-Za-z0-9_-]{16,32}$/;

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

  const result = await prisma.$transaction(async (tx) => {
    const secret = await tx.secret.findUnique({ where: { id } });
    if (!secret) return { kind: "missing" as const };

    const now = new Date();
    if (secret.expiresAt <= now) {
      await tx.secret.delete({ where: { id } }).catch(() => {});
      return { kind: "missing" as const };
    }
    if (secret.viewCount >= secret.maxViews) {
      await tx.secret.delete({ where: { id } }).catch(() => {});
      return { kind: "missing" as const };
    }

    const nextCount = secret.viewCount + 1;
    if (nextCount >= secret.maxViews) {
      await tx.secret.delete({ where: { id } });
    } else {
      await tx.secret.update({
        where: { id },
        data: { viewCount: nextCount },
      });
    }

    return {
      kind: "ok" as const,
      payload: {
        ciphertext: secret.ciphertext,
        iv: secret.iv,
        salt: secret.salt,
        hasPassword: secret.hasPassword,
        viewsRemaining: secret.maxViews - nextCount,
      },
    };
  });

  if (result.kind === "missing") {
    return Response.json(
      { error: "Secret is gone or never existed" },
      {
        status: 404,
        headers: {
          "Cache-Control": "no-store",
        },
      },
    );
  }

  return Response.json(result.payload, {
    headers: {
      "Cache-Control": "no-store",
    },
  });
}
