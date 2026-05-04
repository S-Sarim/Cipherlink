import { NextRequest } from "next/server";
import { prisma } from "@/lib/db";
import { CreateSecretSchema } from "@/lib/schemas";
import { newSecretId } from "@/lib/idgen";
import { rateLimit, clientKey } from "@/lib/ratelimit";

export const runtime = "nodejs";

export async function POST(request: NextRequest) {
  const ip = clientKey(request.headers);
  const rl = rateLimit(`create:${ip}`, { capacity: 10, refillPerSec: 0.2 });
  if (!rl.allowed) {
    return Response.json(
      { error: "Too many requests" },
      { status: 429, headers: { "Retry-After": String(rl.retryAfterSec) } },
    );
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return Response.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const parsed = CreateSecretSchema.safeParse(body);
  if (!parsed.success) {
    return Response.json(
      { error: "Invalid input", details: parsed.error.flatten() },
      { status: 400 },
    );
  }

  const { ciphertext, iv, salt, hasPassword, expiresInSec, maxViews } =
    parsed.data;

  if (hasPassword && !salt) {
    return Response.json(
      { error: "salt required when hasPassword is true" },
      { status: 400 },
    );
  }
  if (!hasPassword && salt) {
    return Response.json(
      { error: "salt must be null when hasPassword is false" },
      { status: 400 },
    );
  }

  const id = newSecretId();
  const expiresAt = new Date(Date.now() + expiresInSec * 1000);

  await prisma.secret.create({
    data: {
      id,
      ciphertext,
      iv,
      salt: salt ?? null,
      hasPassword,
      expiresAt,
      maxViews,
    },
  });

  return Response.json({ id, expiresAt: expiresAt.toISOString() });
}
