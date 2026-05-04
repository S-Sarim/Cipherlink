import { randomBytes } from "node:crypto";

// 128-bit random ID encoded as base64url (22 chars, no padding).
// Collision-resistant and URL-safe.
export function newSecretId(): string {
  return randomBytes(16).toString("base64url");
}
