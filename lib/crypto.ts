// Browser-side WebCrypto helpers for zero-knowledge secret sharing.
// Encryption happens entirely in the user's browser; the server never sees
// plaintext or encryption keys.

import { argon2id } from "hash-wasm";

const KEY_BYTES = 32;
const IV_BYTES = 12;
const SALT_BYTES = 16;

// Argon2id parameters per OWASP's 2026 password storage cheat sheet,
// "second recommended option": m=19456 KiB (~19 MiB), t=2, p=1. This
// is memory-hard, which makes GPU/ASIC brute-force ~100× more expensive
// than PBKDF2-SHA256 at equivalent CPU cost on the user's device.
//
// Why Argon2id instead of PBKDF2: once a recipient (or attacker) holds the
// ciphertext + salt + IV, password attempts happen offline. PBKDF2 is
// embarrassingly parallel on GPUs; Argon2id's memory requirement starves
// each parallel guess of the limited per-core memory bandwidth on commodity
// GPUs, which is the asymmetry we actually need.
const ARGON2_MEMORY_KIB = 19_456;
const ARGON2_ITERATIONS = 2;
const ARGON2_PARALLELISM = 1;

type Bytes = Uint8Array<ArrayBuffer>;

export function toBase64Url(bytes: Bytes): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromBase64Url(s: string): Bytes {
  const pad = s.length % 4 === 0 ? 0 : 4 - (s.length % 4);
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat(pad);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function randomBytes(n: number): Bytes {
  const buf = new Uint8Array(n);
  crypto.getRandomValues(buf);
  return buf;
}

async function importAesKey(raw: Bytes): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, [
    "encrypt",
    "decrypt",
  ]);
}

async function deriveKeyFromPassword(
  password: string,
  salt: Bytes,
): Promise<Bytes> {
  const hash = await argon2id({
    password,
    salt,
    parallelism: ARGON2_PARALLELISM,
    iterations: ARGON2_ITERATIONS,
    memorySize: ARGON2_MEMORY_KIB,
    hashLength: KEY_BYTES,
    outputType: "binary",
  });
  return hash as Uint8Array<ArrayBuffer>;
}

function xor(a: Bytes, b: Bytes): Bytes {
  if (a.length !== b.length) throw new Error("xor length mismatch");
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
}

export type EncryptResult = {
  ciphertext: string; // base64url
  iv: string; // base64url
  salt: string | null; // base64url, only set if password used
  urlKey: string; // base64url, goes in URL fragment
};

export async function encryptSecret(
  plaintext: string,
  password?: string,
): Promise<EncryptResult> {
  const urlKeyRaw = randomBytes(KEY_BYTES);
  const iv = randomBytes(IV_BYTES);

  let finalKeyRaw: Bytes = urlKeyRaw;
  let salt: Bytes | null = null;
  if (password && password.length > 0) {
    salt = randomBytes(SALT_BYTES);
    const pwKey = await deriveKeyFromPassword(password, salt);
    finalKeyRaw = xor(urlKeyRaw, pwKey);
  }

  const key = await importAesKey(finalKeyRaw);
  const ctBuf = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new TextEncoder().encode(plaintext),
  );

  return {
    ciphertext: toBase64Url(new Uint8Array(ctBuf)),
    iv: toBase64Url(iv),
    salt: salt ? toBase64Url(salt) : null,
    urlKey: toBase64Url(urlKeyRaw),
  };
}

export async function decryptSecret(args: {
  ciphertext: string;
  iv: string;
  salt: string | null;
  urlKey: string;
  password?: string;
}): Promise<string> {
  const ct = fromBase64Url(args.ciphertext);
  const iv = fromBase64Url(args.iv);
  const urlKey = fromBase64Url(args.urlKey);

  let finalKeyRaw: Bytes = urlKey;
  if (args.salt) {
    if (!args.password) throw new Error("Password required");
    const salt = fromBase64Url(args.salt);
    const pwKey = await deriveKeyFromPassword(args.password, salt);
    finalKeyRaw = xor(urlKey, pwKey);
  }

  const key = await importAesKey(finalKeyRaw);
  const ptBuf = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    ct,
  );
  return new TextDecoder().decode(ptBuf);
}
