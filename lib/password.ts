// Password strength checking for the create form.
//
// Once an attacker holds the ciphertext (which is true the moment they fetch
// the URL and burn the view), password attempts happen offline against the
// in-browser ciphertext. The ONLY thing standing between them and plaintext
// is password entropy × Argon2id cost. So weak passwords aren't "less safe" —
// they're "broken." We refuse them outright on the create path.

const MIN_LENGTH = 12;

// Tiny embedded list of the most-cracked passwords. We deliberately avoid
// pulling in zxcvbn (~400 KB) because almost all real-world weak passwords
// fall into one of: "too short", "all one character class", "in this list".
const COMMON_WEAK = new Set([
  "password",
  "passw0rd",
  "password1",
  "p@ssword",
  "p@ssw0rd",
  "qwerty",
  "qwertyuiop",
  "letmein",
  "welcome",
  "admin",
  "administrator",
  "iloveyou",
  "monkey",
  "dragon",
  "master",
  "abc123",
  "trustno1",
  "sunshine",
  "princess",
  "football",
  "baseball",
  "ninja",
  "starwars",
  "freedom",
  "whatever",
  "secret",
  "shadow",
  "superman",
  "batman",
]);

function characterClasses(s: string): number {
  let classes = 0;
  if (/[a-z]/.test(s)) classes++;
  if (/[A-Z]/.test(s)) classes++;
  if (/[0-9]/.test(s)) classes++;
  if (/[^A-Za-z0-9]/.test(s)) classes++;
  return classes;
}

function isAllOneClass(s: string): boolean {
  return characterClasses(s) <= 1;
}

function isRepeatingPattern(s: string): boolean {
  // Catches "aaaaaaaaaaaa", "abcabcabcabc", "1212121212", etc.
  for (let len = 1; len <= s.length / 2; len++) {
    const head = s.slice(0, len);
    if (head.repeat(Math.ceil(s.length / len)).slice(0, s.length) === s) {
      return true;
    }
  }
  return false;
}

function isSequential(s: string): boolean {
  // "0123456789012", "abcdefghijklm" — three or more consecutive runs.
  let runs = 0;
  for (let i = 1; i < s.length; i++) {
    if (s.charCodeAt(i) === s.charCodeAt(i - 1) + 1) {
      runs++;
      if (runs >= s.length - 2) return true;
    } else {
      runs = 0;
    }
  }
  return false;
}

export type PasswordVerdict = {
  ok: boolean;
  reason?: string;
  // 0 = unusable, 4 = strong. Used to drive the strength meter.
  score: 0 | 1 | 2 | 3 | 4;
};

export function checkPassword(password: string): PasswordVerdict {
  if (password.length === 0) {
    return { ok: false, score: 0, reason: "Password is empty" };
  }
  if (password.length < MIN_LENGTH) {
    return {
      ok: false,
      score: 1,
      reason: `Use at least ${MIN_LENGTH} characters`,
    };
  }
  const lower = password.toLowerCase();
  if (COMMON_WEAK.has(lower)) {
    return {
      ok: false,
      score: 0,
      reason: "This password is on every cracker's first-guess list",
    };
  }
  if (isRepeatingPattern(password)) {
    return {
      ok: false,
      score: 1,
      reason: "Repeating patterns are easily guessed",
    };
  }
  if (isSequential(password)) {
    return {
      ok: false,
      score: 1,
      reason: "Sequential characters are easily guessed",
    };
  }
  if (isAllOneClass(password)) {
    return {
      ok: false,
      score: 2,
      reason: "Mix in uppercase, numbers, or symbols",
    };
  }

  // Past the floor. Score by length and class diversity.
  const classes = characterClasses(password);
  if (password.length >= 20 && classes >= 3) return { ok: true, score: 4 };
  if (password.length >= 16 && classes >= 2) return { ok: true, score: 3 };
  return { ok: true, score: 2 };
}

// Generate a strong random password using only URL-safe-ish characters that
// survive copy/paste in chat clients (no spaces, no quotes, no backticks).
export function generateStrongPassword(length = 20): string {
  const ALPHABET =
    "ABCDEFGHJKLMNPQRSTUVWXYZ" + // no I/O — confused with 1/0
    "abcdefghijkmnopqrstuvwxyz" + // no l — confused with 1
    "23456789" + // no 0/1
    "!@#$%^&*-_=+";
  const out: string[] = [];
  const buf = new Uint8Array(length);
  crypto.getRandomValues(buf);
  // Rejection sampling to avoid bias from `% ALPHABET.length`.
  const max = 256 - (256 % ALPHABET.length);
  for (let i = 0; i < length; i++) {
    let v = buf[i];
    while (v >= max) {
      const replacement = new Uint8Array(1);
      crypto.getRandomValues(replacement);
      v = replacement[0];
    }
    out.push(ALPHABET[v % ALPHABET.length]);
  }
  return out.join("");
}
