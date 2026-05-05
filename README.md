# CipherLink

A zero-knowledge, one-time secret sharing app. Generate a self-destructing
link for a password, API key, or short note — the server never sees the
plaintext.

## Why

Every team accidentally pastes credentials into Slack, email, or Notion,
where they sit forever in message history, search indexes, and backups.
CipherLink gives you a link you can paste instead. The recipient opens it
once; after that, the server has nothing to leak.

## How it works (zero-knowledge in 5 steps)

1. You type a secret in the browser.
2. The browser generates a random 256-bit AES-GCM key.
3. The browser encrypts the secret locally and POSTs only the ciphertext +
   IV to the server.
4. The server returns an opaque ID. The browser builds the share URL as
   `https://host/s/<id>#<key>`. The part after `#` is the URL fragment,
   which **browsers never send to the server**.
5. The recipient opens the URL. Their browser fetches the ciphertext,
   reads the key from the fragment, and decrypts locally. The server
   atomically marks the secret as consumed and deletes it.

The server's database only ever stores ciphertext, an IV, and (for
password-protected secrets) a salt. Even a full database dump is useless
without the URL fragments.

## Threat model

### What CipherLink protects against

- **Server compromise / data breach.** The DB only contains AES-GCM
  ciphertext keyed by random material the server never sees.
- **Network eavesdropping (when served over HTTPS).** TLS handles transit
  and the URL fragment is never on the wire.
- **Logs and analytics leakage.** The fragment is stripped from `document.URL`
  immediately after the page loads (`history.replaceState`), so it doesn't
  end up in browser history, referer headers, or downstream analytics.
- **Replay / re-reading.** Each fetch atomically increments a view counter
  inside a SQL transaction; once the cap is reached, the row is deleted.
- **Brute-force enumeration.** Secret IDs are 128-bit random base64url
  strings. Read endpoints are rate-limited (token bucket, 30 req/min/IP)
  and return identical 404s for "expired", "consumed", and "never existed"
  to avoid oracle behavior.
- **Password-only links.** When a password is set, the encryption key is
  `urlKey XOR Argon2id(password, salt, m=19456 KiB, t=2, p=1)` — neither
  factor alone is sufficient. Argon2id is memory-hard, so GPU/ASIC
  brute-force costs ~100× more per guess than the equivalent PBKDF2 work.
  Note: once an attacker holds the ciphertext (which happens when they
  fetch the URL and burn the view), password attempts are **offline** —
  there is no server-side rate limit. The defense is password entropy ×
  KDF cost, which is why the create form refuses passwords under 12
  characters and obvious weak patterns.
- **Clickjacking.** `X-Frame-Options: DENY` and `frame-ancestors 'none'`.
- **Stored XSS via secret content.** Plaintext is rendered into a
  `<pre>` with React's default escaping; CSP forbids inline event
  handlers.
- **Plaintext lingering in the recipient's tab.** The reveal page wipes
  the decrypted secret from React state 30 seconds after reveal, the
  moment the tab loses focus, and best-effort clears the clipboard if the
  recipient used the Copy button. This shrinks (but does not eliminate)
  the window during which a malicious extension could exfiltrate.
- **Sender-side leakage.** The UI prominently recommends a password and
  explains that the password should be sent through a different channel
  than the link. A leaked URL alone is useless without it.

### What CipherLink does *not* protect against

- A fully compromised endpoint device. The 30-second wipe shrinks the
  exposure window, but a browser extension that snapshots the DOM the
  moment the recipient clicks "Reveal" can still capture the plaintext.
  E2E encryption fundamentally ends at the endpoint.
- A malicious sender who *also* leaks the password through the same
  channel as the link. The password mitigation only helps if the two
  factors are sent separately.
- Identity. CipherLink ensures a *single* read; it does not authenticate
  *which* reader. For identity-bound access, layer email magic links on
  top (see `Hardening for production`).
- **Denial-of-reveal griefing.** Anyone who has the URL can burn the view
  even without the password — the server consumes a view as soon as the
  ciphertext is fetched, before the recipient's browser has a chance to
  prove it can decrypt. With password protection, an attacker holding only
  the URL cannot read the secret, but they can race the legitimate
  recipient and destroy it. This is intrinsic to a server that doesn't
  see the key: the server cannot tell a successful decryption from a
  failed one without becoming a decryption oracle.
- Traffic analysis, timing attacks, side channels.

## Security features at a glance

| Layer            | Mechanism                                                                 |
| ---------------- | ------------------------------------------------------------------------- |
| Encryption       | AES-GCM-256, key & IV generated by `crypto.getRandomValues`               |
| Key transport    | URL fragment (never sent to server)                                       |
| Password gate    | Argon2id (m=19 MiB, t=2, p=1, 16-byte salt) XOR'd with URL key            |
| Password floor   | Min 12 chars, blocklist of common passwords, repeating/sequential rejected |
| Atomicity        | `prisma.$transaction` — view-and-delete is one DB transaction             |
| Identifier space | 128-bit random base64url IDs                                              |
| Input validation | Zod schemas; ciphertext capped at 64 KiB; base64url regex                 |
| Rate limiting    | In-memory token bucket on create (10 burst / 0.2 rps) and read (30 / 1 rps) |
| Headers          | CSP, HSTS, COOP, CORP, Referrer-Policy: no-referrer, X-Frame-Options: DENY |
| Cache            | API responses set `Cache-Control: no-store`                               |
| Indexing         | `<meta robots="noindex,nofollow">`                                        |
| Auto-wipe        | Reveal page erases plaintext from state after 30s + best-effort clipboard clear |

## Stack

- **Next.js 16** (App Router, React 19, Turbopack)
- **Prisma 6** + SQLite (swap to Postgres by changing `provider` in
  `prisma/schema.prisma` and the `DATABASE_URL`)
- **WebCrypto** (no external crypto library — uses what the browser ships)
- **Zod** for input validation
- **Tailwind CSS 4** for styling

## Running locally

You need a Postgres database for local development. The simplest paths:

- A local Postgres (`brew install postgresql@16 && createdb cipherlink_dev`), or
- A free Neon project — same one you'll use for production.

```bash
cp .env.example .env
# Edit .env: set DATABASE_URL and DIRECT_URL to your local or Neon Postgres.
# Upstash + APP_ORIGIN + CRON_SECRET can be left blank for local dev.

npm install
npx prisma migrate dev --name init   # generates the migration + applies it
npm run dev                          # http://localhost:3000
```

Without Upstash credentials, rate limiting falls back to an in-process
token bucket — fine for local dev, useless on serverless.

## Project layout

```
app/
  page.tsx                  Create form (client component)
  s/[id]/page.tsx           Reveal page (client component)
  api/secrets/route.ts      POST — create
  api/secrets/[id]/route.ts GET  — atomic burn-after-read
  api/sweep/route.ts        GET  — cron-driven cleanup of expired rows
lib/
  crypto.ts                 Browser AES-GCM + PBKDF2
  db.ts                     Prisma client singleton
  idgen.ts                  128-bit random IDs
  ratelimit.ts              Upstash Redis sliding window (in-memory fallback)
  schemas.ts                Zod input schemas
prisma/
  schema.prisma             Secret model (Postgres)
next.config.ts              Security headers (CSP, HSTS, etc.)
vercel.json                 Daily cron config for /api/sweep
```

## Deploying for free (Vercel + Neon + Upstash)

All three services have free tiers that cover a portfolio demo at $0/month
with no credit card.

**1. Provision Postgres on Neon.** Sign up at neon.tech, create a project.
From the connection-strings panel, copy:

- the **pooled** connection string → goes into `DATABASE_URL`
- the **direct** connection string → goes into `DIRECT_URL`

**2. Provision Redis on Upstash.** Sign up at upstash.com, create a Redis
database (regional, closest to your Vercel region). From the "REST API"
section copy `UPSTASH_REDIS_REST_URL` and `UPSTASH_REDIS_REST_TOKEN`.

**3. Generate the Postgres migration locally.**

```bash
cp .env.example .env
# Paste your Neon DIRECT_URL into both DATABASE_URL and DIRECT_URL for now.
npx prisma migrate dev --name init
git add prisma/migrations && git commit -m "add postgres init migration"
git push
```

Vercel needs the migration files committed because production builds run
`prisma migrate deploy`, which only applies committed migrations and never
generates new ones.

**4. Generate `CRON_SECRET`.**

```bash
openssl rand -base64 32
```

Save the output — you'll paste it into Vercel.

**5. Deploy on Vercel.** Sign up at vercel.com, "Add New Project", import
the GitHub repo. In the deploy configuration, add environment variables:

| Name | Value |
| --- | --- |
| `DATABASE_URL` | Neon pooled connection string |
| `DIRECT_URL` | Neon direct connection string |
| `UPSTASH_REDIS_REST_URL` | from Upstash |
| `UPSTASH_REDIS_REST_TOKEN` | from Upstash |
| `APP_ORIGIN` | the deployed URL, e.g. `https://cipherlink.vercel.app` |
| `CRON_SECRET` | the random string from step 4 |

Click Deploy. The build runs `prisma migrate deploy` (applies the migration
to Neon) and then `next build`. First request can be ~500 ms slower than
subsequent ones — that's Neon's autosuspend warming up.

**6. Update `APP_ORIGIN` after first deploy** if Vercel assigned a different
URL than you guessed (e.g. `cipherlink-username.vercel.app`). Then redeploy.

**7. Verify the cron.** Vercel's Cron tab shows the daily `/api/sweep`
invocation; it returns `{ "deleted": <count> }`.

## Hardening still on the roadmap

- **CSP nonce.** Current config allows `'unsafe-inline'` for scripts. A
  production deployment should generate a per-request nonce in
  `middleware.ts`, propagate it to the response header and to Next's
  `<Script>` tags, and drop `'unsafe-inline'`.
- **CAPTCHA on create.** A Cloudflare Turnstile widget on the create form
  + server-side verification would stop scripted DB-fill attacks.
- **Audit log.** Hash `IP || UA || per-secret-salt` at read time so creators
  can be shown an irreversible access log without violating zero-knowledge.
- **File support.** Encrypt files in the browser, store ciphertext in
  object storage (S3 / R2), keep metadata in Postgres.
- **Tests.** Round-trip unit tests for `lib/crypto.ts`, an integration test
  for atomic burn under concurrency, and a Playwright E2E for create →
  reveal → wipe.
