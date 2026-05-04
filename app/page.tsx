"use client";

import { useState } from "react";
import { encryptSecret } from "@/lib/crypto";

const EXPIRY_OPTIONS = [
  { label: "5 minutes", value: 5 * 60 },
  { label: "1 hour", value: 60 * 60 },
  { label: "1 day", value: 24 * 60 * 60 },
  { label: "1 week", value: 7 * 24 * 60 * 60 },
];

const VIEW_OPTIONS = [1, 2, 5, 10];

export default function Home() {
  const [secret, setSecret] = useState("");
  const [password, setPassword] = useState("");
  const [expiresInSec, setExpiresInSec] = useState(60 * 60);
  const [maxViews, setMaxViews] = useState(1);
  const [submitting, setSubmitting] = useState(false);
  const [link, setLink] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLink(null);
    if (secret.trim().length === 0) {
      setError("Secret cannot be empty");
      return;
    }
    setSubmitting(true);
    try {
      const usePassword = password.length > 0;
      const enc = await encryptSecret(
        secret,
        usePassword ? password : undefined,
      );
      const res = await fetch("/api/secrets", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ciphertext: enc.ciphertext,
          iv: enc.iv,
          salt: enc.salt,
          hasPassword: usePassword,
          expiresInSec,
          maxViews,
        }),
      });
      if (!res.ok) {
        const j = await res.json().catch(() => ({}));
        throw new Error(j.error ?? `Server returned ${res.status}`);
      }
      const { id } = (await res.json()) as { id: string };
      const url = `${window.location.origin}/s/${id}#${enc.urlKey}`;
      setLink(url);
      setSecret("");
      setPassword("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Something went wrong");
    } finally {
      setSubmitting(false);
    }
  }

  async function copyLink() {
    if (!link) return;
    await navigator.clipboard.writeText(link);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  function reset() {
    setLink(null);
    setError(null);
    setCopied(false);
  }

  const passwordSet = password.length > 0;

  return (
    <main className="flex flex-1 flex-col items-center justify-center px-4 py-12">
      <div className="w-full max-w-xl">
        <header className="mb-8 text-center">
          <h1 className="text-3xl font-semibold tracking-tight">CipherLink</h1>
          <p className="mt-2 text-sm text-zinc-600 dark:text-zinc-400">
            One-time, end-to-end encrypted links. The server never sees your
            secret.
          </p>
        </header>

        {!link ? (
          <form
            onSubmit={handleSubmit}
            className="rounded-2xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 p-6 shadow-sm"
          >
            <label className="block">
              <span className="text-sm font-medium">Secret</span>
              <textarea
                value={secret}
                onChange={(e) => setSecret(e.target.value)}
                rows={5}
                placeholder="Paste a password, API key, or note…"
                className="mt-1 w-full resize-y rounded-md border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-950 px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-indigo-500"
                required
                maxLength={20_000}
                autoFocus
              />
            </label>

            <div
              className={`mt-5 rounded-lg border p-4 transition-colors ${
                passwordSet
                  ? "border-emerald-300 dark:border-emerald-800 bg-emerald-50/60 dark:bg-emerald-950/30"
                  : "border-amber-300 dark:border-amber-800 bg-amber-50/60 dark:bg-amber-950/30"
              }`}
            >
              <div className="flex items-center justify-between gap-3">
                <span className="text-sm font-medium">Password</span>
                <span
                  className={`text-[10px] uppercase tracking-wide font-semibold px-2 py-0.5 rounded-full ${
                    passwordSet
                      ? "bg-emerald-200/70 dark:bg-emerald-900/60 text-emerald-900 dark:text-emerald-200"
                      : "bg-amber-200/70 dark:bg-amber-900/60 text-amber-900 dark:text-amber-200"
                  }`}
                >
                  {passwordSet ? "Protected" : "Recommended"}
                </span>
              </div>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Add a password the recipient already knows"
                className="mt-3 w-full rounded-md border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-950 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
                autoComplete="new-password"
                maxLength={256}
              />
              <p className="mt-3 text-xs text-zinc-700 dark:text-zinc-300 leading-relaxed">
                Share the password through a <strong>different channel</strong>{" "}
                than the link — voice call, in person, a separate Signal
                message. Even if someone leaks the URL into a public Slack
                channel, the secret stays safe without the password.
              </p>
            </div>

            <div className="mt-5 grid grid-cols-2 gap-4">
              <label className="block">
                <span className="text-sm font-medium">Expires in</span>
                <select
                  value={expiresInSec}
                  onChange={(e) => setExpiresInSec(Number(e.target.value))}
                  className="mt-1 w-full rounded-md border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-950 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
                >
                  {EXPIRY_OPTIONS.map((o) => (
                    <option key={o.value} value={o.value}>
                      {o.label}
                    </option>
                  ))}
                </select>
              </label>

              <label className="block">
                <span className="text-sm font-medium">Max views</span>
                <select
                  value={maxViews}
                  onChange={(e) => setMaxViews(Number(e.target.value))}
                  className="mt-1 w-full rounded-md border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-950 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
                >
                  {VIEW_OPTIONS.map((v) => (
                    <option key={v} value={v}>
                      {v}
                    </option>
                  ))}
                </select>
              </label>
            </div>

            {error ? (
              <p className="mt-4 rounded-md bg-red-50 dark:bg-red-950/40 text-red-700 dark:text-red-300 text-sm px-3 py-2">
                {error}
              </p>
            ) : null}

            <button
              type="submit"
              disabled={submitting}
              className="mt-6 w-full rounded-md bg-indigo-600 hover:bg-indigo-500 disabled:opacity-60 disabled:cursor-not-allowed text-white font-medium px-4 py-2.5 transition-colors"
            >
              {submitting ? "Encrypting…" : "Generate link"}
            </button>

            <p className="mt-4 text-xs text-zinc-500 dark:text-zinc-400 leading-relaxed">
              Encryption (AES-GCM-256) happens in your browser. The decryption
              key lives in the URL fragment after <code>#</code> and is never
              sent to the server. The recipient&rsquo;s page auto-wipes the
              decrypted plaintext 30 seconds after reveal.
            </p>
          </form>
        ) : (
          <div className="rounded-2xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 p-6 shadow-sm">
            <h2 className="text-lg font-semibold">Your link is ready</h2>
            <p className="mt-1 text-sm text-zinc-600 dark:text-zinc-400">
              Share it with the recipient. It will self-destruct after being
              opened or once it expires — whichever comes first.
            </p>
            <div className="mt-4 flex items-stretch gap-2">
              <input
                readOnly
                value={link}
                onFocus={(e) => e.currentTarget.select()}
                className="flex-1 rounded-md border border-zinc-300 dark:border-zinc-700 bg-zinc-50 dark:bg-zinc-950 px-3 py-2 text-xs font-mono"
              />
              <button
                type="button"
                onClick={copyLink}
                className="rounded-md bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-medium px-4"
              >
                {copied ? "Copied" : "Copy"}
              </button>
            </div>
            <button
              type="button"
              onClick={reset}
              className="mt-6 text-sm text-indigo-600 dark:text-indigo-400 hover:underline"
            >
              Create another secret
            </button>
          </div>
        )}

        <footer className="mt-8 text-center text-xs text-zinc-500 dark:text-zinc-400">
          <a
            href="https://github.com/S-Sarim/Cipherlink"
            className="hover:underline"
            target="_blank"
            rel="noopener noreferrer"
          >
            Open source
          </a>
          {" · "}
          Built with Next.js, Prisma, WebCrypto.
        </footer>
      </div>
    </main>
  );
}
