"use client";

import Link from "next/link";
import { use, useEffect, useRef, useState } from "react";
import { decryptSecret } from "@/lib/crypto";

type ServerPayload = {
  ciphertext: string;
  iv: string;
  salt: string | null;
  hasPassword: boolean;
  viewsRemaining: number;
};

type Stage =
  | { kind: "idle" }
  | { kind: "fetching" }
  | { kind: "needs-password"; payload: ServerPayload }
  | { kind: "decrypting" }
  | { kind: "revealed"; plaintext: string; viewsRemaining: number }
  | { kind: "wiped" }
  | { kind: "error"; message: string };

const AUTO_WIPE_SECONDS = 30;

export default function RevealPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = use(params);
  const [stage, setStage] = useState<Stage>({ kind: "idle" });
  const [password, setPassword] = useState("");
  const [revealed, setRevealed] = useState(false);
  const [secondsLeft, setSecondsLeft] = useState(AUTO_WIPE_SECONDS);
  const [copiedToClipboard, setCopiedToClipboard] = useState(false);

  // `null` means "haven't read the URL yet"; "" means "read, but missing".
  // We need this in state so the JSX can react to the post-mount value.
  const [urlKey, setUrlKey] = useState<string | null>(null);

  const initRef = useRef(false);
  const fetchStartedRef = useRef(false);
  const copiedToClipboardRef = useRef(false);

  useEffect(() => {
    // Guard against React 19 / Strict Mode double-invocation in dev.
    if (initRef.current) return;
    initRef.current = true;

    const hash = window.location.hash.replace(/^#/, "");
    if (hash) {
      // Strip the fragment from the address bar so the key doesn't linger
      // in browser history once the page has loaded it.
      window.history.replaceState(
        null,
        "",
        window.location.pathname + window.location.search,
      );
    }
    setUrlKey(hash);
  }, []);

  // Auto-wipe countdown. Once a secret has been revealed in the DOM, it's
  // exposed to anything else running in this browser context — extensions,
  // devtools, screen recorders. We can't fully defend against that, but we
  // can shrink the window of exposure.
  useEffect(() => {
    if (stage.kind !== "revealed") return;
    const interval = setInterval(() => {
      setSecondsLeft((s) => {
        if (s <= 1) {
          clearInterval(interval);
          // Best-effort clipboard wipe. May fail without recent gesture.
          if (copiedToClipboardRef.current) {
            navigator.clipboard.writeText("").catch(() => {});
          }
          setStage({ kind: "wiped" });
          return 0;
        }
        return s - 1;
      });
    }, 1000);
    return () => clearInterval(interval);
  }, [stage.kind]);

  // Mirror the clipboard flag into a ref so the wipe step can read its
  // current value without taking it as an effect dependency.
  useEffect(() => {
    copiedToClipboardRef.current = copiedToClipboard;
  }, [copiedToClipboard]);

  async function startReveal() {
    // The server burns a view on every successful GET. The Reveal button
    // must trigger exactly one network call per page load.
    if (fetchStartedRef.current) return;
    fetchStartedRef.current = true;

    if (!urlKey) {
      setStage({ kind: "error", message: "Decryption key missing from URL" });
      return;
    }
    setStage({ kind: "fetching" });

    let payload: ServerPayload;
    try {
      const res = await fetch(`/api/secrets/${encodeURIComponent(id)}`, {
        method: "GET",
        cache: "no-store",
      });
      if (res.status === 404) {
        setStage({
          kind: "error",
          message:
            "This secret is gone. It may have been viewed already, expired, or never existed.",
        });
        return;
      }
      if (!res.ok) {
        setStage({
          kind: "error",
          message: `Server returned ${res.status}`,
        });
        return;
      }
      payload = (await res.json()) as ServerPayload;
    } catch {
      setStage({ kind: "error", message: "Network error" });
      return;
    }

    if (payload.hasPassword) {
      // Wait for the user to enter the password before decrypting. The
      // ciphertext is already in memory; we do NOT hit the server again.
      setStage({ kind: "needs-password", payload });
      return;
    }

    await decryptAndShow(payload);
  }

  async function decryptAndShow(payload: ServerPayload, pwd?: string) {
    if (!urlKey) {
      setStage({ kind: "error", message: "Decryption key missing from URL" });
      return;
    }
    setStage({ kind: "decrypting" });
    try {
      const plaintext = await decryptSecret({
        ciphertext: payload.ciphertext,
        iv: payload.iv,
        salt: payload.salt,
        urlKey,
        password: pwd,
      });
      setStage({
        kind: "revealed",
        plaintext,
        viewsRemaining: payload.viewsRemaining,
      });
    } catch {
      setStage({
        kind: "error",
        message: payload.hasPassword
          ? "Wrong password — and the secret has now been consumed."
          : "Decryption failed. The link is corrupted or incomplete.",
      });
    }
  }

  async function copyPlaintext(plaintext: string) {
    await navigator.clipboard.writeText(plaintext);
    setCopiedToClipboard(true);
  }

  const isWorking = stage.kind === "fetching" || stage.kind === "decrypting";

  return (
    <main className="flex flex-1 flex-col items-center justify-center px-4 py-12">
      <div className="w-full max-w-xl">
        <header className="mb-8 text-center">
          <h1 className="text-3xl font-semibold tracking-tight">
            CipherLink
          </h1>
          <p className="mt-2 text-sm text-zinc-600 dark:text-zinc-400">
            Someone shared a secret with you.
          </p>
        </header>

        <div className="rounded-2xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 p-6 shadow-sm">
          {stage.kind === "idle" && urlKey === "" && (
            <p className="text-sm text-red-700 dark:text-red-300">
              This URL is missing its decryption key. The link must include the
              part after <code>#</code>.
            </p>
          )}

          {stage.kind === "idle" && !!urlKey && (
            <>
              <p className="text-sm text-zinc-700 dark:text-zinc-300">
                <strong>Heads up.</strong> Opening this secret will permanently
                destroy it after you (or anyone with the link) reads it. The
                decrypted text will auto-erase from this page after{" "}
                {AUTO_WIPE_SECONDS} seconds.
              </p>
              <button
                type="button"
                onClick={startReveal}
                disabled={isWorking}
                className="mt-6 w-full rounded-md bg-indigo-600 hover:bg-indigo-500 disabled:opacity-60 disabled:cursor-not-allowed text-white font-medium px-4 py-2.5 transition-colors"
              >
                Reveal secret
              </button>
            </>
          )}

          {stage.kind === "fetching" && (
            <p className="text-sm text-zinc-700 dark:text-zinc-300">
              Fetching ciphertext…
            </p>
          )}
          {stage.kind === "decrypting" && (
            <p className="text-sm text-zinc-700 dark:text-zinc-300">
              Decrypting in your browser…
            </p>
          )}

          {stage.kind === "needs-password" && (
            <form
              onSubmit={(e) => {
                e.preventDefault();
                decryptAndShow(stage.payload, password);
              }}
            >
              <p className="text-sm text-zinc-700 dark:text-zinc-300">
                This secret is protected with a password. Enter it to decrypt.
              </p>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Password"
                className="mt-4 w-full rounded-md border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-950 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
                autoFocus
                autoComplete="off"
              />
              <button
                type="submit"
                className="mt-4 w-full rounded-md bg-indigo-600 hover:bg-indigo-500 text-white font-medium px-4 py-2.5 transition-colors"
              >
                Decrypt
              </button>
            </form>
          )}

          {stage.kind === "revealed" && (
            <div>
              <div className="flex items-center justify-between gap-4">
                <h2 className="text-sm font-medium text-zinc-700 dark:text-zinc-300">
                  Decrypted secret
                </h2>
                <div className="flex items-center gap-2">
                  {stage.viewsRemaining > 0 ? (
                    <span className="text-xs px-2 py-0.5 rounded-full bg-amber-100 dark:bg-amber-950/40 text-amber-800 dark:text-amber-300">
                      {stage.viewsRemaining} view
                      {stage.viewsRemaining === 1 ? "" : "s"} left
                    </span>
                  ) : (
                    <span className="text-xs px-2 py-0.5 rounded-full bg-red-100 dark:bg-red-950/40 text-red-800 dark:text-red-300">
                      destroyed on server
                    </span>
                  )}
                  <span
                    className={`text-xs px-2 py-0.5 rounded-full font-mono tabular-nums ${
                      secondsLeft <= 5
                        ? "bg-red-100 dark:bg-red-950/40 text-red-800 dark:text-red-300"
                        : "bg-zinc-100 dark:bg-zinc-800 text-zinc-700 dark:text-zinc-300"
                    }`}
                    aria-live="polite"
                  >
                    auto-wipe in {secondsLeft}s
                  </span>
                </div>
              </div>
              <div className="relative mt-3">
                <pre
                  className={`whitespace-pre-wrap break-all rounded-md border border-zinc-300 dark:border-zinc-700 bg-zinc-50 dark:bg-zinc-950 px-3 py-2 text-sm font-mono ${
                    revealed ? "" : "blur-sm select-none"
                  }`}
                >
                  {stage.plaintext}
                </pre>
                {!revealed && (
                  <button
                    type="button"
                    onClick={() => setRevealed(true)}
                    className="absolute inset-0 m-auto h-10 w-32 rounded-md bg-zinc-900/80 dark:bg-zinc-100/80 text-white dark:text-zinc-900 text-sm font-medium"
                  >
                    Click to show
                  </button>
                )}
              </div>
              <div className="mt-4 flex gap-2">
                <button
                  type="button"
                  onClick={() => copyPlaintext(stage.plaintext)}
                  className="rounded-md border border-zinc-300 dark:border-zinc-700 hover:bg-zinc-50 dark:hover:bg-zinc-800 text-sm font-medium px-3 py-1.5"
                >
                  {copiedToClipboard ? "Copied" : "Copy"}
                </button>
                <Link
                  href="/"
                  className="rounded-md border border-zinc-300 dark:border-zinc-700 hover:bg-zinc-50 dark:hover:bg-zinc-800 text-sm font-medium px-3 py-1.5"
                >
                  Send your own
                </Link>
              </div>
              <p className="mt-4 text-xs text-zinc-500 dark:text-zinc-400 leading-relaxed">
                Save the secret in your password manager now. After the wipe,
                refreshing this page will <strong>not</strong> bring it back —
                the server has already destroyed its copy. Your clipboard will
                also be cleared (browser permitting).
              </p>
            </div>
          )}

          {stage.kind === "wiped" && (
            <div>
              <h2 className="text-sm font-medium text-zinc-700 dark:text-zinc-300">
                Plaintext wiped
              </h2>
              <p className="mt-2 text-sm text-zinc-700 dark:text-zinc-300">
                The decrypted secret has been erased from this page after{" "}
                {AUTO_WIPE_SECONDS} seconds. The server&rsquo;s copy was already
                destroyed when you revealed it. There is nothing left to
                recover here.
              </p>
              <Link
                href="/"
                className="mt-4 inline-block rounded-md border border-zinc-300 dark:border-zinc-700 hover:bg-zinc-50 dark:hover:bg-zinc-800 text-sm font-medium px-3 py-1.5"
              >
                Send your own
              </Link>
            </div>
          )}

          {stage.kind === "error" && (
            <div>
              <p className="text-sm text-red-700 dark:text-red-300">
                {stage.message}
              </p>
              <Link
                href="/"
                className="mt-4 inline-block rounded-md border border-zinc-300 dark:border-zinc-700 hover:bg-zinc-50 dark:hover:bg-zinc-800 text-sm font-medium px-3 py-1.5"
              >
                Send your own
              </Link>
            </div>
          )}
        </div>
      </div>
    </main>
  );
}
