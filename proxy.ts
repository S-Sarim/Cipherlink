import { NextResponse, type NextRequest } from "next/server";

// Per-request CSP nonce. Generated here, attached to the CSP header, and
// also exposed to React via the `x-nonce` request header so the root layout
// can apply it to inline tags Next emits during SSR. Without this, the only
// safe alternative is `'unsafe-inline'` on script-src — which means a single
// XSS escape would have a free path to executing arbitrary JS.

const isDev = process.env.NODE_ENV === "development";

export function proxy(request: NextRequest) {
  const nonce = Buffer.from(crypto.randomUUID()).toString("base64");

  // `'strict-dynamic'` lets scripts loaded by a nonce'd script also run, which
  // is what Next.js relies on for its bundle splitting. `unsafe-eval` is only
  // needed in dev (React dev tooling). Tailwind injects per-element style
  // blocks; we keep `style-src 'unsafe-inline'` because nonce-only would
  // break Tailwind's runtime utilities. There are no workers and no external
  // fonts, so worker-src and data: in font-src are dropped.
  //
  // hash-wasm (Argon2id) compiles a small WASM module at first use. WASM
  // execution requires `'wasm-unsafe-eval'` under modern CSP rules.
  const csp = [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic' 'wasm-unsafe-eval'${isDev ? " 'unsafe-eval'" : ""}`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self'",
    "connect-src 'self'",
    "frame-ancestors 'none'",
    "form-action 'self'",
    "base-uri 'self'",
    "object-src 'none'",
    "upgrade-insecure-requests",
  ].join("; ");

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);
  requestHeaders.set("Content-Security-Policy", csp);

  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set("Content-Security-Policy", csp);
  // Prevent the browser from caching HTML — especially the reveal page,
  // whose response should never be re-served from disk cache. API responses
  // already set `Cache-Control: no-store` from their handlers.
  response.headers.set("Cache-Control", "no-store");
  return response;
}

export const config = {
  matcher: [
    // Run on HTML routes only. Skip API responses (they don't render scripts),
    // Next's static asset paths, image optimization, and the favicon. Skipping
    // prefetches keeps the cached responses identical across requests.
    {
      source: "/((?!api|_next/static|_next/image|favicon.ico).*)",
      missing: [
        { type: "header", key: "next-router-prefetch" },
        { type: "header", key: "purpose", value: "prefetch" },
      ],
    },
  ],
};
