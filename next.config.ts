import type { NextConfig } from "next";

// Static security headers that don't depend on the request. The CSP is set
// per-request in `proxy.ts` so each response gets a fresh nonce; setting it
// here would conflict with that.
const securityHeaders = [
  { key: "X-Frame-Options", value: "DENY" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Referrer-Policy", value: "no-referrer" },
  {
    key: "Permissions-Policy",
    value: "camera=(), microphone=(), geolocation=(), interest-cohort=()",
  },
  // `preload` qualifies us for the HSTS preload list (hstspreload.org), which
  // hard-codes HTTPS-only into shipped browsers. Two-year max-age + subdomains
  // is the gate.
  {
    key: "Strict-Transport-Security",
    value: "max-age=63072000; includeSubDomains; preload",
  },
  { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
  { key: "Cross-Origin-Resource-Policy", value: "same-origin" },
  // X-Robots-Tag covers JSON / non-HTML responses too, where a <meta robots>
  // tag obviously can't reach. The metadata `robots` config still emits the
  // meta tag for HTML.
  { key: "X-Robots-Tag", value: "noindex, nofollow, noarchive, nosnippet" },
];

const nextConfig: NextConfig = {
  poweredByHeader: false,
  async headers() {
    return [
      {
        source: "/:path*",
        headers: securityHeaders,
      },
    ];
  },
};

export default nextConfig;
