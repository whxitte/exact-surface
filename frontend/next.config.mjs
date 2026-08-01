/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Ship only what the server actually needs at runtime. Without this the image
  // carries Next's entire BUILD toolchain — postcss, tailwind, rimraf and Next's own
  // vendored tar/glob/cross-spawn — none of which runs in production, but all of which
  // Trivy correctly reports as vulnerable dependencies of the shipped artifact.
  output: "standalone",
  images: {
    // We ship exactly one image — the logo, a small static PNG. Next's server-side
    // optimiser buys nothing for that, and it pulls in `sharp`, whose bundled libvips
    // carries four unfixed high-severity CVEs (GHSA-f88m-g3jw-g9cj). Turning
    // optimisation off lets the image build with `--omit=optional`, which removes the
    // dependency entirely.
    //
    // A security product shipping a container with known-vulnerable native code — to
    // resize one logo — is not a trade worth making.
    unoptimized: true,
  },
  // Proxy /api/* to the FastAPI backend so the browser never needs CORS in dev.
  async rewrites() {
    const api = process.env.API_PROXY_TARGET || "http://localhost:8000";
    return [{ source: "/api/:path*", destination: `${api}/:path*` }];
  },
};

export default nextConfig;
