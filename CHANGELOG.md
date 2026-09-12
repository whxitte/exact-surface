# Changelog

Versions follow [semantic versioning](https://semver.org/). Each release publishes
`api`, `frontend` and `pipeline` images to GHCR, tagged `X.Y.Z` and `latest`, plus a
GitHub Release recording the image digests.

```bash
docker pull ghcr.io/whxitte/api:1.3.2
docker pull ghcr.io/whxitte/frontend:1.3.2
docker pull ghcr.io/whxitte/pipeline:1.3.2
```

## 1.3.2 — 2026-09-12

**Fixed**

- **The published frontend image could not reach the API.** Next.js bakes the `/api/*`
  rewrite destination at build time, and the release runner built without
  `API_PROXY_TARGET`, so every published image from 1.0.0 to 1.3.1 proxied `/api` to
  `http://localhost:8000` — itself — and failed with `ECONNREFUSED`. The dev stack
  never showed it because it builds the other Dockerfile stage. Found by doing a
  clean install from the published images, which is the only way it could have been
  found. Both Dockerfile stages now refuse a bundle pointing at localhost, and a wiring
  test asserts the runner sets the variable.
- `deploy/docker-compose.yml` pins the three pipeline-image services to
  `linux/amd64`, so Apple-silicon and Graviton hosts run them under emulation without
  four platform warnings.
- `deploy/README.md` still referred to a licence token, a licence to breach and "the
  version you were given". Corrected, and it now says how to evaluate on a laptop
  (`DOMAIN=localhost`).

## 1.3.1 — 2026-09-12

**Security**

- **Next.js 15.5.22 → 15.5.25.** Two unauthenticated RCE advisories against 15.5.22
  ([GHSA-p293-qw3h-jr36](https://github.com/advisories/GHSA-p293-qw3h-jr36),
  [GHSA-2xp9-vwfh-vxw4](https://github.com/advisories/GHSA-2xp9-vwfh-vxw4)). Neither
  path is reachable in ExactSurface's configuration — one affects Windows-hosted servers
  and we ship Linux containers, the other is the Image Optimization API which
  `next.config.mjs` disables — but a known unauthenticated RCE on the framework is not
  something to reason around. Upgrade.
- Build-toolchain advisories cleared: `sharp` (optional, never installed in the image),
  `browserslist`, `baseline-browser-mapping`, `js-yaml`. None ship in the runtime image.

**Changed**

- README rebuilt around a banner, screenshots and the conventional section order.
- Dependabot alerts, secret scanning and push protection are enabled on the repository.

## 1.3.0 — 2026-09-07

**Added**

- **Scope override** — a per-program setting, off by default, that waives the scope
  engine for that domain: hosts outside the verified apex, every hard-denied class
  (internal, loopback, CGNAT, multicast, reserved) and third-party CDN edges all become
  fully scannable. Untouched: the program's own exclusion lists, the politeness cap, the
  requirement to be verified and authorized, and link-local `169.254.0.0/16` — the
  metadata address is the worker's own, so no override can reach it. Both edges are logged at WARNING. See `docs/SECURITY.md` §2d for what
  it costs, including the two rows that reach beyond your own estate.
- `SECURITY.md` (vulnerability disclosure, with GitHub private reporting enabled) and
  `CONTRIBUTING.md`.

**Fixed**

- The project site's logo 404'd on GitHub Pages: it used an absolute `/favicon.png`,
  but a project site is served from `/exact-surface/`.
- `make lint` now runs `ruff format --check` as well as `ruff check`, matching CI — the
  README told contributors to run it before a PR, and it could pass while CI failed.

## 1.2.0 — 2026-09-07

**Added**

- **The Playground** (`/playground`) — a drag-and-drop canvas for running modules by
  hand: 36 nodes (28 pipeline modules, 6 utility transforms, a target source, an output
  viewer), typed ports, and validation that refuses cycles and mismatched wires before
  anything runs. It executes through the same dispatch table a scheduled scan uses, so
  the canvas and the scheduler cannot drift apart.
- Playground runs execute on the worker and report per-node progress onto the canvas.

**Fixed**

- **The published frontend image could not start.** `1.0.0` and `1.1.0` both shipped a
  Next.js standalone bundle whose `node_modules` a blanket `.dockerignore` rule had
  stripped, so every container exited with `Cannot find module 'next'`. Both runtime
  stages now assert the bundle is intact at build time, and a wiring test keeps the
  `.dockerignore` negation in place.
- The local dev stack built the wrong Dockerfile stage, so code changes never reached
  the image it ran.

**Changed**

- Licensed under **Apache-2.0**.
- README rewritten for a public audience; the local-testing walkthrough moved to
  `docs/FAQ.md`.
- `deploy/` version pins moved from `1.0.0` to `1.2.0`.

## 1.1.0 — 2026-08-12

**Changed**

- **Became a free, unrestricted self-hosted edition.** Licence keys, the control plane,
  tier gating, the licence-minting scripts and every `402 Payment Required` path were
  removed. No keys, no subscription checks, no domain or scan limits, and no read-only
  degradation.
- Multi-arch release builds reworked to reuse one pre-built frontend bundle across
  architectures.
- Dark-mode palette updated; theme toggle now persists.

**Fixed**

- `nanoid` advisory (CVE-2026-67213).
- A client-side exception on the demo program page.

## 1.0.0 — 2026-08-02

First release. Continuous external attack-surface intelligence, detection only:

- 28 scan modules, from passive domain intelligence through subdomain discovery,
  probing, crawling, content discovery, vulnerability scanning, secrets, CVE/KEV
  matching and risk correlation.
- Scheduler and stateless arq workers with cascade, per-module cadence and a fairness
  cap.
- The central scope engine, DNS-TXT domain verification and the §9b authorisation gate
  with ASN-confirmed IP ranges.
- Fleet-shared politeness limiter, degrading when Redis is unavailable.
- Multi-tenant API with RBAC, a Next.js dashboard, Prometheus/Grafana observability,
  encrypted Mongo backups and a self-contained `deploy/` bundle.
