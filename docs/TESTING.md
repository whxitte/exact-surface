# Testing ExactSurface end to end

From zero to a full run: sign up, add a target you control, watch the pipeline go
discover → probe → scan → find an exposure, get an alert, and download a report.

Everything here works on Linux, macOS (Intel or Apple silicon) and Windows via WSL2.
The images build natively on both amd64 and arm64 — the feroxbuster download is
architecture-aware — so nothing below is arch-specific.

---

## Part 1 — Two ways to run the app

> **For a real end-to-end test use Option B.** One command brings up the whole stack,
> including the workers that run the recon tools and the scheduler that drives
> continuous scanning. Option A is a fast UI/API smoke test against seeded data and
> **runs no scans at all** — no workers, no tool image.

### Option A — Smoke test (UI + API only, no scanning)

Fastest way to click through the product. Only the datastores run in Docker; the API
and frontend run natively.

```bash
git clone https://github.com/whxitte/exact-surface.git && cd exact-surface

# 1. datastores only
docker compose -f docker/docker-compose.yml up -d mongo redis

# 2. runtime dependencies (the test venv does not have them)
python3 -m venv .venv; .venv/bin/pip install -e .

# 3. configuration — the defaults are fine for local dev
cp .env.example .env

# 4. the API (leave this terminal open)
make api                        # → http://localhost:8000, docs at /docs

# 5. seed a demo tenant with sample findings (new terminal)
make seed                       # login: demo@exactsurface.com / demo-password-123

# 6. the frontend (new terminal)
cd frontend && npm install && npm run dev   # → http://localhost:3000
```

Open http://localhost:3000 and sign in. You get the seeded program, a critical `.env`
finding, a masked secret, downloadable HackerOne/Executive/HTML/PDF reports, and the
notification settings. No scanning happens on this path.

### Option B — The full stack

One command builds and starts everything: frontend, api, worker(s), scheduler,
pipeline, mongo, redis.

```bash
cp .env.example .env
docker compose -f docker/docker-compose.yml up --build
```

- Frontend → http://localhost:3000 · API → http://localhost:8000 (docs at `/docs`)
- The **scheduler** enqueues jobs on cadence; **workers** execute the real scans.
- Seed demo data into the running stack:
  `docker compose -f docker/docker-compose.yml exec api python -m scripts.seed_dev`
- Watch it work:
  `docker compose -f docker/docker-compose.yml logs -f worker scheduler`

> The first build compiles the Go recon tools and pre-fetches nuclei templates — expect
> **5–15 minutes** and a few GB. Later starts are fast.

---

## Part 2 — Scanning something, safely

This is the part that matters. ExactSurface scans only what you **verify and
authorize**, and its scope engine **hard-denies private IPs by default**. To exercise
the real pipeline you need a target you legally control. Three options, easiest first.

### Option 1 — A local lab VM

The most complete test, and the only one that needs no public infrastructure. Any
second machine or VM on your network works — a container on the same host does not,
because the scope engine will not resolve it.

1. **On the lab machine**, serve something worth finding:
   ```bash
   # OWASP Juice Shop is the quickest
   docker run -d -p 3000:3000 bkimminich/juice-shop
   # …or expose a fake secret for the secrets module to catch
   mkdir -p /var/www/html && echo "AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE" > /var/www/html/.env
   python3 -m http.server 8080 --directory /var/www/html
   ```
2. **Get its IP** (`ip a` on the lab machine) — say `192.168.64.5`.
3. **Enable lab mode** on the host running ExactSurface: set
   `EXACTSURFACE_LAB_ALLOW_PRIVATE=true` in `.env` and restart the stack. This is a
   development switch and must never be set on an internet-facing instance.
4. **Give it a hostname.** ExactSurface verifies *domains*, so add to the ExactSurface
   host's `/etc/hosts`:
   ```
   192.168.64.5   lab.local www.lab.local
   ```
5. **Seed it as already verified and authorized.** Public DNS cannot verify a made-up
   name, so create the program with the authorization record already in place:
   ```bash
   docker compose -f docker/docker-compose.yml exec api python -m scripts.seed_dev
   ```
   then follow the DNS-verification bypass recipe in [`FAQ.md`](FAQ.md#skipping-dns-verification-on-a-local-instance),
   substituting `lab.local` for the domain.
6. **Trigger a scan** from the program page and watch findings arrive.

> Lab mode relaxes **RFC1918 private ranges only**. Loopback, the cloud metadata
> address (169.254.169.254), CGNAT and multicast stay denied — a property
> `tests/unit/test_scope.py` proves rather than assumes.

### Option 2 — A public host you own

A domain plus any small VPS. Point the domain at it, add it as a program, complete
**DNS-TXT verification** with the `_exactsurface` record it gives you, authorize, and
scan. This is the only option that exercises the real verification flow. Leave
`EXACTSURFACE_LAB_ALLOW_PRIVATE=false`.

### Option 3 — Sanctioned targets

- Port scanning: `scanme.nmap.org`, which nmap's operators explicitly permit.
- Web: only hosts you own. Do not point ExactSurface at a third party, however
  tempting the test case.

---

## Part 3 — What to check

| Feature | How to test |
|---|---|
| Auth + multi-tenancy | Sign up two organisations; confirm neither can see the other's programs |
| Domain verification | Add a domain you own → DNS-TXT challenge → verify |
| Authorization gate | Try "Run scan" before authorizing → blocked (409) |
| Continuous scanning | Authorize → the scheduler runs ingest→probe→scan on cadence |
| Findings detail | Click a finding → description, reproduction, references |
| Correlation | A host with a secret *and* a finding appears as a chain in reports |
| Notifications | Settings → add a webhook → a new finding pings it, masked |
| Reports | Program page → download HackerOne / Executive / HTML / PDF |
| Secret masking | Confirm alerts and reports show `AKIA••••LE`, never the full key |

---

## Part 4 — Health and troubleshooting

```bash
# pre-flight: tools, config and scope feeds, with no network
docker compose -f docker/docker-compose.yml run --rm pipeline python -m daemon.main --dry-run
# liveness / readiness / metrics
curl localhost:8000/healthz ; curl localhost:8000/readyz ; curl localhost:8000/metrics
# the test suite (fast, needs no services)
.venv/bin/python -m pytest -q
```

| Symptom | Usually |
|---|---|
| API 500s, `/readyz` 503 | Mongo or Redis is not up — `docker compose ps` |
| A scan does nothing | The program is not verified or not authorized; or the target is a private IP and `EXACTSURFACE_LAB_ALLOW_PRIVATE` is false |
| Frontend cannot reach the API | It proxies `/api/*` to `http://localhost:8000`; set `API_PROXY_TARGET` to change |
| Very slow first Docker build | Normal — it is compiling the Go recon tools |

**Ethics.** ExactSurface is detection-only and scans only verified, authorized targets.
Keep it that way: your own lab, your own domains, or explicitly sanctioned hosts.
