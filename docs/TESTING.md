# Testing Vantari on a MacBook (Apple Silicon) + Kali VM

This guide gets you from zero to a full end-to-end test: sign up, add a target you
control, watch the continuous pipeline discover → probe → scan → find an exposure,
get an alert, and download a report.

Your setup: **MacBook M-series (ARM64)** + **Kali Linux in VMware Fusion**. Both
are ARM64 — the images build natively (the feroxbuster download is arch-aware).

---

## Part 1 — Two ways to run the app

> **For true end-to-end testing use Option B** — one command brings up the WHOLE
> stack (frontend, API, workers that run the real recon tools, the continuous
> scheduler, Mongo, Redis). Option A is only a fast UI/API smoke test with seeded
> data and **does not run any real scans** (no workers, no tool image).

### Option A — Quick smoke test (UI + API only, NO real scans)
Fastest way to click through the product with seeded demo data. Runs only the
datastores in Docker; API + frontend run natively on your Mac. No scanning happens.

```bash
cd ~/Projects/vantari

# 1. datastores only
docker compose -f docker/docker-compose.yml up -d mongo redis

# 2. install the runtime deps the live API needs (the test venv doesn't have them)
python3 -m venv .venv 2>/dev/null; .venv/bin/pip install -e . 

# 3. env
cp .env.example .env            # fine as-is for local dev

# 4. run the API (leave this terminal open)
make api                        # → http://localhost:8000  (docs at /docs)

# 5. seed a demo tenant with sample findings (new terminal)
make seed                       # login: demo@vantari.io / demo-password-123

# 6. run the frontend (new terminal)
cd frontend && npm install && npm run dev   # → http://localhost:3000
```

Open **http://localhost:3000**, log in with **demo@vantari.io / demo-password-123**.
You'll immediately see the seeded program, a critical `.env` finding, a masked
secret, and can download HackerOne/Executive/HTML/PDF reports and add notification
channels. No real scanning happens on this path.

### Option B — Full end-to-end (EVERYTHING live) ✅
One command builds and starts all 7 services: **frontend, api, worker(s),
scheduler, pipeline, mongo, redis**. Workers run the real recon tools; the
scheduler drives continuous scanning.

```bash
cd ~/Projects/vantari
cp .env.example .env
docker compose -f docker/docker-compose.yml up --build   # first build is slow
```
- Frontend → http://localhost:3000  ·  API → http://localhost:8000 (docs at /docs)
- The **scheduler** enqueues jobs on cadence; **workers** execute real scans.
- Seed demo data into the running stack (new terminal):
  `docker compose -f docker/docker-compose.yml exec api python -m scripts.seed_dev`
- Watch the workers scan:
  `docker compose -f docker/docker-compose.yml logs -f worker scheduler`

> The first build compiles the Go recon tools and pre-fetches nuclei templates —
> expect **5–15 min** and a few GB. Subsequent starts are fast.
>
> To actually scan a target, add + verify + authorize a program in the UI (see
> Part 2). For a local lab VM set `VANTARI_LAB_ALLOW_PRIVATE=true` in `.env`
> before `up`.

---

## Part 2 — Testing REAL scans safely (the important part)

Vantari only scans what you **verify and authorize**, and its scope engine
**hard-denies private IPs by default**. To test the real pipeline you need a
target you legally control. Three options, easiest first.

### Target option 1 — A vulnerable app in your Kali VM (local lab)
This is the most complete test and uses your Kali VM as the victim.

1. **In Kali**, run a deliberately-vulnerable app:
   ```bash
   # OWASP Juice Shop (quickest)
   sudo docker run -d -p 3000:3000 bkimminich/juice-shop
   # …or DVWA, or just expose a fake secret:
   mkdir -p /var/www/html && echo "AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE" > /var/www/html/.env
   python3 -m http.server 8080 --directory /var/www/html
   ```
2. **Find the Kali VM's IP** (from Kali): `ip a` → e.g. `192.168.64.5`.
3. **Enable lab mode** on the Mac (dev-only; lets Vantari scan private IPs):
   in `.env` set `VANTARI_LAB_ALLOW_PRIVATE=true` and restart the API/stack.
4. **Make a hostname** for it. Vantari verifies *domains*, so add a line to your
   Mac's `/etc/hosts`:
   ```
   192.168.64.5   lab.local www.lab.local
   ```
   (Vantari resolves via DNS-over-HTTPS for *verification*, but scanning uses the
   resolved IP; for a pure-IP lab, use Target option 2's IP note below.)
5. In the UI: **add program** `lab.local`. Because public DNS can't verify a
   made-up domain, seed an already-verified+authorized program for it instead:
   ```bash
   .venv/bin/python -c "import asyncio; from db.mongo import get_mongo; from scripts.seed_dev import seed; \
     m=get_mongo(); asyncio.run((lambda: (m.connect(), seed(m, apex='lab.local')))[1]())" 2>/dev/null \
     || make seed   # simplest: seed then edit the program's apex in the UI is not exposed, so:
   ```
   Simpler: run `python -m scripts.seed_dev` after setting `APEX=lab.local` — or
   just trigger a scan via the API once the program is authorized (see below).
6. **Trigger a scan** and watch findings appear (Findings tab / Discord alert).

> Lab mode only relaxes **RFC1918 private** ranges. Loopback, the cloud metadata
> IP (169.254.169.254), CGNAT, and multicast are **still denied** — a safety
> property proven by `tests/unit/test_scope.py`.

### Target option 2 — A public host you own
If you have any domain + a small VPS (DigitalOcean/Hetzner droplet), point the
domain at it, add it as a program in Vantari, complete **DNS-TXT verification**
(add the `_vantari` TXT record it gives you), authorize, and scan. This exercises
the real verification flow. Keep `VANTARI_LAB_ALLOW_PRIVATE=false`.

### Target option 3 — Sanctioned scan targets (no setup)
- Port scanning: `scanme.nmap.org` (nmap explicitly permits scanning it).
- Web: only scan sites you own — do **not** point Vantari at third-party sites.

---

## Part 3 — What to verify

| Feature | How to test |
|---|---|
| Auth + multi-tenant | Sign up two orgs; confirm one can't see the other's programs |
| Domain verification | Add a domain you own → DNS-TXT challenge → verify |
| Authorization gate | Try "Run scan" before authorizing → blocked (409) |
| Continuous scan | Authorize → scheduler runs ingest→probe→scan on cadence |
| Findings + detail | Click a finding → description, reproduction, references |
| Correlation | An asset with secret + finding shows as a chain in reports |
| Notifications | Settings → add a Discord webhook → new finding pings it (masked) |
| Reports | Program page → download HackerOne / Executive / HTML / PDF |
| Secret masking | Confirm alerts/reports show `AKIA••••LE`, never the full key |

---

## Part 4 — Health & troubleshooting

```bash
# pre-flight: tools + config + scope feeds (no network)
docker compose -f docker/docker-compose.yml run --rm pipeline python -m daemon.main --dry-run
# liveness / readiness / metrics
curl localhost:8000/healthz ; curl localhost:8000/readyz ; curl localhost:8000/metrics
# backend unit tests (fast, no services needed)
.venv/bin/python -m pytest -q
```

Common issues:
- **API 500s / `/readyz` 503**: Mongo or Redis not up. `docker compose ps`.
- **Scan does nothing**: program not verified or not authorized; or target is a
  private IP and `VANTARI_LAB_ALLOW_PRIVATE` is false.
- **Frontend can't reach API**: it proxies `/api/*` → `http://localhost:8000`
  (set `API_PROXY_TARGET` in `frontend/.env` to change).
- **Slow first Docker build**: normal — it compiles the Go recon tools.

Ethics: Vantari is **detection only** and scans only verified, authorized targets.
Keep it that way — scan your own lab, your own domains, or explicitly sanctioned
hosts.
