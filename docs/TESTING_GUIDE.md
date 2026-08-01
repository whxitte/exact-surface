# ExactSurface — Comprehensive Testing Guide

How to test ExactSurface to full coverage: what to test, in what order, and how to know
it actually works. This is the reference; [`docs/TESTING.md`](TESTING.md) is the
quick "run it on a Mac + Kali VM" walkthrough.

> **The one lesson that shapes this guide.** During development, several controls
> passed a green test suite while being **dead code or broken at the seams** — the
> politeness limiter was never called; backups couldn't run; a scope feed cron
> deleted protections. Treat **"tests pass" as necessary, never sufficient.** The
> real gate is exercising the thing on live infrastructure and *observing the
> behaviour*, not the exit code. Every layer below builds toward that.

---

## The seven layers (run them in order)

| # | Layer | Proves | When |
|---|-------|--------|------|
| 1 | Automated suite | logic is correct in isolation | every commit |
| 2 | Static + preflight | it lints, imports, and can start | every commit |
| 3 | Local end-to-end | the pipeline runs against a real target you own | before a deploy |
| 4 | **Security & safety** | ExactSurface can't be turned against you or a third party | before a deploy, and after any scope/fetch/auth change |
| 5 | Real-infra validation | the parts CI can't exercise actually work | before first prod |
| 6 | Unattended run (exit gate) | it survives days alone with real tenants | before launch |
| 7 | Load & scale | it holds at multi-tenant volume | before selling multi-tenant |

---

## Layer 1 — Automated suite

```bash
.venv/bin/python -m pytest            # full suite (~25s, no services needed)
.venv/bin/python -m pytest tests/security   # security-specific
.venv/bin/ruff check . && .venv/bin/ruff format --check .
cd frontend && npx tsc --noEmit && npx next lint   # frontend types + lint
```

What the three suites cover:

- **`tests/unit/`** — pure logic with injected runners, zero network/DB. Scope
  deny-list, hashing/dedup, plan quotas, the finding lifecycle, rate derivation,
  every tool wrapper's parsing, the triage classifiers.
- **`tests/integration/`** — whole pipelines against `FakeMongo`: scope enforcement
  end-to-end, the authorization gate, plan-quota enqueue, IP-scope confirmation,
  **that the politeness limiter is actually reached** (`test_politeness_is_wired`).
- **`tests/security/`** — JWT hardening (alg:none, tamper, expiry), tenant isolation
  (cross-tenant → 404 not 403), route auth coverage (no 2xx without creds), NoSQL
  injection, secret-notification leak, authorization self-grant, **SSRF guard**.

**Guardrail tests worth knowing** — these catch the "looks wired, isn't" failure:
`test_limiter_is_reachable`, `test_dashboard_queries` (every Grafana/alert query
references a real metric), `test_subprocess_rate` (every scanner wrapper passes a
rate flag). If you add a control, add its reachability test — a behavioural test of
correct-but-unwired code passes just as happily as wired code.

> **Coverage numbers lie for this product.** High line coverage doesn't prove a
> control is *invoked in production* — the dead limiter had 100%-covered bucket math.
> Prefer the reachability guards above over a coverage percentage.

---

## Layer 2 — Static + preflight

```bash
.venv/bin/ruff check .                          # lint (S-rules incl. security)
python -m daemon.main --dry-run                 # tools + config + scope feeds, no network
curl -s localhost:8000/healthz                  # liveness
curl -s localhost:8000/readyz                   # deps (mongo/redis)
```

`--dry-run` is the fast gate: it prints the module registry and validates config,
scope feeds, every required binary, Mongo and Redis. Config + scope-feed checks are
the hard gate; binary/DB checks pass inside the pipeline image.

---

## Layer 3 — Local end-to-end (a real scan against a target you own)

Bring up the stack and run one full scan against **a domain you control** (or a
sanctioned target — `scanme.nmap.org` for ports, a local DVWA/Juice Shop). See
[`docs/TESTING.md`](TESTING.md) Part 1 for the exact commands.

**Verify each stage produced what it should** (watch the worker logs / the Activity
tab, then the DB / UI):

| Stage | Expect |
|-------|--------|
| ingest | subdomains from subfinder + crt.sh; out-of-apex hosts dropped |
| probe | alive hosts with tech/title/status; **asset interest badges** on the Assets tab |
| crawl | endpoints, with **risk tags** (auth/admin/idor/…) on the interesting ones |
| content_discovery | paths — only on confirmed-dedicated hosts |
| port_scan | open ports — **only on confirmed-dedicated infra**, never CDN/shared |
| scan (nuclei) | findings; a WordPress host gets wordpress templates on its safe scan |
| secrets | masked secrets only — **never a plaintext value anywhere in the doc** |
| notify | one alert per genuinely new fact, gated by the alert policy |

A stage that "skipped" with a note is usually correct (no data yet, or a module
that's off by default) — read the note.

---

## Layer 4 — Security & safety verification (the important part)

This is a scanning product with cloud credentials and multi-tenant data. These are
the tests that prove **ExactSurface doesn't become an attacker's target, and never
attacks a third party it shouldn't.** Re-run them after any change to `core/scope`,
the fetch paths, or auth.

### 4a. Scope enforcement — the core safety control (§9b)

The engine must refuse to actively scan anything that isn't confirmed-dedicated.

- **Metadata / internal IPs are never scanned.** Point a subdomain you control at
  `169.254.169.254` (or an RFC1918 address), run a scan. It must be classified
  hard-deny and **never probed or port-scanned**. (`tests/unit/test_scope.py` proves
  the classification exhaustively; verify it holds end-to-end.)
- **CDN / cloud-shared hosts get HTTP-layer only.** A Cloudflare-fronted host must be
  probed but **never port-scanned or aggressively nuclei'd**.
- **A CIDR you list is only a request.** Add an `ip_scope` CIDR to a program; it must
  stay `unconfirmed` (HTTP-only) unless the apex's real ASN announces it (asnmap
  confirmation, §9b step 3). Confirm you *cannot* unlock port-scanning of third-party
  infra by declaring it "dedicated".

### 4b. Politeness rate cap — the AUP boundary (§3.8b, §15)

No target may be contacted faster than `EXACTSURFACE_GLOBAL_RATE_PER_TARGET` (default 10).

```bash
# During/after a scan, scrape the worker's metrics:
curl -s localhost:9100/metrics | grep exactsurface_subprocess_per_target_pps
```

Every `{tool="…"}` line must be **≤ 10**. This is the §15 exit criterion, verified by
metrics. The `SubprocessRateExceedsPolitenessCap` alert pages if any tool crosses it.
Also confirm in the logs that naabu/httpx/nuclei were handed a derived rate, not
their unbounded default.

### 4c. SSRF guard — ExactSurface must not be steered inward (§3.10)

The takeover probe and secret scanner fetch attacker-influenced content. A target
must not be able to redirect or DNS-rebind them to the cloud metadata endpoint.

- Unit proof: `tests/security/test_ssrf_guard.py` (metadata/RFC1918/CGNAT/IPv6-local
  all forbidden; redirects are off; IP-literal targets refused).
- Live proof: stand up a host that returns `302 → http://169.254.169.254/`, add it in
  scope, run takeover/secrets. ExactSurface must **refuse the redirect** — no metadata
  fetch, no IAM credentials scanned as a "secret".

### 4d. Secret handling — never a plaintext honeypot (§9c)

- Every stored secret is **masked + keyed-hash only**; the raw value appears nowhere
  in the document or in any notification. (`test_secret_notification_leak`,
  `test_pipeline_stores_masked_secret_never_plaintext`.)
- The regex layer filters placeholders/URLs/low-entropy junk (the AWS `…EXAMPLE`
  key, `YOUR_API_KEY_HERE`) so the FP rate stays honest.

### 4e. Tenant isolation & auth

- **Cross-tenant access returns 404, not 403** (don't confirm a resource exists to a
  stranger). Try reading another tenant's program/finding/asset with a valid token.
- **Every route needs auth.** `test_route_auth_coverage` enumerates every route and
  asserts no 2xx without credentials — re-run it after adding endpoints.
- **JWT can't be forged.** `alg:none`, tampered signature/payload, expired, wrong
  secret — all rejected (`test_jwt_hardening`).
- **No privilege self-grant** — a user can't elevate their own role/plan
  (`test_authorization_self_grant`).

### 4f. Prod-safety refusal

Set `EXACTSURFACE_ENV=prod` with the dev-default `EXACTSURFACE_JWT_SECRET` and start the API —
it must **refuse to boot** (`assert_prod_safe`). Same for `EXACTSURFACE_LAB_ALLOW_PRIVATE=true`
in prod.

---

## Layer 5 — Real-infra validation (what CI can't exercise)

Nothing below has run in the dev environment — do it once on a real box before prod:

```bash
# 1. Images actually build (they add age, mongodb-tools, the PD toolchain)
docker build -f docker/Dockerfile.pipeline .
docker build -f docker/Dockerfile.api .

# 2. Prod compose merges and is safe (no daemon needed)
docker compose -f docker/docker-compose.prod.yml config | grep -E "27017|6379"  # must NOT be published

# 3. THE MOST IMPORTANT ONE — restore a backup into a scratch DB
python -m scripts.backup run
python -m scripts.backup restore <archive> --identity id.txt   # into a throwaway EXACTSURFACE_MONGO_DB
```

Also verify against **real** Redis and Mongo (the fakes hide behaviour):
- the rate-limit Lua (including `redis.call('TIME')`) executes and holds the cap;
- the Mongo scope-feed round-trips (`ScopeFeedRepo` `_id`-keyed upsert) and a worker
  restart picks up an updated feed;
- Grafana panels populate (scrape the **worker/scheduler** :9100, not just the API).

**An untested backup is a hypothesis, not a backup.** Restore one before you rely on
it.

---

## Layer 6 — The unattended run (§7 exit gate)

The literal Phase G exit criterion: **runs 7 days unattended with real tenants and
hundreds of domains — no intervention, no AUP complaints.** Can only be *run*.

Watch, in Grafana (the `ExactSurface — Operations` dashboard):
- **`time() - exactsurface_scheduler_last_success_timestamp`** stays under a few ticks —
  proves scanning is still happening (a crashed-but-up scheduler is the silent killer).
- **stage failure/timeout rates** stay low — a stage quietly timing out means scans
  "succeed" with missing data.
- **per-target rate** never crosses the cap (4b) — the AUP guarantee, all week.
- Alert channels stay quiet except for genuine new findings.

If `SchedulerNotTicking` or `SubprocessRateExceedsPolitenessCap` ever fires, the run
has failed — investigate before restarting the clock.

---

## Layer 7 — Load & scale (§8)

Before taking multi-tenant traffic, a Locust run at the spec's target: **100 tenants
/ 10k assets / 1M findings, API p99 < 500ms**, and verify the fairness cap keeps a
5000-asset tenant from starving others. (Not yet written — a real gap for a
multi-tenant launch.)

---

## When to run what

- **Every commit:** Layer 1 + 2 (`pytest`, `ruff`, `tsc`). Fast, no services.
- **Every PR touching scope / fetch / auth / rate-limit:** add Layer 4 for that area.
- **Before a deploy:** Layers 3, 4, 5.
- **Before launch:** Layer 6 (the 7-day run), and Layer 7 if multi-tenant.
- **Weekly in prod:** confirm the Grafana liveness + politeness panels, and that a
  backup restored successfully.

---

## Known gaps to test around (from the engineering log)

- **CVE/KEV match latency (§15 <60min) is not measurable** — `CveRecord` has no
  `published` timestamp yet. Don't expect a latency number here.
- **Redis/Mongo have not run for real in CI** — Layer 5 is where the remaining real
  bugs most likely are. The api, pipeline and demo images DO build (verified), and the
  release build-stamp is checked end-to-end (`OWNER_RUNBOOK.md` §2.1).
- **Org-name ASN lookup is not built** — a CDN-fronted apex will not auto-confirm its
  real origin ASN; use the `scan_shared_infra` opt-in there (ADR-0008).
- **No load suite yet** (Layer 7).

---

## UI completeness checklist

Walk every page and tick each item. This is what "the dashboard is complete" means
concretely — surface each control, confirm it does what it says, and note anything
missing. (Reflects the app as of 2026-08-01 — 28 modules, licence-gated plans.)

**Auth**
- [ ] Sign up creates a tenant + owner; login works; wrong password rejected.
- [ ] `/verify-email` — the resend button hits the real endpoint (dev prints the link
      in the API logs).

**Overview**
- [ ] Stat tiles (programs / assets / actionable / secrets / new) populate after a scan.
- [ ] "Findings by severity" + the **false-positive rate** (`—` until you triage one).

**Programs → detail**
- [ ] Add domain (blocked with a 402 past the licence limit — see Settings › Plan).
- [ ] Verify + Authorize buttons; "Run scan"; **Stop** on a running scan (confirm dialog
      explains what stops); **Scan my cloud infra** toggle (§9b).
- [ ] **Scan modules** panel: every module listed, essential ones locked, opt-in ones
      labelled, and turning one off shows *"Turning this off also stops: …"* before you
      save. A module outside your tier shows as not included rather than as a switch.
- [ ] Tabs: surface, priorities, findings, cves, assets, endpoints, ports, secrets,
      leaks, **JS mine**.
- [ ] **Surface** tab shows the **Domain intelligence** card (SPF/DMARC verdict with the
      raw records, registrar/expiry/transfer-lock/DNSSEC) and **Attack paths**.
- [ ] **Assets** show interest badges (critical/high) with reasons on hover.
- [ ] **Endpoints** show risk tags (auth/admin/idor/…) and the correct **source**
      (feroxbuster *or* ffuf — whichever found it).
- [ ] A **dork** finding shows the exact **Dork query** + **Indexed snippet** +
      a "Search Google for: …" reproduction (not a misleading `curl`).
- [ ] **403-bypass** bar is present on the Endpoints tab even with nothing to test
      (disabled + explanatory), and a bypassed endpoint carries the blue label with the
      payload/detail modal.
- [ ] Schedule card: cadence, last/next run.

**Findings / Changes / DNS / Activity**
- [ ] Findings list + detail (description, matched-at, references, raw request/response).
- [ ] **Module filter** dropdown lists every module that produced a finding, with counts,
      and filtering to one shows only its results.
- [ ] Changes = the state-delta feed (status/tech/title/new-port).
- [ ] DNS page: records, CNAMEs, takeover-risk flags.
- [ ] Activity: live scan-run log (2s poll).

**Settings**
- [ ] Account (tenant, role) and **Plan** (tier + `used / limit` bar) — added 2026-07-18.
- [ ] API-key generation (shown once); notification channels; alert-policy;
      schedule/timeout defaults.

**Knowledge**
- [ ] Search works; the **"Those § numbers explained"** and **"What to look at first"**
      sections are present.

**Grafana** (`:3001`, admin / `GRAFANA_ADMIN_PASSWORD`, default `admin` in dev)
- [ ] The `ExactSurface — Operations` dashboard loads and its panels populate during a scan
      (scheduler liveness, per-target rate, stage outcomes). Nothing to configure —
      datasource + dashboard are auto-provisioned.

### Per-module output check (run after a full scan)

Every module must put something on screen. Filter Findings by module, or open the tab
named. If a module ran successfully and its row here is empty, that is a bug — the
`test_every_module_result_is_reachable_from_the_frontend` contract covers the wiring,
but only a real scan proves the data arrives.

| Module | Where to look |
|---|---|
| `domain_intel` | Surface tab → Domain intelligence card + Findings |
| `ingest` / `reverse_dns` / `cloud_assets` | Assets tab (check the `source` column) |
| `probe` | Assets (alive + tech) and Changes |
| `tls`, `takeover`, `cloud_buckets`, `dork`, `typosquat`, `supply_chain` | Findings, filtered by module |
| `crawl`, `content_discovery`, `nuclei_watch` | Endpoints (check the `source` filter) |
| `js_mine` | **JS mine** tab + Endpoints with source `js` |
| `api_surface` | Endpoints with source `robots`/`sitemap`/`api_surface`, + Findings |
| `http_misconfig` | Findings (CORS / open redirect); WAF appears in the run stats |
| `param_discovery` | Findings, filtered by `param_discovery` |
| `broken_links` | Findings |
| `port_scan` / `service_scan` | Ports tab |
| `scan` | Findings (nuclei) |
| `secrets` | Secrets tab (masked) |
| `cve_watch` | CVEs tab |
| `github_osint` | Leaks tab |
| `correlate` | Surface tab → Attack paths + Priorities |
| `notify` | your configured channel actually receives a message |

### The demo site

The demo is the same frontend with static fixtures, so it is also the fastest way to
review UI changes without running a scan.

```bash
docker build -f demo/Dockerfile -t exactsurface-demo .
docker run --rm -p 3000:3000 exactsurface-demo   # then sign in with anything
```

- [ ] Every tab above is populated (an empty tab in the demo means a missing fixture —
      check the browser console for `[demo] no fixture for …`).
- [ ] Activity shows a run in flight with live logs and the full stage stepper.
- [ ] Clicking a mutating control does nothing and does not error.

### The workbench (developers only)

```bash
python -m devtools     # open the printed URL; the token is required
```

- [ ] Every module appears under **Pipeline stages** and every public function under
      **Functions** (introspected, so a new one appears with no registration).
- [ ] Running a pure function returns its result including dataclass properties.
- [ ] A wrong/absent token returns 404 on every path.

**Known UI gaps to log (not yet built):**
- No billing/plan-upgrade flow (the plan is a display; there's no Stripe). Upgrades are
  done by minting a new licence — see `docs/PRICING_AND_LIMITS.md` §4.
- No in-UI way to change a tenant's plan, and there deliberately never will be: the
  signed licence is the sole authority, so a UI control could only ever *lower* it.
- No self-serve DNS-verification status poller beyond the check button.
