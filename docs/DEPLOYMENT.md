# ExactSurface Deployment

ExactSurface has four runtime roles: **api** (FastAPI), **worker** (stateless scan
executors), **scheduler** (singleton enqueuer), and the datastores **MongoDB** +
**Redis**. Workers use the heavy `pipeline` image (all recon tools); the api uses
the slim image.

## Configuration
All config is `EXACTSURFACE_`-prefixed env (`.env.example`). **Before prod**, change
`EXACTSURFACE_JWT_SECRET` and `EXACTSURFACE_SECRET_HASH_KEY` — the app refuses to boot with
the insecure defaults (`Settings.assert_prod_safe`).

## Local / small deployments — Docker Compose

```bash
cp .env.example .env
docker compose -f docker/docker-compose.yml up --build
# api → http://localhost:8000 (docs at /docs) · frontend → :3000
python -m scripts.seed_dev        # optional: demo tenant + sample findings
```

Self-hosted MongoDB + Redis run in the stack — **no Atlas required** (ADR-0001).
This is enough for a single tenant on one host (min 4 GB / 2 vCPU, §3.8).

## DigitalOcean / AWS / GCP (single VM)
1. Provision a 4 GB / 2 vCPU VM (Ubuntu, Docker installed), with a DNS record for
   your domain pointing at it (Caddy needs it to obtain a certificate).
2. `git clone`; set `.env` (strong `EXACTSURFACE_JWT_SECRET`, `EXACTSURFACE_SECRET_HASH_KEY`)
   **and** the prod-only vars `DOMAIN`, `MONGO_ROOT_USER`, `MONGO_ROOT_PASSWORD`,
   `REDIS_PASSWORD`, `GRAFANA_ADMIN_PASSWORD`.
3. `docker compose -f docker/docker-compose.prod.yml up -d --build`.

The prod compose differs from the dev stack in the ways that matter for exposure:
Mongo and Redis have **no host ports** (internal network only) and **both require
auth**; the API and frontend are not published either — **Caddy** is the single
ingress and terminates TLS (automatic Let's Encrypt for `$DOMAIN`); `EXACTSURFACE_ENV=prod`
makes `assert_prod_safe()` refuse insecure secrets. Grafana is published on
**loopback only** (`127.0.0.1:3001`) — reach it via an SSH tunnel.

> **Mongo auth applies only on first init of an empty volume.** `MONGO_INITDB_ROOT_*`
> is a no-op against an existing `mongo_data` volume — if you started with the dev
> stack, enable auth by migrating (dump → recreate the volume → restore), not by
> flipping the compose file.

4. **Scanning egress:** run workers from IPs whose abuse contact you control;
   keep `EXACTSURFACE_MASSCAN_ENABLED=false` (ADR-0004). Every scanner subprocess stays
   rate-capped (ADR-0009 + ADR-0013).

## Kubernetes (Helm)
```bash
kubectl create secret generic exactsurface-secrets --from-env-file=.env
helm install exactsurface deploy/helm/exactsurface -f my-values.yaml
```
The chart deploys api (2), workers (3, autoscale to scan load), and a **singleton**
scheduler (`strategy: Recreate`). Point `EXACTSURFACE_MONGO_URI` / `EXACTSURFACE_REDIS_URI`
at managed instances (Atlas M10+, managed Redis) or in-cluster StatefulSets.

## Datastore sizing
- **Dev:** self-hosted Mongo container / Atlas M0.
- **Prod:** Atlas **M10+** or self-hosted with backups (see below).
- Redis: small managed instance (queue + rate-limit buckets). **Not optional in
  prod** — it carries the shared politeness ceiling, and a worker that cannot reach
  it refuses to start (ADR-0012).

## Backups

The database is a map of every customer's external attack surface — hosts, open
ports, unfixed findings. A plaintext dump of it is arguably a better target than
the live system, so backups are encrypted with **`age` to a public recipient key**:

```bash
age-keygen -o exactsurface-backup-identity.txt     # DO THIS OFF THE SERVER
# public key → EXACTSURFACE_BACKUP_AGE_RECIPIENT (safe to ship anywhere)
# identity file → a vault/offline store. NOT on the scanning host.
```

The point of the asymmetry: the scanning host holds only the **public** key, so it
can write backups and cannot read them. Someone who owns that host does not thereby
own your backup history. Keep the identity file somewhere else, and **prod refuses
to start a backup without a recipient** rather than quietly writing plaintext.

```bash
python -m scripts.backup run                  # dump | age > archive, then prune
python -m scripts.backup restore <archive> --identity id.txt [--drop]
```

`mongodump --archive` is piped straight into `age`, so the plaintext never touches
disk. Retention is `EXACTSURFACE_BACKUP_RETENTION_DAYS` (default 30) and always keeps at
least the newest archive, so a run of silent failures cannot age out the last good
copy. Cron `run` daily.

> **Shipping offsite is on you, and it matters.** A backup on the same host as the
> database is not a backup — the failure it protects against destroys both. Sync
> `EXACTSURFACE_BACKUP_DIR` with whatever the deployment already uses (rclone, aws-cli,
> restic). Deliberately not bundled: it would mean either a new SDK dependency or
> bucket credentials sitting on the host we just assumed could be compromised.

> **Restore is the only thing that proves a backup.** Test it into a scratch
> database before you need it: an untested backup is a hypothesis.

## Scope feeds

`core/data/cloud_ranges.json` is what tells the engine an IP belongs to
Cloudflare/AWS/Akamai/… and therefore gets **HTTP-layer probing only** (§3.9). It is
a safety control, not a cache: a range that falls out of the feed stops being
recognised as shared infrastructure.

The refresh merges rather than rewrites (it does not fetch akamai/fastly/
google_cloud_lb/azure_front_door and must not delete them), refuses a feed whose
providers vanish or collapse, and writes atomically. A rejected update leaves the
previous feed in place — stale beats empty.

**It is automatic.** The scheduler refreshes a shared copy of the feed in Mongo
every `EXACTSURFACE_SCOPE_FEED_REFRESH_HOURS` (default 24; set 0 to disable and cron the
script instead). Workers load that Mongo copy at startup, falling back to the feed
bundled in the image, and **never** load a Mongo copy smaller than the bundled
baseline — a corrupt or partial write cannot silently un-classify ranges (ADR-0014).

> **Workers pick up a feed change on their next restart, not mid-run.** Provider
> ranges change on the order of weeks, so this is fine — every deploy does a rolling
> restart, and you can trigger one (`kubectl rollout restart` / `docker compose
> restart worker`) to apply a refresh sooner. There is deliberately no in-process
> hot-reload of the scope engine.

`python -m scripts.update_scope_feeds` still exists to refresh the **bundled file**
(for a rebuild) if you prefer that to the Mongo path.

## Observability

**Scraping only the API tells you nothing about scanning.** Each process keeps its
own in-memory registry (ADR-0011), and the API image carries no scan toolchain
(§3.8) — so stage outcomes, run durations, politeness decisions and port-scan
rates all live in the **worker**, and scheduler liveness lives in the
**scheduler**. All three roles must be scraped:

| Role | Endpoint | Served by |
| --- | --- | --- |
| api | `:8000/metrics` | FastAPI |
| worker (each replica) | `:9100/metrics` | `daemon/metrics_server.py` |
| scheduler | `:9100/metrics` | `daemon/metrics_server.py` |

Compose brings up Prometheus + Grafana already wired:

```bash
docker compose -f docker/docker-compose.yml up -d prometheus grafana
# Grafana → http://localhost:3001 (admin / $GRAFANA_ADMIN_PASSWORD, default "admin")
# Dashboard: ExactSurface → Operations
```

Prometheus is not published to the host — reach it through Grafana. Set
`GRAFANA_ADMIN_PASSWORD` before exposing Grafana anywhere reachable; it can query
every metric the platform emits. Under Helm, `metrics.enabled` adds
`prometheus.io/scrape` annotations to the worker/scheduler pods (swap for a
PodMonitor if you run the Prometheus Operator).

`EXACTSURFACE_METRICS_PORT` (default 9100) sets the listener port; a bind failure
degrades to a warning and never blocks the process from starting. On a shared
host, bind loopback rather than publishing 9100.

**The two alerts that matter** (`docker/alerts.yml`):
- `SchedulerNotTicking` — `run_forever` swallows tick errors, so a scheduler that
  has silently stopped enqueueing still passes a liveness probe and keeps its port
  open. This is the only thing that catches it.
- `PortScanRateExceedsPolitenessCap` — §15's "naabu never exceeds the global rate
  cap, verified by metrics". Exceeding it is an AUP breach against a third party.
  Its threshold is **duplicated** from `EXACTSURFACE_GLOBAL_RATE_PER_TARGET` (Prometheus
  cannot read app config): change the setting, change the rule.

## Operations
- Health: `GET /healthz` (liveness), `GET /readyz` (deps) on the api;
  `GET :9100/health` on worker/scheduler (they serve nothing else).
- Pre-flight: `python -m daemon.main --dry-run` (binaries + config + scope feeds).
- Refresh scope feeds: `python -m scripts.update_scope_feeds`. **Redeploy afterwards**
  — see below; running it against a live worker does nothing.
- Backups: `python -m scripts.backup run` (cron, daily) — see Backups above.
