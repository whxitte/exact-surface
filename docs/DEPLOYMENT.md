# Vantari Deployment

Vantari has four runtime roles: **api** (FastAPI), **worker** (stateless scan
executors), **scheduler** (singleton enqueuer), and the datastores **MongoDB** +
**Redis**. Workers use the heavy `pipeline` image (all recon tools); the api uses
the slim image.

## Configuration
All config is `VANTARI_`-prefixed env (`.env.example`). **Before prod**, change
`VANTARI_JWT_SECRET` and `VANTARI_SECRET_HASH_KEY` — the app refuses to boot with
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
1. Provision a 4 GB / 2 vCPU VM (Ubuntu, Docker installed).
2. `git clone`, set `.env` (strong secrets), `docker compose -f docker/docker-compose.yml up -d`.
   > There is **no separate prod compose file yet** — this is the dev stack. Before
   > using it for real traffic: remove the published `mongo`/`redis` host ports,
   > set `GRAFANA_ADMIN_PASSWORD`, and put the api behind TLS (next step).
3. Front the api with a reverse proxy (Caddy/Nginx) for TLS; lock `VANTARI_ENV=prod`.
4. **Scanning egress:** run workers from IPs whose abuse contact you control;
   keep `VANTARI_MASSCAN_ENABLED=false` (ADR-0004). naabu stays rate-capped.

## Kubernetes (Helm)
```bash
kubectl create secret generic vantari-secrets --from-env-file=.env
helm install vantari deploy/helm/vantari -f my-values.yaml
```
The chart deploys api (2), workers (3, autoscale to scan load), and a **singleton**
scheduler (`strategy: Recreate`). Point `VANTARI_MONGO_URI` / `VANTARI_REDIS_URI`
at managed instances (Atlas M10+, managed Redis) or in-cluster StatefulSets.

## Datastore sizing
- **Dev:** self-hosted Mongo container / Atlas M0.
- **Prod:** Atlas **M10+** or self-hosted with backups (`python -m scripts.backup`).
- Redis: small managed instance (queue + rate-limit buckets).

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
# Dashboard: Vantari → Operations
```

Prometheus is not published to the host — reach it through Grafana. Set
`GRAFANA_ADMIN_PASSWORD` before exposing Grafana anywhere reachable; it can query
every metric the platform emits. Under Helm, `metrics.enabled` adds
`prometheus.io/scrape` annotations to the worker/scheduler pods (swap for a
PodMonitor if you run the Prometheus Operator).

`VANTARI_METRICS_PORT` (default 9100) sets the listener port; a bind failure
degrades to a warning and never blocks the process from starting. On a shared
host, bind loopback rather than publishing 9100.

**The two alerts that matter** (`docker/alerts.yml`):
- `SchedulerNotTicking` — `run_forever` swallows tick errors, so a scheduler that
  has silently stopped enqueueing still passes a liveness probe and keeps its port
  open. This is the only thing that catches it.
- `PortScanRateExceedsPolitenessCap` — §15's "naabu never exceeds the global rate
  cap, verified by metrics". Exceeding it is an AUP breach against a third party.
  Its threshold is **duplicated** from `VANTARI_GLOBAL_RATE_PER_TARGET` (Prometheus
  cannot read app config): change the setting, change the rule.

## Operations
- Health: `GET /healthz` (liveness), `GET /readyz` (deps) on the api;
  `GET :9100/health` on worker/scheduler (they serve nothing else).
- Pre-flight: `python -m daemon.main --dry-run` (binaries + config + scope feeds).
- Refresh scope feeds: `python -m scripts.update_scope_feeds` (cron, daily).
- Backups: `python -m scripts.backup` (cron; retention per §9).
