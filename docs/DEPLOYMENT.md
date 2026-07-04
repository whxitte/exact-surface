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
2. `git clone`, set `.env` (strong secrets), `docker compose -f docker/docker-compose.prod.yml up -d`.
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

## Operations
- Health: `GET /healthz` (liveness), `GET /readyz` (deps), `GET /metrics` (Prom).
- Pre-flight: `python -m daemon.main --dry-run` (binaries + config + scope feeds).
- Refresh scope feeds: `python -m scripts.update_scope_feeds` (cron, daily).
- Backups: `python -m scripts.backup` (cron; retention per §9).
