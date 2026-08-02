# ExactSurface — deployment

**This folder is the entire product as a customer receives it.** Copy it to a server,
fill in `.env`, and start it. There is no source code here and nothing is compiled: the
application ships as three pre-built container images, and everything in this directory
is configuration.

```bash
cp .env.example .env      # then edit it — see "Filling in .env" below
docker compose up -d
docker compose logs api | grep "license active"
```

If that last command prints a line naming your organisation, you are running.

---

## What is in here

| File | What it does | Do you edit it? |
|---|---|---|
| `docker-compose.yml` | The whole stack — ten services, wired together. | No |
| `.env.example` | Every setting, commented. | Copy to `.env`, then yes |
| `Caddyfile` | TLS termination and routing. Gets a Let's Encrypt certificate automatically. | No |
| `prometheus.yml` | What metrics get scraped. | No |
| `alerts.yml` | Alert rules (stuck scans, dead workers, rate-cap breaches). | Rarely |
| `grafana/` | A pre-built operations dashboard, provisioned automatically. | No |

**All of these files must stay together.** `docker-compose.yml` mounts the other four by
relative path, so moving or renaming any of them breaks startup — Caddy in particular
fails in a confusing way, because Docker helpfully creates a *directory* where it
expected a config file.

---

## What comes up

Ten services, all wired for you. You start one thing and get the whole platform.

| Service | What it is | Reachable from outside? |
|---|---|---|
| `caddy` | The only public entry point. TLS + routing. | **Yes — 80/443** |
| `frontend` | The web UI. | No — through Caddy |
| `api` | The application API. | No — through Caddy |
| `worker` ×3 | Runs the scans. | No |
| `scheduler` | Decides what to scan and when. | No |
| `pipeline` | Startup gate: validates config, then exits. | No |
| `mongo` | Your data — assets, findings, everything. | **No host port at all** |
| `redis` | Job queue and rate-limit state. | **No host port at all** |
| `prometheus` | Metrics storage. | No |
| `grafana` | Operations dashboard. | Loopback only (see below) |

Mongo and Redis deliberately publish **no ports**. They are reachable only by the other
containers. An exposed, unauthenticated datastore is the most common way a self-hosted
deployment gets breached, and this shape makes it impossible rather than unlikely — they
are password-protected *as well*, but the port simply is not there.

`pipeline` runs once with `--dry-run` and exits. That is intentional: it validates your
configuration and the bundled scope feeds *before* anything else starts, so a broken
setup fails immediately instead of halfway through your first scan. Seeing it in
`Exited (0)` is correct.

Grafana binds to `127.0.0.1` only. Reach it through an SSH tunnel:

```bash
ssh -L 3001:127.0.0.1:3001 you@your-server     # then open http://localhost:3001
```

---

## Before you start

1. **A server.** 4 vCPU / 8 GB RAM minimum, 8/16 recommended. Any Linux with Docker
   Engine 24+ and the Compose plugin.
2. **A DNS A-record** pointing at that server, created **before** you start the stack.
   Caddy requests a certificate on first boot; with no DNS the request fails and you
   will be looking at TLS errors instead of the product.
3. **Outbound internet access.** The scanner has to reach the internet to see your
   attack surface the way an attacker does.
4. **Your licence token**, which we sent you.

---

## Filling in `.env`

Generate real secrets. The stack refuses to start with placeholder values, and compose
will tell you exactly which one is missing rather than booting insecurely.

```bash
openssl rand -hex 24                                             # for the two below
python3 -c "import secrets; print(secrets.token_urlsafe(48))"    # for everything else
```

Required, no defaults:

| Variable | Notes |
|---|---|
| `EXACTSURFACE_LICENSE` | The token we sent you, on **one line**. |
| `DOMAIN` | The hostname this instance serves. Must already resolve to this server. |
| `MONGO_ROOT_PASSWORD` | **Use `openssl rand -hex 24`, not base64.** This value goes into a Mongo connection URI unescaped; a `base64` password containing `+`, `/` or `=` breaks authentication with an error that never mentions the password. |
| `REDIS_PASSWORD` | Same rule, same reason — it goes into a Redis URI the same way. |
| `GRAFANA_ADMIN_PASSWORD` | Random — not URI-embedded, any generator is fine. |
| `EXACTSURFACE_JWT_SECRET` | Random. Signs your users' sessions. |
| `EXACTSURFACE_SECRET_HASH_KEY` | Random. See the warning below. |

> **Two of these cannot be changed freely later.** Rotating `EXACTSURFACE_JWT_SECRET`
> logs everyone out. Rotating `EXACTSURFACE_SECRET_HASH_KEY` makes every previously
> reported leaked-credential finding look brand new, because that key is what lets the
> platform recognise a secret it has seen before *without storing the secret itself*.
> Set both once, back up `.env`, and leave them alone.

> **`.env` holds every secret for this deployment.** `chmod 600` it, keep it out of
> version control, and back it up somewhere private.

### Put the licence in `.env`, not in a shell variable

```ini
EXACTSURFACE_LICENSE=vlic1.eyJjaWQiOiJjdXNf…
```

Not `export EXACTSURFACE_LICENSE=…`. An exported variable lasts one terminal session;
the next `docker compose up` or `docker compose restart` from a shell without it drops
the instance to read-only, and nothing in the logs explains why. Configuration that
survives one terminal session is not configuration.

---

## Starting it

```bash
docker compose up -d
```

First start pulls a few GB — the scanning image carries a full recon toolchain and the
detection-template corpus. Give it a few minutes.

### Confirm your licence activated

Do this before anything else:

```bash
docker compose logs api | grep "license active"
```

```
license active: Acme Corp (business), 25 domain(s), expires 2027-08-02
```

If you see nothing, or the UI shows a red **read-only mode** banner, jump to
[Troubleshooting](#troubleshooting).

### Then

```bash
docker compose ps          # every service healthy? (pipeline Exited (0) is correct)
docker compose logs -f api
```

Open `https://your-domain` and **create the first account — it becomes the owner** of
your organisation. Public signup closes automatically after that; add teammates under
*Settings → members*.

---

## Your first scan

ExactSurface will not scan a domain you have not proven you control. This is not a
formality — it is what keeps your usage lawful and defensible.

1. **Programs → add** your domain.
2. **Verify ownership** — place the DNS TXT record or HTTP file it gives you, then check.
3. **Authorise scanning** — create the authorization record.
4. **Scan**, and watch it live under **Activity**.

Findings arrive progressively: subdomains, then live hosts, then exposures.

> Only add domains you own or are contractually authorised to test. Scanning third
> parties without authorisation is illegal in most jurisdictions and breaches your
> licence.

---

## Day-to-day

```bash
docker compose ps                          # health
docker compose logs -f worker              # what the scanner is doing
docker compose restart api                 # safe any time
docker compose down                        # stop (your data lives in named volumes)
docker compose exec api python -m scripts.backup    # back up the database
```

**Upgrading.** Change `EXACTSURFACE_VERSION` in `.env` to the version you were given,
then:

```bash
docker compose pull && docker compose up -d
```

Images are pinned to a version rather than `latest` on purpose: an image that changes
underneath a running scan is not something you should have to debug.

**Renewing your licence.** You'll receive a new token before or shortly after the old
one lapses. Update it, then **restart is required** — editing `.env` alone does nothing
to an already-running container:

```bash
# edit EXACTSURFACE_LICENSE= in .env, then:
docker compose up -d
docker compose logs api | grep "license active"    # confirm the new expiry shows
```

This isn't optional busywork: the licence is read once when the `api` process starts
and cached for its whole lifetime, so a container that's already running has no way to
notice `.env` changed underneath it. If you edit the file and don't see anything
different, that's why — you haven't recreated the container yet.

You don't need to do this *before* the old licence expires — there's a grace period
(shown in `docker compose logs api | grep -i licen`) that keeps scanning working for a
few days past expiry so a slightly-late renewal doesn't interrupt anything. Past grace,
the instance goes read-only: existing findings stay fully visible and exportable,
scanning simply pauses until the new token is in and the container is restarted.

---

## Troubleshooting

### `api` keeps restarting, logs show "Authentication failed" against Mongo

`MONGO_ROOT_PASSWORD` or `REDIS_PASSWORD` contains a character with special meaning in a
URI — most often `+`, `/`, `=`, `@` or `%`, which is exactly what `openssl rand -base64`
can produce. Both values are placed straight into a connection string with no encoding,
so this fails authentication in a way that never mentions the password. Regenerate both
with `openssl rand -hex 24` (hex only — always URI-safe) and `docker compose up -d`.

### Red "read-only mode — no license configured" banner

The licence did not reach the application. In order:

```bash
docker compose exec api printenv EXACTSURFACE_LICENSE     # is it there at all?
docker compose logs api | grep -i licen                   # what did it decide?
```

- **Nothing printed by the first command** — `EXACTSURFACE_LICENSE` is not in `.env`, or
  you exported it in a shell instead of writing it to the file.
- **`license state: invalid`** — the token is corrupted. It must be one unbroken line;
  a line break pasted into the middle is the usual cause.
- **`license state: expired`** — your subscription lapsed. Findings stay viewable and
  exportable; scanning resumes on renewal.
- **The command printed a token but the banner persists** — restart the API
  (`docker compose up -d api`). A container compose reports as `Running` rather than
  `Started` did not pick up the new environment.

### Caddy will not start / no certificate

Your A-record almost certainly does not point here yet. Confirm with
`dig +short your-domain`, then `docker compose restart caddy`. Let's Encrypt also rate
limits repeated failures, so fix DNS first rather than retrying.

### Scans find nothing

Check the domain is **verified and authorised**, not merely added — an unverified domain
is never scanned. Then check outbound access: `docker compose exec worker curl -sI https://example.com`.

### Everything is slow

Workers are the scaling knob. Raise `replicas:` under the `worker` service in
`docker-compose.yml`, **and** set `EXACTSURFACE_WORKER_FLEET_SIZE` in `.env` to the same
number. They must match: if Redis becomes unreachable each worker falls back to
enforcing 1/fleet-size of the rate cap locally, so a fleet size below the real replica
count lets a degraded fleet scan *over* your ceiling.

---

## A note on politeness

`EXACTSURFACE_GLOBAL_RATE_PER_TARGET` (default 10/sec) is the most important operational
setting here. It is what keeps a scan of your own infrastructure from looking like an
attack to your own monitoring — and from actually degrading a small service. Raise it
only for infrastructure you operate and have capacity for.

---

Full manual: `INSTALL.md` in this directory. Support: the contact you were given.
