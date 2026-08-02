# ExactSurface — Deployment & Operations Guide

ExactSurface is continuous **external attack-surface monitoring** that runs entirely on
your own infrastructure. It discovers your internet-facing assets, watches them for
change, and reports exposures — showing you the exact request behind every finding.

Your data never leaves your servers. There is no vendor cloud holding your attack
surface.

---

## 1. What you received

| Item | What it's for |
|---|---|
| **Licence token** (a `.vlic` file) | Activates your subscription. Treat it as a credential. |
| **Image access** | The published container images (or a pull token for them). |
| **Control-plane URLs** | Where your instance fetches licence renewals + detection updates. |
| **This guide** | Everything below. |

---

## 2. Requirements

**Server** (a single VM is fine to start):

| | Minimum | Recommended |
|---|---|---|
| vCPU | 4 | 8 |
| RAM | 8 GB | 16 GB |
| Disk | 100 GB SSD | 250 GB SSD |
| OS | any Linux with Docker Engine 24+ and the Compose plugin | |

Scanning is bursty and network-heavy; RAM matters most when many subdomains are probed
at once.

**Network**

- **Inbound:** 80 and 443 from wherever your team browses (or your VPN only — safer).
- **Outbound:** unrestricted HTTPS/DNS. The scanner must reach the internet to see your
  attack surface the way an attacker does. Also allow your instance to reach the
  ExactSurface control plane for renewals and detection updates.
- A **DNS A-record** pointing at the server (TLS is issued automatically).

**Also have ready:** an SMTP account if you want email verification/alerts, and a Slack
or Discord webhook if you want alerting.

---

## 3. Install

Download `exactsurface-<version>.tar.gz` from the release you were given. That archive
is the entire deployment — a compose file and its configuration. There is **no source
code to clone and nothing to build**; the images are published and pre-built.

```bash
tar xzf exactsurface-1.0.0.tar.gz && cd exactsurface-1.0.0
cp .env.example .env
```

You should have these files:

| File | What it is |
|---|---|
| `docker-compose.yml` | The stack. Pinned to the exact image versions you were shipped. |
| `.env.example` | Every setting, commented. Copy to `.env` and fill it in. |
| `Caddyfile` | TLS + ingress. Gets a Let's Encrypt certificate automatically. |
| `prometheus.yml`, `alerts.yml` | Metrics and alerting rules. |
| `grafana/` | Pre-built operations dashboard. |
| `INSTALL.md` | This guide. |

If you also want to pull the images ahead of time (optional — compose does it for you):

```bash
docker pull ghcr.io/whxitte/api:1.0.0
docker pull ghcr.io/whxitte/frontend:1.0.0
docker pull ghcr.io/whxitte/pipeline:1.0.0
```

### 3.1 Fill in `.env`

Generate real secrets — the stack **refuses to start in production with defaults**:

```bash
python3 -c "import secrets; print('EXACTSURFACE_JWT_SECRET=' + secrets.token_urlsafe(48))"
python3 -c "import secrets; print('EXACTSURFACE_SECRET_HASH_KEY=' + secrets.token_urlsafe(48))"
```

Minimum you must set:

```ini
# your subscription — paste the token we sent you, on one line
EXACTSURFACE_LICENSE=vlic1.…

EXACTSURFACE_JWT_SECRET=<generated above>
EXACTSURFACE_SECRET_HASH_KEY=<generated above>
EXACTSURFACE_APP_BASE_URL=https://easm.yourcompany.com

# read by docker compose itself (no prefix)
DOMAIN=easm.yourcompany.com
MONGO_ROOT_USER=exactsurface
MONGO_ROOT_PASSWORD=<strong random>
REDIS_PASSWORD=<strong random>
GRAFANA_ADMIN_PASSWORD=<strong random>

# must equal the worker replica count in docker-compose.yml (see §6.3)
EXACTSURFACE_WORKER_FLEET_SIZE=3
```

> **Put the licence in `.env`, not in a shell variable.** `export EXACTSURFACE_LICENSE=…`
> lasts one terminal session; the next `docker compose up` or `restart` without it drops
> the instance to read-only with nothing in the logs explaining why.

Two things you do **not** need to set: `EXACTSURFACE_ENV`, which the compose file already
pins to `prod`, and any "enforce licensing" flag — a released image always enforces, and
no environment variable changes that. If you prefer to mount the token as a file rather
than put it in `.env`, set `EXACTSURFACE_LICENSE_FILE` to the path inside the container
and mount it in a compose override.

> **`.env` holds every secret for this deployment.** It's gitignored — keep it that way,
> restrict it to `chmod 600`, and back it up somewhere safe but private.

### 3.2 Point DNS, then start

Create the A-record for `DOMAIN` **before** starting, so TLS can be issued:

```bash
docker compose up -d
docker compose ps            # all healthy?
docker compose logs -f api   # watch for errors
```

The first start pulls a few GB (the scanning image carries a full recon toolchain and
the template corpus), so give it a few minutes on a slow connection.

**Confirm your licence activated.** This is the one check worth doing before anything
else — a licensed instance says so explicitly:

```bash
docker compose logs api | grep "license active"
```

You want a line naming your organisation, plan and expiry. If instead the UI shows a red
**read-only mode** banner, the licence did not load; see §9 before going further.

Open `https://your-domain` and create the first account — **that account becomes the
owner** of your organisation.

### 3.3 Verify the install

- [ ] `https://your-domain` loads and you can sign up / log in
- [ ] `docker compose ps` shows all services healthy
- [ ] `docker compose logs api | grep "license active"` prints your subscription
- [ ] Settings shows your subscription as **active** (no red banner)
- [ ] `docker compose logs worker` shows the worker connected to Redis

---

## 3.4 Accounts on a self-hosted instance

Your instance serves **one organisation — yours**. Accounts work accordingly:

- **The first person to sign up becomes the owner.** Do this yourself, immediately after
  the stack starts.
- **Public signup then closes automatically.** Someone who reaches your login page cannot
  create an account. Add teammates under *Settings → members*, then put them in a
  permission group (a new member has no access until you do).
- **Email verification is off by default.** On a single-organisation instance there are
  no strangers signing up, and members you create are already trusted — so it would only
  add an SMTP dependency between your team and the login page. Turn it on
  (`EXACTSURFACE_REQUIRE_EMAIL_VERIFICATION=true`) **only if** you want it and have SMTP
  configured; otherwise nobody can complete verification.
- You can still configure SMTP purely for **alerts** without turning verification on.

---

## 4. First scan — the authorisation flow

ExactSurface **will not scan a domain you haven't proven you control.** This is
deliberate: it's what keeps your usage lawful and defensible.

1. **Add the domain.** Programs → add e.g. `yourcompany.com`.
2. **Verify ownership.** Choose DNS TXT or an HTTP file, place the token it gives you,
   then click check.
3. **Authorise scanning.** Create the authorization record. Optionally request specific
   IP ranges as "dedicated" — the platform confirms them against your domain's real
   announced ASN before ever treating them as yours. Self-declaration alone never
   unlocks aggressive scanning.
4. **Scan.** Trigger it, and watch progress live in **Activity**.

Findings appear progressively — subdomains first, then live hosts, then exposures.

> **Only add domains you own or are contractually authorised to test.** Scanning third
> parties without authorisation is illegal in most jurisdictions and is a breach of your
> licence. See §8.

---

## 5. Using the platform

| Where | What you get |
|---|---|
| **Overview** | Attack-surface totals, new findings, recent change |
| **Programs → Assets** | Every discovered subdomain, with live status, tech, and an interest rating |
| **Endpoints** | Live URLs, risk tags, and the on-demand **403/401 bypass** check |
| **Findings** | Exposures with severity — each shows the exact detector and a one-click reproduction |
| **DNS / Ports / Secrets / CVEs** | Takeover risks, open services, leaked credentials (always masked), matched CVEs |
| **Activity** | Live scan logs |
| **Reports** | HTML / PDF / executive / HackerOne-style export |
| **Settings** | Team access, alert channels, integrations, schedules, subscription status |

**Team access.** The owner creates *permission groups* (View / Manage programs / Manage
settings) and adds teammates to them. **A new user has no access until you put them in a
group.** Only the owner can manage members — that's what prevents privilege escalation.

**Alerts.** Settings → notification channels (Slack, Discord, Telegram, email, webhook)
with a severity threshold, so you're told about what matters rather than everything.

**Stopping a scan.** While a scan is running, the program page shows a **Stop scan**
button. It asks for confirmation and tells you exactly what will happen, because a stop
is a real operation, not a cancel-and-forget:

- the step running right now is wound down and its tool shut down, so no further requests
  reach your targets;
- **everything already discovered is kept** — assets, endpoints and findings from
  completed steps stay exactly as they are;
- the remaining steps are skipped and marked stopped;
- the run is recorded as **cancelled**, not failed, and you can start a fresh scan right
  away — it runs normally from the beginning.

Stopping can take up to a minute while the current step winds down; the button shows
"Stopping…" until it's finished.

**403 bypass.** On the Endpoints tab, when forbidden endpoints exist you can run a
detection-only check for whether that 403 is actually bypassable. It uses safe methods
only, never exploits, and shows you the exact request that got through.

---

## 5.9 Optional: let ExactSurface read your cloud accounts

This is the single highest-yield thing you can turn on. DNS enumeration finds what
somebody *published*; your cloud provider knows what actually **exists** — the load
balancer nobody pointed a name at, the VM left over from a migration, the storage
bucket from a project that ended.

### What it needs (and does not need)

* **Not** SSO, and **not** your console login.
* **Not** your personal access keys.
* A **dedicated read-only user or service account per provider**, whose credentials
  you put in a small YAML file and mount into the container.

The credentials are read by *your* deployment, on *your* infrastructure. There is no
vendor-side component that could see them — that is precisely why this feature is
offered on self-hosted and would not be offered on a hosted product.

### Step 1 — create a read-only identity

| Provider | What to create |
|---|---|
| **AWS** | An IAM user with the AWS-managed `ReadOnlyAccess` policy (or `SecurityAudit`, which is tighter). Generate an access key for it. |
| **GCP** | A service account with the `roles/viewer` role. Download its JSON key. |
| **Azure** | A service principal with the `Reader` role on the subscription. |
| **DigitalOcean** | A **read-only** personal access token (DO has a read-only toggle when creating one). |
| **Cloudflare** | An API token scoped to `Zone → DNS → Read`. |

**Give it read-only permissions.** The module only ever lists resources; it never
creates, modifies or deletes anything, so write access buys you nothing and costs you
blast radius if the file leaks.

### Step 2 — write the provider config

Create `cloudlist.yaml` (this is [cloudlist's](https://github.com/projectdiscovery/cloudlist)
own format — you can list as many providers as you like):

```yaml
- provider: aws
  id: production
  aws_access_key: AKIA...
  aws_secret_key: ...

- provider: gcp
  id: production
  gcp_service_account_key: '{"type": "service_account", ...}'

- provider: digitalocean
  id: production
  digitalocean_token: dop_v1_...
```

Protect it like any credential file:

```bash
chmod 600 cloudlist.yaml
```

### Step 3 — mount it and point the setting at it

In your `.env`:

```bash
EXACTSURFACE_CLOUDLIST_CONFIG=/etc/exactsurface/cloudlist.yaml
```

And in your compose override, mount it read-only into the worker:

```yaml
services:
  worker:
    volumes:
      - ./cloudlist.yaml:/etc/exactsurface/cloudlist.yaml:ro
```

Then enable **Cloud asset inventory** on the program's *Scan modules* panel. It is
opt-in and off by default, because it does nothing without credentials.

### Where the results appear

Two places, and the split is deliberate:

| What | Where | Why |
|---|---|---|
| Assets **covered by a domain you verified** | **Surface** tab, alongside everything else, tagged `cloudlist:<provider>` | They are now monitored like any other asset — probed, crawled, scanned on the next run |
| Assets your cloud account owns that **no verified domain covers** | **Findings** tab, as one Medium finding listing them | These are *not* scanned. Your provider confirming you own something answers **ownership**, not **authorisation** — see §8 |

That second row is usually the interesting one. An asset nobody attached a monitored
domain to is, more often than not, an asset nobody is watching. To bring them into
monitoring, add the relevant domain and verify it; nothing is scanned until you do.

> Filter the Findings tab by module `cloud_assets` to see them on their own.

### If it finds nothing

* Check the module is enabled and your tier includes it (Business and above).
* Watch the Activity tab during a run — the stage logs the providers it queried and
  says plainly when no config is set.
* Test the credentials outside the product: `cloudlist -config cloudlist.yaml -json`.

---

## 6. Day-2 operations

### 6.1 Backups — set this up on day one

Your findings history is valuable and your `.env` is irreplaceable.

```bash
# generate an encryption key pair (do this once, keep the identity file OFF this server)
age-keygen -o age-identity.txt          # keep this SAFE and ELSEWHERE
# put the public part in .env:
#   EXACTSURFACE_BACKUP_AGE_RECIPIENT=age1...

# take a backup
docker compose exec api python -m scripts.backup
```

Backups are **encrypted to a key this server cannot read** — so compromising the scanner
does not hand over your backup history. Schedule it nightly via cron.

**Test your restore.** A backup nobody has restored is a hypothesis:

```bash
python -m scripts.backup restore <archive>.age --identity ./age-identity.txt
```

Run that against a scratch database, not production.

Also back up: `.env`, and your licence token.

### 6.2 Upgrades

```bash
git pull                       # or fetch the new release
docker compose pull
docker compose up -d
```

Take a backup first. Read the release notes for anything flagged as breaking.

### 6.3 Scaling

Busy surface? Raise worker replicas in `docker-compose.yml`
(`worker.deploy.replicas`) **and set `EXACTSURFACE_WORKER_FLEET_SIZE` to the same
number.** They must match: the fleet-size value is what keeps the politeness rate limit
correct if Redis becomes unavailable. Setting it too low lets a degraded fleet scan
faster than intended and can get your IP blocked by your own providers.

### 6.4 Monitoring

Grafana is published on localhost only. Reach it over an SSH tunnel:

```bash
ssh -L 3001:127.0.0.1:3001 you@your-server
# then browse http://localhost:3001  (user: admin, password: GRAFANA_ADMIN_PASSWORD)
```

The operations dashboard and Prometheus datasource are pre-provisioned.

### 6.5 Logs

```bash
docker compose logs -f api
docker compose logs -f worker
docker compose logs -f scheduler
```

---

## 7. Your subscription

Your instance carries a cryptographically signed licence and checks it periodically. If
your instance can reach the control plane, renewals apply **automatically** — nothing to
do when you pay.

| State | What happens |
|---|---|
| **Active** | Everything works. |
| **Grace** (just after expiry) | Everything still works. You'll see an amber banner — renew now. |
| **Read-only** (past grace) | Scanning, adding domains, and the 403-bypass stop. **All your existing data stays fully visible and exportable.** Scheduled scans pause. |

Renewing restores full function automatically on the next check (about an hour), or
immediately if you restart the stack.

**Air-gapped?** You'll receive a new token each period instead; replace the file and it
applies on the next check.

**Keeping detections current matters.** Your instance pulls new detection templates from
the update feed while your subscription is active. An instance that can't reach the feed
keeps working but its detections gradually go stale — and a scanner using old detections
misses new CVEs. Don't firewall it off.

---

## 8. Your responsibilities

**Legal — read this one.**
- Only add domains you **own** or have **written authorisation** to test.
- ExactSurface performs active reconnaissance against the hosts you configure. You are
  responsible for having the right to do that.
- The verification and authorisation steps exist to protect you. Don't look for ways
  around them.
- This is a **detection-only** product. It does not exploit vulnerabilities.

**Security**
- Restrict inbound access (VPN or IP allowlist beats public exposure).
- `.env` and the licence token are secrets — `chmod 600`, never commit them.
- Rotate `EXACTSURFACE_JWT_SECRET` if you suspect compromise (this logs everyone out).
- Keep the host patched; apply ExactSurface updates promptly.
- Use permission groups — don't share the owner account.

**Operational**
- Backups configured **and a restore tested**.
- Monitor disk (scan data grows) and keep the server's clock synced via NTP — a clock
  that jumps backwards is treated as tampering and forces read-only.

---

## 9. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Stack won't start, complains about secrets | Defaults left in `.env`. Generate real `JWT_SECRET` / `SECRET_HASH_KEY`. |
| No TLS certificate | DNS A-record missing or not propagated; 80/443 blocked. Fix DNS, restart Caddy. |
| Red "read-only" banner | Subscription lapsed → renew. Or licence env unset/wrong. |
| Banner says clock tampering | Server clock moved backwards. Fix NTP, restart. |
| Scans never start | Program not verified/authorised, or the worker isn't running (`ps`, `logs worker`). |
| "No confirmed-dedicated hosts — ports withheld" | Expected. Your hosts are on shared/cloud infra, so intrusive checks are withheld. Enable "scan my cloud infra" only if you own it. |
| Scan is slow | By design — requests are rate-limited per target so scanning never looks like abuse. |
| Findings show but tiles look wrong | Refresh; counts update as the scan progresses. |
| A teammate can't sign up | Correct — public signup closes after the owner account. Add them under Settings → members. |
| Stuck on "verify your email" | Either configure SMTP, or leave `EXACTSURFACE_REQUIRE_EMAIL_VERIFICATION` unset (the default). |
| Stop button doesn't end the scan instantly | Expected — it winds the current step down cleanly, which can take up to a minute. |

---

## 10. Support

Contact your ExactSurface support address with:

- what you expected vs what happened,
- the relevant `docker compose ... logs` excerpt,
- your licence status from **Settings** (never send the token itself),
- your version (from the release you deployed).

**Supported:** product bugs, licence problems, detection questions, deployment guidance.
**Not supported:** your server/OS/network administration, your DNS and TLS, your database
operations, and authorisation to scan your targets.
