# ExactSurface — Owner & Maintainer Runbook

**Audience: you, the owner.** Not for customers — it contains the private-key handling,
the enforcement levers, and the support boundaries. The customer-facing document is
[`CLIENT_GUIDE.md`](CLIENT_GUIDE.md).

---

## 0. The model in one picture

```
YOU HOST (tiny, ~free)              THEY HOST (everything heavy)
┌────────────────────────┐          ┌──────────────────────────────────┐
│ control plane          │          │ frontend · API · workers         │
│  /v1/license/refresh   │◄─────────│ MongoDB · Redis · Caddy          │
│  /v1/updates/manifest  │  outbound│ all scanning, all their data     │
│  /bundles/*.tar.gz     │  calls   │ (never touches your infra)       │
└────────────────────────┘          └──────────────────────────────────┘
   + container images (GHCR)           + a signed licence token you issued
   + the Ed25519 PRIVATE key
```

You control three things and nothing else: **whether their licence renews**, **whether
they get fresh detections**, and **whether they can pull new images**. That is enough,
because a security scanner running stale detections is worthless within weeks.

**What you never have:** their attack-surface data, their findings, their traffic, their
compute bill, or liability for their scanning.

---

## 1. One-time setup (do this once, ever)

### 1.1 Generate your signing keypair — the single most important asset

> **How many keypairs do I need? Exactly ONE — for the whole product, forever.**
>
> Not one per customer. Not one per release. One keypair signs every licence you will
> ever issue, and its public half is baked into the single image that every customer
> runs. What is *per-customer* is the **licence token** you mint in §3.2 — that's the
> thing you generate again for each client and each renewal.
>
> You only ever generate a second keypair if the private key is compromised (§5.7),
> and that forces a rebuild + re-issue for everyone.

```bash
python -m scripts.license keygen --out-dir ~/exactsurface-keys   # ONCE, ever
```

- `private.pem` — **this is your revenue.** Anyone holding it can mint free, unlimited,
  never-expiring licences for your product.
- `public.pem` — verify-only, safe to bake into every image and hand to anyone.

**Back it up now, before you do anything else:**

- Keep the primary copy **offline** (encrypted USB, or a password manager's secure file).
- Keep one geographically separate copy (different building, or a sealed envelope).
- Never commit it, never put it in CI, never email it, never paste it into a chat.
- If you lose it: **every existing licence keeps working until it expires, but you can
  never issue or renew another one.** You would have to generate a new keypair, rebuild
  every image, and re-issue every customer. Treat losing it as a business-ending event
  and back it up accordingly.

> The control plane needs the private key to sign renewals, so it will live on that
> server too. That is the only machine besides yours that should ever hold it.

### 1.2 Container registry — use GHCR, not Docker Hub

The release workflow publishes to **GHCR** (`ghcr.io/<your-github-account>/api`,
`/frontend`, `/pipeline`). Nothing to set up: the three packages are created on the
first release, Actions authenticates itself, and there is **no registry secret to
manage**.

Why not Docker Hub: its free tier allows only **one private repo**, and we publish
three images. GHCR gives unlimited private packages on a free account.

Choose one access model:
- **Private packages** (recommended): invite each customer's GitHub account to the
  package (Package → Settings → Manage Actions/collaborators). Revoking that invite is a
  third enforcement lever alongside licence + updates.
- **Public packages**: simpler, no per-customer admin. Anyone can pull the image but
  **cannot run it without a licence**, so this is a reasonable choice too.

### 1.3 GitHub secrets

Repo → Settings → Secrets and variables → Actions — exactly one secret:

| Secret | Value |
|---|---|
| `LICENSE_PUBLIC_KEY` | contents of `public.pem` (the **public** one — never the private) |

### 1.4 Stand up the control plane

Any small VPS ($5/mo is plenty — it serves a few KB per customer per hour).

```bash
# on the control-plane server
git clone <your repo> exactsurface && cd exactsurface

# put the keypair where compose expects it
mkdir -p docker/cp-secrets
# copy private.pem + public.pem into docker/cp-secrets/ (scp, then shred the source)
chmod 600 docker/cp-secrets/private.pem

# ingress config
cat > docker/cp.env <<'EOF'
CP_DOMAIN=cp.exactsurface.com
ACME_EMAIL=you@exactsurface.com
EOF

# DNS: point cp.exactsurface.com A-record at this server FIRST (Caddy needs it for TLS)
docker compose -f docker/docker-compose.control-plane.yml up -d --build
curl -fsS https://cp.exactsurface.com/healthz     # → {"ok":true}
```

Firewall: allow 80/443 only. The control plane itself is never published directly.

### 1.5 Publish your first update bundle

```bash
nuclei -update-templates -silent
python -m scripts.build_bundle \
    --templates ~/nuclei-templates \
    --out ./cp-data \
    --base-url https://cp.exactsurface.com/bundles

# copy onto the control-plane volumes (names from `docker compose ps`)
docker cp ./cp-data/bundle-*.tar.gz    exactsurface-control-plane-caddy-1:/srv/bundles/
docker cp ./cp-data/bundle_manifest.json exactsurface-control-plane-control-plane-1:/data/
```

### 1.6 One-time setup checklist

- [ ] Keypair generated
- [ ] `private.pem` backed up **twice**, offline, verified readable
- [ ] `LICENSE_PUBLIC_KEY` secret set in GitHub (the public key — never the private)
- [ ] First release tagged, and the three GHCR packages exist + are pullable
- [ ] Control-plane server up, DNS pointed, TLS working, `/healthz` returns ok
- [ ] First bundle published and `GET /v1/updates/manifest` gated correctly
- [ ] `.env`-style secrets for the control plane are **not** in git

---

## 2. Cutting a release

The version lives in `pyproject.toml`, and CI refuses to release if the tag disagrees:

```bash
# 1. bump pyproject.toml → version = "0.2.0"
# 2. commit, tag, push
git commit -am "Release 0.2.0"
git tag v0.2.0
git push origin main --tags
```

The `Release` workflow then: runs the full test suite + lint + frontend build → builds
and pushes the `api`, `frontend` and `pipeline` images tagged `:0.2.0` and `:latest`
with your public key and the build id baked in → publishes a GitHub Release with the image digests.

Images go to **GHCR** (`ghcr.io/<your-github-account>/…`), not Docker Hub: the free
Docker Hub tier allows one private repo and we publish three images, while GHCR gives
unlimited private packages and needs no registry secret (Actions authenticates itself).
Give a customer access by inviting them to the package, or make the packages public —
they still cannot run the product without a licence.

### 2.1 Smoke-test the build before you tag (5 minutes, do it every time)

CI builds the images, but CI does not tell you whether the **licence stamp** actually
took effect inside the image. That is the one thing worth proving by hand, because if it
silently regressed every customer would get an unlicensed build:

```bash
docker build -f docker/Dockerfile.api \
    --build-arg BUILD_ID=1.0.0 \
    --build-arg GIT_COMMIT=$(git rev-parse --short HEAD) \
    --build-arg LICENSED_TO="Smoke Test" \
    -t es-smoke:api .

# 1. the build identity is baked in
docker run --rm es-smoke:api python -c "from core.build_info import summary; print(summary())"
#    → {'version': '1.0.0', ..., 'release': True, 'licensed_to': 'Smoke Test'}

# 2. THE IMPORTANT ONE — an env var must NOT be able to switch licensing off
docker run --rm -e EXACTSURFACE_LICENSE_ENFORCED=false es-smoke:api python -c "
from core.build_info import licence_enforced
from core.config import get_settings
assert licence_enforced(get_settings().license_enforced) is True, 'BYPASSED'
print('enforcement holds')"

docker rmi es-smoke:api
```

If step 2 prints anything other than `enforcement holds`, **do not tag the release** —
the subscription model is off for everyone who pulls it.

For the pipeline image, also confirm the toolchain and that the workbench stayed out:

```bash
docker build -f docker/Dockerfile.pipeline --build-arg BUILD_ID=1.0.0 -t es-smoke:pipe .
docker run --rm es-smoke:pipe sh -c 'command -v cloudlist arjun nuclei subfinder >/dev/null && echo tools-ok'
docker run --rm es-smoke:pipe sh -c 'test -d /app/devtools && echo LEAKED || echo devtools-absent-ok'
docker rmi es-smoke:pipe
```

**If the tag doesn't match `pyproject.toml`, the release fails on purpose** — that
mismatch is how customers end up on a build you can't identify.

---

## 3. Selling to a customer — the per-sale checklist

### 3.1 Before you take money

- [ ] **Contract signed.** The technical licence enforces the *dates*; the contract is
      what makes bypassing it actionable. Non-negotiable — see §7.
- [ ] Agree the **plan and domain count** (that's what you'll mint).
- [ ] Confirm they can meet the requirements in `CLIENT_GUIDE.md` §2 (a VM with 4 vCPU /
      8 GB / 100 GB, Docker, a domain name, outbound internet).
- [ ] Confirm **they own or are authorised to scan** the domains they intend to add.
      Get that in writing. This is the single biggest legal risk in the whole business.

### 3.2 Mint and register the licence

> **Pricing, every tier's limits, and how each one is enforced:
> [`PRICING_AND_LIMITS.md`](PRICING_AND_LIMITS.md).** Read it before you quote anyone.
> The short version: **domains are the price metric**, the licence states the number,
> and nothing on the customer's machine can raise it.

`--domains` and `--users` override the tier, so "Business but they need 40 domains" is a
licence you mint, not a code change or a new tier. `--features` adds individual optional
modules on top of the tier's set.

> **Unlimited is an omitted flag, never `0`.** A cap of zero allows *nothing* —
> `can_add_domain()` reads it as "fewer than zero domains", so the customer can never add
> one and only finds out after installing. Leave `--domains` off to get the tier's
> default, which is unlimited on `enterprise`. The CLI now refuses `0` outright, and the
> summary line it prints says either a number or the word `unlimited` — read it before
> you send the file.

```bash
python -m scripts.license issue \
    --private-key ~/exactsurface-keys/private.pem \
    --customer "Acme Corp" \
    --plan business \
    --domains 25 \
    --months 1 \
    --grace 14 \
    --store ./cp-data/licenses.json \
    --out acme.vlic

# always verify what you just minted before sending it
python -m scripts.license inspect --public-key ~/exactsurface-keys/public.pem "$(cat acme.vlic)"
```

Then sync the store to the control plane so renewals work:

```bash
docker cp ./cp-data/licenses.json exactsurface-control-plane-control-plane-1:/data/
```

Record in your own ledger (a spreadsheet is fine): customer, `license_id`, plan, domains,
paid-through date, contact email, invoice number.

### 3.2b Your own licence, for testing release images

A release image enforces licensing unconditionally — `RELEASE_BUILD` is stamped into
`core/build_info.py` at build time and `licence_enforced()` ignores every environment
variable once it is set. **That includes yours.** It has to: customers run the identical
image, so an owner-only escape hatch would be a customer-usable one.

So when you pull a published image to smoke-test it, you need a licence like anyone else.
Mint yourself one and keep it:

```bash
python -m scripts.license issue --private-key ~/exactsurface-keys/private.pem --customer "ExactSurface (internal)" --plan enterprise --months 120 --out ~/exactsurface-keys/owner.jwt
```

The token goes in `.env`, **not** in a shell variable — it has to survive restarts:

```bash
echo "EXACTSURFACE_LICENSE=$(cat ~/exactsurface-keys/owner.jwt)" >> .env
```

The verify key is a **build** arg, needed only when you build locally (GHCR images
already carry it, supplied by the release workflow):

```bash
LICENSE_PUBLIC_KEY="$(cat ~/exactsurface-keys/public.pem)" docker compose -f docker/docker-compose.yml up -d --build
```

Confirm it took — a licensed instance says so at startup:

```bash
docker compose -f docker/docker-compose.yml logs api | grep "license active"
```

> **Why `.env` and not `export EXACTSURFACE_LICENSE=…`?** Because the export lasts one
> terminal session. Compose's `environment:` outranks `env_file:`, so listing the licence
> there with a shell default means the next `docker compose up` or `restart` from a shell
> without the export overwrites the real licence with an empty string and drops a working
> deployment to read-only, with nothing in the logs to explain it. `.env` is read the same
> way every time, by every service, whoever runs the command.

If the banner persists, check what actually reached the container:
`docker compose exec api printenv EXACTSURFACE_LICENSE` should print the token and
`… printenv EXACTSURFACE_LICENSE_PUBLIC_KEY` a PEM block. A service compose reports as
`Running` rather than `Started`/`Recreated` did not pick up new environment at all.

Do **not** register this one with `--store`: it is not a sale and should not appear in the
control plane's ledger or your revenue count.

For day-to-day development, use the dev build instead — it is not stamped `--release`, so
enforcement follows `EXACTSURFACE_LICENSE_ENFORCED` and defaults to off. Needing a licence
locally is a sign you are running the customer image, which you only want when you are
deliberately checking the customer's experience.

### 3.2c The four steps, plainly

This is the whole customer flow, once a licence exists. Everything else in §3.2–§3.3 is
detail underneath these four steps:

1. **You mint their licence** (§3.2) — `python -m scripts.license issue …`.
2. **You give them the deployment bundle** — `exactsurface-<version>.tar.gz` from the
   GitHub release, or just the `deploy/` folder if you are handing it over directly. It
   is self-contained: compose file, `.env.example`, Caddy/Prometheus/Grafana config, and
   the guide. No source, no build step.
3. **They copy `.env.example` to `.env` and fill in the required values** — the licence
   token from step 1, `DOMAIN`, and the datastore/app secrets. `deploy/README.md` inside
   the bundle walks through every field.
4. **They run `docker compose up -d`.** That is the entire install.

Nothing else is required. If you find yourself telling a customer to run a fifth command,
something in the bundle needs fixing rather than the customer needing more instructions.

### 3.2d Do a dry run yourself before you ever ship to a real customer

Simulate the exact flow above, on your own machine, before the first real sale — this is
what actually found the gaps below.

```bash
mkdir ~/exactsurface-trial && cp -r deploy/* deploy/.env.example ~/exactsurface-trial/
cd ~/exactsurface-trial
cp .env.example .env
```

Fill in `.env`. Two things a real customer runs into that are easy to miss doing this
yourself:

> **Use `openssl rand -hex 24` for `MONGO_ROOT_PASSWORD` and `REDIS_PASSWORD` —
> never `openssl rand -base64`.** Both values go straight into a connection URI with no
> encoding, and base64's alphabet includes `+`, `/`, `=`, all URI-reserved. A password
> that happens to contain one breaks Mongo/Redis authentication with an error that never
> mentions the password — `docker compose logs api` just says "Authentication failed."
> This is not hypothetical; it is what broke the first real dry run of this bundle.

> **No real domain to test with?** Set `DOMAIN=localhost`. Caddy has a built-in special
> case for that exact hostname: it skips Let's Encrypt entirely and issues its own
> internal self-signed certificate, so the stack comes up with working HTTPS and no DNS
> needed. Your browser will show a certificate warning — click through it (this is Caddy
> talking to itself, not a real client ever seeing this warning on a real deployment,
> where DOMAIN is a real A-record and the certificate is trusted).

Then:

```bash
docker compose up -d
docker compose logs api | grep "license active"
```

If you changed `MONGO_ROOT_PASSWORD` or `REDIS_PASSWORD` **after** a first attempt already
initialised the database, `docker compose down` alone will not fix it — Mongo only
applies root credentials to a **fresh, empty** volume, so it keeps enforcing the old
(broken) password until the volume is wiped:

```bash
docker compose down -v      # only if nothing in it is worth keeping — check first
docker compose up -d
```

> **If you also run the dev stack (`docker/docker-compose.yml`) on the same machine**,
> confirm the two project names differ (`docker compose ls`). They must — Compose scopes
> containers, networks and volumes by project name, not by which file started them, so
> two compose files sharing a name are the same project as far as Docker is concerned.
> Bringing the dev stack up while a customer-bundle test is running under the same name
> would see those containers as its own, detect the service configs differ, and silently
> recreate them — tearing down whatever the other stack was doing. `docker/docker-compose.yml`
> is named `exactsurface-dev` and `deploy/docker-compose.yml` is named `exactsurface`
> specifically so this cannot happen; do not rename either back to match the other.

Open `https://your-domain` (or `https://localhost`), click **Create one**, and sign up —
this is the one step you do as the customer would, not as yourself: the first account
created becomes the org owner, and there is no seed account or default credential to
hand out. There is nothing to "log in" with until you create it.

### 3.3 What you hand over

Send these five things — nothing more, nothing less:

1. **The licence token** (`acme.vlic`) — treat as a credential; send over something
   better than plain email if you can.
2. **The deployment bundle** — `exactsurface-<version>.tar.gz`, attached to the GitHub
   release. This is the product as far as the customer is concerned: compose file,
   config, dashboards and the guide, pinned to the images of that release. It contains
   no source and needs no build. `CLIENT_GUIDE.md` ships inside it as `INSTALL.md`, so
   sending the bundle covers the manual too.
3. **Image access** — for private packages, an invite to the packages for their GitHub
   account. The bundle already names the images, so there is nothing to copy out.
4. **Their control-plane URLs** to put in `.env`:
   `EXACTSURFACE_LICENSE_REFRESH_URL=https://cp.exactsurface.com/v1/license/refresh`
   and `EXACTSURFACE_UPDATE_FEED_URL=https://cp.exactsurface.com`
5. **Support contact + hours**, and what's in scope (§6).

**Never send:** `private.pem`, your control-plane credentials, or another customer's
anything.

### 3.3b Accounts & email — what to tell them

This is the part that feels odd coming from multi-tenant SaaS, so state it plainly on
the call:

- **The first person to sign up on their instance becomes the owner** of the one
  organisation on that server. That's the whole account-creation flow.
- **After that, public signup is closed automatically.** A stranger who reaches their
  login page cannot create an account. Extra teammates are added by the owner under
  *Settings → members*, then placed in a permission group.
- **Email verification is OFF by default, and that's the right default here.** In
  multi-tenant SaaS it exists to stop strangers registering with addresses they don't
  own — but on a single-org, owner-provisioned instance there are no strangers, and
  owner-created members are marked verified already. Turning it on just means the
  instance needs working SMTP or nobody can log in.
- If a customer *wants* verification (some compliance regimes ask for it), they set
  `EXACTSURFACE_REQUIRE_EMAIL_VERIFICATION=true` **and** configure real SMTP. Tell them
  it's their SMTP to run, not yours.
- Email is still worth configuring for **alerts** even with verification off.

### 3.4 Onboarding call (30 minutes, worth doing)

- Watch them run the install end-to-end; fix env issues live.
- Walk the authorisation flow — verify domain → create authorization record → first
  scan. Make sure they understand the product **will not scan an unverified domain**,
  and why that protects them.
- Show where findings, the 403-bypass button, reports, and alerts live.
- Set expectations: first full scan takes a while; findings appear progressively.

---

## 4. Ongoing maintenance (you are the whole ops team)

| Cadence | Task | How |
|---|---|---|
| **Monthly** | Renew paying customers | §5.1 |
| **Monthly** | Suspend non-payers | §5.2 |
| **Weekly–monthly** | Publish a fresh template bundle | §1.5 (re-run) |
| **Weekly** | Check control-plane health | `curl https://cp.../healthz` |
| **On CVE/CVSS-high dep alerts** | Patch + release | §2 |
| **Quarterly** | Test-restore a backup | §5.6 |
| **Quarterly** | Verify your key backups are still readable | read `private.pem` from cold storage |
| **Yearly** | Renew the domain + review the contract | — |

### The one automation worth adding early

Uptime monitoring on `https://cp.exactsurface.com/healthz` (UptimeRobot's free tier is
fine). If the control plane is down for days, connected customers stop renewing and
eventually drop to read-only through no fault of their own — that's a support fire and a
refund conversation. **Grace periods exist to absorb this, but don't rely on them.**

### Control-plane backups

The only state is two small files:

```bash
docker cp exactsurface-control-plane-control-plane-1:/data/licenses.json ./backup-licenses-$(date +%F).json
```

Back that up wherever you keep business records. Losing it means renewals fail until you
rebuild it (you can, from your ledger + the tokens you issued).

---

## 5. Runbooks

### 5.0 Customer wants more domains (the most common upgrade)

Re-issue with the higher `--domains`, same `--customer-id`, and push the store to the
control plane. If they have `EXACTSURFACE_LICENSE_REFRESH_URL` set they pick it up on
the next refresh with no restart and no maintenance window — prefer this. Programs that
were over the old quota resume scanning on the next tick with their history intact.

Full walkthrough in [`PRICING_AND_LIMITS.md`](PRICING_AND_LIMITS.md) §4.

### 5.1 Customer paid — extend their subscription

Edit the store record's `paid_until`, then sync:

```bash
python - <<'PY'
from control_plane.store import LicenseStore
from datetime import datetime, timedelta, UTC
s = LicenseStore("./cp-data/licenses.json")
r = s.get("lic_XXXXXXXX")
r.paid_until = (datetime.now(UTC) + timedelta(days=31)).isoformat()
r.status = "active"
s.upsert(r)
print(r)
PY
docker cp ./cp-data/licenses.json exactsurface-control-plane-control-plane-1:/data/
```

Their instance picks up the renewed token on its next check (default hourly). Nothing for
them to do.

### 5.2 Customer didn't pay — stop them

```bash
python -c "
from control_plane.store import LicenseStore
s = LicenseStore('./cp-data/licenses.json'); print(s.suspend('lic_XXXXXXXX'))"
docker cp ./cp-data/licenses.json exactsurface-control-plane-control-plane-1:/data/
```

What happens: refresh returns 402, so their current token runs out its remaining days,
then the 14-day grace, **then** the instance goes read-only. Their data stays visible and
exportable — deliberately. Also stop serving updates (suspension does this automatically).

If you need it faster, mint short tokens (e.g. `--months 1` with `--grace 3`).

### 5.3 Offline / air-gapped customer

They have no control-plane access by design. Renewal = you mint a new token each period
and send it; they swap the file and it takes effect on the next check. They get no
automatic updates — ship them a bundle out-of-band, or price that in.

### 5.4 "Scanning stopped working"

Ask them to check, in order:

1. `GET /auth/license` (or the banner in the UI) → what does `status` say?
   - `expired` → billing issue, see 5.1
   - `missing`/`invalid` → their `EXACTSURFACE_LICENSE` env is wrong or unset
   - `tampered` → their server clock jumped backwards; fix NTP
2. Is the **worker** running? `docker compose ps`
3. Is the program **verified + authorised**? Unauthorised programs never scan (by design).

### 5.5 "We can't pull the images"

Private packages → their GitHub account isn't invited (or the invite lapsed); re-invite,
and have them `docker login ghcr.io` with a personal access token that has `read:packages`.
Either way, check they're using the right tag and platform — `pipeline` is **amd64-only**,
so it will not pull on an arm64 host (Apple silicon, Graviton).

### 5.6 Test-restore a backup (do this quarterly — untested backups aren't backups)

```bash
python -m scripts.backup restore ./backups/<file>.age --identity ~/age-identity.txt
```

Do it against a throwaway Mongo, not production. If you've never run it, you don't have
backups.

### 5.7 Private key compromised (or you suspect it)

This is the emergency. In order:

1. Generate a new keypair.
2. Update the `LICENSE_PUBLIC_KEY` GitHub secret; cut a new release so images carry the
   new key.
3. Re-issue every active customer a token signed by the new key.
4. Have each customer upgrade to the new image + new token (coordinate — old tokens stop
   verifying on the new build).
5. Rotate the control-plane copy of the key.

Every previously-issued licence becomes unverifiable on new builds, which is the point.

### 5.8 Control plane down

Customers keep working — that's what grace windows are for. Restore service, and if the
outage was long, extend affected customers' `paid_until` by the outage duration as
goodwill.

---

## 6. Support boundaries — decide these before your first customer

| You support | They own |
|---|---|
| Product bugs, licence issues, update feed | Their server, OS, Docker, network |
| "Is this finding real?" questions | Their MongoDB/Redis operations |
| Deploy guidance from `CLIENT_GUIDE.md` | Backups + restore (you provide the tooling) |
| Security patches to ExactSurface | Their TLS certs, DNS, firewall |
| — | **Authorisation to scan their targets** |

Put this table in the contract. As a solo operator, the fastest way to burn out is
accidentally becoming a customer's sysadmin.

---

## 7. Business hygiene (not code, but it's what makes this real)

- **A contract/EULA.** Must cover: licence grant (non-transferable, per-instance), the
  prohibition on reverse-engineering/removing licence checks, **the customer's warranty
  that they are authorised to scan the targets they configure**, liability caps, and
  termination. Get a lawyer for one hour; reuse forever. This is the single highest-value
  non-code item on your list.
- **An Acceptable Use Policy** — this product performs active reconnaissance against
  internet hosts. State plainly that scanning targets the customer doesn't own/isn't
  authorised for is a breach and grounds for immediate termination.
- **Invoicing** — Stripe (or Razorpay in India) invoices are enough at first. Manual
  renewal (§5.1) is fine for the first ~20 customers; automate only when it hurts.
- **Records to keep per customer:** signed contract, `license_id`, plan, paid-through,
  invoices, the domains they attested to owning.
- **Data-handling stance** — you hold no customer scan data (say this loudly; it's a
  selling point). You do hold their company name, contact, and licence metadata.

---

## 8. Pre-handover checklist (run every single time)

- [ ] Contract signed, authorisation-to-scan attested in writing
- [ ] Payment received / invoice issued
- [ ] Licence minted with the **agreed** plan + domain count, and `inspect`-verified
- [ ] Registered in `licenses.json` **and synced to the control plane**
- [ ] Recorded in your ledger
- [ ] Image access confirmed working (have them pull once before the call)
- [ ] Sent: token, `CLIENT_GUIDE.md`, image access, control-plane URLs, support contact
- [ ] Onboarding call booked
- [ ] Control plane healthy at handover time
