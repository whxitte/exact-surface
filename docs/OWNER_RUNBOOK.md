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

### 3.3 What you hand over

Send these five things — nothing more, nothing less:

1. **The licence token** (`acme.vlic`) — treat as a credential; send over something
   better than plain email if you can.
2. **[`CLIENT_GUIDE.md`](CLIENT_GUIDE.md)** — their complete deploy + operate manual.
3. **Image access** — the GHCR image names, plus (for private packages) an invite to
   the packages for their GitHub account.
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
2. Is the **worker** running? `docker compose -f docker/docker-compose.prod.yml ps`
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
