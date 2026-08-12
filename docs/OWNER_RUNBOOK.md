# ExactSurface — Owner & Maintainer Runbook

**Audience: you, the owner.** Not for customers — it contains the private-key handling,
the enforcement levers, and the support boundaries. The customer-facing document is
[`CLIENT_GUIDE.md`](CLIENT_GUIDE.md).

---

## 0. The model in one picture

```
YOU DELIVER                          THEY HOST (everything)
┌────────────────────────┐          ┌──────────────────────────────────┐
│ Container images       │─────────►│ frontend · API · workers         │
│ deploy/ bundle         │          │ MongoDB · Redis · Caddy          │
│ software updates       │          │ all scanning, all their data     │
└────────────────────────┘          │ (never touches your infra)       │
                                    └──────────────────────────────────┘
```

**What you never have:** their attack-surface data, their findings, their traffic, their
compute bill, or liability for their scanning.

**Self-Hosted Architecture:** The customer's instance runs completely self-contained on their own infrastructure. The software carries no domain limits, seat caps, scan quotas, or license key checks.

---

## 1. One-time setup (do this once, ever)

### 1.1 Container registry — GHCR

The release workflow publishes to **GHCR** (`ghcr.io/<your-github-account>/api`, `/frontend`, `/pipeline`).

Choose one access model:
- **Private packages** (recommended): invite each customer's GitHub account to the package.
- **Public packages**: simpler, no per-customer invitation admin.

### 1.2 GitHub Actions secrets

Set in repo settings (**Settings → Secrets and variables → Actions**):

| Secret | Value |
|---|---|
| `DOCKER_HUB_TOKEN` | (optional if using Docker Hub) PAT with read/write access |

--- | contents of `public.pem` (the **public** one — never the private) |

### 1.4 One-time setup checklist

- [ ] `LICENSE_PUBLIC_KEY` secret set in GitHub (if needed for release signature verification)
- [ ] First release tagged, and the product GHCR packages exist + are pullable
- [ ] `.env`-style secrets for production are **not** in git

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

### 3.2 Software Delivery

Once the client pays directly, hand over the built container images or `deploy/` bundle. The software runs **100% free for life** on the client's infrastructure with unlimited domains, unlimited seats, unlimited scans, and all 28+ modules unlocked out of the box.

Record in your own ledger (a spreadsheet is fine): customer name, contact email, invoice number, delivery date.
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
docker compose ps
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
4. **Support contact + hours**, and what's in scope (§6).

**Never send:** internal credentials or another customer's data.

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

## 4. Ongoing maintenance

| Cadence | Task | How |
|---|---|---|
| **On CVE/CVSS-high dep alerts** | Patch + release | §2 |
| **Quarterly** | Test-restore a backup | §5.6 |
| **Yearly** | Review contract and updates | — |

---

## 5. Operations & Customer Delivery

### 5.1 Customer Delivery Flow

1. Receive payment directly from the client.
2. Provide the container images or `deploy/` bundle.
3. The client deploys the stack on their server (`docker compose up -d`).
4. The client gains **100% free, unrestricted access** for life with unlimited domains, users, scans, and all 28+ modules unlocked.

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
- [ ] Recorded in your ledger
- [ ] Image access confirmed working (have them pull once before the call)
- [ ] Sent: `CLIENT_GUIDE.md`, image access, support contact
- [ ] Onboarding call booked
