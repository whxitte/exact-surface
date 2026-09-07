# FAQ and local-instance recipes

Questions that keep coming up, and the two recipes worth having written down. For the
full end-to-end walkthrough see [`TESTING.md`](TESTING.md); for the control model see
[`SECURITY.md`](SECURITY.md).

---

## Resetting a local instance to zero

### 1 · Wipe everything

From the repo root:

```bash
docker compose -f docker/docker-compose.yml down -v
```

The `-v` is the part that matters: it deletes the named volumes (`mongo_data`,
`redis_data`, `grafana_data`, …), so every tenant, program, finding and scan is gone.
Containers and networks go with them. Add `--rmi local` if you also want the images
rebuilt from scratch.

### 2 · Bring it back up

```bash
docker compose -f docker/docker-compose.yml up --build -d
docker compose -f docker/docker-compose.yml ps    # wait for mongo/redis to be "healthy"
```

`--build` picks up code changes. Give it 30–60 seconds.

### 3 · Sign up and add a program

Open http://localhost:3000, create an account — the first one becomes the instance
owner — then **Programs → add the domain you control**. Stop there; do not try to verify
in the UI. Email verification is off in dev by default. If you set
`EXACTSURFACE_REQUIRE_EMAIL_VERIFICATION=true`, the link is printed in the API logs:

```bash
docker compose -f docker/docker-compose.yml logs api | grep verify
```

---

## Skipping DNS verification on a local instance

> **Only ever do this for a domain you actually own, on your own instance.** Domain
> verification is the control that stops ExactSurface from scanning someone else's
> property. Bypassing it for a domain you do not control is precisely the abuse the
> whole authorisation chain exists to prevent — and it is illegal in most places.

This flips a program to verified and writes a current authorization record — exactly
what the normal flow produces, minus the DNS TXT check. It runs inside the `api`
container, so the model shapes are guaranteed to match the code.

```bash
docker compose -f docker/docker-compose.yml exec api python - <<'PY'
import asyncio
from db.mongo import get_mongo
from db.programs import ProgramRepo
from db.authorizations import AuthorizationRepo
from core.models import Authorization

DOMAIN = "example.com"   # <- a domain YOU control

async def main():
    m = get_mongo(); await m.connect()
    progs = await ProgramRepo.from_mongo(m).list_all()
    match = [p for p in progs if p["apex_domain"] == DOMAIN]
    if not match:
        print(f"!! add {DOMAIN} in the UI first"); return
    p = match[0]; tid, pid = p["tenant_id"], p["program_id"]
    await ProgramRepo.from_mongo(m).set_verified(tid, pid, True)
    await AuthorizationRepo.from_mongo(m).save(Authorization(
        tenant_id=tid, program_id=pid, authorized_by="dev-bypass", apex_verified=True))
    print(f"OK — {pid} is now verified + authorized")

asyncio.run(main())
PY
```

Reload the program in the UI — it now shows **Verified**. Either click **Scan**, or wait:
the scheduler's bootstrap tick enqueues the first full run automatically, because a
program that has never completed a run is due immediately.

Watch it from the **Activity** tab, or:

```bash
docker compose -f docker/docker-compose.yml logs -f worker
```

**Two things to expect, so they do not look like bugs:**

- Port scanning and content discovery will most likely skip with *"no confirmed-dedicated
  hosts."* That is correct. Those only run on IPs confirmed as yours via asnmap (§9b),
  which the DNS bypass does not do. Probe, crawl, safe nuclei and secrets all still run
  over HTTP.
- This is a **real scan hitting the domain over the network**, rate-limited to 10 req/s
  per target.

---

## Questions

### Where is email used, and why is there no setting for it?

Signup email verification only — the confirm-your-address link. It is configuration, not
a UI setting, which is why it is not in the app. In dev,
`EXACTSURFACE_EMAIL_TRANSPORT=log` prints the link to the API logs and needs no provider.
For real mail, set `smtp` plus any provider's SMTP credentials in `.env`.
"Provider-agnostic" means it speaks plain SMTP, so Resend, Brevo and SES all work.
Nothing needs configuring to test scanning.

### Tech-aware nuclei — does targeting templates lose generic findings?

No. The safe baseline still runs in full: `exposure`, `misconfig`, `tech`, `ssl`, `cve`,
`default-login`. TLS expiry, generic misconfigurations and CVEs are all still covered.
Technology tags are added *on top* — a WordPress host also gets WordPress templates. It
is strictly more coverage, never less. Only the aggressive run, on confirmed-dedicated
infrastructure, uses the full library.

### Where is the ASN mapper in the pipeline? I don't see a stage for it.

It is not a visible stage. It runs inside authorization confirmation
(`confirm_authorization_ip_scope`), before scanning — which is why it has no entry in the
stepper.

### What stops someone pointing `x.theirdomain.com` at any IP, declaring a `/24` dedicated, and scanning third-party infrastructure?

The ASN check above. A client only ever *requests* CIDRs, and they are recorded as
**unconfirmed** — HTTP-layer probing only. Before each scan the worker runs asnmap
against the verified apex's real announced ASN, and promotes a CIDR to *dedicated* only
if it genuinely falls within that ASN's ranges. Self-attestation never unlocks aggressive
scanning.

This is also why a scan of a CDN-fronted domain reports *"no confirmed-dedicated hosts —
ports/content withheld (§9b)"*: the domain sits on shared infrastructure, so port
scanning, content discovery and active nuclei are correctly withheld. To scan your own
cloud infrastructure, enable **Scan my cloud infra** (`scan_shared_infra`) on the
program — only because you own it.

### What is `nuclei_watch`?

It baselines which nuclei templates currently match your stack, then alerts when a *new*
template starts matching — for example when a freshly published CVE template begins
firing on one of your hosts. It is opt-in because its template-lister contract is not
verified against the pinned binary.

### Grafana — credentials and configuration?

http://localhost:3001, `admin` / `admin` in dev (set `GRAFANA_ADMIN_PASSWORD` to change
it). Nothing to configure: the Prometheus datasource and the "ExactSurface — Operations"
dashboard are auto-provisioned. Panels populate during a scan — the worker and scheduler
are scraped on `:9100`.
