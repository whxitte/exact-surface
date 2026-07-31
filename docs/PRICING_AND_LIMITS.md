# Pricing, plan limits, and how they are enforced

The single reference for the commercial model: what each tier includes, where every
limit is enforced in code, and how to sell an upgrade. Read alongside
[`OWNER_RUNBOOK.md`](OWNER_RUNBOOK.md) (the selling process) and
[`SECURITY.md`](SECURITY.md) §10 (our own attack surface).

---

## 1. The tiers

| | **Free / Trial** | **Pro** | **Business** | **Enterprise** |
|---|---|---|---|---|
| **Domains** | 1 | 5 | 25 | unlimited |
| **Users** | 1 | 3 | 15 | unlimited |
| **API keys** | 1 | 3 | 10 | unlimited |
| **Fastest re-scan** | daily | every 6h | hourly | every 15 min |
| **History kept** | 30 days | 180 days | 1 year | 3 years |
| **On-demand 403 bypass** | — | ✓ | ✓ | ✓ |
| **Scheduled reports** | — | ✓ | ✓ | ✓ |
| **Optional modules** | none | TLS, service fingerprint, hidden parameters | + lookalike domains, cloud buckets, cloud asset inventory, template watch, dorking, internet-index search | all, including any added later |

The always-on modules — subdomain discovery, probing, crawling, content discovery, JS
mining, API surface, CORS/redirect/WAF, takeover, nuclei, secrets, CVE watch, GitHub
leaks, broken links, dependency confusion, domain intelligence, correlation and alerting
— are in **every** tier including Free. Tiers differ on **scale** (domains, users), on
**speed** (re-scan frequency), on **memory** (retention), and on the handful of modules
that are costly or need a key.

That is deliberate. Gating the core detection behind a paywall would mean shipping a
customer a scanner that deliberately misses things, and telling them so only in a
pricing table.

### Selling by quantity

The two axes customers actually negotiate are **domains** and **users**, so a licence
states them explicitly and overrides its tier:

```bash
# "Business, but they have 40 domains"
python -m scripts.license issue --plan business --domains 40 --users 15 ...

# "Pro, plus cloud-bucket scanning"
python -m scripts.license issue --plan pro --features cloud_buckets ...
```

No new tier, no code change. `--features` adds to the tier's module set rather than
replacing it.

> **Domains are the primary price metric.** A customer with one domain pays the base
> rate; each additional block of domains is more. The licence is where that is
> recorded, and it is the only place that counts.

---

## 2. Where each limit is enforced

Every limit below is checked in code. A limit that exists in a table but is never
checked is worse than no limit at all: it reads as enforced when it is not.

| Limit | Enforced in | When |
|---|---|---|
| `max_domains` | `api/routes/programs.py` (create) **and** `taskqueue/scheduler.py` (enqueue) | Both, deliberately — see below |
| `max_users` | `api/routes/members.py` | On member create |
| `max_api_keys` | `api/routes/members.py` | On key create |
| `min_scan_interval_seconds` | `taskqueue/cadence.py` | Applied to shipped defaults *and* user overrides |
| `retention_days` | retention job | On the scheduled purge |
| `optional_modules` | `core/modules.py::resolve` | Every path — settings screen, orchestrator, scheduler, dispatch |
| `on_demand_bypass` | `api/routes/programs.py` | On the 403-bypass trigger |

**Why `max_domains` is checked twice.** Creation is the friendly check — the user gets a
clear 402 instead of a surprise. Enqueue is the *authoritative* one: it means a
downgrade takes effect on the next scheduler tick without anyone deleting data. The
excess programs stay in the database, stop being scanned, and resume if the customer
upgrades. Nothing is destroyed by a billing event.

**Why the module gate lives in `resolve()`.** That is the one function every path
already calls. Putting the check at the API edge would leave the scheduler and the
event cascade unguarded, which is exactly the class of bug that let disabled modules
keep running before.

---

## 3. Where the authority comes from — the part that matters

This is a **self-hosted** product. The customer owns the machine, the database, the
environment variables and the container. Any limit anchored to something they control is
decorative. Two rules follow.

### 3.1 The signed licence is the sole authority

Limits come from the Ed25519-signed licence token and **nothing else**. The tenant's
stored `plan` field is ignored entirely whenever a licence is present.

Not intersected with it — *ignored*. Leaving a customer-controlled value anywhere in the
decision is all a bypass needs, in either direction.

```
db.tenants.updateOne({}, {$set: {plan: "enterprise"}})   ← buys nothing
```

Only the holder of the private key (you) can mint a licence, so `max_domains` cannot be
raised on the customer's side at all. Asserted by
`test_stored_plan_cannot_raise_a_limit_above_the_licence`.

### 3.2 Enforcement is baked into the image, not configured

Enforcement used to hang off `EXACTSURFACE_LICENSE_ENFORCED`, an ordinary setting — so
`docker run -e EXACTSURFACE_LICENSE_ENFORCED=false` switched the whole subscription off.

`core/build_info.py` is now stamped at build time by `scripts/stamp_build.py`. A release
image enforces **because of what it is**; the setting only has effect in a source
checkout. No environment variable can disable a release build.

### 3.3 What this does not claim

An engineer with the source and root on their own machine can patch the check out and
rebuild. **No self-hosted product prevents that**, and claiming otherwise would be
dishonest. What the design achieves is moving the bypass from *"set an environment
variable"* — which a customer can do by accident — to *"fork the product and maintain
your own build"*, which is a deliberate act with three real consequences:

1. **The licence contract** — breach is a legal matter, and the image is watermarked to
   the customer (`build_info.LICENSED_TO`), so a leaked build says whose it was.
2. **The update stream** — new nuclei templates, tool versions and detections come from
   your control plane, gated on a valid licence. A security scanner running
   three-month-old templates is worthless, so renewal is largely self-enforcing.
3. **Support** — a patched build gets none.

That combination, not the code, is what makes people pay. The code's job is to make
*not* paying a conscious decision rather than an accident.

---

## 4. Runbook: changing what a customer has

### Sell more domains (mid-term upgrade)

```bash
python -m scripts.license issue \
    --private-key ~/exactsurface-keys/private.pem \
    --customer "Acme Corp" --customer-id cus_acme \
    --plan business --domains 40 --users 15 \
    --months 1 --grace 14 \
    --store ./cp-data/licenses.json --out acme.vlic

python -m scripts.license inspect --public-key ~/exactsurface-keys/public.pem "$(cat acme.vlic)"
docker cp ./cp-data/licenses.json exactsurface-control-plane-control-plane-1:/data/
```

The customer either restarts with the new token, or — if they have
`EXACTSURFACE_LICENSE_REFRESH_URL` set — picks it up automatically on the next refresh
without touching anything. **Prefer the refresh path**: it makes an upgrade a
conversation rather than a maintenance window.

The new domains become addable immediately. Programs already created but over the old
quota start being scanned again on the next scheduler tick, with their history intact.

### Downgrade

Mint a licence with the lower numbers. On the next tick the scheduler stops scanning the
excess programs, oldest-first-kept, deterministically. **Nothing is deleted.** The
customer sees the same programs kept on every tick rather than a shifting subset, and
everything returns if they upgrade again.

### Add a single module without moving tier

```bash
--features cloud_buckets,typosquat
```

### Trial

```bash
--plan pro --domains 2 --months 0.5 --grace 0
```

`--grace 0` matters for a trial: you want it to stop, not linger.

---

## 5. What happens when a subscription lapses

| State | Behaviour |
|---|---|
| **Active** | Everything works |
| **Expired, within grace** | Everything still works. A banner warns. Grace exists so a late invoice never silently kills a security team's monitoring |
| **Past grace** | **Read-only.** No scans start, no domains can be added, no 403-bypass. All existing data stays visible and exportable |
| **Missing / invalid / tampered clock** | Same as past grace — fail closed, never open |

Read-only rather than data deletion is a deliberate choice. Holding a customer's
security findings hostage would be a poor thing to do, and a worse thing to be known
for. They keep what they have paid for; they stop getting new work.
