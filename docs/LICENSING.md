# Vantari licensing — operating the self-hosted subscription

Vantari ships as an image the customer runs in **their own** infrastructure, on a monthly
subscription. This document is how you, the vendor, issue and enforce that subscription.

## How it works (and its honest limits)

Each running instance verifies a **cryptographically signed license** (Ed25519) against a
public key baked into the image. You hold the private key and mint licenses; the customer
cannot forge one, change the expiry, or raise their domain cap — the signature won't
verify. When the subscription lapses **past its grace window**, the instance drops to
**read-only** (fail-closed): scanning, 403-bypass and adding domains are refused
server-side (HTTP 402), while existing findings stay viewable and exportable.

What this **does** stop: every non-developer bypass — forging, date-editing, clock
rollback (detected via a persisted high-water-mark), running with no license. What it
**cannot** stop: an engineer with the source and root on their own box patching the check
out and rebuilding. No self-hosted product prevents that. Your real backstops:

1. **The license contract** — bypassing it is a breach you can act on.
2. **The update stream** — new Nuclei templates, tool binaries, CVE feeds and patched
   images are served from *your* infra, gated on a valid subscription. A security product
   running stale detections is worthless within weeks, so renewal is self-enforcing. This
   is the enforcement that actually holds; treat it as the primary one.

## One-time setup (you)

```bash
# Generate your signing keypair — do this ONCE, keep private.pem offline & backed up.
python -m scripts.license keygen --out-dir ./license-keys
```

Bake `license-keys/public.pem` into the image you distribute (it can only verify, never
mint — safe to ship), by setting `VANTARI_LICENSE_PUBLIC_KEY` at build time.

## Issuing a subscription (you)

```bash
python -m scripts.license issue \
    --private-key ./license-keys/private.pem \
    --customer "Acme Corp" --plan business --domains 25 --months 1 --grace 14 \
    --out acme.vlic

# verify what you minted
python -m scripts.license inspect --public-key ./license-keys/public.pem "$(cat acme.vlic)"
```

Plans map to the existing `core/plans.py` tiers (`free`/`pro`/`business`/`enterprise`);
`--domains` overrides the tier default (omit for unlimited on enterprise). `--months`
sets the paid period; `--grace` is the post-expiry window that stays fully functional
before read-only kicks in.

## Deploying at the customer

The instance is configured entirely by environment variables (or a mounted license file):

| Env var | Meaning |
|---|---|
| `VANTARI_LICENSE_ENFORCED` | `true` in every customer deployment. `false` (default) disables gating — dev/self-serve only. |
| `VANTARI_LICENSE_PUBLIC_KEY` | Your Ed25519 public key (PEM). Bake into the image. |
| `VANTARI_LICENSE` | The license token, or… |
| `VANTARI_LICENSE_FILE` | …a path to a file containing it (mount a secret). |
| `VANTARI_LICENSE_REFRESH_URL` | *(hybrid, optional)* your license server — the instance periodically pulls a renewed token from here. Omit for pure-offline / air-gapped. |
| `VANTARI_LICENSE_CHECK_INTERVAL_SECONDS` | How often the instance re-evaluates the clock and refreshes (default 3600). |

Enforcement is server-side and multi-point (the scan/add-domain/403-bypass routes **and**
the scheduler/worker), so a patched frontend cannot re-enable scanning.

## Renewal

- **Offline:** mint a new token with a later `--expires`/`--months` and hand it to the
  customer (new env value or replace the mounted file). It takes effect on the next
  license check — no restart needed.
- **Hybrid (online refresh):** run a small license server at `VANTARI_LICENSE_REFRESH_URL`.
  Each instance periodically calls it:

  ```
  POST {refresh_url}
  → { "token": "<the instance's current token, or null>" }
  ← { "token": "<a freshly-signed license>" }        # 200 to renew
  ← 4xx                                                # decline (no change)
  ```

  The returned token is **verified against your public key before it's trusted**, so the
  refresh endpoint can extend a subscription but can never inject entitlements it didn't
  sign. Persisted in the instance's DB, so it survives restarts. This is how you deliver
  true monthly renewals (and revocation, by declining) to connected customers while
  air-gapped ones stay on the offline flow.

## What read-only actually blocks

| Action | Active / Grace | Read-only (expired past grace) |
|---|---|---|
| View findings, assets, ports, reports, export | ✅ | ✅ |
| Log in, see license status | ✅ | ✅ |
| Run a scan / 403-bypass | ✅ | ❌ 402 |
| Add a domain | ✅ | ❌ 402 |
| Scheduled/automated scans | ✅ | ❌ skipped |

The customer never loses visibility of their attack surface — a security tool going fully
dark is dangerous — but it stops *advancing* until they renew.

## Security notes

- The **private key is your revenue** — keep it offline, backed up, never in a repo or image.
- Rotating the keypair invalidates every issued license; only do it on compromise, and
  re-issue all customers.
- The clock-rollback guard tolerates ~6h of skew (NTP), then treats a backward jump below
  the recorded high-water-mark as tampering → read-only.
