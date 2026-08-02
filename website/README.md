# exactsurface.com — marketing site

Static HTML, no build step, no framework. `index.html` is the entire site.

**Not part of the product.** One of the three things the vendor hosts (marketing site,
the demo, the control plane); customers run the real product themselves. Never referenced
by any product Dockerfile — see `tests/unit/test_wiring.py`.

## Deploy to Vercel

1. [vercel.com/new](https://vercel.com/new) → import this GitHub repo.
2. **Root Directory**: `website`
3. **Framework Preset**: Other (Vercel serves it as static files — no build command,
   no install command, nothing else to set).
4. Deploy. Point `exactsurface.com` at the project in Vercel's domain settings.

## Editing

Everything — copy, pricing, capability list — is real text in `index.html`, not
generated. Keep the pricing table in sync with
[`docs/PRICING_AND_LIMITS.md`](../docs/PRICING_AND_LIMITS.md) and the capability list
with [`core/modules.py`](../core/modules.py) when either changes; nothing wires them
together automatically since this site is intentionally dependency-free.

`logo.png` / `favicon.png` are copied from `frontend/public/logo.png` and
`frontend/app/icon.png` — re-copy them here if the brand mark ever changes.
