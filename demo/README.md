# ExactSurface demo site — public, read-only, no backend

**Not part of the product.** One of the two things the maintainer hosts: the project site
and this demo. Everyone else self-hosts the real thing.

```bash
docker build -f demo/Dockerfile -t exactsurface-demo .
docker run --rm -p 3000:3000 exactsurface-demo
```

Sign in with anything — the login screen is real, but there is nothing behind it.

## What this is

The **real frontend**, with exactly one file replaced at build time:
`frontend/lib/transport.ts`, the module every API call passes through. The demo version
returns static fixtures instead of making HTTP requests.

```
frontend/lib/api.ts        ← types + every endpoint, UNCHANGED
        ↓ imports
frontend/lib/transport.ts  ← swapped for demo/lib/transport.ts in demo/Dockerfile
        ↓ reads
demo/lib/fixtures.ts       ← the entire "backend"
```

Two properties fall out of that, and both were the point:

**There is no backend to secure.** No database, no API, no auth to bypass. Read-only is
not a rule that could be misconfigured — there is nowhere for a write to go. Mutating
calls resolve to a friendly refusal object so the UI stays pleasant while doing nothing.

**The demo cannot drift from the product.** No copied pages, no second component tree.
If a component starts calling a new endpoint, the demo logs `[demo] no fixture for …`
and we add one — rather than the demo silently becoming a museum piece.

## It must never enter a product image

* `docker/Dockerfile.frontend` copies `frontend/` only and never mentions `demo/`.
* `.dockerignore` lists `demo`.
* `tests/unit/test_wiring.py` asserts no product Dockerfile references `demo/`, and
  that none uses `COPY . .` (which would sweep it in).

## Deploy to Vercel

Docker (above) works anywhere. To deploy without a container, on Vercel:

1. [vercel.com/new](https://vercel.com/new) → import this repo.
2. **Root Directory**: `frontend` — Vercel's Next.js auto-detection needs
   `package.json` and `next.config.mjs` at the project root it's given, and those live
   in `frontend/`, not `demo/`.
3. **Build Command**, override to perform the same swap the Dockerfile does before
   building:
   ```
   cp ../demo/lib/fixtures.ts ../demo/lib/transport.ts lib/ && npm run build
   ```
   (Paths are relative to Root Directory, so `../demo/lib/` reaches this folder — the
   full repo is checked out regardless of Root Directory, only the build's working
   directory changes.)
4. **Install Command**: leave as default (`npm ci`).
5. Nothing else. The frontend ships `noindex` by default — a self-hosted dashboard must
   never be crawlable — and recognises a Vercel build (`VERCEL=1`, set automatically) as
   the demo, which is the one deployment that *should* be found. Elsewhere,
   `NEXT_PUBLIC_INDEXABLE=1` at build time is the explicit opt-in.
5. No environment variables needed — there is no backend to point at.
6. Deploy. The Vercel URL is the demo; no custom domain is needed.

This is dashboard configuration, not a checked-in `vercel.json` — deliberately, so
`frontend/` (which *does* ship inside the real product image) stays free of any
Vercel-specific file. Re-apply these settings if the Vercel project is ever recreated.

## Refreshing the data

`demo/lib/fixtures.ts` is a plain TypeScript module — edit it directly, or regenerate
it. It is deliberately checked in rather than generated at build time so that what the
demo shows is reviewable in a diff.

The data is fictional and confined to `demo.exactsurface.com`. Keep it that way: a demo
displaying findings against a real third party would be exactly the thing this product
exists to warn people about.
