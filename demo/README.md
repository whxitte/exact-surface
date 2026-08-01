# ExactSurface demo site — public, read-only, no backend

**Not part of the product.** One of the three things the vendor hosts: the marketing
site, this demo, and the control plane. Customers run the real product themselves.

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

## Refreshing the data

`demo/lib/fixtures.ts` is a plain TypeScript module — edit it directly, or regenerate
it. It is deliberately checked in rather than generated at build time so that what the
demo shows is reviewable in a diff.

The data is fictional and confined to `demo.exactsurface.com`. Keep it that way: a demo
displaying findings against a real third party would be exactly the thing this product
exists to warn people about.
