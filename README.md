# ExactSurface — project site

Static HTML, no build step, no framework. `index.html` is the entire site.

**This branch carries only the site.** It is an orphan branch: it shares no history with
`main` and contains none of the product. That keeps a page nobody deploys out of every
clone of the source, and gives GitHub Pages a branch root to serve directly.

## Deploying

GitHub Pages, from this branch's root:

*Settings → Pages → Source: "Deploy from a branch" → Branch: `site` / `/ (root)`*

Any static host works just as well — there is nothing to build. Point a custom domain at
it by adding a `CNAME` file here containing the domain, and setting the DNS record.

## Editing

Everything — copy, the capability list, the comparison table — is real text in
`index.html`, not generated. Nothing wires it to the product automatically, because the
site is deliberately dependency-free, so when either changes keep it in sync by hand
with `docs/PRICING_AND_LIMITS.md` and `core/modules.py` on `main`.

`logo.png` and `favicon.png` are copies of `frontend/public/logo.png` and
`frontend/app/icon.png` on `main` — re-copy them if the brand mark changes.

## Making a change

```bash
git checkout site        # nothing from main is here; that is intentional
# edit index.html
git commit -am "..." && git push origin site
```
