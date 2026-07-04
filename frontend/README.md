# Vantari Frontend

Next.js 14 (App Router) + Tailwind. Dark-first security dashboard. Talks to the
FastAPI backend through the `/api/*` proxy (see `next.config.mjs`), so no CORS in dev.

## Run

```bash
npm install
cp .env.example .env          # point API_PROXY_TARGET at the backend
npm run dev                   # http://localhost:3000
```

Start the backend first (`make api` in the repo root → :8000).

## Screens
- `(auth)/login`, `(auth)/signup` — JWT auth (token in localStorage)
- `overview` — severity breakdown + asset/finding/secret counts
- `programs` — list + add domain
- `programs/[id]` — verification wizard, authorize, scan, and tabs for
  findings / assets / secrets / timeline
- `findings` — cross-program triage with severity filters
- `settings` — account + API-key issuance (shown once)

## Design
Tokens live in `app/globals.css` (zinc canvas, emerald accent) and
`tailwind.config.ts` (severity color scale). Components in `components/ui`.
