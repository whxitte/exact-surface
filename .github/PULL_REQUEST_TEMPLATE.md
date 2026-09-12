## What and why

<!-- What the change does is readable from the diff. Why you chose this — the constraint,
     the alternative you rejected, the bug it closes — is not, and is the part that matters
     in six months. Link the issue if there is one. -->

## Checklist

- [ ] `make test && make lint` pass (lint is `ruff check` **and** `ruff format --check`, exactly what CI runs)
- [ ] `cd frontend && npx tsc --noEmit && npx next lint` pass, if the frontend changed
- [ ] New behaviour has a test — and for anything cross-cutting, a test that asserts the *relationship*, not just the function
- [ ] If a component calls a new endpoint, `demo/lib/fixtures.ts` has a fixture for it (otherwise the demo logs `[demo] no fixture for …`)
- [ ] If this adds or renames a module: it is in all seven registries, and `tests/unit/test_wiring.py` is green without edits to the assertions
- [ ] `CHANGELOG.md` has an entry under *Unreleased*, if a user would notice the change

## If this touches a safety control

<!-- Scope engine, DNS verification, §9b authorization, politeness limiter, secret masking,
     tenant isolation. Delete this section if it does not. -->

- [ ] There is an ADR in `docs/ADRs/` arguing the case: what the control guarantees today, what this change costs, and why the trade is right
- [ ] It is still detection-only — no exploitation, no payload delivery, no auth bypass against live targets
- [ ] `docs/SECURITY.md` says what is now true
