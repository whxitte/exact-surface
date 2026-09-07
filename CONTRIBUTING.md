# Contributing

Issues and pull requests are welcome. Two things about this codebase will save you a
round trip, and one of them is not negotiable.

## 1. The safety controls are not negotiable

ExactSurface is **detection only**. It does not exploit, deliver payloads, brute-force
credentials, or bypass authentication against a live target, and a pull request that
adds any of those will not be merged regardless of how well it is written.

The controls that keep it that way are the scope engine, the DNS-TXT verification and
§9b authorization gate, the politeness limiter, and the secret masking. A change that
weakens one needs an **ADR** in [`docs/ADRs/`](docs/ADRs/) arguing the case — what the
control buys, what your change costs, and why the trade is right — not just a diff. Read
[`docs/SECURITY.md`](docs/SECURITY.md) §2 before you start; it explains what each control
actually guarantees, which is usually narrower than people assume.

Found a hole in one of them? That is a security report, not a pull request — see
[`SECURITY.md`](SECURITY.md).

## 2. Registries must not drift

A capability here is not one thing in one file. A module is a spec in `core.modules`, a
route in `pipelines.dispatch`, a stage in the orchestrator, an interval in
`taskqueue.cadence`, a budget in `taskqueue.timeouts`, an entry on the in-app Knowledge
page, and usually a binary in the scanning image.

Add it to six of those seven and everything looks fine until the one path that needs the
seventh runs — in production, at 3am, on someone else's deployment. That is not
hypothetical; it has happened twice, and both times a green test suite said nothing.

`tests/unit/test_wiring.py` asserts the relationships between those registries. When it
fails it names the gap. Do not delete the assertion to make it pass.

## Getting set up

```bash
git clone https://github.com/whxitte/exact-surface.git && cd exact-surface
make venv && make install
make dry-run      # config, scope feeds, binaries, datastores — no network
make test         # the suite
make lint         # ruff check + ruff format --check, exactly what CI runs
```

[`docs/TESTING.md`](docs/TESTING.md) takes you from there to a real scan against a
target you control. For the frontend, `cd frontend && npm install && npm run dev`, then
`npx tsc --noEmit` and `npx next lint` before you push.

## Before you open a PR

- `make test && make lint` pass, and `npx tsc --noEmit` if you touched the frontend.
- **New behaviour has a test.** The bugs that have actually hurt this project were
  integration-shaped — a route that was never wired, a file that was never committed, an
  image whose dependencies a `.dockerignore` had silently stripped. Tests that assert
  relationships are worth more here than tests that assert a function returns 4.
- **The demo keeps up.** `demo/` is the real frontend with only `lib/transport.ts`
  swapped, so a component that starts calling a new endpoint needs a fixture in
  `demo/lib/fixtures.ts` or the demo logs `[demo] no fixture for …` and renders empty.
- **Explain why in the commit message.** What the code does is readable from the diff;
  why you chose it is not, and in six months that is the part anyone needs.

## Scope of contributions

Good first areas: a new detection module (follow an existing one in `modules/` and wire
all seven registries), Playground nodes, report formats, and documentation that assumes
less than the current docs do.

[`docs/ROADMAP.md`](docs/ROADMAP.md) lists the three biggest gaps. They are each a
sizeable piece of work — open an issue before starting one so we can agree the shape
first.
