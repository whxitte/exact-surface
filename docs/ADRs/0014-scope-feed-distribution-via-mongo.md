# 0014 — Distribute the scope feed through Mongo, with the bundled file as the floor

Date: 2026-07-17
Status: Accepted

## Context

`core/data/cloud_ranges.json` is the CDN/cloud range feed. The engine classifies an
IP as CDN or CLOUD_SHARED from it, and those classes are what confine ExactSurface to
HTTP-layer probing (§3.9). It is a safety control, not a cache.

ADR-0013's predecessor commit made the *updater* safe (merge-not-clobber, validate,
atomic write). But it left the distribution problem open, and the problem was real:
the feed ships **inside the image**, and `default_engine()` is `@lru_cache`d for the
process's life. So `python -m scripts.update_scope_feeds` on a live host wrote a file
that no running process ever re-read. The daily-cron the deploy guide recommended
**did nothing**. §7 lists a "scope-feed auto-update job" as a Phase G deliverable,
and there was no mechanism for an update to reach the fleet at all.

Two distribution options were on the table:

- **A shared volume** (Docker volume / k8s PVC): the updater writes the file, workers
  read it. In Kubernetes this needs `ReadWriteMany`, which most storage classes do
  not offer; a shared *writable* volume across a worker fleet is an anti-pattern; and
  it adds infrastructure that exists nowhere else in the stack.
- **Mongo**: store the feed as a document, updater writes it, processes load it.

## Decision

**Store the feed in Mongo; keep the bundled file as an always-available floor.**

Mongo is the natural home: it is already the single shared store every process
connects to, so this needs no new infrastructure and sidesteps the RWX-volume
problem entirely.

- `core/scope.py` gains `ScopeEngine.from_feed(dict)` — a pure builder — and
  `bundled_feed()`. `from_data_file` becomes a thin wrapper. `core` stays
  I/O-free and dependency-free; it never learns the feed can come from Mongo.
- `db/scope_feed.py` holds the DB-touching parts: `ScopeFeedRepo` (get/set a single
  global document) and `build_scope_engine(mongo)`, which is where the Mongo-or-file
  choice lives. This keeps the dependency direction intact (`db → core`).
- The worker builds its engine from Mongo at startup, holds it on `ctx`, and passes
  it to every task. An update therefore reaches a worker **on its next restart** —
  which is what makes running the updater no longer a no-op.
- The scheduler (a singleton that is always up, so exactly one process fetches)
  refreshes the shared Mongo copy on a slow cadence
  (`scope_feed_refresh_hours`, default 24). Fully guarded: a refresh failing must
  never touch scan scheduling.

**The bundled file is the floor, and the load path fails toward *more* protection.**
`build_scope_engine` uses the Mongo copy only when it is present, readable, and **at
least as large as the bundled baseline**. A missing, unreadable, or thinner Mongo
feed falls back to the file. This is the same asymmetry the updater enforces on
write, now enforced on read too: a feed that loses ranges is a removed protection, so
neither a corrupt document nor a partial write can quietly widen scope. The updater's
Mongo path seeds an empty/thin Mongo copy from the bundled file before merging, so
the first refresh preserves the hand-maintained providers (akamai/fastly/google/
azure) that ship in the image rather than starting from only what it fetched.

## Consequences

**Good.** The §7 auto-update job exists and is genuinely automatic for the shared
copy: the scheduler refreshes Mongo daily, and any process that restarts — every
deploy does a rolling restart, and one can be triggered — picks it up. No new
infrastructure. `core` stays pure. The safety property is strictly stronger than
before: previously a hand-edited or mis-generated file *was* trusted; now a feed
below the shipped baseline is refused on load.

**Workers do not hot-reload.** An update reaches a running worker only on restart,
not mid-process. This is deliberate: provider ranges change on the order of weeks, a
rolling restart is routine and cheap, and in-process hot-reload would add cache
invalidation and version-checking to a *safety control* for little real gain. The
staleness window is bounded by restart cadence and documented.

**`worker_fleet_size`-style duplication does not arise** — the feed is single-source
(Mongo), and the file is only ever a read-time fallback, never separately edited in
prod.

**Mongo is now on the worker's critical startup path for scope.** If Mongo is
unreachable at startup the worker falls back to the bundled file (logged), so it
still starts with a correct, if possibly slightly stale, feed rather than failing.

**Untested against real Mongo.** The repo and loader are exercised against
`FakeMongo`; the `_id`-keyed single-document upsert and the projection want a check
against a live Mongo before the unattended run.

## Alternatives considered

- **Shared volume / PVC.** Rejected: RWX storage-class friction in k8s, a shared
  writable volume across the fleet is an anti-pattern, and it introduces
  infrastructure used nowhere else.
- **In-process hot-reload** (worker re-reads Mongo per scan or on a TTL). More moving
  parts and a version-check on every run, added to a safety control, to shave a
  restart off a feed that changes monthly. Not worth the risk now; the seam
  (`build_scope_engine`) is where it would go if it ever is.
- **Leave it file-only, document rebuild+redeploy.** Honest but it means §7's
  auto-update job simply does not exist, and the deploy guide keeps recommending a
  cron that does nothing.
- **Push the feed to workers over Redis pub/sub.** Redis is already there, but it
  turns a slowly-changing config blob into an eventing problem and needs a cache to
  fall back on anyway. Mongo is the durable store; this would sit on top of it.
