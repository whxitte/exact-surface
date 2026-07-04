# 0007 — Package named `taskqueue`, not `queue`
Date: 2026-07-04
Status: Accepted

## Context
The original directory layout named the task-queue package `queue/`. With the
repo root on `sys.path`, a top-level `queue` package **shadows the Python standard
library `queue` module**. Dependencies (including parts of the async/concurrency
stack) import stdlib `queue`; shadowing it causes obscure, hard-to-debug failures.

## Decision
Name the package **`taskqueue`**. This is the only deviation from the §4 layout in
the original spec, and it exists purely to avoid the stdlib collision.

## Consequences
- No stdlib shadowing; imports are unambiguous.
- All references (`taskqueue.worker.WorkerSettings`, `taskqueue.jobs`, etc.) and
  the Dockerfiles/compose commands use `taskqueue`.

## Alternatives considered
- **Keep `queue/` and rely on import ordering.** Rejected: fragile and a classic
  Python footgun.
- **Make everything a subpackage of `vantari/`.** Rejected: larger deviation from
  the documented flat layout than necessary to fix the one real collision.
