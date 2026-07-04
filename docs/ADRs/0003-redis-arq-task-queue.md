# 0003 — Redis + arq task queue, not a daemon of async loops
Date: 2026-07-04
Status: Accepted

## Context
The original design ran "an independent async loop per pipeline" inside one
process. That cannot scale horizontally, apply back-pressure, enforce a global
rate ceiling across workers, or keep one large tenant from starving others.

## Decision
Introduce a **Redis-backed task queue (`arq`)**. A **scheduler** reads DB state and
*enqueues* jobs; a stateless **worker** pool pulls and executes them. Workers are
the single choke point where authorization, scope, and rate limits are enforced.
Per-tenant fair queuing prevents starvation.

## Consequences
- Workers scale horizontally (compose `replicas`, or K8s HPA) independent of the API.
- The global politeness limiter (§3.8b) uses a Redis token bucket shared by all
  workers, so the per-target ceiling holds regardless of concurrency.
- The package is named `taskqueue` (not `queue`) — see ADR-0007.
- Redis becomes a required infrastructure component (already needed for buckets).

## Alternatives considered
- **Celery.** Sync-first; awkward with the async tool wrappers and motor.
- **In-process async loops.** The original approach; rejected for the scaling and
  fairness reasons above.
