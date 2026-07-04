# 0001 — MongoDB (self-hosted first), not Firestore, with Postgres as the escape hatch
Date: 2026-07-04
Status: Accepted

## Context
Vantari needs a datastore for a write-heavy, state-aware workload: continuous
upserts keyed on content-hash fingerprints, "read state before doing expensive
work," multi-filter triage queries, and cross-module correlation. Cost discipline
matters (§3.8). The datastore must also support an on-prem/enterprise deployment
option (§13) and "data never leaves the tenant" (§3.7).

## Decision
Use **MongoDB, self-hosted first** (a container in the compose stack / on the VM,
which is free). MongoDB Atlas is an *optional* managed target, not a requirement.

Explicitly **reject Firestore/Firebase** despite its free tier.

Record **PostgreSQL + Row-Level Security** as the sanctioned migration path.

## Consequences
- The "Atlas is expensive" concern is moot: self-hosting the DB costs nothing
  beyond the VM. Atlas M10+ is a convenience for managed production only.
- Mongo's `$setOnInsert`/`$set` upsert maps 1:1 to the idempotency model (§3.2),
  and its flexible documents suit heterogeneous, evolving scan-tool output —
  a real velocity win for a solo dev.
- We keep app-layer tenant filtering + centralized ownership deps (§3.7). This is
  weaker than DB-enforced isolation; the Postgres path below would strengthen it.

## Alternatives considered
- **Firestore/Firebase.** Rejected. It bills **per document read/write**, which
  directly punishes the state-aware "read before work" pattern that is Vantari's
  core loop — continuous re-scans of millions of findings become a runaway bill.
  It cannot be self-hosted (kills on-prem/enterprise and complicates §3.7), and
  its query model (no joins, one range field per query, composite-index-per-shape)
  fights the triage dashboards and the correlator. "Free" is a scaling trap here.
- **PostgreSQL + JSONB + RLS.** The strongest long-term fit: Row-Level Security
  makes tenant isolation "impossible by construction" at the *database* layer;
  `INSERT ... ON CONFLICT DO UPDATE` is the idempotent upsert; SQL joins/aggregates
  make the correlator and analytics trivial; cheap scale-to-zero managed tiers
  (Neon, Supabase) exist; JSONB keeps schema flexibility. Not chosen *now* only to
  avoid thrashing the foundation, since self-hosted Mongo already resolves the cost
  driver. This ADR is the recorded trigger to revisit when DB-enforced isolation or
  heavy analytics justify the migration.
