"""Evidence-based "gone" detection (§continuous monitoring, accuracy-critical).

An item (asset / endpoint / port / finding / CVE) is **gone** only when we have proof:
a *full-coverage* run of the item's producing phase re-scanned its target and did NOT
re-observe it. We never infer gone from wall-clock age — a value that drifts every time
a partial (cascade) run bumps one item's timestamp, which wrongly "resolves" everything
else.

The proof is anchored to scan runs:

* ``phase_reference_starts`` returns, per phase, the START time of the latest
  full-coverage (non-cascade, ``targets == []``) run in which that phase succeeded. A
  full pipeline run contributes each of its succeeded stages; a scheduled single-phase
  run contributes itself. Cascade (target-scoped) runs are ignored — they only cover a
  few new hosts, so they are not evidence about everything else.
* An item is gone iff ``last_seen < reference[phase]`` — it existed, the phase re-ran
  with full coverage, and its ``last_seen`` was not bumped, i.e. it wasn't re-observed.
* Guard against a flaky/empty run (a phase that "succeeded" but found nothing, e.g.
  feroxbuster failing to connect): the reference only counts if at least one peer item
  of that phase was actually re-observed at/after it (``reference <= phase_max``). If a
  run observed nothing, no peer advanced, so nothing flips to gone — we wait for a good
  run instead of resolving live assets.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

#: endpoint ``source`` → the phase that re-discovers it (so a feroxbuster path is judged
#: only against content_discovery re-runs, never against a probe that only hits roots).
ENDPOINT_SOURCE_PHASE: dict[str, str] = {
    "probe": "probe",
    "crawl": "crawl",
    "katana": "crawl",
    "gau": "crawl",
    "wayback": "crawl",
    "feroxbuster": "content_discovery",
    "ffuf": "content_discovery",
}

#: finding ``module`` → producing phase (stage name in a full run).
FINDING_MODULE_PHASE: dict[str, str] = {
    "nuclei": "scan",
    "tlsx": "tls",
    "dork": "dork",
    "takeover": "takeover",
}


def _aware(dt: Any) -> datetime | None:
    if not isinstance(dt, datetime):
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def phase_reference_starts(runs: list[dict]) -> dict[str, datetime]:
    """Latest full-coverage successful-run start per phase (see module docstring)."""
    refs: dict[str, datetime] = {}

    def bump(phase: str | None, when: Any) -> None:
        w = _aware(when)
        if not phase or w is None:
            return
        cur = refs.get(phase)
        if cur is None or w > cur:
            refs[phase] = w

    for r in runs:
        if r.get("targets"):  # cascade / target-scoped — not full coverage
            continue
        started = r.get("started_at")
        if r.get("pipeline") == "full":
            # a full run re-runs everything; each succeeded stage is its own evidence
            for st in r.get("stages") or []:
                if st.get("status") == "success":
                    bump(st.get("name"), st.get("started_at") or started)
        elif r.get("status") == "success":
            bump(r.get("pipeline"), started)
    return refs


def annotate_gone(docs: list[dict], refs: dict[str, datetime], phase_of) -> list[dict]:
    """Tag each doc ``gone`` using the phase references. ``phase_of(doc)`` maps a doc to
    its producing phase (``None`` → never gone)."""
    # freshest last_seen per phase — proves that phase's latest reference re-observed
    # something (guards flaky/empty runs).
    phase_max: dict[str, datetime] = {}
    for d in docs:
        ph = phase_of(d)
        ls = _aware(d.get("last_seen"))
        if ph and ls and (phase_max.get(ph) is None or ls > phase_max[ph]):
            phase_max[ph] = ls

    for d in docs:
        ph = phase_of(d)
        ls = _aware(d.get("last_seen"))
        ref = refs.get(ph) if ph else None
        pmax = phase_max.get(ph) if ph else None
        d["gone"] = bool(ph and ref and ls and pmax and ref <= pmax and ls < ref)
    return docs


def endpoint_phase(doc: dict) -> str | None:
    return ENDPOINT_SOURCE_PHASE.get(doc.get("source") or "")


def finding_phase(doc: dict) -> str | None:
    return FINDING_MODULE_PHASE.get(doc.get("module") or "")


def const_phase(phase: str):
    return lambda _doc: phase
