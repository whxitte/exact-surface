"""The dashboards and alerts must reference metrics that actually exist (§7 Phase G).

This is the failure mode that makes monitoring worse than none: a renamed or
typo'd metric doesn't error anywhere. The panel just renders empty and the alert
just never fires, and both look exactly like "nothing is wrong". Nothing else in
the stack couples ``docker/*.yml`` to the emitting code, so this test is the
coupling — if you rename a metric, this fails instead of the dashboard lying.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
DASHBOARD = ROOT / "docker/grafana/dashboards/vantari-operations.json"
ALERTS = ROOT / "docker/alerts.yml"

#: Source dirs that may emit metrics. `tests/` is excluded on purpose — a probe
#: metric invented by a test must not satisfy a dashboard reference.
SOURCE_DIRS = ("core", "modules", "pipelines", "api", "db", "daemon", "taskqueue")

_METRIC_RE = re.compile(r"vantari_[a-z0-9_]+")
#: Prometheus synthesises these from a histogram registered under the base name.
_HISTOGRAM_SUFFIXES = ("_bucket", "_sum", "_count")


def _emitted_names() -> set[str]:
    """Metric names registered anywhere in the app source."""
    names: set[str] = set()
    for d in SOURCE_DIRS:
        for path in (ROOT / d).rglob("*.py"):
            for match in re.finditer(r"""["'](vantari_[a-z0-9_]+)["']""", path.read_text()):
                names.add(match.group(1))
    return names


def _base_name(name: str) -> str:
    for suffix in _HISTOGRAM_SUFFIXES:
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def _dashboard_referenced() -> set[str]:
    dashboard = json.loads(DASHBOARD.read_text())
    names: set[str] = set()
    for panel in dashboard["panels"]:
        for target in panel.get("targets", []):
            names |= set(_METRIC_RE.findall(target.get("expr", "")))
    return names


def _alert_referenced() -> set[str]:
    # Parsed as text, not YAML: pyyaml is not a guaranteed dev dependency here and
    # the metric names are what matter, not the rule structure.
    return set(_METRIC_RE.findall(ALERTS.read_text()))


def test_emitted_metric_names_were_found():
    """Guard the guard: if the source scan silently returned nothing, every
    assertion below would vacuously pass."""
    assert len(_emitted_names()) >= 10


@pytest.mark.parametrize("referenced", sorted(_dashboard_referenced()))
def test_every_dashboard_query_references_a_real_metric(referenced):
    assert _base_name(referenced) in _emitted_names(), (
        f"dashboard queries {referenced!r}, which nothing emits — the panel will "
        f"render empty forever"
    )


@pytest.mark.parametrize("referenced", sorted(_alert_referenced()))
def test_every_alert_rule_references_a_real_metric(referenced):
    assert _base_name(referenced) in _emitted_names(), (
        f"alerts.yml queries {referenced!r}, which nothing emits — the rule can never fire"
    )


def test_histogram_queries_use_the_bucket_suffix():
    """histogram_quantile() over the bare metric silently returns nothing."""
    dashboard = json.loads(DASHBOARD.read_text())
    for panel in dashboard["panels"]:
        for target in panel.get("targets", []):
            expr = target.get("expr", "")
            if "histogram_quantile" not in expr:
                continue
            assert "_bucket" in expr, f"{panel['title']!r}: histogram_quantile without _bucket"


def test_the_politeness_cap_alert_matches_the_configured_default():
    """The threshold is duplicated into Prometheus because it cannot read app
    config. If the setting moves and the rule doesn't, the §15 exit criterion
    ("naabu never exceeds the global rate cap") stops being enforced."""
    from core.config import Settings

    cap = Settings().global_rate_per_target
    assert f"vantari_port_scan_per_target_pps > {cap:g}" in ALERTS.read_text(), (
        f"alerts.yml threshold does not match global_rate_per_target={cap:g}"
    )
