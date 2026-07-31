"""The module registry: dependency-aware enable/disable.

The point of this registry is that a toggle tells the truth. Turning off a module that
others consume must stop them too — and say so — rather than leaving them to run against
no input and report a misleading zero.
"""

from __future__ import annotations

import pytest

from core.modules import (
    BY_NAME,
    ESSENTIAL,
    MODULE_NAMES,
    catalogue,
    dependents_of,
    resolve,
    sanitize_disabled,
)
from taskqueue.cadence import DEFAULT_CADENCE_SECONDS


def test_defaults_enable_the_core_chain():
    st = resolve()
    for name in ("domain_intel", "ingest", "probe", "crawl", "scan", "js_mine"):
        assert st.is_enabled(name), name


def test_opt_in_modules_are_off_until_enabled():
    st = resolve()
    for name in ("uncover", "tls", "dork", "cloud_buckets", "nuclei_watch", "service_scan"):
        assert not st.is_enabled(name)
        assert "not enabled" in st.reason(name)
    assert resolve(enabled_modules=["dork"]).is_enabled("dork")


def test_essential_modules_cannot_be_disabled():
    """Everything reads ingest/probe — a scanner without them finds nothing, so the
    honest answer is to refuse rather than let someone break their deployment."""
    st = resolve(disabled_modules=["ingest", "probe"])
    assert st.is_enabled("ingest") and st.is_enabled("probe")
    assert sanitize_disabled(["ingest", "probe", "crawl"]) == ["crawl"]


def test_disabling_a_module_cascades_to_its_dependents():
    st = resolve(disabled_modules=["crawl"])
    assert st.reason("crawl") == "turned off in settings"
    for dependent in ("js_mine", "broken_links"):
        assert not st.is_enabled(dependent)
        assert "Crawling" in st.reason(dependent)


def test_cascade_is_transitive():
    """port_scan → service_scan is one hop; the resolver must keep going, not stop at
    the first level."""
    assert dependents_of("port_scan") == ("service_scan",)
    st = resolve(enabled_modules=["service_scan"], disabled_modules=["port_scan"])
    assert not st.is_enabled("service_scan")
    assert "Port scanning" in st.reason("service_scan")


def test_unrelated_modules_are_unaffected():
    st = resolve(disabled_modules=["crawl"])
    for name in ("port_scan", "scan", "secrets", "domain_intel", "github_osint"):
        assert st.is_enabled(name), name


def test_dependents_of_reports_the_full_downstream_cost():
    assert set(dependents_of("ingest")) >= {"probe", "crawl", "js_mine", "scan", "port_scan"}
    assert dependents_of("notify") == ()  # nothing consumes alerting


def test_unknown_names_are_ignored():
    assert sanitize_disabled(["nope", None, 123]) == []
    assert resolve(disabled_modules=["nope"]).is_enabled("crawl")


def test_catalogue_exposes_what_the_ui_needs():
    rows = {r["name"]: r for r in catalogue(disabled_modules=["crawl"])}
    assert len(rows) == len(MODULE_NAMES)
    crawl = rows["crawl"]
    assert crawl["turned_off"] is True and crawl["enabled"] is False
    # supply_chain is transitive: crawl -> js_mine -> supply_chain
    assert set(crawl["required_by"]) == {"js_mine", "broken_links", "supply_chain"}
    assert rows["ingest"]["essential"] is True
    assert rows["js_mine"]["requires"] == ["crawl"]
    assert rows["dork"]["opt_in"] is True and rows["dork"]["opt_in_reason"]


@pytest.mark.parametrize("name", [n for n in MODULE_NAMES if BY_NAME[n].schedulable])
def test_every_schedulable_module_has_a_cadence(name):
    """A module the user can switch on must also be re-runnable on a schedule —
    otherwise it only ever runs inside a manual full scan."""
    assert name in DEFAULT_CADENCE_SECONDS


def test_requirements_reference_real_modules():
    for spec in BY_NAME.values():
        for req in spec.requires:
            assert req in BY_NAME, f"{spec.name} requires unknown module {req}"
        assert spec.name not in spec.requires  # no self-dependency
    assert ESSENTIAL == {"ingest", "probe"}
