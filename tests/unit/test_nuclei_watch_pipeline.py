"""Nuclei-template watch pipeline (module 22) — state-aware new-template matching."""

from __future__ import annotations

from core.models import Endpoint, Program
from core.tenant import TenantContext
from db.endpoints import EndpointRepo
from db.programs import ProgramRepo
from pipelines.nuclei_watch import run_nuclei_watch
from tests.fakes import FakeMongo

TENANT = TenantContext(tenant_id="t1")


async def _seed(mongo, tech=("nginx", "wordpress")):
    await ProgramRepo.from_mongo(mongo).save(
        Program(tenant_id="t1", program_id="p1", apex_domain="customer.com")
    )
    await EndpointRepo.from_mongo(mongo).upsert(
        Endpoint(
            tenant_id="t1",
            program_id="p1",
            fingerprint="e1",
            url="https://app.customer.com",
            tech=list(tech),
        )
    )


def _lister(templates):
    async def list_templates():
        return templates

    return list_templates


async def test_uses_the_real_corpus_by_default():
    """The lister used to be un-wired, so this stage always skipped with "no template
    lister configured" — dead code in the pipeline. It now defaults to the corpus
    installed in the scanning image; with no corpus present (as in CI) it degrades to
    "no templates" rather than claiming everything is new."""
    mongo = FakeMongo()
    await _seed(mongo)
    res = await run_nuclei_watch(mongo=mongo, tenant=TENANT, program_id="p1")
    assert "lister" not in (res.get("note") or "")
    assert res.get("new_templates") == []


async def test_unreadable_template_dir_degrades_instead_of_raising(tmp_path, monkeypatch):
    """A corpus directory we cannot stat must skip to the next candidate.

    The default search path includes /root/nuclei-templates, which every non-root
    process is forbidden to stat. Letting that PermissionError escape took the whole
    nuclei_watch stage down on any deployment not running the scanner as root — and
    silently, since the stage is scheduled rather than user-triggered.
    """
    import os

    import pytest

    from modules.scanning import nuclei

    if os.geteuid() == 0:
        pytest.skip("root can stat any directory, so mode 000 proves nothing")

    # Two ways a candidate can be unusable, both of which happen in the wild:
    #   unstattable -- parent is mode 700, so we cannot even stat the child. This is
    #                  literally /root/nuclei-templates seen by a non-root scanner.
    #   unlistable  -- the directory stats fine but cannot be opened.
    home = tmp_path / "home"
    (home / "nuclei-templates").mkdir(parents=True)
    unstattable = home / "nuclei-templates"

    unlistable = tmp_path / "unlistable"
    unlistable.mkdir()

    readable = tmp_path / "corpus" / "http" / "cves" / "2024"
    readable.mkdir(parents=True)
    (readable / "CVE-2024-1234.yaml").write_text("id: CVE-2024-1234\n")

    home.chmod(0o000)
    unlistable.chmod(0o000)
    try:
        monkeypatch.setattr(
            nuclei,
            "_TEMPLATE_DIRS",
            (str(unstattable), str(unlistable), str(tmp_path / "corpus")),
            raising=True,
        )
        found = await nuclei.list_templates()
    finally:
        home.chmod(0o755)
        unlistable.chmod(0o755)

    # Skipped the unreadable candidate and used the next one, rather than raising.
    assert [t["id"] for t in found] == ["CVE-2024-1234"]
    assert found[0]["tags"] == ["http", "cves", "2024"]


async def test_no_tech_skips():
    mongo = FakeMongo()
    await ProgramRepo.from_mongo(mongo).save(
        Program(tenant_id="t1", program_id="p1", apex_domain="customer.com")
    )
    res = await run_nuclei_watch(
        mongo=mongo, tenant=TENANT, program_id="p1", templates=_lister([{"id": "x"}])
    )
    assert res["skipped"] is True and "tech" in res["note"]


async def test_first_run_baselines_and_fires_nothing():
    """Day one, every existing template would look 'new' — that must not trigger
    a rescan storm."""
    mongo = FakeMongo()
    await _seed(mongo)
    res = await run_nuclei_watch(
        mongo=mongo,
        tenant=TENANT,
        program_id="p1",
        templates=_lister(
            [
                {"id": "nginx-version", "product": "nginx"},
                {"id": "wp-login", "tags": ["wordpress"]},
                {"id": "joomla-rce", "product": "joomla"},  # irrelevant to this stack
            ]
        ),
    )
    assert res["baseline"] is True
    assert res["new_templates"] == [] and res["rescan_hosts"] == []

    prog = await ProgramRepo.from_mongo(mongo).get("t1", "p1")
    # only the RELEVANT ids are stored — never the whole corpus
    assert set(prog["known_template_ids"]) == {"nginx-version", "wp-login"}


async def test_new_relevant_template_names_hosts_to_rescan():
    mongo = FakeMongo()
    await _seed(mongo)
    base = [{"id": "nginx-version", "product": "nginx"}]
    await run_nuclei_watch(mongo=mongo, tenant=TENANT, program_id="p1", templates=_lister(base))

    res = await run_nuclei_watch(
        mongo=mongo,
        tenant=TENANT,
        program_id="p1",
        templates=_lister(base + [{"id": "nginx-cve-2026-1", "product": "nginx"}]),
    )
    assert res["new_templates"] == ["nginx-cve-2026-1"]
    assert res["rescan_hosts"] == ["app.customer.com"]


async def test_new_irrelevant_template_is_ignored():
    """A new Joomla template must not re-scan an nginx/wordpress stack."""
    mongo = FakeMongo()
    await _seed(mongo)
    base = [{"id": "nginx-version", "product": "nginx"}]
    await run_nuclei_watch(mongo=mongo, tenant=TENANT, program_id="p1", templates=_lister(base))

    res = await run_nuclei_watch(
        mongo=mongo,
        tenant=TENANT,
        program_id="p1",
        templates=_lister(base + [{"id": "joomla-rce", "product": "joomla"}]),
    )
    assert res["new_templates"] == [] and res["rescan_hosts"] == []


async def test_second_run_with_no_change_is_quiet():
    mongo = FakeMongo()
    await _seed(mongo)
    base = [{"id": "nginx-version", "product": "nginx"}]
    kw = dict(mongo=mongo, tenant=TENANT, program_id="p1", templates=_lister(base))
    await run_nuclei_watch(**kw)
    res = await run_nuclei_watch(**kw)
    assert res["new_templates"] == [] and res["rescan_hosts"] == []


async def test_new_template_is_only_reported_once():
    """State-awareness: the same new template must not re-fire every run."""
    mongo = FakeMongo()
    await _seed(mongo)
    base = [{"id": "nginx-version", "product": "nginx"}]
    await run_nuclei_watch(mongo=mongo, tenant=TENANT, program_id="p1", templates=_lister(base))
    grown = base + [{"id": "nginx-cve-2026-1", "product": "nginx"}]

    first = await run_nuclei_watch(
        mongo=mongo, tenant=TENANT, program_id="p1", templates=_lister(grown)
    )
    second = await run_nuclei_watch(
        mongo=mongo, tenant=TENANT, program_id="p1", templates=_lister(grown)
    )
    assert first["new_templates"] == ["nginx-cve-2026-1"]
    assert second["new_templates"] == []  # fires exactly once
