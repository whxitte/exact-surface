"""The `exactsurface` CLI: argument mapping, output modes, and above all exit codes.

A CLI's exit codes are its API for CI. Every one documented in --help is asserted
here against the condition that produces it, because a pipeline that treats "scan
found a critical" and "instance was unreachable" as the same failure is worse than
no gate at all.
"""

from __future__ import annotations

import json

import httpx
import pytest
from exactsurface_client import cli
from exactsurface_client.api_client import ExactSurfaceClient
from typer.testing import CliRunner

from tests.unit.test_mcp_server import FakeApi

runner = CliRunner()


@pytest.fixture()
def api(monkeypatch):
    monkeypatch.setenv("EXACTSURFACE_URL", "https://es.example.com")
    monkeypatch.setenv("EXACTSURFACE_API_KEY", "exs_test")
    monkeypatch.delenv("EXACTSURFACE_CONFIG", raising=False)
    fake = FakeApi()
    fake.on(
        "GET",
        "/api/programs",
        200,
        [
            {"program_id": "prog_1", "apex_domain": "acme.com", "verified": True, "enabled": True},
            {"program_id": "prog_2", "apex_domain": "beta.io", "verified": False, "enabled": True},
        ],
    )
    c = ExactSurfaceClient(
        "https://es.example.com", "exs_test", transport=httpx.MockTransport(fake.handler)
    )
    cli.set_client(c)
    yield fake
    cli.set_client(None)


def invoke(*args: str):
    return runner.invoke(cli.app, list(args))


# -- output modes --------------------------------------------------------------
def test_whoami_renders_a_table_and_json(api):
    api.on(
        "GET",
        "/api/auth/me",
        200,
        {
            "tenant_id": "t1",
            "auth": "apikey",
            "role": "member",
            "key_id": "k_1",
            "scopes": ["read", "scans:run"],
            "permissions": ["view"],
        },
    )
    r = invoke("whoami")
    assert r.exit_code == 0 and "scans:run" in r.stdout and "k_1" in r.stdout
    r = invoke("--json", "whoami")
    assert r.exit_code == 0 and json.loads(r.stdout)["key_id"] == "k_1"


def test_programs_list(api):
    r = invoke("programs", "list")
    assert r.exit_code == 0 and "acme.com" in r.stdout and "beta.io" in r.stdout


# -- program resolution ----------------------------------------------------------
def test_a_program_may_be_named_by_apex_domain(api):
    api.on(
        "GET",
        "/api/programs/prog_1/findings",
        200,
        [
            {
                "name": "Exposed .git",
                "severity": "critical",
                "state": "new",
                "module": "scan",
                "location": "https://a/.git",
            },
        ],
    )
    r = invoke("findings", "acme.com", "--severity", "critical", "--state", "new")
    assert r.exit_code == 0, r.stdout + r.stderr
    assert "Exposed .git" in r.stdout
    method, path, meta = api.calls[-1]
    assert path == "/api/programs/prog_1/findings" and meta["params"] == {
        "severity": "critical",
        "state": "new",
    }


def test_an_unknown_program_exits_4(api):
    r = invoke("findings", "nope.example")
    assert r.exit_code == 4
    assert "no program for 'nope.example'" in r.stderr


# -- exit codes for the API's answers -------------------------------------------
def test_a_refusal_exits_3_with_the_reason(api):
    api.on(
        "POST",
        "/api/programs/prog_1/scan",
        403,
        {"detail": "this API key does not have the 'scans:run' scope"},
    )
    r = invoke("scan", "run", "acme.com")
    assert r.exit_code == 3 and "scans:run" in r.stderr


def test_an_unreachable_instance_exits_6(monkeypatch):
    monkeypatch.setenv("EXACTSURFACE_URL", "https://es.example.invalid")
    monkeypatch.setenv("EXACTSURFACE_API_KEY", "exs_test")

    def boom(request):
        raise httpx.ConnectError("nodename nor servname provided")

    cli.set_client(
        ExactSurfaceClient("https://es.example.invalid", "k", transport=httpx.MockTransport(boom))
    )
    try:
        r = invoke("programs", "list")
    finally:
        cli.set_client(None)
    assert r.exit_code == 6 and "could not reach" in r.stderr


def test_missing_configuration_exits_1_with_a_readable_message(monkeypatch):
    monkeypatch.delenv("EXACTSURFACE_URL", raising=False)
    monkeypatch.delenv("EXACTSURFACE_API_KEY", raising=False)
    monkeypatch.setenv("EXACTSURFACE_CONFIG", "/nonexistent/config.toml")
    cli.set_client(None)
    r = invoke("programs", "list")
    assert r.exit_code == 1 and "EXACTSURFACE_URL" in r.stderr


# -- the CI gate -------------------------------------------------------------------
def test_scan_run_wait_fail_on_exits_5_when_new_findings_meet_the_threshold(api, monkeypatch):
    monkeypatch.setattr(cli.asyncio, "sleep", _no_sleep)
    api.on("POST", "/api/programs/prog_1/scan", 202, {"status": "queued", "scan_id": "s1"})
    api.on(
        "GET",
        "/api/programs/prog_1/scan-runs",
        200,
        [{"scan_id": "s1", "status": "success", "stages": []}],
    )
    api.on(
        "GET",
        "/api/programs/prog_1/findings",
        200,
        [
            {"name": "Leaked key", "severity": "high", "state": "new", "location": "https://a"},
            {"name": "Old low", "severity": "low", "state": "new", "location": "https://b"},
        ],
    )
    r = invoke("scan", "run", "acme.com", "--wait", "--fail-on", "high", "-q")
    assert r.exit_code == 5, r.stdout + r.stderr
    assert "1 NEW findings at or above high" in r.stdout
    assert api.calls[-1][2]["params"] == {"state": "new"}


def test_scan_run_wait_fail_on_exits_0_when_nothing_meets_the_threshold(api, monkeypatch):
    monkeypatch.setattr(cli.asyncio, "sleep", _no_sleep)
    api.on("POST", "/api/programs/prog_1/scan", 202, {"status": "queued", "scan_id": "s1"})
    api.on(
        "GET",
        "/api/programs/prog_1/scan-runs",
        200,
        [{"scan_id": "s1", "status": "success", "stages": []}],
    )
    api.on(
        "GET",
        "/api/programs/prog_1/findings",
        200,
        [{"name": "x", "severity": "low", "state": "new"}],
    )
    r = invoke("scan", "run", "acme.com", "--wait", "--fail-on", "high", "-q")
    assert r.exit_code == 0 and "no new findings at or above high" in r.stdout


def test_fail_on_rejects_an_unknown_severity(api):
    r = invoke("scan", "run", "acme.com", "--wait", "--fail-on", "scary")
    assert r.exit_code == 2 and "must be one of" in r.stderr


async def _no_sleep(_s: float) -> None:
    return None


# -- playground ---------------------------------------------------------------------
def test_playground_validate_exits_1_on_a_bad_graph(api, tmp_path):
    graph = tmp_path / "g.json"
    graph.write_text(json.dumps({"nodes": {"o": {"type": "output:view"}}, "edges": []}))
    api.on(
        "POST",
        "/api/playground/validate",
        200,
        {"ok": False, "message": "Output viewer input 'value' is required", "node": "o"},
    )
    r = invoke("playground", "validate", str(graph))
    assert r.exit_code == 1 and "required" in r.stdout
    api.on("POST", "/api/playground/validate", 200, {"ok": True, "order": ["t", "o"]})
    assert invoke("playground", "validate", str(graph)).exit_code == 0


# -- configuration file ----------------------------------------------------------------
def test_config_file_is_read_when_env_is_absent(monkeypatch, tmp_path):
    monkeypatch.delenv("EXACTSURFACE_URL", raising=False)
    monkeypatch.delenv("EXACTSURFACE_API_KEY", raising=False)
    cfg = tmp_path / "config.toml"
    cfg.write_text('[default]\nurl = "https://cfg.example.com"\napi_key = "exs_fromfile"\n')
    monkeypatch.setenv("EXACTSURFACE_CONFIG", str(cfg))
    cli.set_client(None)
    r = invoke("config")
    assert r.exit_code == 0 and "cfg.example.com" in r.stdout and "config" in r.stdout
    assert "exs_fromfile" not in r.stdout  # never echo the whole key


def test_version_works_without_a_subcommand():
    r = invoke("--version")
    assert r.exit_code == 0 and "exactsurface-client" in r.stdout
