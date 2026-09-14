"""The MCP server is a thin client, and these tests hold it to that.

Nothing here reaches a network: a MockTransport plays the API. What is asserted is
the mapping (tool → path → params), the bounding of output, the labelling of
target-authored text, that errors arrive as sentences an agent can act on, and — the
one structural property — that no human-only action is offered as a tool at all.
"""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest
from exactsurface_client import mcp_server as srv
from exactsurface_client.api_client import ExactSurfaceClient, ExactSurfaceError


class FakeApi:
    """Records requests and answers from a table of (method, path) -> response."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict]] = []
        self.routes: dict[tuple[str, str], tuple[int, object]] = {}

    def on(self, method: str, path: str, status: int = 200, body: object = None) -> None:
        self.routes[(method, path)] = (status, body)

    def handler(self, request: httpx.Request) -> httpx.Response:
        params = dict(request.url.params)
        body = json.loads(request.content) if request.content else None
        self.calls.append((request.method, request.url.path, {"params": params, "body": body}))
        status, payload = self.routes.get(
            (request.method, request.url.path), (404, {"detail": "nope"})
        )
        if status == 204:
            return httpx.Response(204)
        return httpx.Response(status, json=payload)


@pytest.fixture()
def api():
    fake = FakeApi()
    c = ExactSurfaceClient(
        "https://es.example.com", "exs_test", transport=httpx.MockTransport(fake.handler)
    )
    srv.set_client(c)
    yield fake
    srv.set_client(None)
    asyncio.run(c.aclose())


def run(coro):
    return asyncio.run(coro)


# -- structural ---------------------------------------------------------------
def test_no_human_only_action_is_offered_as_a_tool():
    """The API would refuse them anyway; the point is that an agent is never shown
    the option. If a tool name ever matches one of these, that is a design change
    that needs SECURITY.md §6a updated first."""
    names = {t.name for t in run(srv.server.list_tools())}
    forbidden = (
        "verify",
        "authoriz",
        "scan_config",
        "scope_override",
        "delete",
        "member",
        "group",
        "api_key",
        "create_key",
        "revoke",
    )
    offenders = [n for n in names if any(f in n for f in forbidden)]
    assert not offenders, offenders
    assert len(names) >= 20


def test_write_tools_are_annotated_as_such():
    tools = {t.name: t for t in run(srv.server.list_tools())}
    for name in ("run_scan", "cancel_scan", "run_workflow"):
        assert tools[name].annotations.read_only_hint is False, name
    for name in ("list_findings", "whoami", "list_programs", "get_scan_logs"):
        assert tools[name].annotations.read_only_hint is True, name


# -- the client ---------------------------------------------------------------
def test_missing_env_fails_with_a_readable_message(monkeypatch):
    monkeypatch.delenv("EXACTSURFACE_URL", raising=False)
    monkeypatch.delenv("EXACTSURFACE_API_KEY", raising=False)
    with pytest.raises(ExactSurfaceError, match="EXACTSURFACE_URL"):
        ExactSurfaceClient()
    with pytest.raises(ExactSurfaceError, match="EXACTSURFACE_API_KEY"):
        ExactSurfaceClient("https://x.example")


@pytest.mark.parametrize(
    "given,expected",
    [
        ("https://es.example.com", "https://es.example.com/api"),
        ("https://es.example.com/", "https://es.example.com/api"),
        ("https://es.example.com/api", "https://es.example.com/api"),
        ("http://localhost:8000", "http://localhost:8000"),
    ],
)
def test_url_normalisation(given, expected):
    """A deployed instance is reached through the frontend's /api proxy; a bare API
    port is not. Both spellings should just work."""
    c = ExactSurfaceClient(given, "k", transport=httpx.MockTransport(lambda r: httpx.Response(200)))
    assert str(c._http.base_url).rstrip("/") == expected


def test_errors_reach_the_agent_as_sentences_it_can_act_on(api):
    """The SDK reports an unknown exception as "Error executing tool X", which throws
    away the message. Tools must raise its ToolError so the sentence survives."""
    from mcp.server.mcpserver.exceptions import ToolError

    api.on(
        "POST",
        "/api/programs/p1/scan",
        403,
        {"detail": "this API key does not have the 'scans:run' scope"},
    )
    api.on("GET", "/api/programs/p2", 404, {"detail": "not found"})
    api.on("GET", "/api/programs", 401, {"detail": "invalid api key"})
    with pytest.raises(ToolError, match="scans:run"):
        run(srv.run_scan("p1"))
    with pytest.raises(ToolError, match="not found"):
        run(srv.get_program("p2"))
    with pytest.raises(ToolError, match="EXACTSURFACE_API_KEY"):
        run(srv.list_programs())


# -- mapping and shaping ------------------------------------------------------
def test_list_findings_passes_filters_and_bounds_output(api):
    api.on(
        "GET", "/api/programs/p1/findings", 200, [{"id": i, "title": f"f{i}"} for i in range(80)]
    )
    out = run(srv.list_findings("p1", severity="high", state="new", limit=10))
    method, path, meta = api.calls[-1]
    assert (method, path) == ("GET", "/api/programs/p1/findings")
    assert meta["params"] == {"severity": "high", "state": "new"}
    assert len(out["items"]) == 10 and out["total"] == 80 and out["truncated"] is True
    assert out["notice"] == srv.NOTICE


def test_omitted_filters_are_not_sent(api):
    api.on("GET", "/api/programs/p1/findings", 200, [])
    run(srv.list_findings("p1"))
    assert api.calls[-1][2]["params"] == {}


def test_target_authored_results_are_labelled_and_others_are_not(api):
    api.on("GET", "/api/programs/p1/endpoints", 200, [{"url": "https://a"}])
    api.on("GET", "/api/programs/p1/cves", 200, [{"cve": "CVE-2026-1"}])
    api.on("GET", "/api/programs/p1/scan-runs", 200, [{"scan_id": "s"}])
    assert "notice" in run(srv.list_endpoints("p1"))
    assert "notice" not in run(srv.list_cves("p1"))
    assert "notice" not in run(srv.list_scan_runs("p1"))


def test_scan_logs_tail_from_the_end(api):
    api.on(
        "GET",
        "/api/programs/p1/scan-runs/s1/logs",
        200,
        {"scan_id": "s1", "lines": [f"l{i}" for i in range(500)]},
    )
    out = run(srv.get_scan_logs("p1", "s1", tail=3))
    assert out["lines"] == ["l497", "l498", "l499"] and out["total"] == 500


def test_run_scan_and_workflow_post_the_right_bodies(api):
    api.on("POST", "/api/programs/p1/scan", 202, {"status": "queued", "scan_id": "s9"})
    api.on("POST", "/api/playground/run", 200, {"run_id": "r1", "status": "queued"})
    assert run(srv.run_scan("p1"))["scan_id"] == "s9"
    graph = {"nodes": {"a": {"type": "pipeline:probe"}}, "edges": []}
    out = run(srv.run_workflow("p1", graph))
    assert out["run_id"] == "r1"
    assert api.calls[-1][2]["body"] == {"program_id": "p1", "graph": graph}


def test_whoami_summarises_what_the_key_may_do(api):
    api.on(
        "GET",
        "/api/auth/me",
        200,
        {
            "tenant_id": "t",
            "role": "member",
            "auth": "apikey",
            "key_id": "k_1",
            "scopes": ["read", "scans:run"],
            "permissions": ["view", "programs.manage"],
        },
    )
    me = run(srv.whoami())
    assert me["can_run_scans"] is True and me["can_run_playground"] is False
    assert "verify a domain" in me["human_only"]


def test_a_204_is_not_an_error(api):
    api.on("POST", "/api/programs/p1/scan-runs/s1/cancel", 204)
    assert run(srv.cancel_scan("p1", "s1")) is None
