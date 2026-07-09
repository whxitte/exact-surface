"""Tool-wrapper parsing tests with an injected runner/fetch (no binaries, no net)."""

from __future__ import annotations

from modules.probing.httpx import probe
from modules.recon.crtsh import enumerate_subdomains as crtsh_enum
from modules.recon.dnsx import resolve_hosts, resolve_one
from modules.recon.subfinder import enumerate_subdomains as subfinder_enum
from modules.scanning.nuclei import SAFE_EXCLUDE_TAGS, scan


def make_runner(rows, capture=None):
    async def runner(binary, args, *, timeout, stdin=None):
        if capture is not None:
            capture.append({"binary": binary, "args": list(args), "stdin": stdin})
        return rows

    return runner


async def test_subfinder_dedups_and_sorts():
    rows = [{"host": "b.customer.com"}, {"host": "a.customer.com"}, {"host": "b.customer.com"}]
    out = await subfinder_enum("customer.com", 10, runner=make_runner(rows))
    assert out == ["a.customer.com", "b.customer.com"]


async def test_dnsx_groups_ips_per_host():
    rows = [
        {"host": "a.customer.com", "a": ["1.1.1.1", "1.1.1.2"]},
        {"host": "a.customer.com", "a": ["1.1.1.2"]},
        {"host": "b.customer.com", "a": ["2.2.2.2"]},
    ]
    out = await resolve_hosts(["a.customer.com", "b.customer.com"], 10, runner=make_runner(rows))
    assert out == {"a.customer.com": ["1.1.1.1", "1.1.1.2"], "b.customer.com": ["2.2.2.2"]}
    one = await resolve_one("a.customer.com", 10, runner=make_runner(rows))
    assert one == ["1.1.1.1", "1.1.1.2"]


async def test_httpx_normalises_records():
    rows = [
        {
            "url": "https://a.customer.com",
            "input": "a.customer.com",
            "status_code": 200,
            "title": "Home",
            "tech": ["nginx", "php"],
        },
        {"no_url": True},  # dropped
    ]
    out = await probe(["a.customer.com"], 10, runner=make_runner(rows))
    assert len(out) == 1
    assert out[0]["url"] == "https://a.customer.com" and out[0]["tech"] == ["nginx", "php"]


async def test_crtsh_filters_to_domain_and_strips_wildcards():
    async def fetch(_url):
        return (
            '[{"name_value": "*.customer.com\\napp.customer.com"},'
            ' {"name_value": "mail.customer.com"},'
            ' {"name_value": "evil.attacker.com"}]'
        )

    out = await crtsh_enum("customer.com", fetch=fetch)
    assert out == ["app.customer.com", "customer.com", "mail.customer.com"]


async def test_crtsh_degrades_on_error():
    async def fetch(_url):
        raise RuntimeError("crt.sh down")

    async def no_sleep(_s):
        return None

    assert await crtsh_enum("customer.com", fetch=fetch, attempts=1, sleep=no_sleep) == []


async def test_crtsh_retries_then_succeeds():
    calls = {"n": 0}

    async def flaky_fetch(_url):
        calls["n"] += 1
        if calls["n"] < 2:
            return ""  # crt.sh empty body → JSON parse fails → retry
        return '[{"name_value": "app.customer.com"}]'

    async def no_sleep(_s):
        return None

    out = await crtsh_enum("customer.com", fetch=flaky_fetch, sleep=no_sleep)
    assert out == ["app.customer.com"] and calls["n"] == 2


async def test_nuclei_enforces_safe_excludes_and_parses():
    rows = [
        {
            "template-id": "exposed-env",
            "info": {"name": "Exposed .env", "severity": "high", "description": "d"},
            "matched-at": "https://a.customer.com/.env",
        }
    ]
    cap = []
    out = await scan(
        ["https://a.customer.com"], 10, aggressive=False, runner=make_runner(rows, cap)
    )
    # safe excludes always present
    args = cap[0]["args"]
    assert "-etags" in args
    etags = args[args.index("-etags") + 1]
    assert all(tag in etags for tag in SAFE_EXCLUDE_TAGS)
    # non-aggressive restricts to a safe tag set
    assert "-tags" in args
    assert out[0]["severity"] == "high" and out[0]["template_id"] == "exposed-env"


async def test_nuclei_aggressive_drops_tag_restriction_but_keeps_excludes():
    cap = []
    await scan(["https://a"], 10, aggressive=True, runner=make_runner([], cap))
    args = cap[0]["args"]
    assert "-tags" not in args  # aggressive widens template set
    assert "-etags" in args  # but still excludes harmful tags


# -- stream_tool: live streaming + partial-on-timeout (nuclei's runner) -------
async def test_stream_tool_streams_lines_and_calls_back():
    from modules.exec import stream_tool

    seen: list[str] = []
    rc, out, _err, timed_out = await stream_tool(
        "sh", ["-c", "printf 'a\\nb\\n'"], timeout=5, on_stdout=seen.append
    )
    assert not timed_out and rc == 0
    assert out == ["a", "b"] and seen == ["a", "b"]


async def test_stream_tool_keeps_partial_output_on_timeout():
    from modules.exec import stream_tool

    # emits one line, then hangs → killed at the timeout, but the line is kept
    _rc, out, _err, timed_out = await stream_tool(
        "sh", ["-c", "printf 'early\\n'; sleep 5"], timeout=0.5
    )
    assert timed_out and "early" in out


async def test_stream_tool_handles_lines_over_64kb():
    # A single JSONL line larger than asyncio's 64 KB StreamReader limit must NOT
    # raise "Separator is not found, and chunk exceed the limit" (the nuclei crash).
    from modules.exec import stream_tool

    big = "x" * 200_000  # 200 KB, well past the 64 KB readline limit
    seen: list[str] = []
    rc, out, _err, timed_out = await stream_tool(
        "sh", ["-c", f"printf '%s\\nsmall\\n' '{big}'"], timeout=10, on_stdout=seen.append
    )
    assert not timed_out and rc == 0
    assert out == [big, "small"] and seen == [big, "small"]
