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

    assert await crtsh_enum("customer.com", fetch=fetch) == []


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
