"""Parsing tests for the crawl/tls/uncover wrappers (mock runners, no binaries)."""

from __future__ import annotations

from modules.crawling.gau import fetch_urls as gau_fetch
from modules.crawling.katana import crawl as katana_crawl
from modules.crawling.waybackurls import fetch_urls as wayback_fetch
from modules.probing.tlsx import inspect as tlsx_inspect
from modules.recon.uncover import search as uncover_search


def jsonl_runner(rows):
    async def runner(binary, args, *, timeout, stdin=None):
        return rows

    return runner


def lines_runner(lines):
    async def runner(binary, args, *, timeout, stdin=None):
        return lines

    return runner


async def test_katana_extracts_endpoints_from_varied_shapes():
    rows = [
        {"endpoint": "https://a.com/1"},
        {"url": "https://a.com/2"},
        {"request": {"endpoint": "https://a.com/3"}},
        {"noise": True},
    ]
    out = await katana_crawl("https://a.com", 10, runner=jsonl_runner(rows))
    assert out == ["https://a.com/1", "https://a.com/2", "https://a.com/3"]


async def test_gau_and_wayback_dedupe_and_sort():
    lines = ["https://a.com/2", "https://a.com/1", "https://a.com/2"]
    assert await gau_fetch("a.com", 10, runner=lines_runner(lines)) == [
        "https://a.com/1",
        "https://a.com/2",
    ]
    assert await wayback_fetch("a.com", 10, runner=lines_runner(lines)) == [
        "https://a.com/1",
        "https://a.com/2",
    ]


async def test_tlsx_parses_cert_and_sans():
    rows = [
        {
            "host": "A.com",
            "subject_cn": "a.com",
            "subject_an": ["a.com", "www.a.com"],
            "not_after": "2027-01-01",
            "expired": False,
        }
    ]
    out = await tlsx_inspect(["a.com"], 10, runner=jsonl_runner(rows))
    assert out[0]["host"] == "a.com" and out[0]["sans"] == ["a.com", "www.a.com"]
    assert out[0]["expired"] is False


async def test_uncover_returns_hostports():
    async def runner(_query):  # new signature: (query) -> [{host, ip, port}, …]
        return [
            {"host": "api.example.com", "ip": "1.2.3.4", "port": 443},
            {"host": "5.6.7.8", "ip": "5.6.7.8", "port": 80},
        ]

    out = await uncover_search("ssl:customer.com", 10, engine="shodan", runner=runner)
    assert {r["host"] for r in out} == {"api.example.com", "5.6.7.8"}
