"""The scope-feed updater must never remove protection (§3.9, §7 Phase G).

This file is a safety control, not a cache. The engine classifies an IP as
CDN/CLOUD_SHARED from these ranges, and those classes are what confine ExactSurface to
HTTP-layer probing. A range that drops out of the feed stops being recognised as
shared infrastructure — so a bad update is not a stale feed, it is a *removed*
protection, and the target finds out before we do.

The original updater rewrote the whole file from the two feeds it fetches, which
silently deleted the four providers it does not (akamai, fastly, google_cloud_lb,
azure_front_door) — via the daily cron the deploy guide recommends.
"""

from __future__ import annotations

import json

import pytest

from scripts.update_scope_feeds import (
    FeedRejected,
    build_feed,
    load_current,
    update_scope_feeds,
    validate_feed,
    write_feed,
)

AWS = {"cdn": ["13.32.0.0/15"], "cloud_shared": ["52.0.0.0/11"]}
CF = ["104.16.0.0/13"]


def _current(**counts) -> dict:
    """A feed with `counts` ranges per provider."""
    return {
        "providers": [
            {"name": name, "class": "cdn", "cidrs": [f"10.0.{i}.0/24" for i in range(n)]}
            for name, n in counts.items()
        ]
    }


# -- merge, never clobber ----------------------------------------------------
def test_unmanaged_providers_survive_an_update():
    """The regression. akamai/fastly/google/azure are hand-maintained; this script
    does not fetch them and must not delete them."""
    current = _current(akamai=8, fastly=14, google_cloud_lb=4, azure_front_door=4, cloudflare=22)
    feed = build_feed(aws=AWS, cloudflare=CF, current=current)

    names = {p["name"] for p in feed["providers"]}
    assert {"akamai", "fastly", "google_cloud_lb", "azure_front_door"} <= names


def test_managed_providers_are_replaced_not_duplicated():
    current = _current(cloudflare=22)
    feed = build_feed(aws=AWS, cloudflare=CF, current=current)

    cf = [p for p in feed["providers"] if p["name"] == "cloudflare"]
    assert len(cf) == 1
    assert cf[0]["cidrs"] == CF  # the fetched value won


def test_build_feed_without_a_current_file_still_works():
    feed = build_feed(aws=AWS, cloudflare=CF, current=None)
    assert {p["name"] for p in feed["providers"]} == {"cloudflare", "aws_cloudfront", "aws_cloud"}


# -- refuse a feed that removes protection -----------------------------------
def test_an_empty_fetch_is_refused():
    """An error page parsed as JSON yields zero prefixes. Writing that would
    un-classify every AWS range at once."""
    feed = build_feed(aws={"cdn": [], "cloud_shared": []}, cloudflare=CF, current=None)
    with pytest.raises(FeedRejected, match="zero ranges"):
        validate_feed(feed, None)


def test_a_collapsing_provider_is_refused():
    current = _current(cloudflare=100, akamai=8)
    feed = build_feed(aws=AWS, cloudflare=["1.1.1.0/24"], current=current)  # 100 -> 1
    with pytest.raises(FeedRejected, match="shrank"):
        validate_feed(feed, current)


def test_a_disappearing_provider_is_refused():
    """cloudflare count matches the fetch so only akamai's removal is under test —
    otherwise the shrink rule fires first and this asserts the wrong thing."""
    current = _current(cloudflare=1, akamai=8)
    feed = build_feed(aws=AWS, cloudflare=CF, current=current)
    feed["providers"] = [p for p in feed["providers"] if p["name"] != "akamai"]
    with pytest.raises(FeedRejected, match="disappear"):
        validate_feed(feed, current)


def test_normal_growth_is_accepted():
    current = _current(cloudflare=1, akamai=8)
    feed = build_feed(aws=AWS, cloudflare=["1.1.1.0/24", "2.2.2.0/24"], current=current)
    validate_feed(feed, current)  # must not raise


def test_a_small_wobble_is_accepted():
    """Real feeds shrink slightly all the time; only a collapse is suspicious."""
    current = _current(cloudflare=10, akamai=8)
    feed = build_feed(aws=AWS, cloudflare=[f"10.0.{i}.0/24" for i in range(9)], current=current)
    validate_feed(feed, current)  # 10 -> 9 is fine


# -- writing -----------------------------------------------------------------
def test_write_is_atomic_and_leaves_no_temp_files(tmp_path):
    """The engine loads this at startup: a half-written file is a worker that will
    not boot."""
    path = tmp_path / "cloud_ranges.json"
    write_feed(build_feed(aws=AWS, cloudflare=CF, current=None), path)

    assert json.loads(path.read_text())["providers"]
    assert list(tmp_path.iterdir()) == [path]  # no .tmp left behind


def test_load_current_tolerates_a_missing_or_corrupt_file(tmp_path):
    assert load_current(tmp_path / "nope.json") is None
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    assert load_current(bad) is None


# -- end to end --------------------------------------------------------------
async def test_a_rejected_update_leaves_the_existing_feed_untouched(tmp_path):
    """The whole point: failing must keep the old protections, not drop them."""
    path = tmp_path / "cloud_ranges.json"
    original = _current(cloudflare=100, akamai=8)
    path.write_text(json.dumps(original))

    async def fetch_garbage():
        return {"prefixes": []}, ""  # an error page / partial fetch

    with pytest.raises(FeedRejected):
        await update_scope_feeds(path, fetch=fetch_garbage)

    assert json.loads(path.read_text()) == original  # byte-for-byte unchanged


async def test_a_good_update_merges_and_writes(tmp_path):
    path = tmp_path / "cloud_ranges.json"
    path.write_text(json.dumps(_current(akamai=8, cloudflare=1)))

    async def fetch_ok():
        return (
            {
                "prefixes": [
                    {"ip_prefix": "13.32.0.0/15", "service": "CLOUDFRONT"},
                    {"ip_prefix": "52.0.0.0/11", "service": "EC2"},
                ]
            },
            "104.16.0.0/13\n172.64.0.0/13\n",
        )

    feed = await update_scope_feeds(path, fetch=fetch_ok)

    written = json.loads(path.read_text())
    assert written == feed
    names = {p["name"] for p in written["providers"]}
    assert "akamai" in names, "unmanaged provider lost on a successful update"
    assert "aws_cloud" in names
