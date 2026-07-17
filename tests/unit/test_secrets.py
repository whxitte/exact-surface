"""Secret detection + §9c never-store-plaintext policy."""

from __future__ import annotations

import json

from core.hashing import asset_fingerprint, endpoint_fingerprint, keyed_hash
from core.models import Asset, Endpoint
from core.scope import ProgramScope, ScopeEngine
from core.secrets_policy import find_secrets, mask
from core.tenant import TenantContext
from db.assets import AssetRepo
from db.endpoints import EndpointRepo
from db.secrets import SecretRepo
from modules.scanning.secretfinder import is_scannable_url, scan_urls
from pipelines.secrets import run_secret_scan
from tests.fakes import FakeMongo

ENGINE = ScopeEngine.from_data_file()
TENANT = TenantContext("t1", "u1")
SCOPE = ProgramScope(
    verified_apexes=("customer.com",), authorized_dedicated_cidrs=("45.55.0.0/16",)
)
KEY = b"unit-hmac-key"

# A realistic-looking key (NOT the canonical `AKIA…EXAMPLE` docs placeholder, which
# is now correctly filtered as a false positive — see test below).
AWS_KEY = "AKIAZ7Q2K9WMFB3RTUVX"


def test_is_scannable_url_skips_binary_assets():
    assert is_scannable_url("https://x.com/app.js")
    assert is_scannable_url("https://x.com/.env")
    assert is_scannable_url("https://x.com/api/config")  # no extension → scan
    assert not is_scannable_url("https://x.com/logo.png")
    assert not is_scannable_url("https://x.com/font.woff2")
    assert not is_scannable_url("https://x.com/favicon.ico")
    # strips ;jsessionid before checking the extension
    assert not is_scannable_url("https://x.com/logo.png;jsessionid=ABC123")


async def test_scan_urls_skips_binary_without_fetching():
    fetched: list[str] = []

    async def fetch(url):
        fetched.append(url)
        return AWS_KEY

    hits = await scan_urls(
        ["https://x.com/app.js", "https://x.com/logo.png", "https://x.com/f.ttf"],
        fetch=fetch,
    )
    assert fetched == ["https://x.com/app.js"]  # binary assets never fetched
    assert len(hits) == 1  # secret found in the one text asset


def test_find_secrets_detects_high_signal_types():
    text = (
        f"const k='{AWS_KEY}';\n"
        "token = ghp_abcdefghijklmnopqrstuvwxyz0123456789;\n"
        "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n"
        'api_key: "supersecretvalue123456"\n'
    )
    kinds = {h["kind"] for h in find_secrets(text, "https://a/main.js")}
    assert {"aws_access_key", "github_token", "private_key", "generic_secret"} <= kinds


def test_find_secrets_dedupes_within_source():
    text = f"{AWS_KEY} again {AWS_KEY}"
    hits = [h for h in find_secrets(text, "s") if h["kind"] == "aws_access_key"]
    assert len(hits) == 1


# -- false-positive filtering (§15 FP rate — the make-or-break metric) --------
def test_placeholder_generic_secrets_are_filtered():
    """The regex layer records hits independently of trufflehog verification, so a
    JS bundle full of tutorial placeholders used to become 'findings'."""
    text = (
        'apiKey = "YOUR_API_KEY_HERE"\n'
        'secret: "changeme_please_1234"\n'
        "token = 'example_token_value'\n"
    )
    assert find_secrets(text, "s") == []


def test_the_canonical_aws_example_key_is_filtered():
    """AKIA…EXAMPLE is AWS's own docs key — it appears in countless copied
    tutorials, so flagging it is pure noise. Filtering it removes a real FP source."""
    kinds = {h["kind"] for h in find_secrets("key=AKIAIOSFODNN7EXAMPLE", "s")}
    assert "aws_access_key" not in kinds


def test_secret_valued_as_a_url_is_filtered():
    """generic patterns can match `apiUrl = "https://…"`; a URL is not a credential."""
    assert find_secrets('apiKey = "https://api.example.com/v1/thing"', "s") == []


def test_low_entropy_generic_junk_is_filtered():
    assert find_secrets('token = "aaaaaaaaaaaaaaaaaaaa"', "s") == []


def test_real_prefixed_keys_are_never_entropy_filtered():
    """Entropy applies ONLY to the catch-all pattern. A real prefixed key must be
    kept even if its entropy is modest — dropping it would be a false negative."""
    text = f"{AWS_KEY}\nghp_abcdefghijklmnopqrstuvwxyz0123456789\n"
    kinds = {h["kind"] for h in find_secrets(text, "s")}
    assert {"aws_access_key", "github_token"} <= kinds


def test_a_real_generic_secret_still_passes():
    hits = find_secrets('client_secret: "a8Fk29Lm4Qp7Rs1Tv6Wx3Yz"', "s")
    assert any(h["kind"] == "generic_secret" for h in hits)


def test_mask_redacts_middle():
    m = mask(AWS_KEY)
    assert m.startswith("AKIA") and "•" in m and AWS_KEY not in m


async def _seed(mongo, hostname, ips, url):
    await AssetRepo(mongo.collection("assets")).upsert(
        Asset(
            tenant_id="t1",
            program_id="p1",
            fingerprint=asset_fingerprint("p1", hostname),
            hostname=hostname,
            resolved_ips=ips,
        )
    )
    await EndpointRepo(mongo.collection("endpoints")).upsert(
        Endpoint(
            tenant_id="t1",
            program_id="p1",
            fingerprint=endpoint_fingerprint("p1", "GET", url),
            url=url,
        )
    )


async def test_pipeline_stores_masked_secret_never_plaintext():
    mongo = FakeMongo()
    await _seed(mongo, "app.customer.com", ["45.55.1.1"], "https://app.customer.com/main.js")

    async def fetch(_url):
        return f"var cfg = {{ key: '{AWS_KEY}' }};"

    res = await run_secret_scan(
        mongo=mongo,
        engine=ENGINE,
        scope=SCOPE,
        tenant=TENANT,
        program_id="p1",
        hmac_key=KEY,
        fetch=fetch,
    )
    assert res["new"] == 1

    docs = list(SecretRepo(mongo.collection("secrets"))._c.docs.values())
    doc = docs[0]
    assert doc["masked"].startswith("AKIA") and "•" in doc["masked"]
    assert doc["value_hash"] == keyed_hash(AWS_KEY, KEY)
    # The plaintext must appear nowhere in the stored document.
    assert AWS_KEY not in json.dumps(doc, default=str)


async def test_scan_urls_streams_each_hit_immediately():
    streamed: list[str] = []

    async def fetch(_url):
        return f"a={AWS_KEY}"

    async def on_hit(h):
        streamed.append(h["value"])

    await scan_urls(
        ["https://x.com/a.js", "https://x.com/b.js"],
        fetch=fetch,
        deep_scan=None,
        on_hit=on_hit,
    )
    assert streamed == [AWS_KEY, AWS_KEY]  # one callback per secret, as found


async def test_pipeline_persists_secrets_before_a_later_failure(monkeypatch):
    # A secret found early must already be stored even if the scan blows up later —
    # this is what keeps a timed-out huge haul from losing everything.
    import pytest

    import pipelines.secrets as secrets_mod

    mongo = FakeMongo()
    await _seed(mongo, "app.customer.com", ["45.55.1.1"], "https://app.customer.com/main.js")

    async def fake_scan_urls(urls, *, on_hit=None, **_kw):
        await on_hit(
            {
                "value": AWS_KEY,
                "kind": "aws_access_key",
                "source_locator": urls[0],
                "severity": "high",
            }
        )
        raise RuntimeError("scan crashed after the first hit")

    monkeypatch.setattr(secrets_mod, "scan_urls", fake_scan_urls)

    with pytest.raises(RuntimeError):
        await run_secret_scan(
            mongo=mongo,
            engine=ENGINE,
            scope=SCOPE,
            tenant=TENANT,
            program_id="p1",
            hmac_key=KEY,
            fetch=lambda _u: "",
        )

    # The AWS key was streamed to the DB before the crash — not lost.
    docs = list(SecretRepo(mongo.collection("secrets"))._c.docs.values())
    assert len(docs) == 1 and docs[0]["value_hash"] == keyed_hash(AWS_KEY, KEY)


async def test_pipeline_skips_out_of_reach_hosts():
    mongo = FakeMongo()
    # Host resolves to the metadata IP → scope denies contact → must not be fetched.
    await _seed(mongo, "evil.customer.com", ["169.254.169.254"], "https://evil.customer.com/app.js")
    fetched: list[str] = []

    async def fetch(url):
        fetched.append(url)
        return AWS_KEY

    res = await run_secret_scan(
        mongo=mongo,
        engine=ENGINE,
        scope=SCOPE,
        tenant=TENANT,
        program_id="p1",
        hmac_key=KEY,
        fetch=fetch,
    )
    assert fetched == [] and res["new"] == 0
