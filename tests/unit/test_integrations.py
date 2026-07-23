"""Per-tenant integration secrets: encrypted round-trip + tenant-first resolution."""

from __future__ import annotations

from core.crypto import decrypt, encrypt
from db.integrations import IntegrationSecretRepo, resolve_secret
from tests.fakes import FakeMongo


def test_encrypt_round_trips_and_hides_plaintext():
    token = "ghp_supersecrettoken1234567890"
    blob = encrypt(token)
    assert token not in blob  # ciphertext, not the raw value
    assert decrypt(blob) == token
    assert decrypt("not-a-valid-token") is None  # tamper/garbage → None, no raise


async def test_set_stores_encrypted_and_masked_not_plaintext():
    mongo = FakeMongo()
    repo = IntegrationSecretRepo.from_mongo(mongo)
    doc = await repo.set("t1", "github_token", "ghp_abcdef1234567890")

    assert "ghp_abcdef1234567890" not in doc["value_enc"]  # stored encrypted
    assert doc["masked"] and doc["masked"] != "ghp_abcdef1234567890"
    assert await repo.get_value("t1", "github_token") == "ghp_abcdef1234567890"


async def test_resolve_prefers_tenant_value_over_env(monkeypatch):
    from core.config import Settings, get_settings

    get_settings.cache_clear()
    monkeypatch.setenv("EXACTSURFACE_GITHUB_TOKEN", "env-fallback-token")
    assert Settings().github_token is not None  # env fallback is present

    mongo = FakeMongo()
    # no tenant value yet → env fallback wins
    assert await resolve_secret(mongo, "t1", "github_token") == "env-fallback-token"
    # tenant sets its own → that wins
    await IntegrationSecretRepo.from_mongo(mongo).set("t1", "github_token", "tenant-key")
    assert await resolve_secret(mongo, "t1", "github_token") == "tenant-key"
    get_settings.cache_clear()


async def test_resolve_returns_none_when_unconfigured():
    mongo = FakeMongo()
    assert await resolve_secret(mongo, "t1", "shodan_api_key") is None


async def test_tenants_are_isolated():
    mongo = FakeMongo()
    repo = IntegrationSecretRepo.from_mongo(mongo)
    await repo.set("t1", "github_token", "t1-token")
    assert await repo.get_value("t2", "github_token") is None
    await repo.delete("t1", "github_token")
    assert await repo.get_value("t1", "github_token") is None
