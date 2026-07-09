"""Registry of the external API keys / integration settings the toolchain uses.

Each entry declares a stable storage ``name``, UI copy, and the ``Settings``
attribute it falls back to when a tenant hasn't stored its own value. Consumers
never read ``get_settings()`` for these directly — they call
``db.integrations.resolve_secret`` so a per-tenant key always wins over the
process-wide ``.env`` fallback. Actual values live encrypted in
``db.integrations.IntegrationSecretRepo``.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class IntegrationKey:
    name: str  #: storage key + API path segment
    label: str  #: human label for the settings UI
    help: str  #: one-line explanation of what enabling it unlocks
    settings_attr: str  #: attribute on Settings used as the env fallback ("" = none)
    secret: bool = True  #: mask in the UI / never echo back the plaintext


#: The integrations a tenant can configure from the settings page. Order = UI order.
INTEGRATION_KEYS: tuple[IntegrationKey, ...] = (
    IntegrationKey(
        "github_token",
        "GitHub token",
        "Personal access token — enables GitHub code-search OSINT for leaked secrets.",
        "github_token",
    ),
    IntegrationKey(
        "google_cse_key",
        "Google CSE API key",
        "Google Custom Search key — enables dork / indexed-exposure detection.",
        "google_cse_key",
    ),
    IntegrationKey(
        "google_cse_cx",
        "Google CSE engine ID",
        "Custom Search Engine ID (cx) — pairs with the Google CSE key.",
        "google_cse_cx",
        secret=False,
    ),
    IntegrationKey(
        "shodan_api_key",
        "Shodan API key",
        "Enables Shodan-backed host discovery (uncover).",
        "shodan_api_key",
    ),
    IntegrationKey(
        "censys_api_id",
        "Censys API ID",
        "Censys API identifier for host discovery (uncover).",
        "censys_api_id",
    ),
    IntegrationKey(
        "censys_api_secret",
        "Censys API secret",
        "Censys API secret — pairs with the Censys API ID.",
        "censys_api_secret",
    ),
    IntegrationKey(
        "brave_api_key",
        "Brave Search API key",
        "Alternative search backend for dorking.",
        "brave_api_key",
    ),
    IntegrationKey(
        "serpapi_key",
        "SerpApi key",
        "Alternative search backend for dorking.",
        "serpapi_key",
    ),
)

INTEGRATION_BY_NAME: dict[str, IntegrationKey] = {k.name: k for k in INTEGRATION_KEYS}
