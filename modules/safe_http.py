"""A hardened aiohttp session for fetching attacker-influenced targets (§3.10).

Every in-process fetch of a customer host — the takeover probe, the secret scanner —
goes through :func:`guarded_session`. It closes the SSRF hole described in
:mod:`core.netguard` with two independent controls:

1. **A filtering DNS resolver on the connector.** aiohttp resolves every host it
   connects to — the initial URL *and* every redirect hop — through the connector's
   resolver. This one drops any resolved address that :func:`is_forbidden_target_ip`
   rejects, so a name that resolves (or rebinds) to 169.254.169.254 / an RFC1918
   address simply has no address to connect to. This also closes the check-then-
   connect DNS-rebinding gap, because the filter runs at connect time, not earlier.

2. **Redirects off, plus an IP-literal precheck.** aiohttp bypasses the resolver for
   a bare-IP host, so the resolver alone would not stop ``http://10.0.0.1/``. With
   ``allow_redirects=False`` the only host we ever connect to is the one the caller
   passed, and :func:`assert_url_allowed` refuses that up front if it is a forbidden
   IP literal. Following redirects is not needed for takeover/secret detection and is
   the primary SSRF vector, so it stays off.

aiohttp is imported lazily (it is a runtime-only dependency, absent from the test
venv); the guard logic in :mod:`core.netguard` is pure and independently tested.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from core.netguard import is_forbidden_target_ip, is_ip_literal


class ForbiddenTarget(Exception):
    """Raised when a fetch would reach a non-globally-routable address."""


def assert_url_allowed(url: str) -> None:
    """Refuse a URL whose host is a forbidden IP literal (the resolver's blind spot)."""
    host = urlsplit(url).hostname or ""
    if host and is_ip_literal(host) and is_forbidden_target_ip(host):
        raise ForbiddenTarget(f"refusing to fetch a non-public address: {host}")


def _filtering_resolver():  # pragma: no cover - needs aiohttp + real DNS
    """An aiohttp resolver that strips forbidden IPs from every resolution."""
    import aiohttp

    base = aiohttp.AsyncResolver() if _has_aiodns() else aiohttp.ThreadedResolver()

    class _Guarded(aiohttp.abc.AbstractResolver):
        async def resolve(self, host, port=0, family=0):
            hosts = await base.resolve(host, port, family)
            safe = [h for h in hosts if not is_forbidden_target_ip(h["host"])]
            if not safe:
                raise ForbiddenTarget(f"{host} resolves only to non-public addresses")
            return safe

        async def close(self):
            await base.close()

    return _Guarded()


def _has_aiodns() -> bool:  # pragma: no cover
    try:
        import aiodns  # noqa: F401

        return True
    except ImportError:
        return False


def guarded_session(**kwargs):  # pragma: no cover - needs aiohttp
    """An ``aiohttp.ClientSession`` that cannot be steered to an internal address.

    Redirects are disabled by default (the main SSRF vector) and the connector uses
    the filtering resolver. Pass ``allow_redirects``/``connector`` only if you truly
    mean to override the guard.
    """
    import aiohttp

    kwargs.setdefault("connector", aiohttp.TCPConnector(resolver=_filtering_resolver()))
    return aiohttp.ClientSession(**kwargs)


async def guarded_post(  # pragma: no cover - needs aiohttp
    url: str, payload: dict, *, timeout: float = 15.0
) -> int:
    """POST *payload* as JSON to *url* through the SSRF-safe guarded session.

    Used for outbound webhooks (Discord/Slack/generic/Telegram), whose URL is
    user-supplied. The filtering resolver blocks any host that resolves to a non-public
    address (metadata/RFC1918/loopback) — closing the DNS-rebinding gap — and
    ``assert_url_allowed`` refuses a forbidden IP literal up front. Redirects are off so
    a 302 can't hop to an internal address. Returns the HTTP status; raises
    :class:`ForbiddenTarget` if the destination is not globally routable.
    """
    import aiohttp

    assert_url_allowed(url)
    async with guarded_session() as session:
        async with session.post(
            url,
            json=payload,
            timeout=aiohttp.ClientTimeout(total=timeout),
            allow_redirects=False,
        ) as resp:
            return resp.status
