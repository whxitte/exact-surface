"""Domain-ownership verification (DNS TXT + HTTP file challenges).

Verifying ownership is what gates a program before scanning (§9b, Phase C exit).
DNS lookups go over DNS-over-HTTPS (Google) so there is no extra native dependency;
HTTP-file checks are a plain fetch. The verifier is injected as a FastAPI dependency
so tests can override it with a deterministic stub.
"""

from __future__ import annotations

from core.logging import logger
from core.models import VerificationMethod

_DNS_LABEL = "_exactsurface"
_HTTP_PATH = "/.well-known/exactsurface-challenge.txt"


class DomainVerifier:
    """Default verifier using real DNS-over-HTTPS and HTTP fetches."""

    async def verify(self, apex: str, method: str, token: str) -> bool:
        try:
            if method == VerificationMethod.DNS_TXT.value:
                return await self._verify_dns(apex, token)
            if method == VerificationMethod.HTTP_FILE.value:
                return await self._verify_http(apex, token)
        except Exception as exc:  # noqa: BLE001 - verification failure is a False, not a 500
            logger.warning("verification error for {}: {}", apex, exc)
        return False

    async def _verify_dns(self, apex: str, token: str) -> bool:
        import aiohttp

        url = f"https://dns.google/resolve?name={_DNS_LABEL}.{apex}&type=TXT"
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                data = await resp.json(content_type=None)
        for answer in data.get("Answer", []):
            if token in (answer.get("data", "") or "").strip('"'):
                return True
        return False

    async def _verify_http(self, apex: str, token: str) -> bool:
        import aiohttp

        for scheme in ("https", "http"):
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        f"{scheme}://{apex}{_HTTP_PATH}",
                        timeout=aiohttp.ClientTimeout(total=15),
                    ) as resp:
                        if resp.status == 200 and token in (await resp.text()):
                            return True
            except Exception:  # noqa: BLE001,S112 - fall through to the other scheme
                continue
        return False


def dns_instructions(apex: str, token: str) -> str:
    return f"Add a DNS TXT record at {_DNS_LABEL}.{apex} with value: {token}"


def http_instructions(apex: str, token: str) -> str:
    return f"Serve http://{apex}{_HTTP_PATH} containing: {token}"
