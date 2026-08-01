"""cloudlist wrapper — enumerate assets from the customer's own cloud accounts.

Why this exists now and did not before
--------------------------------------
cloudlist asks a cloud provider "what do I have?" using the account's own API
credentials. In a vendor-hosted product that would mean customers sending us read
access to their AWS/GCP/Azure accounts — a trust escalation we were not willing to ask
for, so the module was left unbuilt and the binary was removed as dead weight.

**Self-hosting changes the calculus completely.** The credentials sit in the customer's
own deployment, are read by a process on their own infrastructure, and never traverse a
network we control. The vendor never sees them. That makes this the single highest-yield
discovery source available: DNS enumeration finds what someone published, while this
finds what actually *exists* — the load balancer nobody pointed a name at, the storage
bucket from a migration, the forgotten staging VM.

Scope safety
------------
This returns assets the cloud provider says the customer owns, which is a stronger
ownership claim than anything else in the product — stronger than DNS, stronger than
certificate transparency. But it is still not authorisation to scan: a shared-tenancy
IP inside their account may still front infrastructure they do not exclusively control.
So discovered assets go through the same scope engine as everything else, and IPs are
recorded as candidates rather than auto-promoted to `dedicated`.

Credentials
-----------
Read from a cloudlist provider config file the customer writes and mounts. We never
prompt for, store, or transmit them; the path is all this module knows. Read-only
permissions are all it needs, and the docs say so in bold.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from core.errors import ToolNotFound
from core.logging import logger
from modules.exec import run_tool_jsonl

Runner = Callable[..., Awaitable[list[dict]]]

#: Providers cloudlist supports that we surface. Others still work — this is only used
#: for the friendly label on a finding.
PROVIDERS = (
    "aws",
    "gcp",
    "azure",
    "digitalocean",
    "scaleway",
    "cloudflare",
    "heroku",
    "linode",
    "fastly",
    "alibaba",
    "namecheap",
    "terraform",
    "hetzner",
    "openstack",
    "kubernetes",
    "consul",
    "nomad",
)

#: Bound a single run. A large estate can return tens of thousands of records, and the
#: point is discovery, not exhaustive inventory.
MAX_ASSETS = 5000


@dataclass(frozen=True)
class CloudAsset:
    """One asset a cloud provider reports as belonging to the customer."""

    value: str  # hostname or IP
    provider: str
    service: str = ""
    is_ip: bool = False

    @property
    def hostname(self) -> str:
        return "" if self.is_ip else self.value

    @property
    def ip(self) -> str:
        return self.value if self.is_ip else ""


def _looks_like_ip(value: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def parse(rows: list[dict]) -> list[CloudAsset]:
    """Turn cloudlist's JSONL into assets, deduped.

    cloudlist emits ``{"provider","id","public_ipv4","private_ipv4","dns_name",...}``
    with the shape varying by provider. Private addresses are dropped: they are real
    assets but not *external* attack surface, and this product only speaks about what an
    outsider can reach.
    """
    seen: dict[str, CloudAsset] = {}
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        provider = str(row.get("provider") or "cloud").lower()
        service = str(row.get("service") or row.get("id") or "")
        for key in ("dns_name", "public_ipv4", "public_ipv6", "hostname", "host"):
            raw = row.get(key)
            for value in raw if isinstance(raw, list) else [raw]:
                text = str(value or "").strip().rstrip(".").lower()
                if not text or text in seen:
                    continue
                is_ip = _looks_like_ip(text)
                if is_ip and _is_private(text):
                    continue  # internal-only; not external attack surface
                seen[text] = CloudAsset(value=text, provider=provider, service=service, is_ip=is_ip)
                if len(seen) >= MAX_ASSETS:
                    return list(seen.values())
    return list(seen.values())


def _is_private(ip: str) -> bool:
    import ipaddress

    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved


async def enumerate_assets(
    config_path: str,
    timeout: float,
    *,
    provider: str | None = None,
    runner: Runner = run_tool_jsonl,
) -> list[CloudAsset]:
    """Run cloudlist against the customer's own provider config.

    Returns ``[]`` — never raises — when the binary is absent or the config is
    unreadable, so a misconfigured optional module degrades instead of failing a scan.
    """
    if not config_path:
        return []
    args = ["-config", config_path, "-json", "-silent"]
    if provider:
        args += ["-provider", provider]
    try:
        rows = await runner("cloudlist", args, timeout=timeout)
    except ToolNotFound:
        logger.info("cloudlist not installed — cloud asset enumeration skipped")
        return []
    except Exception as exc:  # noqa: BLE001 - one tool never sinks a stage
        logger.warning("cloudlist failed ({}); continuing without cloud assets", exc)
        return []

    assets = parse(rows)
    logger.info(
        "cloudlist: {} external asset(s) across {} provider(s)",
        len(assets),
        len({a.provider for a in assets}),
    )
    return assets
