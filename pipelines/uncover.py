"""uncover pipeline (module 3) — Shodan/Censys passive discovery → assets + ports.

Queries indexed-scan engines (Shodan/Censys/…) for the program's apex and folds the
results back into the attack surface, STRICTLY scope-gated:

  * a result that is a hostname under a verified apex becomes an Asset;
  * a result that is an IP inside an authorized dedicated CIDR becomes a Port;
  * everything else is counted and dropped — Shodan listing an IP does not authorize it.

Needs a Shodan and/or Censys key; skips cleanly without one (like dork/github-osint).
Newly discovered hosts are returned as ``cascade_targets`` so downstream phases run.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from core.fingerprint import is_ephemeral_host
from core.hashing import asset_fingerprint, port_fingerprint
from core.logging import logger
from core.models import Asset, Port
from core.scope import ProgramScope, ScopeEngine
from core.tenant import TenantContext
from db.assets import AssetRepo
from db.integrations import resolve_secret
from db.ports import PortRepo
from modules.recon.uncover import search as uncover_search


def _engine_query(engine: str, apex: str) -> str:
    """Cert-based queries that catch wildcard + CDN certs (CN=``*.apex``) — an exact
    ``subject.CN:apex`` misses those, which is why the first run found nothing.

    * Shodan: ``ssl:"apex"`` matches the domain anywhere in the TLS cert (CN, SANs, …).
    * Censys: ``…leaf_data.names: "apex"`` — ``names`` is CN + every SAN, so it covers
      subdomains and wildcard leaf certs too."""
    if engine == "shodan":
        return f'ssl:"{apex}"'
    if engine == "censys":
        return f'services.tls.certificates.leaf_data.names: "{apex}"'
    return apex  # fofa/quake: full-text keyword


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _in_cidrs(ip: str, cidrs) -> bool:
    addr = ipaddress.ip_address(ip)
    for c in cidrs:
        try:
            net = ipaddress.ip_network(c, strict=False)
        except ValueError:
            continue
        if addr.version == net.version and addr in net:
            return True
    return False


def _ip_authorized(scope: ProgramScope, ip: str) -> bool:
    """True only if *ip* is in an authorized dedicated CIDR and not excluded — a Shodan
    listing never authorizes an IP on its own (§9b)."""
    return _in_cidrs(ip, scope.authorized_dedicated_cidrs) and not _in_cidrs(
        ip, scope.excluded_cidrs
    )


async def _resolve_keys(mongo: Any, tid: str) -> tuple[dict[str, str], list[str]]:
    """Return (API-key env for the uncover child, engines that have a usable key).

    uncover reads keys from env vars, so we hand the tenant's stored keys straight to
    the subprocess (SHODAN_API_KEY / CENSYS_API_ID+SECRET)."""
    env: dict[str, str] = {}
    engines: list[str] = []
    shodan = await resolve_secret(mongo, tid, "shodan_api_key")
    if shodan:
        env["SHODAN_API_KEY"] = shodan
        engines.append("shodan")
    cid = await resolve_secret(mongo, tid, "censys_api_id")
    csec = await resolve_secret(mongo, tid, "censys_api_secret")
    if cid and csec:
        env["CENSYS_API_ID"] = cid
        env["CENSYS_API_SECRET"] = csec
        engines.append("censys")
    return env, engines


async def run_uncover(
    *,
    mongo: Any,
    engine: ScopeEngine,
    scope: ProgramScope,
    tenant: TenantContext,
    program_id: str,
    apex: str,
    timeout: float,
    search=None,
) -> dict:
    tid = tenant.tenant_id

    # Collect {host, ip, port} results from every configured engine (or the test double).
    results: list[dict] = []
    if search is not None:
        results.extend(await search(apex))
    else:
        api_env, engines = await _resolve_keys(mongo, tid)
        if not engines:
            logger.info("uncover {}: skipped (no Shodan/Censys key configured)", apex)
            return {
                "found": 0,
                "new_assets": 0,
                "new_ports": 0,
                "skipped": True,
                "note": "needs a Shodan or Censys API key — add one in Settings",
            }
        for eng in engines:
            try:
                hits = await uncover_search(
                    _engine_query(eng, apex), timeout, engine=eng, api_env=api_env
                )
                results.extend(hits)
                # per-engine visibility: an empty result on a paid Shodan plan vs a
                # Censys auth/plan error read very differently in the logs.
                logger.info("uncover {}: {} result(s) from {}", apex, len(hits), eng)
            except Exception as exc:  # noqa: BLE001 - one engine must not sink the stage
                logger.warning("uncover {} via {} failed: {}", apex, eng, exc)

    # Scope-gate every result. A single result can yield BOTH an asset (its in-scope
    # hostname — e.g. a cert SAN Shodan surfaced) AND a port (its IP, if that IP is in an
    # authorized dedicated CIDR). Neither in scope → dropped (a listing ≠ authorization).
    seen: set[tuple] = set()
    host_set: set[str] = set()
    ports: dict[tuple[str, int], Port] = {}
    out_of_scope = 0
    for r in results:
        key = (r.get("host", ""), r.get("ip", ""), r.get("port"))
        if key in seen:
            continue
        seen.add(key)
        host, ip, port = r.get("host", ""), r.get("ip", ""), r.get("port")
        used = False
        if host and not _is_ip(host) and scope.owns_host(host):
            host_set.add(host)
            used = True
        if ip and port and _is_ip(ip) and _ip_authorized(scope, ip):
            ports[(ip, int(port))] = Port(
                tenant_id=tid,
                program_id=program_id,
                fingerprint=port_fingerprint(program_id, ip, int(port), "tcp"),
                ip=ip,
                port=int(port),
                source="uncover",
            )
            used = True
        if not used:
            out_of_scope += 1

    asset_models = [
        Asset(
            tenant_id=tid,
            program_id=program_id,
            fingerprint=asset_fingerprint(program_id, host),
            hostname=host,
            source="uncover",
            is_ephemeral=is_ephemeral_host(host),
        )
        for host in sorted(host_set)
    ]
    a_res = await AssetRepo.from_mongo(mongo).upsert_all(asset_models)
    new_hosts = [m.hostname for m, r in zip(asset_models, a_res, strict=True) if r.inserted]
    _, new_ports = await PortRepo.from_mongo(mongo).upsert_many(list(ports.values()))

    logger.info(
        "uncover {}: {} indexed result(s) → {} in-scope asset(s) ({} new), "
        "{} authorized port(s) ({} new), {} out-of-scope dropped",
        apex,
        len(seen),
        len(asset_models),
        len(new_hosts),
        len(ports),
        new_ports,
        out_of_scope,
    )
    return {
        "found": len(seen),
        "assets": len(asset_models),
        "new_assets": len(new_hosts),
        "ports": len(ports),
        "new_ports": new_ports,
        "out_of_scope": out_of_scope,
        # cascade: probe/scan the newly discovered hosts immediately
        "cascade_targets": new_hosts,
    }
