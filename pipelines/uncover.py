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
    """Broad SSL/keyword queries so wildcard + CDN certs (CN=``*.apex``) still match —
    an exact ``subject.CN:apex`` misses those, which is why the first run found nothing."""
    if engine == "shodan":
        return f'ssl:"{apex}"'  # matches the domain anywhere in the cert (CN, SANs, …)
    return apex  # censys/fofa/quake: full-text keyword


def _split(entry: str) -> tuple[str, int] | None:
    host, _, port = entry.rpartition(":")
    if not host or not port.isdigit():
        return None
    return host.strip().lower().rstrip("."), int(port)


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

    # Collect raw host:port entries from every configured engine (or the test double).
    entries: set[str] = set()
    if search is not None:
        entries.update(await search(apex))
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
                entries.update(
                    await uncover_search(
                        _engine_query(eng, apex), timeout, engine=eng, api_env=api_env
                    )
                )
            except Exception as exc:  # noqa: BLE001 - one engine must not sink the stage
                logger.warning("uncover {} via {} failed: {}", apex, eng, exc)

    # Scope-gate every result: in-scope hostname → asset, authorized IP → port, else drop.
    host_set: set[str] = set()
    ports: dict[tuple[str, int], Port] = {}
    out_of_scope = 0
    for entry in entries:
        parsed = _split(entry)
        if parsed is None:
            continue
        host, port = parsed
        if _is_ip(host):
            if _ip_authorized(scope, host):
                ports[(host, port)] = Port(
                    tenant_id=tid,
                    program_id=program_id,
                    fingerprint=port_fingerprint(program_id, host, port, "tcp"),
                    ip=host,
                    port=port,
                    source="uncover",
                )
            else:
                out_of_scope += 1
        elif scope.owns_host(host):
            host_set.add(host)
        else:
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
        len(entries),
        len(asset_models),
        len(new_hosts),
        len(ports),
        new_ports,
        out_of_scope,
    )
    return {
        "found": len(entries),
        "assets": len(asset_models),
        "new_assets": len(new_hosts),
        "ports": len(ports),
        "new_ports": new_ports,
        "out_of_scope": out_of_scope,
        # cascade: probe/scan the newly discovered hosts immediately
        "cascade_targets": new_hosts,
    }
