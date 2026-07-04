"""Daemon entry point.

``python -m daemon.main --dry-run`` runs pre-flight health checks and prints the
module registry (Phase A exit criterion) without touching the network. Without
``--dry-run`` it supervises the scheduler + worker pool (built out in Phase B).
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from core.config import get_settings
from core.logging import configure_logging, logger
from daemon.health import run_health_checks
from modules.registry import MODULE_REGISTRY, enabled_modules


def _print_registry() -> None:
    print("\nMODULE REGISTRY")
    print("-" * 78)
    print(f"{'MODULE':<20}{'CATEGORY':<18}{'BINARY':<14}{'PHASE':<6}{'ENABLED':<8}")
    print("-" * 78)
    for m in MODULE_REGISTRY:
        print(
            f"{m.name:<20}{m.category:<18}{(m.binary or '-'):<14}"
            f"{m.phase:<6}{('yes' if m.enabled else 'NO'):<8}"
        )
    print("-" * 78)
    print(f"{len(enabled_modules())}/{len(MODULE_REGISTRY)} modules enabled\n")


def _print_health(report) -> None:
    print("HEALTH CHECKS")
    print("-" * 78)
    for c in report.checks:
        status = "PASS" if c.ok else "FAIL"
        print(f"[{status}] {c.name:<20} {c.detail}")
    print("-" * 78)


async def _dry_run() -> int:
    settings = get_settings()
    configure_logging(json_logs=settings.is_prod)
    logger.info("vantari daemon dry-run (env={})", settings.env)
    # Services may be absent on a bare dev box; report them but don't require them.
    report = await run_health_checks(check_services=True)
    _print_health(report)
    _print_registry()
    # Config + scope feeds are the hard gate for a dry-run to be meaningful.
    critical = {"config", "scope_feeds"}
    ok = report.critical_ok(critical)
    print(f"dry-run {'OK' if ok else 'FAILED'} (critical checks: {', '.join(sorted(critical))})")
    return 0 if ok else 1


async def _supervise() -> int:
    """Full run: start scheduler + workers. Wired up in Phase B."""
    settings = get_settings()
    configure_logging(json_logs=settings.is_prod)
    settings.assert_prod_safe()
    logger.info("vantari daemon starting (Phase B scheduler/worker supervision pending)")
    from daemon.health import run_health_checks as _rc

    report = await _rc(check_services=True)
    if not report.critical_ok({"config", "scope_feeds", "mongo", "redis"}):
        logger.error("pre-flight failed; refusing to start")
        return 1
    logger.info("pre-flight passed; supervisor loop is a Phase B deliverable")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="vantari-daemon")
    parser.add_argument("--dry-run", action="store_true", help="health check + registry, no I/O")
    args = parser.parse_args(argv)
    coro = _dry_run() if args.dry_run else _supervise()
    return asyncio.run(coro)


if __name__ == "__main__":
    sys.exit(main())
