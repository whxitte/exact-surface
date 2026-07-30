"""Subdomain permutation with alterx (module: ingest).

Passive sources only return names somebody published. The interesting hosts are often
the ones nobody published: an attacker takes the names they *did* find and generates
variants — `api` → `api-dev`, `api-staging`, `api2`, `dev-api` — then resolves them.
That is how the unlisted staging box gets found, and it is standard practice in every
engagement.

alterx (ProjectDiscovery, already installed in the scanning image) generates the
candidate list; dnsx then resolves them, so nothing is persisted that does not actually
exist. Generation is offline and cheap — the cost is the DNS resolution, which is why
the output is capped.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from modules.exec import ToolNotFound, run_tool_lines

Runner = Callable[..., Awaitable[list[str]]]

#: Ceiling on generated candidates. alterx multiplies patterns × word list × inputs, so
#: an unbounded run on a large surface can emit hundreds of thousands of names — far
#: more DNS traffic than the politeness budget allows, for rapidly diminishing returns.
MAX_PERMUTATIONS = 5000

#: Word list for the permutation payload. Deliberately small and high-yield: these are
#: the environment/tier prefixes that actually exist in the wild.
DEFAULT_WORDS: tuple[str, ...] = (
    "dev", "development", "staging", "stage", "test", "testing", "qa", "uat",
    "sandbox", "demo", "beta", "alpha", "preview", "internal", "int", "corp",
    "admin", "api", "api2", "apiv2", "app", "portal", "dashboard", "console",
    "old", "new", "legacy", "backup", "bak", "tmp", "temp", "v1", "v2", "v3",
    "prod", "production", "live", "edge", "cdn", "static", "assets", "media",
    "mail", "smtp", "vpn", "git", "jenkins", "ci", "build", "deploy", "monitor",
)


async def permute(
    hosts: list[str],
    timeout: float,
    *,
    limit: int = MAX_PERMUTATIONS,
    runner: Runner = run_tool_lines,
) -> list[str]:
    """Generate subdomain permutations from known *hosts*.

    Returns candidate names only — they are unresolved guesses until dnsx confirms
    them, so the caller must resolve before persisting anything. A missing binary
    yields an empty list rather than failing the stage: permutation is an enhancement,
    and losing it must never cost us the subdomains we already found.
    """
    hosts = [h for h in hosts if h]
    if not hosts:
        return []
    try:
        lines = await runner(
            "alterx",
            ["-silent", "-enrich", "-limit", str(limit)],
            timeout=timeout,
            stdin="\n".join(hosts),
        )
    except (ToolNotFound, Exception):  # noqa: BLE001 - enhancement, never fatal
        return []

    known = {h.lower().rstrip(".") for h in hosts}
    out: list[str] = []
    seen: set[str] = set()
    for line in lines:
        name = line.strip().lower().rstrip(".")
        # Only new, well-formed names; alterx echoes its inputs when enriching.
        if not name or name in known or name in seen or "." not in name or " " in name:
            continue
        seen.add(name)
        out.append(name)
        if len(out) >= limit:
            break
    return out
