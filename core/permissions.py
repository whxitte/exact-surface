"""Tenant-scoped RBAC permission model (§ access control).

ExactSurface is multi-tenant: one company (a *tenant*) has one **owner** and any number of
member users. The owner grants access the mature-SaaS way — by composing **permission
groups** (AWS-IAM style) and adding users to them. A brand-new user has **no group and
therefore no access at all** until the owner places them in one.

The security design is deliberately simple so it is hard to get wrong:

* The **owner** implicitly holds every permission and is the only principal who can
  manage users and groups. Member management is **not a delegable permission** — so a
  non-owner can *never* create users, edit groups, or grant themselves anything.
  Privilege escalation is impossible by construction.
* A member's effective permissions are the **union** of their groups'. No group ⇒
  empty set ⇒ every guarded route refuses them.
* A ``*.manage`` permission **implies** :data:`VIEW` (you cannot manage what you
  cannot see), avoiding a confusing "can act but the page 403s" state.

Enforcement lives in ``api.deps`` (the guards) and ``api.routes.members`` (owner-only
management); the values and rules live here, pure and unit-testable.
"""

from __future__ import annotations

#: The permissions an owner can grant to a group. Coarse on purpose — one per area of
#: the product, matching what a user recognises in the UI.
VIEW = "view"
PROGRAMS_MANAGE = "programs.manage"
SETTINGS_MANAGE = "settings.manage"

#: (permission, label, description) — the catalogue the management UI renders.
PERMISSION_CATALOGUE: tuple[tuple[str, str, str], ...] = (
    (VIEW, "View", "Read everything — overview, programs, assets, findings, DNS, activity."),
    (
        PROGRAMS_MANAGE,
        "Manage programs",
        "Add/remove domains, verify, authorize, run scans, toggle modules, mute assets.",
    ),
    (
        SETTINGS_MANAGE,
        "Manage settings",
        "API keys, integrations, notification channels, alert policy, schedules.",
    ),
)

#: Everything an owner can grant. Member/group management is intentionally NOT here —
#: it is owner-only and non-delegable, which is what makes escalation impossible.
ASSIGNABLE_PERMISSIONS: frozenset[str] = frozenset(p for p, _, _ in PERMISSION_CATALOGUE)

_MANAGE_PERMISSIONS: frozenset[str] = frozenset({PROGRAMS_MANAGE, SETTINGS_MANAGE})

#: The read-only group seeded for every tenant. The owner can rename/re-permission it.
DEFAULT_VIEWER_PERMISSIONS: frozenset[str] = frozenset({VIEW})


def normalise_permissions(perms) -> frozenset[str]:
    """Keep only assignable permissions; add VIEW when any manage permission is set."""
    valid = {p for p in perms if p in ASSIGNABLE_PERMISSIONS}
    if valid & _MANAGE_PERMISSIONS:
        valid.add(VIEW)
    return frozenset(valid)


def effective_permissions(*, is_owner: bool, group_permissions) -> frozenset[str]:
    """Permissions a principal actually holds.

    Owner ⇒ every assignable permission (and can never be reduced). Otherwise the
    normalised union of their groups — empty for a user with no group, which denies
    access everywhere.
    """
    if is_owner:
        return ASSIGNABLE_PERMISSIONS
    return normalise_permissions(group_permissions)


# --------------------------------------------------------------------------- #
# API-key scopes
# --------------------------------------------------------------------------- #
# A key inherits its creator's permissions and then *narrows* them with scopes. Scopes
# exist because the principal behind a key is increasingly not a person: it is a CI job,
# an integration, or an AI agent. Those need the least authority that does the job, and
# "everything my creator can do" is never the least. A key with no scopes beyond
# ``read`` can look at everything and change nothing, which is the right default for
# something that might be talked into doing otherwise.
#
# Each scope names the coarse permission its creator must hold. A scope the creator
# could not exercise themselves is dropped at creation, silently, so a key can never
# be a way up.
SCOPE_READ = "read"
SCOPE_SCANS_RUN = "scans:run"
SCOPE_PROGRAMS_WRITE = "programs:write"
SCOPE_PLAYGROUND_RUN = "playground:run"
SCOPE_SETTINGS_WRITE = "settings:write"

#: (scope, label, description, required coarse permission)
SCOPE_CATALOGUE: tuple[tuple[str, str, str, str], ...] = (
    (SCOPE_READ, "Read", "Programs, assets, findings, endpoints, scan history, reports.", VIEW),
    (
        SCOPE_SCANS_RUN,
        "Run scans",
        "Start and cancel scans on already-verified programs.",
        PROGRAMS_MANAGE,
    ),
    (
        SCOPE_PROGRAMS_WRITE,
        "Change programs",
        "Add programs, toggle modules and monitoring, set cadence, timeouts and alert policy.",
        PROGRAMS_MANAGE,
    ),
    (SCOPE_PLAYGROUND_RUN, "Run the Playground", "Run and save canvases.", PROGRAMS_MANAGE),
    (
        SCOPE_SETTINGS_WRITE,
        "Change settings",
        "Notification channels, integrations, schedule defaults.",
        SETTINGS_MANAGE,
    ),
)

SCOPE_REQUIRES: dict[str, str] = {s: p for s, _, _, p in SCOPE_CATALOGUE}
ALL_SCOPES: frozenset[str] = frozenset(SCOPE_REQUIRES)

#: What a key gets when nothing is asked for. Read-only, on purpose.
DEFAULT_KEY_SCOPES: frozenset[str] = frozenset({SCOPE_READ})

#: Actions no API key may perform with any scope. Each one either widens what may be
#: scanned or changes who may act, and each is the kind of thing an automated caller
#: — a compromised integration, a prompt-injected agent — must be structurally unable
#: to do to itself. A person, in a session, does these.
HUMAN_ONLY_ACTIONS: tuple[str, ...] = (
    "verify a domain",
    "create or revoke an authorization record",
    "change scan-scope switches (scan_shared_infra, scope_override)",
    "delete a program",
    "manage members and groups",
    "create or revoke API keys",
)


def allowed_scopes_for(permissions) -> frozenset[str]:
    """The scopes a principal with *permissions* may grant to a key."""
    perms = set(permissions)
    return frozenset(s for s, p in SCOPE_REQUIRES.items() if p in perms)


def normalise_scopes(requested, creator_permissions) -> frozenset[str]:
    """Requested scopes, bounded by what the creator holds, always including ``read``.

    Unknown scopes and scopes the creator cannot exercise are dropped rather than
    rejected: a client asking for more than it may have gets a key that does what it
    is allowed to, and can see exactly which scopes it received.
    """
    allowed = allowed_scopes_for(creator_permissions)
    granted = {s for s in requested if s in allowed}
    if VIEW in set(creator_permissions):
        granted.add(SCOPE_READ)
    return frozenset(granted)
