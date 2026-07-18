"""Tenant-scoped RBAC permission model (§ access control).

Vantari is multi-tenant: one company (a *tenant*) has one **owner** and any number of
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
