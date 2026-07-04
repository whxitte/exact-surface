"""Tenant context — the object threaded through every request and job.

Carrying an explicit :class:`TenantContext` (rather than reading globals) is what
makes tenant isolation checkable: a function that needs tenant data must be handed
the context, and DB helpers assert the context's ``tenant_id`` matches the filter.
"""

from __future__ import annotations

from dataclasses import dataclass

from core.errors import TenantIsolationError


@dataclass(frozen=True)
class TenantContext:
    tenant_id: str
    actor_id: str | None = None  # user or api-key id that initiated the action

    def assert_owns(self, tenant_id: str) -> None:
        """Raise if *tenant_id* is not this context's tenant (cross-tenant guard)."""
        if tenant_id != self.tenant_id:
            raise TenantIsolationError(
                f"actor in tenant {self.tenant_id!r} touched tenant {tenant_id!r}"
            )
