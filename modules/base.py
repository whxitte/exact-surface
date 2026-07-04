"""The module interface every capability implements (§3.3).

One clean contract:  ``async def run(ctx: RunContext) -> RunResult``.

``RunContext`` carries everything a module legitimately needs — tenant/program
identity, the target, the scope engine, the politeness limiter, resolved scope
decision, and settings — so modules never reach into globals or each other.
Swapping one tool for another is a config change, not a code change.

Every module MUST consult ``ctx.decision`` (already computed by the worker via the
scope engine) and act only within its permitted action set. A module that ignores
it is a defect.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol, runtime_checkable

from core.config import Settings
from core.ratelimit import PolitenessLimiter
from core.scope import Action, ScopeDecision
from core.tenant import TenantContext


@dataclass
class RunContext:
    tenant: TenantContext
    program_id: str
    target: str
    decision: ScopeDecision  # precomputed scope verdict for the target
    limiter: PolitenessLimiter
    settings: Settings
    scan_id: str = "-"
    extra: dict = field(default_factory=dict)

    @property
    def tenant_id(self) -> str:
        return self.tenant.tenant_id

    def permits(self, action: Action) -> bool:
        return self.decision.permits(action)


class RunStatus(str, Enum):
    SUCCESS = "success"
    SKIPPED = "skipped"  # e.g. action not permitted, or state-aware no-op
    FAILED = "failed"


@dataclass
class RunResult:
    module: str
    status: RunStatus
    discovered: int = 0
    new: int = 0
    errors: list[str] = field(default_factory=list)
    items: list = field(default_factory=list)  # entities produced (assets/findings/...)

    @classmethod
    def skipped(cls, module: str, reason: str) -> RunResult:
        return cls(module=module, status=RunStatus.SKIPPED, errors=[reason])


@runtime_checkable
class Module(Protocol):
    name: str
    requires: Action

    async def run(self, ctx: RunContext) -> RunResult: ...
