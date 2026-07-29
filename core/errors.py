"""ExactSurface exception hierarchy.

Every custom exception derives from :class:`ExactSurfaceError` so callers can catch
the whole family with one ``except``. Tool wrappers and the scope/rate-limit
subsystems raise the specific subclasses defined here; nothing in the codebase
should raise a bare ``Exception`` for a condition that has a type below.
"""

from __future__ import annotations


class ExactSurfaceError(Exception):
    """Base class for every ExactSurface-raised error."""


class ConfigError(ExactSurfaceError):
    """Configuration is missing or invalid at startup."""


class OutOfScope(ExactSurfaceError):
    """A target was rejected by the central scope engine (``core/scope.py``).

    Raising this is a *safety stop*, not a bug: it means a module tried to touch
    a host/IP it is not authorised to touch. It is never swallowed silently.
    """

    def __init__(self, host: str, reason: str) -> None:
        self.host = host
        self.reason = reason
        super().__init__(f"out of scope: {host} ({reason})")


class ActionNotPermitted(ExactSurfaceError):
    """The host is in scope but the requested action is not allowed for it.

    Typically raised when a module asks to port-scan or run aggressive
    templates against a CDN/cloud-shared IP that only permits HTTP probing.
    """

    def __init__(self, host: str, action: str, reason: str) -> None:
        self.host = host
        self.action = action
        self.reason = reason
        super().__init__(f"action {action!r} not permitted on {host}: {reason}")


class RateLimited(ExactSurfaceError):
    """The politeness limiter refused a call because the target's budget is spent."""

    def __init__(self, key: str, retry_after: float) -> None:
        self.key = key
        self.retry_after = retry_after
        super().__init__(f"rate limited on {key}; retry after {retry_after:.2f}s")


class AuthorizationRequired(ExactSurfaceError):
    """No current authorization record exists for the program being scanned."""


class TenantIsolationError(ExactSurfaceError):
    """A caller attempted to reach data belonging to another tenant."""


class ScanCancelled(ExactSurfaceError):
    """A user asked to stop this run.

    Deliberately NOT a failure: everything discovered before the stop is already
    persisted (every write is an idempotent upsert), so the run finishes in a clean
    ``CANCELLED`` state rather than an error state. Raised by the orchestrator's
    cancellation check, never by a scanning module.
    """

    def __init__(self, stage: str) -> None:
        self.stage = stage
        super().__init__(f"run stopped by user during stage {stage!r}")


class ToolNotFound(ExactSurfaceError):
    """A required external binary is not installed or not on PATH."""

    def __init__(self, binary: str) -> None:
        self.binary = binary
        super().__init__(f"required tool not found: {binary}")


class ToolTimeout(ExactSurfaceError):
    """An external tool exceeded its per-call timeout and was killed."""

    def __init__(self, binary: str, timeout: float) -> None:
        self.binary = binary
        self.timeout = timeout
        super().__init__(f"tool {binary} timed out after {timeout:.0f}s")


class ToolExecutionError(ExactSurfaceError):
    """An external tool exited non-zero or produced unparseable output."""
