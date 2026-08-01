"""Discover every callable the workbench can run, with its real signature.

Introspection rather than a hand-maintained list, for the same reason the dispatcher
uses a table: a registry someone has to remember to update is a registry that goes
stale. Anything importable under ``modules/`` shows up here the moment it is written.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from dataclasses import dataclass, field
from typing import Any

#: Packages the workbench exposes. `modules` is the pure engine layer — functions that
#: take data and return verdicts, which is what you want to poke at while developing.
_ROOTS = ("modules",)

#: Never offer these: they are plumbing, not capabilities under test.
_SKIP_MODULES = frozenset({"modules.registry", "modules.exec", "modules.safe_http"})
_SKIP_NAMES = frozenset({"main", "run", "__init__"})


@dataclass
class Param:
    name: str
    kind: str  # str | int | float | bool | list | dict | any
    required: bool
    default: Any = None
    annotation: str = ""


@dataclass
class Callable_:
    """One function the workbench can invoke."""

    module: str  # modules.scanning.http_misconfig
    name: str  # analyse_cors
    qualname: str  # modules.scanning.http_misconfig:analyse_cors
    doc: str
    is_async: bool
    params: list[Param] = field(default_factory=list)
    returns: str = ""

    @property
    def group(self) -> str:
        """recon | scanning | osint | … — the folder, used to group the UI."""
        parts = self.module.split(".")
        return parts[1] if len(parts) > 2 else parts[-1]


def _kind_of(annotation: Any) -> str:
    text = str(annotation)
    if annotation is inspect.Parameter.empty:
        return "any"
    for needle, kind in (
        ("bool", "bool"),
        ("int", "int"),
        ("float", "float"),
        ("list", "list"),
        ("tuple", "list"),
        ("set", "list"),
        ("dict", "dict"),
        ("str", "str"),
    ):
        if needle in text:
            return kind
    return "any"


def _describe(fn: Any, module_name: str, name: str) -> Callable_ | None:
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        return None

    params: list[Param] = []
    for pname, p in sig.parameters.items():
        if p.kind in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD):
            continue
        params.append(
            Param(
                name=pname,
                kind=_kind_of(p.annotation),
                required=p.default is inspect.Parameter.empty,
                default=None if p.default is inspect.Parameter.empty else _safe(p.default),
                annotation=("" if p.annotation is inspect.Parameter.empty else str(p.annotation)),
            )
        )

    doc = inspect.getdoc(fn) or ""
    return Callable_(
        module=module_name,
        name=name,
        qualname=f"{module_name}:{name}",
        doc=doc,
        is_async=inspect.iscoroutinefunction(fn),
        params=params,
        returns=(
            "" if sig.return_annotation is inspect.Signature.empty else str(sig.return_annotation)
        ),
    )


def _safe(value: Any) -> Any:
    """Defaults must survive JSON — a callable default (the injection seams these
    modules use everywhere) is shown by name rather than crashing the listing."""
    if isinstance(value, (str, int, float, bool, type(None))):
        return value
    if isinstance(value, (list, tuple, set)):
        return [_safe(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _safe(v) for k, v in value.items()}
    return getattr(value, "__name__", None) or str(value)


def discover() -> list[Callable_]:
    """Every public function under the exposed roots, sorted for a stable UI."""
    out: list[Callable_] = []
    for root in _ROOTS:
        try:
            pkg = importlib.import_module(root)
        except ImportError:
            continue
        for mod in pkgutil.walk_packages(pkg.__path__, prefix=f"{root}."):
            if mod.name in _SKIP_MODULES or mod.ispkg:
                continue
            try:
                module = importlib.import_module(mod.name)
            except Exception:  # noqa: BLE001, S112 - a module that will not import is
                continue  # simply not offered; the workbench must still list the rest
            for name, obj in vars(module).items():
                if name.startswith("_") or name in _SKIP_NAMES:
                    continue
                if not inspect.isfunction(obj):
                    continue
                if obj.__module__ != mod.name:  # re-export, not defined here
                    continue
                described = _describe(obj, mod.name, name)
                if described:
                    out.append(described)
    out.sort(key=lambda c: (c.group, c.module, c.name))
    return out


def resolve(qualname: str):
    """``module:function`` -> the actual callable, or None."""
    if ":" not in qualname:
        return None
    module_name, _, fn_name = qualname.partition(":")
    if module_name in _SKIP_MODULES or not module_name.startswith(_ROOTS):
        return None  # only ever call what discover() would have offered
    try:
        module = importlib.import_module(module_name)
    except Exception:  # noqa: BLE001
        return None
    fn = getattr(module, fn_name, None)
    return fn if inspect.isfunction(fn) else None
