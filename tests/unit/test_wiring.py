"""Wiring contracts — the registries that must never drift apart.

A capability in this product is not one thing in one file. A module is a spec in
``core.modules``, a route in ``pipelines.dispatch``, a stage in the orchestrator, an
interval in ``taskqueue.cadence``, a budget in ``taskqueue.timeouts``, and usually a
binary in the scanning image. Add it to five of those six and everything looks fine
until the one path that needs the sixth runs — in production, at 3am, on a customer's
deployment.

That is not hypothetical. It has now happened twice:

* ``alterx`` was installed in the image and imported by nothing, so permutation
  discovery silently never ran;
* ``js_mine``, ``broken_links``, ``domain_intel``, ``tls``, ``service_scan``,
  ``cloud_buckets``, ``nuclei_watch`` and ``dork`` were registered, scheduled and
  wired into the full scan but had no dispatch route, so every per-phase run after
  the first bootstrap scan died with "unknown pipeline".

Both were invisible to a green test suite because nothing asserted the *relationships*
between the registries — only that each one was individually well-formed. These tests
assert the relationships. They are pure and fast (no I/O, no network, no DB): they read
declarations and compare sets. When one fails it is telling you that you added a
capability to some places and not others, and the failure message names the gap.
"""

from __future__ import annotations

import pathlib
import re

import pytest

from core import modules as registry
from modules.registry import MODULE_REGISTRY, required_binaries
from pipelines.dispatch import ROUTES
from pipelines.orchestrate import FULL_STAGE_NAMES
from taskqueue.cadence import CONFIGURABLE_PIPELINES, DEFAULT_CADENCE_SECONDS
from taskqueue.cascade import CASCADE
from taskqueue.timeouts import DEFAULT_TIMEOUTS_SECONDS

REPO = pathlib.Path(__file__).resolve().parents[2]
DOCKERFILE = REPO / "docker" / "Dockerfile.pipeline"

#: Directories whose Python is allowed to invoke an external binary.
_SOURCE_DIRS = ("modules", "pipelines", "core", "scripts", "taskqueue", "daemon", "api")


# --------------------------------------------------------------------------
# module registry <-> the four tables that must cover it
# --------------------------------------------------------------------------


def test_every_module_has_a_dispatch_route():
    """A module with no route can be scheduled but not run — the "unknown pipeline" bug."""
    missing = [m for m in registry.MODULE_NAMES if m not in ROUTES]
    assert not missing, (
        f"modules with no route in pipelines.dispatch.ROUTES: {missing}. "
        "The scheduler will enqueue these and every run will fail."
    )


def test_no_route_without_a_module():
    """The reverse: a route for a module that no longer exists is dead code."""
    orphans = [name for name in ROUTES if name not in registry.BY_NAME]
    assert not orphans, f"dispatch routes for modules that do not exist: {orphans}"


def test_schedulable_modules_match_the_cadence_table_exactly():
    """Schedulable means "has its own re-run interval" — so it must have one, and a
    module that is not schedulable must not be given one (the scheduler would run it)."""
    schedulable = {m.name for m in registry.MODULES if m.schedulable}
    assert schedulable - set(DEFAULT_CADENCE_SECONDS) == set(), (
        f"schedulable modules with no cadence: {sorted(schedulable - set(DEFAULT_CADENCE_SECONDS))}"
    )
    assert set(DEFAULT_CADENCE_SECONDS) - schedulable == set(), (
        "cadence entries for modules that are not schedulable: "
        f"{sorted(set(DEFAULT_CADENCE_SECONDS) - schedulable)}"
    )


def test_every_module_has_a_timeout_budget():
    """Without one a stage falls back to a caller-supplied default, which is how a
    stage ends up with the wrong budget and times out every run (see: dork)."""
    missing = [m for m in registry.MODULE_NAMES if m not in DEFAULT_TIMEOUTS_SECONDS]
    assert not missing, f"modules with no entry in DEFAULT_TIMEOUTS_SECONDS: {missing}"
    orphans = [s for s in DEFAULT_TIMEOUTS_SECONDS if s not in registry.BY_NAME]
    assert not orphans, f"timeout budgets for modules that do not exist: {orphans}"


def test_full_pipeline_runs_every_module_in_registry_order():
    """The full scan must cover every module, and the registry's declaration order is
    the documented execution order the UI renders — so they cannot disagree."""
    assert list(FULL_STAGE_NAMES) == list(registry.MODULE_NAMES), (
        "FULL_STAGE_NAMES and core.modules.MODULE_NAMES disagree.\n"
        f"  only in full run: {sorted(set(FULL_STAGE_NAMES) - set(registry.MODULE_NAMES))}\n"
        f"  only in registry: {sorted(set(registry.MODULE_NAMES) - set(FULL_STAGE_NAMES))}\n"
        "  (if both are empty the contents match but the ORDER differs)"
    )


def test_cadence_configurable_set_matches_the_table():
    assert set(CONFIGURABLE_PIPELINES) == set(DEFAULT_CADENCE_SECONDS)


def test_every_cascade_phase_is_a_real_dispatchable_module():
    """The event cascade enqueues by name too, so its graph is a third source of
    pipeline names that can rot."""
    reachable = set(CASCADE) | {n for nxt in CASCADE.values() for n in nxt}
    unknown = sorted(p for p in reachable if p not in registry.BY_NAME)
    assert not unknown, f"cascade refers to modules that do not exist: {unknown}"
    unroutable = sorted(p for p in reachable if p not in ROUTES)
    assert not unroutable, f"cascade phases with no dispatch route: {unroutable}"


# --------------------------------------------------------------------------
# module registry internal consistency
# --------------------------------------------------------------------------


def test_dependencies_name_real_modules():
    for spec in registry.MODULES:
        for need in spec.requires:
            assert need in registry.BY_NAME, f"{spec.name} requires unknown module {need!r}"


def test_dependencies_point_backwards_in_execution_order():
    """A stage cannot consume the output of a stage that runs after it."""
    position = {name: i for i, name in enumerate(registry.MODULE_NAMES)}
    for spec in registry.MODULES:
        for need in spec.requires:
            assert position[need] < position[spec.name], (
                f"{spec.name} requires {need}, which runs later in the pipeline"
            )


def test_essential_modules_have_no_optional_dependencies():
    """An essential module that depends on a disableable one is a contradiction: the
    user could switch off its input and the resolver would try to skip the unskippable."""
    for spec in registry.MODULES:
        if not spec.essential:
            continue
        for need in spec.requires:
            assert registry.BY_NAME[need].essential, (
                f"essential module {spec.name} depends on non-essential {need}"
            )


def test_opt_in_modules_explain_themselves():
    """A switch that is off by default has to say why, or the user cannot make a choice."""
    for spec in registry.MODULES:
        if not spec.default_enabled:
            assert spec.opt_in_reason.strip(), f"{spec.name} is opt-in but gives no reason"


def test_every_module_has_user_facing_text():
    for spec in registry.MODULES:
        assert spec.label.strip(), f"{spec.name} has no label"
        assert spec.summary.strip(), f"{spec.name} has no summary"
        assert spec.label != spec.name, f"{spec.name} label is the raw name, not written for a user"


def test_essential_modules_survive_being_disabled():
    """The single enforcement point: no combination of user input disables the spine."""
    state = registry.resolve(disabled_modules=list(registry.MODULE_NAMES))
    for name in registry.ESSENTIAL:
        assert state.is_enabled(name), f"{name} is essential but was disabled"
    assert registry.sanitize_disabled(list(registry.MODULE_NAMES)) == sorted(
        set(registry.MODULE_NAMES) - registry.ESSENTIAL
    )


def test_disabling_a_module_reports_a_reason_for_every_casualty():
    """Anything that stops running must say why — silence is what makes a toggle a trap."""
    state = registry.resolve(disabled_modules=["crawl"])
    for name in registry.MODULE_NAMES:
        if not state.is_enabled(name):
            assert state.reason(name).strip(), f"{name} will not run but gives no reason"
    for name in registry.dependents_of("crawl"):
        assert not state.is_enabled(name), f"{name} depends on crawl but stayed enabled"


# --------------------------------------------------------------------------
# code <-> scanning image
# --------------------------------------------------------------------------


def _dockerfile_text() -> str:
    return DOCKERFILE.read_text()


def _go_installed_binaries() -> set[str]:
    """Binary names from `go install <path>/<name>[/vN]@<version>` lines."""
    return set(re.findall(r"go install \S*?/([A-Za-z0-9_-]+)(?:/v\d)?@", _dockerfile_text()))


def _source_files() -> list[pathlib.Path]:
    files: list[pathlib.Path] = []
    for d in _SOURCE_DIRS:
        files.extend((REPO / d).rglob("*.py"))
    return files


def _binary_is_invoked(binary: str) -> bool:
    """True if any source file names *binary* as a string literal.

    Every wrapper passes the binary name as a quoted literal to ``modules.exec``, so
    this is precise enough to catch a tool nothing calls without matching prose.
    """
    needles = (f'"{binary}"', f"'{binary}'")
    return any(
        any(n in f.read_text() for n in needles)
        for f in _source_files()
        if f.name != "registry.py"  # the roster names every tool by definition
    )


@pytest.mark.parametrize("binary", sorted(_go_installed_binaries()))
def test_every_installed_binary_has_a_caller(binary: str):
    """No dead tools in the image.

    Shipping a binary nothing calls is wasted image weight and, worse, a false promise:
    the tool list is a sales claim. If a tool is here it must be wired. If we have
    decided not to wire it, it comes out of the Dockerfile (and the reason is recorded
    there) rather than sitting inert — cloudlist, notify and masscan were all removed
    this way.
    """
    assert _binary_is_invoked(binary), (
        f"{binary} is installed in the scanning image but no source file invokes it. "
        "Wire it into a module, or remove it from docker/Dockerfile.pipeline."
    )


@pytest.mark.parametrize("binary", sorted(required_binaries()))
def test_every_required_binary_is_installed(binary: str):
    """The reverse, and the more dangerous direction: a wrapper that shells out to a
    binary the image never installs fails only at runtime, on a real scan."""
    assert binary in _dockerfile_text(), (
        f"{binary} is required by an enabled module but never installed in "
        "docker/Dockerfile.pipeline."
    )


# --------------------------------------------------------------------------
# discoveries <-> the API that shows them
# --------------------------------------------------------------------------

#: Every per-program discovery store and the route a user reads it through. The
#: product's promise is that anything we find is visible; a repository the API never
#: exposes is a thing we found and then hid. domain_intel shipped that way once — the
#: email posture was computed every scan and thrown away because only ints survived
#: into the ScanRun — so the mapping is declared explicitly and checked both ways.
REPO_ROUTES: dict[str, str] = {
    "AssetRepo": "/programs/{program_id}/assets",
    "EndpointRepo": "/programs/{program_id}/endpoints",
    "FindingRepo": "/programs/{program_id}/findings",
    "SecretRepo": "/programs/{program_id}/secrets",
    "PortRepo": "/programs/{program_id}/ports",
    "LeakRepo": "/programs/{program_id}/leaks",
    "CveMatchRepo": "/programs/{program_id}/cves",
    "JsFileRepo": "/programs/{program_id}/js-files",
}


def _discovery_repos() -> dict[str, type]:
    """Every concrete per-program store (a ``db.base.Repository`` subclass)."""
    import importlib
    import inspect
    import pkgutil

    import db
    from db.base import Repository

    out: dict[str, type] = {}
    for mod_info in pkgutil.iter_modules(db.__path__):
        mod = importlib.import_module(f"db.{mod_info.name}")
        for name, obj in vars(mod).items():
            if (
                inspect.isclass(obj)
                and issubclass(obj, Repository)
                and obj is not Repository
                and obj.__module__ == mod.__name__
            ):
                out[name] = obj
    return out


def test_every_discovery_store_is_readable_through_the_api():
    """Anything we persist about a program must have a way for the user to see it."""
    repos = set(_discovery_repos())
    unexposed = sorted(repos - set(REPO_ROUTES))
    assert not unexposed, (
        f"discovery repositories with no declared API route: {unexposed}. "
        "We store this and never show it — either expose it or explain why here."
    )
    stale = sorted(set(REPO_ROUTES) - repos)
    assert not stale, f"REPO_ROUTES names repositories that no longer exist: {stale}"


def test_declared_discovery_routes_actually_exist():
    """...and the declared route is real, not aspirational."""
    from api.routes.programs import router

    live = {r.path for r in router.routes if "GET" in getattr(r, "methods", set())}
    missing = sorted(p for p in REPO_ROUTES.values() if p not in live)
    assert not missing, f"declared read routes that the router does not serve: {missing}"


def test_disabled_registry_modules_do_not_ship_their_binary():
    """A disabled module's tool must not be in the image; that is what disabled means.
    masscan's ADR claimed the binary shipped "so re-enabling is a config change" while
    no wrapper existed — a promise the code could not keep."""
    text = _dockerfile_text()
    for spec in MODULE_REGISTRY:
        if spec.enabled or not spec.binary:
            continue
        assert not re.search(rf"(go install \S*{spec.binary}@|^\s+{spec.binary}\s)", text, re.M), (
            f"{spec.name} is disabled in modules/registry.py but its binary is still "
            "installed in the scanning image."
        )


# --------------------------------------------------------------------------
# the workbench must never ship
# --------------------------------------------------------------------------


def test_devtools_is_not_copied_into_any_image():
    """The workbench can call a scanning function directly, with no scope engine in
    front of it. That is fine on a developer's laptop and unacceptable in a customer's
    deployment, so it must never enter an image. Both Dockerfiles use explicit COPY
    lists rather than `COPY . .`, which is what keeps it out — this asserts nobody
    later "simplifies" that into a wildcard."""
    for name in ("Dockerfile.api", "Dockerfile.pipeline", "Dockerfile.frontend"):
        path = REPO / "docker" / name
        if not path.exists():
            continue
        text = path.read_text()
        assert "devtools" not in text, f"{name} copies devtools/ into the image"
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped.startswith("COPY ") or "--from" in stripped:
                continue
            src = stripped.split()[1]
            assert src not in (".", "./"), (
                f"{name} uses `COPY {src}`, which would sweep devtools/ into the image. "
                "Copy the specific directories the service needs instead."
            )


def test_devtools_is_not_a_service_in_the_production_compose_file():
    compose = REPO / "docker-compose.yml"
    if compose.exists():
        assert "devtools" not in compose.read_text(), (
            "docker-compose.yml defines a devtools service; the workbench is local-only"
        )
