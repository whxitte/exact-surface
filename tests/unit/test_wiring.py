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


def test_cloud_assets_reason_does_not_imply_a_settings_field():
    """The one opt-in module with no per-tenant credential field must say so.

    Every other opt-in module's reason names an API key you paste into Settings
    (Shodan, Censys, SerpApi, ...) and INTEGRATION_KEYS backs that with a real field.
    cloud_assets is different on purpose -- cloud provider credentials are wider blast
    radius than an API key, so the module was built to never let them touch the
    database (modules/recon/cloudlist.py); they live only in an operator-mounted file.
    Reusing the generic "needs a ... key" phrasing here reads exactly like every
    self-service module and sends a customer looking for a field that does not exist.
    """
    spec = next(m for m in registry.MODULES if m.name == "cloud_assets")
    reason = spec.opt_in_reason.lower()
    assert "settings" not in reason or "not from settings" in reason
    assert "cloudlist" in reason or "client_guide" in reason.lower(), (
        "cloud_assets' opt_in_reason must point at where the real setup steps live"
    )


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
        for internal in ("devtools", "demo/"):
            assert internal not in text, f"{name} copies {internal} into the product image"
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped.startswith("COPY ") or "--from" in stripped:
                continue
            src = stripped.split()[1]
            assert src not in (".", "./"), (
                f"{name} uses `COPY {src}`, which would sweep devtools/ into the image. "
                "Copy the specific directories the service needs instead."
            )


def test_the_demo_site_never_enters_a_product_image():
    """The demo replaces lib/transport.ts with a fixture-backed version. If that file
    reached a customer image, the product would silently stop talking to its own API."""
    demo_dockerfile = REPO / "demo" / "Dockerfile"
    assert demo_dockerfile.exists(), "demo/Dockerfile is missing"
    for name in ("Dockerfile.api", "Dockerfile.pipeline", "Dockerfile.frontend"):
        path = REPO / "docker" / name
        if path.exists():
            assert "demo/" not in path.read_text(), f"{name} references demo/"
    assert "demo" in (REPO / ".dockerignore").read_text().split()


def test_demo_attack_surface_fixture_matches_the_current_ui_contract():
    """The demo shares product pages, so its fixtures must evolve with their API shape.

    The attack-surface endpoint once returned ``totals`` and ``by_interest``. The
    product grew a timeline and change log, but the demo fixture was not updated;
    opening a program or Changes therefore crashed in the browser. Keep the static
    fixture explicit about every field the shared UI reads.
    """
    text = (REPO / "demo" / "lib" / "fixtures.ts").read_text()
    start = text.index("export const ATTACK_SURFACE = {")
    end = text.index("} as const;", start)
    fixture = text[start:end]

    required = (
        '"generated_at"',
        '"latest_scan_at"',
        '"previous_scan_at"',
        '"scan_count"',
        '"current"',
        '"total"',
        '"assets"',
        '"endpoints"',
        '"ports"',
        '"findings"',
        '"secrets"',
        '"leaks"',
        '"change"',
        '"opened"',
        '"resolved"',
        '"net"',
        '"series"',
        '"recent"',
        '"kind"',
        '"type"',
        '"label"',
        '"at"',
        '"severity"',
    )
    missing = [field for field in required if field not in fixture]
    assert not missing, f"demo ATTACK_SURFACE is stale; missing current UI fields: {missing}"
    assert '"totals"' not in fixture and '"by_interest"' not in fixture, (
        "demo ATTACK_SURFACE still uses the retired response shape"
    )


def test_the_marketing_site_never_enters_a_product_image():
    """website/ is static marketing HTML deployed to Vercel -- it has no reason to be
    in a product image, and shipping it there would just be bloat and an unreviewed
    surface. Same hygiene as demo/ and devtools/, for the same reason: an explicit
    COPY list can't accidentally sweep it in, but only if nobody adds `COPY . .`."""
    assert (REPO / "website").is_dir(), "website/ is missing"
    for name in ("Dockerfile.api", "Dockerfile.pipeline", "Dockerfile.frontend"):
        path = REPO / "docker" / name
        if path.exists():
            assert "website/" not in path.read_text(), f"{name} references website/"
    assert "website" in (REPO / ".dockerignore").read_text().split()


def test_devtools_is_not_a_service_in_the_production_compose_file():
    compose = REPO / "docker-compose.yml"
    if compose.exists():
        assert "devtools" not in compose.read_text(), (
            "docker-compose.yml defines a devtools service; the workbench is local-only"
        )


# --------------------------------------------------------------------------
# every module's output reaches the user
# --------------------------------------------------------------------------

#: repository class -> the collection it writes, and the frontend method that reads it.
#: A module that persists something the UI cannot fetch has done work nobody will see,
#: which is the same failure as not running at all.
#: (collection, frontend method, API route segment). The route is stated rather than
#: derived from the collection name — `cve_matches` is served at `/cves`, and guessing
#: would make this test assert a convention the code never promised.
_SURFACED: dict[str, tuple[str, str, str]] = {
    "FindingRepo": ("findings", "listFindings", "findings"),
    "AssetRepo": ("assets", "listAssets", "assets"),
    "EndpointRepo": ("endpoints", "listEndpoints", "endpoints"),
    "PortRepo": ("ports", "listPorts", "ports"),
    "SecretRepo": ("secrets", "listSecrets", "secrets"),
    "LeakRepo": ("leaks", "listLeaks", "leaks"),
    "CveMatchRepo": ("cve_matches", "listCves", "cves"),
    "JsFileRepo": ("js_files", "listJsFiles", "js-files"),
    "DeltaRepo": ("deltas", "listDeltas", "deltas"),
    "DomainIntelRepo": ("domain_intel", "getDomainIntel", "domain-intel"),
}


def test_every_module_result_is_reachable_from_the_frontend():
    """Whatever a module finds must be visible to the user.

    The rule this enforces: if a pipeline writes through a repository, the frontend
    must have an API method that reads that repository's data. Otherwise the module
    runs, finds something real, stores it — and the customer never sees it. That has
    happened before (domain_intel computed a full email-security posture and threw it
    away, keeping only integer stats), which is why it is a test and not a habit.
    """
    api_ts = (REPO / "frontend" / "lib" / "api.ts").read_text()
    gaps: list[str] = []

    for spec in registry.MODULES:
        path = REPO / "pipelines" / f"{spec.name}.py"
        if not path.exists():
            continue
        body = path.read_text()
        for repo_cls, (collection, ui_method, _route) in _SURFACED.items():
            if f"{repo_cls}.from_mongo" not in body:
                continue
            if f"{ui_method}:" not in api_ts and f"{ui_method} " not in api_ts:
                gaps.append(f"{spec.name} writes {collection}, but the UI has no {ui_method}")

    assert not gaps, "module output the user cannot see:\n  " + "\n  ".join(gaps)


def test_every_surfaced_collection_has_a_backend_route():
    """The other half: the frontend method must have something to call."""
    programs = (REPO / "api" / "routes" / "programs.py").read_text()
    missing = [
        collection
        for collection, _ui, route in _SURFACED.values()
        if f'/{{program_id}}/{route}"' not in programs
    ]
    assert not missing, f"collections with no API route: {missing}"


def test_every_module_has_an_activity_stepper_label():
    """Every backend module name needs a human label in the frontend's stepper.

    frontend/lib/pipelines.ts' PIPELINE_INFO is a SEPARATE list from core.modules'
    ModuleSpec.label -- it exists because the Activity page's stage stepper wants
    shorter labels ("Discover" vs "Subdomain discovery") than the Settings panel does.
    Being separate means it drifts: twelve modules built after this file was last
    touched (domain_intel, cloud_assets, reverse_dns, js_mine, api_surface,
    http_misconfig, param_discovery, broken_links, cloud_buckets, nuclei_watch,
    supply_chain, typosquat) fell back to their raw snake_case name with no entry,
    which is also what made the stepper look cluttered -- long unstyled names sitting
    next to short Title Case ones threw off what should have been consistent spacing.
    """
    ts = (REPO / "frontend" / "lib" / "pipelines.ts").read_text()
    missing = [spec.name for spec in registry.MODULES if f"\n  {spec.name}: {{" not in ts]
    assert not missing, f"pipelines.ts PIPELINE_INFO has no entry for: {missing}"


def test_every_module_is_mentioned_in_the_knowledge_page():
    """The in-app Knowledge wiki has to explain what a module does, or a customer has
    no way to learn about a capability except by noticing it produced a finding.

    Four modules -- reverse_dns, param_discovery, cloud_buckets, nuclei_watch -- had
    zero mentions anywhere in this file despite being fully shipped, because the page
    is hand-written prose with no structural link back to core.modules (unlike
    PIPELINE_INFO, there isn't even a dict to keep in sync -- it just has to be
    remembered). This can't catch "explained well" vs "explained badly", only
    "mentioned at all": for each module's ModuleSpec.label, every significant word
    (stemmed, so 'inspection' matches 'inspect', 'alerting' matches 'alert') must
    appear somewhere on the page. A label reword is expected to occasionally trip
    this -- fix it by extending the relevant section's prose, not by weakening the
    check.
    """
    import re as _re

    text = (
        (REPO / "frontend" / "app" / "(dashboard)" / "knowledge" / "page.tsx").read_text().lower()
    )
    stop = {"a", "an", "the", "of", "and", "or", "on", "in", "to", "for"}

    def stem(w: str) -> str:
        return w[:5] if len(w) > 6 else w

    gaps: dict[str, list[str]] = {}
    for spec in registry.MODULES:
        words = [
            w for w in _re.findall(r"[a-z]+", spec.label.lower()) if w not in stop and len(w) > 2
        ]
        missing = [w for w in words if stem(w) not in text]
        if missing:
            gaps[spec.name] = missing
    assert not gaps, f"modules with no mention in the Knowledge page: {gaps}"


def test_the_bundled_scope_feed_is_committed():
    """The scope engine's CDN/cloud ranges must be IN GIT, not just on disk.

    `.gitignore` carried an unanchored `data/`, which also matched `core/data/` and
    silently kept this file untracked. Every local build passed because Docker copies
    the working tree — but CI and the release pipeline check out from git, so the
    published images would have shipped without it and raised FileNotFoundError from
    `default_engine()` at import. The product would not have started.

    A file the safety controls depend on has to be verifiably present, not incidentally
    present.
    """
    import subprocess

    result = subprocess.run(  # noqa: S603
        ["git", "ls-files", "--error-unmatch", "core/data/cloud_ranges.json"],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, (
        "core/data/cloud_ranges.json is not tracked by git. Local builds will pass and "
        "released images will fail to start."
    )

    ignored = subprocess.run(  # noqa: S603
        ["git", "check-ignore", "core/data/cloud_ranges.json"],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=False,
    )
    assert ignored.returncode != 0, "core/data/cloud_ranges.json is matched by .gitignore"


def test_the_scope_feed_actually_loads_and_is_not_empty():
    """A present-but-empty feed is worse than a missing one: the engine would classify
    every CDN address as ordinary public space and permit port scans against it."""
    from core.scope import ScopeEngine

    engine = ScopeEngine.from_data_file()
    total = sum(len(v) for v in engine._ranges.values())
    assert total > 20, f"the bundled scope feed has only {total} ranges — it looks empty"


def test_the_customer_bundle_is_installable_without_source():
    """What a buyer receives must run with no repo, no build step and no guesswork.

    docker-compose.prod.yml -- what CLIENT_GUIDE used to point customers at -- names
    local build tags (`exactsurface/api:latest`) and carries `build:` sections. A
    customer who ran the documented `docker pull ghcr.io/...` commands got images that
    file does not reference, and compose would have gone looking for something else
    entirely on Docker Hub. There was no install path at all.
    """
    from pathlib import Path

    import yaml

    text = Path("deploy/docker-compose.yml").read_text()
    spec = yaml.safe_load(text)
    services = spec["services"]

    # No build: anywhere. The customer has no source tree to build from.
    for name, svc in services.items():
        assert "build" not in svc, f"{name} has a build: section; customers have no source"

    # Our own images come from the published registry, pinned, never `latest`.
    ours = ("api", "frontend", "pipeline", "scheduler", "worker")
    for name in ours:
        image = services[name]["image"]
        assert "EXACTSURFACE_REGISTRY" in image, f"{name} does not use the published registry"
        assert ":${EXACTSURFACE_VERSION" in image, f"{name} is not version-pinned"
        assert ":latest}" not in image, (
            f"{name} defaults to `latest`; an image that moves under a running scan is "
            "not something a customer should have to debug"
        )

    # env_file must be beside the compose file, not up a directory into a repo layout.
    for name in ("api", "pipeline", "scheduler", "worker"):
        assert services[name].get("env_file") == ".env", (
            f"{name} must read ./.env — `../.env` assumes the repo directory structure"
        )

    # Datastores must not publish host ports; that is the whole point of the prod shape.
    for name in ("mongo", "redis"):
        assert "ports" not in services[name], f"{name} must not be reachable from the host"

    # deploy/ must be COPYABLE ON ITS OWN. Every host path the compose file mounts has
    # to sit beside it, because that folder is what a customer receives. When these
    # lived in docker/, copying deploy/ to a server produced a compose file mounting
    # four paths that were not there -- and Docker creates a *directory* in place of a
    # missing bind-mount source, so Caddy failed with a confusing error instead of a
    # useful one.
    import re

    for mount in re.findall(r"^\s+- \./([^:]+):", text, re.M):
        assert (Path("deploy") / mount).exists(), (
            f"docker-compose.yml mounts ./{mount} but deploy/{mount} does not exist; "
            "deploy/ must be self-contained, since it is copied verbatim to customers"
        )


def test_the_bundle_env_template_names_every_required_variable():
    """A value compose declares required must appear in the template the customer edits.

    Compose fails with `variable is not set` and no further explanation. Anything
    marked `:?` has to be in .env.example or the customer's first run dies on a
    message that does not say what to do about it.
    """
    import re
    from pathlib import Path

    compose = Path("deploy/docker-compose.yml").read_text()
    template = Path("deploy/.env.example").read_text()

    required = set(re.findall(r"\$\{([A-Z_]+):\?", compose))
    assert required, "expected some required variables"
    for var in sorted(required):
        assert re.search(rf"^{var}=", template, re.M), (
            f"{var} is required by docker-compose.yml but absent from .env.example"
        )


def test_dev_and_customer_compose_projects_cannot_collide():
    """Two compose files sharing a project name are the same project to Docker.

    Compose scopes containers/networks/volumes by the com.docker.compose.project
    label, not by which file started them. If docker/docker-compose.yml (dev) and
    deploy/docker-compose.yml (what a customer -- or an owner simulating one --
    runs) ever share a `name:`, bringing one up after the other is running sees the
    existing containers as belonging to ITS project, detects the service configs
    differ, and recreates them to match: whichever stack was live gets silently
    torn down and rebuilt as the other. This happened in practice: both were named
    `exactsurface` until this test was added.
    """
    import re
    from pathlib import Path

    def project_name(path: str) -> str:
        text = Path(path).read_text()
        m = re.search(r"^name:\s*(\S+)", text, re.M)
        assert m, f"{path} has no top-level `name:`"
        return m.group(1)

    names = {
        "docker/docker-compose.yml": project_name("docker/docker-compose.yml"),
        "deploy/docker-compose.yml": project_name("deploy/docker-compose.yml"),
    }
    assert len(set(names.values())) == len(names), (
        f"compose project names must all be distinct, got {names}"
    )


def test_the_frontend_standalone_bundle_survives_the_build_context():
    """`.dockerignore` must not strip the node_modules Next.js traces into .next.

    ``docker/Dockerfile.frontend``'s ``prebuilt`` stage — the one CI publishes, because
    the standalone output is arch-independent JS and rebuilding it per architecture
    under QEMU is slow — copies ``frontend/.next/standalone`` from the BUILD CONTEXT.
    The bundle carries its own traced ``node_modules``, and the blanket
    ``**/node_modules`` rule matched it: the build succeeded, the image shipped a
    ``server.js`` with no ``next`` module, and every container died at startup with
    "Cannot find module 'next'". Both published images had it.

    Docker resolves ignore rules last-match-wins, so the negation only works if it comes
    after the blanket rule. That ordering is the thing worth asserting: a later edit
    that appends another ``**/node_modules`` (or sorts the file) silently re-breaks it,
    and the next release ships an image nobody can start.
    """
    lines = [ln.strip() for ln in (REPO / ".dockerignore").read_text().splitlines()]
    rules = [ln for ln in lines if ln and not ln.startswith("#")]

    negation = "!frontend/.next/standalone/node_modules"
    assert negation in rules, (
        ".dockerignore must re-include the standalone bundle's node_modules; without it "
        "the published frontend image has no `next` module"
    )
    blanket = [i for i, r in enumerate(rules) if r == "**/node_modules"]
    assert blanket, "expected a **/node_modules rule to negate"
    assert rules.index(negation) > blanket[-1], (
        "the negation must come after every **/node_modules rule — Docker applies the "
        "LAST matching pattern, so an earlier negation is a no-op"
    )

    # And the image itself refuses to build without it, so a context regression fails
    # loudly at build time rather than at some stranger's `docker compose up`.
    dockerfile = (REPO / "docker" / "Dockerfile.frontend").read_text()
    assert dockerfile.count("test -d node_modules/next") == 2, (
        "both the runtime and prebuilt stages should assert the bundle is intact"
    )
