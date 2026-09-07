# The Workbench — internal module test bench

**Read this before running `devtools/`.** It explains what the workbench is, why it is a
separate application rather than a page in the product, exactly how it is contained, and
how to build and use it.

> **The workbench is not part of ExactSurface.** It is never built into a shipped image,
> it adds no endpoint to the product's API, and it refuses to start outside a dev
> environment. If you are an operator reading this: this tool is not in your deployment.

---

## 1. Why it exists

The product runs modules two ways:

* the **full pipeline** — every stage in order, against a verified program;
* the **scheduler's cadence** — each stage on its own interval.

Neither helps when you are *writing* a module and want to call one function, with
arguments you choose, and read what came back. Waiting for a 40-minute pipeline to see
whether your regex works is not a development loop.

The workbench is the third way: pick a function, fill in its arguments, run it, read the
result and the logs.

---

## 2. Why it is a separate app (the important part)

This was a deliberate correction. An earlier version put a "developer console" inside the
ExactSurface dashboard. That was wrong, and not merely for tidiness:

**The product's central promise is that it cannot be aimed at a target you have not
proven you own.** Every scanning call in the pipeline is wrapped by the scope engine,
which refuses hosts outside a verified, authorised program (§9b).

The workbench calls those functions **directly**. `nuclei_scan(url)` with a URL you
typed. No scope engine, no authorisation record, no politeness limiter unless you pass
one. That is exactly what you want while developing a module — and exactly what must
never be reachable from the product's login.

So:

> A tool that can bypass the scope engine must not share a login, a process, or an image
> with the tool whose entire value is that it cannot.

**When you use the workbench, *you* are the control.** Only ever point it at hosts you
own or are explicitly authorised to test. Nothing is enforcing that for you.

---

## 3. How it is contained

### 3.1 It adds nothing to ExactSurface

The most common misunderstanding is that the workbench calls the ExactSurface API with
some special key, and that an outsider might guess that endpoint.

**It does not.** There is no such endpoint. The workbench:

* imports `pipelines.dispatch`, `modules.*` etc. **as Python**, in its own process;
* connects to **Mongo directly** using the same config the product uses.

```
  ┌─────────────────┐        ┌──────────────┐
  │  ExactSurface   │───────▶│              │
  │  api + worker   │        │    MongoDB   │
  └─────────────────┘        │              │
                             │              │
  ┌─────────────────┐        │              │
  │   Workbench     │───────▶│              │
  │  (local only)   │        └──────────────┘
  └─────────────────┘
        imports modules/ + pipelines/ in-process
        ── no HTTP call to the product, ever ──
```

Two tests hold this line:

| Test | Asserts |
|---|---|
| `test_product_api_has_no_devtools_surface` | no route in the product API contains `devtool`, `workbench` or `run-module` |
| `test_no_product_source_file_imports_devtools` | the dependency points one way only — `devtools` imports the product, never the reverse |

There was briefly a `POST /programs/{id}/run-module` endpoint on the product API. **It
was removed.** The second test above exists so it cannot come back by accident.

### 3.2 The workbench's own server

The workbench does run an HTTP server, and that server is its own attack surface. The
threat is **not** the internet — it binds loopback. The threat is the developer's own
browser:

| Threat | Why loopback alone doesn't stop it | Control |
|---|---|---|
| **A website you have open in another tab** | Browsers happily send cross-origin requests to `127.0.0.1`. Without a control, visiting a page could make *your* machine run a scanner. | `Sec-Fetch-Site` / `Origin` check — any cross-site request is refused. `Sec-Fetch-Site` is set by the browser and page JavaScript cannot forge it. |
| **DNS rebinding** — attacker points `evil.com` at `127.0.0.1` so the browser treats it as same-origin | The request genuinely arrives on loopback | `Host` allow-list — only `127.0.0.1`/`localhost`/`[::1]` on our port |
| **Another process or user on the machine** | The port is guessable | Per-run token, `secrets.token_urlsafe(32)`, compared in constant time |

**Every failure returns `404`, never `401`/`403`.** A wrong token makes the whole server
look like it is not there, rather than confirming to a prober that something exists and
only the credential is missing.

The token is:

* **new on every start** — restarting invalidates old links;
* **never written to disk** (a test asserts this — a token in a file outlives the
  process that owned it);
* **sent as a header**, not left in the address bar, so it does not leak via browser
  history or a `Referer`.

### 3.3 It cannot be talked into running arbitrary code

The HTTP API takes a `module:function` string. `introspect.resolve()` only returns
callables that `introspect.discover()` would have offered — under `modules/`, excluding
plumbing. `os:system`, `subprocess:run` and `builtins:eval` all resolve to `None` and
return 400. Tested.

### 3.4 It never enters an image

* Both Dockerfiles use **explicit `COPY` lists**, and none names `devtools`.
* `.dockerignore` lists `devtools`.
* `docker-compose.yml` has no service for it.
* `_assert_dev_only()` raises `SystemExit` when `EXACTSURFACE_ENV=prod` — **not
  overridable by a flag**, because the whole point is that no configuration mistake can
  expose it.

Tests: `test_devtools_is_not_copied_into_any_image` (which also fails if someone
"simplifies" a Dockerfile to `COPY . .`), `test_devtools_is_not_a_service_in_the_
production_compose_file`, `test_production_env_refuses_to_start`.

---

## 4. Building and running it

### Requirements

Nothing beyond the project's own dev dependencies. The workbench uses `fastapi` and
`uvicorn`, both already needed by the API.

```bash
pip install -r requirements.txt
```

### Run

```bash
python -m devtools
```
Or via Docker with all binary tools:

```bash
docker run --rm -d --name exactsurface-workbench -p 8765:8765 -e DEVTOOLS_HOST=0.0.0.0 -e EXACTSURFACE_ENV=dev -v $(pwd):/app exactsurface/pipeline:latest python -m devtools

```
It prints the **only URL that works**:

```
  ExactSurface Workbench — internal only, not part of the product

  http://127.0.0.1:8765/?t=tU-z5b7Cj61vz5AQw2zbIIR-xL3nB1AdDoKzMrhAPOE

  The token is new on every start and is never written to disk.
  Without it every path returns 404, including this one.
```

Open that URL. Without the token, every path — including `/` — returns 404.

### For the pipeline-stage bench only

Stage runs need the datastore the product uses:

```bash
docker compose up -d mongo redis
```

The **function bench needs nothing at all** — no database, no program, no
authorisation. That is the point of it.

### Do not

* **Do not change the bind address.** If you need it from another machine, use an SSH
  tunnel: `ssh -L 8765:127.0.0.1:8765 you@devbox`.
* **Do not put it behind a reverse proxy.** The `Host` allow-list will reject the
  proxied requests, and defeating that check would remove the DNS-rebinding defence.
* **Do not add an endpoint to the product API "just for testing".** A test will fail,
  and it is failing for a reason.

---

## 5. Using it

### Functions tab

Every public callable under `modules/` (currently ~107), discovered by **introspection**
— so a function you write appears the moment you save it, with no registration step.

1. Filter by name or docstring.
2. Pick a function. Its docstring, signature and return type are shown.
3. Fill in arguments. Types come from the annotations:
   * `str` / `int` / `float` → text box
   * `bool` → dropdown
   * `dict` / `list` / untyped → textarea accepting **JSON** *or* a comma-separated list
   * blank means "use the default"
4. **Run**. The result appears as JSON — including dataclass `@property` values such as
   `.severity`, `.vulnerable` and `.evidence`, which are usually the interesting part.

Failures show the **full traceback**, which is the feature, not an error.

### Pipeline stages tab

Runs a real stage against a real program through `pipelines.dispatch.run_pipeline` —
the same entry point the scheduler uses. Scope checks, the authorisation gate, module
on/off resolution and rate limits all apply exactly as in production. A module you have
disabled in settings reports itself skipped here too; that is the honest answer, not a
console limitation.

### Runs pane

Every invocation is listed with status and duration. Click one to see its result and its
**captured log lines** — loguru output is routed into that run's buffer while it
executes. **stop** cancels a run; `modules/exec.py` kills any subprocess it started, the
same path the product's Stop button uses.

Runs are in memory only; the last 50 are kept. This is a dev tool, not a datastore.

---

## 6. Maintaining it

| File | What it does |
|---|---|
| `devtools/server.py` | FastAPI app, the `_guard()` containment checks, run registry, log capture |
| `devtools/introspect.py` | discovers callables and their signatures; `resolve()` is the allow-list |
| `devtools/static/index.html` | the whole UI — vanilla JS, no build step, deliberately |
| `tests/unit/test_devtools_security.py` | every containment control above |

The UI has **no build step on purpose**. A dev tool that needs `npm install` before you
can debug a regex is a dev tool people stop using.

If you add a capability, add its containment test in the same commit. The rule for this
directory is stricter than for the product:

> We sell attack-surface management. Shipping a tool that exposes our own surface would
> be the worst possible advertisement — and unlike a normal bug, it would be quoted back
> at us forever.
