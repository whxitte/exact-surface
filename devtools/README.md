# ExactSurface Workbench — internal module test bench

**This is not part of the product.** It is a separate local-only app for developing and
testing modules. It is never built into the shipped images, never mounted on the
customer API, and refuses to start outside a dev environment.

## What it is for

The product runs modules two ways: the whole ordered pipeline, or the scheduler's
per-phase cadence. Neither helps when you are writing a module and want to call one
function, with arguments you choose, and read what came back.

The workbench gives you the third way:

* **Call any function directly** — every public callable under `modules/` is discovered
  by introspection, with its real signature. Fill in the arguments, run it, see the
  return value and the log lines it produced. No pipeline, no database, no program, no
  scope engine. Just the function.
* **Run any pipeline stage** — the full stage against a real program, through the same
  `run_pipeline` dispatcher production uses, so scope/auth/politeness behave identically.
* **Stop a run** that is taking too long.
* **Read the logs** of either, live.

## Running it

```bash
python -m devtools
```

Then open <http://127.0.0.1:8765>.

It binds `127.0.0.1` only — it is not reachable from another machine, and there is no
authentication because there is no network path to it. Do not put it behind a proxy or
change the bind address; if you need it elsewhere, use an SSH tunnel.

## Safety

* **Refuses to start when `EXACTSURFACE_ENV=prod`.** The check is in
  `devtools/server.py::_assert_dev_only` and is not overridable by a flag.
* **Not in any production image.** `docker/Dockerfile.pipeline` and the api/frontend
  images do not copy `devtools/`, and `docker-compose.yml` has no service for it.
* **Calling a scanning function still hits the network.** The workbench bypasses the
  pipeline, which means it also bypasses the scope engine's target checks that the
  pipeline applies around these functions. **You are the control.** Only ever point it
  at hosts you own or are authorised to test — the same rule that governs the product,
  except here nothing is enforcing it for you.

That last point is why this is a separate app rather than a page in the product: the
product's guarantee is that it cannot be pointed at a target you have not proven you
own. A tool that can call `nuclei_scan(url)` directly cannot make that promise, so it
must not live behind the same login.
