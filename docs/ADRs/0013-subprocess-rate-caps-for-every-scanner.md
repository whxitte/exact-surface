# 0013 — Every scanner subprocess is rate-capped, not just naabu

Date: 2026-07-17
Status: Accepted

## Context

ADR-0009 established that a token bucket in our process cannot govern a subprocess:
naabu sends its own packets, so the politeness ceiling (§3.8b) has to be handed to
it as a `-rate` flag derived from the per-target cap. That ADR fixed naabu.

It did not fix the other five tools that send their own traffic at customer hosts,
and nobody had checked them. An audit found **none of them passed any rate flag**:

| Tool | Wrapper | Own default | Passed |
| --- | --- | --- | --- |
| httpx | `modules/probing/httpx.py` | 150 rps | nothing |
| katana | `modules/crawling/katana.py` | 150 rps | nothing |
| nuclei | `modules/scanning/nuclei.py` | 150 rps (`-rl`) | `-c 50` only (concurrency, not rate) |
| feroxbuster | `modules/content_discovery/feroxbuster.py` | unlimited | `-t 25` only (threads, not rate) |
| ffuf | `modules/content_discovery/ffuf.py` | unlimited (`-rate 0`) | nothing |

So the configured "10 requests/sec per target" was, in practice, **15× that for
every HTTP-layer tool and unbounded for content discovery** — which brute-forces
thousands of wordlist paths and is the single most abusive thing the platform does
to one host. This is the same class of gap as ADR-0009 and ADR-0012: the *intent*
was documented (the §3.8b ceiling), and the code at the edge did not honour it.

A subtlety that made it easy to miss: `nuclei -c` and `feroxbuster -t` *look* like
rate controls. They are concurrency controls. Fifty templates running at once with
no `-rl` still leaves requests at whatever rate the host will answer; bounding
concurrency without bounding rate does not cap the rate.

## Decision

**Every subprocess that talks to a customer host derives and passes a rate flag,
through one shared helper.**

`core.ratelimit.derive_subprocess_rate(host_count, cap, *, tool)` replaces the
naabu-only `subprocess_rate_for` call site. It returns a `SubprocessRate`
(aggregate, per-target, cap, `within_cap`) **and publishes** the per-tool metrics.
Deriving and reporting are one act on purpose — a tool cannot end up
capped-but-invisible, or (worse) look reported while running uncapped, because both
come from the same call.

Two invocation shapes, and getting them wrong silently breaks the cap:

- **Many hosts, one process** (naabu, httpx): the tool is handed the whole host
  list, so its flag is an *aggregate* and the per-target rate is `aggregate ÷
  hosts`. `derive_subprocess_rate(len(hosts), cap, …)`.
- **One host per invocation** (katana, feroxbuster, ffuf, and nuclei per URL): the
  flag *is* the per-target rate, so pass `host_count=1` and hand over the cap
  itself. Concurrent invocations are of *different* hosts, so each stays within its
  own target's ceiling.

nuclei is the case to watch: it is handed a URL list, but `pipelines/scan.py`
already reduces to one representative URL per host, so URL-count equals host-count.
That reduction is now load-bearing for the rate math, and is commented as such — if
it ever changes to multiple URLs per host, the derivation silently grants that host
N× the cap.

The metric family is unified: `exactsurface_subprocess_rate_pps{tool}` and
`exactsurface_subprocess_per_target_pps{tool}` replace the naabu-specific
`exactsurface_port_scan_*` gauges. The §15 alert (`SubprocessRateExceedsPolitenessCap`)
and the dashboard panel now cover every tool, with the `tool` label identifying
which one slipped.

Each wrapper keeps a `DEFAULT_RATE = 10` for direct/manual use, but it is a
fallback, not the policy — the policy is what the pipeline derives and passes.

## Consequences

**Good.** The §3.8b ceiling is enforced for all in-house scan egress, not one tool
of six. The §15 exit criterion — "verified by metrics" — now has a per-tool signal
behind it. `test_subprocess_rate.py` guards the derivation math *and* asserts at the
source level that every wrapper passes its flag and every pipeline derives a rate —
the reachability check that the "supports a flag" vs "passes the flag" gap needs,
since a behavioural test of a correct-but-unwired flag passes just as happily as a
wired one (the lesson of ADR-0012).

**Throughput cost, accepted.** Capping httpx/katana/nuclei from 150 to ≤10 rps
per target makes probing and scanning slower. That is the correct direction: §3.8b
exists precisely to trade our speed for a third party's not filing an abuse report.
Where genuinely more throughput is safe (a customer's own confirmed-dedicated
infra), the lever is `global_rate_per_target`, which flows through the derivation to
every tool at once.

**Concurrency is still unbounded per-tool in aggregate.** `derive_subprocess_rate`
caps the *rate* each invocation uses; the pipelines separately bound how many
invocations run at once (`CRAWL_CONCURRENCY`, the content-discovery semaphore). A
tool's rate is capped per target, but two crawls of two different hosts still run
in parallel — which is correct, since the ceiling is per target.

**`SUBPROCESS_RATE_CEILING` (1000) still applies** as an absolute aggregate stop, so
a pathological host count cannot hand a tool an unbounded rate even within the
per-target math.

**Not covered:** tools that do not contact customer hosts (subfinder, dnsx against
resolvers, gau/waybackurls against archives, asnmap). Their traffic goes to
third-party APIs/resolvers, governed by those services' own limits, not §3.8b.

## Alternatives considered

- **Leave the HTTP tools uncapped and rely on concurrency limits.** The status quo.
  Concurrency bounds parallelism, not rate; a single-threaded loop against one host
  still exceeds the cap. It also failed the §15 exit criterion outright.
- **Route every tool's requests through the in-process token bucket.** Impossible by
  construction — that is the whole ADR-0009 premise. The bucket cannot see a
  subprocess's sockets.
- **One rate flag value, hard-coded per tool.** Ignores host count: 50 hosts handed
  to httpx at 10 rps aggregate is 0.2 rps each (needlessly slow), while 1 host at a
  fixed aggregate could exceed the cap. The rate has to be derived from the actual
  host count, which is what the helper does.
- **A separate metric per tool** (`exactsurface_httpx_rate_pps`, …). More series, and the
  alert would need one rule per tool. A `tool` label gives one rule and one panel.
