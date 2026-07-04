# 0002 — ProjectDiscovery-first toolchain
Date: 2026-07-04
Status: Accepted

## Context
The pipeline chains many recon/scan tools. A heterogeneous set (each with its own
output format, flags, and maintenance status) inflates the wrapper surface and the
parsing burden, and makes rate-limiting inconsistent.

## Decision
Standardise on the **ProjectDiscovery suite** where one exists: `subfinder`,
`dnsx`, `httpx`, `naabu`, `katana`, `nuclei`, `tlsx`, `asnmap`, `cloudlist`,
`uncover`, `notify`, `alterx`. Keep best-in-class non-PD tools where PD has no
equal: `feroxbuster`/`ffuf` (content discovery), `gau`/`waybackurls` (archives),
`nmap` (deep service ID), `gitleaks`/`trufflehog` (secret detection).

## Consequences
- Consistent JSON output across tools → smaller, uniform wrapper layer.
- Built-in `-rate`/`-c` flags across PD tools make the politeness limiter (§3.8b)
  enforceable at the tool level as well as globally.
- One `nuclei -update-templates` cadence instead of many scanner updates.
- `uncover` collapses Shodan/Censys/Fofa/Zoomeye into one wrapper (replaces the
  separate Shodan + Censys modules in the original spec).

## Alternatives considered
- A per-capability "best tool" grab-bag. Rejected: higher wrapper/parse/maintenance
  cost and inconsistent rate controls.
