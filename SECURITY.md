# Reporting a vulnerability

**Do not open a public issue for a security bug.** Use GitHub's private reporting:
[**Report a vulnerability**](https://github.com/whxitte/exact-surface/security/advisories/new),
which opens a private advisory only the maintainers can see.

Include what you'd want if you were fixing it: affected version or commit, what an
attacker gains, and the shortest reproduction you have. A proof-of-concept against your
own instance is welcome; please don't test against anyone else's.

**What to expect:** an acknowledgement within a few days and a first assessment within a
week. This is a small project — if it's quiet longer than that, it means the message was
missed, so please chase it rather than assume it was ignored.

Fixes ship in a normal release with a `CHANGELOG.md` entry and, where it matters to
anyone running an instance, a GitHub Security Advisory. Tell us if you'd like credit and
how you want to be named.

## What counts as a vulnerability here

ExactSurface is a scanner that holds credentials and scans real infrastructure, so the
bugs that matter most are the ones that break its own boundaries:

- **Scope-engine escape** — anything that gets a scan to reach an address the engine
  should have refused: internal ranges, link-local and cloud metadata, a CDN edge,
  or a host outside the verified apex. See [`docs/SECURITY.md`](docs/SECURITY.md) §2 and
  ADR-0005.
- **Authorization bypass** — scanning without a current authorization record, or
  defeating DNS-TXT verification or the §9b ASN confirmation.
- **Tenant isolation** — reading, writing or inferring another tenant's programs,
  findings, assets or secrets. Cross-tenant reads are 404s by design; a 403 that leaks
  existence is itself a finding.
- **Secret exposure** — a discovered secret stored, logged, exported or alerted in
  plaintext. ADR-0006 says these are masked everywhere.
- **SSRF and command injection** — the scanner fetches attacker-influenced URLs and
  shells out to tools; `modules/safe_http.py` and `modules/exec.py` are the guards.
- **RCE, auth bypass, privilege escalation** in the API or worker, and injection into
  the datastores.

## What does not

- **Findings the tool reports about your own infrastructure.** Those are output, not
  bugs in ExactSurface. Take them to whoever owns that infrastructure.
- **Scanning you configured.** ExactSurface scans what a verified, authorized program
  tells it to, and an operator can widen that deliberately — including with the
  scope-override switch, which exists on purpose, is off by default, and is documented
  as dangerous. Turning it on and reaching something you should not have is the
  operator's decision, not a vulnerability.
- **Anything requiring database access to the instance.** Somebody who can write to your
  Mongo can mark any domain verified. `docs/SECURITY.md` §2 states this trade openly:
  there is no cryptographic fix that does not turn this project into a gatekeeper over
  what every operator may scan.
- **Missing hardening with no exploit path** — a header, a dependency with no reachable
  call, a scanner's default output. Interesting, but send it as a normal issue.

## Supported versions

The latest release only. This is a small project; there are no maintained release
branches, and the fix for anything reported here will land on `main` and in the next
version.
