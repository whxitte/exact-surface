# Licensing

ExactSurface is released under the **Apache License 2.0** — see [`../LICENSE`](../LICENSE).

You may run, modify and redistribute it, including commercially and inside closed-source
products, subject to the attribution and patent terms in the licence. There is no
separate commercial edition, and nothing in the codebase phones home.

## No runtime restrictions

Earlier builds carried a licence-key check and a control plane that could degrade an
instance to read-only. **Both were removed in 1.1.0.** There are no keys, no
subscription checks, no paywalls, and no domain or scan limits. Every module is unlocked
out of the box.

| Capability | Status |
|---|---|
| Domains & programs | Unlimited |
| Users & members | Unlimited |
| API keys | Unlimited |
| Scans & cadence | Unlimited — no interval floor |
| History retention | Full |
| 403 bypass & reports | Included |
| Detection modules | All 28, individually togglable per program |
| Read-only degradation | Does not exist |

Modules are turned on and off per program on the **Scan modules** card. The README
lists all 28 and what each one does.

## Third-party tools

The pipeline image downloads the scanning toolchain (subfinder, httpx, nuclei, katana,
naabu, feroxbuster, nmap and others) at build time. Those are third-party programs under
their own licences; they are not redistributed as part of this repository, and Apache-2.0
covers ExactSurface's own code only.

## Scanning is still governed by law, not by this licence

The licence grants you rights to the software. It grants you nothing with respect to
systems you do not own. See [`SECURITY.md`](SECURITY.md) §2 and the authorised-use notice
in the README.
