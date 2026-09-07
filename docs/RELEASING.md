# Maintainer runbook

For cutting a release and keeping deployments healthy. If you are *running*
ExactSurface rather than releasing it, [`OPERATIONS.md`](OPERATIONS.md) is the document
you want.

---

## 1. Cutting a release

The version lives in `pyproject.toml`, and CI refuses to release if the tag disagrees.

```bash
# 1. bump pyproject.toml   → version = "1.3.0"
# 2. add the entry to CHANGELOG.md
git commit -am "Version 1.3.0"
git tag -a v1.3.0 -m "ExactSurface v1.3.0"
git push origin main --tags
```

The `Release` workflow then runs the full test suite, lint and the frontend build;
builds and pushes `api`, `frontend` and `pipeline` to GHCR tagged `:X.Y.Z` and
`:latest` with the build id baked in; and publishes a GitHub Release carrying the image
digests and the packaged `deploy/` bundle.

**A tag that disagrees with `pyproject.toml` fails the release on purpose.** That
mismatch is how people end up running a build nobody can identify.

Images go to GHCR rather than Docker Hub: Actions authenticates to GHCR with its own
`GITHUB_TOKEN`, so there is no registry secret to manage. The workflow needs no
repository secrets at all.

### Smoke-test before you tag

Five minutes, worth it every time — a release is three multi-arch images and a public
GitHub Release, and unpicking one is far more work than this.

```bash
docker build -f docker/Dockerfile.api \
    --build-arg BUILD_ID=1.3.0 \
    --build-arg GIT_COMMIT=$(git rev-parse --short HEAD) \
    -t es-smoke:api .
docker run --rm es-smoke:api python -c "from core.build_info import summary; print(summary())"
docker rmi es-smoke:api
```

For the pipeline image, confirm the toolchain arrived and the workbench did not:

```bash
docker build -f docker/Dockerfile.pipeline --build-arg BUILD_ID=1.3.0 -t es-smoke:pipe .
docker run --rm es-smoke:pipe sh -c 'command -v cloudlist arjun nuclei subfinder >/dev/null && echo tools-ok'
docker run --rm es-smoke:pipe sh -c 'test -d /app/devtools && echo LEAKED || echo devtools-absent-ok'
docker rmi es-smoke:pipe
```

For the frontend, confirm it actually starts. This is not paranoia: 1.0.0 and 1.1.0 both
shipped an image that exited immediately with `Cannot find module 'next'`, because a
`.dockerignore` rule had stripped the standalone bundle's dependencies and nothing
checked. The build now asserts it, but the thirty-second version is still worth running:

```bash
docker build -f docker/Dockerfile.frontend --target runtime -t es-smoke:web .
docker run --rm -d --name es-smoke -p 3999:3000 es-smoke:web
curl -sf localhost:3999/login >/dev/null && echo frontend-ok
docker rm -f es-smoke && docker rmi es-smoke:web
```

## 2. After the release

Confirm the published images are what you think they are, rather than trusting a green
workflow:

```bash
docker pull ghcr.io/whxitte/frontend:1.3.0
docker run --rm --entrypoint sh ghcr.io/whxitte/frontend:1.3.0 -c "ls node_modules/next >/dev/null && echo ok"
```

The GHCR packages are public. If someone cannot pull, check the tag exists and check the
platform — `pipeline` is **amd64-only**, so it will not pull on an arm64 host (Apple
silicon, Graviton).

## 3. Ongoing maintenance

| Cadence | Task |
|---|---|
| On a high-severity dependency advisory | Patch and cut a release |
| Quarterly | Test-restore a backup |
| Per release | Keep `CHANGELOG.md` current — it is the only version history anyone reads |

### Test-restore a backup

```bash
python -m scripts.backup restore ./backups/<file>.age --identity ~/age-identity.txt
```

Against a throwaway Mongo, never production. **If you have never run it, you do not have
backups** — you have files you hope are backups.

## 4. When a scan does nothing

In order:

1. Is the **worker** running? `docker compose ps`
2. Is the program **verified and authorized**? Unauthorized programs never scan, by
   design — see [`SECURITY.md`](SECURITY.md) §2.
3. Is the target on shared infrastructure? Port scanning and content discovery are
   withheld without ASN-confirmed dedicated ranges (§9b). The run log says so.
