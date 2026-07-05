#!/usr/bin/env bash
# Print the latest upstream release tag for each pinned recon tool, formatted as
# docker build-args. Use it to refresh the ARG pins in docker/Dockerfile.pipeline.
#
#   scripts/tool_versions.sh                 # list current latest tags
#   docker build $(scripts/tool_versions.sh --args) -f docker/Dockerfile.pipeline .
#
# Requires curl. GitHub's unauthenticated API is rate-limited (~60/hr); set
# GITHUB_TOKEN to raise the limit. Portable to bash 3.2 (macOS default).
set -eu

# "ARGNAME repo" pairs (no associative arrays — bash 3.2 has none).
TOOLS="
SUBFINDER projectdiscovery/subfinder
DNSX projectdiscovery/dnsx
HTTPX projectdiscovery/httpx
NAABU projectdiscovery/naabu
KATANA projectdiscovery/katana
NUCLEI projectdiscovery/nuclei
TLSX projectdiscovery/tlsx
ASNMAP projectdiscovery/asnmap
CLOUDLIST projectdiscovery/cloudlist
UNCOVER projectdiscovery/uncover
NOTIFY projectdiscovery/notify
ALTERX projectdiscovery/alterx
FFUF ffuf/ffuf
GAU lc/gau
"

AUTH=""
[ -n "${GITHUB_TOKEN:-}" ] && AUTH="-H Authorization:Bearer ${GITHUB_TOKEN}"

as_args="${1:-}"
echo "$TOOLS" | while read -r name repo; do
  [ -z "$name" ] && continue
  tag=$(curl -fsS $AUTH "https://api.github.com/repos/${repo}/releases/latest" \
        | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')
  if [ "$as_args" = "--args" ]; then
    printf -- '--build-arg %s_VERSION=%s ' "$name" "$tag"
  else
    printf '%-12s %s\n' "$name" "$tag"
  fi
done
echo
