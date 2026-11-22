#!/usr/bin/env bash
# Fetch the public, intentionally vulnerable Node.js applications used as a
# real-world benchmark, pinned to the exact commits used in the evaluation.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p repos
fetch() {
  local name=$1 url=$2 sha=$3
  if [ ! -d "repos/$name/.git" ]; then git clone --quiet "$url" "repos/$name"; fi
  git -C "repos/$name" fetch --quiet --depth 1 origin "$sha" 2>/dev/null || true
  git -C "repos/$name" checkout --quiet "$sha"
  echo "$name @ $sha"
}
fetch NodeGoat https://github.com/OWASP/NodeGoat c5cb68a7084e4ae7dcc60e6a98768720a81841e8
fetch dvna https://github.com/appsecco/dvna 9ba473add536f66ac9007966acb2a775dd31277a
