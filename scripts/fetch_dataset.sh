#!/usr/bin/env bash
# Download the JsVul dataset (pinned) into data/raw/tools/jsvul and rebuild
# data/processed/ (cleaned records + repository-disjoint train/val/test splits).
set -euo pipefail
cd "$(dirname "$0")/.."
SHA=036c7f7
if [ ! -d data/raw/tools/jsvul/.git ]; then
  mkdir -p data/raw/tools
  git clone https://github.com/jsvul/jsvul.git data/raw/tools/jsvul
fi
git -C data/raw/tools/jsvul checkout --quiet "$SHA"
npm install
npm run phase1
