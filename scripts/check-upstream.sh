#!/usr/bin/env bash
set -euo pipefail

UPSTREAM_URL="https://github.com/martadams89/gofile-dl.git"
REVIEWED_SHA="0341160"
WATCH_PATHS=(run.py app.py errors.py templates/ config.yml)

if ! git remote get-url upstream >/dev/null 2>&1; then
  git remote add upstream "$UPSTREAM_URL"
  git config remote.upstream.fetch "+refs/heads/main:refs/remotes/upstream/main"
  git remote set-url --push upstream DISABLE
fi

git fetch --quiet upstream main
HEAD_SHA="$(git rev-parse --short upstream/main)"

if [[ "${1:-}" == "--ack" ]]; then
  sed -i "s/^REVIEWED_SHA=\".*\"/REVIEWED_SHA=\"${HEAD_SHA}\"/" "$0"
  echo "Updated REVIEWED_SHA -> ${HEAD_SHA}"
  exit 0
fi

TOTAL="$(git rev-list --count "${REVIEWED_SHA}..upstream/main")"
echo "Upstream range: ${REVIEWED_SHA}..${HEAD_SHA} (${TOTAL} total commits)"

if [[ "${1:-}" == "--diff" ]]; then
  git diff "${REVIEWED_SHA}..upstream/main" -- "${WATCH_PATHS[@]}"
  exit 0
fi

CHANGES="$(git log --oneline "${REVIEWED_SHA}..upstream/main" -- "${WATCH_PATHS[@]}")"
if [[ -z "$CHANGES" ]]; then
  echo "No upstream protocol/CLI/web changes. (Run '$0 --ack' to advance watermark.)"
else
  echo "Upstream business changes detected:"
  echo "$CHANGES"
  echo ""
  echo "Run '$0 --diff' to inspect patches, then '$0 --ack' once handled."
fi
