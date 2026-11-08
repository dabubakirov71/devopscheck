#!/usr/bin/env bash
# Downloads the live evaluation set's snapshot tarballs on a host with a fast
# link to GitHub/GitLab and copies them into .eval-cache/ here
# (docs/accuracy/spec.md, stage 1.3). Usage: scripts/eval-fetch.sh user@host
set -euo pipefail
HOST=${1:?usage: scripts/eval-fetch.sh user@host}
cd "$(dirname "$0")/.."
DC="docker compose -f docker/docker-compose.yml"
$DC exec -T web python manage.py eval_checks --fetch-list 2>/dev/null | grep -P '^https?://' | while IFS=$'\t' read -r url path; do
  echo "fetch $path"
  ssh "$HOST" "mkdir -p /tmp/evalsnap && curl -sfL --retry 3 --retry-delay 5 --connect-timeout 20 --max-time 600 -o /tmp/evalsnap/snap.tar.gz '$url'" </dev/null
  mkdir -p ".eval-cache/$(dirname "$path")"
  scp -q "$HOST:/tmp/evalsnap/snap.tar.gz" ".eval-cache/$path"
  ssh "$HOST" "rm -f /tmp/evalsnap/snap.tar.gz" </dev/null
done
echo done
