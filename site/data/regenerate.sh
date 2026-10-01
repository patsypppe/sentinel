#!/usr/bin/env bash
# Regenerate every JSON file the showcase page reads. Nothing on the page is
# typed in by hand: each number and finding is produced by `sentinel` itself.
#
# Prerequisites, from the repository root:
#   docker compose up -d --wait postgres broker          # the broker on :8080
#   uv run sentinel fixture serve --profile nonconformant &   # :9000
#   uv run sentinel fixture serve --profile conformant &      # :9001
#   export SCAN_TOKEN=$(BROKER_OAUTH_DEV_SEED=aaaa…aaaa \
#       BROKER_OAUTH_ISSUER=https://issuer.sentinel.local \
#       BROKER_OAUTH_AUDIENCE=https://broker.sentinel.local \
#       go run ./broker/cmd/broker mint-token \
#         --principal 00000000-0000-0000-0000-0000000000a2 \
#         --audience https://broker.sentinel.local \
#         --scopes "ops:plan ops:apply warehouse:read warehouse:describe" --ttl 1h)
#   (the dev seed is the 64 'a' characters in docker-compose.yml; see docs/runbook.md)
#
# Then:  bash site/data/regenerate.sh [YYYY-MM-DD]
#
# `scan` exits 1 when the target fails the MUST gate. That is the expected
# result for the non-conformant fixture, so only exit 2 (the scanner broke)
# aborts this script.
set -uo pipefail

: "${SCAN_TOKEN:?export SCAN_TOKEN first (see the header of this script)}"
AS_OF="${1:-$(date +%F)}"
OUT="$(cd "$(dirname "$0")" && pwd)"
BROKER=http://localhost:8080/mcp
UNMIGRATED=http://127.0.0.1:9000/mcp
CONFORMANT=http://127.0.0.1:9001/mcp

EXITS=()
# run LABEL CMD... : runs CMD, records its exit code under LABEL, aborts on 2+.
run() {
  local label="$1"; shift
  "$@" >/dev/null
  local rc=$?
  if [ "$rc" -ge 2 ]; then echo "failed (exit $rc): $label" >&2; exit "$rc"; fi
  EXITS+=("\"$label\": $rc")
  echo "exit $rc  $label"
}

run broker.scan uv run sentinel scan --endpoint "$BROKER" --token "$SCAN_TOKEN" --gate must --format json --no-color --out "$OUT/broker.scan.json"
run nonconformant.scan uv run sentinel scan --endpoint "$UNMIGRATED" --gate must --format json --no-color --out "$OUT/nonconformant.scan.json"
run conformant.scan uv run sentinel scan --endpoint "$CONFORMANT" --gate must --format json --no-color --out "$OUT/conformant.scan.json"
# The same unmigrated scan with the retired rules switched back on, so the page
# can show each deprecated rule next to the successor that replaced it.
run nonconformant.with-deprecated-rules.scan uv run sentinel scan --endpoint "$UNMIGRATED" --gate must --format json --no-color --include-deprecated-rules --out "$OUT/nonconformant.with-deprecated-rules.scan.json"

run broker.deprecations uv run sentinel deprecations --endpoint "$BROKER" --token "$SCAN_TOKEN" --as-of "$AS_OF" --format json --no-color --out "$OUT/broker.deprecations.json"
run nonconformant.deprecations uv run sentinel deprecations --endpoint "$UNMIGRATED" --as-of "$AS_OF" --format json --no-color --out "$OUT/nonconformant.deprecations.json"

# What moving this server to 2026-07-28 involves, sized from the same wire evidence.
run nonconformant.migrate uv run sentinel migrate --endpoint "$UNMIGRATED" --format json --out "$OUT/nonconformant.migrate.json"

uv run sentinel version > "$OUT/sentinel-version.txt"
uv run sentinel catalog validate > "$OUT/catalog-validate.txt"

# Exit codes are part of the result: 0 passed, 1 the target failed the gate.
( IFS=,; printf '{"asOf": "%s", "exitCodes": {%s}}\n' "$AS_OF" "${EXITS[*]}" ) > "$OUT/meta.json"
echo "wrote $OUT (as of $AS_OF)"
