#!/usr/bin/env bash
# Runs the official MCP conformance suite and Sentinel against the same servers
# and writes results/<server>.json. See docs/BENCHMARK.md for what it measures.
#
#   benchmarks/official-suite/run.sh
#
# Needs: uv, node >= 20, pnpm (corepack), git. Starts its own servers on
# ports 9301-9302 and 3311 and stops them on exit.

set -euo pipefail
cd "$(dirname "$0")/../.."
ROOT=$PWD
HERE=$ROOT/benchmarks/official-suite
WORK=${WORK:-$(mktemp -d)}
CONFORMANCE_VERSION=${CONFORMANCE_VERSION:-0.2.0-alpha.12}
SDK_REF=${SDK_REF:-main}
mkdir -p "$HERE/results"
pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

(cd fixtures && python3 -m server.conformant 9301 >/dev/null 2>&1) & pids+=($!)
(cd fixtures && python3 -m server.nonconformant 9302 >/dev/null 2>&1) & pids+=($!)

# The official suite's own reference server: the TypeScript SDK's
# everythingServer, the server its expected-failures baseline is written for.
if [ ! -d "$WORK/typescript-sdk" ]; then
  git clone -q --depth 1 --branch "$SDK_REF" https://github.com/modelcontextprotocol/typescript-sdk "$WORK/typescript-sdk"
fi
(cd "$WORK/typescript-sdk" && pnpm install --frozen-lockfile --ignore-scripts >/dev/null \
  && pnpm -r --filter "./packages/**" build >/dev/null)
(cd "$WORK/typescript-sdk/test/conformance" && PORT=3311 node --import tsx ./src/everythingServer.ts >/dev/null 2>&1) & pids+=($!)

(cd "$WORK" && npm init -y >/dev/null && npm install --silent "@modelcontextprotocol/conformance@$CONFORMANCE_VERSION")
sleep 5

for target in "sentinel-conformant http://127.0.0.1:9301/mcp" \
              "sentinel-nonconformant http://127.0.0.1:9302/mcp" \
              "official-reference http://localhost:3311/mcp"; do
  set -- $target
  name=$1 url=$2
  rm -rf "$WORK/out-$name"
  (cd "$WORK" && npx conformance server --url "$url" --requirements 2026-07-28 \
     -o "out-$name" --timeout 15000 > "run-$name.txt" 2>&1) || true
  uv run sentinel scan --endpoint "$url" --format json --out "$WORK/sentinel-$name.json" --no-color >/dev/null 2>&1 || true
  python3 "$HERE/compare.py" "$name" "$WORK/out-$name" "$WORK/run-$name.txt" "$WORK/sentinel-$name.json" \
    > "$HERE/results/$name.json"
  echo "wrote benchmarks/official-suite/results/$name.json"
done
