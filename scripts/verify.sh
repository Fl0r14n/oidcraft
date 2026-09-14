#!/usr/bin/env bash
# The same sequence CI runs, in the same order, failing on the first red step.
set -euo pipefail
cd "$(dirname "$0")/.."
bunx biome ci .
bun run build
bun run typecheck
bun test
echo "✓ biome, build, typecheck and tests all pass"
