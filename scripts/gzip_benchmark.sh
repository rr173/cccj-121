#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ART="$ROOT/bench_gzip_out"
mkdir -p "$ART"
for SIZE in 8 32; do
  DIR="$ART/$SIZE"
  rm -rf "$DIR"
  mkdir -p "$DIR"
  # Reference generation/decompression in a different process from measurement.
  python3 -I "$ROOT/scripts/gzip_benchmark.py" generate \
    --size-mib "$SIZE" --artifact-dir "$DIR"
  python3 -I "$ROOT/scripts/gzip_benchmark.py" measure \
    --size-mib "$SIZE" --artifact-dir "$DIR" --spacing 65536 \
    | tee "$DIR/report.json"
done
