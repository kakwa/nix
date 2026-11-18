#!/usr/bin/env bash
# Start (or stop) an AFL++ campaign against the derivation-parsing fuzz targets.
#
# Usage:
#   ./run-afl-derivation.sh                    single worker with the interactive AFL++ UI (foreground)
#   ./run-afl-derivation.sh --parallel         N workers in the background (no UI, logs only)
#   ./run-afl-derivation.sh stop               stop all workers
#
# Set DURATION to a positive number to auto-stop the interactive run.
#
# Environment:
#   BUILD_DIR   path to the meson build directory (default: auto-detected)
#   TARGET      fuzz target: parse-derivation or parse-derivation-experimental
#               (default: parse-derivation)
#   OUT         AFL output directory (default: ./afl-out-derivations)
#   WORKERS     number of parallel instances (default: 4)
#   DURATION    seconds per instance; 0 = unlimited (default: 0)

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
BUILD_DIR=${BUILD_DIR:-/tmp/opencode/nix-fuzz-parent/build-afl-deny}
TARGET=${TARGET:-parse-derivation}
OUT=${OUT:-/tmp/opencode/nix-fuzz-parent/afl-out-derivations}
SEEDS=$SCRIPT_DIR/data/derivations
DICT=$SCRIPT_DIR/data/derivations.dict
BIN=$BUILD_DIR/src/libstore-tests/fuzz/harnesses/fuzz-$TARGET
WORKERS=${WORKERS:-4}
DURATION=${DURATION:-0}

case "$TARGET" in
  parse-derivation|parse-derivation-experimental) ;;
  *)
    echo "Unknown TARGET: $TARGET (expected parse-derivation or parse-derivation-experimental)" >&2
    exit 1
    ;;
esac

stop() {
  echo "Stopping AFL++ processes for $OUT..."
  pkill -TERM -f "afl-fuzz.*$(basename "$OUT")" 2>/dev/null || true
  sleep 1
  pgrep -a afl-fuzz || echo "All stopped."
}

common_env() {
  export LD_LIBRARY_PATH="$BUILD_DIR/src/libutil:$BUILD_DIR/src/libstore${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
  export AFL_SKIP_CPUFREQ=1
  export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
}

check_bin() {
  if [[ ! -x "$BIN" ]]; then
    echo "Binary not found: $BIN" >&2
    echo "Set BUILD_DIR to a meson build directory containing fuzz-$TARGET." >&2
    exit 1
  fi
  if [[ ! -d "$SEEDS" ]]; then
    echo "Seed corpus not found: $SEEDS" >&2
    exit 1
  fi
}

duration_args() {
  if (( DURATION > 0 )); then printf -- '-V %d' "$DURATION"; fi
}

print_stats() {
  for d in "$OUT"/*/; do
    printf '%-20s ' "$(basename "$d")"
    grep -E '^execs_done|^execs_per_sec|^corpus_count|^stability' "$d/fuzzer_stats" 2>/dev/null | tr '\n' ' '
    echo
  done
}

start_interactive() {
  check_bin
  common_env
  mkdir -p "$OUT"

  echo "Starting AFL++ with the interactive UI..."
  echo "  binary: $BIN"
  echo "  seeds:  $SEEDS"
  echo "  dict:   $DICT"
  echo "  output: $OUT"

  # shellcheck disable=SC2086
  exec afl-fuzz -i "$SEEDS" -o "$OUT" -x "$DICT" $(duration_args) -- "$BIN"
}

start_parallel() {
  check_bin
  common_env
  export AFL_NO_UI=1
  mkdir -p "$OUT"

  echo "Starting $WORKERS AFL++ workers for ${DURATION:-unlimited}s..."
  echo "  binary: $BIN"
  echo "  seeds:  $SEEDS"
  echo "  output: $OUT"

  # shellcheck disable=SC2086
  afl-fuzz -i "$SEEDS" -o "$OUT" -M master -x "$DICT" $(duration_args) -- "$BIN" \
    >"$OUT/master.log" 2>&1 &

  for ((i = 1; i < WORKERS; i++)); do
    # shellcheck disable=SC2086
    afl-fuzz -i "$SEEDS" -o "$OUT" -S "secondary-$i" -x "$DICT" $(duration_args) -- "$BIN" \
      >"$OUT/secondary-$i.log" 2>&1 &
  done

  echo "Workers started. PIDs: $(jobs -p | tr '\n' ' ')"
  echo "Stop with: $0 stop"
  echo "Stats: for d in $OUT/*/; do grep -E 'execs_done|stability' \$d/fuzzer_stats; done"

  wait
  echo "All workers finished."
  print_stats
}

case "${1:-}" in
  stop)          stop ;;
  --parallel)    shift; start_parallel "$@" ;;
  *)             start_interactive "$@" ;;
esac
