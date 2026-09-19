#!/usr/bin/env bash
# Cross-glibc test matrix: build host/payload against different glibc versions
# (done elsewhere) and feed each host/payload pair to burpkat.
#
# Env:
#   BURPKAT  path to burpkat binary (default build/burpkat)
#   DIR      directory containing <name>/{host,payload} subdirs
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BURPKAT="${BURPKAT:-$ROOT/build/burpkat}"
DIR="${DIR:-/tmp/opencode/cross}"

names=()
for d in "$DIR"/*/; do
  [ -f "$d/host" ] && [ -f "$d/payload" ] && names+=("$(basename "$d")")
done

echo "burpkat: $BURPKAT"
echo "variants: ${names[*]}"
echo

printf '%-10s %-10s %-8s %-9s %s\n' host payload build run note
printf '%s\n' "---------------------------------------------------------------"

for h in "${names[@]}"; do
  for p in "${names[@]}"; do
    out="/tmp/opencode/ab-${h}-${p}"
    log="/tmp/opencode/ab-${h}-${p}.log"
    if "$BURPKAT" -i "$DIR/$h/host" -p "$DIR/$p/payload" -o "$out" -d \
        >"$log" 2>&1; then
      build=ok
      note=""
    else
      build=FAIL
      note="$(grep -E 'runtime error' "$log" | tail -1 | cut -c1-60)"
    fi

    run="-"
    if [ "$build" = ok ]; then
      rlog="/tmp/opencode/run-${h}-${p}.log"
      timeout 3 "$out" >"$rlog" 2>&1
      rc=$?
      marks=0
      grep -q tick "$rlog" && marks=$((marks+1))
      grep -q infected "$rlog" && marks=$((marks+1))
      if [ "$marks" = 2 ]; then
        run="both"
      elif [ "$rc" = 139 ]; then
        run="SEGV"
      elif [ "$rc" = 127 ]; then
        run="ld-fail"
      elif [ "$marks" = 1 ]; then
        run="partial"
      else
        run="rc=$rc"
      fi
      [ -z "$note" ] && note="$(grep -iE 'error|not found|version' "$rlog" | tail -1 | cut -c1-60)"
    fi

    printf '%-10s %-10s %-8s %-9s %s\n' "$h" "$p" "$build" "$run" "$note"
  done
done
