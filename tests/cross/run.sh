#!/usr/bin/env bash
# Cross-glibc test matrix: build host/payload against different glibc versions
# (done elsewhere) and feed each host/payload pair to burpkat.
#
# Both ET_EXEC (`host`) and PIE (`host-pie`) hosts are exercised against every
# PIE payload.
#
# Env:
#   BURPKAT  path to burpkat binary (default build/burpkat)
#   DIR      directory containing <name>/{host,host-pie,payload} files
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BURPKAT="${BURPKAT:-$ROOT/build/burpkat}"
DIR="${DIR:-/tmp/opencode/cross}"

names=()
for d in "$DIR"/*/; do
  [ -f "$d/payload" ] && names+=("$(basename "$d")")
done

host_types=(host host-pie)

echo "burpkat: $BURPKAT"
echo "variants: ${names[*]}"
echo

printf '%-12s %-10s %-8s %-9s %s\n' host payload build run note
printf '%s\n' "---------------------------------------------------------------"

for h in "${names[@]}"; do
  for ht in "${host_types[@]}"; do
    hostfile="$DIR/$h/$ht"
    [ -f "$hostfile" ] || continue
    [ "$ht" = host-pie ] && hlabel="$h-pie" || hlabel="$h"

    for p in "${names[@]}"; do
      out="/tmp/opencode/ab-${hlabel}-${p}"
      log="/tmp/opencode/ab-${hlabel}-${p}.log"
      if "$BURPKAT" -i "$hostfile" -p "$DIR/$p/payload" -o "$out" -d \
          >"$log" 2>&1; then
        build=ok
        note=""
      else
        build=FAIL
        note="$(grep -E 'runtime error' "$log" | tail -1 | cut -c1-60)"
      fi

      run="-"
      if [ "$build" = ok ]; then
        rlog="/tmp/opencode/run-${hlabel}-${p}.log"
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

      printf '%-12s %-10s %-8s %-9s %s\n' "$hlabel" "$p" "$build" "$run" "$note"
    done
  done
done
