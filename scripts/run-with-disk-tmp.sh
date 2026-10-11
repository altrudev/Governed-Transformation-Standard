#!/bin/sh
# Explicit per-command disk-backed scratch and private reports.
set -eu
if [ "$#" -eq 0 ]; then
  echo "Usage: sh scripts/run-with-disk-tmp.sh COMMAND [ARG ...]" >&2
  exit 64
fi
umask 077
state="${XDG_STATE_HOME:-$HOME/.local/state}/altru"
mkdir -p "$state/tmp" "$state/reports"
chmod 700 "$state/tmp" "$state/reports"
export TMPDIR="$state/tmp"
export TMP="$TMPDIR"
export TEMP="$TMPDIR"
exec "$@"
