#!/usr/bin/env bash
# Tells a real fuzz failure from the fuzzing engine dying on its own.
#
#   fuzz-engine-death.sh TARGET FUZZ_LOG
#
# Exits 0 only if the log shows the engine itself died ("fuzzing process hung or
# terminated unexpectedly") and every input it saved replays cleanly: nothing then
# depends on the input, so there is no library bug to report. Any assertion
# failure, panic, or input that still fails exits 1.
set -euo pipefail
cd "$(dirname "$0")/../.."
target=${1:?target}
log=${2:?fuzz log}

grep -q 'fuzzing process hung or terminated unexpectedly' "$log" || exit 1
# A real failure prints its own message after "--- FAIL"; the engine-death message is the only one.
if grep -E -A8 -- '^--- FAIL' "$log" | grep -v -E -- '^--- FAIL|^[[:space:]]*(fuzzing process hung|Failing input written|To re-run:)|^[[:space:]]*go test|^FAIL|^exit status|^--$|^[[:space:]]*$' | grep -q .; then
	exit 1
fi

dir="testdata/fuzz/$target"
[ -d "$dir" ] && [ -n "$(find "$dir" -type f)" ] || exit 1
# Every saved input is replayed as a seed by a plain test run.
go test -count=1 -run="^${target}\$" . >/dev/null 2>&1
