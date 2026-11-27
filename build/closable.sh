#!/bin/sh
#
# What of the KnownIssue and ToDo tests passes - a finding fixed, a ToDo
# done, to be closed by a pin of the fix (PLAN.md, section 9) - as markdown,
# from the TRX files of their run; for the nightly's job summary.
#
#   sh build/closable.sh artifacts/open*.trx
#
# Never fails on what it finds: it reports, the tests gate.

set -eu

if [ $# -eq 0 ]; then
    echo "usage: sh build/closable.sh <trx file>..." >&2
    exit 64
fi

results=$(cat "$@" | grep -o '<UnitTestResult [^>]*>' || true)
total=$(printf '%s' "$results" | grep -c 'outcome=' || true)
passed=$(printf '%s\n' "$results" | grep 'outcome="Passed"' | sed 's/.*testName="\([^"]*\)".*/\1/; s/&quot;/"/g' | sort -u || true)

echo "### KnownIssue and ToDo"
echo

if [ -z "$passed" ]; then
    echo "None of the $total passes: every finding and every ToDo is still open."
else
    echo "$(printf '%s\n' "$passed" | wc -l | tr -d ' ') of $total pass now - a finding fixed or a ToDo done, to be closed (PLAN.md, section 9):"
    echo
    printf '%s\n' "$passed" | sed 's/^/- `/; s/$/`/'
fi
