#!/usr/bin/env bash
#
# renpkt correctness gate. It runs two passes.
#
# Pass 1, decode. The script runs every header listed in tests/manifest.txt
# through --decode. It captures the output, reads the program's status, and
# compares the output against tests/expected/. The comparison strips
# trailing carriage returns, for the reason Block 1 explained.
#
# Pass 2, contract. ./contract_test decodes and re-encodes every header the
# manifest marks valid. It checks the checksum vector that needs two carry
# folds. It checks the register discipline of all three routines. That
# pass catches what the output comparison cannot see: a lost field on the
# encode path, a truncated fold, and a clobbered callee-saved register.
#
# The manifest is the one list both passes share. A .bin under tests/ that
# the manifest does not list fails the gate, and so does a listed header
# without a tests/expected/NAME.out file. Add a header to the manifest and
# it joins both passes.
#
#       ./run_tests.sh
#
# Build first (make). The script reports each case and exits nonzero when a
# case differs, when the program crashes, or when the program returns
# nonzero. The program's status is read before the comparison runs, so a
# correct-looking output cannot hide a crash.

set -uo pipefail

bin="./renpkt"
if [ ! -x "$bin" ] && [ -x "$bin.exe" ]; then
    bin="$bin.exe"
fi

if [ ! -x "$bin" ]; then
    echo "run_tests.sh: $bin not found. Build it first: make" >&2
    exit 1
fi

# The decode pass captures each run here, then removes the file.
out="./.decode.out"
trap 'rm -f "$out"' EXIT

failures=0
total=0

manifest="tests/manifest.txt"
if [ ! -f "$manifest" ]; then
    echo "run_tests.sh: $manifest not found." >&2
    exit 1
fi

# Every .bin must be listed. The gate would otherwise skip, in silence, a
# header dropped into tests/ without a manifest line and an expected file.
for header in tests/*.bin; do
    name="$(basename "$header" .bin)"
    if ! grep -qE "^$name[[:space:]]+(valid|invalid)[[:space:]]*$" "$manifest"; then
        echo "FAIL  $name is in tests/ but not in $manifest. Add a line: $name valid (or invalid)."
        failures=$((failures + 1))
        total=$((total + 1))
    fi
done

while read -r name kind; do
    case "$name" in ''|'#'*) continue ;; esac
    kind="${kind%$'\r'}"    # a manifest checked out with CRLF still reads
    header="tests/$name.bin"
    expected="tests/expected/$name.out"
    total=$((total + 1))

    if [ "$kind" != valid ] && [ "$kind" != invalid ]; then
        echo "FAIL  $name: $manifest marks it '$kind'. The class is valid or invalid."
        failures=$((failures + 1))
        continue
    fi
    if [ ! -f "$header" ]; then
        echo "FAIL  $name is listed in $manifest but $header does not exist"
        failures=$((failures + 1))
        continue
    fi
    if [ ! -f "$expected" ]; then
        echo "FAIL  $name has no expected output. Write $expected first."
        failures=$((failures + 1))
        continue
    fi

    "$bin" --decode "$header" > "$out" 2>/dev/null
    status=$?

    if [ "$status" -ne 0 ]; then
        echo "FAIL  $name (the program exited with status $status)"
        failures=$((failures + 1))
        continue
    fi

    if diff -u --strip-trailing-cr \
        --label "$expected" --label "what renpkt printed" "$expected" "$out"; then
        echo "ok    $name"
    else
        echo "FAIL  $name"
        failures=$((failures + 1))
    fi
done < "$manifest"

# The contract pass. One more check, and it lives in its own program.
testbin="./contract_test"
if [ ! -x "$testbin" ] && [ -x "$testbin.exe" ]; then
    testbin="$testbin.exe"
fi

if [ ! -x "$testbin" ]; then
    echo "run_tests.sh: $testbin not found. Build it first: make" >&2
    exit 1
fi

total=$((total + 1))
if "$testbin"; then
    echo "ok    contract"
else
    echo "FAIL  contract"
    failures=$((failures + 1))
fi

echo
if [ "$failures" -eq 0 ]; then
    echo "All $total checks passed."
    exit 0
else
    echo "$failures of $total checks differ."
    exit 1
fi
