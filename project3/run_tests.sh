#!/bin/sh
# // Name: Atharva Gupta
# // Case Network ID: axg1395
# // date created: 10/25/2026
# // date updated: 10/27/2026
# // filename: run_tests.sh
# // description: test suite for proj3. Checks generated traces, the sample traces in
# // p3-all-samples-v5.tar when present, and command-line/file error handling.

PROG=${PROG:-./proj3}
GEN=./gen_traces
SAMPLES_TAR=p3-all-samples-v5.tar

pass=0
fail=0

WORK=$(mktemp -d) || exit 1
trap 'rm -rf "$WORK"' EXIT

record_pass() {
    pass=$((pass + 1))
}

record_fail() {
    echo "FAIL: $1"
    fail=$((fail + 1))
}

# Compare every NAME-MODE.out in a directory with './proj3 -MODE -r NAME.trace'.
# Packet output must match exactly; count and flow output may be in any order, so they
# are sorted before comparing.
check_outputs() {
    for expected in "$1"/*.out; do
        base=$(basename "$expected" .out)
        name=${base%-*}
        mode=${base##*-}
        actual="$WORK/actual.txt"

        if ! "$PROG" "-$mode" -r "$1/$name.trace" > "$actual"; then
            record_fail "$base (nonzero exit)"
            continue
        fi

        if [ "$mode" = p ]; then
            cmp -s "$expected" "$actual"
        else
            sort "$expected" > "$WORK/expected.sorted"
            sort "$actual" > "$WORK/actual.sorted"
            cmp -s "$WORK/expected.sorted" "$WORK/actual.sorted"
        fi

        if [ $? -eq 0 ]; then
            record_pass
        else
            record_fail "$base"
        fi
    done
}

# The sample archive has no reference output for some trace/mode pairs. These outputs
# were derived independently from the reference -p output of the same trace.
write_derived_sample_outputs() {
    dir=$1
    printf '17 100\n6 100\n' > "$dir/100-flows-c.out"
    printf '17 100000\n6 100000\n' > "$dir/50K-flows-c.out"
    printf '1 1\n' > "$dir/1i-c.out"
    : > "$dir/1i-n.out"
    printf '6 1\n' > "$dir/1t-c.out"
    printf '17 1\n' > "$dir/1u-c.out"
    printf '1 1\n17 2\n6 6\n' > "$dir/funky-c.out"
    cat > "$dir/1t-n.out" <<EOF
68.71.38.5 873 192.150.186.39 59526 T 1429260295.000231 0.000000 1 0 1448 0
EOF
    cat > "$dir/1u-n.out" <<EOF
192.168.1.126 42389 255.255.255.255 9999 U 1791172765.000231 0.000000 1 0 58 0
EOF
    cat > "$dir/3iut-n.out" <<EOF
192.168.1.126 42389 255.255.255.255 9999 U 1791172765.000231 0.000000 1 0 58 0
68.71.38.5 873 192.150.186.39 59526 T 1429260295.000231 0.000000 1 0 1448 0
EOF
    cat > "$dir/funky-n.out" <<EOF
169.229.0.139 179 169.229.0.140 59084 T 1429260303.865277 0.000000 1 0 19 0
178.89.99.122 63215 192.150.186.11 25 T 1429260303.908035 0.000000 1 0 0 0
192.150.186.39 59526 68.71.38.5 873 T 1429260296.000231 0.000000 1 0 0 0
192.150.186.39 59526 68.71.38.5 873 U 1429260303.690987 0.000000 1 0 0 0
192.150.187.50 61471 192.30.252.130 443 T 1429260303.709923 0.000000 1 0 517 0
192.30.252.130 443 192.150.187.50 61470 U 1429260303.692361 0.000000 1 0 972 0
218.5.72.78 57793 192.150.186.93 22 T 1429260303.832625 0.000000 1 0 0 0
218.77.79.43 56588 192.150.186.222 25 T 1429260304.237353 0.000000 1 0 0 0
EOF
}

# Each call must exit nonzero, print an error on stderr and print nothing on stdout.
check_error() {
    out=$("$PROG" "$@" 2> "$WORK/stderr.txt")
    status=$?
    if [ $status -ne 0 ] && [ -z "$out" ] && [ -s "$WORK/stderr.txt" ]; then
        record_pass
    else
        record_fail "expected an error for: proj3 $*"
    fi
}

mkdir "$WORK/generated"
if ! "$GEN" "$WORK/generated"; then
    echo "FAIL: could not generate test traces"
    exit 1
fi
check_outputs "$WORK/generated"

if [ -f "$SAMPLES_TAR" ]; then
    mkdir "$WORK/samples"
    if tar xf "$SAMPLES_TAR" -C "$WORK/samples"; then
        write_derived_sample_outputs "$WORK/samples"
        check_outputs "$WORK/samples"
    else
        record_fail "could not extract $SAMPLES_TAR"
    fi
else
    echo "note: $SAMPLES_TAR not found, skipping sample traces"
fi

# Options may appear in any order.
"$PROG" -r "$WORK/generated/udp_single.trace" -p > "$WORK/actual.txt"
if cmp -s "$WORK/generated/udp_single-p.out" "$WORK/actual.txt"; then
    record_pass
else
    record_fail "options in reverse order"
fi

TRACE="$WORK/generated/udp_single.trace"
check_error
check_error -p
check_error -c
check_error -n
check_error -r "$TRACE"
check_error -p -c -r "$TRACE"
check_error -p -n -r "$TRACE"
check_error -c -n -r "$TRACE"
check_error -x -r "$TRACE"
check_error -p -r
check_error -p -r "$TRACE" extra
check_error -p -r "$TRACE" -r "$TRACE"
check_error -p -r "$WORK/does_not_exist.trace"
check_error -c -r "$WORK/generated/truncated.trace"
check_error -n -r "$WORK/generated/truncated.trace"

echo "passed: $pass, failed: $fail"
[ $fail -eq 0 ]
