#!/bin/bash
# test.sh - run nftsim test suites and summarize the results
#
# usage: ./test.sh [test_name1 test_name2 ...]
#        ./test.sh                               # run all suites
#        ./test.sh 01_basics 03_accept_verdict   # run specific suites
#
# runs suites from testdata/ with live per-case output. cases named with a
# SHOULD_FAIL: prefix count as passing when nftsim reports them as failed.

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# nftsim's per-case result lines: "  <name> ... pass" / "  <name> ... fail"
CASE_LINE='^\s+.+\.\.\.'
CASE_PASS='\.\.\. pass$'
CASE_FAIL='\.\.\. fail$'

# kill nftsim and any orphaned UML guests so an interrupted run leaves nothing behind
# shellcheck disable=SC2329 # invoked by trap
cleanup() {
    echo ""
    echo -e "${YELLOW}caught interrupt signal, cleaning up...${NC}"
    pkill -P $$ 2>/dev/null || true
    pkill -f "linux.uml" 2>/dev/null || true
    echo -e "${YELLOW}cleanup complete${NC}"
    exit 130
}

trap cleanup INT TERM

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ ! -f "./target/release/nftsim" ]; then
    echo -e "${YELLOW}binary not found, building release version...${NC}"
    cargo build --release
fi

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  nftsim test suite runner${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

all_suites=(
    "01_basics"
    "02_verdict_validation"
    "03_accept_verdict"
    "04_udp"
    "05_icmp"
    "06_conntrack"
    "07_mixed"
    "08_nat"
    "09_rate_limiting"
    "10_port_forwarding"
    "11_security"
    "12_dmz"
    "13_sets"
    "14_quotas"
    "15_stress"
    "16_tcp_flags"
    "17_icmp_types"
    "18_ttl_validation"
    "19_protocol_edge_cases"
    "20_advanced_nat"
    "21_payload"
    "22_ipv6"
    "23_docker_host"
    "24_vpn_gateway"
    "25_laptop"
    "26_guest_injection"
)

if [ $# -eq 0 ]; then
    suites=("${all_suites[@]}")
else
    suites=("$@")
fi

total_tests=0
total_passed=0
total_failed=0
failed_suites=()

for suite in "${suites[@]}"; do
    nft_file="testdata/${suite}.nft"
    toml_file="testdata/${suite}.toml"

    if [ ! -f "$nft_file" ] || [ ! -f "$toml_file" ]; then
        echo -e "${RED}error: missing files for suite: ${suite}${NC}"
        continue
    fi

    echo -e "${NC}running: ${suite}${NC}"

    # output is captured so it can be tallied after the live display finishes
    tmpfile=$(mktemp)

    suite_total=0
    suite_passed=0
    suite_failed=0
    suite_unexpected_failures=()

    ./target/release/nftsim test "$nft_file" "$toml_file" 2>&1 | tee "$tmpfile" | while IFS= read -r line; do
        if echo "$line" | grep -qE "$CASE_LINE"; then
            if echo "$line" | grep -qE "$CASE_PASS"; then
                echo -e "  ${GREEN}${line}${NC}"
            elif echo "$line" | grep -qE "$CASE_FAIL"; then
                echo -e "  ${RED}${line}${NC}"
            else
                echo "  ${line}"
            fi
        fi
    done

    while IFS= read -r line; do
        if echo "$line" | grep -qE "$CASE_LINE"; then
            suite_total=$((suite_total + 1))
            test_name=$(echo "$line" | sed -E 's/^[[:space:]]+(.+)\.\.\..*$/\1/')

            is_should_fail=false
            if echo "$test_name" | grep -q "^SHOULD_FAIL:"; then
                is_should_fail=true
            fi

            # a SHOULD_FAIL case inverts the meaning of nftsim's verdict
            if echo "$line" | grep -qE "$CASE_PASS"; then
                if [ "$is_should_fail" = true ]; then
                    suite_failed=$((suite_failed + 1))
                    suite_unexpected_failures+=("$test_name (expected to fail but passed)")
                else
                    suite_passed=$((suite_passed + 1))
                fi
            elif echo "$line" | grep -qE "$CASE_FAIL"; then
                if [ "$is_should_fail" = true ]; then
                    suite_passed=$((suite_passed + 1))
                else
                    suite_failed=$((suite_failed + 1))
                    suite_unexpected_failures+=("$test_name")
                fi
            fi
        fi
    done < "$tmpfile"

    rm -f "$tmpfile"

    if [ "$suite_total" -eq 0 ]; then
        echo -e "${RED}  error: failed to parse results (test execution may have failed)${NC}"
        failed_suites+=("$suite (parse error)")
        # count as one failed test so an empty run cannot report 100%
        total_tests=$((total_tests + 1))
        total_failed=$((total_failed + 1))
        echo ""
        continue
    fi

    total_tests=$((total_tests + suite_total))
    total_passed=$((total_passed + suite_passed))
    total_failed=$((total_failed + suite_failed))

    if [ "$suite_failed" -eq 0 ]; then
        echo -e "${GREEN}  suite complete: ${suite_passed}/${suite_total} passed${NC}"
    else
        echo -e "${YELLOW}  warning: suite complete: ${suite_passed}/${suite_total} passed (${suite_failed} unexpected failures)${NC}"
        failed_suites+=("$suite")
        for failed_test in "${suite_unexpected_failures[@]}"; do
            echo -e "${YELLOW}    - ${failed_test}${NC}"
        done
    fi

    echo ""
done

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  test summary${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo -e "total tests:  ${total_tests}"
echo -e "${GREEN}passed:       ${total_passed}${NC}"

if [ "$total_failed" -gt 0 ]; then
    echo -e "${YELLOW}failed:       ${total_failed}${NC}"
else
    echo -e "${GREEN}failed:       ${total_failed}${NC}"
fi

if [ "$total_tests" -gt 0 ]; then
    percentage=$(awk "BEGIN {printf \"%.1f\", ($total_passed / $total_tests) * 100}")
    echo -e "pass rate:    ${percentage}%"
fi

echo ""

if [ ${#failed_suites[@]} -gt 0 ]; then
    echo -e "${YELLOW}suites with failures:${NC}"
    for suite in "${failed_suites[@]}"; do
        echo -e "  - ${suite}"
    done
    echo ""
    exit 1
else
    echo -e "${GREEN}all test suites passed${NC}"
    echo ""
    exit 0
fi
