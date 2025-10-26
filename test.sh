#!/bin/bash
# run-tests.sh - Run nftsim test suites and display results
#
# Usage: ./run-tests.sh [test_name1 test_name2 ...]
#        ./run-tests.sh                      # Run all tests
#        ./run-tests.sh 01_basics 03_accept_verdict  # Run specific tests
#
# This script runs test suites in the testdata/ directory and provides
# a comprehensive summary of test results with live progress updates.

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Trap Ctrl+C and kill any running UML processes
cleanup() {
    echo ""
    echo -e "${YELLOW}Caught interrupt signal, cleaning up...${NC}"

    # Kill all child processes (nftsim and its children)
    pkill -P $$ 2>/dev/null || true

    # Kill any orphaned UML processes
    pkill -f "linux.uml" 2>/dev/null || true

    echo -e "${YELLOW}Cleanup complete${NC}"
    exit 130
}

trap cleanup INT TERM

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Check if binary exists
if [ ! -f "./target/release/nftsim" ]; then
    echo -e "${YELLOW}Binary not found. Building release version...${NC}"
    cargo build --release
fi

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  nftsim Test Suite Runner${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# All available test suites (in order)
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

# Determine which suites to run
if [ $# -eq 0 ]; then
    # No arguments - run all tests
    suites=("${all_suites[@]}")
else
    # Arguments provided - run only specified tests
    suites=("$@")
fi

# Counters
total_tests=0
total_passed=0
total_failed=0
failed_suites=()

# Run each test suite
for suite in "${suites[@]}"; do
    nft_file="testdata/${suite}.nft"
    toml_file="testdata/${suite}.toml"

    if [ ! -f "$nft_file" ] || [ ! -f "$toml_file" ]; then
        echo -e "${RED}✗ Missing files for suite: ${suite}${NC}"
        continue
    fi

    echo -e "${NC}Running: ${suite}${NC}"

    # Create a temp file to capture output for later parsing
    tmpfile=$(mktemp)

    # Track suite-specific results
    suite_total=0
    suite_passed=0
    suite_failed=0
    suite_unexpected_failures=()

    # Run the test with live output, processing lines as they come
    ./target/release/nftsim test "$nft_file" "$toml_file" 2>&1 | tee "$tmpfile" | while IFS= read -r line; do
        # Only colorize and display test result lines (lines with "...")
        if echo "$line" | grep -qE "^\s+.+\.\.\."; then
            if echo "$line" | grep -q "✓ PASS"; then
                echo -e "  ${GREEN}${line}${NC}"
            elif echo "$line" | grep -q "✗ FAIL"; then
                echo -e "  ${RED}${line}${NC}"
            else
                echo "  ${line}"
            fi
        fi
    done

    # Parse test results line by line from captured output
    while IFS= read -r line; do
        if echo "$line" | grep -qE "^\s+.+\.\.\."; then
            suite_total=$((suite_total + 1))

            # Extract test name (everything before "...")
            test_name=$(echo "$line" | sed -E 's/^[[:space:]]+(.+)\.\.\..*$/\1/')

            # Check if this is a SHOULD_FAIL test (tests without prefix are expected to pass)
            is_should_fail=false
            if echo "$test_name" | grep -q "^SHOULD_FAIL:"; then
                is_should_fail=true
            fi

            # Check if test passed or failed
            if echo "$line" | grep -q "✓ PASS"; then
                if [ "$is_should_fail" = true ]; then
                    # SHOULD_FAIL test passed - this is unexpected!
                    suite_failed=$((suite_failed + 1))
                    suite_unexpected_failures+=("$test_name (expected to fail but passed)")
                else
                    # Normal test passed - good
                    suite_passed=$((suite_passed + 1))
                fi
            elif echo "$line" | grep -q "✗ FAIL"; then
                if [ "$is_should_fail" = true ]; then
                    # SHOULD_FAIL test failed - this is expected, count as pass
                    suite_passed=$((suite_passed + 1))
                else
                    # Normal test failed - bad
                    suite_failed=$((suite_failed + 1))
                    suite_unexpected_failures+=("$test_name")
                fi
            fi
        fi
    done < "$tmpfile"

    # Clean up temp file
    rm -f "$tmpfile"

    if [ "$suite_total" -eq 0 ]; then
        echo -e "${RED}  ✗ Failed to parse results (test execution may have failed)${NC}"
        failed_suites+=("$suite (parse error)")
        # Count as 1 failed test to avoid 0/0 = 100% success
        total_tests=$((total_tests + 1))
        total_failed=$((total_failed + 1))
        echo ""
        continue
    fi

    # Update totals
    total_tests=$((total_tests + suite_total))
    total_passed=$((total_passed + suite_passed))
    total_failed=$((total_failed + suite_failed))

    # Display suite result
    if [ "$suite_failed" -eq 0 ]; then
        echo -e "${GREEN}  ✓ Suite complete: ${suite_passed}/${suite_total} passed${NC}"
    else
        echo -e "${YELLOW}  ⚠ Suite complete: ${suite_passed}/${suite_total} passed (${suite_failed} unexpected failures)${NC}"
        failed_suites+=("$suite")
        # Show which tests unexpectedly failed
        for failed_test in "${suite_unexpected_failures[@]}"; do
            echo -e "${YELLOW}    - ${failed_test}${NC}"
        done
    fi

    echo ""
done

# Display summary
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Test Summary${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo -e "Total Tests:  ${total_tests}"
echo -e "${GREEN}Passed:       ${total_passed}${NC}"

if [ "$total_failed" -gt 0 ]; then
    echo -e "${YELLOW}Failed:       ${total_failed}${NC}"
else
    echo -e "${GREEN}Failed:       ${total_failed}${NC}"
fi

# Calculate percentage
if [ "$total_tests" -gt 0 ]; then
    percentage=$(awk "BEGIN {printf \"%.1f\", ($total_passed / $total_tests) * 100}")
    echo -e "Pass Rate:    ${percentage}%"
fi

echo ""

# List failed suites if any
if [ ${#failed_suites[@]} -gt 0 ]; then
    echo -e "${YELLOW}Suites with failures:${NC}"
    for suite in "${failed_suites[@]}"; do
        echo -e "  - ${suite}"
    done
    echo ""
    exit 1
else
    echo -e "${GREEN}All test suites passed!${NC}"
    echo ""
    exit 0
fi
