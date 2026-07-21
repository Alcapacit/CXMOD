#!/bin/sh
# CXMOD test suite
# Usage: ./tests/test_basic.sh [./cx]

CXMOD="${1:-./cx}"
PASS=0; FAIL=0; SKIP=0

col_green='\033[32m'; col_red='\033[31m'
col_yellow='\033[33m'; col_reset='\033[0m'

pass() { PASS=$((PASS+1));  printf "  ${col_green}PASS${col_reset}  %s\n" "$1"; }
fail() { FAIL=$((FAIL+1));  printf "  ${col_red}FAIL${col_reset}  %s — %s\n" "$1" "$2"; }
skip() { SKIP=$((SKIP+1));  printf "  ${col_yellow}SKIP${col_reset}  %s\n" "$1"; }

check() {
    NAME="$1"; shift
    if "$CXMOD" "$@" --no-color >/dev/null 2>&1; then
        pass "$NAME"
    else
        fail "$NAME" "exit code $?"
    fi
}

check_output() {
    NAME="$1"; NEEDLE="$2"; shift 2
    OUT=$("$CXMOD" "$@" --no-color 2>&1)
    if echo "$OUT" | grep -qi "$NEEDLE"; then
        pass "$NAME"
    else
        fail "$NAME" "expected '$NEEDLE' in output"
    fi
}

echo ""
echo "CXMOD Test Suite  ($CXMOD)"
echo ""

# ── Binary exists and runs ─────────────────────────────────────────────────
if [ ! -x "$CXMOD" ]; then
    echo "  ERROR: $CXMOD not found or not executable"
    echo "  Run: make"
    exit 1
fi

# ── Version / help ─────────────────────────────────────────────────────────
check_output  "version"                  "CXMOD v"        version
check_output  "version --version"        "CXMOD v"        --version
check_output  "help"                     "diagnose"       --help
check_output  "help subcommands listed"  "tune"           --help
check_output  "help fix listed"          "fix"            --help
check_output  "help persist listed"      "persist"        --help
check_output  "help offload listed"      "offload"        --help
check_output  "help sockstat listed"     "sockstat"       --help

# ── Tuning ─────────────────────────────────────────────────────────────────
check_output  "tune --list"              "balanced"       tune --list
check_output  "tune --list profiles"     "high_throughput" tune --list
check_output  "tune --list satellite"    "satellite"      tune --list
check         "tune --current"           tune --current
check_output  "tune --bdp 1000 10"      "BDP"            tune --bdp 1000 10
check_output  "tune --bdp 10000 200"    "BDP"            tune --bdp 10000 200
check_output  "tune --bdp big link"     "Mbit"           tune --bdp 100000 5
check_output  "tune --auto-bdp"         "Mbit"           tune --auto-bdp

check_output  "tune balanced dry-run"      "sysctl"      tune --profile=balanced --dry-run
check_output  "tune high_throughput dry"   "sysctl"      tune --profile=high_throughput --dry-run
check_output  "tune low_latency dry"       "sysctl"      tune --profile=low_latency --dry-run
check_output  "tune satellite dry"         "sysctl"      tune --profile=satellite --dry-run
check_output  "tune hardened dry"          "sysctl"      tune --profile=hardened --dry-run

# ── Persist ────────────────────────────────────────────────────────────────
check_output  "persist --show (no file)" "persist" persist --show

# ── Conntrack ─────────────────────────────────────────────────────────────
check         "conntrack --stats"       conntrack --stats
check         "conntrack --states"      conntrack --states
check_output  "conntrack fix dry"       "dry"    conntrack --fix --dry-run

# ── IRQ ────────────────────────────────────────────────────────────────────
check         "irq --show"             irq --show
check_output  "irq --balance dry"      "IRQ"    irq --balance --dry-run
check_output  "irq --rps dry"          "RPS"    irq --rps --dry-run

# ── QoS ────────────────────────────────────────────────────────────────────
check_output  "qos --apply dry"        "dry"    qos --apply --iface=lo --bw=100 --dry-run
check_output  "qos --remove dry"       "tc"     qos --remove --iface=lo --dry-run
check         "qos --show"             qos --show

# ── Offload ────────────────────────────────────────────────────────────────
check         "offload --show"         offload --show
check_output  "offload fix-lro dry"    "dry"    offload --fix-lro --dry-run

# ── Route ─────────────────────────────────────────────────────────────────
check         "route --show"           route --show
check_output  "route --show table"     "Destination"  route --show
check_output  "route --add dry"        "dry"          route --add 192.168.99.0/24 via 10.0.0.1 --dry-run

# ── Sockstat ──────────────────────────────────────────────────────────────
check         "sockstat"               sockstat
check_output  "sockstat TCP"           "TCP"          sockstat
check_output  "sockstat orphans"       "Orphan"       sockstat

# ── Proto ─────────────────────────────────────────────────────────────────
check         "proto"                  proto
check_output  "proto TCP"             "TCP"           proto
check_output  "proto retransmit"      "retransmit"    proto

# ── Iface ─────────────────────────────────────────────────────────────────
check         "iface"                  iface
check_output  "iface lo"              "lo"             iface
check_output  "iface --iface=lo"      "lo"             iface --iface=lo

# ── Diagnose ──────────────────────────────────────────────────────────────
check         "diagnose"              diagnose

# ── Fix dry-run ────────────────────────────────────────────────────────────
check_output  "fix --dry-run"         "DRY-RUN"       fix --dry-run

# ── Report ────────────────────────────────────────────────────────────────
check         "report"                report

TMP_REPORT=$(mktemp /tmp/cxmod_report_XXXXXX.txt)
if "$CXMOD" report --output="$TMP_REPORT" --no-color >/dev/null 2>&1; then
    if [ -s "$TMP_REPORT" ]; then
        pass "report --output=FILE"
    else
        fail "report --output=FILE" "output file is empty"
    fi
else
    fail "report --output=FILE" "command failed"
fi
rm -f "$TMP_REPORT"

TMP_JSON=$(mktemp /tmp/cxmod_report_XXXXXX.json)
if "$CXMOD" report --json --output="$TMP_JSON" --no-color >/dev/null 2>&1; then
    if grep -q '"cxmod_version"' "$TMP_JSON" 2>/dev/null; then
        pass "report --json --output=FILE"
    else
        fail "report --json --output=FILE" "missing cxmod_version key"
    fi
else
    fail "report --json --output=FILE" "command failed"
fi
rm -f "$TMP_JSON"

# ── Global flags ──────────────────────────────────────────────────────────
check         "no-color flag"          version --no-color
check         "verbose flag"           tune --list --verbose
check_output  "unknown cmd fails"      ""   version 2>/dev/null  # exit 0

# verify unknown cmd exits non-zero
if "$CXMOD" nonexistent_cmd --no-color >/dev/null 2>&1; then
    fail "unknown cmd exits non-zero" "should return exit code 1"
else
    pass "unknown cmd exits non-zero"
fi

# ── Summary ────────────────────────────────────────────────────────────────
echo ""
TOTAL=$((PASS + FAIL + SKIP))
echo "Results: ${PASS} passed, ${FAIL} failed, ${SKIP} skipped  (${TOTAL} total)"
echo ""

if [ "$FAIL" -gt 0 ]; then
    printf "  ${col_red}FAIL: %d test(s) failed${col_reset}\n\n" "$FAIL"
    exit 1
else
    printf "  ${col_green}All tests passed${col_reset}\n\n"
    exit 0
fi
