#!/bin/bash
BASEDIR="/home/ezechiel203/ksmbd/debug/tests/baseline"
ALL_SUITES="compound compound_async compound_find connect create credits delete-on-close-perms dir dirlease dosmode durable-open durable-v2-open getinfo ioctl lease lock maxfid maximum_allowed mkdir mux notify openattr oplock read rename replay rw secleak session setinfo streams zero-data-ioctl"

total_pass=0
total_fail=0
total_skip=0
total_error=0

printf "%-30s %6s %6s %6s %8s\n" "SUITE" "PASS" "FAIL" "SKIP" "STATUS"
printf "%-30s %6s %6s %6s %8s\n" "-----" "----" "----" "----" "------"

for suite in $ALL_SUITES; do
    logfile="$BASEDIR/${suite}.log"
    if [ ! -f "$logfile" ]; then
        printf "%-30s %6s %6s %6s %8s\n" "smb2.$suite" "-" "-" "-" "MISSING"
        continue
    fi

    pass=$(grep -c 'success:' "$logfile" 2>/dev/null || echo 0)
    fail=$(grep -c 'failure:' "$logfile" 2>/dev/null || echo 0)
    skip=$(grep -c 'skip:' "$logfile" 2>/dev/null || echo 0)
    
    # Detect timeout (no "Tests " summary line and large file or specific pattern)
    timedout=""
    if grep -q 'Timed out' "$logfile" 2>/dev/null || [ "$(wc -c < "$logfile")" -eq 0 ]; then
        timedout="TIMEOUT"
    fi
    
    # Status
    if [ "$pass" -gt 0 ] && [ "$fail" -eq 0 ]; then
        status="PASS"
    elif [ "$fail" -gt 0 ]; then
        status="FAIL"
    elif [ "$pass" -eq 0 ] && [ "$fail" -eq 0 ] && [ "$skip" -eq 0 ]; then
        status="ERROR"
        total_error=$((total_error + 1))
    else
        status="SKIP"
    fi
    
    if [ -n "$timedout" ]; then
        status="${status}+TO"
    fi

    total_pass=$((total_pass + pass))
    total_fail=$((total_fail + fail))
    total_skip=$((total_skip + skip))

    printf "%-30s %6d %6d %6d %8s\n" "smb2.$suite" "$pass" "$fail" "$skip" "$status"
done

printf "%-30s %6s %6s %6s %8s\n" "-----" "----" "----" "----" "------"
printf "%-30s %6d %6d %6d\n" "TOTAL" "$total_pass" "$total_fail" "$total_skip"
echo ""
echo "Grand total tests: $((total_pass + total_fail + total_skip))"
echo "Pass rate: $(echo "scale=1; $total_pass * 100 / ($total_pass + $total_fail + $total_skip)" | bc 2>/dev/null || echo "N/A")%"
