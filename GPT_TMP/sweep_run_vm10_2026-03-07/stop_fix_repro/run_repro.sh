#!/bin/bash
set -euo pipefail
SSH=(sshpass -p root ssh -p 20022 -o StrictHostKeyChecking=no -o ConnectTimeout=5 root@127.0.0.1)
OUT=GPT_TMP/sweep_run_vm10_2026-03-07/stop_fix_repro
"${SSH[@]}" 'dmesg -C >/dev/null 2>&1 || true'
for i in 1 2 3; do
  echo "=== ITER $i ==="
  timeout 180 smbtorture //127.0.0.1/test -U testuser%testpass -p 20445 smb2.durable-v2-open > "$OUT/durable_v2_open_iter${i}.log" 2>&1 || true
  if "${SSH[@]}" "timeout 60 ksmbdctl stop > /tmp/ksmbd-stop-${i}.log 2>&1"; then
    echo "stop: ok"
  else
    echo "stop: fail"
    "${SSH[@]}" "cat /tmp/ksmbd-stop-${i}.log 2>/dev/null || true; ps -ef | grep -E 'ksmbdctl stop|ksmbd-durable' | grep -v grep || true; dmesg | tail -n 120" > "$OUT/stop_iter${i}_failure_probe.log" 2>&1 || true
    exit 1
  fi
  "${SSH[@]}" 'rm -f /run/ksmbd.lock /var/run/ksmbd.lock /usr/var/run/ksmbd.lock /tmp/ksmbd.lock; ksmbdctl start > /tmp/ksmbd-start-repro.log 2>&1; sleep 5; ksmbdctl status || true' > "$OUT/start_iter${i}.log" 2>&1
  echo "start: ok"
  sleep 2
done
"${SSH[@]}" 'dmesg | tail -n 200' > "$OUT/final_dmesg.log" 2>&1 || true
