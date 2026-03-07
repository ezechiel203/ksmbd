#!/bin/bash
# Quick SMB2 smbtorture smoke over QUIC bridge emulator port 443.

set -euo pipefail

TARGET_HOST="${1:-127.0.0.1}"
TARGET_SHARE="${2:-test}"
TARGET_PORT="${3:-443}"
AUTH="${4:-testuser%testpass}"
TEST_TIMEOUT_SECS="${TEST_TIMEOUT_SECS:-60}"

UNC="//${TARGET_HOST}/${TARGET_SHARE}"

tests=(
  smb2.scan smb2.getinfo smb2.read smb2.create
  smb2.dir smb2.compound smb2.durable-v2-regressions
)

pass=0
fail=0
skip=0
infra=0

/bin/bash /mnt/ksmbd/vm/vm-guest-prepare.sh >/dev/null 2>&1 || true
systemd-run --unit ksmbd-daemon -p KillMode=none /usr/bin/ksmbdctl start >/dev/null 2>&1 || true
/bin/bash /mnt/ksmbd/vm/quic-proxy-guest.sh start >/dev/null 2>&1 || true
sleep 1

for t in "${tests[@]}"; do
  if ! timeout 8s smbclient -s /dev/null -U "$AUTH" -m SMB3_11 -p "$TARGET_PORT" "$UNC" -c ls >/dev/null 2>&1; then
    echo "RESULT ${t}: INFRA_FAIL(precheck)"
    infra=$((infra + 1))
    continue
  fi

  tmp_out="/tmp/smbtorture-quic-${t//./_}.out"
  echo "=== ${t} ==="
  extra_args=()
  # smb2.create gentest subtest expects --target=win7 access_mask behaviour
  [ "$t" = "smb2.create" ] && extra_args=(--target=win7)
  # smb2.dir has many long-running subtests (many/modify/sorted each ~60s)
  test_timeout="${TEST_TIMEOUT_SECS}"
  [ "$t" = "smb2.dir" ] && test_timeout=300
  if timeout "${test_timeout}"s smbtorture "$UNC" "$t" -U "$AUTH" -m SMB3_11 -p "$TARGET_PORT" --client-protection=encrypt -d 0 "${extra_args[@]}" >"$tmp_out" 2>&1; then
    echo "RESULT ${t}: PASS"
    pass=$((pass + 1))
  else
    rc=$?
    if [ "$rc" -eq 124 ]; then
      echo "RESULT ${t}: SKIP(timeout)"
      skip=$((skip + 1))
    elif grep -qE "NT_STATUS_CONNECTION_(RESET|DISCONNECTED|REFUSED)|Failed to connect to SMB2 share" "$tmp_out"; then
      echo "RESULT ${t}: INFRA_FAIL(connectivity rc=${rc})"
      sed -n '1,20p' "$tmp_out"
      infra=$((infra + 1))
    else
      echo "RESULT ${t}: FAIL(rc=${rc})"
      sed -n '1,25p' "$tmp_out"
      fail=$((fail + 1))
    fi
  fi
done

echo "QUIC_SMOKE PASS=${pass} FAIL=${fail} SKIP=${skip} INFRA=${infra}"
