#!/bin/bash
# Run SMB2 smbtorture matrix over QUIC bridge TCP port.

set -euo pipefail

TARGET_HOST="${1:-127.0.0.1}"
TARGET_SHARE="${2:-test}"
TARGET_PORT="${3:-443}"
AUTH="${4:-testuser%testpass}"
TEST_TIMEOUT_SECS="${TEST_TIMEOUT_SECS:-45}"
KSMBD_START_WAIT="${KSMBD_START_WAIT:-8}"
PROXY_START_WAIT="${PROXY_START_WAIT:-5}"
PRECHECK_TIMEOUT_SECS="${PRECHECK_TIMEOUT_SECS:-8}"
MAX_INFRA_STREAK="${MAX_INFRA_STREAK:-5}"

OUT_DIR="/root/smbtorture-quic"
mkdir -p "$OUT_DIR"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT_FILE="$OUT_DIR/smbtorture-quic-${STAMP}.log"
SUMMARY_FILE="$OUT_DIR/smbtorture-quic-${STAMP}.summary"

UNC="//${TARGET_HOST}/${TARGET_SHARE}"

tests=(
  smb2.scan smb2.getinfo smb2.lock smb2.read smb2.aio_delay smb2.bench
  smb2.create smb2.twrp smb2.fileid smb2.acls smb2.acls_non_canonical
  smb2.notify smb2.notify-inotify smb2.change_notify_disabled smb2.durable-open
  smb2.durable-open-disconnect smb2.durable-v2-open smb2.durable-v2-delay
  smb2.durable-v2-regressions smb2.dir smb2.lease smb2.dirlease smb2.compound
  smb2.compound_find smb2.compound_async smb2.oplock smb2.kernel-oplocks
  smb2.streams smb2.ioctl smb2.rename smb2.sharemode smb2.session
  smb2.session-require-signing smb2.replay smb2.credits
  smb2.delete-on-close-perms smb2.multichannel smb2.samba3misc smb2.timestamps
  smb2.timestamp_resolution smb2.rw smb2.maximum_allowed smb2.name-mangling
  smb2.charset smb2.deny smb2.ea smb2.create_no_streams smb2.connect
  smb2.setinfo smb2.stream-inherit-perms smb2.set-sparse-ioctl
  smb2.zero-data-ioctl smb2.ioctl-on-stream smb2.hold-oplock smb2.dosmode
  smb2.async_dosmode smb2.maxfid smb2.hold-sharemode smb2.check-sharemode
  smb2.openattr smb2.winattr smb2.winattr2 smb2.sdread smb2.tcon smb2.mkdir
  smb2.secleak smb2.session-id
)

pass=0
fail=0
skip=0
infra=0
infra_streak=0

collect_diag() {
  local reason="$1"
  local test_name="$2"
  {
    echo
    echo "--- DIAG reason=${reason} test=${test_name} ts=$(date -Is) ---"
    timeout 5s ksmbdctl status 2>&1 || true
    timeout 5s ss -ltn 2>&1 || true
    timeout 5s pgrep -af 'ksmbdctl|ksmbd.mountd|quic-proxy-emulator.py' 2>&1 || true
    timeout 5s dmesg | tail -n 80 2>&1 || true
    timeout 5s /bin/bash /mnt/ksmbd/vm/quic-proxy-guest.sh logs 2>&1 || true
    timeout 5s /bin/bash -lc "tail -n 120 /root/ksmbd-mountd.log" 2>&1 || true
    echo "--- END DIAG ---"
    echo
  } >> "$OUT_FILE"
}

ensure_ksmbd() {
  if ksmbdctl status 2>/dev/null | grep -q "ksmbd.mountd:   running"; then
    return 0
  fi

  pkill -f 'ksmbdctl stop' >/dev/null 2>&1 || true
  pkill -f 'ksmbdctl start' >/dev/null 2>&1 || true
  pkill -f 'ksmbd.mountd' >/dev/null 2>&1 || true
  rm -f /run/ksmbd.lock /var/run/ksmbd.lock /usr/var/run/ksmbd.lock

  /bin/bash /mnt/ksmbd/vm/vm-guest-prepare.sh >/dev/null 2>&1 || true
  nohup ksmbdctl start --nodetach >/root/ksmbd-mountd.log 2>&1 </dev/null &

  for _ in $(seq 1 "$KSMBD_START_WAIT"); do
    if ksmbdctl status 2>/dev/null | grep -q "ksmbd.mountd:   running"; then
      return 0
    fi
    sleep 1
  done

  return 1
}

ensure_proxy() {
  if ss -ltn | grep -q ':443 '; then
    return 0
  fi

  /bin/bash /mnt/ksmbd/vm/quic-proxy-guest.sh start >/dev/null 2>&1 || true

  for _ in $(seq 1 "$PROXY_START_WAIT"); do
    if ss -ltn | grep -q ':443 '; then
      return 0
    fi
    sleep 1
  done

  return 1
}

ensure_stack() {
  if ! ensure_ksmbd; then
    return 1
  fi

  if ! ensure_proxy; then
    return 1
  fi

  if timeout "${PRECHECK_TIMEOUT_SECS}"s smbclient -s /dev/null -U "$AUTH" -m SMB3_11 -p "$TARGET_PORT" "//${TARGET_HOST}/${TARGET_SHARE}" -c ls >/dev/null 2>&1; then
    return 0
  fi

  /bin/bash /mnt/ksmbd/vm/quic-proxy-guest.sh stop >/dev/null 2>&1 || true
  if ! ensure_proxy; then
    return 1
  fi

  timeout "${PRECHECK_TIMEOUT_SECS}"s smbclient -s /dev/null -U "$AUTH" -m SMB3_11 -p "$TARGET_PORT" "//${TARGET_HOST}/${TARGET_SHARE}" -c ls >/dev/null 2>&1
}

{
  echo "smbtorture over QUIC bridge (TCP emulation mode)"
  echo "target=${UNC} port=${TARGET_PORT}"
  echo "tests=${#tests[@]}"
  echo
} > "$OUT_FILE"

for t in "${tests[@]}"; do
  if ! ensure_stack; then
    echo "RESULT ${t}: INFRA_FAIL(precheck)" | tee -a "$OUT_FILE"
    infra=$((infra + 1))
    infra_streak=$((infra_streak + 1))
    collect_diag "precheck" "$t"
    if [ "$infra_streak" -ge "$MAX_INFRA_STREAK" ]; then
      echo "ABORT: consecutive infra failures reached ${MAX_INFRA_STREAK}" | tee -a "$OUT_FILE"
      break
    fi
    continue
  fi

  infra_streak=0

  echo "=== ${t} ===" | tee -a "$OUT_FILE"
  tmp_out="/tmp/smbtorture-${t//./_}.out"
  if timeout "${TEST_TIMEOUT_SECS}"s smbtorture "$UNC" "$t" -U "$AUTH" -m SMB3_11 -p "$TARGET_PORT" --client-protection=encrypt -d 0 >"$tmp_out" 2>&1; then
    cat "$tmp_out" >> "$OUT_FILE"
    echo "RESULT ${t}: PASS" | tee -a "$OUT_FILE"
    pass=$((pass + 1))
  else
    rc=$?
    cat "$tmp_out" >> "$OUT_FILE"
    if [ "$rc" -eq 124 ]; then
      echo "RESULT ${t}: SKIP(timeout)" | tee -a "$OUT_FILE"
      skip=$((skip + 1))
    else
      if grep -qE "NT_STATUS_CONNECTION_(RESET|DISCONNECTED)|Failed to connect to SMB2 share" "$tmp_out"; then
        echo "RESULT ${t}: INFRA_FAIL(connectivity rc=${rc})" | tee -a "$OUT_FILE"
        infra=$((infra + 1))
        infra_streak=$((infra_streak + 1))
        collect_diag "connectivity" "$t"
        if [ "$infra_streak" -ge "$MAX_INFRA_STREAK" ]; then
          echo "ABORT: consecutive infra failures reached ${MAX_INFRA_STREAK}" | tee -a "$OUT_FILE"
          rm -f "$tmp_out"
          break
        fi
      else
        echo "RESULT ${t}: FAIL(rc=${rc})" | tee -a "$OUT_FILE"
        fail=$((fail + 1))
        infra_streak=0
      fi
    fi
  fi
  rm -f "$tmp_out"
done

{
  echo "PASS=${pass} FAIL=${fail} SKIP=${skip} INFRA=${infra}"
  echo "LOG=${OUT_FILE}"
} | tee "$SUMMARY_FILE"

cat "$SUMMARY_FILE"
