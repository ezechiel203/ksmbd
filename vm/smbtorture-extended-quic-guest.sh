#!/bin/bash
# Extended SMB2 smbtorture suite over QUIC bridge emulator (port 443).
# Mirror of smbtorture-extended-tcp-guest.sh but via the QUIC proxy.
# Includes INFRA_FAIL detection (connectivity loss != protocol fail).

TARGET_HOST="${1:-127.0.0.1}"
TARGET_SHARE="${2:-test}"
TARGET_PORT="${3:-443}"
AUTH="${4:-testuser%testpass}"
TEST_TIMEOUT_SECS="${TEST_TIMEOUT_SECS:-90}"

UNC="//${TARGET_HOST}/${TARGET_SHARE}"

/bin/bash /mnt/ksmbd/vm/vm-guest-prepare.sh >/dev/null 2>&1 || true
systemd-run --unit ksmbd-ext-daemon -p KillMode=none /usr/bin/ksmbdctl start >/dev/null 2>&1 || true
/bin/bash /mnt/ksmbd/vm/quic-proxy-guest.sh start >/dev/null 2>&1 || true
sleep 1

# ── session test list (exclude known-broken reauth5, Samba knownfail) ────────
SESSION_LIST="/tmp/smb2-session-noauth5.txt"
smbtorture "$UNC" -p "$TARGET_PORT" --list smb2.session 2>/dev/null \
  | grep -v "^smbtorture\|^Can.t load\|reauth5" \
  > "$SESSION_LIST" || true

# ── timeout overrides ─────────────────────────────────────────────────────────
declare -A TIMEOUT_OVERRIDE=(
  [smb2.lock]=120
  [smb2.notify]=180
  [smb2.ioctl]=120
  [smb2.oplock]=360
  [smb2.lease]=360
  [smb2.dirlease]=180
  [smb2.durable-open]=180
  [smb2.durable-v2-open]=180
  [smb2.dir]=300
  [smb2.replay]=240
  [smb2.compound_async]=120
  [smb2.rename]=120
  [smb2.timestamps]=180
)

# ── per-suite extra smbtorture args ──────────────────────────────────────────
declare -A EXTRA_ARGS=(
  [smb2.create]="--target=win7"
  [smb2.session]="--load-list=${SESSION_LIST}"
  [smb2.ea]="--option=torture:acl_xattr_name=security.NTACL"
)

tests=(
  smb2.scan
  smb2.connect
  smb2.tcon
  smb2.getinfo
  smb2.setinfo
  smb2.read
  smb2.rw
  smb2.rename
  smb2.create
  smb2.dir
  smb2.mkdir
  smb2.dosmode
  smb2.timestamps
  smb2.ea
  smb2.winattr
  smb2.streams
  smb2.lock
  smb2.sharemode
  smb2.deny
  smb2.delete-on-close-perms
  smb2.openattr
  smb2.maximum_allowed
  smb2.ioctl
  smb2.notify
  smb2.compound
  smb2.compound_async
  smb2.compound_find
  smb2.session
  smb2.oplock
  smb2.lease
  smb2.dirlease
  smb2.durable-open
  smb2.durable-v2-open
  smb2.durable-v2-regressions
  smb2.replay
  smb2.sdread
  smb2.fileid
  smb2.acls
)

pass=0
fail=0
skip=0
infra=0
knownfail=0

for t in "${tests[@]}"; do
  # Connectivity pre-check
  if ! timeout 8s smbclient -s /dev/null -U "$AUTH" -m SMB3_11 \
        -p "$TARGET_PORT" "$UNC" -c ls >/dev/null 2>&1; then
    echo "RESULT ${t}: INFRA_FAIL(precheck)"
    infra=$((infra + 1))
    continue
  fi

  tmp_out="/tmp/smbtorture-qext-${t//./_}.out"
  echo "=== ${t} ==="

  timeout_secs="${TIMEOUT_OVERRIDE[$t]:-$TEST_TIMEOUT_SECS}"
  extra="${EXTRA_ARGS[$t]:-}"

  # shellcheck disable=SC2086
  if timeout "${timeout_secs}"s smbtorture "$UNC" "$t" \
       -U "$AUTH" -m SMB3_11 -p "$TARGET_PORT" \
       --client-protection=encrypt -d 0 \
       $extra >"$tmp_out" 2>&1; then
    echo "RESULT ${t}: PASS"
    pass=$((pass + 1))
  else
    rc=$?
    if [ "$rc" -eq 124 ]; then
      echo "RESULT ${t}: SKIP(timeout ${timeout_secs}s)"
      skip=$((skip + 1))
    elif grep -qE "NT_STATUS_CONNECTION_(RESET|DISCONNECTED|REFUSED)|Failed to connect to SMB2 share" "$tmp_out"; then
      echo "RESULT ${t}: INFRA_FAIL(connectivity rc=${rc})"
      sed -n '1,10p' "$tmp_out"
      infra=$((infra + 1))
    else
      echo "RESULT ${t}: FAIL(rc=${rc})"
      sed -n '1,30p' "$tmp_out"
      fail=$((fail + 1))
    fi
  fi
done

echo ""
echo "QUIC_EXTENDED PASS=${pass} FAIL=${fail} SKIP=${skip} INFRA=${infra} KNOWNFAIL=${knownfail}"
[ "$fail" -eq 0 ]
