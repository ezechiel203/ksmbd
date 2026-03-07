#!/bin/bash
# sweep-smb2.sh - Run all smb2.* suites on a VM and tally results
# Usage: ./vm/sweep-smb2.sh [SSH_PORT [SMB_PORT]]

set -u

SSH_PORT="${1:-13022}"
SMB_PORT="${2:-13445}"
OUTDIR="/tmp/sweep-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUTDIR"

if ! command -v smbtorture >/dev/null 2>&1; then
  echo "FATAL: smbtorture not found on host PATH" >&2
  exit 1
fi

SSH=(sshpass -p root ssh -p "$SSH_PORT" -o StrictHostKeyChecking=no \
     -o ConnectTimeout=5 root@127.0.0.1)

# Suites to test (comprehensive smb2.* list)
SUITES=(
  compound
  compound_async
  compound_find
  connect
  create
  credits
  delete-on-close-perms
  dir
  dirlease
  dosmode
  durable-open
  durable-v2-open
  getinfo
  ioctl
  lease
  lock
  maxfid
  maximum_allowed
  mkdir
  mux
  notify
  openattr
  oplock
  read
  rename
  replay
  rw
  secleak
  session
  setinfo
  streams
  zero-data-ioctl
)

TOTAL_P=0
TOTAL_F=0
TOTAL_S=0
TOTAL_E=0

echo "=== SMB2 Sweep: $(date) ==="
echo "SSH=$SSH_PORT  SMB=$SMB_PORT"
echo "Output: $OUTDIR"
echo "Reset mode: full guest factory reset before every suite"
echo ""

# wait_ssh: wait up to 90s for SSH to become available, return 0 or 1
wait_ssh() {
  local _
  for _ in $(seq 1 30); do
    if "${SSH[@]}" "true" 2>/dev/null; then
      return 0
    fi
    sleep 3
  done
  echo "FATAL: VM SSH unavailable after 90s" >&2
  return 1
}

# wait_smb_port: wait up to 60s for SMB port to be reachable from host
wait_smb_port() {
  local _
  for _ in $(seq 1 20); do
    if timeout 3 bash -c "echo > /dev/tcp/127.0.0.1/$SMB_PORT" 2>/dev/null; then
      return 0
    fi
    sleep 3
  done
  echo "WARNING: SMB port $SMB_PORT not reachable from host after 60s" >&2
  return 1
}

guest_factory_reset() {
  "${SSH[@]}" /bin/bash <<'EOF'
set -euo pipefail

for proc in ksmbd.mountd ksmbd.control ksmbdctl smbtorture smbclient mount.cifs umount.cifs; do
  pkill -TERM -x "$proc" >/dev/null 2>&1 || true
done
ksmbdctl stop >/dev/null 2>&1 || true
sleep 1
for proc in ksmbd.mountd ksmbd.control ksmbdctl smbtorture smbclient mount.cifs umount.cifs; do
  pkill -KILL -x "$proc" >/dev/null 2>&1 || true
done

rm -f /run/ksmbd.lock /var/run/ksmbd.lock /usr/var/run/ksmbd.lock /tmp/ksmbd.lock
rm -f /run/ksmbd.fifo* /var/run/ksmbd.fifo* /usr/var/run/ksmbd.fifo* /tmp/ksmbd.fifo*
rm -rf /run/ksmbd /var/run/ksmbd /usr/var/run/ksmbd

rm -f /etc/ksmbd/ksmbd.conf /etc/ksmbd/ksmbdpwd.db /etc/ksmbd/ksmbd.subauth
rm -rf /srv/smb

mkdir -p /run /var/run /usr/var/run /etc/ksmbd /srv/smb/test
chmod 0777 /srv/smb /srv/smb/test

find /tmp -maxdepth 1 \
  \( -name 'smbtorture-*' -o -name 'ksmbd-*' -o -name 'trace.ksmbd*' \) \
  -exec rm -rf {} + 2>/dev/null || true
rm -f /root/ksmbd-mountd.log /root/smbtorture-*.log /tmp/ksmbd-start.log

cat > /etc/ksmbd/ksmbd.conf <<'CONF'
[global]
    netbios name = KSMBD-VM
    server string = ksmbd test server
    workgroup = WORKGROUP
    server min protocol = SMB2_10
    server max protocol = SMB3_11
    map to guest = bad user
    max ip connections = 256
    smb2 leases = yes
    durable handles = yes

[test]
    path = /srv/smb/test
    comment = Test Share
    read only = no
    guest ok = yes
    browseable = yes
    create mask = 0777
    directory mask = 0777
    acl xattr = yes
    oplocks = yes
    streams = yes
CONF

printf 'testuser:Ncy6kWix1cpgk7S31Wxhmw==\n' > /etc/ksmbd/ksmbdpwd.db
chmod 0600 /etc/ksmbd/ksmbdpwd.db
EOF
}

# ksmbd_start_on_vm: load module and start daemon (VM must be reachable via SSH)
ksmbd_start_on_vm() {
  # shellcheck disable=SC2016
  "${SSH[@]}" '
    modprobe hkdf 2>/dev/null || insmod /mnt/ksmbd/vm/hkdf.ko.zst 2>/dev/null; true
    modprobe lz4 2>/dev/null; true
    modprobe libdes 2>/dev/null; true

    # Load fresh module if not already loaded
    if ! lsmod | grep -q "^ksmbd "; then
      insmod /mnt/ksmbd/ksmbd.ko 2>/dev/null ||
      insmod /root/ksmbd.ko 2>/dev/null ||
      insmod /usr/lib/modules/$(uname -r)/ksmbd.ko 2>/dev/null
    fi
    lsmod | grep -q "^ksmbd " || { echo "FATAL: ksmbd not loaded" >&2; exit 1; }
  ' 2>/dev/null || return 1

  guest_factory_reset || return 1

  # shellcheck disable=SC2016
  "${SSH[@]}" '
    ksmbdctl start >/dev/null 2>&1; true
    sleep 4

    # Retry start if not listening yet
    if ! ss -tlnp | grep -q ":445 "; then
      pkill -x ksmbdctl 2>/dev/null; sleep 1
      rm -f /run/ksmbd.lock /var/run/ksmbd.lock /usr/var/run/ksmbd.lock /tmp/ksmbd.lock 2>/dev/null; true
      rm -f /run/ksmbd.fifo* /var/run/ksmbd.fifo* /usr/var/run/ksmbd.fifo* /tmp/ksmbd.fifo* 2>/dev/null; true
      ksmbdctl start >/dev/null 2>&1; true
      sleep 4
    fi

    # Final check
    for _p in $(seq 1 12); do
      ss -tlnp | grep -q ":445 " && break
      sleep 2
    done
    ss -tlnp | grep -q ":445 " || { echo "FATAL: port 445 not listening" >&2; exit 1; }
  ' 2>/dev/null
}

restart_ksmbd() {
  # Step 1: wait for SSH (handles case where VM just rebooted)
  wait_ssh || return 1

  # Step 2: stop daemon and unload module on VM
  local ssh_rc
  # shellcheck disable=SC2016
  "${SSH[@]}" '
    # Stop daemon gracefully (best effort)
    ksmbdctl stop >/dev/null 2>&1; true
    sleep 2
    pkill -9 -x ksmbdctl 2>/dev/null; true
    pkill -9 -x smbtorture 2>/dev/null; true
    sleep 1

    # Only unload if the module is actually loaded
    if lsmod | grep -q "^ksmbd "; then
      # Wait for TCP connections to drain
      for i in $(seq 1 10); do
        cnt=$(ss -tnp 2>/dev/null | grep -c ":445" || true)
        [ "$cnt" -eq 0 ] && break
        sleep 2
      done

      # Try to unload module (up to 45s)
      rmmod_ok=0
      for i in $(seq 1 15); do
        rmmod ksmbd 2>/dev/null && rmmod_ok=1 && break
        sleep 3
      done

      if [ $rmmod_ok -eq 0 ]; then
        # Module stuck — reboot for clean state
        echo "rmmod stuck after 45s — rebooting VM" >&2
        reboot
        exit 99  # signals reboot to outer shell
      fi
    fi
    exit 0
  ' 2>/dev/null
  ssh_rc=$?

  # Step 3: if SSH returned non-zero (reboot triggered or SSH died), wait for VM
  if [ $ssh_rc -ne 0 ]; then
    echo "  [VM rebooting, waiting up to 120s...]" >&2
    sleep 20  # give reboot time to start (kernel shutdown ~5-15s)
    wait_ssh || { echo "FATAL: VM did not come back" >&2; return 1; }
  fi

  # Step 4: load module and start daemon
  ksmbd_start_on_vm || return 1

  # Step 5: wait for SMB port from host side
  wait_smb_port
  return 0
}

# ── Initial restart ──────────────────────────────────────────────────────────
echo "Restarting ksmbd..."
restart_ksmbd || { echo "FATAL: initial restart failed" >&2; exit 1; }

# ── Suite loop ───────────────────────────────────────────────────────────────
for suite in "${SUITES[@]}"; do
  logfile="$OUTDIR/${suite}.log"

  # Per-suite timeout
  timeout=120
  case "$suite" in
    dir) timeout=300 ;;
    lease|oplock|durable-*|replay|session|notify) timeout=180 ;;
  esac

  echo -n "  smb2.${suite} ... "

  # Full reset before every suite so each run sees a virgin guest/server state.
  restart_ksmbd || {
    echo "RESET-FAILED" >> "$logfile"
    echo "RESET-FAILED"
    TOTAL_E=$((TOTAL_E + 1))
    continue
  }

  # Run the suite
  timeout "$timeout" \
    smbtorture "//127.0.0.1/test" -U "testuser%testpass" -p "$SMB_PORT" \
    "smb2.${suite}" > "$logfile" 2>&1
  rc=$?

  # Record timeout
  if [ $rc -eq 124 ]; then
    echo "TIMEOUT" >> "$logfile"
  fi

  # Count results
  p=$(grep -c 'success:' "$logfile" 2>/dev/null || true)
  f=$(grep -c 'failure:' "$logfile" 2>/dev/null || true)
  s=$(grep -c 'skip:' "$logfile" 2>/dev/null || true)
  e=$(grep -cE 'INTERNAL ERROR|DEAD|panic|Oops' "$logfile" 2>/dev/null || true)
  if [ "$rc" -ne 0 ] && [ "$rc" -ne 1 ] && [ "$e" -eq 0 ]; then
    e=1
  fi
  : "${p:=0}" "${f:=0}" "${s:=0}" "${e:=0}"

  TOTAL_P=$((TOTAL_P + p))
  TOTAL_F=$((TOTAL_F + f))
  TOTAL_S=$((TOTAL_S + s))
  TOTAL_E=$((TOTAL_E + e))

  echo "P=$p F=$f S=$s E=$e"
done

echo ""
echo "=== TOTALS ==="
echo "PASS=$TOTAL_P  FAIL=$TOTAL_F  SKIP=$TOTAL_S  ERROR=$TOTAL_E"
echo "Total tests: $((TOTAL_P + TOTAL_F + TOTAL_S))"
echo ""
echo "Results saved to: $OUTDIR"
