#!/bin/bash
# Host wrapper to run SMB2 smbtorture matrix over QUIC bridge mode.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

VM_NAME="${1:-VM0}"

"$SCRIPT_DIR/vm-exec-instance.sh" "$VM_NAME" /bin/bash /mnt/ksmbd/vm/vm-guest-prepare.sh
"$SCRIPT_DIR/vm-exec-instance.sh" "$VM_NAME" /bin/bash /mnt/ksmbd/vm/smbtorture-over-quic-guest.sh
