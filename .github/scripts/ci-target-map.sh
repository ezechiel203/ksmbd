#!/usr/bin/env bash

# SPDX-License-Identifier: GPL-2.0-or-later
#
# Map a logical CI target name to kernel ARCH and cross-compiler prefix.

set -euo pipefail

target_arch="${1:-${TARGET_ARCH:-x86_64}}"

case "$target_arch" in
    x86_64|amd64)
        cat <<'EOF'
ARCH=x86_64
CROSS_COMPILE=
APT_CROSS_PACKAGES=
DNF_CROSS_PACKAGES=
EOF
        ;;
    arm32|arm|armhf)
        cat <<'EOF'
ARCH=arm
CROSS_COMPILE=arm-linux-gnueabihf-
APT_CROSS_PACKAGES=gcc-arm-linux-gnueabihf binutils-arm-linux-gnueabihf
DNF_CROSS_PACKAGES=gcc-arm-linux-gnu binutils-arm-linux-gnu
EOF
        ;;
    arm64|aarch64)
        cat <<'EOF'
ARCH=arm64
CROSS_COMPILE=aarch64-linux-gnu-
APT_CROSS_PACKAGES=gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu
DNF_CROSS_PACKAGES=gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu
EOF
        ;;
    powerpc64|ppc64)
        cat <<'EOF'
ARCH=powerpc
CROSS_COMPILE=powerpc64-linux-gnu-
APT_CROSS_PACKAGES=gcc-powerpc64-linux-gnu binutils-powerpc64-linux-gnu
DNF_CROSS_PACKAGES=gcc-powerpc64-linux-gnu binutils-powerpc64-linux-gnu
EOF
        ;;
    powerpc|ppc|powerpc64le|ppc64le)
        cat <<'EOF'
ARCH=powerpc
CROSS_COMPILE=powerpc64le-linux-gnu-
APT_CROSS_PACKAGES=gcc-powerpc64le-linux-gnu binutils-powerpc64le-linux-gnu
DNF_CROSS_PACKAGES=gcc-powerpc64le-linux-gnu binutils-powerpc64le-linux-gnu
EOF
        ;;
    riscv|riscv64)
        cat <<'EOF'
ARCH=riscv
CROSS_COMPILE=riscv64-linux-gnu-
APT_CROSS_PACKAGES=gcc-riscv64-linux-gnu binutils-riscv64-linux-gnu
DNF_CROSS_PACKAGES=gcc-riscv64-linux-gnu binutils-riscv64-linux-gnu
EOF
        ;;
    *)
        echo "Unsupported TARGET_ARCH: $target_arch" >&2
        exit 1
        ;;
esac
