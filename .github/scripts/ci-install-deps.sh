#!/usr/bin/env bash

# SPDX-License-Identifier: GPL-2.0-or-later
#
# Install build dependencies for the requested architecture on apt/dnf distros.

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
target_arch="${TARGET_ARCH:-x86_64}"

eval "$("$script_dir/ci-target-map.sh" "$target_arch")"

install_apt() {
    export DEBIAN_FRONTEND=noninteractive

    apt-get update
    apt-get install -y --no-install-recommends \
        ca-certificates curl xz-utils tar gzip \
        git make file bc bison flex perl python3 \
        gcc sparse cppcheck shellcheck \
        libelf-dev libssl-dev dwarves cpio rsync

    if [ -n "$APT_CROSS_PACKAGES" ]; then
        apt-get install -y --no-install-recommends $APT_CROSS_PACKAGES
    fi
}

install_dnf() {
    dnf -y install \
        ca-certificates curl xz tar gzip \
        git make file bc bison flex perl python3 \
        gcc clang llvm sparse cppcheck ShellCheck \
        elfutils-libelf-devel openssl-devel dwarves cpio rsync

    if [ -n "$DNF_CROSS_PACKAGES" ]; then
        dnf -y install $DNF_CROSS_PACKAGES
    fi
}

if command -v apt-get >/dev/null 2>&1; then
    install_apt
elif command -v dnf >/dev/null 2>&1; then
    install_dnf
else
    echo "Unsupported package manager. Expected apt-get or dnf." >&2
    exit 1
fi
