#!/usr/bin/env bash

# SPDX-License-Identifier: GPL-2.0-or-later
#
# Cross-build ksmbd against a kernel tree prepared for a specific target arch.

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/../.." && pwd)"

target_arch="${TARGET_ARCH:-x86_64}"
kernel_version="${KERNEL_VERSION:-6.12.16}"
jobs="${JOBS:-2}"
kernel_workdir="${KERNEL_WORKDIR:-$repo_root/.ci-kernel}"

eval "$("$script_dir/ci-target-map.sh" "$target_arch")"

kernel_major="$(echo "$kernel_version" | cut -d. -f1)"
kernel_resolved_version="$kernel_version"
kernel_src="$kernel_workdir/linux-$kernel_version-$ARCH"
kernel_tar="$kernel_workdir/linux-$kernel_version.tar.xz"

download_kernel() {
    mkdir -p "$kernel_workdir"

    if [ -d "$kernel_src" ]; then
        return
    fi

    if [[ "$kernel_version" =~ ^[0-9]+\.[0-9]+\.0$ ]]; then
        local fallback_version="${kernel_version%.0}"
        local fallback_src="$kernel_workdir/linux-$fallback_version-$ARCH"
        if [ -d "$fallback_src" ]; then
            kernel_resolved_version="$fallback_version"
            kernel_src="$fallback_src"
            return
        fi
    fi

    rm -f "$kernel_tar"

    url_base_list=(
        "https://cdn.kernel.org/pub/linux/kernel/v${kernel_major}.x"
        "https://mirrors.edge.kernel.org/pub/linux/kernel/v${kernel_major}.x"
        "https://www.kernel.org/pub/linux/kernel/v${kernel_major}.x"
    )

    version_candidates=("$kernel_version")
    if [[ "$kernel_version" =~ ^[0-9]+\.[0-9]+\.0$ ]]; then
        version_candidates+=("${kernel_version%.0}")
    fi

    downloaded_version=""
    for candidate in "${version_candidates[@]}"; do
        for base in "${url_base_list[@]}"; do
            if curl -fsSL "${base}/linux-${candidate}.tar.xz" -o "$kernel_tar"; then
                downloaded_version="$candidate"
                break 2
            fi
        done
    done

    if [ ! -s "$kernel_tar" ]; then
        echo "Failed to download kernel tarball for requested version $kernel_version" >&2
        exit 1
    fi

    kernel_resolved_version="$downloaded_version"
    kernel_src="$kernel_workdir/linux-$kernel_resolved_version-$ARCH"

    if [ -d "$kernel_workdir/linux-$kernel_resolved_version" ]; then
        find "$kernel_workdir/linux-$kernel_resolved_version" -depth -delete
    fi
    tar -C "$kernel_workdir" -xf "$kernel_tar"
    mv "$kernel_workdir/linux-$kernel_resolved_version" "$kernel_src"
}

make_kernel_build_env() {
    local make_args=("-C" "$kernel_src" "ARCH=$ARCH")
    if [ -n "$CROSS_COMPILE" ]; then
        make_args+=("CROSS_COMPILE=$CROSS_COMPILE")
    fi

    make "${make_args[@]}" defconfig

    "$kernel_src/scripts/config" --file "$kernel_src/.config" \
        -m SMB_SERVER \
        -e SMB_INSECURE_SERVER \
        -d SMB_SERVER_SMBDIRECT \
        -e MODULES \
        -e INET \
        -e FILE_LOCKING

    make "${make_args[@]}" olddefconfig
    make "${make_args[@]}" modules_prepare
}

build_module() {
    local make_args=("-C" "$kernel_src" "M=$repo_root" "ARCH=$ARCH")

    if [ -n "$CROSS_COMPILE" ]; then
        make_args+=("CROSS_COMPILE=$CROSS_COMPILE")
    fi

    make -C "$repo_root" clean >/dev/null 2>&1 || true

    make "${make_args[@]}" \
        "CONFIG_SMB_SERVER=m" \
        "CONFIG_SMB_INSECURE_SERVER=y" \
        "CONFIG_SMB_SERVER_SMBDIRECT=n" \
        -j"$jobs" modules
}

verify_artifact() {
    if [ ! -f "$repo_root/ksmbd.ko" ]; then
        echo "ksmbd.ko not produced for target $target_arch" >&2
        exit 1
    fi

    file "$repo_root/ksmbd.ko"
}

download_kernel
make_kernel_build_env
build_module
verify_artifact
