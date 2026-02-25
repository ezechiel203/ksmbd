#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2019 Samsung Electronics Co., Ltd.
#

set -euo pipefail

KERNEL_SRC=""
COMP_FLAGS="${FLAGS:-}"
MODULE_DIR=""
MODULE_NAME=""

err() {
	echo "ERROR: $*" >&2
	exit 1
}

ensure_context() {
	if [[ -z "$KERNEL_SRC" || -z "$MODULE_DIR" || -z "$MODULE_NAME" ]]; then
		err "build context is not initialized"
	fi
}

is_module() {
	ensure_context
	grep -q '^CONFIG_SMB_SERVER=m$' "$KERNEL_SRC/.config"
}

patch_fs_config() {
	local cwd
	local kconfig_new

	cwd=$(pwd)
	case "$cwd" in
		*/fs/smbd)
			MODULE_DIR="smbd"
			MODULE_NAME="smbd"
			;;
		*/fs/ksmbd)
			MODULE_DIR="ksmbd"
			MODULE_NAME="ksmbd"
			;;
		*)
			err "please cd to fs/smbd or fs/ksmbd"
			;;
	esac

	KERNEL_SRC="${cwd%/fs/$MODULE_DIR}"
	if [[ ! -f "$KERNEL_SRC/fs/Kconfig" ]]; then
		err "invalid kernel tree: missing $KERNEL_SRC/fs/Kconfig"
	fi

	if ! grep -q "$MODULE_DIR" "$KERNEL_SRC/fs/Makefile"; then
		echo "obj-\$(CONFIG_SMB_SERVER)\t+= $MODULE_DIR/" >> "$KERNEL_SRC/fs/Makefile"
	fi

	if ! grep -q "fs/$MODULE_DIR/Kconfig" "$KERNEL_SRC/fs/Kconfig"; then
		kconfig_new="$KERNEL_SRC/fs/Kconfig.new"
		sed "s#source \"fs/cifs/Kconfig\"#source \"fs/cifs/Kconfig\"\\nsource \"fs/$MODULE_DIR/Kconfig\"#" \
			"$KERNEL_SRC/fs/Kconfig" > "$kconfig_new"
		mv "$kconfig_new" "$KERNEL_SRC/fs/Kconfig"
	fi

	if ! grep -q '^CONFIG_NETWORK_FILESYSTEMS=y$' "$KERNEL_SRC/.config"; then
		echo "CONFIG_NETWORK_FILESYSTEMS=y" >> "$KERNEL_SRC/.config"
	fi

	if ! is_module; then
		echo "CONFIG_SMB_SERVER=m" >> "$KERNEL_SRC/.config"
		echo "CONFIG_SMB_INSECURE_SERVER=y" >> "$KERNEL_SRC/.config"
	fi
}

ksmbd_module_make() {
	local -a cmd

	ensure_context
	echo "Running $MODULE_NAME make"

	cmd=(make)
	if [[ -n "$COMP_FLAGS" ]]; then
		local -a flag_args
		read -r -a flag_args <<< "$COMP_FLAGS"
		cmd+=("${flag_args[@]}")
	fi
	cmd+=(-C "$KERNEL_SRC" "M=$KERNEL_SRC/fs/$MODULE_DIR")

	rm -f "$MODULE_NAME.ko"
	(
		cd "$KERNEL_SRC"
		"${cmd[@]}"
	)
}

ksmbd_module_install() {
	local ver
	local module_path
	local module_dest

	ensure_context
	echo "Running $MODULE_NAME install"

	if lsmod | awk '{print $1}' | grep -qx "$MODULE_NAME"; then
		sudo rmmod "$MODULE_NAME" || err "unable to rmmod $MODULE_NAME"
	fi

	if ! is_module; then
		err "CONFIG_SMB_SERVER is not configured as module"
	fi

	module_path="$KERNEL_SRC/fs/$MODULE_DIR/$MODULE_NAME.ko"
	if [[ ! -f "$module_path" ]]; then
		err "$module_path was not found"
	fi

	module_dest="/lib/modules/$(uname -r)/kernel/fs/$MODULE_DIR/$MODULE_NAME.ko"
	if ls "${module_dest}"* >/dev/null 2>&1; then
		sudo rm -f "${module_dest}"*
		sudo install -m644 "$module_path" "$module_dest"
		ver=$(make -s -C "$KERNEL_SRC" kernelrelease)
		sudo depmod -A "$ver"
	else
		sudo make -C "$KERNEL_SRC" "M=$KERNEL_SRC/fs/$MODULE_DIR/" modules_install
		ver=$(make -s -C "$KERNEL_SRC" kernelrelease)
		sudo depmod -A "$ver"
	fi
}

ksmbd_module_clean() {
	ensure_context
	echo "Running $MODULE_NAME clean"
	(
		cd "$KERNEL_SRC"
		make -C "$KERNEL_SRC" "M=$KERNEL_SRC/fs/$MODULE_DIR/" clean
	)
}

main() {
	patch_fs_config

	case "${1:-make}" in
		clean)
			ksmbd_module_clean
			;;
		install)
			ksmbd_module_make
			ksmbd_module_install
			;;
		make)
			ksmbd_module_make
			;;
		help)
			echo "Usage: build_ksmbd.sh [clean | make | install]"
			;;
		*)
			ksmbd_module_make
			;;
	esac
}

main "$@"
