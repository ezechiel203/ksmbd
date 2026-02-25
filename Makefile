# SPDX-License-Identifier: GPL-2.0-or-later
#
# Makefile for Linux SMB3 kernel server
#
ifneq ($(KERNELRELEASE),)
# For kernel build

# CONFIG_SMB_SERVER_SMBDIRECT is supported in the kernel above 4.12 version.
SMBDIRECT_SUPPORTED = $(shell [ $(VERSION) -gt 4 -o \( $(VERSION) -eq 4 -a \
		      $(PATCHLEVEL) -gt 12 \) ] && echo y)

KSMBD_SRC_ROOT := $(src)/src
KSMBD_INCLUDE_DIRS := \
	-I$(KSMBD_SRC_ROOT) \
	-I$(KSMBD_SRC_ROOT)/include/core \
	-I$(KSMBD_SRC_ROOT)/include/fs \
	-I$(KSMBD_SRC_ROOT)/include/protocol \
	-I$(KSMBD_SRC_ROOT)/include/transport \
	-I$(KSMBD_SRC_ROOT)/include/encoding \
	-I$(obj)/src/encoding

ccflags-y += $(KSMBD_INCLUDE_DIRS)

ifeq "$(CONFIG_SMB_SERVER_SMBDIRECT)" "y"
ifneq "$(SMBDIRECT_SUPPORTED)" "y"
$(error CONFIG_SMB_SERVER_SMBDIRECT is supported in the kernel above 4.12 version)
endif
endif

obj-$(CONFIG_SMB_SERVER) += ksmbd.o

ksmbd-y :=	src/encoding/unicode.o src/core/auth.o src/fs/vfs.o \
		src/fs/vfs_cache.o src/core/connection.o src/core/crypto_ctx.o \
		src/core/server.o src/core/misc.o src/fs/oplock.o \
		src/core/ksmbd_work.o src/fs/smbacl.o src/encoding/ndr.o \
		src/core/ksmbd_buffer.o src/core/smb2_compress.o \
		src/mgmt/ksmbd_ida.o src/mgmt/user_config.o \
		src/mgmt/share_config.o src/mgmt/tree_connect.o \
		src/mgmt/user_session.o src/mgmt/ksmbd_witness.o \
		src/protocol/common/smb_common.o \
		src/transport/transport_tcp.o src/transport/transport_ipc.o \
		src/core/ksmbd_debugfs.o src/core/ksmbd_config.o \
		src/core/ksmbd_feature.o

ksmbd-y +=	src/protocol/smb2/smb2_pdu_common.o \
		src/protocol/smb2/smb2_negotiate.o \
		src/protocol/smb2/smb2_session.o \
		src/protocol/smb2/smb2_tree.o \
		src/protocol/smb2/smb2_create.o \
		src/protocol/smb2/smb2_dir.o \
		src/protocol/smb2/smb2_query_set.o \
		src/protocol/smb2/smb2_read_write.o \
		src/protocol/smb2/smb2_lock.o \
		src/protocol/smb2/smb2_ioctl.o \
		src/protocol/smb2/smb2_notify.o \
		src/protocol/smb2/smb2_misc_cmds.o \
		src/protocol/smb2/smb2ops.o src/protocol/smb2/smb2misc.o \
		src/encoding/ksmbd_spnego_negtokeninit.asn1.o \
		src/encoding/ksmbd_spnego_negtokentarg.asn1.o \
		src/encoding/asn1.o src/core/compat.o \
		src/fs/ksmbd_fsctl.o src/fs/ksmbd_create_ctx.o \
		src/fs/ksmbd_info.o src/fs/ksmbd_dfs.o src/fs/ksmbd_vss.o \
		src/fs/ksmbd_notify.o src/fs/ksmbd_reparse.o \
		src/fs/ksmbd_resilient.o src/fs/ksmbd_quota.o \
		src/fs/ksmbd_app_instance.o src/fs/ksmbd_fsctl_extra.o \
		src/fs/ksmbd_rsvd.o \
		src/fs/ksmbd_branchcache.o \
		src/core/ksmbd_hooks.o

ifeq ($(CONFIG_KSMBD_FRUIT),y)
ccflags-y += -DCONFIG_KSMBD_FRUIT
ksmbd-y += src/protocol/smb2/smb2fruit.o
endif

$(obj)/src/encoding/asn1.o: $(obj)/src/encoding/ksmbd_spnego_negtokeninit.asn1.h \
	$(obj)/src/encoding/ksmbd_spnego_negtokentarg.asn1.h

$(obj)/src/encoding/ksmbd_spnego_negtokeninit.asn1.o: \
	$(obj)/src/encoding/ksmbd_spnego_negtokeninit.asn1.c \
	$(obj)/src/encoding/ksmbd_spnego_negtokeninit.asn1.h
$(obj)/src/encoding/ksmbd_spnego_negtokentarg.asn1.o: \
	$(obj)/src/encoding/ksmbd_spnego_negtokentarg.asn1.c \
	$(obj)/src/encoding/ksmbd_spnego_negtokentarg.asn1.h

ksmbd-$(CONFIG_SMB_INSECURE_SERVER) += src/protocol/smb1/smb1pdu.o \
		src/protocol/smb1/smb1ops.o src/protocol/smb1/smb1misc.o \
		src/protocol/common/netmisc.o
ksmbd-$(CONFIG_SMB_SERVER_SMBDIRECT) += src/transport/transport_rdma.o

# SMB over QUIC transport (userspace proxy bridge).
# Set CONFIG_SMB_SERVER_QUIC=y to enable, =n or unset to disable.
CONFIG_SMB_SERVER_QUIC ?= n

ifeq ($(CONFIG_SMB_SERVER_QUIC),y)
ccflags-y += -DCONFIG_SMB_SERVER_QUIC
ksmbd-y += src/transport/transport_quic.o
endif
else
# For external module build
KDIR ?= /lib/modules/$(shell uname -r)/build
MDIR ?= /lib/modules/$(shell uname -r)
PWD := $(shell pwd)
MODULE_NAME := ksmbd
MODULE_DEST_DIR := $(MDIR)/kernel/fs/$(MODULE_NAME)
MODULE_DEST := $(MODULE_DEST_DIR)/$(MODULE_NAME).ko
PKGVER ?= $(shell git rev-parse --short HEAD 2>/dev/null || date +%Y%m%d%H%M%S)
PKGVER_RE ?= ^[A-Za-z0-9._-]+$$
REMOTE_TMP ?= /tmp/$(MODULE_NAME).ko
REMOTE_HOST ?=
X86_64_HOST ?=
ARM64_HOST ?=
PPC64_HOST ?=
X86_64_REMOTE_TMP ?=
ARM64_REMOTE_TMP ?=
PPC64_REMOTE_TMP ?=
UNAME_M := $(shell uname -m)
# Normalize uname -m to the kernel ARCH value used by kbuild.
ifeq ($(UNAME_M),x86_64)
LOCAL_ARCH := x86_64
else ifeq ($(UNAME_M),aarch64)
LOCAL_ARCH := arm64
else ifeq ($(UNAME_M),arm64)
LOCAL_ARCH := arm64
else ifneq ($(filter ppc64 ppc64le powerpc64 powerpc64le,$(UNAME_M)),)
LOCAL_ARCH := powerpc
else
LOCAL_ARCH := $(UNAME_M)
endif
ARCH ?= $(LOCAL_ARCH)

export CONFIG_SMB_SERVER := m

check-pkgver:
	@if ! printf '%s\n' "$(PKGVER)" | grep -Eq '$(PKGVER_RE)'; then \
		echo "ERROR: PKGVER contains unsupported characters: $(PKGVER)"; \
		echo "Allowed pattern: $(PKGVER_RE)"; \
		exit 1; \
	fi

check-kdir:
	@if [ ! -d "$(KDIR)" ]; then \
		echo "ERROR: kernel build directory not found: $(KDIR)"; \
		echo "Install matching kernel headers first (e.g. linux-headers-$$(uname -r))."; \
		exit 1; \
	fi

all: check-kdir
	$(MAKE) -C $(KDIR) M=$(PWD) ARCH=$(ARCH) modules

clean:
	@if [ -d "$(KDIR)" ]; then \
		$(MAKE) -C $(KDIR) M=$(PWD) ARCH=$(ARCH) clean; \
	fi
	rm -rf .tmp_versions

install: all
	@if [ ! -f "$(PWD)/ksmbd.ko" ]; then \
		echo "ERROR: ksmbd.ko was not generated by the build."; \
		exit 1; \
	fi
	rm -f "$(MODULE_DEST)"
	install -m644 -b -D "$(PWD)/ksmbd.ko" "$(MODULE_DEST)"
	depmod -a

deploy: install
	@if lsmod | awk '{print $$1}' | grep -qx "$(MODULE_NAME)"; then \
		modprobe -r "$(MODULE_NAME)"; \
	fi
	modprobe "$(MODULE_NAME)"

remote-deploy-x86_64:
	$(MAKE) -f Makefile.x86_64 deploy \
		X86_64_HOST="$(or $(X86_64_HOST),$(REMOTE_HOST))" \
		X86_64_REMOTE_TMP="$(or $(X86_64_REMOTE_TMP),$(REMOTE_TMP))"

remote-deploy-arm64:
	$(MAKE) -f Makefile.arm64 deploy \
		ARM64_HOST="$(or $(ARM64_HOST),$(REMOTE_HOST))" \
		ARM64_REMOTE_TMP="$(or $(ARM64_REMOTE_TMP),$(REMOTE_TMP))"

remote-deploy-ppc64:
	$(MAKE) -f Makefile.ppc64 deploy \
		PPC64_HOST="$(or $(PPC64_HOST),$(REMOTE_HOST))" \
		PPC64_REMOTE_TMP="$(or $(PPC64_REMOTE_TMP),$(REMOTE_TMP))"

undeploy:
	@if lsmod | awk '{print $$1}' | grep -qx "$(MODULE_NAME)"; then \
		modprobe -r "$(MODULE_NAME)"; \
	else \
		echo "$(MODULE_NAME) is not loaded."; \
	fi

dkms-install: check-pkgver
	sudo rm -rf "/usr/src/ksmbd-$(PKGVER)"
	sudo cp -r "$(PWD)" "/usr/src/ksmbd-$(PKGVER)"
	sudo sed -e "s/@VERSION@/$(PKGVER)/" -i "/usr/src/ksmbd-$(PKGVER)/dkms.conf"
	sudo dkms add -m ksmbd -v "$(PKGVER)" 2>/dev/null || true
	sudo dkms build -m ksmbd -v "$(PKGVER)"
	sudo dkms install -m ksmbd -v "$(PKGVER)" --force

dkms-uninstall: check-pkgver
	sudo modprobe -r "$(MODULE_NAME)" 2>/dev/null || true
	sudo dkms remove -m ksmbd -v "$(PKGVER)" --all 2>/dev/null || true
	sudo rm -rf "/usr/src/ksmbd-$(PKGVER)"

uninstall:
	rm -rf "$(MODULE_DEST_DIR)"
	depmod -a

help:
	@echo "KSMBD module build/deploy targets"
	@echo ""
	@echo "  all            Build ksmbd.ko against running kernel headers"
	@echo "  clean          Remove module build artifacts"
	@echo "  install        Build and install module into /lib/modules"
	@echo "  deploy         Install, then reload ksmbd with modprobe"
	@echo "  remote-deploy-x86_64 Build and deploy to remote x86_64 host"
	@echo "  remote-deploy-arm64  Build and deploy to remote ARM64 host"
	@echo "  remote-deploy-ppc64  Build and deploy to remote PowerPC64 host"
	@echo "  undeploy       Unload ksmbd if currently loaded"
	@echo "  uninstall      Remove installed module and refresh module deps"
	@echo "  dkms-install   Register/build/install module via DKMS"
	@echo "  dkms-uninstall Remove DKMS module version"
	@echo ""
	@echo "Variables:"
	@echo "  KDIR=<kernel build dir> (default: /lib/modules/\$$(uname -r)/build)"
	@echo "  MDIR=<module dir root>  (default: /lib/modules/\$$(uname -r))"
	@echo "  ARCH=<kbuild arch>      (default: auto-detected from uname -m: $(LOCAL_ARCH))"
	@echo "  PKGVER=<dkms version>   (default: git short SHA or timestamp)"
	@echo "  REMOTE_HOST=<user@host> (generic fallback for remote deploy targets)"
	@echo "  REMOTE_TMP=<remote path> (default: /tmp/ksmbd.ko)"
	@echo "  X86_64_HOST / ARM64_HOST / PPC64_HOST for arch-specific targets"
endif

.PHONY: check-kdir check-pkgver all clean install deploy remote-deploy-x86_64 remote-deploy-arm64 remote-deploy-ppc64 undeploy dkms-install dkms-uninstall uninstall help
