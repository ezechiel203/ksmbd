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
ifneq "$(call SMBDIRECT_SUPPORTED)" "y"
$(error CONFIG_SMB_SERVER_SMBDIRECT is supported in the kernel above 4.12 version)
endif
endif

obj-$(CONFIG_SMB_SERVER) += ksmbd.o

ksmbd-y :=	src/encoding/unicode.o src/core/auth.o src/fs/vfs.o \
		src/fs/vfs_cache.o src/core/connection.o src/core/crypto_ctx.o \
		src/core/server.o src/core/misc.o src/fs/oplock.o \
		src/core/ksmbd_work.o src/fs/smbacl.o src/encoding/ndr.o \
		src/core/ksmbd_buffer.o \
		src/mgmt/ksmbd_ida.o src/mgmt/user_config.o \
		src/mgmt/share_config.o src/mgmt/tree_connect.o \
		src/mgmt/user_session.o src/protocol/common/smb_common.o \
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
else
# For external module build
EXTRA_FLAGS += -I$(PWD)/src \
	-I$(PWD)/src/include/core \
	-I$(PWD)/src/include/fs \
	-I$(PWD)/src/include/protocol \
	-I$(PWD)/src/include/transport \
	-I$(PWD)/src/include/encoding
KDIR	?= /lib/modules/$(shell uname -r)/build
MDIR	?= /lib/modules/$(shell uname -r)
PWD	:= $(shell pwd)

export CONFIG_SMB_SERVER := m

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

install: ksmbd.ko
	rm -f ${MDIR}/kernel/fs/ksmbd/ksmbd.ko
	install -m644 -b -D ksmbd.ko ${MDIR}/kernel/fs/ksmbd/ksmbd.ko
	depmod -a

# install dkms
PKGVER=$(shell echo `git rev-parse --short HEAD`)
dkms-install:
	sudo rm -rf "/usr/src/ksmbd*"
	sudo cp -r "$(PWD)" "/usr/src/ksmbd-$(PKGVER)"
	sudo sed -e "s/@VERSION@/$(PKGVER)/" -i "/usr/src/ksmbd-$(PKGVER)/dkms.conf"
	sudo dkms install -m ksmbd/$(PKGVER) --force

dkms-uninstall:
	sudo modprobe -r ksmbd
	sudo dkms remove ksmbd/$(PKGVER)
	sudo rm -rf "/usr/src/ksmbd-$(PKGVER)"

uninstall:
	rm -rf ${MDIR}/kernel/fs/ksmbd
	depmod -a
endif

.PHONY : all clean install uninstall
