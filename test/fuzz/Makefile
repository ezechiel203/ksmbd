# SPDX-License-Identifier: GPL-2.0-or-later
#
# Kernel-module fuzz harnesses for ksmbd (syzkaller-compatible)
# Build: make -C /lib/modules/$(uname -r)/build M=$(pwd)/../.. \
#        CONFIG_KSMBD_FUZZ_TEST=m modules
#
ccflags-y += -I$(src)/../..

obj-$(CONFIG_KSMBD_FUZZ_TEST) += \
	acl_builder_fuzz.o \
	asn1_fuzz.o \
	cancel_request_fuzz.o \
	close_request_fuzz.o \
	compound_request_fuzz.o \
	compression_fuzz.o \
	copychunk_fuzz.o \
	create_context_fuzz.o \
	dfs_referral_fuzz.o \
	durable_handle_fuzz.o \
	ea_parse_fuzz.o \
	encryption_fuzz.o \
	flush_request_fuzz.o \
	ioctl_fuzz.o \
	ipc_message_fuzz.o \
	kerberos_blob_fuzz.o \
	lease_break_fuzz.o \
	lock_request_fuzz.o \
	ndr_fuzz.o \
	negotiate_context_fuzz.o \
	notify_change_fuzz.o \
	ntlmssp_blob_fuzz.o \
	notify_fuzz.o \
	oplock_break_fuzz.o \
	path_parse_fuzz.o \
	query_set_info_fuzz.o \
	quic_packet_fuzz.o \
	quota_request_fuzz.o \
	rdma_negotiate_fuzz.o \
	read_request_fuzz.o \
	reparse_point_fuzz.o \
	rsvd_fuzz.o \
	security_descriptor_fuzz.o \
	session_setup_fuzz.o \
	signing_fuzz.o \
	smb2_query_dir_fuzz.o \
	smb2_set_info_fuzz.o \
	smb1_command_fuzz.o \
	smb2_create_fuzz.o \
	smb2_header_fuzz.o \
	smb2_lock_fuzz.o \
	smb2_read_fuzz.o \
	smb2_write_fuzz.o \
	transform_header_fuzz.o \
	tree_connect_fuzz.o \
	unicode_fuzz.o \
	wildcard_fuzz.o \
	write_request_fuzz.o
