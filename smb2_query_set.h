/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *
 *   smb2_query_set.h - KUnit-testable function declarations for
 *   SMB2 QUERY_INFO / SET_INFO handlers (smb2pdu.c).
 */
#ifndef __KSMBD_SMB2_QUERY_SET_H__
#define __KSMBD_SMB2_QUERY_SET_H__

#include "smb2pdu.h"
#include "vfs_cache.h"

#if IS_ENABLED(CONFIG_KUNIT)

/* buffer_check_err - validate response buffer length */
int buffer_check_err(int reqOutputBufferLength,
		     struct smb2_query_info_rsp *rsp,
		     void *rsp_org,
		     int min_output_length);

/* Pipe info responses */
void get_standard_info_pipe(struct smb2_query_info_rsp *rsp,
			    void *rsp_org);
void get_internal_info_pipe(struct smb2_query_info_rsp *rsp, u64 num,
			    void *rsp_org);

/* File info query responses */
void get_file_access_info(struct smb2_query_info_rsp *rsp,
			  struct ksmbd_file *fp, void *rsp_org);
int get_file_basic_info(struct smb2_query_info_rsp *rsp,
			struct ksmbd_file *fp, void *rsp_org);
int get_file_standard_info(struct smb2_query_info_rsp *rsp,
			   struct ksmbd_file *fp, void *rsp_org);
void get_file_alignment_info(struct smb2_query_info_rsp *rsp,
			     void *rsp_org);
int get_file_internal_info(struct smb2_query_info_rsp *rsp,
			   struct ksmbd_file *fp, void *rsp_org);
void get_file_ea_info(struct smb2_query_info_rsp *rsp,
		      struct ksmbd_file *fp, void *rsp_org);
void get_file_position_info(struct smb2_query_info_rsp *rsp,
			    struct ksmbd_file *fp, void *rsp_org);
void get_file_mode_info(struct smb2_query_info_rsp *rsp,
			struct ksmbd_file *fp, void *rsp_org);
int get_file_compression_info(struct smb2_query_info_rsp *rsp,
			      struct ksmbd_file *fp, void *rsp_org);
int get_file_attribute_tag_info(struct smb2_query_info_rsp *rsp,
				struct ksmbd_file *fp, void *rsp_org);

/* File info set handlers */
int set_file_position_info(struct ksmbd_file *fp,
			   struct smb2_file_pos_info *file_info);
int set_file_mode_info(struct ksmbd_file *fp,
		       struct smb2_file_mode_info *file_info);

#endif /* CONFIG_KUNIT */
#endif /* __KSMBD_SMB2_QUERY_SET_H__ */
