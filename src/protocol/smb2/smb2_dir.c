// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   smb2_dir.c - SMB2_QUERY_DIRECTORY handler
 */

// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 */

#include <linux/inetdevice.h>
#include <net/addrconf.h>
#include <linux/syscalls.h>
#include <linux/namei.h>
#include <linux/statfs.h>
#include <linux/ethtool.h>
#include <linux/falloc.h>
#include <linux/crc32.h>
#include <linux/mount.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
#include <linux/filelock.h>
#endif

#include <crypto/algapi.h>

#include "compat.h"
#include "glob.h"
#include "smb2pdu.h"
#include "smbfsctl.h"
#include "oplock.h"
#include "smbacl.h"

#include "auth.h"
#include "asn1.h"
#include "connection.h"
#include "transport_ipc.h"
#include "transport_rdma.h"
#include "vfs.h"
#include "vfs_cache.h"
#include "misc.h"

#include "server.h"
#include "smb_common.h"
#include "smbstatus.h"
#include "ksmbd_work.h"
#include "mgmt/user_config.h"
#include "mgmt/share_config.h"
#include "mgmt/tree_connect.h"
#include "mgmt/user_session.h"
#include "mgmt/ksmbd_ida.h"
#include "ndr.h"
#include "transport_tcp.h"
#include "smb2fruit.h"
#include "ksmbd_fsctl.h"
#include "ksmbd_create_ctx.h"
#include "ksmbd_vss.h"
#include "ksmbd_notify.h"
#include "ksmbd_info.h"
#include "ksmbd_buffer.h"
#include "smb2pdu_internal.h"

static int readdir_info_level_struct_sz(int info_level)
{
	switch (info_level) {
	case FILE_FULL_DIRECTORY_INFORMATION:
		return sizeof(struct file_full_directory_info);
	case FILE_BOTH_DIRECTORY_INFORMATION:
		return sizeof(struct file_both_directory_info);
	case FILE_DIRECTORY_INFORMATION:
		return sizeof(struct file_directory_info);
	case FILE_NAMES_INFORMATION:
		return sizeof(struct file_names_info);
	case FILEID_FULL_DIRECTORY_INFORMATION:
		return sizeof(struct file_id_full_dir_info);
	case FILEID_BOTH_DIRECTORY_INFORMATION:
		return sizeof(struct file_id_both_directory_info);
	case FILEID_GLOBAL_TX_DIRECTORY_INFORMATION:
		return sizeof(struct file_id_both_directory_info);
	case FILEID_EXTD_DIRECTORY_INFORMATION:
		return sizeof(struct file_id_extd_dir_info);
	case FILEID_EXTD_BOTH_DIRECTORY_INFORMATION:
		return sizeof(struct file_id_extd_both_dir_info);
	case FILEID_64_EXTD_DIRECTORY_INFORMATION:
		return sizeof(struct file_id_64_extd_dir_info);
	case FILEID_64_EXTD_BOTH_DIRECTORY_INFORMATION:
		return sizeof(struct file_id_64_extd_both_dir_info);
	case FILEID_ALL_EXTD_DIRECTORY_INFORMATION:
		return sizeof(struct file_id_all_extd_dir_info);
	case FILEID_ALL_EXTD_BOTH_DIRECTORY_INFORMATION:
		return sizeof(struct file_id_all_extd_both_dir_info);
	case SMB_FIND_FILE_POSIX_INFO:
		return sizeof(struct smb2_posix_info);
	default:
		return -EOPNOTSUPP;
	}
}

static int dentry_name(struct ksmbd_dir_info *d_info, int info_level)
{
	switch (info_level) {
	case FILE_FULL_DIRECTORY_INFORMATION:
	{
		struct file_full_directory_info *ffdinfo;

		ffdinfo = (struct file_full_directory_info *)d_info->rptr;
		d_info->rptr += le32_to_cpu(ffdinfo->NextEntryOffset);
		d_info->name = ffdinfo->FileName;
		d_info->name_len = le32_to_cpu(ffdinfo->FileNameLength);
		return 0;
	}
	case FILE_BOTH_DIRECTORY_INFORMATION:
	{
		struct file_both_directory_info *fbdinfo;

		fbdinfo = (struct file_both_directory_info *)d_info->rptr;
		d_info->rptr += le32_to_cpu(fbdinfo->NextEntryOffset);
		d_info->name = fbdinfo->FileName;
		d_info->name_len = le32_to_cpu(fbdinfo->FileNameLength);
		return 0;
	}
	case FILE_DIRECTORY_INFORMATION:
	{
		struct file_directory_info *fdinfo;

		fdinfo = (struct file_directory_info *)d_info->rptr;
		d_info->rptr += le32_to_cpu(fdinfo->NextEntryOffset);
		d_info->name = fdinfo->FileName;
		d_info->name_len = le32_to_cpu(fdinfo->FileNameLength);
		return 0;
	}
	case FILE_NAMES_INFORMATION:
	{
		struct file_names_info *fninfo;

		fninfo = (struct file_names_info *)d_info->rptr;
		d_info->rptr += le32_to_cpu(fninfo->NextEntryOffset);
		d_info->name = fninfo->FileName;
		d_info->name_len = le32_to_cpu(fninfo->FileNameLength);
		return 0;
	}
	case FILEID_FULL_DIRECTORY_INFORMATION:
	{
		struct file_id_full_dir_info *dinfo;

		dinfo = (struct file_id_full_dir_info *)d_info->rptr;
		d_info->rptr += le32_to_cpu(dinfo->NextEntryOffset);
		d_info->name = dinfo->FileName;
		d_info->name_len = le32_to_cpu(dinfo->FileNameLength);
		return 0;
	}
	case FILEID_BOTH_DIRECTORY_INFORMATION:
	{
		struct file_id_both_directory_info *fibdinfo;

		fibdinfo = (struct file_id_both_directory_info *)d_info->rptr;
		d_info->rptr += le32_to_cpu(fibdinfo->NextEntryOffset);
		d_info->name = fibdinfo->FileName;
		d_info->name_len = le32_to_cpu(fibdinfo->FileNameLength);
		return 0;
	}
	case FILEID_GLOBAL_TX_DIRECTORY_INFORMATION:
	{
		struct file_id_both_directory_info *fibdinfo;

		fibdinfo = (struct file_id_both_directory_info *)d_info->rptr;
		d_info->rptr += le32_to_cpu(fibdinfo->NextEntryOffset);
		d_info->name = fibdinfo->FileName;
		d_info->name_len = le32_to_cpu(fibdinfo->FileNameLength);
		return 0;
	}
	case FILEID_EXTD_DIRECTORY_INFORMATION:
	{
		struct file_id_extd_dir_info *extdinfo;

		extdinfo = (struct file_id_extd_dir_info *)d_info->rptr;
		d_info->rptr += le32_to_cpu(extdinfo->NextEntryOffset);
		d_info->name = extdinfo->FileName;
		d_info->name_len = le32_to_cpu(extdinfo->FileNameLength);
		return 0;
	}
	case FILEID_EXTD_BOTH_DIRECTORY_INFORMATION:
	{
		struct file_id_extd_both_dir_info *extdbinfo;

		extdbinfo = (struct file_id_extd_both_dir_info *)d_info->rptr;
		d_info->rptr += le32_to_cpu(extdbinfo->NextEntryOffset);
		d_info->name = extdbinfo->FileName;
		d_info->name_len = le32_to_cpu(extdbinfo->FileNameLength);
		return 0;
	}
	case FILEID_64_EXTD_DIRECTORY_INFORMATION:
	{
		struct file_id_64_extd_dir_info *extd64info;

		extd64info = (struct file_id_64_extd_dir_info *)d_info->rptr;
		d_info->rptr += le32_to_cpu(extd64info->NextEntryOffset);
		d_info->name = extd64info->FileName;
		d_info->name_len = le32_to_cpu(extd64info->FileNameLength);
		return 0;
	}
	case FILEID_64_EXTD_BOTH_DIRECTORY_INFORMATION:
	{
		struct file_id_64_extd_both_dir_info *extd64binfo;

		extd64binfo = (struct file_id_64_extd_both_dir_info *)d_info->rptr;
		d_info->rptr += le32_to_cpu(extd64binfo->NextEntryOffset);
		d_info->name = extd64binfo->FileName;
		d_info->name_len = le32_to_cpu(extd64binfo->FileNameLength);
		return 0;
	}
	case FILEID_ALL_EXTD_DIRECTORY_INFORMATION:
	{
		struct file_id_all_extd_dir_info *allexdinfo;

		allexdinfo = (struct file_id_all_extd_dir_info *)d_info->rptr;
		d_info->rptr += le32_to_cpu(allexdinfo->NextEntryOffset);
		d_info->name = allexdinfo->FileName;
		d_info->name_len = le32_to_cpu(allexdinfo->FileNameLength);
		return 0;
	}
	case FILEID_ALL_EXTD_BOTH_DIRECTORY_INFORMATION:
	{
		struct file_id_all_extd_both_dir_info *allexdbinfo;

		allexdbinfo = (struct file_id_all_extd_both_dir_info *)d_info->rptr;
		d_info->rptr += le32_to_cpu(allexdbinfo->NextEntryOffset);
		d_info->name = allexdbinfo->FileName;
		d_info->name_len = le32_to_cpu(allexdbinfo->FileNameLength);
		return 0;
	}
	case SMB_FIND_FILE_POSIX_INFO:
	{
		struct smb2_posix_info *posix_info;

		posix_info = (struct smb2_posix_info *)d_info->rptr;
		d_info->rptr += le32_to_cpu(posix_info->NextEntryOffset);
		d_info->name = posix_info->name;
		d_info->name_len = le32_to_cpu(posix_info->name_len);
		return 0;
	}
	default:
		return -EINVAL;
	}
}

/**
 * smb2_populate_readdir_entry() - encode directory entry in smb2 response
 * buffer
 * @conn:	connection instance
 * @info_level:	smb information level
 * @d_info:	structure included variables for query dir
 * @ksmbd_kstat:	ksmbd wrapper of dirent stat information
 *
 * if directory has many entries, find first can't read it fully.
 * find next might be called multiple times to read remaining dir entries
 *
 * Return:	0 on success, otherwise error
 */
static int smb2_populate_readdir_entry(struct ksmbd_conn *conn, int info_level,
				       struct ksmbd_dir_info *d_info,
				       struct ksmbd_kstat *ksmbd_kstat)
{
	int next_entry_offset = 0;
	char *conv_name;
	int conv_len;
	void *kstat;
	int struct_sz, rc = 0;

	conv_name = ksmbd_convert_dir_info_name(d_info,
						conn->local_nls,
						&conv_len);
	if (!conv_name)
		return -ENOMEM;

	/* Somehow the name has only terminating NULL bytes */
	if (conv_len < 0) {
		rc = -EINVAL;
		goto free_conv_name;
	}

	struct_sz = readdir_info_level_struct_sz(info_level) + conv_len;
	next_entry_offset = ALIGN(struct_sz, KSMBD_DIR_INFO_ALIGNMENT);
	d_info->last_entry_off_align = next_entry_offset - struct_sz;

	if (next_entry_offset > d_info->out_buf_len) {
		d_info->out_buf_len = 0;
		rc = -ENOSPC;
		goto free_conv_name;
	}

	kstat = d_info->wptr;
	if (info_level != FILE_NAMES_INFORMATION)
		kstat = ksmbd_vfs_init_kstat(&d_info->wptr, ksmbd_kstat);

	switch (info_level) {
	case FILE_FULL_DIRECTORY_INFORMATION:
	{
		struct file_full_directory_info *ffdinfo;

		ffdinfo = (struct file_full_directory_info *)kstat;
		ffdinfo->FileNameLength = cpu_to_le32(conv_len);
		ffdinfo->EaSize =
			smb2_get_reparse_tag_special_file(ksmbd_kstat->kstat->mode);
		if (ffdinfo->EaSize)
			ffdinfo->ExtFileAttributes = ATTR_REPARSE_POINT_LE;
		if (d_info->hide_dot_file && d_info->name[0] == '.')
			ffdinfo->ExtFileAttributes |= ATTR_HIDDEN_LE;
		memcpy(ffdinfo->FileName, conv_name, conv_len);
		ffdinfo->NextEntryOffset = cpu_to_le32(next_entry_offset);
		break;
	}
	case FILE_BOTH_DIRECTORY_INFORMATION:
	{
		struct file_both_directory_info *fbdinfo;

		fbdinfo = (struct file_both_directory_info *)kstat;
		fbdinfo->FileNameLength = cpu_to_le32(conv_len);
		fbdinfo->EaSize =
			smb2_get_reparse_tag_special_file(ksmbd_kstat->kstat->mode);
		if (fbdinfo->EaSize)
			fbdinfo->ExtFileAttributes = ATTR_REPARSE_POINT_LE;
		fbdinfo->ShortNameLength = 0;
		fbdinfo->Reserved = 0;
		if (d_info->hide_dot_file && d_info->name[0] == '.')
			fbdinfo->ExtFileAttributes |= ATTR_HIDDEN_LE;
		memcpy(fbdinfo->FileName, conv_name, conv_len);
		fbdinfo->NextEntryOffset = cpu_to_le32(next_entry_offset);
		break;
	}
	case FILE_DIRECTORY_INFORMATION:
	{
		struct file_directory_info *fdinfo;

		fdinfo = (struct file_directory_info *)kstat;
		fdinfo->FileNameLength = cpu_to_le32(conv_len);
		if (d_info->hide_dot_file && d_info->name[0] == '.')
			fdinfo->ExtFileAttributes |= ATTR_HIDDEN_LE;
		memcpy(fdinfo->FileName, conv_name, conv_len);
		fdinfo->NextEntryOffset = cpu_to_le32(next_entry_offset);
		break;
	}
	case FILE_NAMES_INFORMATION:
	{
		struct file_names_info *fninfo;

		fninfo = (struct file_names_info *)kstat;
		fninfo->FileNameLength = cpu_to_le32(conv_len);
		memcpy(fninfo->FileName, conv_name, conv_len);
		fninfo->NextEntryOffset = cpu_to_le32(next_entry_offset);
		break;
	}
	case FILEID_FULL_DIRECTORY_INFORMATION:
	{
		struct file_id_full_dir_info *dinfo;

		dinfo = (struct file_id_full_dir_info *)kstat;
		dinfo->FileNameLength = cpu_to_le32(conv_len);
		dinfo->EaSize =
			smb2_get_reparse_tag_special_file(ksmbd_kstat->kstat->mode);
		if (dinfo->EaSize)
			dinfo->ExtFileAttributes = ATTR_REPARSE_POINT_LE;
#ifdef CONFIG_KSMBD_FRUIT
		if (conn->is_fruit)
			smb2_read_dir_attr_fill(conn,
						ksmbd_kstat->kstat_dentry,
						ksmbd_kstat->kstat,
						ksmbd_kstat->share,
						&dinfo->EaSize);
#endif
		dinfo->Reserved = 0;
#ifdef CONFIG_KSMBD_FRUIT
		if (conn->is_fruit &&
		    (server_conf.flags & KSMBD_GLOBAL_FLAG_FRUIT_ZERO_FILEID) &&
		    d_info->name[0] == '.')
			dinfo->UniqueId = 0;
		else
#endif
			dinfo->UniqueId = cpu_to_le64(ksmbd_kstat->kstat->ino);
		if (d_info->hide_dot_file && d_info->name[0] == '.')
			dinfo->ExtFileAttributes |= ATTR_HIDDEN_LE;
		memcpy(dinfo->FileName, conv_name, conv_len);
		dinfo->NextEntryOffset = cpu_to_le32(next_entry_offset);
		break;
	}
	case FILEID_BOTH_DIRECTORY_INFORMATION:
	case FILEID_GLOBAL_TX_DIRECTORY_INFORMATION:
	{
		struct file_id_both_directory_info *fibdinfo;

		fibdinfo = (struct file_id_both_directory_info *)kstat;
		fibdinfo->FileNameLength = cpu_to_le32(conv_len);
		fibdinfo->EaSize =
			smb2_get_reparse_tag_special_file(ksmbd_kstat->kstat->mode);
		if (fibdinfo->EaSize)
			fibdinfo->ExtFileAttributes = ATTR_REPARSE_POINT_LE;
#ifdef CONFIG_KSMBD_FRUIT
		if (conn->is_fruit)
			smb2_read_dir_attr_fill(conn,
						ksmbd_kstat->kstat_dentry,
						ksmbd_kstat->kstat,
						ksmbd_kstat->share,
						&fibdinfo->EaSize);
		if (conn->is_fruit &&
		    (server_conf.flags & KSMBD_GLOBAL_FLAG_FRUIT_ZERO_FILEID) &&
		    d_info->name[0] == '.')
			fibdinfo->UniqueId = 0;
		else
#endif
			fibdinfo->UniqueId = cpu_to_le64(ksmbd_kstat->kstat->ino);
		fibdinfo->ShortNameLength = 0;
		fibdinfo->Reserved = 0;
		fibdinfo->Reserved2 = cpu_to_le16(0);
		if (d_info->hide_dot_file && d_info->name[0] == '.')
			fibdinfo->ExtFileAttributes |= ATTR_HIDDEN_LE;
		memcpy(fibdinfo->FileName, conv_name, conv_len);
		fibdinfo->NextEntryOffset = cpu_to_le32(next_entry_offset);
		break;
	}
	case FILEID_EXTD_DIRECTORY_INFORMATION:
	{
		struct file_id_extd_dir_info *extdinfo;
		__le32 reparse_tag;
		__le64 ino = cpu_to_le64(ksmbd_kstat->kstat->ino);

		extdinfo = (struct file_id_extd_dir_info *)kstat;
		extdinfo->FileNameLength = cpu_to_le32(conv_len);
		reparse_tag =
			smb2_get_reparse_tag_special_file(ksmbd_kstat->kstat->mode);
		extdinfo->EaSize = reparse_tag;
		extdinfo->ReparsePointTag = reparse_tag;
		if (reparse_tag)
			extdinfo->ExtFileAttributes = ATTR_REPARSE_POINT_LE;
		memcpy(&extdinfo->FileId[0], &ino, sizeof(ino));
		memset(&extdinfo->FileId[8], 0, 8);
		if (d_info->hide_dot_file && d_info->name[0] == '.')
			extdinfo->ExtFileAttributes |= ATTR_HIDDEN_LE;
		memcpy(extdinfo->FileName, conv_name, conv_len);
		extdinfo->NextEntryOffset = cpu_to_le32(next_entry_offset);
		break;
	}
	case FILEID_EXTD_BOTH_DIRECTORY_INFORMATION:
	{
		struct file_id_extd_both_dir_info *extdbinfo;
		__le32 reparse_tag;
		__le64 ino = cpu_to_le64(ksmbd_kstat->kstat->ino);

		extdbinfo = (struct file_id_extd_both_dir_info *)kstat;
		extdbinfo->FileNameLength = cpu_to_le32(conv_len);
		reparse_tag =
			smb2_get_reparse_tag_special_file(ksmbd_kstat->kstat->mode);
		extdbinfo->EaSize = reparse_tag;
		extdbinfo->ReparsePointTag = reparse_tag;
		if (reparse_tag)
			extdbinfo->ExtFileAttributes = ATTR_REPARSE_POINT_LE;
		memcpy(&extdbinfo->FileId[0], &ino, sizeof(ino));
		memset(&extdbinfo->FileId[8], 0, 8);
		extdbinfo->ShortNameLength = 0;
		extdbinfo->Reserved = 0;
		if (d_info->hide_dot_file && d_info->name[0] == '.')
			extdbinfo->ExtFileAttributes |= ATTR_HIDDEN_LE;
		memcpy(extdbinfo->FileName, conv_name, conv_len);
		extdbinfo->NextEntryOffset = cpu_to_le32(next_entry_offset);
		break;
	}
	case FILEID_64_EXTD_DIRECTORY_INFORMATION:
	{
		struct file_id_64_extd_dir_info *extd64info;
		__le32 reparse_tag;

		extd64info = (struct file_id_64_extd_dir_info *)kstat;
		extd64info->FileNameLength = cpu_to_le32(conv_len);
		reparse_tag =
			smb2_get_reparse_tag_special_file(ksmbd_kstat->kstat->mode);
		extd64info->EaSize = reparse_tag;
		extd64info->ReparsePointTag = reparse_tag;
		if (reparse_tag)
			extd64info->ExtFileAttributes = ATTR_REPARSE_POINT_LE;
		extd64info->FileId = cpu_to_le64(ksmbd_kstat->kstat->ino);
		if (d_info->hide_dot_file && d_info->name[0] == '.')
			extd64info->ExtFileAttributes |= ATTR_HIDDEN_LE;
		memcpy(extd64info->FileName, conv_name, conv_len);
		extd64info->NextEntryOffset = cpu_to_le32(next_entry_offset);
		break;
	}
	case FILEID_64_EXTD_BOTH_DIRECTORY_INFORMATION:
	{
		struct file_id_64_extd_both_dir_info *extd64binfo;
		__le32 reparse_tag;

		extd64binfo = (struct file_id_64_extd_both_dir_info *)kstat;
		extd64binfo->FileNameLength = cpu_to_le32(conv_len);
		reparse_tag =
			smb2_get_reparse_tag_special_file(ksmbd_kstat->kstat->mode);
		extd64binfo->EaSize = reparse_tag;
		extd64binfo->ReparsePointTag = reparse_tag;
		if (reparse_tag)
			extd64binfo->ExtFileAttributes = ATTR_REPARSE_POINT_LE;
		extd64binfo->FileId = cpu_to_le64(ksmbd_kstat->kstat->ino);
		extd64binfo->ShortNameLength = 0;
		extd64binfo->Reserved = 0;
		if (d_info->hide_dot_file && d_info->name[0] == '.')
			extd64binfo->ExtFileAttributes |= ATTR_HIDDEN_LE;
		memcpy(extd64binfo->FileName, conv_name, conv_len);
		extd64binfo->NextEntryOffset = cpu_to_le32(next_entry_offset);
		break;
	}
	case FILEID_ALL_EXTD_DIRECTORY_INFORMATION:
	{
		struct file_id_all_extd_dir_info *allexdinfo;
		__le32 reparse_tag;
		__le64 ino = cpu_to_le64(ksmbd_kstat->kstat->ino);

		allexdinfo = (struct file_id_all_extd_dir_info *)kstat;
		allexdinfo->FileNameLength = cpu_to_le32(conv_len);
		reparse_tag =
			smb2_get_reparse_tag_special_file(ksmbd_kstat->kstat->mode);
		allexdinfo->EaSize = reparse_tag;
		allexdinfo->ReparsePointTag = reparse_tag;
		if (reparse_tag)
			allexdinfo->ExtFileAttributes = ATTR_REPARSE_POINT_LE;
		allexdinfo->FileId = ino;
		memcpy(&allexdinfo->FileId128[0], &ino, sizeof(ino));
		memset(&allexdinfo->FileId128[8], 0, 8);
		if (d_info->hide_dot_file && d_info->name[0] == '.')
			allexdinfo->ExtFileAttributes |= ATTR_HIDDEN_LE;
		memcpy(allexdinfo->FileName, conv_name, conv_len);
		allexdinfo->NextEntryOffset = cpu_to_le32(next_entry_offset);
		break;
	}
	case FILEID_ALL_EXTD_BOTH_DIRECTORY_INFORMATION:
	{
		struct file_id_all_extd_both_dir_info *allexdbinfo;
		__le32 reparse_tag;
		__le64 ino = cpu_to_le64(ksmbd_kstat->kstat->ino);

		allexdbinfo = (struct file_id_all_extd_both_dir_info *)kstat;
		allexdbinfo->FileNameLength = cpu_to_le32(conv_len);
		reparse_tag =
			smb2_get_reparse_tag_special_file(ksmbd_kstat->kstat->mode);
		allexdbinfo->EaSize = reparse_tag;
		allexdbinfo->ReparsePointTag = reparse_tag;
		if (reparse_tag)
			allexdbinfo->ExtFileAttributes = ATTR_REPARSE_POINT_LE;
		allexdbinfo->FileId = ino;
		memcpy(&allexdbinfo->FileId128[0], &ino, sizeof(ino));
		memset(&allexdbinfo->FileId128[8], 0, 8);
		allexdbinfo->ShortNameLength = 0;
		allexdbinfo->Reserved = 0;
		if (d_info->hide_dot_file && d_info->name[0] == '.')
			allexdbinfo->ExtFileAttributes |= ATTR_HIDDEN_LE;
		memcpy(allexdbinfo->FileName, conv_name, conv_len);
		allexdbinfo->NextEntryOffset = cpu_to_le32(next_entry_offset);
		break;
	}
	case SMB_FIND_FILE_POSIX_INFO:
	{
		struct smb2_posix_info *posix_info;
		u64 time;

		posix_info = (struct smb2_posix_info *)kstat;
		posix_info->Ignored = 0;
		posix_info->CreationTime = cpu_to_le64(ksmbd_kstat->create_time);
		time = ksmbd_UnixTimeToNT(ksmbd_kstat->kstat->ctime);
		posix_info->ChangeTime = cpu_to_le64(time);
		time = ksmbd_UnixTimeToNT(ksmbd_kstat->kstat->atime);
		posix_info->LastAccessTime = cpu_to_le64(time);
		time = ksmbd_UnixTimeToNT(ksmbd_kstat->kstat->mtime);
		posix_info->LastWriteTime = cpu_to_le64(time);
		posix_info->EndOfFile = cpu_to_le64(ksmbd_kstat->kstat->size);
		posix_info->AllocationSize = cpu_to_le64(ksmbd_kstat->kstat->blocks << 9);
		posix_info->DeviceId = cpu_to_le32(ksmbd_kstat->kstat->rdev);
		posix_info->HardLinks = cpu_to_le32(ksmbd_kstat->kstat->nlink);
		posix_info->Mode = cpu_to_le32(ksmbd_kstat->kstat->mode & 0777);
		switch (ksmbd_kstat->kstat->mode & S_IFMT) {
		case S_IFDIR:
			posix_info->Mode |= cpu_to_le32(POSIX_TYPE_DIR << POSIX_FILETYPE_SHIFT);
			break;
		case S_IFLNK:
			posix_info->Mode |= cpu_to_le32(POSIX_TYPE_SYMLINK << POSIX_FILETYPE_SHIFT);
			break;
		case S_IFCHR:
			posix_info->Mode |= cpu_to_le32(POSIX_TYPE_CHARDEV << POSIX_FILETYPE_SHIFT);
			break;
		case S_IFBLK:
			posix_info->Mode |= cpu_to_le32(POSIX_TYPE_BLKDEV << POSIX_FILETYPE_SHIFT);
			break;
		case S_IFIFO:
			posix_info->Mode |= cpu_to_le32(POSIX_TYPE_FIFO << POSIX_FILETYPE_SHIFT);
			break;
		case S_IFSOCK:
			posix_info->Mode |= cpu_to_le32(POSIX_TYPE_SOCKET << POSIX_FILETYPE_SHIFT);
		}

		posix_info->Inode = cpu_to_le64(ksmbd_kstat->kstat->ino);
		posix_info->DosAttributes =
			S_ISDIR(ksmbd_kstat->kstat->mode) ? ATTR_DIRECTORY_LE : ATTR_ARCHIVE_LE;
		if (d_info->hide_dot_file && d_info->name[0] == '.')
			posix_info->DosAttributes |= ATTR_HIDDEN_LE;
		/*
		 * SidBuffer(32) contain two sids(Domain sid(16), UNIX group sid(16)).
		 * UNIX sid(16) = revision(1) + num_subauth(1) + authority(6) +
		 * 		  sub_auth(4 * 1(num_subauth)) + RID(4).
		 */
		id_to_sid(from_kuid_munged(&init_user_ns, ksmbd_kstat->kstat->uid),
			  SIDUNIX_USER, (struct smb_sid *)&posix_info->SidBuffer[0]);
		id_to_sid(from_kgid_munged(&init_user_ns, ksmbd_kstat->kstat->gid),
			  SIDUNIX_GROUP, (struct smb_sid *)&posix_info->SidBuffer[16]);
		memcpy(posix_info->name, conv_name, conv_len);
		posix_info->name_len = cpu_to_le32(conv_len);
		posix_info->NextEntryOffset = cpu_to_le32(next_entry_offset);
		break;
	}

	} /* switch (info_level) */

	d_info->last_entry_offset = d_info->data_count;
	d_info->data_count += next_entry_offset;
	d_info->out_buf_len -= next_entry_offset;
	d_info->wptr += next_entry_offset;

	ksmbd_debug(SMB,
		    "info_level : %d, buf_len :%d, next_offset : %d, data_count : %d\n",
		    info_level, d_info->out_buf_len,
		    next_entry_offset, d_info->data_count);

free_conv_name:
	kfree(conv_name);
	return rc;
}

struct smb2_query_dir_private {
	struct ksmbd_work	*work;
	char			*search_pattern;
	struct ksmbd_file	*dir_fp;

	struct ksmbd_dir_info	*d_info;
	int			info_level;
	int			flags;
	int			entry_count;
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 16, 0)
static void lock_dir(struct ksmbd_file *dir_fp)
{
	struct dentry *dir = dir_fp->filp->f_path.dentry;

	inode_lock_nested(d_inode(dir), I_MUTEX_PARENT);
}

static void unlock_dir(struct ksmbd_file *dir_fp)
{
	struct dentry *dir = dir_fp->filp->f_path.dentry;

	inode_unlock(d_inode(dir));
}
#endif

static int process_query_dir_entries(struct smb2_query_dir_private *priv)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	struct mnt_idmap	*idmap = file_mnt_idmap(priv->dir_fp->filp);
#else
	struct user_namespace	*user_ns = file_mnt_user_ns(priv->dir_fp->filp);
#endif
	struct kstat		kstat;
	struct ksmbd_kstat	ksmbd_kstat;
	int			rc;
	int			i;

	for (i = 0; i < priv->d_info->num_entry; i++) {
		struct dentry *dent;

		if (dentry_name(priv->d_info, priv->info_level))
			return -EINVAL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 16, 0)
		dent = lookup_one_unlocked(idmap,
					   &QSTR_LEN(priv->d_info->name,
					   priv->d_info->name_len),
					   priv->dir_fp->filp->f_path.dentry);
#else
		lock_dir(priv->dir_fp);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
		dent = lookup_one(idmap, priv->d_info->name,
#else
		dent = lookup_one(user_ns, priv->d_info->name,
#endif
				  priv->dir_fp->filp->f_path.dentry,
				  priv->d_info->name_len);
#else
		dent = lookup_one_len(priv->d_info->name,
				  priv->dir_fp->filp->f_path.dentry,
				  priv->d_info->name_len);
#endif
		unlock_dir(priv->dir_fp);
#endif

		if (IS_ERR(dent)) {
			ksmbd_debug(SMB, "Cannot lookup `%s' [%ld]\n",
				    priv->d_info->name,
				    PTR_ERR(dent));
			continue;
		}
		if (unlikely(d_is_negative(dent))) {
			dput(dent);
			ksmbd_debug(SMB, "Negative dentry `%s'\n",
				    priv->d_info->name);
			continue;
		}

		ksmbd_kstat.kstat = &kstat;
		ksmbd_kstat.kstat_dentry = dent;
#ifdef CONFIG_KSMBD_FRUIT
		ksmbd_kstat.share = priv->dir_fp->tcon ?
			priv->dir_fp->tcon->share_conf : NULL;
#endif
		if (priv->info_level != FILE_NAMES_INFORMATION) {
			rc = ksmbd_vfs_fill_dentry_attrs(priv->work,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
							 idmap,
#else
							 user_ns,
#endif

							 dent,
							 &ksmbd_kstat);
			if (rc) {
				dput(dent);
				continue;
			}
		}

		rc = smb2_populate_readdir_entry(priv->work->conn,
						 priv->info_level,
						 priv->d_info,
						 &ksmbd_kstat);
		dput(dent);
		if (rc)
			return rc;
	}
	return 0;
}

static int reserve_populate_dentry(struct ksmbd_dir_info *d_info,
				   int info_level)
{
	int struct_sz;
	int conv_len;
	int next_entry_offset;

	struct_sz = readdir_info_level_struct_sz(info_level);
	if (struct_sz == -EOPNOTSUPP)
		return -EOPNOTSUPP;

	conv_len = (d_info->name_len + 1) * 2;
	next_entry_offset = ALIGN(struct_sz + conv_len,
				  KSMBD_DIR_INFO_ALIGNMENT);

	if (next_entry_offset > d_info->out_buf_len) {
		d_info->out_buf_len = 0;
		return -ENOSPC;
	}

	switch (info_level) {
	case FILE_FULL_DIRECTORY_INFORMATION:
	{
		struct file_full_directory_info *ffdinfo;

		ffdinfo = (struct file_full_directory_info *)d_info->wptr;
		memcpy(ffdinfo->FileName, d_info->name, d_info->name_len);
		ffdinfo->FileName[d_info->name_len] = 0x00;
		ffdinfo->FileNameLength = cpu_to_le32(d_info->name_len);
		ffdinfo->NextEntryOffset = cpu_to_le32(next_entry_offset);
		break;
	}
	case FILE_BOTH_DIRECTORY_INFORMATION:
	{
		struct file_both_directory_info *fbdinfo;

		fbdinfo = (struct file_both_directory_info *)d_info->wptr;
		memcpy(fbdinfo->FileName, d_info->name, d_info->name_len);
		fbdinfo->FileName[d_info->name_len] = 0x00;
		fbdinfo->FileNameLength = cpu_to_le32(d_info->name_len);
		fbdinfo->NextEntryOffset = cpu_to_le32(next_entry_offset);
		break;
	}
	case FILE_DIRECTORY_INFORMATION:
	{
		struct file_directory_info *fdinfo;

		fdinfo = (struct file_directory_info *)d_info->wptr;
		memcpy(fdinfo->FileName, d_info->name, d_info->name_len);
		fdinfo->FileName[d_info->name_len] = 0x00;
		fdinfo->FileNameLength = cpu_to_le32(d_info->name_len);
		fdinfo->NextEntryOffset = cpu_to_le32(next_entry_offset);
		break;
	}
	case FILE_NAMES_INFORMATION:
	{
		struct file_names_info *fninfo;

		fninfo = (struct file_names_info *)d_info->wptr;
		memcpy(fninfo->FileName, d_info->name, d_info->name_len);
		fninfo->FileName[d_info->name_len] = 0x00;
		fninfo->FileNameLength = cpu_to_le32(d_info->name_len);
		fninfo->NextEntryOffset = cpu_to_le32(next_entry_offset);
		break;
	}
	case FILEID_FULL_DIRECTORY_INFORMATION:
	{
		struct file_id_full_dir_info *dinfo;

		dinfo = (struct file_id_full_dir_info *)d_info->wptr;
		memcpy(dinfo->FileName, d_info->name, d_info->name_len);
		dinfo->FileName[d_info->name_len] = 0x00;
		dinfo->FileNameLength = cpu_to_le32(d_info->name_len);
		dinfo->NextEntryOffset = cpu_to_le32(next_entry_offset);
		break;
	}
	case FILEID_BOTH_DIRECTORY_INFORMATION:
	case FILEID_GLOBAL_TX_DIRECTORY_INFORMATION:
	{
		struct file_id_both_directory_info *fibdinfo;

		fibdinfo = (struct file_id_both_directory_info *)d_info->wptr;
		memcpy(fibdinfo->FileName, d_info->name, d_info->name_len);
		fibdinfo->FileName[d_info->name_len] = 0x00;
		fibdinfo->FileNameLength = cpu_to_le32(d_info->name_len);
		fibdinfo->NextEntryOffset = cpu_to_le32(next_entry_offset);
		break;
	}
	case FILEID_EXTD_DIRECTORY_INFORMATION:
	{
		struct file_id_extd_dir_info *extdinfo;

		extdinfo = (struct file_id_extd_dir_info *)d_info->wptr;
		memcpy(extdinfo->FileName, d_info->name, d_info->name_len);
		extdinfo->FileName[d_info->name_len] = 0x00;
		extdinfo->FileNameLength = cpu_to_le32(d_info->name_len);
		extdinfo->NextEntryOffset = cpu_to_le32(next_entry_offset);
		break;
	}
	case FILEID_EXTD_BOTH_DIRECTORY_INFORMATION:
	{
		struct file_id_extd_both_dir_info *extdbinfo;

		extdbinfo = (struct file_id_extd_both_dir_info *)d_info->wptr;
		memcpy(extdbinfo->FileName, d_info->name, d_info->name_len);
		extdbinfo->FileName[d_info->name_len] = 0x00;
		extdbinfo->FileNameLength = cpu_to_le32(d_info->name_len);
		extdbinfo->NextEntryOffset = cpu_to_le32(next_entry_offset);
		break;
	}
	case FILEID_64_EXTD_DIRECTORY_INFORMATION:
	{
		struct file_id_64_extd_dir_info *extd64info;

		extd64info = (struct file_id_64_extd_dir_info *)d_info->wptr;
		memcpy(extd64info->FileName, d_info->name, d_info->name_len);
		extd64info->FileName[d_info->name_len] = 0x00;
		extd64info->FileNameLength = cpu_to_le32(d_info->name_len);
		extd64info->NextEntryOffset = cpu_to_le32(next_entry_offset);
		break;
	}
	case FILEID_64_EXTD_BOTH_DIRECTORY_INFORMATION:
	{
		struct file_id_64_extd_both_dir_info *extd64binfo;

		extd64binfo = (struct file_id_64_extd_both_dir_info *)d_info->wptr;
		memcpy(extd64binfo->FileName, d_info->name, d_info->name_len);
		extd64binfo->FileName[d_info->name_len] = 0x00;
		extd64binfo->FileNameLength = cpu_to_le32(d_info->name_len);
		extd64binfo->NextEntryOffset = cpu_to_le32(next_entry_offset);
		break;
	}
	case FILEID_ALL_EXTD_DIRECTORY_INFORMATION:
	{
		struct file_id_all_extd_dir_info *allexdinfo;

		allexdinfo = (struct file_id_all_extd_dir_info *)d_info->wptr;
		memcpy(allexdinfo->FileName, d_info->name, d_info->name_len);
		allexdinfo->FileName[d_info->name_len] = 0x00;
		allexdinfo->FileNameLength = cpu_to_le32(d_info->name_len);
		allexdinfo->NextEntryOffset = cpu_to_le32(next_entry_offset);
		break;
	}
	case FILEID_ALL_EXTD_BOTH_DIRECTORY_INFORMATION:
	{
		struct file_id_all_extd_both_dir_info *allexdbinfo;

		allexdbinfo =
			(struct file_id_all_extd_both_dir_info *)d_info->wptr;
		memcpy(allexdbinfo->FileName, d_info->name, d_info->name_len);
		allexdbinfo->FileName[d_info->name_len] = 0x00;
		allexdbinfo->FileNameLength = cpu_to_le32(d_info->name_len);
		allexdbinfo->NextEntryOffset = cpu_to_le32(next_entry_offset);
		break;
	}
	case SMB_FIND_FILE_POSIX_INFO:
	{
		struct smb2_posix_info *posix_info;

		posix_info = (struct smb2_posix_info *)d_info->wptr;
		memcpy(posix_info->name, d_info->name, d_info->name_len);
		posix_info->name[d_info->name_len] = 0x00;
		posix_info->name_len = cpu_to_le32(d_info->name_len);
		posix_info->NextEntryOffset =
			cpu_to_le32(next_entry_offset);
		break;
	}
	} /* switch (info_level) */

	d_info->num_entry++;
	d_info->out_buf_len -= next_entry_offset;
	d_info->wptr += next_entry_offset;
	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
static bool __query_dir(struct dir_context *ctx, const char *name, int namlen,
#else
static int __query_dir(struct dir_context *ctx, const char *name, int namlen,
#endif
		       loff_t offset, u64 ino, unsigned int d_type)
{
	struct ksmbd_readdir_data	*buf;
	struct smb2_query_dir_private	*priv;
	struct ksmbd_dir_info		*d_info;
	int				rc;

	buf	= container_of(ctx, struct ksmbd_readdir_data, ctx);
	priv	= buf->private;
	d_info	= priv->d_info;

	/* dot and dotdot entries are already reserved */
	if (!strcmp(".", name) || !strcmp("..", name))
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
		return true;
#else
		return 0;
#endif
	d_info->num_scan++;
	if (ksmbd_share_veto_filename(priv->work->tcon->share_conf, name))
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
		return true;
#else
		return 0;
#endif
	if (!match_pattern(name, namlen, priv->search_pattern))
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
		return true;
#else
		return 0;
#endif

	d_info->name		= name;
	d_info->name_len	= namlen;
	rc = reserve_populate_dentry(d_info, priv->info_level);
	if (rc)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
		return false;
#else
		return rc;
#endif
	if (d_info->flags & SMB2_RETURN_SINGLE_ENTRY) {
		d_info->out_buf_len = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
		return true;
#else
		return 0;
#endif
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
	return true;
#else
	return 0;
#endif
}

static int verify_info_level(int info_level)
{
	switch (info_level) {
	case FILE_FULL_DIRECTORY_INFORMATION:
	case FILE_BOTH_DIRECTORY_INFORMATION:
	case FILE_DIRECTORY_INFORMATION:
	case FILE_NAMES_INFORMATION:
	case FILEID_FULL_DIRECTORY_INFORMATION:
	case FILEID_BOTH_DIRECTORY_INFORMATION:
	case FILEID_GLOBAL_TX_DIRECTORY_INFORMATION:
	case FILEID_EXTD_DIRECTORY_INFORMATION:
	case FILEID_EXTD_BOTH_DIRECTORY_INFORMATION:
	case FILEID_64_EXTD_DIRECTORY_INFORMATION:
	case FILEID_64_EXTD_BOTH_DIRECTORY_INFORMATION:
	case FILEID_ALL_EXTD_DIRECTORY_INFORMATION:
	case FILEID_ALL_EXTD_BOTH_DIRECTORY_INFORMATION:
	case SMB_FIND_FILE_POSIX_INFO:
		break;
	default:
		return -EOPNOTSUPP;
	}

	return 0;
}

int smb2_resp_buf_len(struct ksmbd_work *work, unsigned short hdr2_len)
{
	int free_len;

	free_len = (int)(work->response_sz -
		(get_rfc1002_len(work->response_buf) + 4)) - hdr2_len;
	return free_len;
}

int smb2_calc_max_out_buf_len(struct ksmbd_work *work,
				     unsigned short hdr2_len,
				     unsigned int out_buf_len)
{
	int free_len;

	if (out_buf_len > work->conn->vals->max_trans_size)
		return -EINVAL;

	free_len = smb2_resp_buf_len(work, hdr2_len);
	if (free_len < 0)
		return -EINVAL;

	return min_t(int, out_buf_len, free_len);
}

int smb2_query_dir(struct ksmbd_work *work)
{
	struct ksmbd_conn *conn = work->conn;
	struct smb2_query_directory_req *req;
	struct smb2_query_directory_rsp *rsp;
	struct ksmbd_share_config *share = work->tcon->share_conf;
	struct ksmbd_file *dir_fp = NULL;
	struct ksmbd_dir_info d_info;
	int rc = 0;
	char *srch_ptr = NULL;
	unsigned char srch_flag;
	int buffer_sz;
	struct smb2_query_dir_private query_dir_private = {NULL, };

	ksmbd_debug(SMB, "Received smb2 query directory request\n");

	WORK_BUFFERS(work, req, rsp);

	if (ksmbd_override_fsids(work)) {
		rsp->hdr.Status = STATUS_NO_MEMORY;
		smb2_set_err_rsp(work);
		return -ENOMEM;
	}

	rc = verify_info_level(req->FileInformationClass);
	if (rc) {
		rc = -EFAULT;
		goto err_out2;
	}

	dir_fp = ksmbd_lookup_fd_slow(work, req->VolatileFileId, req->PersistentFileId);
	if (!dir_fp) {
		rc = -EBADF;
		goto err_out2;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
	if (!(dir_fp->daccess & FILE_LIST_DIRECTORY_LE) ||
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	    inode_permission(file_mnt_idmap(dir_fp->filp),
#else
	    inode_permission(file_mnt_user_ns(dir_fp->filp),
#endif
			     file_inode(dir_fp->filp),
			     MAY_READ | MAY_EXEC)) {
#else
	if (!(dir_fp->daccess & FILE_LIST_DIRECTORY_LE) ||
	    inode_permission(file_inode(dir_fp->filp), MAY_READ | MAY_EXEC)) {
#endif
		pr_err("no right to enumerate directory (%pD)\n", dir_fp->filp);
		rc = -EACCES;
		goto err_out2;
	}

	if (!S_ISDIR(file_inode(dir_fp->filp)->i_mode)) {
		pr_err("can't do query dir for a file\n");
		rc = -EINVAL;
		goto err_out2;
	}

	srch_flag = req->Flags;
	if ((u64)le16_to_cpu(req->FileNameOffset) + le16_to_cpu(req->FileNameLength) >
	    get_rfc1002_len(work->request_buf) + 4) {
		rc = -EINVAL;
		goto err_out2;
	}

	srch_ptr = smb_strndup_from_utf16((char *)req + le16_to_cpu(req->FileNameOffset),
					  le16_to_cpu(req->FileNameLength), 1,
					  conn->local_nls);
	if (IS_ERR(srch_ptr)) {
		ksmbd_debug(SMB, "Search Pattern not found\n");
		rc = -EINVAL;
		goto err_out2;
	} else {
		ksmbd_debug(SMB, "Search pattern is %s\n", srch_ptr);
	}

	if (srch_flag & SMB2_REOPEN || srch_flag & SMB2_RESTART_SCANS) {
		ksmbd_debug(SMB, "Restart directory scan\n");
		generic_file_llseek(dir_fp->filp, 0, SEEK_SET);
	}

	memset(&d_info, 0, sizeof(struct ksmbd_dir_info));
	d_info.wptr = (char *)rsp->Buffer;
	d_info.rptr = (char *)rsp->Buffer;
	d_info.out_buf_len =
		smb2_calc_max_out_buf_len(work, 8,
					  le32_to_cpu(req->OutputBufferLength));
	if (d_info.out_buf_len < 0) {
		rc = -EINVAL;
		goto err_out;
	}
	d_info.flags = srch_flag;

	/*
	 * reserve dot and dotdot entries in head of buffer
	 * in first response
	 */
	rc = ksmbd_populate_dot_dotdot_entries(work, req->FileInformationClass,
					       dir_fp, &d_info, srch_ptr,
					       smb2_populate_readdir_entry);
	if (rc == -ENOSPC)
		rc = 0;
	else if (rc)
		goto err_out;

	if (test_share_config_flag(share, KSMBD_SHARE_FLAG_HIDE_DOT_FILES))
		d_info.hide_dot_file = true;

	buffer_sz				= d_info.out_buf_len;
	d_info.rptr				= d_info.wptr;
	query_dir_private.work			= work;
	query_dir_private.search_pattern	= srch_ptr;
	query_dir_private.dir_fp		= dir_fp;
	query_dir_private.d_info		= &d_info;
	query_dir_private.info_level		= req->FileInformationClass;
	dir_fp->readdir_data.private		= &query_dir_private;
	set_ctx_actor(&dir_fp->readdir_data.ctx, __query_dir);

again:
	d_info.num_scan = 0;
	rc = iterate_dir(dir_fp->filp, &dir_fp->readdir_data.ctx);
	/*
	 * num_entry can be 0 if the directory iteration stops before reaching
	 * the end of the directory and no file is matched with the search
	 * pattern.
	 */
	if (rc >= 0 && !d_info.num_entry && d_info.num_scan &&
	    d_info.out_buf_len > 0)
		goto again;
	/*
	 * req->OutputBufferLength is too small to contain even one entry.
	 * In this case, it immediately returns OutputBufferLength 0 to client.
	 */
	if (!d_info.out_buf_len && !d_info.num_entry)
		goto no_buf_len;
	if (rc > 0 || rc == -ENOSPC)
		rc = 0;
	else if (rc)
		goto err_out;

	d_info.wptr = d_info.rptr;
	d_info.out_buf_len = buffer_sz;
	rc = process_query_dir_entries(&query_dir_private);
	if (rc)
		goto err_out;

	if (!d_info.data_count && d_info.out_buf_len >= 0) {
		if (srch_flag & SMB2_RETURN_SINGLE_ENTRY && !is_asterisk(srch_ptr)) {
			rsp->hdr.Status = STATUS_NO_SUCH_FILE;
		} else {
			dir_fp->dot_dotdot[0] = dir_fp->dot_dotdot[1] = 0;
			rsp->hdr.Status = STATUS_NO_MORE_FILES;
		}
		rsp->StructureSize = cpu_to_le16(9);
		rsp->OutputBufferOffset = cpu_to_le16(0);
		rsp->OutputBufferLength = cpu_to_le32(0);
		rsp->Buffer[0] = 0;
		rc = ksmbd_iov_pin_rsp(work, (void *)rsp,
				       offsetof(struct smb2_query_directory_rsp, Buffer)
				       + 1);
		if (rc)
			goto err_out;
	} else {
no_buf_len:
		((struct file_directory_info *)
		((char *)rsp->Buffer + d_info.last_entry_offset))
		->NextEntryOffset = 0;
		if (d_info.data_count >= d_info.last_entry_off_align)
			d_info.data_count -= d_info.last_entry_off_align;

		rsp->StructureSize = cpu_to_le16(9);
		rsp->OutputBufferOffset = cpu_to_le16(72);
		rsp->OutputBufferLength = cpu_to_le32(d_info.data_count);
		rc = ksmbd_iov_pin_rsp(work, (void *)rsp,
				       offsetof(struct smb2_query_directory_rsp, Buffer) +
				       d_info.data_count);
		if (rc)
			goto err_out;
	}

	kfree(srch_ptr);
	ksmbd_fd_put(work, dir_fp);
	ksmbd_revert_fsids(work);
	return 0;

err_out:
	pr_err("error while processing smb2 query dir rc = %d\n", rc);
	kfree(srch_ptr);

err_out2:
	if (rc == -EINVAL)
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
	else if (rc == -EACCES)
		rsp->hdr.Status = STATUS_ACCESS_DENIED;
	else if (rc == -ENOENT)
		rsp->hdr.Status = STATUS_NO_SUCH_FILE;
	else if (rc == -EBADF)
		rsp->hdr.Status = STATUS_FILE_CLOSED;
	else if (rc == -ENOMEM)
		rsp->hdr.Status = STATUS_NO_MEMORY;
	else if (rc == -EFAULT)
		rsp->hdr.Status = STATUS_INVALID_INFO_CLASS;
	else if (rc == -EIO)
		rsp->hdr.Status = STATUS_FILE_CORRUPT_ERROR;
	if (!rsp->hdr.Status)
		rsp->hdr.Status = STATUS_UNEXPECTED_IO_ERROR;

	smb2_set_err_rsp(work);
	ksmbd_fd_put(work, dir_fp);
	ksmbd_revert_fsids(work);
	return rc;
}

/**
 * buffer_check_err() - helper function to check buffer errors
 * @reqOutputBufferLength:	max buffer length expected in command response
 * @rsp:		query info response buffer contains output buffer length
 * @rsp_org:		base response buffer pointer in case of chained response
 *
 * Return:	0 on success, otherwise error
 */
