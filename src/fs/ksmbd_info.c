// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   Info-level handler registration table for ksmbd
 *
 *   Provides an RCU-protected hash table for dispatching SMB2 QUERY_INFO
 *   and SET_INFO requests, keyed on (info_type, info_class, op).
 *
 *   Handlers can be registered by core and extension modules.
 */

#include <linux/kernel.h>
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/module.h>
#include <linux/path.h>
#include <linux/fs.h>
#include <linux/nls.h>
#include <linux/falloc.h>

#include "ksmbd_info.h"
#include "glob.h"
#include "smb2pdu.h"
#include "connection.h"
#include "misc.h"
#include "oplock.h"
#include "server.h"
#include "mgmt/share_config.h"

/* 256 buckets (2^8) -- sufficient for all SMB2 info classes */
#define KSMBD_INFO_HASH_BITS	8

static DEFINE_HASHTABLE(info_handlers, KSMBD_INFO_HASH_BITS);
static DEFINE_SPINLOCK(info_lock);

/**
 * info_hash_key() - compute hash key from info type, class, and operation
 * @info_type:  SMB2 info type (FILE, FILESYSTEM, SECURITY, QUOTA)
 * @info_class: info class within the type
 * @op:         GET or SET operation
 *
 * Return: composite 32-bit hash key
 */
static inline u32 info_hash_key(u8 info_type, u8 info_class,
				enum ksmbd_info_op op)
{
	return (u32)info_type << 16 | (u32)info_class << 8 | (u32)op;
}

/**
 * ksmbd_register_info_handler() - Register an info-level handler
 * @h: handler descriptor (caller must keep alive until unregistered)
 *
 * Adds the handler to the hash table under spinlock using hash_add_rcu.
 * Checks for duplicates before insertion.
 *
 * Return: 0 on success, -EEXIST if (info_type, info_class, op) already
 *         registered
 */
int ksmbd_register_info_handler(struct ksmbd_info_handler *h)
{
	struct ksmbd_info_handler *cur;
	u32 key = info_hash_key(h->info_type, h->info_class, h->op);

	spin_lock(&info_lock);
	hash_for_each_possible_rcu(info_handlers, cur, node, key) {
		if (cur->info_type == h->info_type &&
		    cur->info_class == h->info_class &&
		    cur->op == h->op) {
			spin_unlock(&info_lock);
			pr_err("Info handler (type=%u, class=%u, op=%d) already registered\n",
			       h->info_type, h->info_class, h->op);
			return -EEXIST;
		}
	}
	hash_add_rcu(info_handlers, &h->node, key);
	spin_unlock(&info_lock);
	return 0;
}

/**
 * ksmbd_unregister_info_handler() - Unregister an info-level handler
 * @h: handler descriptor previously registered
 *
 * Removes the handler under spinlock and waits for an RCU grace period
 * so that in-flight lookups complete safely.
 */
void ksmbd_unregister_info_handler(struct ksmbd_info_handler *h)
{
	spin_lock(&info_lock);
	hash_del_rcu(&h->node);
	spin_unlock(&info_lock);
	synchronize_rcu();
}

/**
 * ksmbd_dispatch_info() - Look up and invoke a registered info handler
 * @work:       smb work for this request
 * @fp:         ksmbd file pointer (may be NULL for filesystem-level queries)
 * @info_type:  SMB2 info type
 * @info_class: info class within the type
 * @op:         GET or SET operation
 * @buf:        pointer to data buffer (response buffer for GET, request
 *              buffer for SET)
 * @buf_len:    buffer length
 * @out_len:    [out] number of bytes written (GET) or consumed (SET)
 *
 * Performs an RCU-protected hash lookup, takes a module reference on the
 * owning module, and invokes the handler callback.
 *
 * Return: 0 on success, handler errno on failure, -EOPNOTSUPP if no
 *         handler is registered for the given key.
 */
int ksmbd_dispatch_info(struct ksmbd_work *work,
			struct ksmbd_file *fp,
			u8 info_type, u8 info_class,
			enum ksmbd_info_op op,
			void *buf, unsigned int buf_len,
			unsigned int *out_len)
{
	struct ksmbd_info_handler *h;
	u32 key = info_hash_key(info_type, info_class, op);
	int ret = -EOPNOTSUPP;

	*out_len = 0;

	rcu_read_lock();
	hash_for_each_possible_rcu(info_handlers, h, node, key) {
		if (h->info_type != info_type ||
		    h->info_class != info_class ||
		    h->op != op)
			continue;

		if (!try_module_get(h->owner)) {
			rcu_read_unlock();
			return -ENODEV;
		}
		rcu_read_unlock();

		ret = h->handler(work, fp, buf, buf_len, out_len);
		module_put(h->owner);
		return ret;
	}
	rcu_read_unlock();

	return ret;
}

/*
 * FILE_NAME_INFORMATION (class 9) GET handler
 *
 * Returns the file path relative to the share root encoded as
 * UTF-16LE.  The response layout is:
 *   4 bytes  FileNameLength (in bytes, of the UTF-16LE name)
 *   variable FileName[]     (UTF-16LE, NOT null-terminated)
 */

/**
 * ksmbd_info_get_file_name() - FILE_NAME_INFORMATION query handler
 * @work:    smb work for this request
 * @fp:      ksmbd file pointer
 * @buf:     response buffer to fill
 * @buf_len: available space in @buf
 * @out_len: [out] bytes written to @buf
 *
 * Retrieves the file path relative to the share root, converts it
 * to UTF-16LE, and writes FileNameLength + FileName into @buf.
 *
 * Return: 0 on success, negative errno on failure
 */
static int ksmbd_info_get_file_name(struct ksmbd_work *work,
				    struct ksmbd_file *fp,
				    void *buf,
				    unsigned int buf_len,
				    unsigned int *out_len)
{
	struct ksmbd_conn *conn = work->conn;
	char *filename;
	int conv_len;
	__le32 *name_len_ptr;
	unsigned int min_len;
	unsigned int max_utf16_chars;

	if (!fp)
		return -EINVAL;

	/* Need at least 4 bytes for FileNameLength */
	min_len = sizeof(__le32);
	if (buf_len < min_len)
		return -ENOSPC;
	max_utf16_chars = (buf_len - min_len) / sizeof(__le16);
	if (!max_utf16_chars)
		return -ENOSPC;

	filename = convert_to_nt_pathname(work->tcon->share_conf,
					  &fp->filp->f_path);
	if (IS_ERR(filename))
		return PTR_ERR(filename);

	ksmbd_debug(SMB,
		    "FILE_NAME_INFORMATION: filename = %s\n",
		    filename);

	name_len_ptr = (__le32 *)buf;

	/*
	 * Convert filename to UTF-16LE after the 4-byte length
	 * field.  smbConvertToUTF16 returns the number of
	 * UTF-16 code units written.
	 */
	conv_len = smbConvertToUTF16(
			(__le16 *)((char *)buf + sizeof(__le32)),
			filename,
			max_utf16_chars,
			conn->local_nls,
			0);
	if (conv_len < 0) {
		kfree(filename);
		return -EINVAL;
	}
	conv_len *= 2; /* code units -> bytes */

	if (sizeof(__le32) + conv_len > buf_len) {
		kfree(filename);
		return -ENOSPC;
	}

	*name_len_ptr = cpu_to_le32(conv_len);
	*out_len = sizeof(__le32) + conv_len;

	kfree(filename);
	return 0;
}

/*
 * FS_CONTROL_INFORMATION (class 6) SET handler
 *
 * Accepts and validates an smb2_fs_control_info structure from the
 * client.  Quota control is not supported by most Linux filesystems
 * so this handler accepts the request and returns success, matching
 * Windows server behavior for non-quota filesystems.
 */

/**
 * ksmbd_info_set_fs_control() - FS_CONTROL_INFORMATION set handler
 * @work:    smb work for this request
 * @fp:      ksmbd file pointer (may be NULL)
 * @buf:     request data buffer containing smb2_fs_control_info
 * @buf_len: length of request data
 * @out_len: [out] bytes consumed from @buf
 *
 * Validates the buffer size and accepts the FS control information.
 * Quota enforcement is not implemented; the handler returns success
 * to match typical Windows server behavior on non-quota volumes.
 *
 * Return: 0 on success, -EMSGSIZE if buffer too small
 */
static int ksmbd_info_set_fs_control(struct ksmbd_work *work,
				     struct ksmbd_file *fp,
				     void *buf,
				     unsigned int buf_len,
				     unsigned int *out_len)
{
	if (buf_len < sizeof(struct smb2_fs_control_info))
		return -EMSGSIZE;

	ksmbd_debug(SMB,
		    "FS_CONTROL_INFORMATION SET: accepted (quota not enforced)\n");

	*out_len = sizeof(struct smb2_fs_control_info);
	return 0;
}

/*
 * FILE_PIPE_INFORMATION (class 23) GET handler
 *
 * Returns pipe read mode and completion mode.  Since ksmbd does not
 * serve named pipes directly, return default values (byte-stream
 * mode, blocking completion).
 */

/**
 * ksmbd_info_get_pipe() - FILE_PIPE_INFORMATION query handler
 * @work:    smb work for this request
 * @fp:      ksmbd file pointer
 * @buf:     response buffer to fill
 * @buf_len: available space in @buf
 * @out_len: [out] bytes written to @buf
 *
 * Return: 0 on success, negative errno on failure
 */
static int ksmbd_info_get_pipe(struct ksmbd_work *work,
			       struct ksmbd_file *fp,
			       void *buf,
			       unsigned int buf_len,
			       unsigned int *out_len)
{
	struct smb2_file_pipe_info *pipe_info;

	if (buf_len < sizeof(struct smb2_file_pipe_info))
		return -ENOSPC;

	pipe_info = (struct smb2_file_pipe_info *)buf;
	pipe_info->ReadMode = cpu_to_le32(0);
	pipe_info->CompletionMode = cpu_to_le32(0);

	*out_len = sizeof(struct smb2_file_pipe_info);

	ksmbd_debug(SMB,
		    "FILE_PIPE_INFORMATION: default response\n");
	return 0;
}

/*
 * FILE_PIPE_LOCAL_INFORMATION (class 24) GET handler
 *
 * Returns local pipe information.  Since ksmbd does not serve named
 * pipes directly, return default values for all fields.
 */

/**
 * ksmbd_info_get_pipe_local() - FILE_PIPE_LOCAL_INFORMATION query handler
 * @work:    smb work for this request
 * @fp:      ksmbd file pointer
 * @buf:     response buffer to fill
 * @buf_len: available space in @buf
 * @out_len: [out] bytes written to @buf
 *
 * Return: 0 on success, negative errno on failure
 */
static int ksmbd_info_get_pipe_local(struct ksmbd_work *work,
				     struct ksmbd_file *fp,
				     void *buf,
				     unsigned int buf_len,
				     unsigned int *out_len)
{
	struct smb2_file_pipe_local_info *pipe_info;

	if (buf_len < sizeof(struct smb2_file_pipe_local_info))
		return -ENOSPC;

	pipe_info = (struct smb2_file_pipe_local_info *)buf;
	pipe_info->NamedPipeType = cpu_to_le32(0);
	pipe_info->NamedPipeConfiguration = cpu_to_le32(0);
	pipe_info->MaximumInstances = cpu_to_le32(0xFFFFFFFF);
	pipe_info->CurrentInstances = cpu_to_le32(0);
	pipe_info->InboundQuota = cpu_to_le32(0);
	pipe_info->ReadDataAvailable = cpu_to_le32(0);
	pipe_info->OutboundQuota = cpu_to_le32(0);
	pipe_info->WriteQuotaAvailable = cpu_to_le32(0);
	pipe_info->NamedPipeState = cpu_to_le32(0);
	pipe_info->NamedPipeEnd = cpu_to_le32(0);

	*out_len = sizeof(struct smb2_file_pipe_local_info);

	ksmbd_debug(SMB,
		    "FILE_PIPE_LOCAL_INFORMATION: default response\n");
	return 0;
}

struct smb2_file_pipe_remote_info {
	__le64 CollectDataTime;
	__le32 MaximumCollectionCount;
	__le32 CollectDataTimeout;
} __packed;

static int ksmbd_info_get_pipe_remote(struct ksmbd_work *work,
				      struct ksmbd_file *fp,
				      void *buf,
				      unsigned int buf_len,
				      unsigned int *out_len)
{
	struct smb2_file_pipe_remote_info *pipe_info;

	if (buf_len < sizeof(*pipe_info))
		return -ENOSPC;

	pipe_info = (struct smb2_file_pipe_remote_info *)buf;
	memset(pipe_info, 0, sizeof(*pipe_info));
	*out_len = sizeof(*pipe_info);
	return 0;
}

struct smb2_file_mailslot_query_info {
	__le32 MaximumMessageSize;
	__le32 MailslotQuota;
	__le32 NextMessageSize;
	__le32 MessagesAvailable;
	__le64 ReadTimeout;
} __packed;

struct smb2_file_mailslot_set_info {
	__le64 ReadTimeout;
} __packed;

static int ksmbd_info_get_mailslot_query(struct ksmbd_work *work,
					 struct ksmbd_file *fp,
					 void *buf,
					 unsigned int buf_len,
					 unsigned int *out_len)
{
	struct smb2_file_mailslot_query_info *mail_info;

	if (buf_len < sizeof(*mail_info))
		return -ENOSPC;

	mail_info = (struct smb2_file_mailslot_query_info *)buf;
	memset(mail_info, 0, sizeof(*mail_info));
	*out_len = sizeof(*mail_info);
	return 0;
}

static int ksmbd_info_set_mailslot(struct ksmbd_work *work,
				   struct ksmbd_file *fp,
				   void *buf,
				   unsigned int buf_len,
				   unsigned int *out_len)
{
	if (buf_len < sizeof(struct smb2_file_mailslot_set_info))
		return -EMSGSIZE;

	*out_len = sizeof(struct smb2_file_mailslot_set_info);
	return 0;
}

static int ksmbd_info_set_pipe_info(struct ksmbd_work *work,
				    struct ksmbd_file *fp,
				    void *buf,
				    unsigned int buf_len,
				    unsigned int *out_len)
{
	if (buf_len < sizeof(struct smb2_file_pipe_info))
		return -EMSGSIZE;

	*out_len = sizeof(struct smb2_file_pipe_info);
	return 0;
}

static int ksmbd_info_set_pipe_remote(struct ksmbd_work *work,
				      struct ksmbd_file *fp,
				      void *buf,
				      unsigned int buf_len,
				      unsigned int *out_len)
{
	if (buf_len < sizeof(struct smb2_file_pipe_remote_info))
		return -EMSGSIZE;

	*out_len = sizeof(struct smb2_file_pipe_remote_info);
	return 0;
}

static int ksmbd_info_set_noop_consume(struct ksmbd_work *work,
				       struct ksmbd_file *fp,
				       void *buf,
				       unsigned int buf_len,
				       unsigned int *out_len)
{
	*out_len = buf_len;
	return 0;
}

struct smb2_file_links_info {
	__le32 BytesNeeded;
	__le32 EntriesReturned;
} __packed;

struct smb2_file_link_entry_info {
	__le32 NextEntryOffset;
	__u8 ParentFileId[16];
	__le32 FileNameLength;
	__le16 FileName[];
} __packed;

static int ksmbd_info_get_hard_link(struct ksmbd_work *work,
				    struct ksmbd_file *fp,
				    void *buf,
				    unsigned int buf_len,
				    unsigned int *out_len)
{
	struct ksmbd_conn *conn = work->conn;
	struct smb2_file_links_info *links_info;
	struct smb2_file_link_entry_info *entry_info;
	char *filename;
	__le16 *utf16_name;
	unsigned int name_bytes;
	unsigned int needed;
	int conv_len;

	if (!fp)
		return -EINVAL;

	filename = convert_to_nt_pathname(work->tcon->share_conf,
					  &fp->filp->f_path);
	if (IS_ERR(filename))
		return PTR_ERR(filename);

	utf16_name = kcalloc(PATH_MAX + 1, sizeof(__le16), KSMBD_DEFAULT_GFP);
	if (!utf16_name) {
		kfree(filename);
		return -ENOMEM;
	}

	conv_len = smbConvertToUTF16(utf16_name, filename, PATH_MAX,
				     conn->local_nls, 0);
	if (conv_len < 0) {
		kfree(utf16_name);
		kfree(filename);
		return -EINVAL;
	}

	name_bytes = conv_len * sizeof(__le16);
	needed = sizeof(*links_info) +
		 offsetof(struct smb2_file_link_entry_info, FileName) +
		 name_bytes;
	if (buf_len < needed) {
		kfree(utf16_name);
		kfree(filename);
		return -ENOSPC;
	}

	links_info = (struct smb2_file_links_info *)buf;
	entry_info = (struct smb2_file_link_entry_info *)((char *)buf +
			sizeof(*links_info));
	links_info->BytesNeeded = cpu_to_le32(needed);
	links_info->EntriesReturned = cpu_to_le32(1);

	entry_info->NextEntryOffset = 0;
	memset(entry_info->ParentFileId, 0, sizeof(entry_info->ParentFileId));
	entry_info->FileNameLength = cpu_to_le32(name_bytes);
	memcpy(entry_info->FileName, utf16_name, name_bytes);
	*out_len = needed;

	kfree(utf16_name);
	kfree(filename);
	return 0;
}

/*
 * FILE_VALID_DATA_LENGTH_INFORMATION (class 39) SET handler
 *
 * Sets the valid data length for a file.  Uses vfs_fallocate()
 * with FALLOC_FL_KEEP_SIZE to pre-allocate without changing
 * the file size.
 */

/**
 * ksmbd_info_set_valid_data_length() - FILE_VALID_DATA_LENGTH set handler
 * @work:    smb work for this request
 * @fp:      ksmbd file pointer
 * @buf:     request data buffer
 * @buf_len: length of request data
 * @out_len: [out] bytes consumed from @buf
 *
 * Return: 0 on success, negative errno on failure
 */
static int ksmbd_info_set_valid_data_length(struct ksmbd_work *work,
					    struct ksmbd_file *fp,
					    void *buf,
					    unsigned int buf_len,
					    unsigned int *out_len)
{
	struct smb2_file_valid_data_length_info *vdl_info;
	loff_t length;
	int rc;

	if (!fp)
		return -EINVAL;

	if (buf_len < sizeof(struct smb2_file_valid_data_length_info))
		return -EMSGSIZE;

	vdl_info = (struct smb2_file_valid_data_length_info *)buf;
	length = le64_to_cpu(vdl_info->ValidDataLength);

	if (length < 0)
		return -EINVAL;

	ksmbd_debug(SMB,
		    "FILE_VALID_DATA_LENGTH_INFORMATION SET: length=%lld\n",
		    length);

	smb_break_all_levII_oplock(work, fp, 1);

	rc = vfs_fallocate(fp->filp, FALLOC_FL_KEEP_SIZE, 0, length);
	if (rc && rc != -EOPNOTSUPP) {
		pr_err("vfs_fallocate for valid data length failed: %d\n",
		       rc);
		return rc;
	}

	*out_len = sizeof(struct smb2_file_valid_data_length_info);
	return 0;
}

/*
 * FILE_NORMALIZED_NAME_INFORMATION (class 48) GET handler
 *
 * Returns the normalized (canonical) name of the file using the
 * dentry path.  The response layout matches FILE_NAME_INFORMATION:
 *   4 bytes  FileNameLength (in bytes, of the UTF-16LE name)
 *   variable FileName[]     (UTF-16LE, NOT null-terminated)
 */

/**
 * ksmbd_info_get_normalized_name() - FILE_NORMALIZED_NAME query handler
 * @work:    smb work for this request
 * @fp:      ksmbd file pointer
 * @buf:     response buffer to fill
 * @buf_len: available space in @buf
 * @out_len: [out] bytes written to @buf
 *
 * Return: 0 on success, negative errno on failure
 */
static int ksmbd_info_get_normalized_name(struct ksmbd_work *work,
					  struct ksmbd_file *fp,
					  void *buf,
					  unsigned int buf_len,
					  unsigned int *out_len)
{
	struct ksmbd_conn *conn = work->conn;
	char *filename;
	int conv_len;
	__le32 *name_len_ptr;
	unsigned int min_len;
	unsigned int max_utf16_chars;

	if (!fp)
		return -EINVAL;

	/* Need at least 4 bytes for FileNameLength */
	min_len = sizeof(__le32);
	if (buf_len < min_len)
		return -ENOSPC;
	max_utf16_chars = (buf_len - min_len) / sizeof(__le16);
	if (!max_utf16_chars)
		return -ENOSPC;

	filename = convert_to_nt_pathname(work->tcon->share_conf,
					  &fp->filp->f_path);
	if (IS_ERR(filename))
		return PTR_ERR(filename);

	ksmbd_debug(SMB,
		    "FILE_NORMALIZED_NAME_INFORMATION: filename = %s\n",
		    filename);

	name_len_ptr = (__le32 *)buf;

	/*
	 * Convert filename to UTF-16LE after the 4-byte length
	 * field.  smbConvertToUTF16 returns the number of
	 * UTF-16 code units written.
	 */
	conv_len = smbConvertToUTF16(
			(__le16 *)((char *)buf + sizeof(__le32)),
			filename,
			max_utf16_chars,
			conn->local_nls,
			0);
	if (conv_len < 0) {
		kfree(filename);
		return -EINVAL;
	}
	conv_len *= 2; /* code units -> bytes */

	if (sizeof(__le32) + conv_len > buf_len) {
		kfree(filename);
		return -ENOSPC;
	}

	*name_len_ptr = cpu_to_le32(conv_len);
	*out_len = sizeof(__le32) + conv_len;

	kfree(filename);
	return 0;
}

struct smb2_file_process_ids_using_file_info {
	__le32 NumberOfProcessIdsInList;
	__le32 Reserved;
	__le64 ProcessIdList[];
} __packed;

static int ksmbd_info_get_process_ids_using_file(struct ksmbd_work *work,
						 struct ksmbd_file *fp,
						 void *buf,
						 unsigned int buf_len,
						 unsigned int *out_len)
{
	struct smb2_file_process_ids_using_file_info *info;

	if (buf_len < sizeof(*info))
		return -ENOSPC;

	info = (struct smb2_file_process_ids_using_file_info *)buf;
	info->NumberOfProcessIdsInList = 0;
	info->Reserved = 0;
	*out_len = sizeof(*info);
	return 0;
}

struct smb2_file_network_physical_name_info {
	__le32 FileNameLength;
	__le16 FileName[];
} __packed;

static int ksmbd_info_get_network_physical_name(struct ksmbd_work *work,
						struct ksmbd_file *fp,
						void *buf,
						unsigned int buf_len,
						unsigned int *out_len)
{
	struct ksmbd_conn *conn = work->conn;
	struct ksmbd_share_config *share = work->tcon->share_conf;
	char *filename, *network_name;
	int conv_len;
	__le32 *name_len_ptr;
	unsigned int max_utf16_chars;

	if (!fp || !share || !share->name)
		return -EINVAL;

	if (buf_len < sizeof(__le32))
		return -ENOSPC;
	max_utf16_chars = (buf_len - sizeof(__le32)) / sizeof(__le16);
	if (!max_utf16_chars)
		return -ENOSPC;

	filename = convert_to_nt_pathname(share, &fp->filp->f_path);
	if (IS_ERR(filename))
		return PTR_ERR(filename);

	if (filename[0] == '\\' || filename[0] == '/') {
		network_name = kasprintf(KSMBD_DEFAULT_GFP, "\\\\%s\\%s%s",
					 ksmbd_netbios_name(), share->name,
					 filename);
	} else {
		network_name = kasprintf(KSMBD_DEFAULT_GFP, "\\\\%s\\%s\\%s",
					 ksmbd_netbios_name(), share->name,
					 filename);
	}
	kfree(filename);
	if (!network_name)
		return -ENOMEM;

	ksmbd_conv_path_to_windows(network_name);

	name_len_ptr = (__le32 *)buf;
	conv_len = smbConvertToUTF16((__le16 *)((char *)buf + sizeof(__le32)),
				     network_name, max_utf16_chars,
				     conn->local_nls, 0);
	kfree(network_name);
	if (conv_len < 0)
		return -EINVAL;

	conv_len *= 2;
	if (sizeof(__le32) + conv_len > buf_len)
		return -ENOSPC;

	*name_len_ptr = cpu_to_le32(conv_len);
	*out_len = sizeof(__le32) + conv_len;
	return 0;
}

struct smb2_file_volume_name_info {
	__le32 DeviceNameLength;
	__le16 DeviceName[];
} __packed;

static int ksmbd_info_get_volume_name(struct ksmbd_work *work,
				      struct ksmbd_file *fp,
				      void *buf,
				      unsigned int buf_len,
				      unsigned int *out_len)
{
	struct ksmbd_conn *conn = work->conn;
	struct ksmbd_share_config *share = work->tcon->share_conf;
	char *volume_name;
	__le32 *name_len_ptr;
	int conv_len;
	unsigned int max_utf16_chars;

	if (!share || !share->name)
		return -EINVAL;

	if (buf_len < sizeof(__le32))
		return -ENOSPC;
	max_utf16_chars = (buf_len - sizeof(__le32)) / sizeof(__le16);
	if (!max_utf16_chars)
		return -ENOSPC;

	volume_name = kasprintf(KSMBD_DEFAULT_GFP, "\\\\%s", share->name);
	if (!volume_name)
		return -ENOMEM;

	name_len_ptr = (__le32 *)buf;
	conv_len = smbConvertToUTF16((__le16 *)((char *)buf + sizeof(__le32)),
				     volume_name, max_utf16_chars,
				     conn->local_nls, 0);
	kfree(volume_name);
	if (conv_len < 0)
		return -EINVAL;

	conv_len *= 2;
	if (sizeof(__le32) + conv_len > buf_len)
		return -ENOSPC;

	*name_len_ptr = cpu_to_le32(conv_len);
	*out_len = sizeof(__le32) + conv_len;
	return 0;
}

struct smb2_file_is_remote_device_info {
	__le32 Flags;
} __packed;

static int ksmbd_info_get_is_remote_device(struct ksmbd_work *work,
					   struct ksmbd_file *fp,
					   void *buf,
					   unsigned int buf_len,
					   unsigned int *out_len)
{
	struct smb2_file_is_remote_device_info *info;

	if (buf_len < sizeof(*info))
		return -ENOSPC;

	info = (struct smb2_file_is_remote_device_info *)buf;
	info->Flags = 0;
	*out_len = sizeof(*info);
	return 0;
}

/*
 * FILE_REMOTE_PROTOCOL_INFORMATION (class 55) response.
 *
 * MS-FSCC defines a fixed-size structure that reports the network
 * redirector protocol and version details.
 */
struct smb2_file_remote_protocol_info {
	__le16 StructureVersion;
	__le16 StructureSize;
	__le32 Protocol;
	__le16 ProtocolMajorVersion;
	__le16 ProtocolMinorVersion;
	__le16 ProtocolRevision;
	__le16 Reserved;
	__le32 Flags;
	__le32 GenericReserved[8];
	__le32 ProtocolSpecificReserved[16];
} __packed;

#define KSMBD_REMOTE_PROTOCOL_WNNC_NET_LANMAN	0x00020000

static void ksmbd_info_fill_remote_protocol_version(struct ksmbd_conn *conn,
						    struct smb2_file_remote_protocol_info *info)
{
	u16 major = 3;
	u16 minor = 1;
	u16 rev = 1;

	if (!conn)
		goto out;

	switch (conn->dialect) {
	case SMB20_PROT_ID:
		major = 2;
		minor = 0;
		rev = 0;
		break;
	case SMB21_PROT_ID:
		major = 2;
		minor = 1;
		rev = 0;
		break;
	case SMB30_PROT_ID:
		major = 3;
		minor = 0;
		rev = 0;
		break;
	case SMB302_PROT_ID:
		major = 3;
		minor = 0;
		rev = 2;
		break;
	case SMB311_PROT_ID:
	default:
		major = 3;
		minor = 1;
		rev = 1;
		break;
	}

out:
	info->ProtocolMajorVersion = cpu_to_le16(major);
	info->ProtocolMinorVersion = cpu_to_le16(minor);
	info->ProtocolRevision = cpu_to_le16(rev);
}

static int ksmbd_info_get_remote_protocol(struct ksmbd_work *work,
					  struct ksmbd_file *fp,
					  void *buf,
					  unsigned int buf_len,
					  unsigned int *out_len)
{
	struct smb2_file_remote_protocol_info *info;

	if (buf_len < sizeof(*info))
		return -ENOSPC;

	info = (struct smb2_file_remote_protocol_info *)buf;
	memset(info, 0, sizeof(*info));
	info->StructureVersion = cpu_to_le16(1);
	info->StructureSize = cpu_to_le16(sizeof(*info));
	info->Protocol = cpu_to_le32(KSMBD_REMOTE_PROTOCOL_WNNC_NET_LANMAN);
	ksmbd_info_fill_remote_protocol_version(work->conn, info);
	*out_len = sizeof(*info);
	return 0;
}

struct smb2_file_case_sensitive_info {
	__le32 Flags;
} __packed;

static int ksmbd_info_get_case_sensitive(struct ksmbd_work *work,
					 struct ksmbd_file *fp,
					 void *buf,
					 unsigned int buf_len,
					 unsigned int *out_len)
{
	struct smb2_file_case_sensitive_info *info;

	if (buf_len < sizeof(*info))
		return -ENOSPC;

	info = (struct smb2_file_case_sensitive_info *)buf;
	info->Flags = 0;
	*out_len = sizeof(*info);
	return 0;
}

static int ksmbd_info_set_case_sensitive(struct ksmbd_work *work,
					 struct ksmbd_file *fp,
					 void *buf,
					 unsigned int buf_len,
					 unsigned int *out_len)
{
	struct smb2_file_case_sensitive_info *info;
	u32 flags;

	if (buf_len < sizeof(*info))
		return -EMSGSIZE;

	info = (struct smb2_file_case_sensitive_info *)buf;
	flags = le32_to_cpu(info->Flags);
	if (flags & ~FILE_CS_FLAG_CASE_SENSITIVE_DIR)
		return -EINVAL;

	*out_len = sizeof(*info);
	return 0;
}

struct smb2_fs_driver_path_info {
	__u8 DriverInPath;
	__u8 Reserved[3];
} __packed;

static int ksmbd_info_get_fs_driver_path(struct ksmbd_work *work,
					 struct ksmbd_file *fp,
					 void *buf,
					 unsigned int buf_len,
					 unsigned int *out_len)
{
	struct smb2_fs_driver_path_info *info;

	if (buf_len < sizeof(*info))
		return -ENOSPC;

	info = (struct smb2_fs_driver_path_info *)buf;
	memset(info, 0, sizeof(*info));
	*out_len = sizeof(*info);
	return 0;
}

struct smb2_fs_label_info {
	__le32 VolumeLabelLength;
	__le16 VolumeLabel[];
} __packed;

static int ksmbd_info_set_fs_label(struct ksmbd_work *work,
				   struct ksmbd_file *fp,
				   void *buf,
				   unsigned int buf_len,
				   unsigned int *out_len)
{
	struct smb2_fs_label_info *info;
	unsigned int consumed;
	u32 label_len;

	if (buf_len < sizeof(*info))
		return -EMSGSIZE;

	info = (struct smb2_fs_label_info *)buf;
	label_len = le32_to_cpu(info->VolumeLabelLength);
	if (label_len & 1)
		return -EINVAL;

	consumed = offsetof(struct smb2_fs_label_info, VolumeLabel) + label_len;
	if (consumed > buf_len)
		return -EINVAL;

	*out_len = consumed;
	return 0;
}

static int ksmbd_info_set_fs_object_id(struct ksmbd_work *work,
				       struct ksmbd_file *fp,
				       void *buf,
				       unsigned int buf_len,
				       unsigned int *out_len)
{
	if (buf_len < sizeof(struct object_id_info))
		return -EMSGSIZE;

	*out_len = sizeof(struct object_id_info);
	return 0;
}

/*
 * QUOTA_INFORMATION (type=SMB2_O_INFO_QUOTA, class=FILE_QUOTA_INFORMATION)
 *
 * ksmbd currently does not implement full on-disk quota accounting in
 * protocol responses. Return an empty result for GET and accept SET as a
 * no-op for interoperability with clients that probe quota support.
 */
static int ksmbd_info_get_quota(struct ksmbd_work *work,
				struct ksmbd_file *fp,
				void *buf,
				unsigned int buf_len,
				unsigned int *out_len)
{
	*out_len = 0;
	return 0;
}

static int ksmbd_info_set_quota(struct ksmbd_work *work,
				struct ksmbd_file *fp,
				void *buf,
				unsigned int buf_len,
				unsigned int *out_len)
{
	*out_len = buf_len;
	return 0;
}

/* Static handler descriptors for built-in info-level handlers */
static struct ksmbd_info_handler ksmbd_file_name_get_handler = {
	.info_type	= SMB2_O_INFO_FILE,
	.info_class	= FILE_NAME_INFORMATION,
	.op		= KSMBD_INFO_GET,
	.handler	= ksmbd_info_get_file_name,
	.owner		= THIS_MODULE,
};

static struct ksmbd_info_handler ksmbd_fs_control_set_handler = {
	.info_type	= SMB2_O_INFO_FILESYSTEM,
	.info_class	= FS_CONTROL_INFORMATION,
	.op		= KSMBD_INFO_SET,
	.handler	= ksmbd_info_set_fs_control,
	.owner		= THIS_MODULE,
};

static struct ksmbd_info_handler ksmbd_fs_driver_path_get_handler = {
	.info_type	= SMB2_O_INFO_FILESYSTEM,
	.info_class	= FS_DRIVER_PATH_INFORMATION,
	.op		= KSMBD_INFO_GET,
	.handler	= ksmbd_info_get_fs_driver_path,
	.owner		= THIS_MODULE,
};

static struct ksmbd_info_handler ksmbd_fs_label_set_handler = {
	.info_type	= SMB2_O_INFO_FILESYSTEM,
	.info_class	= FS_LABEL_INFORMATION,
	.op		= KSMBD_INFO_SET,
	.handler	= ksmbd_info_set_fs_label,
	.owner		= THIS_MODULE,
};

static struct ksmbd_info_handler ksmbd_fs_object_id_set_handler = {
	.info_type	= SMB2_O_INFO_FILESYSTEM,
	.info_class	= FS_OBJECT_ID_INFORMATION,
	.op		= KSMBD_INFO_SET,
	.handler	= ksmbd_info_set_fs_object_id,
	.owner		= THIS_MODULE,
};

static struct ksmbd_info_handler ksmbd_pipe_info_get_handler = {
	.info_type	= SMB2_O_INFO_FILE,
	.info_class	= FILE_PIPE_INFORMATION,
	.op		= KSMBD_INFO_GET,
	.handler	= ksmbd_info_get_pipe,
	.owner		= THIS_MODULE,
};

static struct ksmbd_info_handler ksmbd_pipe_local_info_get_handler = {
	.info_type	= SMB2_O_INFO_FILE,
	.info_class	= FILE_PIPE_LOCAL_INFORMATION,
	.op		= KSMBD_INFO_GET,
	.handler	= ksmbd_info_get_pipe_local,
	.owner		= THIS_MODULE,
};

static struct ksmbd_info_handler ksmbd_pipe_remote_info_get_handler = {
	.info_type	= SMB2_O_INFO_FILE,
	.info_class	= FILE_PIPE_REMOTE_INFORMATION,
	.op		= KSMBD_INFO_GET,
	.handler	= ksmbd_info_get_pipe_remote,
	.owner		= THIS_MODULE,
};

static struct ksmbd_info_handler ksmbd_mailslot_query_get_handler = {
	.info_type	= SMB2_O_INFO_FILE,
	.info_class	= FILE_MAILSLOT_QUERY_INFORMATION,
	.op		= KSMBD_INFO_GET,
	.handler	= ksmbd_info_get_mailslot_query,
	.owner		= THIS_MODULE,
};

static struct ksmbd_info_handler ksmbd_hard_link_get_handler = {
	.info_type	= SMB2_O_INFO_FILE,
	.info_class	= FILE_HARD_LINK_INFORMATION,
	.op		= KSMBD_INFO_GET,
	.handler	= ksmbd_info_get_hard_link,
	.owner		= THIS_MODULE,
};

static struct ksmbd_info_handler ksmbd_pipe_info_set_handler = {
	.info_type	= SMB2_O_INFO_FILE,
	.info_class	= FILE_PIPE_INFORMATION,
	.op		= KSMBD_INFO_SET,
	.handler	= ksmbd_info_set_pipe_info,
	.owner		= THIS_MODULE,
};

static struct ksmbd_info_handler ksmbd_pipe_remote_set_handler = {
	.info_type	= SMB2_O_INFO_FILE,
	.info_class	= FILE_PIPE_REMOTE_INFORMATION,
	.op		= KSMBD_INFO_SET,
	.handler	= ksmbd_info_set_pipe_remote,
	.owner		= THIS_MODULE,
};

static struct ksmbd_info_handler ksmbd_mailslot_set_handler = {
	.info_type	= SMB2_O_INFO_FILE,
	.info_class	= FILE_MAILSLOT_SET_INFORMATION,
	.op		= KSMBD_INFO_SET,
	.handler	= ksmbd_info_set_mailslot,
	.owner		= THIS_MODULE,
};

static struct ksmbd_info_handler ksmbd_move_cluster_set_handler = {
	.info_type	= SMB2_O_INFO_FILE,
	.info_class	= FILE_MOVE_CLUSTER_INFORMATION,
	.op		= KSMBD_INFO_SET,
	.handler	= ksmbd_info_set_noop_consume,
	.owner		= THIS_MODULE,
};

static struct ksmbd_info_handler ksmbd_tracking_set_handler = {
	.info_type	= SMB2_O_INFO_FILE,
	.info_class	= FILE_TRACKING_INFORMATION,
	.op		= KSMBD_INFO_SET,
	.handler	= ksmbd_info_set_noop_consume,
	.owner		= THIS_MODULE,
};

static struct ksmbd_info_handler ksmbd_short_name_set_handler = {
	.info_type	= SMB2_O_INFO_FILE,
	.info_class	= FILE_SHORT_NAME_INFORMATION,
	.op		= KSMBD_INFO_SET,
	.handler	= ksmbd_info_set_noop_consume,
	.owner		= THIS_MODULE,
};

static struct ksmbd_info_handler ksmbd_sfio_reserve_set_handler = {
	.info_type	= SMB2_O_INFO_FILE,
	.info_class	= FILE_SFIO_RESERVE_INFORMATION,
	.op		= KSMBD_INFO_SET,
	.handler	= ksmbd_info_set_noop_consume,
	.owner		= THIS_MODULE,
};

static struct ksmbd_info_handler ksmbd_sfio_volume_set_handler = {
	.info_type	= SMB2_O_INFO_FILE,
	.info_class	= FILE_SFIO_VOLUME_INFORMATION,
	.op		= KSMBD_INFO_SET,
	.handler	= ksmbd_info_set_noop_consume,
	.owner		= THIS_MODULE,
};

static struct ksmbd_info_handler ksmbd_valid_data_length_set_handler = {
	.info_type	= SMB2_O_INFO_FILE,
	.info_class	= FILE_VALID_DATA_LENGTH_INFORMATION,
	.op		= KSMBD_INFO_SET,
	.handler	= ksmbd_info_set_valid_data_length,
	.owner		= THIS_MODULE,
};

static struct ksmbd_info_handler ksmbd_normalized_name_get_handler = {
	.info_type	= SMB2_O_INFO_FILE,
	.info_class	= FILE_NORMALIZED_NAME_INFORMATION,
	.op		= KSMBD_INFO_GET,
	.handler	= ksmbd_info_get_normalized_name,
	.owner		= THIS_MODULE,
};

static struct ksmbd_info_handler ksmbd_process_ids_get_handler = {
	.info_type	= SMB2_O_INFO_FILE,
	.info_class	= FILE_PROCESS_IDS_USING_FILE_INFORMATION,
	.op		= KSMBD_INFO_GET,
	.handler	= ksmbd_info_get_process_ids_using_file,
	.owner		= THIS_MODULE,
};

static struct ksmbd_info_handler ksmbd_network_physical_name_get_handler = {
	.info_type	= SMB2_O_INFO_FILE,
	.info_class	= FILE_NETWORK_PHYSICAL_NAME_INFORMATION,
	.op		= KSMBD_INFO_GET,
	.handler	= ksmbd_info_get_network_physical_name,
	.owner		= THIS_MODULE,
};

static struct ksmbd_info_handler ksmbd_volume_name_get_handler = {
	.info_type	= SMB2_O_INFO_FILE,
	.info_class	= FILE_VOLUME_NAME_INFORMATION,
	.op		= KSMBD_INFO_GET,
	.handler	= ksmbd_info_get_volume_name,
	.owner		= THIS_MODULE,
};

static struct ksmbd_info_handler ksmbd_is_remote_device_get_handler = {
	.info_type	= SMB2_O_INFO_FILE,
	.info_class	= FILE_IS_REMOTE_DEVICE_INFORMATION,
	.op		= KSMBD_INFO_GET,
	.handler	= ksmbd_info_get_is_remote_device,
	.owner		= THIS_MODULE,
};

static struct ksmbd_info_handler ksmbd_case_sensitive_get_handler = {
	.info_type	= SMB2_O_INFO_FILE,
	.info_class	= FILE_CASE_SENSITIVE_INFORMATION,
	.op		= KSMBD_INFO_GET,
	.handler	= ksmbd_info_get_case_sensitive,
	.owner		= THIS_MODULE,
};

static struct ksmbd_info_handler ksmbd_case_sensitive_set_handler = {
	.info_type	= SMB2_O_INFO_FILE,
	.info_class	= FILE_CASE_SENSITIVE_INFORMATION,
	.op		= KSMBD_INFO_SET,
	.handler	= ksmbd_info_set_case_sensitive,
	.owner		= THIS_MODULE,
};

static struct ksmbd_info_handler ksmbd_remote_protocol_get_handler = {
	.info_type	= SMB2_O_INFO_FILE,
	.info_class	= FILE_REMOTE_PROTOCOL_INFORMATION,
	.op		= KSMBD_INFO_GET,
	.handler	= ksmbd_info_get_remote_protocol,
	.owner		= THIS_MODULE,
};

static struct ksmbd_info_handler ksmbd_quota_get_handler = {
	.info_type	= SMB2_O_INFO_QUOTA,
	.info_class	= FILE_QUOTA_INFORMATION,
	.op		= KSMBD_INFO_GET,
	.handler	= ksmbd_info_get_quota,
	.owner		= THIS_MODULE,
};

static struct ksmbd_info_handler ksmbd_quota_set_handler = {
	.info_type	= SMB2_O_INFO_QUOTA,
	.info_class	= FILE_QUOTA_INFORMATION,
	.op		= KSMBD_INFO_SET,
	.handler	= ksmbd_info_set_quota,
	.owner		= THIS_MODULE,
};

static struct ksmbd_info_handler *builtin_info_handlers[] = {
	&ksmbd_file_name_get_handler,
	&ksmbd_fs_control_set_handler,
	&ksmbd_fs_driver_path_get_handler,
	&ksmbd_fs_label_set_handler,
	&ksmbd_fs_object_id_set_handler,
	&ksmbd_pipe_info_get_handler,
	&ksmbd_pipe_local_info_get_handler,
	&ksmbd_pipe_remote_info_get_handler,
	&ksmbd_mailslot_query_get_handler,
	&ksmbd_hard_link_get_handler,
	&ksmbd_pipe_info_set_handler,
	&ksmbd_pipe_remote_set_handler,
	&ksmbd_mailslot_set_handler,
	&ksmbd_move_cluster_set_handler,
	&ksmbd_tracking_set_handler,
	&ksmbd_short_name_set_handler,
	&ksmbd_sfio_reserve_set_handler,
	&ksmbd_sfio_volume_set_handler,
	&ksmbd_valid_data_length_set_handler,
	&ksmbd_normalized_name_get_handler,
	&ksmbd_process_ids_get_handler,
	&ksmbd_network_physical_name_get_handler,
	&ksmbd_volume_name_get_handler,
	&ksmbd_is_remote_device_get_handler,
	&ksmbd_case_sensitive_get_handler,
	&ksmbd_case_sensitive_set_handler,
	&ksmbd_remote_protocol_get_handler,
	&ksmbd_quota_get_handler,
	&ksmbd_quota_set_handler,
};

/**
 * ksmbd_info_init() - Initialize the info-level dispatch table
 *
 * Registers built-in info-level handlers.
 *
 * Return: 0 on success, negative errno on failure
 */
int ksmbd_info_init(void)
{
	int i, ret;

	hash_init(info_handlers);

	for (i = 0; i < ARRAY_SIZE(builtin_info_handlers); i++) {
		ret = ksmbd_register_info_handler(builtin_info_handlers[i]);
		if (ret) {
			pr_err("Failed to register info handler (type=%u, class=%u, op=%d): %d\n",
			       builtin_info_handlers[i]->info_type,
			       builtin_info_handlers[i]->info_class,
			       builtin_info_handlers[i]->op, ret);
			goto err_unregister;
		}
	}

	ksmbd_debug(SMB, "Info-level handler table initialized\n");
	return 0;

err_unregister:
	while (--i >= 0)
		ksmbd_unregister_info_handler(builtin_info_handlers[i]);
	return ret;
}

/**
 * ksmbd_info_exit() - Tear down the info-level dispatch table
 *
 * Unregisters all built-in info-level handlers.
 */
void ksmbd_info_exit(void)
{
	int i;

	for (i = ARRAY_SIZE(builtin_info_handlers) - 1; i >= 0; i--)
		ksmbd_unregister_info_handler(builtin_info_handlers[i]);
}
