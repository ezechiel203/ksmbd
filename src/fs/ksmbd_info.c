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

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

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
#include <linux/version.h>
#include <linux/fileattr.h>

#include "ksmbd_info.h"
#include "glob.h"
#include "smb2pdu.h"
#include "connection.h"
#include "misc.h"
#include "oplock.h"
#include "server.h"
#include "mgmt/share_config.h"
#include "smb_common.h"
#include "vfs_cache.h"
#include "xattr.h"
#include "compat.h"
#include "vfs.h"

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
	ksmbd_debug(SMB,
		    "SET_INFO noop: silently consuming %u bytes (unimplemented info class)\n",
		    buf_len);
	*out_len = buf_len;
	return 0;
}

/*
 * L-03/L-04: Handler for SET_INFO classes that are accepted by the protocol
 * but not supported by ksmbd (e.g. FileShortNameInformation, FileFsLabel).
 * Return STATUS_NOT_SUPPORTED so clients know the operation is unavailable
 * rather than silently discarding the request.
 */
static int ksmbd_info_set_not_supported(struct ksmbd_work *work,
					struct ksmbd_file *fp,
					void *buf,
					unsigned int buf_len,
					unsigned int *out_len)
{
	*out_len = 0;
	return -EOPNOTSUPP;
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

/*
 * Context for iterate_dir callback that collects filenames whose inode
 * number matches a target inode (hard link siblings).
 */
struct ksmbd_hardlink_scan_ctx {
	struct dir_context ctx;
	u64 target_ino;          /* inode number to match */

	/* Output buffer management */
	char *buf;               /* response buffer start */
	unsigned int buf_len;    /* total buffer capacity */
	unsigned int written;    /* bytes written so far */

	/* Entries written */
	u32 entries;

	/* Pointer to previous entry for NextEntryOffset chain */
	struct smb2_file_link_entry_info *prev_entry;

	/* NLS for UTF-16 conversion */
	struct nls_table *nls;

	/* Total bytes needed (even if we ran out of buffer space) */
	u32 bytes_needed;

	int error;
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
static bool ksmbd_hardlink_filldir(struct dir_context *ctx,
				   const char *name, int namlen,
				   loff_t offset, u64 ino,
				   unsigned int d_type)
#else
static int ksmbd_hardlink_filldir(struct dir_context *ctx,
				  const char *name, int namlen,
				  loff_t offset, u64 ino,
				  unsigned int d_type)
#endif
{
	struct ksmbd_hardlink_scan_ctx *scan_ctx =
		container_of(ctx, struct ksmbd_hardlink_scan_ctx, ctx);
	struct smb2_file_link_entry_info *entry;
	unsigned int entry_hdr_size;
	unsigned int name_bytes;
	unsigned int entry_total;
	int conv_len;

	/* Only interested in entries matching the target inode */
	if (ino != scan_ctx->target_ino)
		goto cont;

	/* Skip . and .. */
	if (namlen <= 2 && name[0] == '.' &&
	    (namlen == 1 || name[1] == '.'))
		goto cont;

	entry_hdr_size = offsetof(struct smb2_file_link_entry_info, FileName);

	/*
	 * Estimate name size: worst case is 2 bytes per source byte.
	 * Actual conversion may differ, so we pre-convert into a temporary
	 * buffer to get the real size.
	 */
	{
		__le16 *tmp_utf16;
		unsigned int max_chars;

		/* Allocate temporary buffer for UTF-16 conversion */
		tmp_utf16 = kcalloc(namlen + 1, sizeof(__le16),
				    KSMBD_DEFAULT_GFP);
		if (!tmp_utf16) {
			scan_ctx->error = -ENOMEM;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
			return false;
#else
			return -ENOMEM;
#endif
		}

		max_chars = namlen;
		conv_len = smbConvertToUTF16(tmp_utf16, name, max_chars,
					     scan_ctx->nls, 0);
		if (conv_len < 0) {
			kfree(tmp_utf16);
			goto cont;
		}
		name_bytes = (unsigned int)conv_len * sizeof(__le16);
		/* Align to 8 bytes for NextEntryOffset chain */
		entry_total = ALIGN(entry_hdr_size + name_bytes, 8);

		/* Track how much space this would need */
		scan_ctx->bytes_needed += entry_total;

		/* Check if we have room in the output buffer */
		if (scan_ctx->written + sizeof(struct smb2_file_links_info) +
		    entry_total <= scan_ctx->buf_len) {
			entry = (struct smb2_file_link_entry_info *)
				(scan_ctx->buf +
				 sizeof(struct smb2_file_links_info) +
				 scan_ctx->written);

			/* Link previous entry to this one */
			if (scan_ctx->prev_entry) {
				scan_ctx->prev_entry->NextEntryOffset =
					cpu_to_le32(entry_total);
			}

			entry->NextEntryOffset = 0;
			memset(entry->ParentFileId, 0,
			       sizeof(entry->ParentFileId));
			entry->FileNameLength = cpu_to_le32(name_bytes);
			memcpy(entry->FileName, tmp_utf16, name_bytes);

			scan_ctx->written += entry_total;
			scan_ctx->entries++;
			scan_ctx->prev_entry = entry;
		}

		kfree(tmp_utf16);
	}

cont:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
	return true;
#else
	return 0;
#endif
}

static int ksmbd_info_get_hard_link(struct ksmbd_work *work,
				    struct ksmbd_file *fp,
				    void *buf,
				    unsigned int buf_len,
				    unsigned int *out_len)
{
	struct ksmbd_conn *conn = work->conn;
	struct smb2_file_links_info *links_info;
	struct kstat stat;
	struct path parent_path;
	struct file *parent_filp;
	struct ksmbd_hardlink_scan_ctx scan_ctx;
	int ret;

	if (!fp)
		return -EINVAL;

	/* Need at least the links_info header */
	if (buf_len < sizeof(*links_info))
		return -ENOSPC;

	ret = ksmbd_vfs_getattr(&fp->filp->f_path, &stat);
	if (ret)
		return ret;

	links_info = (struct smb2_file_links_info *)buf;

	/*
	 * If nlink == 1, fast path: only one link exists (the current file).
	 * Return a single entry using the current file's name.
	 */
	if (stat.nlink <= 1) {
		struct smb2_file_link_entry_info *entry_info;
		char *filename;
		__le16 *utf16_name;
		unsigned int name_bytes;
		unsigned int needed;
		int conv_len;

		filename = convert_to_nt_pathname(work->tcon->share_conf,
						  &fp->filp->f_path);
		if (IS_ERR(filename))
			return PTR_ERR(filename);

		/* Use just the base name (last component after last '\') */
		{
			char *base = strrchr(filename, '\\');
			if (base)
				base++;
			else
				base = filename;

			utf16_name = kcalloc(PATH_MAX + 1, sizeof(__le16),
					     KSMBD_DEFAULT_GFP);
			if (!utf16_name) {
				kfree(filename);
				return -ENOMEM;
			}

			conv_len = smbConvertToUTF16(utf16_name, base, PATH_MAX,
						     conn->local_nls, 0);
			if (conv_len < 0) {
				kfree(utf16_name);
				kfree(filename);
				return -EINVAL;
			}
		}

		name_bytes = conv_len * sizeof(__le16);
		needed = sizeof(*links_info) +
			 offsetof(struct smb2_file_link_entry_info, FileName) +
			 name_bytes;

		if (buf_len < needed) {
			kfree(utf16_name);
			kfree(filename);
			links_info->BytesNeeded = cpu_to_le32(needed);
			links_info->EntriesReturned = 0;
			*out_len = sizeof(*links_info);
			return -ENOSPC;
		}

		entry_info = (struct smb2_file_link_entry_info *)
			((char *)buf + sizeof(*links_info));
		links_info->BytesNeeded = cpu_to_le32(needed);
		links_info->EntriesReturned = cpu_to_le32(1);

		entry_info->NextEntryOffset = 0;
		memset(entry_info->ParentFileId, 0,
		       sizeof(entry_info->ParentFileId));
		entry_info->FileNameLength = cpu_to_le32(name_bytes);
		memcpy(entry_info->FileName, utf16_name, name_bytes);
		*out_len = needed;

		kfree(utf16_name);
		kfree(filename);
		return 0;
	}

	/*
	 * nlink > 1: enumerate all sibling hard links by opening the parent
	 * directory and iterating its entries for matching inode numbers.
	 */
	parent_path.mnt = fp->filp->f_path.mnt;
	parent_path.dentry = dget_parent(fp->filp->f_path.dentry);

	parent_filp = dentry_open(&parent_path, O_RDONLY | O_DIRECTORY,
				  current_cred());
	dput(parent_path.dentry);
	if (IS_ERR(parent_filp)) {
		/*
		 * Cannot open parent — fall back to single-entry response.
		 * This can happen if the client lacks read access to the parent.
		 */
		goto fallback_single;
	}

	memset(&scan_ctx, 0, sizeof(scan_ctx));
	scan_ctx.target_ino = stat.ino;
	scan_ctx.buf = (char *)buf;
	scan_ctx.buf_len = buf_len;
	scan_ctx.written = 0;
	scan_ctx.entries = 0;
	scan_ctx.prev_entry = NULL;
	scan_ctx.nls = conn->local_nls;
	scan_ctx.bytes_needed = 0;
	set_ctx_actor(&scan_ctx.ctx, ksmbd_hardlink_filldir);

	ret = iterate_dir(parent_filp, &scan_ctx.ctx);
	fput(parent_filp);

	if (scan_ctx.error) {
		if (scan_ctx.error == -ENOMEM)
			return -ENOMEM;
		goto fallback_single;
	}

	if (scan_ctx.entries == 0) {
		/* Nothing found in parent (race?) -- fall back */
		goto fallback_single;
	}

	links_info->BytesNeeded =
		cpu_to_le32(sizeof(*links_info) + scan_ctx.bytes_needed);
	links_info->EntriesReturned = cpu_to_le32(scan_ctx.entries);
	*out_len = sizeof(*links_info) + scan_ctx.written;
	return 0;

fallback_single:
	/*
	 * Fallback: return the single current-name entry.
	 * Same as the nlink==1 fast path above.
	 */
	{
		struct smb2_file_link_entry_info *entry_info;
		char *filename;
		char *base;
		__le16 *utf16_name;
		unsigned int name_bytes;
		unsigned int needed;
		int conv_len;

		filename = convert_to_nt_pathname(work->tcon->share_conf,
						  &fp->filp->f_path);
		if (IS_ERR(filename))
			return PTR_ERR(filename);

		base = strrchr(filename, '\\');
		if (base)
			base++;
		else
			base = filename;

		utf16_name = kcalloc(PATH_MAX + 1, sizeof(__le16),
				     KSMBD_DEFAULT_GFP);
		if (!utf16_name) {
			kfree(filename);
			return -ENOMEM;
		}

		conv_len = smbConvertToUTF16(utf16_name, base, PATH_MAX,
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
			links_info->BytesNeeded = cpu_to_le32(needed);
			links_info->EntriesReturned = 0;
			*out_len = sizeof(*links_info);
			return -ENOSPC;
		}

		entry_info = (struct smb2_file_link_entry_info *)
			((char *)buf + sizeof(*links_info));
		links_info->BytesNeeded = cpu_to_le32(needed);
		links_info->EntriesReturned = cpu_to_le32(1);

		entry_info->NextEntryOffset = 0;
		memset(entry_info->ParentFileId, 0,
		       sizeof(entry_info->ParentFileId));
		entry_info->FileNameLength = cpu_to_le32(name_bytes);
		memcpy(entry_info->FileName, utf16_name, name_bytes);
		*out_len = needed;

		kfree(utf16_name);
		kfree(filename);
		return 0;
	}
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

	/*
	 * FILE_NORMALIZED_NAME_INFORMATION is valid for SMB 3.0 and
	 * SMB 3.1.1+ (MS-SMB2 §2.2.37).  Return -ENOSYS for
	 * 2.0.2, 2.1, and 3.0.2 dialects.
	 */
	if (conn->dialect != SMB30_PROT_ID && conn->dialect < SMB311_PROT_ID)
		return -ENOSYS;

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
	 * Per MS-FSCC 2.1.5 / smbtorture expectations: the root of
	 * a share (just "\") should return an empty (zero-length)
	 * normalized name.
	 */
	if (!strcmp(filename, "\\")) {
		*name_len_ptr = 0;
		*out_len = sizeof(__le32);
		kfree(filename);
		return 0;
	}

	/*
	 * Per MS-FSCC 2.1.7, the normalized name is relative to the
	 * share root and does not include a leading path separator.
	 * convert_to_nt_pathname returns a leading '\' which we skip.
	 *
	 * For stream handles, append the stream name (":streamname")
	 * to match the format the client used when opening.
	 */
	{
		char *name_start = filename;
		char *full_name = NULL;

		if (*name_start == '\\')
			name_start++;

		/*
		 * If this is a stream handle, append the stream name.
		 * fp->stream.name has the xattr format:
		 *   "user.DosStream.<name>:<type>"
		 * Extract just the "<name>" part.
		 */
		if (ksmbd_stream_fd(fp) && fp->stream.name) {
			const char *sname;
			const char *colon;
			size_t sname_len;

			sname = &fp->stream.name[XATTR_NAME_STREAM_LEN];
			/* Strip the :$DATA or :$INDEX_ALLOCATION suffix */
			colon = strrchr(sname, ':');
			sname_len = colon ? (size_t)(colon - sname) : strlen(sname);

			full_name = kasprintf(KSMBD_DEFAULT_GFP,
					      "%s:%.*s", name_start,
					      (int)sname_len, sname);
			if (!full_name) {
				kfree(filename);
				return -ENOMEM;
			}
			name_start = full_name;
		}

		conv_len = smbConvertToUTF16(
				(__le16 *)((char *)buf + sizeof(__le32)),
				name_start,
				max_utf16_chars,
				conn->local_nls,
				0);

		kfree(full_name);
	}
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

	/*
	 * QS-21: FileVolumeNameInformation must return the share name (the
	 * volume label), not the UNC path.  MS-FSCC §2.5.9 specifies that
	 * VolumeName is the label of the volume, not a path.
	 */
	name_len_ptr = (__le32 *)buf;
	conv_len = smbConvertToUTF16((__le16 *)((char *)buf + sizeof(__le32)),
				     share->name, max_utf16_chars,
				     conn->local_nls, 0);
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
	struct file_kattr fa;
	u32 flags = 0;
	int ret;

	if (buf_len < sizeof(*info))
		return -ENOSPC;

	/*
	 * QS-15: FileCaseSensitiveInformation GET must reflect the actual
	 * filesystem case-sensitivity state.  Read the inode flags via
	 * vfs_fileattr_get(): if FS_CASEFOLD_FL is NOT set the directory is
	 * case-sensitive, so return FILE_CS_FLAG_CASE_SENSITIVE_DIR (0x01).
	 * If the filesystem does not support fileattr, fall back to 0.
	 */
	if (fp && fp->filp) {
		memset(&fa, 0, sizeof(fa));
		ret = vfs_fileattr_get(fp->filp->f_path.dentry, &fa);
		if (!ret && !(fa.flags & FS_CASEFOLD_FL))
			flags = FILE_CS_FLAG_CASE_SENSITIVE_DIR;
	}

	info = (struct smb2_file_case_sensitive_info *)buf;
	info->Flags = cpu_to_le32(flags);
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
	struct file_kattr fa;
	struct dentry *dentry;
	u32 flags;
	u32 cur_iflags;
	int ret;

	if (!fp)
		return -EINVAL;

	if (buf_len < sizeof(*info))
		return -EMSGSIZE;

	info = (struct smb2_file_case_sensitive_info *)buf;
	flags = le32_to_cpu(info->Flags);
	if (flags & ~FILE_CS_FLAG_CASE_SENSITIVE_DIR)
		return -EINVAL;

	dentry = fp->filp->f_path.dentry;

	/*
	 * Read current file attributes so we can modify just the
	 * FS_CASEFOLD_FL bit without disturbing other flags.
	 */
	memset(&fa, 0, sizeof(fa));
	ret = vfs_fileattr_get(dentry, &fa);
	if (ret) {
		/*
		 * If the filesystem does not support fileattr, treat as
		 * not supported.
		 */
		if (ret == -ENOTTY || ret == -EOPNOTSUPP)
			return -EOPNOTSUPP;
		return ret;
	}

	cur_iflags = fa.flags;

	if (flags & FILE_CS_FLAG_CASE_SENSITIVE_DIR) {
		/* Enable case-sensitive (disable casefolding) */
		cur_iflags &= ~FS_CASEFOLD_FL;
	} else {
		/* Disable case-sensitive (enable casefolding) */
		cur_iflags |= FS_CASEFOLD_FL;
	}

	/*
	 * Only issue the set call if the flag actually changed, to
	 * avoid unnecessary permission checks.
	 */
	if (cur_iflags == fa.flags) {
		*out_len = sizeof(*info);
		return 0;
	}

	fileattr_fill_flags(&fa, cur_iflags);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	ret = vfs_fileattr_set(file_mnt_idmap(fp->filp), dentry, &fa);
#else
	ret = vfs_fileattr_set(file_mnt_user_ns(fp->filp), dentry, &fa);
#endif
	if (ret) {
		if (ret == -EOPNOTSUPP || ret == -ENOTTY)
			return -EOPNOTSUPP;
		return ret;
	}

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
	/*
	 * L-04: Volume label changes are not persisted by ksmbd.
	 * Return STATUS_NOT_SUPPORTED so clients know the label is read-only
	 * rather than appearing to succeed without effect.
	 */
	*out_len = 0;
	return -EOPNOTSUPP;
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

/*
 * ksmbd_info_set_quota - Quota SET handler (stub)
 *
 * Quota setting is not implemented in ksmbd.  Return success for
 * compatibility with Windows clients that may attempt to set quota
 * information.  The request payload is consumed but no quota is
 * actually enforced on the underlying filesystem.
 */
static int ksmbd_info_set_quota(struct ksmbd_work *work,
				struct ksmbd_file *fp,
				void *buf,
				unsigned int buf_len,
				unsigned int *out_len)
{
	/*
	 * L-01: Quota enforcement is not implemented.  Accept the
	 * request as a no-op for interoperability with Windows clients
	 * that probe or set quota information.
	 */
	*out_len = 0;
	return 0;
}

/*
 * G.3 — FileStatInformation (class 70 = 0x46, MS-FSCC §2.4.47)
 *
 * SMB3.1.1 extension providing large-file stat information.
 * Layout (56 bytes):
 *   FileId           __le64  inode number
 *   CreationTime     __le64  FILETIME
 *   LastAccessTime   __le64  FILETIME
 *   LastWriteTime    __le64  FILETIME
 *   ChangeTime       __le64  FILETIME
 *   AllocationSize   __le64  blocks * 512
 *   EndOfFile        __le64  file size
 *   NumberOfLinks    __le32  nlink
 *   DeletePending    __u8
 *   Directory        __u8
 *   Reserved         __le16  (padding)
 */
struct smb2_file_stat_info {
	__le64 FileId;
	__le64 CreationTime;
	__le64 LastAccessTime;
	__le64 LastWriteTime;
	__le64 ChangeTime;
	__le64 AllocationSize;
	__le64 EndOfFile;
	__le32 NumberOfLinks;
	__u8   DeletePending;
	__u8   Directory;
	__le16 Reserved;
} __packed; /* 56 bytes */

static int ksmbd_info_get_file_stat(struct ksmbd_work *work,
				    struct ksmbd_file *fp,
				    void *buf,
				    unsigned int buf_len,
				    unsigned int *out_len)
{
	struct smb2_file_stat_info *info;
	struct kstat stat;
	u64 time;
	int ret;
	unsigned int delete_pending;

	if (!fp)
		return -EINVAL;

	if (buf_len < sizeof(*info))
		return -ENOSPC;

	ret = ksmbd_vfs_getattr(&fp->filp->f_path, &stat);
	if (ret)
		return ret;

	delete_pending = ksmbd_inode_pending_delete(fp);
	info = (struct smb2_file_stat_info *)buf;
	memset(info, 0, sizeof(*info));

	info->FileId = cpu_to_le64(stat.ino);
	info->CreationTime = cpu_to_le64(fp->create_time);

	time = ksmbd_UnixTimeToNT(stat.atime);
	info->LastAccessTime = cpu_to_le64(time);
	time = ksmbd_UnixTimeToNT(stat.mtime);
	info->LastWriteTime = cpu_to_le64(time);
	time = ksmbd_UnixTimeToNT(stat.ctime);
	info->ChangeTime = cpu_to_le64(time);

	if (ksmbd_stream_fd(fp) == false) {
		info->AllocationSize =
			cpu_to_le64(ksmbd_alloc_size(fp, &stat));
		info->EndOfFile =
			S_ISDIR(stat.mode) ? 0 : cpu_to_le64(stat.size);
	} else {
		info->AllocationSize = cpu_to_le64(fp->stream.size);
		info->EndOfFile = cpu_to_le64(fp->stream.size);
	}

	info->NumberOfLinks =
		cpu_to_le32(get_nlink(&stat) - delete_pending);
	info->DeletePending = delete_pending;
	info->Directory = S_ISDIR(stat.mode) ? 1 : 0;
	info->Reserved = 0;

	*out_len = sizeof(*info);
	return 0;
}

/*
 * G.4 — FileStatLxInformation (class 71 = 0x47, MS-FSCC §2.4.48)
 *
 * WSL/POSIX extension extending FileStatInformation with Linux-specific
 * fields.  Try to read LxUid/LxGid/LxMode from xattrs (user.LXUID,
 * user.LXGID, user.LXMOD); fall back to uid/gid/mode from kstat.
 *
 * Note: FILE_CASE_SENSITIVE_INFORMATION is also numbered 71 in this
 * codebase and is registered separately in the dispatch table under
 * the same class number.  Since the dispatch table uses a hash lookup
 * and the FILE_CASE_SENSITIVE handler is registered after this one,
 * the CASE_SENSITIVE handler (from ksmbd_case_sensitive_get_handler)
 * will shadow this entry.  FileStatLxInformation is therefore only
 * reachable when explicitly requested via a FILE_STAT_LX_INFORMATION
 * switch case added in smb2_get_info_file().
 */
#define KSMBD_XATTR_NAME_LXUID  "user.LXUID"
#define KSMBD_XATTR_NAME_LXGID  "user.LXGID"
#define KSMBD_XATTR_NAME_LXMOD  "user.LXMOD"

struct smb2_file_stat_lx_info {
	__le64 FileId;
	__le64 CreationTime;
	__le64 LastAccessTime;
	__le64 LastWriteTime;
	__le64 ChangeTime;
	__le64 AllocationSize;
	__le64 EndOfFile;
	__le32 NumberOfLinks;
	__u8   DeletePending;
	__u8   Directory;
	__le16 Reserved;
	__le32 LxFlags;
	__le32 LxUid;
	__le32 LxGid;
	__le32 LxMode;
	__le32 LxDeviceIdMajor;
	__le32 LxDeviceIdMinor;
} __packed; /* 80 bytes */

int ksmbd_info_get_file_stat_lx(struct ksmbd_work *work,
				struct ksmbd_file *fp,
				void *buf,
				unsigned int buf_len,
				unsigned int *out_len)
{
	struct smb2_file_stat_lx_info *info;
	struct kstat stat;
	u64 time;
	int ret;
	unsigned int delete_pending;
	u32 lx_uid, lx_gid, lx_mode;
	char *xattr_val = NULL;
	ssize_t xattr_len;

	if (!fp)
		return -EINVAL;

	if (buf_len < sizeof(*info))
		return -ENOSPC;

	ret = ksmbd_vfs_getattr(&fp->filp->f_path, &stat);
	if (ret)
		return ret;

	delete_pending = ksmbd_inode_pending_delete(fp);
	info = (struct smb2_file_stat_lx_info *)buf;
	memset(info, 0, sizeof(*info));

	info->FileId = cpu_to_le64(stat.ino);
	info->CreationTime = cpu_to_le64(fp->create_time);

	time = ksmbd_UnixTimeToNT(stat.atime);
	info->LastAccessTime = cpu_to_le64(time);
	time = ksmbd_UnixTimeToNT(stat.mtime);
	info->LastWriteTime = cpu_to_le64(time);
	time = ksmbd_UnixTimeToNT(stat.ctime);
	info->ChangeTime = cpu_to_le64(time);

	if (ksmbd_stream_fd(fp) == false) {
		info->AllocationSize =
			cpu_to_le64(ksmbd_alloc_size(fp, &stat));
		info->EndOfFile =
			S_ISDIR(stat.mode) ? 0 : cpu_to_le64(stat.size);
	} else {
		info->AllocationSize = cpu_to_le64(fp->stream.size);
		info->EndOfFile = cpu_to_le64(fp->stream.size);
	}

	info->NumberOfLinks =
		cpu_to_le32(get_nlink(&stat) - delete_pending);
	info->DeletePending = delete_pending;
	info->Directory = S_ISDIR(stat.mode) ? 1 : 0;

	/*
	 * Read LxUid/LxGid/LxMode from xattrs; fall back to uid/gid/mode
	 * from kstat when xattrs are absent.
	 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	xattr_len = ksmbd_vfs_getxattr(file_mnt_idmap(fp->filp),
#else
	xattr_len = ksmbd_vfs_getxattr(file_mnt_user_ns(fp->filp),
#endif
				       fp->filp->f_path.dentry,
				       KSMBD_XATTR_NAME_LXUID, &xattr_val);
	if (xattr_len == sizeof(u32) && xattr_val)
		memcpy(&lx_uid, xattr_val, sizeof(u32));
	else
		lx_uid = from_kuid(&init_user_ns, stat.uid);
	kfree(xattr_val);
	xattr_val = NULL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	xattr_len = ksmbd_vfs_getxattr(file_mnt_idmap(fp->filp),
#else
	xattr_len = ksmbd_vfs_getxattr(file_mnt_user_ns(fp->filp),
#endif
				       fp->filp->f_path.dentry,
				       KSMBD_XATTR_NAME_LXGID, &xattr_val);
	if (xattr_len == sizeof(u32) && xattr_val)
		memcpy(&lx_gid, xattr_val, sizeof(u32));
	else
		lx_gid = from_kgid(&init_user_ns, stat.gid);
	kfree(xattr_val);
	xattr_val = NULL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	xattr_len = ksmbd_vfs_getxattr(file_mnt_idmap(fp->filp),
#else
	xattr_len = ksmbd_vfs_getxattr(file_mnt_user_ns(fp->filp),
#endif
				       fp->filp->f_path.dentry,
				       KSMBD_XATTR_NAME_LXMOD, &xattr_val);
	if (xattr_len == sizeof(u32) && xattr_val)
		memcpy(&lx_mode, xattr_val, sizeof(u32));
	else
		lx_mode = stat.mode;
	kfree(xattr_val);

	/* QSA-08: LxFlags encodes file type for WSL2 (MS-FSCC §2.4.48) */
	if (S_ISREG(stat.mode))
		info->LxFlags = cpu_to_le32(0x2);
	else if (S_ISDIR(stat.mode))
		info->LxFlags = cpu_to_le32(0x4);
	else if (S_ISLNK(stat.mode))
		info->LxFlags = cpu_to_le32(0x10);
	else if (S_ISCHR(stat.mode))
		info->LxFlags = cpu_to_le32(0x20);
	else if (S_ISBLK(stat.mode))
		info->LxFlags = cpu_to_le32(0x40);
	else if (S_ISFIFO(stat.mode))
		info->LxFlags = cpu_to_le32(0x80);
	else if (S_ISSOCK(stat.mode))
		info->LxFlags = cpu_to_le32(0x100);
	else
		info->LxFlags = 0;
	info->LxUid = cpu_to_le32(lx_uid);
	info->LxGid = cpu_to_le32(lx_gid);
	info->LxMode = cpu_to_le32(lx_mode);
	info->LxDeviceIdMajor = cpu_to_le32(MAJOR(stat.rdev));
	info->LxDeviceIdMinor = cpu_to_le32(MINOR(stat.rdev));

	*out_len = sizeof(*info);
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
	/* L-03: MS-FSCC §2.4.41 — short name changes not supported; return NOT_SUPPORTED */
	.info_class	= FILE_SHORT_NAME_INFORMATION,
	.op		= KSMBD_INFO_SET,
	.handler	= ksmbd_info_set_not_supported,
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

static struct ksmbd_info_handler ksmbd_file_stat_get_handler = {
	.info_type	= SMB2_O_INFO_FILE,
	.info_class	= FILE_STAT_INFORMATION,
	.op		= KSMBD_INFO_GET,
	.handler	= ksmbd_info_get_file_stat,
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
	&ksmbd_file_stat_get_handler,
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
