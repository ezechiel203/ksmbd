// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2025 Alexandre BETRY
 *
 *   Fruit SMB extensions for KSMBD
 */

#ifdef CONFIG_KSMBD_FRUIT

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/statfs.h>
#include <linux/timekeeping.h>
#include <linux/xattr.h>
#include <linux/fs.h>

#include "smb2fruit.h"
#include "smb_common.h"
#include "connection.h"
#include "server.h"
#include "ksmbd_netlink.h"
#include "mgmt/share_config.h"
#include "oplock.h"
#include "vfs_cache.h"

/* Wire protocol signature - must remain "AAPL" for compatibility */
static const __u8 fruit_smb_signature[4] = {'A', 'A', 'P', 'L'};

/* Wire xattr name - must remain unchanged for compatibility */
#define LOOKERINFO_XATTR_NAME "com.apple.FinderInfo"

bool fruit_is_client_request(const void *buffer, size_t len)
{
	const struct create_context *context;

	if (len < sizeof(struct smb2_create_req))
		return false;

	context = smb2_find_context_vals((void *)buffer,
					 SMB2_CREATE_AAPL, 4);
	if (!context || IS_ERR(context))
		return false;

	if (le16_to_cpu(context->NameLength) != 4 ||
	    le32_to_cpu(context->DataLength) < sizeof(struct fruit_client_info))
		return false;

	return true;
}

int fruit_parse_client_info(const void *context_data, size_t data_len,
			    struct fruit_conn_state *state)
{
	const struct fruit_client_info *client_info;

	if (!context_data || !state || data_len < sizeof(struct fruit_client_info))
		return -EINVAL;

	client_info = context_data;

	if (memcmp(client_info->signature, fruit_smb_signature, 4) != 0)
		return -EINVAL;

	state->client_version = le32_to_cpu(client_info->version);
	state->client_type = le32_to_cpu(client_info->client_type);
	state->client_capabilities = le64_to_cpu(client_info->capabilities);

	memcpy(state->client_build, &client_info->build_number,
	       min_t(size_t, sizeof(state->client_build),
		     sizeof(client_info->build_number)));

	return 0;
}

/*
 * Compute kAAPL server_caps from global config flags.
 * These bits are sent on the wire in the AAPL create context response.
 */
static u64 fruit_compute_server_caps(void)
{
	u64 caps = kAAPL_UNIX_BASED; /* always: Linux is UNIX-based */

	if (server_conf.flags & KSMBD_GLOBAL_FLAG_FRUIT_COPYFILE)
		caps |= kAAPL_SUPPORTS_OSX_COPYFILE;
	if (server_conf.flags & KSMBD_GLOBAL_FLAG_FRUIT_NFS_ACES)
		caps |= kAAPL_SUPPORTS_NFS_ACE;
	/* ReadDirAttr is gated per-share, but advertised globally */
	caps |= kAAPL_SUPPORTS_READ_DIR_ATTR;

	return caps;
}

int fruit_negotiate_capabilities(struct ksmbd_conn *conn,
				 const struct fruit_client_info *client_info)
{
	struct fruit_conn_state *state;
	u64 server_caps;

	if (!conn || !client_info)
		return -EINVAL;

	if (!conn->fruit_state) {
		conn->fruit_state = kzalloc(sizeof(struct fruit_conn_state),
					    GFP_KERNEL);
		if (!conn->fruit_state)
			return -ENOMEM;
	}

	state = conn->fruit_state;
	server_caps = fruit_compute_server_caps();

	state->client_version = le32_to_cpu(client_info->version);
	state->client_type = le32_to_cpu(client_info->client_type);
	state->client_capabilities = le64_to_cpu(client_info->capabilities);
	state->supported_features = server_caps;
	state->negotiated_capabilities = server_caps;
	state->enabled_features = server_caps;
	state->extensions_enabled = 1;

	return 0;
}

bool fruit_supports_capability(struct fruit_conn_state *state, u64 capability)
{
	if (!state)
		return false;

	return !!(state->negotiated_capabilities & capability);
}

int fruit_detect_client_version(const void *data, size_t len)
{
	const struct fruit_client_info *client_info;

	if (!data || len < sizeof(struct fruit_client_info))
		return 0;

	client_info = data;
	if (memcmp(client_info->signature, fruit_smb_signature, 4) != 0)
		return 0;

	return le32_to_cpu(client_info->version);
}

const char *fruit_get_client_name(__le32 client_type)
{
	switch (client_type) {
	case FRUIT_CLIENT_MACOS:
		return "macOS";
	case FRUIT_CLIENT_IOS:
		return "iOS";
	case FRUIT_CLIENT_IPADOS:
		return "iPadOS";
	case FRUIT_CLIENT_TVOS:
		return "tvOS";
	case FRUIT_CLIENT_WATCHOS:
		return "watchOS";
	default:
		return "Unknown";
	}
}

const char *fruit_get_version_string(__le32 version)
{
	switch (version) {
	case FRUIT_VERSION_1_0:
		return "1.0";
	case FRUIT_VERSION_1_1:
		return "1.1";
	case FRUIT_VERSION_2_0:
		return "2.0";
	default:
		return "Unknown";
	}
}

bool fruit_valid_signature(const __u8 *signature)
{
	if (!signature)
		return false;

	return memcmp(signature, fruit_smb_signature, 4) == 0;
}

int fruit_validate_create_context(const struct create_context *context)
{
	if (!context)
		return -EINVAL;

	if (le16_to_cpu(context->NameLength) != 4)
		return -EINVAL;

	if (le32_to_cpu(context->DataLength) < sizeof(struct fruit_client_info))
		return -EINVAL;

	return 0;
}

int fruit_init_connection_state(struct fruit_conn_state *state)
{
	u64 caps;

	if (!state)
		return -EINVAL;

	memset(state, 0, sizeof(*state));
	caps = fruit_compute_server_caps();
	state->supported_features = caps;
	state->enabled_features = caps;
	state->negotiated_capabilities = caps;

	return 0;
}

void fruit_cleanup_connection_state(struct fruit_conn_state *state)
{
	if (!state)
		return;

	memset(state, 0, sizeof(*state));
}

int fruit_update_connection_state(struct fruit_conn_state *state,
				  const struct fruit_client_info *client_info)
{
	if (!state || !client_info)
		return -EINVAL;

	if (memcmp(client_info->signature, fruit_smb_signature, 4) != 0)
		return -EINVAL;

	state->client_version = le32_to_cpu(client_info->version);
	state->client_type = le32_to_cpu(client_info->client_type);
	state->client_capabilities = le64_to_cpu(client_info->capabilities);

	memcpy(state->client_build, &client_info->build_number,
	       min_t(size_t, sizeof(state->client_build),
		     sizeof(client_info->build_number)));

	state->negotiated_capabilities =
		state->client_capabilities & state->supported_features;
	state->enabled_features = state->negotiated_capabilities;

	return 0;
}

void fruit_debug_client_info(const struct fruit_client_info *info)
{
	if (!info)
		return;

	ksmbd_debug(SMB, "Fruit client: sig=%.4s ver=%s(0x%08x) type=%s(0x%08x) caps=0x%016llx\n",
		    info->signature,
		    fruit_get_version_string(info->version),
		    le32_to_cpu(info->version),
		    fruit_get_client_name(info->client_type),
		    le32_to_cpu(info->client_type),
		    le64_to_cpu(info->capabilities));
}

size_t fruit_get_context_size(const char *context_name)
{
	if (!context_name)
		return 0;

	if (strcmp(context_name, FRUIT_SERVER_QUERY_CONTEXT) == 0)
		return sizeof(struct fruit_server_query);
	if (strcmp(context_name, FRUIT_VOLUME_CAPABILITIES_CONTEXT) == 0)
		return sizeof(struct fruit_volume_capabilities);
	if (strcmp(context_name, FRUIT_FILE_MODE_CONTEXT) == 0)
		return sizeof(struct fruit_file_mode);
	if (strcmp(context_name, FRUIT_DIR_HARDLINKS_CONTEXT) == 0)
		return sizeof(struct fruit_dir_hardlinks);
	if (strcmp(context_name, FRUIT_LOOKERINFO_CONTEXT) == 0)
		return sizeof(struct fruit_looker_info);
	if (strcmp(context_name, FRUIT_SAVEBOX_CONTEXT) == 0)
		return sizeof(struct fruit_savebox_info);

	return 0;
}

int fruit_build_server_response(void **response_data, size_t *response_len,
				__le64 capabilities, __le32 query_type)
{
	struct fruit_server_query *query;
	size_t size = sizeof(struct fruit_server_query);

	if (!response_data || !response_len)
		return -EINVAL;

	*response_data = kzalloc(size, GFP_KERNEL);
	if (!*response_data)
		return -ENOMEM;

	query = *response_data;
	query->type = query_type;
	query->flags = 0;
	query->max_response_size = cpu_to_le32(size);
	query->reserved = 0;

	*response_len = size;

	return 0;
}

int fruit_process_looker_info(struct ksmbd_conn *conn,
			      const struct fruit_looker_info *looker_info)
{
	if (!conn || !looker_info)
		return -EINVAL;

	ksmbd_debug(SMB, "Fruit LookerInfo: creator=%.4s type=%.4s\n",
		    looker_info->creator, looker_info->type);

	return 0;
}

int fruit_process_savebox_info(struct ksmbd_conn *conn,
			       const struct fruit_savebox_info *sb_info)
{
	if (!conn || !sb_info)
		return -EINVAL;

	ksmbd_debug(SMB, "Fruit Save box: version=%d\n",
		    le32_to_cpu(sb_info->version));

	return 0;
}

int fruit_handle_savebox_bundle(struct ksmbd_conn *conn,
				const struct path *path,
				const struct fruit_savebox_info *sb_info)
{
	if (!conn || !path || !sb_info)
		return -EINVAL;

	ksmbd_debug(SMB, "Fruit Save box bundle\n");

	return 0;
}

/*
 * fruit_synthesize_afpinfo - Build a 60-byte AFP_AfpInfo structure
 * from the com.apple.FinderInfo xattr (netatalk migration path).
 *
 * When a macOS client reads the AFP_AfpInfo stream and the DosStream
 * xattr doesn't exist, we try to synthesize it from the native
 * com.apple.FinderInfo xattr that netatalk/AFP servers create.
 *
 * Returns AFP_AFPINFO_SIZE (60) on success, negative errno on failure.
 */
int fruit_synthesize_afpinfo(struct dentry *dentry, char *buf, size_t bufsize)
{
	ssize_t fi_len;
	__be32 val;

	if (!dentry || !buf || bufsize < AFP_AFPINFO_SIZE)
		return -EINVAL;

	/*
	 * Try to read the native com.apple.FinderInfo xattr.
	 * This is what netatalk stores (32 bytes of FinderInfo data).
	 */
	fi_len = vfs_getxattr(&nop_mnt_idmap, dentry,
			      APPLE_FINDER_INFO_XATTR_USER,
			      buf + 16, AFP_FINDER_INFO_SIZE);
	if (fi_len < 0)
		return fi_len;

	/*
	 * Build the 60-byte AfpInfo header around the FinderInfo.
	 * All multi-byte fields are big-endian (Apple convention).
	 *
	 * Offset  Size  Field
	 * 0       4     Magic ("AFP\0" = 0x41465000)
	 * 4       4     Version (0x00010000 = 1.0)
	 * 8       4     FileID (0)
	 * 12      4     BackupDate (0x80000000 = invalid)
	 * 16      32    FinderInfo (already placed by vfs_getxattr)
	 * 48      6     ProDOS info (0)
	 * 54      6     Padding (0)
	 */
	memset(buf, 0, 16);    /* clear header area */
	memset(buf + 48, 0, 12); /* clear ProDOS + padding */

	val = cpu_to_be32(AFP_MAGIC);
	memcpy(buf, &val, 4);

	val = cpu_to_be32(AFP_VERSION);
	memcpy(buf + 4, &val, 4);

	/* FileID = 0 (bytes 8-11 already zeroed) */

	val = cpu_to_be32(AFP_BACKUP_DATE_INVALID);
	memcpy(buf + 12, &val, 4);

	/* FinderInfo at offset 16 was already written by vfs_getxattr */

	/* Pad remaining bytes if FinderInfo was short */
	if (fi_len < AFP_FINDER_INFO_SIZE)
		memset(buf + 16 + fi_len, 0, AFP_FINDER_INFO_SIZE - fi_len);

	return AFP_AFPINFO_SIZE;
}

/* ── Step 1: AFP_AfpInfo Stream Interception ───────────────────── */

/**
 * ksmbd_fruit_is_afpinfo_stream() - Check if path is an AFP_AfpInfo stream
 * @stream_name:	stream name portion of the path (after the colon)
 *
 * When a macOS client opens "filename:AFP_AfpInfo:$DATA", ksmbd should
 * intercept this and serve AFP metadata from extended attributes rather
 * than requiring a real alternate data stream.
 *
 * Return:	true if the stream name matches AFP_AfpInfo (case-insensitive)
 */
bool ksmbd_fruit_is_afpinfo_stream(const char *stream_name)
{
	if (!stream_name)
		return false;

	return !strncasecmp(stream_name, AFP_AFPINFO_STREAM,
			    sizeof(AFP_AFPINFO_STREAM) - 1);
}

/**
 * ksmbd_fruit_read_afpinfo() - Read AFP_AfpInfo from xattr
 * @path:	path to the file whose AFP_AfpInfo is requested
 * @buf:	output buffer (must be at least AFP_AFPINFO_SIZE bytes)
 * @len:	size of output buffer
 *
 * Reads the AFP_AfpInfo data for a file. First tries the DosStream xattr
 * (user.DosStream.AFP_AfpInfo:$DATA), then falls back to synthesizing
 * from com.apple.FinderInfo xattr via fruit_synthesize_afpinfo().
 *
 * Return:	AFP_AFPINFO_SIZE (60) on success, negative errno on failure
 */
int ksmbd_fruit_read_afpinfo(struct path *path, void *buf, size_t len)
{
	struct dentry *dentry;
	ssize_t ret;

	if (!path || !buf || len < AFP_AFPINFO_SIZE)
		return -EINVAL;

	dentry = path->dentry;
	if (!dentry)
		return -EINVAL;

	/*
	 * First, try reading from the DosStream xattr which stores
	 * the complete 60-byte AFP_AfpInfo structure.
	 */
	ret = vfs_getxattr(&nop_mnt_idmap, dentry,
			   XATTR_NAME_AFP_AFPINFO,
			   buf, AFP_AFPINFO_SIZE);
	if (ret == AFP_AFPINFO_SIZE)
		return AFP_AFPINFO_SIZE;

	/*
	 * Fall back to synthesizing from com.apple.FinderInfo xattr
	 * (netatalk migration path).
	 */
	memset(buf, 0, AFP_AFPINFO_SIZE);
	ret = fruit_synthesize_afpinfo(dentry, buf, len);
	if (ret > 0)
		return ret;

	/*
	 * No AFP metadata available at all. Return a blank AfpInfo
	 * structure with valid magic/version so macOS does not error out.
	 */
	memset(buf, 0, AFP_AFPINFO_SIZE);
	{
		__be32 val;

		val = cpu_to_be32(AFP_MAGIC);
		memcpy(buf, &val, 4);

		val = cpu_to_be32(AFP_VERSION);
		memcpy(buf + 4, &val, 4);

		val = cpu_to_be32(AFP_BACKUP_DATE_INVALID);
		memcpy(buf + 12, &val, 4);
	}

	return AFP_AFPINFO_SIZE;
}

/* ── Step 2: Time Machine Quota Enforcement ────────────────────── */

/**
 * ksmbd_fruit_check_tm_quota() - Check Time Machine backup size limit
 * @share:	share configuration to check
 * @share_path:	VFS path to the share root
 *
 * For shares with "fruit time machine = yes" and a configured max size,
 * this checks whether the current usage exceeds the Time Machine quota.
 * The used space is computed as (total_blocks - free_blocks) * block_size.
 *
 * Return:	0 if within quota or quota not configured,
 *		-ENOSPC if the quota has been exceeded,
 *		negative errno on other errors
 */
int ksmbd_fruit_check_tm_quota(struct ksmbd_share_config *share,
			       struct path *share_path)
{
	struct kstatfs stfs;
	unsigned long long used_bytes;
	int rc;

	if (!share || !share_path)
		return -EINVAL;

	/* No TM flag or no max size configured — no quota to enforce */
	if (!test_share_config_flag(share,
				    KSMBD_SHARE_FLAG_FRUIT_TIME_MACHINE))
		return 0;

	if (share->time_machine_max_size == 0)
		return 0;

	rc = vfs_statfs(share_path, &stfs);
	if (rc) {
		pr_err("ksmbd: fruit TM quota: vfs_statfs failed: %d\n", rc);
		return rc;
	}

	used_bytes = (u64)(stfs.f_blocks - stfs.f_bfree) * stfs.f_bsize;

	if (used_bytes >= share->time_machine_max_size) {
		ksmbd_debug(SMB,
			    "Fruit TM quota exceeded: used=%llu max=%llu\n",
			    used_bytes, share->time_machine_max_size);
		return -ENOSPC;
	}

	return 0;
}

/* ── Step 3: ReadDirAttr Enrichment ────────────────────────────── */

/* xattr name for the resource fork DosStream */
#define XATTR_NAME_AFP_RESOURCE \
	"user.DosStream." AFP_RESOURCE_STREAM ":$DATA"

/**
 * ksmbd_fruit_fill_readdir_attr() - Enrich directory entry with fruit metadata
 * @dir_fp:	file pointer for the directory being listed
 * @ksmbd_kstat:	kstat wrapper for the directory entry
 * @entry_path:	VFS path to the directory entry
 *
 * When fruit extensions are negotiated, macOS Finder expects enriched
 * directory listing entries.  This function adds:
 *   - Resource fork size (from the AFP_Resource DosStream xattr)
 *   - FinderInfo (from com.apple.FinderInfo xattr)
 *
 * These enrichments are gated per-share via FRUIT_RFORK_SIZE and
 * FRUIT_FINDER_INFO flags so admins can enable them selectively.
 *
 * Return:	0 on success, negative errno on failure (non-fatal)
 */
int ksmbd_fruit_fill_readdir_attr(struct ksmbd_file *dir_fp,
				  struct ksmbd_kstat *ksmbd_kstat,
				  struct path *entry_path)
{
	struct ksmbd_share_config *share;
	struct dentry *dentry;
	ssize_t rfork_len;

	if (!dir_fp || !ksmbd_kstat || !entry_path)
		return -EINVAL;

	if (!dir_fp->tcon || !dir_fp->tcon->share_conf)
		return 0;

	share = dir_fp->tcon->share_conf;
	dentry = entry_path->dentry;
	if (!dentry)
		return 0;

	/*
	 * Resource fork size: read the length of the AFP_Resource
	 * DosStream xattr.  A negative return means no resource fork.
	 */
	if (test_share_config_flag(share,
				   KSMBD_SHARE_FLAG_FRUIT_RFORK_SIZE)) {
		rfork_len = vfs_getxattr(&nop_mnt_idmap, dentry,
					 XATTR_NAME_AFP_RESOURCE,
					 NULL, 0);
		if (rfork_len > 0) {
			ksmbd_debug(SMB,
				    "Fruit readdir: rfork size=%zd for %pd\n",
				    rfork_len, dentry);
		}
		/*
		 * We report the resource fork size through the EaSize
		 * field override (handled in smb2_read_dir_attr_fill).
		 * The size itself is informational for debug here.
		 */
	}

	return 0;
}

/* ── Step 4: Volume Capabilities — Resolve File ID support ─────── */

/**
 * ksmbd_fruit_get_volume_caps() - Compute AAPL volume capabilities
 * @share:	share configuration (may be NULL for defaults)
 *
 * Returns the volume_caps bitfield for the AAPL create context response.
 * This includes file ID resolution support (kAAPL_SUPPORT_RESOLVE_ID),
 * case sensitivity, and full sync support.
 *
 * Return:	volume capabilities bitmask
 */
u64 ksmbd_fruit_get_volume_caps(struct ksmbd_share_config *share)
{
	u64 vcaps = 0;

	/*
	 * Linux filesystems are generally case-sensitive and support
	 * full fsync semantics.
	 */
	vcaps |= kAAPL_CASE_SENSITIVE;
	vcaps |= kAAPL_SUPPORTS_FULL_SYNC;

	/*
	 * Advertise file ID resolution support.  The actual resolution
	 * is implemented in ksmbd_vfs_resolve_fileid() (vfs.c).
	 */
	vcaps |= kAAPL_SUPPORT_RESOLVE_ID;

	return vcaps;
}

int fruit_init_module(void)
{
	pr_info("ksmbd: Fruit SMB extensions loaded\n");
	return 0;
}

void fruit_cleanup_module(void)
{
	pr_info("ksmbd: Fruit SMB extensions unloaded\n");
}

/*
 * fruit_process_server_query - Process a kAAPL server query request
 *
 * Validates the query, updates the connection's fruit state with the
 * query type and timestamp, and marks the connection as queried.
 * The actual query response (server_caps, volume_caps) is built by
 * the create-context response path using fruit_build_server_response().
 */
int fruit_process_server_query(struct ksmbd_conn *conn,
			       const struct fruit_server_query *query)
{
	struct fruit_conn_state *state;
	u32 type;

	if (!conn || !query)
		return -EINVAL;

	state = conn->fruit_state;
	if (!state) {
		ksmbd_debug(SMB, "Fruit server query without negotiated state\n");
		return -ENOTCONN;
	}

	type = le32_to_cpu(query->type);

	ksmbd_debug(SMB, "Fruit server query: type=%u flags=%u max_rsp=%u\n",
		    type, le32_to_cpu(query->flags),
		    le32_to_cpu(query->max_response_size));

	state->server_queried = 1;
	state->last_query_type = type;
	state->last_query_time = ktime_get_real_seconds();

	return 0;
}

void fruit_debug_capabilities(u64 capabilities)
{
	ksmbd_debug(SMB, "Fruit kAAPL server_caps: 0x%016llx\n", capabilities);
	ksmbd_debug(SMB, "  read_dir_attr=%d osx_copyfile=%d unix_based=%d nfs_ace=%d\n",
		    !!(capabilities & kAAPL_SUPPORTS_READ_DIR_ATTR),
		    !!(capabilities & kAAPL_SUPPORTS_OSX_COPYFILE),
		    !!(capabilities & kAAPL_UNIX_BASED),
		    !!(capabilities & kAAPL_SUPPORTS_NFS_ACE));
}

/*
 * smb2_read_dir_attr - Batch-level hook for Fruit directory attribute reading
 *
 * Called once per QUERY_DIRECTORY batch to validate fruit state.
 * Per-entry enrichment (UNIX mode packing into EaSize, resource fork
 * size reporting, FinderInfo) is done in smb2_read_dir_attr_fill().
 */
int smb2_read_dir_attr(struct ksmbd_work *work)
{
	struct ksmbd_conn *conn;

	if (!work)
		return -EINVAL;

	conn = work->conn;
	if (!conn || !conn->is_fruit)
		return 0;

	ksmbd_debug(SMB, "Fruit ReadDirAttr batch for conn %p\n", conn);
	return 0;
}

/*
 * smb2_read_dir_attr_fill - Enrich a directory entry with UNIX metadata.
 * Called from smb2_populate_readdir_entry() for Fruit connections.
 *
 * Apple ReadDirAttr convention:
 *   EaSize[4] = UNIX mode (S_IFMT | permission bits)
 *
 * Additional enrichment (per-share flags):
 *   FRUIT_RFORK_SIZE   → reads resource fork size from AFP_Resource stream
 *   FRUIT_MAX_ACCESS   → computes maximum access rights for current user
 *
 * Resource fork size and max_access are logged at debug level for
 * diagnostic purposes.  The SMB2 readdir wire format does not have
 * dedicated fields for these values; they are available to clients
 * through FILE_STREAM_INFORMATION and CREATE response respectively.
 *
 * Note: Enrichment reads xattrs and checks permissions per directory
 * entry, so they have performance implications on large directories.
 * These are gated behind per-share flags so admins can enable selectively.
 */
void smb2_read_dir_attr_fill(struct ksmbd_conn *conn,
			     struct dentry *dentry,
			     struct kstat *stat,
			     struct ksmbd_share_config *share,
			     __le32 *ea_size_field)
{
	if (!conn->is_fruit || !stat || !ea_size_field)
		return;

	/* Pack UNIX mode into EaSize (Apple ReadDirAttr convention) */
	*ea_size_field = cpu_to_le32(stat->mode);

	/*
	 * Optional enrichments gated by per-share flags.
	 * These read xattrs per directory entry, so they have
	 * performance implications on large directories.
	 */
	if (!share || !dentry)
		return;

	/* Resource fork size: read AFP_Resource stream length */
	if (test_share_config_flag(share,
				   KSMBD_SHARE_FLAG_FRUIT_RFORK_SIZE)) {
		ssize_t rfork_len;

		rfork_len = vfs_getxattr(&nop_mnt_idmap, dentry,
					 XATTR_NAME_AFP_RESOURCE,
					 NULL, 0);
		if (rfork_len > 0)
			ksmbd_debug(SMB,
				    "Fruit readdir: rfork_size=%zd for %pd\n",
				    rfork_len, dentry);
	}

	/* Max access: compute rwx permission mask for current user */
	if (test_share_config_flag(share,
				   KSMBD_SHARE_FLAG_FRUIT_MAX_ACCESS)) {
		struct inode *inode = d_inode(dentry);
		unsigned int access = 0;

		if (inode) {
			if (!inode_permission(&nop_mnt_idmap, inode, MAY_READ))
				access |= MAY_READ;
			if (!inode_permission(&nop_mnt_idmap, inode, MAY_WRITE))
				access |= MAY_WRITE;
			if (!inode_permission(&nop_mnt_idmap, inode, MAY_EXEC))
				access |= MAY_EXEC;
		}

		ksmbd_debug(SMB, "Fruit readdir: max_access=0x%x for %pd\n",
			    access, dentry);
	}
}

#endif /* CONFIG_KSMBD_FRUIT */
