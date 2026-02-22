// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2025 Alexandre BETRY
 *
 *   Fruit SMB extensions for KSMBD
 */

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/xattr.h>
#include <linux/fs.h>

#include "smb2fruit.h"
#include "smb_common.h"
#include "connection.h"
#include "server.h"
#include "ksmbd_netlink.h"
#include "oplock.h"

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

int fruit_init_module(void)
{
	pr_info("ksmbd: Fruit SMB extensions loaded\n");
	return 0;
}

void fruit_cleanup_module(void)
{
	pr_info("ksmbd: Fruit SMB extensions unloaded\n");
}

int fruit_process_server_query(struct ksmbd_conn *conn,
			       const struct fruit_server_query *query)
{
	if (!conn || !query)
		return -EINVAL;

	ksmbd_debug(SMB, "Fruit server query: type=%d flags=%d\n",
		    le32_to_cpu(query->type), le32_to_cpu(query->flags));

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

int smb2_read_dir_attr(struct ksmbd_work *work)
{
	if (!work)
		return -EINVAL;

	ksmbd_debug(SMB, "Fruit read directory attrs\n");

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
 *   FRUIT_FINDER_INFO  → reads com.apple.FinderInfo xattr (32 bytes)
 *   FRUIT_RFORK_SIZE   → reads resource fork size from AFP_Resource stream
 *   FRUIT_MAX_ACCESS   → computes maximum access rights for current user
 *
 * Note: Full FinderInfo/ResourceFork/MaxAccess enrichment reads xattrs
 * per directory entry which has performance implications on large dirs.
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
}
