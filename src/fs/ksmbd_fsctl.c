// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *
 *   FSCTL handler registration table for ksmbd
 *
 *   Replaces the monolithic switch-case dispatch in smb2_ioctl() with an
 *   RCU-protected hash table.  Built-in handlers are registered at module
 *   init; additional handlers can be registered by extension modules.
 */

#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/module.h>
#include <linux/string.h>

#include "ksmbd_fsctl.h"
#include "smb2pdu.h"
#include "smbfsctl.h"
#include "smbstatus.h"
#include "smb_common.h"
#include "glob.h"
#include "connection.h"
#include "transport_ipc.h"
#include "ksmbd_netlink.h"
#include "vfs_cache.h"
#include "ksmbd_work.h"
#include "mgmt/user_session.h"

/* 256 buckets (2^8) — sufficient for the ~20 built-in FSCTLs */
#define KSMBD_FSCTL_HASH_BITS	8

static DEFINE_HASHTABLE(fsctl_handlers, KSMBD_FSCTL_HASH_BITS);
static DEFINE_SPINLOCK(fsctl_lock);

/**
 * ksmbd_register_fsctl() - Register an FSCTL handler
 * @h: handler descriptor
 *
 * Adds the handler to the hash table under spinlock using hash_add_rcu.
 *
 * Return: 0 on success, -EEXIST if a handler for the same ctl_code
 *         is already registered.
 */
int ksmbd_register_fsctl(struct ksmbd_fsctl_handler *h)
{
	struct ksmbd_fsctl_handler *cur;

	spin_lock(&fsctl_lock);
	hash_for_each_possible_rcu(fsctl_handlers, cur, node, h->ctl_code) {
		if (cur->ctl_code == h->ctl_code) {
			spin_unlock(&fsctl_lock);
			pr_err("FSCTL handler 0x%08x already registered\n",
			       h->ctl_code);
			return -EEXIST;
		}
	}
	hash_add_rcu(fsctl_handlers, &h->node, h->ctl_code);
	spin_unlock(&fsctl_lock);
	return 0;
}

/**
 * ksmbd_unregister_fsctl() - Unregister an FSCTL handler
 * @h: handler descriptor previously registered
 *
 * Removes the handler under spinlock and waits for an RCU grace period.
 */
void ksmbd_unregister_fsctl(struct ksmbd_fsctl_handler *h)
{
	spin_lock(&fsctl_lock);
	hash_del_rcu(&h->node);
	spin_unlock(&fsctl_lock);
	synchronize_rcu();
}

/**
 * ksmbd_dispatch_fsctl() - Look up and invoke a registered FSCTL handler
 * @work:	    smb work for this request
 * @ctl_code:	    FSCTL control code (host byte order)
 * @id:		    volatile file id
 * @in_buf:	    pointer to input buffer
 * @in_buf_len:    input buffer length
 * @max_out_len:   maximum output length allowed
 * @rsp:	    pointer to ioctl response structure
 * @out_len:	    [out] number of output bytes written by the handler
 *
 * Performs an RCU-protected hash lookup, takes a module reference on the
 * owning module, and invokes the handler callback.
 *
 * Return: 0 on success, handler errno on failure, -EOPNOTSUPP if no
 *         handler is registered for the given ctl_code.
 */
int ksmbd_dispatch_fsctl(struct ksmbd_work *work, u32 ctl_code,
			 u64 id, void *in_buf, unsigned int in_buf_len,
			 unsigned int max_out_len,
			 struct smb2_ioctl_rsp *rsp,
			 unsigned int *out_len)
{
	struct ksmbd_fsctl_handler *h;
	int ret = -EOPNOTSUPP;

	*out_len = 0;

	rcu_read_lock();
	hash_for_each_possible_rcu(fsctl_handlers, h, node, ctl_code) {
		if (h->ctl_code != ctl_code)
			continue;

		if (!try_module_get(h->owner)) {
			rcu_read_unlock();
			return -ENODEV;
		}
		rcu_read_unlock();

		ret = h->handler(work, id, in_buf, in_buf_len,
				 max_out_len, rsp, out_len);
		module_put(h->owner);
		return ret;
	}
	rcu_read_unlock();

	return ret;
}

/*
 * ============================================================
 *  Built-in FSCTL handler implementations
 * ============================================================
 *
 * These are extracted from smb2_ioctl() in smb2pdu.c.  Each follows
 * the unified handler signature defined in ksmbd_fsctl.h.
 */

/**
 * fsctl_create_or_get_object_id_handler() - FSCTL_CREATE_OR_GET_OBJECT_ID
 *
 * Returns a dummy object ID (all zeros) to satisfy smbtorture tests.
 */
static int fsctl_create_or_get_object_id_handler(struct ksmbd_work *work,
						  u64 id, void *in_buf,
						  unsigned int in_buf_len,
						  unsigned int max_out_len,
						  struct smb2_ioctl_rsp *rsp,
						  unsigned int *out_len)
{
	struct file_object_buf_type1_ioctl_rsp *obj_buf;

	if (max_out_len < sizeof(*obj_buf))
		return -ENOSPC;

	obj_buf = (struct file_object_buf_type1_ioctl_rsp *)&rsp->Buffer[0];

	/*
	 * TODO: This is dummy implementation to pass smbtorture
	 * Need to check correct response later
	 */
	memset(obj_buf->ObjectId, 0x0, 16);
	memset(obj_buf->BirthVolumeId, 0x0, 16);
	memset(obj_buf->BirthObjectId, 0x0, 16);
	memset(obj_buf->DomainId, 0x0, 16);

	*out_len = sizeof(*obj_buf);
	return 0;
}

/**
 * fsctl_validate_negotiate_info_handler() - FSCTL_VALIDATE_NEGOTIATE_INFO
 *
 * Validates that the negotiation parameters match what the server
 * agreed on, preventing downgrade attacks (MS-SMB2 3.3.5.15.12).
 */
static int fsctl_validate_negotiate_info_handler(struct ksmbd_work *work,
						  u64 id, void *in_buf,
						  unsigned int in_buf_len,
						  unsigned int max_out_len,
						  struct smb2_ioctl_rsp *rsp,
						  unsigned int *out_len)
{
	struct ksmbd_conn *conn = work->conn;
	struct validate_negotiate_info_req *neg_req;
	struct validate_negotiate_info_rsp *neg_rsp;
	int ret;
	int dialect;

	if (conn->dialect < SMB30_PROT_ID)
		return -EOPNOTSUPP;

	if (in_buf_len < offsetof(struct validate_negotiate_info_req,
				  Dialects))
		return -EINVAL;

	if (max_out_len < sizeof(struct validate_negotiate_info_rsp))
		return -EINVAL;

	neg_req = (struct validate_negotiate_info_req *)in_buf;

	if (in_buf_len < offsetof(struct validate_negotiate_info_req, Dialects) +
			le16_to_cpu(neg_req->DialectCount) * sizeof(__le16))
		return -EINVAL;

	dialect = ksmbd_lookup_dialect_by_id(neg_req->Dialects,
					     neg_req->DialectCount);
	if (dialect == BAD_PROT_ID || dialect != conn->dialect)
		return -EINVAL;

	if (strncmp(neg_req->Guid, conn->ClientGUID, SMB2_CLIENT_GUID_SIZE))
		return -EINVAL;

	if (le16_to_cpu(neg_req->SecurityMode) != conn->cli_sec_mode)
		return -EINVAL;

	if (le32_to_cpu(neg_req->Capabilities) != conn->cli_cap)
		return -EINVAL;

	neg_rsp = (struct validate_negotiate_info_rsp *)&rsp->Buffer[0];
	neg_rsp->Capabilities = cpu_to_le32(conn->vals->capabilities);
	memset(neg_rsp->Guid, 0, SMB2_CLIENT_GUID_SIZE);
	neg_rsp->SecurityMode = cpu_to_le16(conn->srv_sec_mode);
	neg_rsp->Dialect = cpu_to_le16(conn->dialect);

	rsp->PersistentFileId = SMB2_NO_FID;
	rsp->VolatileFileId = SMB2_NO_FID;

	*out_len = sizeof(struct validate_negotiate_info_rsp);
	ret = 0;
	return ret;
}

/**
 * fsctl_pipe_transceive_handler() - FSCTL_PIPE_TRANSCEIVE
 *
 * Forwards an RPC request to the userspace daemon and copies
 * the response into the SMB2 output buffer.
 */
static int fsctl_pipe_transceive_handler(struct ksmbd_work *work,
					  u64 id, void *in_buf,
					  unsigned int in_buf_len,
					  unsigned int max_out_len,
					  struct smb2_ioctl_rsp *rsp,
					  unsigned int *out_len)
{
	struct ksmbd_rpc_command *rpc_resp;
	unsigned int capped_out_len;
	int nbytes = 0;

	capped_out_len = min_t(u32, KSMBD_IPC_MAX_PAYLOAD, max_out_len);

	rpc_resp = ksmbd_rpc_ioctl(work->sess, id, in_buf, in_buf_len);
	if (rpc_resp) {
		if (rpc_resp->flags == KSMBD_RPC_SOME_NOT_MAPPED) {
			/*
			 * set STATUS_SOME_NOT_MAPPED response
			 * for unknown domain sid.
			 */
			rsp->hdr.Status = STATUS_SOME_NOT_MAPPED;
		} else if (rpc_resp->flags == KSMBD_RPC_ENOTIMPLEMENTED) {
			rsp->hdr.Status = STATUS_NOT_SUPPORTED;
			goto out;
		} else if (rpc_resp->flags != KSMBD_RPC_OK) {
			rsp->hdr.Status = STATUS_INVALID_PARAMETER;
			goto out;
		}

		nbytes = rpc_resp->payload_sz;
		if (rpc_resp->payload_sz > capped_out_len) {
			rsp->hdr.Status = STATUS_BUFFER_OVERFLOW;
			nbytes = capped_out_len;
		}

		if (!rpc_resp->payload_sz) {
			rsp->hdr.Status = STATUS_UNEXPECTED_IO_ERROR;
			goto out;
		}

		memcpy((char *)rsp->Buffer, rpc_resp->payload, nbytes);
	}
out:
	kvfree(rpc_resp);
	*out_len = nbytes;
	return 0;
}

/*
 * ============================================================
 *  Built-in handler table
 * ============================================================
 */

static struct ksmbd_fsctl_handler builtin_fsctl_handlers[] = {
	{
		.ctl_code = FSCTL_CREATE_OR_GET_OBJECT_ID,
		.handler  = fsctl_create_or_get_object_id_handler,
		.owner    = THIS_MODULE,
	},
	{
		.ctl_code = FSCTL_VALIDATE_NEGOTIATE_INFO,
		.handler  = fsctl_validate_negotiate_info_handler,
		.owner    = THIS_MODULE,
	},
	{
		.ctl_code = FSCTL_PIPE_TRANSCEIVE,
		.handler  = fsctl_pipe_transceive_handler,
		.owner    = THIS_MODULE,
	},
};

/**
 * ksmbd_fsctl_init() - Initialize FSCTL dispatch table with built-in handlers
 *
 * Return: 0 on success, negative errno on failure
 */
int ksmbd_fsctl_init(void)
{
	int i, ret;

	hash_init(fsctl_handlers);

	for (i = 0; i < ARRAY_SIZE(builtin_fsctl_handlers); i++) {
		ret = ksmbd_register_fsctl(&builtin_fsctl_handlers[i]);
		if (ret) {
			pr_err("Failed to register FSCTL 0x%08x: %d\n",
			       builtin_fsctl_handlers[i].ctl_code, ret);
			goto err_unregister;
		}
	}

	ksmbd_debug(SMB, "Registered %zu built-in FSCTL handlers\n",
		    ARRAY_SIZE(builtin_fsctl_handlers));
	return 0;

err_unregister:
	while (--i >= 0)
		ksmbd_unregister_fsctl(&builtin_fsctl_handlers[i]);
	return ret;
}

/**
 * ksmbd_fsctl_exit() - Unregister all FSCTL handlers and clean up
 */
void ksmbd_fsctl_exit(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(builtin_fsctl_handlers); i++)
		ksmbd_unregister_fsctl(&builtin_fsctl_handlers[i]);
}
