// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * H-01: Persistent durable handle on-disk state storage.
 */

#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/slab.h>

#include "glob.h"
#include "oplock.h"
#include "smb2pdu.h"
#include "vfs_cache.h"
#include "connection.h"
#include "mgmt/tree_connect.h"

#define KSMBD_PH_MAGIC   0x4B504800
#define KSMBD_PH_VERSION 2
#define KSMBD_PH_DIR     "/var/lib/ksmbd/ph"
#define KSMBD_PH_FLAG_IS_LEASE 0x00000001

struct ksmbd_ph_hdr {
	__le32 magic;
	__le32 version;
	__le64 persistent_id;
	__u8 create_guid[SMB2_CREATE_GUID_SIZE];
	__u8 client_guid[SMB2_CLIENT_GUID_SIZE];
	__le32 daccess;
	__le32 file_attrs;
	__le32 coption;
	__le32 durable_timeout;
	__le32 oplock_level;
	__le32 flags;
	__le32 lease_state;
	__le32 lease_flags;
	__le64 lease_duration;
	__u8 lease_key[SMB2_LEASE_KEY_SIZE];
	__u8 parent_lease_key[SMB2_LEASE_KEY_SIZE];
	__le16 lease_epoch;
	__le16 lease_version;
	__le32 share_name_len;
	__le32 file_path_len;
} __packed;

static bool ksmbd_ph_ensure_dir(void)
{
	struct path dir;
	int err;
	static bool checked, exists;

	if (checked)
		return exists;
	checked = true;
	err = kern_path(KSMBD_PH_DIR, LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &dir);
	if (!err) {
		path_put(&dir);
		exists = true;
		return true;
	}
	pr_warn_once("ksmbd: %s does not exist; persistent handles disabled\n",
		     KSMBD_PH_DIR);
	return false;
}

static void ksmbd_ph_build_path(char *buf, size_t sz, const char *guid)
{
	snprintf(buf, sz, KSMBD_PH_DIR "/%16phN", guid);
}

void ksmbd_ph_save(struct ksmbd_file *fp)
{
	char ph_path[64];
	struct file *filp;
	struct ksmbd_ph_hdr hdr;
	struct oplock_info *opinfo = NULL;
	char fpbuf[PATH_MAX];
	const char *share_name, *file_path;
	int snl, fpl;
	loff_t pos = 0;
	ssize_t wr;

	if (!fp->tcon || !fp->tcon->share_conf)
		return;
	if (!ksmbd_ph_ensure_dir())
		return;

	share_name = fp->tcon->share_conf->name;
	snl = strlen(share_name);
	file_path = d_path(&fp->filp->f_path, fpbuf, sizeof(fpbuf));
	if (IS_ERR(file_path))
		return;
	fpl = strlen(file_path);

	ksmbd_ph_build_path(ph_path, sizeof(ph_path), fp->create_guid);
	filp = filp_open(ph_path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
	if (IS_ERR(filp))
		return;

	memset(&hdr, 0, sizeof(hdr));
	hdr.magic = cpu_to_le32(KSMBD_PH_MAGIC);
	hdr.version = cpu_to_le32(KSMBD_PH_VERSION);
	hdr.persistent_id = cpu_to_le64(fp->persistent_id);
	memcpy(hdr.create_guid, fp->create_guid, SMB2_CREATE_GUID_SIZE);
	memcpy(hdr.client_guid, fp->client_guid, SMB2_CLIENT_GUID_SIZE);
	hdr.daccess = fp->daccess;
	if (fp->f_ci)
		hdr.file_attrs = fp->f_ci->m_fattr;
	hdr.coption = fp->coption;
	hdr.durable_timeout = cpu_to_le32(fp->durable_timeout);
	hdr.share_name_len = cpu_to_le32(snl);
	hdr.file_path_len = cpu_to_le32(fpl);

	opinfo = opinfo_get(fp);
	if (opinfo) {
		hdr.oplock_level = cpu_to_le32(opinfo->level);
		if (opinfo->is_lease && opinfo->o_lease) {
			hdr.flags |= cpu_to_le32(KSMBD_PH_FLAG_IS_LEASE);
			hdr.lease_state = opinfo->o_lease->state;
			hdr.lease_flags = opinfo->o_lease->flags;
			hdr.lease_duration = opinfo->o_lease->duration;
			memcpy(hdr.lease_key, opinfo->o_lease->lease_key,
			       SMB2_LEASE_KEY_SIZE);
			memcpy(hdr.parent_lease_key,
			       opinfo->o_lease->parent_lease_key,
			       SMB2_LEASE_KEY_SIZE);
			hdr.lease_epoch = cpu_to_le16(opinfo->o_lease->epoch);
			hdr.lease_version =
				cpu_to_le16(opinfo->o_lease->version);
		}
		opinfo_put(opinfo);
	}

	wr = kernel_write(filp, &hdr, sizeof(hdr), &pos);
	if (wr != sizeof(hdr))
		goto out;
	wr = kernel_write(filp, share_name, snl, &pos);
	if (wr != snl)
		goto out;
	wr = kernel_write(filp, file_path, fpl, &pos);
out:
	filp_close(filp, NULL);
}

struct ksmbd_file *ksmbd_ph_restore(struct ksmbd_work *work,
				    u64 persistent_id, const char *guid)
{
	char ph_path[64];
	struct file *sf;
	struct ksmbd_ph_hdr hdr;
	char *sn = NULL, *fp_path = NULL;
	struct lease_ctx_info lctx = {0};
	struct lease_ctx_info *lctxp = NULL;
	bool needs_write;
	u32 snl, fpl, dt;
	u32 flags;
	loff_t pos = 0;
	ssize_t nr;
	struct ksmbd_file *fp = NULL;
	struct file *filp;
	struct path fkp;
	int oplock_level;
	int err;

	ksmbd_ph_build_path(ph_path, sizeof(ph_path), guid);
	sf = filp_open(ph_path, O_RDONLY, 0);
	if (IS_ERR(sf))
		return NULL;

	nr = kernel_read(sf, &hdr, sizeof(hdr), &pos);
	if (nr != sizeof(hdr))
		goto out_close;

	if (le32_to_cpu(hdr.magic) != KSMBD_PH_MAGIC)
		goto out_close;
	if (le32_to_cpu(hdr.version) != KSMBD_PH_VERSION)
		goto out_close;
	if (le64_to_cpu(hdr.persistent_id) != persistent_id)
		goto out_close;
	if (memcmp(hdr.create_guid, guid, SMB2_CREATE_GUID_SIZE))
		goto out_close;
	flags = le32_to_cpu(hdr.flags);
	oplock_level = le32_to_cpu(hdr.oplock_level);
	if (flags & ~KSMBD_PH_FLAG_IS_LEASE)
		goto out_close;
	switch (oplock_level) {
	case SMB2_OPLOCK_LEVEL_NONE:
	case SMB2_OPLOCK_LEVEL_II:
	case SMB2_OPLOCK_LEVEL_EXCLUSIVE:
	case SMB2_OPLOCK_LEVEL_BATCH:
		break;
	default:
		goto out_close;
	}
	if ((flags & KSMBD_PH_FLAG_IS_LEASE) &&
	    le16_to_cpu(hdr.lease_version) != 1 &&
	    le16_to_cpu(hdr.lease_version) != 2)
		goto out_close;

	snl = le32_to_cpu(hdr.share_name_len);
	fpl = le32_to_cpu(hdr.file_path_len);
	if (!snl || snl > 256 || !fpl || fpl > PATH_MAX)
		goto out_close;
	needs_write = !!(hdr.daccess &
			 (FILE_WRITE_DATA_LE | FILE_APPEND_DATA_LE |
			  FILE_WRITE_EA_LE | FILE_WRITE_ATTRIBUTES_LE |
			  FILE_WRITE_DAC_LE | FILE_WRITE_OWNER_LE |
			  FILE_DELETE_LE | FILE_ACCESS_SYSTEM_SECURITY_LE));

	sn = kmalloc(snl + 1, GFP_KERNEL);
	if (!sn) goto out_close;
	nr = kernel_read(sf, sn, snl, &pos);
	if (nr != (ssize_t)snl) goto out_free;
	sn[snl] = 0;

	fp_path = kmalloc(fpl + 1, GFP_KERNEL);
	if (!fp_path) goto out_free;
	nr = kernel_read(sf, fp_path, fpl, &pos);
	if (nr != (ssize_t)fpl) goto out_free;
	fp_path[fpl] = 0;

	if (!work->tcon || !work->tcon->share_conf ||
	    strcmp(work->tcon->share_conf->name, sn))
		goto out_free;

	err = kern_path(fp_path, LOOKUP_FOLLOW, &fkp);
	if (err) goto out_free;
	ksmbd_lease_breaker_enter();
	filp = dentry_open(&fkp, O_RDWR, current_cred());
	ksmbd_lease_breaker_exit();
	path_put(&fkp);
	if (IS_ERR(filp)) {
		if (needs_write)
			goto out_free;
		err = kern_path(fp_path, LOOKUP_FOLLOW, &fkp);
		if (err) goto out_free;
		ksmbd_lease_breaker_enter();
		filp = dentry_open(&fkp, O_RDONLY, current_cred());
		ksmbd_lease_breaker_exit();
		path_put(&fkp);
		if (IS_ERR(filp)) goto out_free;
	}

	if (!path_is_under(&filp->f_path, &work->tcon->share_conf->vfs_path)) {
		pr_err_ratelimited("persistent handle restore escapes share root\n");
		fput(filp);
		goto out_free;
	}

	fp = ksmbd_open_fd(work, filp);
	if (IS_ERR(fp)) { fput(filp); fp = NULL; goto out_free; }

	memcpy(fp->create_guid, hdr.create_guid, SMB2_CREATE_GUID_SIZE);
	memcpy(fp->client_guid, hdr.client_guid, SMB2_CLIENT_GUID_SIZE);
	fp->daccess = hdr.daccess;
	if (fp->f_ci)
		fp->f_ci->m_fattr = hdr.file_attrs;
	fp->coption = hdr.coption;
	dt = le32_to_cpu(hdr.durable_timeout);
	fp->durable_timeout = dt;
	fp->is_durable = true;
	fp->is_persistent = true;
	fp->persistent_restore_pending = true;
	err = ksmbd_open_durable_fd_id(fp, persistent_id);
	if (err) {
		ksmbd_put_durable_fd(fp);
		fp = NULL;
		goto out_free;
	}

	if (flags & KSMBD_PH_FLAG_IS_LEASE) {
		memcpy(lctx.lease_key, hdr.lease_key, SMB2_LEASE_KEY_SIZE);
		lctx.req_state = hdr.lease_state;
		lctx.flags = hdr.lease_flags;
		lctx.duration = hdr.lease_duration;
		memcpy(lctx.parent_lease_key, hdr.parent_lease_key,
		       SMB2_LEASE_KEY_SIZE);
		lctx.epoch = hdr.lease_epoch;
		lctx.version = le16_to_cpu(hdr.lease_version);
		lctxp = &lctx;
	}

	err = ksmbd_restore_oplock(work, fp, oplock_level, lctxp);
	if (err) {
		ksmbd_put_durable_fd(fp);
		fp = NULL;
		goto out_free;
	}

	fp->conn = NULL;
	fp->tcon = NULL;
	fp->volatile_id = KSMBD_NO_FID;

out_free:
	kfree(sn);
	kfree(fp_path);
out_close:
	filp_close(sf, NULL);
	return fp;
}

void ksmbd_ph_delete(struct ksmbd_file *fp)
{
	char ph_path[64];
	struct path kp;
	int err;

	if (!fp->is_persistent) return;
	ksmbd_ph_build_path(ph_path, sizeof(ph_path), fp->create_guid);
	err = kern_path(ph_path, LOOKUP_FOLLOW, &kp);
	if (err) return;
	inode_lock(d_inode(kp.dentry->d_parent));
	vfs_unlink(mnt_idmap(kp.mnt), d_inode(kp.dentry->d_parent), kp.dentry, NULL);
	inode_unlock(d_inode(kp.dentry->d_parent));
	path_put(&kp);
}
