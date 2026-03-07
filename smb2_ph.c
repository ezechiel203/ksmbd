// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * H-01: Persistent durable handle on-disk state storage.
 */

#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/slab.h>

#include "glob.h"
#include "smb2pdu.h"
#include "vfs_cache.h"
#include "connection.h"
#include "mgmt/tree_connect.h"

#define KSMBD_PH_MAGIC   0x4B504800
#define KSMBD_PH_VERSION 1
#define KSMBD_PH_DIR     "/var/lib/ksmbd/ph"
#define KSMBD_PH_HDR_SIZE 56

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
	u8 hdr[KSMBD_PH_HDR_SIZE];
	char *fpbuf;
	const char *share_name, *file_path;
	__le32 v32;
	__le64 v64;
	int snl, fpl;
	loff_t pos = 0;
	ssize_t wr;
	int off = 0;

	if (!fp->tcon || !fp->tcon->share_conf)
		return;
	if (!ksmbd_ph_ensure_dir())
		return;

	fpbuf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!fpbuf)
		return;

	share_name = fp->tcon->share_conf->name;
	snl = strlen(share_name);
	file_path = d_path(&fp->filp->f_path, fpbuf, PATH_MAX);
	if (IS_ERR(file_path)) {
		kfree(fpbuf);
		return;
	}
	fpl = strlen(file_path);

	ksmbd_ph_build_path(ph_path, sizeof(ph_path), fp->create_guid);
	filp = filp_open(ph_path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
	if (IS_ERR(filp))
		return;

	memset(hdr, 0, sizeof(hdr));
	v32 = cpu_to_le32(KSMBD_PH_MAGIC);
	memcpy(hdr + off, &v32, 4); off += 4;
	v32 = cpu_to_le32(KSMBD_PH_VERSION);
	memcpy(hdr + off, &v32, 4); off += 4;
	v64 = cpu_to_le64(fp->persistent_id);
	memcpy(hdr + off, &v64, 8); off += 8;
	memcpy(hdr + off, fp->create_guid, SMB2_CREATE_GUID_SIZE); off += SMB2_CREATE_GUID_SIZE;
	memcpy(hdr + off, &fp->daccess, 4); off += 4;
	if (fp->f_ci)
		memcpy(hdr + off, &fp->f_ci->m_fattr, 4);
	off += 4;
	memcpy(hdr + off, &fp->coption, 4); off += 4;
	v32 = cpu_to_le32(fp->durable_timeout);
	memcpy(hdr + off, &v32, 4); off += 4;
	v32 = cpu_to_le32(snl);
	memcpy(hdr + off, &v32, 4); off += 4;
	v32 = cpu_to_le32(fpl);
	memcpy(hdr + off, &v32, 4); off += 4;

	wr = kernel_write(filp, hdr, KSMBD_PH_HDR_SIZE, &pos);
	if (wr != KSMBD_PH_HDR_SIZE)
		goto out;
	wr = kernel_write(filp, share_name, snl, &pos);
	if (wr != snl)
		goto out;
	wr = kernel_write(filp, file_path, fpl, &pos);
out:
	filp_close(filp, NULL);
	kfree(fpbuf);
}

struct ksmbd_file *ksmbd_ph_restore(struct ksmbd_work *work,
				    u64 persistent_id, const char *guid)
{
	char ph_path[64];
	struct file *sf;
	u8 hdr[KSMBD_PH_HDR_SIZE];
	char *sn = NULL, *fp_path = NULL;
	__le32 t32;
	__le64 spid;
	u32 snl, fpl, dt;
	loff_t pos = 0;
	ssize_t nr;
	struct ksmbd_file *fp = NULL;
	struct file *filp;
	struct path fkp;
	int err;

	ksmbd_ph_build_path(ph_path, sizeof(ph_path), guid);
	sf = filp_open(ph_path, O_RDONLY, 0);
	if (IS_ERR(sf))
		return NULL;

	nr = kernel_read(sf, hdr, KSMBD_PH_HDR_SIZE, &pos);
	if (nr != KSMBD_PH_HDR_SIZE)
		goto out_close;

	memcpy(&t32, hdr, 4);
	if (le32_to_cpu(t32) != KSMBD_PH_MAGIC)
		goto out_close;
	memcpy(&t32, hdr + 4, 4);
	if (le32_to_cpu(t32) != KSMBD_PH_VERSION)
		goto out_close;
	memcpy(&spid, hdr + 8, 8);
	if (le64_to_cpu(spid) != persistent_id)
		goto out_close;
	if (memcmp(hdr + 16, guid, SMB2_CREATE_GUID_SIZE))
		goto out_close;

	memcpy(&t32, hdr + 48, 4);
	snl = le32_to_cpu(t32);
	memcpy(&t32, hdr + 52, 4);
	fpl = le32_to_cpu(t32);
	if (snl > 256 || fpl > PATH_MAX)
		goto out_close;

	sn = kmalloc(snl + 1, GFP_KERNEL);
	if (!sn)
		goto out_close;
	nr = kernel_read(sf, sn, snl, &pos);
	if (nr != (ssize_t)snl)
		goto out_free;
	sn[snl] = 0;

	fp_path = kmalloc(fpl + 1, GFP_KERNEL);
	if (!fp_path)
		goto out_free;
	nr = kernel_read(sf, fp_path, fpl, &pos);
	if (nr != (ssize_t)fpl)
		goto out_free;
	fp_path[fpl] = 0;

	if (!work->tcon || !work->tcon->share_conf ||
	    strcmp(work->tcon->share_conf->name, sn))
		goto out_free;

	err = kern_path(fp_path, LOOKUP_FOLLOW, &fkp);
	if (err)
		goto out_free;
	filp = dentry_open(&fkp, O_RDWR, current_cred());
	path_put(&fkp);
	if (IS_ERR(filp)) {
		err = kern_path(fp_path, LOOKUP_FOLLOW, &fkp);
		if (err)
			goto out_free;
		filp = dentry_open(&fkp, O_RDONLY, current_cred());
		path_put(&fkp);
		if (IS_ERR(filp))
			goto out_free;
	}

	fp = ksmbd_open_fd(work, filp);
	if (IS_ERR(fp)) {
		fput(filp);
		fp = NULL;
		goto out_free;
	}

	memcpy(fp->create_guid, guid, SMB2_CREATE_GUID_SIZE);
	memcpy(&fp->daccess, hdr + 32, 4);
	if (fp->f_ci)
		memcpy(&fp->f_ci->m_fattr, hdr + 36, 4);
	memcpy(&fp->coption, hdr + 40, 4);
	memcpy(&t32, hdr + 44, 4);
	dt = le32_to_cpu(t32);
	fp->durable_timeout = dt;
	fp->is_durable = true;
	fp->is_persistent = true;
	ksmbd_open_durable_fd(fp);
	fp->persistent_id = persistent_id;

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

	if (!fp->is_persistent)
		return;
	ksmbd_ph_build_path(ph_path, sizeof(ph_path), fp->create_guid);
	err = kern_path(ph_path, LOOKUP_FOLLOW, &kp);
	if (err)
		return;
	inode_lock(d_inode(kp.dentry->d_parent));
	vfs_unlink(mnt_idmap(kp.mnt), d_inode(kp.dentry->d_parent),
		   kp.dentry, NULL);
	inode_unlock(d_inode(kp.dentry->d_parent));
	path_put(&kp);
}
