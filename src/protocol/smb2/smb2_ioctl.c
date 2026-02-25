// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *
 *   smb2_ioctl.c - SMB2_IOCTL handler
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


static int fsctl_copychunk(struct ksmbd_work *work,
			   struct copychunk_ioctl_req *ci_req,
			   unsigned int cnt_code,
			   unsigned int input_count,
			   unsigned long long volatile_id,
			   unsigned long long persistent_id,
			   struct smb2_ioctl_rsp *rsp)
{
	struct copychunk_ioctl_rsp *ci_rsp;
	struct ksmbd_file *src_fp = NULL, *dst_fp = NULL;
	struct srv_copychunk *chunks;
	unsigned int i, chunk_count, chunk_count_written = 0;
	unsigned int chunk_size_written = 0;
	loff_t total_size_written = 0;
	int ret = 0;

	ci_rsp = (struct copychunk_ioctl_rsp *)&rsp->Buffer[0];

	rsp->VolatileFileId = volatile_id;
	rsp->PersistentFileId = persistent_id;
	ci_rsp->ChunksWritten =
		cpu_to_le32(ksmbd_server_side_copy_max_chunk_count());
	ci_rsp->ChunkBytesWritten =
		cpu_to_le32(ksmbd_server_side_copy_max_chunk_size());
	ci_rsp->TotalBytesWritten =
		cpu_to_le32(ksmbd_server_side_copy_max_total_size());

	chunks = (struct srv_copychunk *)&ci_req->Chunks[0];
	chunk_count = le32_to_cpu(ci_req->ChunkCount);
	if (chunk_count == 0)
		goto out;
	total_size_written = 0;

	/* verify the SRV_COPYCHUNK_COPY packet */
	if (chunk_count > ksmbd_server_side_copy_max_chunk_count() ||
	    input_count < offsetof(struct copychunk_ioctl_req, Chunks) +
	     chunk_count * sizeof(struct srv_copychunk)) {
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		return -EINVAL;
	}

	for (i = 0; i < chunk_count; i++) {
		if (le32_to_cpu(chunks[i].Length) == 0 ||
		    le32_to_cpu(chunks[i].Length) > ksmbd_server_side_copy_max_chunk_size())
			break;
		total_size_written += le32_to_cpu(chunks[i].Length);
	}

	if (i < chunk_count ||
	    total_size_written > ksmbd_server_side_copy_max_total_size()) {
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		return -EINVAL;
	}

	src_fp = ksmbd_lookup_foreign_fd(work,
					 le64_to_cpu(ci_req->ResumeKey[0]));
	dst_fp = ksmbd_lookup_fd_slow(work, volatile_id, persistent_id);
	ret = -EINVAL;
	if (!src_fp ||
	    src_fp->persistent_id != le64_to_cpu(ci_req->ResumeKey[1])) {
		rsp->hdr.Status = STATUS_OBJECT_NAME_NOT_FOUND;
		goto out;
	}

	if (!dst_fp) {
		rsp->hdr.Status = STATUS_FILE_CLOSED;
		goto out;
	}

	/*
	 * FILE_READ_DATA should only be included in
	 * the FSCTL_COPYCHUNK case
	 */
	if (cnt_code == FSCTL_COPYCHUNK &&
	    !(dst_fp->daccess & (FILE_READ_DATA_LE | FILE_GENERIC_READ_LE))) {
		rsp->hdr.Status = STATUS_ACCESS_DENIED;
		goto out;
	}

	ret = ksmbd_vfs_copy_file_ranges(work, src_fp, dst_fp,
					 chunks, chunk_count,
					 &chunk_count_written,
					 &chunk_size_written,
					 &total_size_written);
	if (ret < 0) {
		if (ret == -EACCES)
			rsp->hdr.Status = STATUS_ACCESS_DENIED;
		if (ret == -EAGAIN)
			rsp->hdr.Status = STATUS_FILE_LOCK_CONFLICT;
		else if (ret == -EBADF)
			rsp->hdr.Status = STATUS_INVALID_HANDLE;
		else if (ret == -EFBIG || ret == -ENOSPC)
			rsp->hdr.Status = STATUS_DISK_FULL;
		else if (ret == -EINVAL)
			rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		else if (ret == -EISDIR)
			rsp->hdr.Status = STATUS_FILE_IS_A_DIRECTORY;
		else if (ret == -E2BIG)
			rsp->hdr.Status = STATUS_INVALID_VIEW_SIZE;
		else
			rsp->hdr.Status = STATUS_UNEXPECTED_IO_ERROR;
	}

	/*
	 * If chunks were successfully written, compute the last chunk's
	 * written size from total_size_written minus the preceding chunks.
	 * ksmbd_vfs_copy_file_ranges does not update chunk_size_written.
	 */
	if (chunk_count_written > 0) {
		loff_t preceding = 0;

		for (i = 0; i + 1 < chunk_count_written; i++)
			preceding += le32_to_cpu(chunks[i].Length);
		chunk_size_written = (unsigned int)(total_size_written - preceding);
	}

	ci_rsp->ChunksWritten = cpu_to_le32(chunk_count_written);
	ci_rsp->ChunkBytesWritten = cpu_to_le32(chunk_size_written);
	ci_rsp->TotalBytesWritten = cpu_to_le32(total_size_written);

#ifdef CONFIG_KSMBD_FRUIT
	/*
	 * Apple COPYFILE: after data copy succeeds, also copy
	 * user.* xattrs (FinderInfo, resource forks, DosStream
	 * attributes) from source to destination.
	 */
	if (!ret && work->conn->is_fruit && src_fp && dst_fp &&
	    (server_conf.flags & KSMBD_GLOBAL_FLAG_FRUIT_COPYFILE)) {
		ksmbd_vfs_copy_xattrs(
			src_fp->filp->f_path.dentry,
			dst_fp->filp->f_path.dentry,
			&dst_fp->filp->f_path);
	}
#endif

out:
	ksmbd_fd_put(work, src_fp);
	ksmbd_fd_put(work, dst_fp);
	return ret;
}

static __be32 idev_ipv4_address(struct in_device *idev)
{
	__be32 addr = 0;

	struct in_ifaddr *ifa;

	rcu_read_lock();
	in_dev_for_each_ifa_rcu(ifa, idev) {
		if (ifa->ifa_flags & IFA_F_SECONDARY)
			continue;

		addr = ifa->ifa_address;
		break;
	}
	rcu_read_unlock();
	return addr;
}

static int fsctl_query_iface_info_ioctl(struct ksmbd_conn *conn,
					struct smb2_ioctl_rsp *rsp,
					unsigned int out_buf_len)
{
	struct network_interface_info_ioctl_rsp *nii_rsp = NULL;
	int nbytes = 0;
	struct net_device *netdev;
	struct sockaddr_storage_rsp *sockaddr_storage;
	unsigned int flags;
	unsigned long long speed;

	rtnl_lock();
	for_each_netdev(&init_net, netdev) {
		bool ipv4_set = false;

		if (netdev->type == ARPHRD_LOOPBACK)
			continue;

		if (!ksmbd_find_netdev_name_iface_list(netdev->name))
			continue;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 17, 0)
		flags = netif_get_flags(netdev);
#else
		flags = dev_get_flags(netdev);
#endif
		if (!(flags & IFF_RUNNING))
			continue;
ipv6_retry:
		if (out_buf_len <
		    nbytes + sizeof(struct network_interface_info_ioctl_rsp)) {
			rtnl_unlock();
			return -ENOSPC;
		}

		nii_rsp = (struct network_interface_info_ioctl_rsp *)
				&rsp->Buffer[nbytes];
		nii_rsp->IfIndex = cpu_to_le32(netdev->ifindex);

		nii_rsp->Capability = 0;
		if (netdev->real_num_tx_queues > 1)
			nii_rsp->Capability |= cpu_to_le32(RSS_CAPABLE);
		if (ksmbd_rdma_capable_netdev(netdev))
			nii_rsp->Capability |= cpu_to_le32(RDMA_CAPABLE);

		nii_rsp->Next = cpu_to_le32(152);
		nii_rsp->Reserved = 0;

		if (netdev->ethtool_ops->get_link_ksettings) {
			struct ethtool_link_ksettings cmd;

			netdev->ethtool_ops->get_link_ksettings(netdev, &cmd);
			speed = cmd.base.speed;
		} else {
			ksmbd_debug(SMB, "%s %s\n", netdev->name,
				    "speed is unknown, defaulting to 1Gb/sec");
			speed = SPEED_1000;
		}

		speed *= 1000000;
		nii_rsp->LinkSpeed = cpu_to_le64(speed);

		sockaddr_storage = (struct sockaddr_storage_rsp *)
					nii_rsp->SockAddr_Storage;
		memset(sockaddr_storage, 0, 128);

		if (!ipv4_set) {
			struct in_device *idev;

			sockaddr_storage->Family = cpu_to_le16(INTERNETWORK);
			sockaddr_storage->addr4.Port = 0;

			idev = __in_dev_get_rtnl(netdev);
			if (!idev)
				continue;
			sockaddr_storage->addr4.IPv4address =
						idev_ipv4_address(idev);
			nbytes += sizeof(struct network_interface_info_ioctl_rsp);
			ipv4_set = true;
			goto ipv6_retry;
		} else {
			struct inet6_dev *idev6;
			struct inet6_ifaddr *ifa;
			__u8 *ipv6_addr = sockaddr_storage->addr6.IPv6address;

			sockaddr_storage->Family = cpu_to_le16(INTERNETWORKV6);
			sockaddr_storage->addr6.Port = 0;
			sockaddr_storage->addr6.FlowInfo = 0;

			idev6 = __in6_dev_get(netdev);
			if (!idev6)
				continue;

			list_for_each_entry(ifa, &idev6->addr_list, if_list) {
				if (ifa->flags & (IFA_F_TENTATIVE |
							IFA_F_DEPRECATED))
					continue;
				memcpy(ipv6_addr, ifa->addr.s6_addr, 16);
				break;
			}
			sockaddr_storage->addr6.ScopeId = 0;
			nbytes += sizeof(struct network_interface_info_ioctl_rsp);
		}
	}
	rtnl_unlock();

	/* zero if this is last one */
	if (nii_rsp)
		nii_rsp->Next = 0;

	rsp->PersistentFileId = SMB2_NO_FID;
	rsp->VolatileFileId = SMB2_NO_FID;
	return nbytes;
}

static int fsctl_query_allocated_ranges(struct ksmbd_work *work, u64 id,
					struct file_allocated_range_buffer *qar_req,
					struct file_allocated_range_buffer *qar_rsp,
					unsigned int in_count, unsigned int *out_count)
{
	struct ksmbd_file *fp;
	loff_t start, length;
	int ret = 0;

	*out_count = 0;
	if (in_count == 0)
		return -EINVAL;

	start = le64_to_cpu(qar_req->file_offset);
	length = le64_to_cpu(qar_req->length);

	if (start < 0 || length < 0)
		return -EINVAL;

	fp = ksmbd_lookup_fd_fast(work, id);
	if (!fp)
		return -ENOENT;

	ret = ksmbd_vfs_fqar_lseek(fp, start, length,
				   qar_rsp, in_count, out_count);
	if (ret && ret != -E2BIG)
		*out_count = 0;

	ksmbd_fd_put(work, fp);
	return ret;
}

static inline int fsctl_set_sparse(struct ksmbd_work *work, u64 id,
				   struct file_sparse *sparse)
{
	struct ksmbd_file *fp;
	int ret = 0;
	__le32 old_fattr;

	fp = ksmbd_lookup_fd_fast(work, id);
	if (!fp)
		return -ENOENT;

	old_fattr = fp->f_ci->m_fattr;
	if (sparse->SetSparse)
		fp->f_ci->m_fattr |= ATTR_SPARSE_FILE_LE;
	else
		fp->f_ci->m_fattr &= ~ATTR_SPARSE_FILE_LE;

	if (fp->f_ci->m_fattr != old_fattr &&
	    test_share_config_flag(work->tcon->share_conf,
				   KSMBD_SHARE_FLAG_STORE_DOS_ATTRS)) {
		struct xattr_dos_attrib da;

		ret = compat_ksmbd_vfs_get_dos_attrib_xattr(&fp->filp->f_path,
							    fp->filp->f_path.dentry,
							    &da);
		if (ret <= 0)
			goto out;

		da.attr = le32_to_cpu(fp->f_ci->m_fattr);
		ret = compat_ksmbd_vfs_set_dos_attrib_xattr(&fp->filp->f_path,
							    &da,
							    true);
		if (ret)
			fp->f_ci->m_fattr = old_fattr;
	}

out:
	ksmbd_fd_put(work, fp);
	return ret;
}

static int fsctl_request_resume_key(struct ksmbd_work *work,
				    struct smb2_ioctl_req *req,
				    struct resume_key_ioctl_rsp *key_rsp)
{
	struct ksmbd_file *fp;

	fp = ksmbd_lookup_fd_slow(work, req->VolatileFileId, req->PersistentFileId);
	if (!fp)
		return -ENOENT;

	memset(key_rsp, 0, sizeof(*key_rsp));
	key_rsp->ResumeKey[0] = req->VolatileFileId;
	key_rsp->ResumeKey[1] = req->PersistentFileId;
	ksmbd_fd_put(work, fp);

	return 0;
}

/**
 * smb2_ioctl() - handler for smb2 ioctl command
 * @work:	smb work containing ioctl command buffer
 *
 * Return:	0 on success, otherwise error
 */
int smb2_ioctl(struct ksmbd_work *work)
{
	struct smb2_ioctl_req *req;
	struct smb2_ioctl_rsp *rsp;
	unsigned int cnt_code, nbytes = 0, out_buf_len, in_buf_len;
	u64 id = KSMBD_NO_FID;
	struct ksmbd_conn *conn = work->conn;
	int ret = 0;
	char *buffer;

	ksmbd_debug(SMB, "Received smb2 ioctl request\n");

	if (work->next_smb2_rcv_hdr_off) {
		req = ksmbd_req_buf_next(work);
		rsp = ksmbd_resp_buf_next(work);
		if (!has_file_id(req->VolatileFileId)) {
			ksmbd_debug(SMB, "Compound request set FID = %llu\n",
				    work->compound_fid);
			id = work->compound_fid;
		}
	} else {
		req = smb2_get_msg(work->request_buf);
		rsp = smb2_get_msg(work->response_buf);
	}

	if (!has_file_id(id))
		id = req->VolatileFileId;

	if (req->Flags != cpu_to_le32(SMB2_0_IOCTL_IS_FSCTL) &&
	    req->Flags != 0) {
		ret = -EOPNOTSUPP;
		goto out;
	}

	cnt_code = le32_to_cpu(req->CntCode);
	ret = smb2_calc_max_out_buf_len(work, 48,
					le32_to_cpu(req->MaxOutputResponse));
	if (ret < 0) {
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;
		goto out;
	}
	out_buf_len = (unsigned int)ret;
	in_buf_len = le32_to_cpu(req->InputCount);

	/* Validate InputOffset before using it as pointer arithmetic */
	if (in_buf_len > 0) {
		unsigned int input_off = le32_to_cpu(req->InputOffset);
		unsigned int req_len = get_rfc1002_len(work->request_buf) + 4;

		if (work->next_smb2_rcv_hdr_off)
			req_len -= work->next_smb2_rcv_hdr_off;

		if (input_off < sizeof(struct smb2_ioctl_req) ||
		    input_off > req_len ||
		    in_buf_len > req_len - input_off) {
			pr_err_ratelimited("Invalid IOCTL InputOffset %u or InputCount %u (req_len=%u)\n",
					   input_off, in_buf_len, req_len);
			ret = -EINVAL;
			rsp->hdr.Status = STATUS_INVALID_PARAMETER;
			goto out;
		}
	}

	buffer = (char *)req + le32_to_cpu(req->InputOffset);

	/* Try registered FSCTL handlers first */
	ret = ksmbd_dispatch_fsctl(work, cnt_code, id, buffer,
				   in_buf_len, out_buf_len, rsp, &nbytes);
	if (ret != -EOPNOTSUPP)
		goto done;

	/* Legacy compatibility fallback for non-registered handlers */
	ret = 0;
	switch (cnt_code) {
	/* Legacy compatibility fallback */
	case FSCTL_QUERY_NETWORK_INTERFACE_INFO:
		ret = fsctl_query_iface_info_ioctl(conn, rsp, out_buf_len);
		if (ret < 0)
			goto out;
		nbytes = ret;
		break;
	/* Legacy compatibility fallback */
	case FSCTL_REQUEST_RESUME_KEY:
		if (out_buf_len < sizeof(struct resume_key_ioctl_rsp)) {
			ret = -EINVAL;
			goto out;
		}

		ret = fsctl_request_resume_key(work, req,
					       (struct resume_key_ioctl_rsp *)&rsp->Buffer[0]);
		if (ret < 0)
			goto out;
		rsp->PersistentFileId = req->PersistentFileId;
		rsp->VolatileFileId = req->VolatileFileId;
		nbytes = sizeof(struct resume_key_ioctl_rsp);
		break;
	/* Legacy compatibility fallback */
	case FSCTL_COPYCHUNK:
	case FSCTL_COPYCHUNK_WRITE:
		if (!test_tree_conn_flag(work->tcon, KSMBD_TREE_CONN_FLAG_WRITABLE)) {
			ksmbd_debug(SMB,
				    "User does not have write permission\n");
			ret = -EACCES;
			goto out;
		}

		if (in_buf_len <= sizeof(struct copychunk_ioctl_req)) {
			ret = -EINVAL;
			goto out;
		}

		if (out_buf_len < sizeof(struct copychunk_ioctl_rsp)) {
			ret = -EINVAL;
			goto out;
		}

		nbytes = sizeof(struct copychunk_ioctl_rsp);
		rsp->VolatileFileId = req->VolatileFileId;
		rsp->PersistentFileId = req->PersistentFileId;
		fsctl_copychunk(work,
				(struct copychunk_ioctl_req *)buffer,
				le32_to_cpu(req->CntCode),
				le32_to_cpu(req->InputCount),
				req->VolatileFileId,
				req->PersistentFileId,
				rsp);
		break;
	/* Legacy compatibility fallback */
	case FSCTL_SET_SPARSE:
		if (in_buf_len < sizeof(struct file_sparse)) {
			ret = -EINVAL;
			goto out;
		}

		ret = fsctl_set_sparse(work, id, (struct file_sparse *)buffer);
		if (ret < 0)
			goto out;
		break;
	/* Legacy compatibility fallback */
	case FSCTL_SET_ZERO_DATA:
	{
		struct file_zero_data_information *zero_data;
		struct ksmbd_file *fp;
		loff_t off, len, bfz;

		if (!test_tree_conn_flag(work->tcon, KSMBD_TREE_CONN_FLAG_WRITABLE)) {
			ksmbd_debug(SMB,
				    "User does not have write permission\n");
			ret = -EACCES;
			goto out;
		}

		if (in_buf_len < sizeof(struct file_zero_data_information)) {
			ret = -EINVAL;
			goto out;
		}

		zero_data =
			(struct file_zero_data_information *)buffer;

		off = le64_to_cpu(zero_data->FileOffset);
		bfz = le64_to_cpu(zero_data->BeyondFinalZero);
		if (off < 0 || bfz < 0 || off > bfz) {
			ret = -EINVAL;
			goto out;
		}

		len = bfz - off;
		if (len) {
			fp = ksmbd_lookup_fd_fast(work, id);
			if (!fp) {
				ret = -ENOENT;
				goto out;
			}

			ret = ksmbd_vfs_zero_data(work, fp, off, len);
			ksmbd_fd_put(work, fp);
			if (ret < 0)
				goto out;
		}
		break;
	}
	/* Legacy compatibility fallback */
	case FSCTL_QUERY_ALLOCATED_RANGES:
		if (in_buf_len < sizeof(struct file_allocated_range_buffer)) {
			ret = -EINVAL;
			goto out;
		}

		ret = fsctl_query_allocated_ranges(work, id,
			(struct file_allocated_range_buffer *)buffer,
			(struct file_allocated_range_buffer *)&rsp->Buffer[0],
			out_buf_len /
			sizeof(struct file_allocated_range_buffer), &nbytes);
		if (ret == -E2BIG) {
			rsp->hdr.Status = STATUS_BUFFER_OVERFLOW;
		} else if (ret < 0) {
			nbytes = 0;
			goto out;
		}

		nbytes *= sizeof(struct file_allocated_range_buffer);
		break;
	/* Legacy compatibility fallback */
	case FSCTL_GET_REPARSE_POINT:
	{
		struct reparse_data_buffer *reparse_ptr;
		struct ksmbd_file *fp;

		reparse_ptr = (struct reparse_data_buffer *)&rsp->Buffer[0];
		fp = ksmbd_lookup_fd_fast(work, id);
		if (!fp) {
			pr_err("not found fp!!\n");
			ret = -ENOENT;
			goto out;
		}

		reparse_ptr->ReparseTag =
			smb2_get_reparse_tag_special_file(file_inode(fp->filp)->i_mode);
		reparse_ptr->ReparseDataLength = 0;
		ksmbd_fd_put(work, fp);
		nbytes = sizeof(struct reparse_data_buffer);
		break;
	}
	/* Legacy compatibility fallback */
	case FSCTL_DUPLICATE_EXTENTS_TO_FILE:
	{
		struct ksmbd_file *fp_in, *fp_out = NULL;
		struct duplicate_extents_to_file *dup_ext;
		loff_t src_off, dst_off, length, cloned;

		if (in_buf_len < sizeof(struct duplicate_extents_to_file)) {
			ret = -EINVAL;
			goto out;
		}

		dup_ext = (struct duplicate_extents_to_file *)buffer;

		fp_in = ksmbd_lookup_fd_slow(work, dup_ext->VolatileFileHandle,
					     dup_ext->PersistentFileHandle);
		if (!fp_in) {
			pr_err("not found file handle in duplicate extent to file\n");
			ret = -ENOENT;
			goto out;
		}

		fp_out = ksmbd_lookup_fd_fast(work, id);
		if (!fp_out) {
			pr_err("not found fp\n");
			ret = -ENOENT;
			goto dup_ext_out;
		}

		src_off = le64_to_cpu(dup_ext->SourceFileOffset);
		dst_off = le64_to_cpu(dup_ext->TargetFileOffset);
		length = le64_to_cpu(dup_ext->ByteCount);
		/*
		 * XXX: It is not clear if FSCTL_DUPLICATE_EXTENTS_TO_FILE
		 * should fall back to vfs_copy_file_range().  This could be
		 * beneficial when re-exporting nfs/smb mount, but note that
		 * this can result in partial copy that returns an error status.
		 * If/when FSCTL_DUPLICATE_EXTENTS_TO_FILE_EX is implemented,
		 * fall back to vfs_copy_file_range(), should be avoided when
		 * the flag DUPLICATE_EXTENTS_DATA_EX_SOURCE_ATOMIC is set.
		 */
		cloned = vfs_clone_file_range(fp_in->filp, src_off,
					      fp_out->filp, dst_off, length, 0);
		if (cloned == -EXDEV || cloned == -EOPNOTSUPP) {
			ret = -EOPNOTSUPP;
			goto dup_ext_out;
		} else if (cloned != length) {
			cloned = vfs_copy_file_range(fp_in->filp, src_off,
						     fp_out->filp, dst_off,
						     length, 0);
			if (cloned != length) {
				if (cloned < 0)
					ret = cloned;
				else
					ret = -EINVAL;
			}
		}

dup_ext_out:
		ksmbd_fd_put(work, fp_in);
		ksmbd_fd_put(work, fp_out);
		if (ret < 0)
			goto out;
		break;
	}
	default:
		ksmbd_debug(SMB, "unknown ioctl command 0x%x\n",
			    cnt_code);
		ret = -EOPNOTSUPP;
		goto out;
	}

done:
	rsp->CntCode = cpu_to_le32(cnt_code);
	rsp->InputCount = cpu_to_le32(0);
	rsp->InputOffset = cpu_to_le32(112);
	rsp->OutputOffset = cpu_to_le32(112);
	rsp->OutputCount = cpu_to_le32(nbytes);
	rsp->StructureSize = cpu_to_le16(49);
	rsp->Reserved = cpu_to_le16(0);
	rsp->Flags = cpu_to_le32(0);
	rsp->Reserved2 = cpu_to_le32(0);
	ret = ksmbd_iov_pin_rsp(work, rsp, sizeof(struct smb2_ioctl_rsp) + nbytes);
	if (!ret)
		return ret;

out:
	if (ret == -EACCES)
		rsp->hdr.Status = STATUS_ACCESS_DENIED;
	else if (ret == -ENOENT)
		rsp->hdr.Status = STATUS_OBJECT_NAME_NOT_FOUND;
	else if (ret == -EOPNOTSUPP)
		rsp->hdr.Status = STATUS_INVALID_DEVICE_REQUEST;
	else if (ret == -ENOSPC)
		rsp->hdr.Status = STATUS_BUFFER_TOO_SMALL;
	else if (ret < 0 || rsp->hdr.Status == 0)
		rsp->hdr.Status = STATUS_INVALID_PARAMETER;

	smb2_set_err_rsp(work);
	return ret;
}

/**
 * smb20_oplock_break_ack() - handler for smb2.0 oplock break command
 * @work:	smb work containing oplock break command buffer
 *
 * Return:	0
 */
