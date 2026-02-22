#ifndef __KSMBD_COMPAT_H__
#define __KSMBD_COMPAT_H__

#include <linux/version.h>
#include <linux/workqueue.h>

/*
 * disable_work_sync() was introduced in Linux 6.13.
 * On older kernels, fall back to cancel_work_sync().
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 13, 0)
static inline bool disable_work_sync(struct work_struct *work)
{
	return cancel_work_sync(work);
}
#endif

struct dentry;
struct inode;
struct path;
struct xattr_dos_attrib;

/* linux vfs */
int compat_inode_permission(struct path *path, struct inode *inode, int mask);

/* ksmbd vfs */
ssize_t compat_ksmbd_vfs_getxattr(struct path *path, struct dentry *dentry,
				  char *xattr_name, char **xattr_buf);
int compat_ksmbd_vfs_get_dos_attrib_xattr(const struct path *path,
					  struct dentry *dentry,
					  struct xattr_dos_attrib *da);

int compat_ksmbd_vfs_set_dos_attrib_xattr(const struct path *path,
					  struct xattr_dos_attrib *da,
					  bool get_write);

#endif
