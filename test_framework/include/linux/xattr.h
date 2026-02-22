/* Stub for userspace testing */
#ifndef _LINUX_XATTR_H
#define _LINUX_XATTR_H
#define XATTR_USER_PREFIX "user."
#define XATTR_USER_PREFIX_LEN (sizeof(XATTR_USER_PREFIX) - 1)

struct mnt_idmap { int dummy; };
struct dentry;

static struct mnt_idmap nop_mnt_idmap;

static inline ssize_t vfs_getxattr(struct mnt_idmap *idmap,
				   struct dentry *dentry,
				   const char *name,
				   void *value, size_t size)
{
	(void)idmap; (void)dentry; (void)name; (void)value; (void)size;
	return -1; /* ENODATA */
}
#endif
