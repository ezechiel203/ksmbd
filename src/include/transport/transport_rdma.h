/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *   Copyright (C) 2017, Microsoft Corporation.
 *   Copyright (C) 2018, LG Electronics.
 */

#ifndef __KSMBD_TRANSPORT_RDMA_H__
#define __KSMBD_TRANSPORT_RDMA_H__

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>
#include <linux/errno.h>

#define SMBD_DEFAULT_IOSIZE (8 * 1024 * 1024)
#define SMBD_MIN_IOSIZE (512 * 1024)
#define SMBD_MAX_IOSIZE (16 * 1024 * 1024)

/* SMB DIRECT negotiation request packet [MS-SMBD] 2.2.1 */
struct smb_direct_negotiate_req {
	__le16 min_version;
	__le16 max_version;
	__le16 reserved;
	__le16 credits_requested;
	__le32 preferred_send_size;
	__le32 max_receive_size;
	__le32 max_fragmented_size;
} __packed;

/* SMB DIRECT negotiation response packet [MS-SMBD] 2.2.2 */
struct smb_direct_negotiate_resp {
	__le16 min_version;
	__le16 max_version;
	__le16 negotiated_version;
	__le16 reserved;
	__le16 credits_requested;
	__le16 credits_granted;
	__le32 status;
	__le32 max_readwrite_size;
	__le32 preferred_send_size;
	__le32 max_receive_size;
	__le32 max_fragmented_size;
} __packed;

#define SMB_DIRECT_RESPONSE_REQUESTED 0x0001

/* SMB DIRECT data transfer packet with payload [MS-SMBD] 2.2.3 */
struct smb_direct_data_transfer {
	__le16 credits_requested;
	__le16 credits_granted;
	__le16 flags;
	__le16 reserved;
	__le32 remaining_data_length;
	__le32 data_offset;
	__le32 data_length;
	__le32 padding;
	__u8 buffer[];
} __packed;

/*
 * Use KSMBD_SMBDIRECT instead of CONFIG_SMB_SERVER_SMBDIRECT so that
 * out-of-tree builds are not tricked by the host kernel's autoconf.h
 * which may define CONFIG_SMB_SERVER_SMBDIRECT for the in-tree ksmbd.
 * The ksmbd Makefile sets -DKSMBD_SMBDIRECT only when RDMA is wanted.
 */
#if defined(KSMBD_SMBDIRECT) || defined(KSMBD_TRANSPORT_RDMA_IMPL)
int ksmbd_rdma_init(void);
void ksmbd_rdma_stop_listening(void);
void ksmbd_rdma_destroy(void);
bool ksmbd_rdma_listener_active(void);
bool ksmbd_rdma_capable_netdev(struct net_device *netdev);
void init_smbd_max_io_size(unsigned int sz);
unsigned int get_smbd_max_read_write_size(void);
bool ksmbd_rdma_transform_supported(struct ksmbd_conn *conn, __le16 transform_id);
#else
static inline int ksmbd_rdma_init(void) { return 0; }
static inline void ksmbd_rdma_stop_listening(void) { }
static inline void ksmbd_rdma_destroy(void) { }
static inline bool ksmbd_rdma_listener_active(void) { return false; }
static inline bool ksmbd_rdma_capable_netdev(struct net_device *netdev) { return false; }
static inline void init_smbd_max_io_size(unsigned int sz) { }
static inline unsigned int get_smbd_max_read_write_size(void) { return 0; }
static inline bool ksmbd_rdma_transform_supported(struct ksmbd_conn *conn,
						   __le16 transform_id)
{
	return false;
}
#endif

/*
 * RDMA credit pool - testable credit accounting layer.
 *
 * This abstraction encapsulates the credit math used by SMB Direct
 * transport connections.  It is designed to be testable without RDMA
 * hardware: the pool tracks available, granted (posted), and reclaimed
 * credits with atomic operations and spinlock protection.
 *
 * The pool maintains the invariant:
 *   granted + available == total
 *
 * Used by transport_rdma.c for actual credit management and by
 * ksmbd_test_rdma_credit.c for KUnit testing.
 */

#define SMBD_CREDIT_POOL_DEFAULT_TOTAL	255

struct smbd_credit_pool {
	spinlock_t	lock;
	int		total;		/* fixed total capacity */
	int		available;	/* credits available to grant */
	int		granted;	/* credits currently outstanding */
	atomic_t	lifetime_granted;   /* cumulative grants */
	atomic_t	lifetime_reclaimed; /* cumulative reclaims */
};

/**
 * smbd_credit_pool_init - initialize a credit pool
 * @pool: pool to initialize
 * @total: total number of credits (e.g. 255)
 *
 * Returns 0 on success, -EINVAL if total <= 0.
 */
static inline int smbd_credit_pool_init(struct smbd_credit_pool *pool,
					int total)
{
	if (total <= 0)
		return -EINVAL;

	spin_lock_init(&pool->lock);
	pool->total = total;
	pool->available = total;
	pool->granted = 0;
	atomic_set(&pool->lifetime_granted, 0);
	atomic_set(&pool->lifetime_reclaimed, 0);
	return 0;
}

/**
 * smbd_credit_pool_grant - grant credits from the pool
 * @pool: credit pool
 * @count: number of credits to grant
 *
 * Returns 0 on success, -ENOSPC if not enough credits available,
 * -EINVAL if count <= 0.
 */
static inline int smbd_credit_pool_grant(struct smbd_credit_pool *pool,
					 int count)
{
	int ret = 0;

	if (count < 0)
		return -EINVAL;
	if (count == 0)
		return 0;

	spin_lock(&pool->lock);
	if (count > pool->available) {
		ret = -ENOSPC;
	} else {
		pool->available -= count;
		pool->granted += count;
		atomic_add(count, &pool->lifetime_granted);
	}
	spin_unlock(&pool->lock);
	return ret;
}

/**
 * smbd_credit_pool_reclaim - return credits to the pool
 * @pool: credit pool
 * @count: number of credits to reclaim
 *
 * Returns 0 on success, -EINVAL if count < 0 or count > granted.
 */
static inline int smbd_credit_pool_reclaim(struct smbd_credit_pool *pool,
					   int count)
{
	int ret = 0;

	if (count < 0)
		return -EINVAL;
	if (count == 0)
		return 0;

	spin_lock(&pool->lock);
	if (count > pool->granted) {
		ret = -EINVAL;
	} else {
		pool->granted -= count;
		pool->available += count;
		atomic_add(count, &pool->lifetime_reclaimed);
	}
	spin_unlock(&pool->lock);
	return ret;
}

/**
 * smbd_credit_pool_reclaim_all - reclaim all outstanding credits
 * @pool: credit pool
 *
 * Returns the number of credits reclaimed (the previous granted count).
 */
static inline int smbd_credit_pool_reclaim_all(struct smbd_credit_pool *pool)
{
	int reclaimed;

	spin_lock(&pool->lock);
	reclaimed = pool->granted;
	pool->available += reclaimed;
	pool->granted = 0;
	atomic_add(reclaimed, &pool->lifetime_reclaimed);
	spin_unlock(&pool->lock);
	return reclaimed;
}

/**
 * smbd_credit_pool_audit - verify credit invariants
 * @pool: credit pool
 *
 * Returns 0 if invariants hold, -EINVAL otherwise.
 */
static inline int smbd_credit_pool_audit(struct smbd_credit_pool *pool)
{
	int avail, granted, total;

	spin_lock(&pool->lock);
	avail = pool->available;
	granted = pool->granted;
	total = pool->total;
	spin_unlock(&pool->lock);

	/* Invariant: granted + available == total */
	if (granted + avail != total)
		return -EINVAL;

	/* No negative values */
	if (avail < 0 || granted < 0 || total <= 0)
		return -EINVAL;

	return 0;
}

/**
 * smbd_credit_pool_check_leak - check for credit leaks
 * @pool: credit pool
 *
 * Returns 0 if lifetime_granted == lifetime_reclaimed and granted == 0,
 * -EINVAL if there is a leak.
 */
static inline int smbd_credit_pool_check_leak(struct smbd_credit_pool *pool)
{
	int granted, lg, lr;

	spin_lock(&pool->lock);
	granted = pool->granted;
	spin_unlock(&pool->lock);

	lg = atomic_read(&pool->lifetime_granted);
	lr = atomic_read(&pool->lifetime_reclaimed);

	if (granted != 0)
		return -EINVAL;
	if (lg != lr)
		return -EINVAL;
	return 0;
}

#endif /* __KSMBD_TRANSPORT_RDMA_H__ */
