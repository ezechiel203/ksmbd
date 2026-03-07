# Line-by-line Review: src/include/transport/transport_rdma.h

- L00001 [NONE] `/* SPDX-License-Identifier: GPL-2.0-or-later */`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` *   Copyright (C) 2017, Microsoft Corporation.`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` *   Copyright (C) 2018, LG Electronics.`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] `#ifndef __KSMBD_TRANSPORT_RDMA_H__`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] `#define __KSMBD_TRANSPORT_RDMA_H__`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `#include <linux/types.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `#include <linux/spinlock.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] `#include <linux/atomic.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `#include <linux/errno.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `#define SMBD_DEFAULT_IOSIZE (8 * 1024 * 1024)`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `#define SMBD_MIN_IOSIZE (512 * 1024)`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `#define SMBD_MAX_IOSIZE (16 * 1024 * 1024)`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `/* SMB DIRECT negotiation request packet [MS-SMBD] 2.2.1 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `struct smb_direct_negotiate_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `	__le16 min_version;`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] `	__le16 max_version;`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `	__le16 reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `	__le16 credits_requested;`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `	__le32 preferred_send_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `	__le32 max_receive_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `	__le32 max_fragmented_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `/* SMB DIRECT negotiation response packet [MS-SMBD] 2.2.2 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `struct smb_direct_negotiate_resp {`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `	__le16 min_version;`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `	__le16 max_version;`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] `	__le16 negotiated_version;`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `	__le16 reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `	__le16 credits_requested;`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `	__le16 credits_granted;`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `	__le32 status;`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] `	__le32 max_readwrite_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] `	__le32 preferred_send_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] `	__le32 max_receive_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] `	__le32 max_fragmented_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] `#define SMB_DIRECT_RESPONSE_REQUESTED 0x0001`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] `/* SMB DIRECT data transfer packet with payload [MS-SMBD] 2.2.3 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] `struct smb_direct_data_transfer {`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `	__le16 credits_requested;`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] `	__le16 credits_granted;`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] `	__le16 flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] `	__le16 reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `	__le32 remaining_data_length;`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `	__le32 data_offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] `	__le32 data_length;`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `	__le32 padding;`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] `	__u8 buffer[];`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] ` * Use KSMBD_SMBDIRECT instead of CONFIG_SMB_SERVER_SMBDIRECT so that`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] ` * out-of-tree builds are not tricked by the host kernel's autoconf.h`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] ` * which may define CONFIG_SMB_SERVER_SMBDIRECT for the in-tree ksmbd.`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] ` * The ksmbd Makefile sets -DKSMBD_SMBDIRECT only when RDMA is wanted.`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] `#ifdef KSMBD_SMBDIRECT`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] `int ksmbd_rdma_init(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `void ksmbd_rdma_stop_listening(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] `void ksmbd_rdma_destroy(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] `bool ksmbd_rdma_capable_netdev(struct net_device *netdev);`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] `void init_smbd_max_io_size(unsigned int sz);`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] `unsigned int get_smbd_max_read_write_size(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] `bool ksmbd_rdma_transform_supported(struct ksmbd_conn *conn, __le16 transform_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] `static inline int ksmbd_rdma_init(void) { return 0; }`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] `static inline void ksmbd_rdma_stop_listening(void) { }`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] `static inline void ksmbd_rdma_destroy(void) { }`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] `static inline bool ksmbd_rdma_capable_netdev(struct net_device *netdev) { return false; }`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] `static inline void init_smbd_max_io_size(unsigned int sz) { }`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] `static inline unsigned int get_smbd_max_read_write_size(void) { return 0; }`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] `static inline bool ksmbd_rdma_transform_supported(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] `						   __le16 transform_id)`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] `	return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] ` * RDMA credit pool - testable credit accounting layer.`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] ` * This abstraction encapsulates the credit math used by SMB Direct`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] ` * transport connections.  It is designed to be testable without RDMA`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] ` * hardware: the pool tracks available, granted (posted), and reclaimed`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] ` * credits with atomic operations and spinlock protection.`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] ` * The pool maintains the invariant:`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] ` *   granted + available == total`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] ` * Used by transport_rdma.c for actual credit management and by`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] ` * ksmbd_test_rdma_credit.c for KUnit testing.`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] `#define SMBD_CREDIT_POOL_DEFAULT_TOTAL	255`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] `struct smbd_credit_pool {`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] `	spinlock_t	lock;`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] `	int		total;		/* fixed total capacity */`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] `	int		available;	/* credits available to grant */`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] `	int		granted;	/* credits currently outstanding */`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [LIFETIME|] `	atomic_t	lifetime_granted;   /* cumulative grants */`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00111 [LIFETIME|] `	atomic_t	lifetime_reclaimed; /* cumulative reclaims */`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00112 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] ` * smbd_credit_pool_init - initialize a credit pool`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] ` * @pool: pool to initialize`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] ` * @total: total number of credits (e.g. 255)`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] ` * Returns 0 on success, -EINVAL if total <= 0.`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] `static inline int smbd_credit_pool_init(struct smbd_credit_pool *pool,`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] `					int total)`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] `	if (total <= 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00126 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] `	spin_lock_init(&pool->lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] `	pool->total = total;`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] `	pool->available = total;`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] `	pool->granted = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [LIFETIME|] `	atomic_set(&pool->lifetime_granted, 0);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00132 [LIFETIME|] `	atomic_set(&pool->lifetime_reclaimed, 0);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00133 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] ` * smbd_credit_pool_grant - grant credits from the pool`
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] ` * @pool: credit pool`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] ` * @count: number of credits to grant`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] ` * Returns 0 on success, -ENOSPC if not enough credits available,`
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] ` * -EINVAL if count <= 0.`
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] `static inline int smbd_credit_pool_grant(struct smbd_credit_pool *pool,`
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] `					 int count)`
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] `	int ret = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] `	if (count < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00151 [NONE] `	if (count == 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [LOCK|] `	spin_lock(&pool->lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00155 [NONE] `	if (count > pool->available) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] `		ret = -ENOSPC;`
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] `		pool->available -= count;`
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] `		pool->granted += count;`
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [LIFETIME|] `		atomic_add(count, &pool->lifetime_granted);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00161 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [LOCK|] `	spin_unlock(&pool->lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00163 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] ` * smbd_credit_pool_reclaim - return credits to the pool`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] ` * @pool: credit pool`
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] ` * @count: number of credits to reclaim`
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] ` * Returns 0 on success, -EINVAL if count < 0 or count > granted.`
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] `static inline int smbd_credit_pool_reclaim(struct smbd_credit_pool *pool,`
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [NONE] `					   int count)`
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [NONE] `	int ret = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00178 [NONE] `	if (count < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00179 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00180 [NONE] `	if (count == 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [LOCK|] `	spin_lock(&pool->lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00184 [NONE] `	if (count > pool->granted) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [NONE] `		ret = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00186 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00187 [NONE] `		pool->granted -= count;`
  Review: Low-risk line; verify in surrounding control flow.
- L00188 [NONE] `		pool->available += count;`
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [LIFETIME|] `		atomic_add(count, &pool->lifetime_reclaimed);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00190 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [LOCK|] `	spin_unlock(&pool->lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00192 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00193 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00194 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00195 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00196 [NONE] ` * smbd_credit_pool_reclaim_all - reclaim all outstanding credits`
  Review: Low-risk line; verify in surrounding control flow.
- L00197 [NONE] ` * @pool: credit pool`
  Review: Low-risk line; verify in surrounding control flow.
- L00198 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00199 [NONE] ` * Returns the number of credits reclaimed (the previous granted count).`
  Review: Low-risk line; verify in surrounding control flow.
- L00200 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00201 [NONE] `static inline int smbd_credit_pool_reclaim_all(struct smbd_credit_pool *pool)`
  Review: Low-risk line; verify in surrounding control flow.
- L00202 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00203 [NONE] `	int reclaimed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00204 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00205 [LOCK|] `	spin_lock(&pool->lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00206 [NONE] `	reclaimed = pool->granted;`
  Review: Low-risk line; verify in surrounding control flow.
- L00207 [NONE] `	pool->available += reclaimed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00208 [NONE] `	pool->granted = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00209 [LIFETIME|] `	atomic_add(reclaimed, &pool->lifetime_reclaimed);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00210 [LOCK|] `	spin_unlock(&pool->lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00211 [NONE] `	return reclaimed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00212 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00213 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00214 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00215 [NONE] ` * smbd_credit_pool_audit - verify credit invariants`
  Review: Low-risk line; verify in surrounding control flow.
- L00216 [NONE] ` * @pool: credit pool`
  Review: Low-risk line; verify in surrounding control flow.
- L00217 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00218 [NONE] ` * Returns 0 if invariants hold, -EINVAL otherwise.`
  Review: Low-risk line; verify in surrounding control flow.
- L00219 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00220 [NONE] `static inline int smbd_credit_pool_audit(struct smbd_credit_pool *pool)`
  Review: Low-risk line; verify in surrounding control flow.
- L00221 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00222 [NONE] `	int avail, granted, total;`
  Review: Low-risk line; verify in surrounding control flow.
- L00223 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00224 [LOCK|] `	spin_lock(&pool->lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00225 [NONE] `	avail = pool->available;`
  Review: Low-risk line; verify in surrounding control flow.
- L00226 [NONE] `	granted = pool->granted;`
  Review: Low-risk line; verify in surrounding control flow.
- L00227 [NONE] `	total = pool->total;`
  Review: Low-risk line; verify in surrounding control flow.
- L00228 [LOCK|] `	spin_unlock(&pool->lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00229 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00230 [NONE] `	/* Invariant: granted + available == total */`
  Review: Low-risk line; verify in surrounding control flow.
- L00231 [NONE] `	if (granted + avail != total)`
  Review: Low-risk line; verify in surrounding control flow.
- L00232 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00233 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00234 [NONE] `	/* No negative values */`
  Review: Low-risk line; verify in surrounding control flow.
- L00235 [NONE] `	if (avail < 0 || granted < 0 || total <= 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00236 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00237 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00238 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00239 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00240 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00241 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00242 [NONE] ` * smbd_credit_pool_check_leak - check for credit leaks`
  Review: Low-risk line; verify in surrounding control flow.
- L00243 [NONE] ` * @pool: credit pool`
  Review: Low-risk line; verify in surrounding control flow.
- L00244 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00245 [NONE] ` * Returns 0 if lifetime_granted == lifetime_reclaimed and granted == 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L00246 [NONE] ` * -EINVAL if there is a leak.`
  Review: Low-risk line; verify in surrounding control flow.
- L00247 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00248 [NONE] `static inline int smbd_credit_pool_check_leak(struct smbd_credit_pool *pool)`
  Review: Low-risk line; verify in surrounding control flow.
- L00249 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00250 [NONE] `	int granted, lg, lr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00251 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00252 [LOCK|] `	spin_lock(&pool->lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00253 [NONE] `	granted = pool->granted;`
  Review: Low-risk line; verify in surrounding control flow.
- L00254 [LOCK|] `	spin_unlock(&pool->lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00255 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00256 [LIFETIME|] `	lg = atomic_read(&pool->lifetime_granted);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00257 [LIFETIME|] `	lr = atomic_read(&pool->lifetime_reclaimed);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00258 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00259 [NONE] `	if (granted != 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00260 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00261 [NONE] `	if (lg != lr)`
  Review: Low-risk line; verify in surrounding control flow.
- L00262 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00263 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00264 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00265 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00266 [NONE] `#endif /* __KSMBD_TRANSPORT_RDMA_H__ */`
  Review: Low-risk line; verify in surrounding control flow.
