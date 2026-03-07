# Line-by-line Review: src/transport/transport_rdma.c

- L00001 [NONE] `// SPDX-License-Identifier: GPL-2.0-or-later`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` *   Copyright (C) 2017, Microsoft Corporation.`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` *   Copyright (C) 2018, LG Electronics.`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] ` *   Author(s): Long Li <longli@microsoft.com>,`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] ` *		Hyunchul Lee <hyc.lee@gmail.com>`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `#define SUBMOD_NAME	"smb_direct"`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] `#include <linux/kthread.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `#include <linux/list.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `#include <linux/mempool.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `#include <linux/highmem.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `#include <linux/scatterlist.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `#include <rdma/ib_verbs.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `#include <rdma/rdma_cm.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `#include <rdma/ib_cm.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `#include <rdma/rw.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] `#include "glob.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `#include "compat.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `#include "connection.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `#include "server.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `#include "smb_common.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `#include "smbstatus.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `#include "transport_rdma.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `#define SMB_DIRECT_PORT_IWARP		5445`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `#define SMB_DIRECT_PORT_INFINIBAND	445`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `#define SMB_DIRECT_VERSION_LE		cpu_to_le16(0x0100)`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `/* SMB_DIRECT negotiation timeout in seconds */`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `#define SMB_DIRECT_NEGOTIATE_TIMEOUT		120`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `#define SMB_DIRECT_MAX_SEND_SGES		6`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] `#define SMB_DIRECT_MAX_RECV_SGES		1`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] ` * Default maximum number of RDMA read/write outstanding on this connection`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] ` * This value is possibly decreased during QP creation on hardware limit`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] `#define SMB_DIRECT_CM_INITIATOR_DEPTH		8`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] `/* Maximum number of retries on data transfer operations */`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] `#define SMB_DIRECT_CM_RETRY			6`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `/* No need to retry on Receiver Not Ready since SMB_DIRECT manages credits */`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] `#define SMB_DIRECT_CM_RNR_RETRY		0`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] ` * User configurable initial values per SMB_DIRECT transport connection`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] ` * as defined in [MS-SMBD] 3.1.1.1`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] ` * Those may change after a SMB_DIRECT negotiation`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] `/* Set 445 port to SMB Direct port by default */`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] `static int smb_direct_port = SMB_DIRECT_PORT_INFINIBAND;`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] `/* The local peer's maximum number of credits to grant to the peer */`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] `static int smb_direct_receive_credit_max = 255;`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] `/* The remote peer's credit request of local peer */`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `static int smb_direct_send_credit_target = 255;`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] `/* The maximum single message size can be sent to remote peer */`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `static int smb_direct_max_send_size = 1364;`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] `/*  The maximum fragmented upper-layer payload receive size supported */`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] `static int smb_direct_max_fragmented_recv_size = 1024 * 1024;`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] `/*  The maximum single-message size which can be received */`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] `static int smb_direct_max_receive_size = 1364;`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] `static int smb_direct_max_read_write_size = SMBD_DEFAULT_IOSIZE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [LIFETIME|] `static atomic_t smbd_active_conn;`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00079 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] `static LIST_HEAD(smb_direct_device_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] `static DEFINE_RWLOCK(smb_direct_device_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] `struct smb_direct_device {`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] `	struct ib_device	*ib_dev;`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] `	struct list_head	list;`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] `static struct smb_direct_listener {`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] `	struct rdma_cm_id	*cm_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] `} smb_direct_listener;`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] `static struct workqueue_struct *smb_direct_wq;`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] `enum smb_direct_status {`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] `	SMB_DIRECT_CS_NEW = 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] `	SMB_DIRECT_CS_CONNECTED,`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] `	SMB_DIRECT_CS_DISCONNECTING,`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] `	SMB_DIRECT_CS_DISCONNECTED,`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] ` * Credit pool low-watermark threshold.  When the number of available`
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] ` * receive credits drops below this fraction of recv_credit_max, a`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] ` * rate-limited warning is emitted.  Set to 10% of the default 255.`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] `#define SMB_DIRECT_CREDIT_LOW_WATERMARK_PCT	10`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] `struct smb_direct_transport {`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] `	struct ksmbd_transport	transport;`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] `	enum smb_direct_status	status;`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] `	bool			full_packet_received;`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] `	wait_queue_head_t	wait_status;`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] `	struct rdma_cm_id	*cm_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] `	struct ib_cq		*send_cq;`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] `	struct ib_cq		*recv_cq;`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] `	struct ib_pd		*pd;`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] `	struct ib_qp		*qp;`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] `	int			max_send_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] `	int			max_recv_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] `	int			max_fragmented_send_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] `	int			max_fragmented_recv_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] `	int			max_rdma_rw_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] `	spinlock_t		reassembly_queue_lock;`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] `	struct list_head	reassembly_queue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] `	int			reassembly_data_length;`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] `	int			reassembly_queue_length;`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] `	int			first_entry_offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] `	wait_queue_head_t	wait_reassembly_queue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] `	spinlock_t		receive_credit_lock;`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] `	int			recv_credits;`
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] `	int			count_avail_recvmsg;`
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] `	int			recv_credit_max;`
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] `	int			recv_credit_target;`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] `	spinlock_t		recvmsg_queue_lock;`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] `	struct list_head	recvmsg_queue;`
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] `	int			send_credit_target;`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [LIFETIME|] `	atomic_t		send_credits;`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00145 [NONE] `	spinlock_t		lock_new_recv_credits;`
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] `	int			new_recv_credits;`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] `	int			max_rw_credits;`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] `	int			pages_per_rw_credit;`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [LIFETIME|] `	atomic_t		rw_credits;`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00150 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] `	wait_queue_head_t	wait_send_credits;`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] `	wait_queue_head_t	wait_rw_credits;`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] `	mempool_t		*sendmsg_mempool;`
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] `	struct kmem_cache	*sendmsg_cache;`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] `	mempool_t		*recvmsg_mempool;`
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] `	struct kmem_cache	*recvmsg_cache;`
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] `	wait_queue_head_t	wait_send_pending;`
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [LIFETIME|] `	atomic_t		send_pending;`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00161 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] `	struct work_struct	post_recv_credits_work;`
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] `	struct work_struct	send_immediate_work;`
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] `	struct work_struct	disconnect_work;`
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] `	bool			negotiation_requested;`
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] `	 * Credit accounting for leak detection.`
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] `	 * total_credits_granted: cumulative credits posted to RDMA HW`
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] `	 * total_credits_reclaimed: cumulative credits returned (recv`
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] `	 *   completions, both success and flush errors)`
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [NONE] `	 * recv_posted: number of receive buffers currently posted to HW`
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [NONE] `	 *   (incremented on post, decremented on any completion)`
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [NONE] `	 * Invariant (while connected):`
  Review: Low-risk line; verify in surrounding control flow.
- L00178 [NONE] `	 *   recv_credits + count_avail_recvmsg == recv_credit_max`
  Review: Low-risk line; verify in surrounding control flow.
- L00179 [NONE] `	 *   recv_posted >= 0`
  Review: Low-risk line; verify in surrounding control flow.
- L00180 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [NONE] `	 * On disconnect:`
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [NONE] `	 *   total_credits_granted == total_credits_reclaimed`
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [NONE] `	 *   recv_posted == 0`
  Review: Low-risk line; verify in surrounding control flow.
- L00184 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [LIFETIME|] `	atomic_t		recv_posted;`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00186 [LIFETIME|] `	atomic_t		total_credits_granted;`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00187 [LIFETIME|] `	atomic_t		total_credits_reclaimed;`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00188 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00190 [NONE] `#define KSMBD_TRANS(t) ((struct ksmbd_transport *)&((t)->transport))`
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [NONE] `#define SMBD_TRANS(t)	((struct smb_direct_transport *)container_of(t, \`
  Review: Low-risk line; verify in surrounding control flow.
- L00192 [NONE] `				struct smb_direct_transport, transport))`
  Review: Low-risk line; verify in surrounding control flow.
- L00193 [NONE] `enum {`
  Review: Low-risk line; verify in surrounding control flow.
- L00194 [NONE] `	SMB_DIRECT_MSG_NEGOTIATE_REQ = 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L00195 [NONE] `	SMB_DIRECT_MSG_DATA_TRANSFER`
  Review: Low-risk line; verify in surrounding control flow.
- L00196 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00197 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00198 [NONE] `static const struct ksmbd_transport_ops ksmbd_smb_direct_transport_ops;`
  Review: Low-risk line; verify in surrounding control flow.
- L00199 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00200 [NONE] `struct smb_direct_send_ctx {`
  Review: Low-risk line; verify in surrounding control flow.
- L00201 [NONE] `	struct list_head	msg_list;`
  Review: Low-risk line; verify in surrounding control flow.
- L00202 [NONE] `	int			wr_cnt;`
  Review: Low-risk line; verify in surrounding control flow.
- L00203 [NONE] `	bool			need_invalidate_rkey;`
  Review: Low-risk line; verify in surrounding control flow.
- L00204 [NONE] `	unsigned int		remote_key;`
  Review: Low-risk line; verify in surrounding control flow.
- L00205 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00206 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00207 [NONE] `struct smb_direct_sendmsg {`
  Review: Low-risk line; verify in surrounding control flow.
- L00208 [NONE] `	struct smb_direct_transport	*transport;`
  Review: Low-risk line; verify in surrounding control flow.
- L00209 [NONE] `	struct ib_send_wr	wr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00210 [NONE] `	struct list_head	list;`
  Review: Low-risk line; verify in surrounding control flow.
- L00211 [NONE] `	int			num_sge;`
  Review: Low-risk line; verify in surrounding control flow.
- L00212 [NONE] `	struct ib_sge		sge[SMB_DIRECT_MAX_SEND_SGES];`
  Review: Low-risk line; verify in surrounding control flow.
- L00213 [NONE] `	struct ib_cqe		cqe;`
  Review: Low-risk line; verify in surrounding control flow.
- L00214 [NONE] `	u8			packet[];`
  Review: Low-risk line; verify in surrounding control flow.
- L00215 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00216 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00217 [NONE] `struct smb_direct_recvmsg {`
  Review: Low-risk line; verify in surrounding control flow.
- L00218 [NONE] `	struct smb_direct_transport	*transport;`
  Review: Low-risk line; verify in surrounding control flow.
- L00219 [NONE] `	struct list_head	list;`
  Review: Low-risk line; verify in surrounding control flow.
- L00220 [NONE] `	int			type;`
  Review: Low-risk line; verify in surrounding control flow.
- L00221 [NONE] `	struct ib_sge		sge;`
  Review: Low-risk line; verify in surrounding control flow.
- L00222 [NONE] `	struct ib_cqe		cqe;`
  Review: Low-risk line; verify in surrounding control flow.
- L00223 [NONE] `	bool			first_segment;`
  Review: Low-risk line; verify in surrounding control flow.
- L00224 [NONE] `	u8			packet[];`
  Review: Low-risk line; verify in surrounding control flow.
- L00225 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00226 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00227 [NONE] `struct smb_direct_rdma_rw_msg {`
  Review: Low-risk line; verify in surrounding control flow.
- L00228 [NONE] `	struct smb_direct_transport	*t;`
  Review: Low-risk line; verify in surrounding control flow.
- L00229 [NONE] `	struct ib_cqe		cqe;`
  Review: Low-risk line; verify in surrounding control flow.
- L00230 [NONE] `	int			status;`
  Review: Low-risk line; verify in surrounding control flow.
- L00231 [NONE] `	struct completion	*completion;`
  Review: Low-risk line; verify in surrounding control flow.
- L00232 [NONE] `	struct list_head	list;`
  Review: Low-risk line; verify in surrounding control flow.
- L00233 [NONE] `	struct rdma_rw_ctx	rw_ctx;`
  Review: Low-risk line; verify in surrounding control flow.
- L00234 [NONE] `	struct sg_table		sgt;`
  Review: Low-risk line; verify in surrounding control flow.
- L00235 [NONE] `	struct scatterlist	sg_list[];`
  Review: Low-risk line; verify in surrounding control flow.
- L00236 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00237 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00238 [NONE] `void init_smbd_max_io_size(unsigned int sz)`
  Review: Low-risk line; verify in surrounding control flow.
- L00239 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00240 [NONE] `	sz = clamp_val(sz, SMBD_MIN_IOSIZE, SMBD_MAX_IOSIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00241 [NONE] `	smb_direct_max_read_write_size = sz;`
  Review: Low-risk line; verify in surrounding control flow.
- L00242 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00243 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00244 [NONE] `unsigned int get_smbd_max_read_write_size(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L00245 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00246 [NONE] `	return smb_direct_max_read_write_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00247 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00248 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00249 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00250 [NONE] ` * ksmbd_rdma_transform_supported() - check if an RDMA transform is negotiated`
  Review: Low-risk line; verify in surrounding control flow.
- L00251 [NONE] ` * @conn:	smb connection`
  Review: Low-risk line; verify in surrounding control flow.
- L00252 [NONE] ` * @transform_id: RDMA transform ID to check (le16)`
  Review: Low-risk line; verify in surrounding control flow.
- L00253 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00254 [NONE] ` * Return:	true if the transform was negotiated, else false`
  Review: Low-risk line; verify in surrounding control flow.
- L00255 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00256 [NONE] `bool ksmbd_rdma_transform_supported(struct ksmbd_conn *conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00257 [NONE] `				     __le16 transform_id)`
  Review: Low-risk line; verify in surrounding control flow.
- L00258 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00259 [NONE] `	unsigned int i;`
  Review: Low-risk line; verify in surrounding control flow.
- L00260 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00261 [NONE] `	for (i = 0; i < conn->rdma_transform_count; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00262 [NONE] `		if (conn->rdma_transform_ids[i] == transform_id)`
  Review: Low-risk line; verify in surrounding control flow.
- L00263 [NONE] `			return true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00264 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00265 [NONE] `	return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00266 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00267 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00268 [NONE] `static inline int get_buf_page_count(void *buf, int size)`
  Review: Low-risk line; verify in surrounding control flow.
- L00269 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00270 [NONE] `	return (int)(DIV_ROUND_UP((uintptr_t)buf + size, PAGE_SIZE) -`
  Review: Low-risk line; verify in surrounding control flow.
- L00271 [NONE] `		     (uintptr_t)buf / PAGE_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00272 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00273 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00274 [NONE] `static void smb_direct_destroy_pools(struct smb_direct_transport *transport);`
  Review: Low-risk line; verify in surrounding control flow.
- L00275 [NONE] `static void smb_direct_post_recv_credits(struct work_struct *work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00276 [NONE] `static int smb_direct_post_send_data(struct smb_direct_transport *t,`
  Review: Low-risk line; verify in surrounding control flow.
- L00277 [NONE] `				     struct smb_direct_send_ctx *send_ctx,`
  Review: Low-risk line; verify in surrounding control flow.
- L00278 [NONE] `				     struct kvec *iov, int niov,`
  Review: Low-risk line; verify in surrounding control flow.
- L00279 [NONE] `				     int remaining_data_length);`
  Review: Low-risk line; verify in surrounding control flow.
- L00280 [NONE] `static int smb_direct_credit_audit(struct smb_direct_transport *t);`
  Review: Low-risk line; verify in surrounding control flow.
- L00281 [NONE] `static void smb_direct_reclaim_credits(struct smb_direct_transport *t);`
  Review: Low-risk line; verify in surrounding control flow.
- L00282 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00283 [NONE] `static int smb_direct_wait_send_pending(struct smb_direct_transport *t,`
  Review: Low-risk line; verify in surrounding control flow.
- L00284 [NONE] `					const char *caller)`
  Review: Low-risk line; verify in surrounding control flow.
- L00285 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00286 [NONE] `	long ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00287 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00288 [WAIT_LOOP|] `	ret = wait_event_timeout(t->wait_send_pending,`
  Review: Bounded wait and cancellation path must be guaranteed.
- L00289 [LIFETIME|] `				 atomic_read(&t->send_pending) == 0 ||`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00290 [NONE] `				 t->status != SMB_DIRECT_CS_CONNECTED,`
  Review: Low-risk line; verify in surrounding control flow.
- L00291 [NONE] `				 SMB_DIRECT_NEGOTIATE_TIMEOUT * HZ);`
  Review: Low-risk line; verify in surrounding control flow.
- L00292 [NONE] `	if (ret <= 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00293 [ERROR_PATH|] `		pr_err_ratelimited("%s: timeout waiting for pending sends (pending=%d status=%d)\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00294 [LIFETIME|] `				   caller, atomic_read(&t->send_pending), t->status);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00295 [ERROR_PATH|] `		return -ETIMEDOUT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00296 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00297 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00298 [LIFETIME|] `	if (atomic_read(&t->send_pending) == 0)`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00299 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00300 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00301 [ERROR_PATH|] `	return -ENOTCONN;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00302 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00303 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00304 [NONE] `static inline struct smb_direct_transport *`
  Review: Low-risk line; verify in surrounding control flow.
- L00305 [NONE] `smb_trans_direct_transfort(struct ksmbd_transport *t)`
  Review: Low-risk line; verify in surrounding control flow.
- L00306 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00307 [NONE] `	return container_of(t, struct smb_direct_transport, transport);`
  Review: Low-risk line; verify in surrounding control flow.
- L00308 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00309 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00310 [NONE] `static inline void`
  Review: Low-risk line; verify in surrounding control flow.
- L00311 [NONE] `*smb_direct_recvmsg_payload(struct smb_direct_recvmsg *recvmsg)`
  Review: Low-risk line; verify in surrounding control flow.
- L00312 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00313 [NONE] `	return (void *)recvmsg->packet;`
  Review: Low-risk line; verify in surrounding control flow.
- L00314 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00315 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00316 [NONE] `static inline bool is_receive_credit_post_required(int receive_credits,`
  Review: Low-risk line; verify in surrounding control flow.
- L00317 [NONE] `						   int avail_recvmsg_count)`
  Review: Low-risk line; verify in surrounding control flow.
- L00318 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00319 [NONE] `	return receive_credits <= (smb_direct_receive_credit_max >> 3) &&`
  Review: Low-risk line; verify in surrounding control flow.
- L00320 [NONE] `		avail_recvmsg_count >= (receive_credits >> 2);`
  Review: Low-risk line; verify in surrounding control flow.
- L00321 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00322 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00323 [NONE] `static struct`
  Review: Low-risk line; verify in surrounding control flow.
- L00324 [NONE] `smb_direct_recvmsg *get_free_recvmsg(struct smb_direct_transport *t)`
  Review: Low-risk line; verify in surrounding control flow.
- L00325 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00326 [NONE] `	struct smb_direct_recvmsg *recvmsg = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00327 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00328 [LOCK|] `	spin_lock(&t->recvmsg_queue_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00329 [NONE] `	if (!list_empty(&t->recvmsg_queue)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00330 [NONE] `		recvmsg = list_first_entry(&t->recvmsg_queue,`
  Review: Low-risk line; verify in surrounding control flow.
- L00331 [NONE] `					   struct smb_direct_recvmsg,`
  Review: Low-risk line; verify in surrounding control flow.
- L00332 [NONE] `					   list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00333 [NONE] `		list_del(&recvmsg->list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00334 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00335 [LOCK|] `	spin_unlock(&t->recvmsg_queue_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00336 [NONE] `	return recvmsg;`
  Review: Low-risk line; verify in surrounding control flow.
- L00337 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00338 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00339 [NONE] `static void put_recvmsg(struct smb_direct_transport *t,`
  Review: Low-risk line; verify in surrounding control flow.
- L00340 [NONE] `			struct smb_direct_recvmsg *recvmsg)`
  Review: Low-risk line; verify in surrounding control flow.
- L00341 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00342 [NONE] `	if (likely(recvmsg->sge.length != 0)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00343 [NONE] `		ib_dma_unmap_single(t->cm_id->device,`
  Review: Low-risk line; verify in surrounding control flow.
- L00344 [NONE] `				    recvmsg->sge.addr,`
  Review: Low-risk line; verify in surrounding control flow.
- L00345 [NONE] `				    recvmsg->sge.length,`
  Review: Low-risk line; verify in surrounding control flow.
- L00346 [NONE] `				    DMA_FROM_DEVICE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00347 [NONE] `		recvmsg->sge.length = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00348 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00349 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00350 [LOCK|] `	spin_lock(&t->recvmsg_queue_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00351 [NONE] `	list_add(&recvmsg->list, &t->recvmsg_queue);`
  Review: Low-risk line; verify in surrounding control flow.
- L00352 [LOCK|] `	spin_unlock(&t->recvmsg_queue_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00353 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00354 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00355 [NONE] `static void enqueue_reassembly(struct smb_direct_transport *t,`
  Review: Low-risk line; verify in surrounding control flow.
- L00356 [NONE] `			       struct smb_direct_recvmsg *recvmsg,`
  Review: Low-risk line; verify in surrounding control flow.
- L00357 [NONE] `			       int data_length)`
  Review: Low-risk line; verify in surrounding control flow.
- L00358 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00359 [LOCK|] `	spin_lock(&t->reassembly_queue_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00360 [NONE] `	list_add_tail(&recvmsg->list, &t->reassembly_queue);`
  Review: Low-risk line; verify in surrounding control flow.
- L00361 [NONE] `	t->reassembly_queue_length++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00362 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00363 [NONE] `	 * Make sure reassembly_data_length is updated after list and`
  Review: Low-risk line; verify in surrounding control flow.
- L00364 [NONE] `	 * reassembly_queue_length are updated. On the dequeue side`
  Review: Low-risk line; verify in surrounding control flow.
- L00365 [NONE] `	 * reassembly_data_length is checked without a lock to determine`
  Review: Low-risk line; verify in surrounding control flow.
- L00366 [NONE] `	 * if reassembly_queue_length and list is up to date`
  Review: Low-risk line; verify in surrounding control flow.
- L00367 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00368 [NONE] `	virt_wmb();`
  Review: Low-risk line; verify in surrounding control flow.
- L00369 [NONE] `	t->reassembly_data_length += data_length;`
  Review: Low-risk line; verify in surrounding control flow.
- L00370 [LOCK|] `	spin_unlock(&t->reassembly_queue_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00371 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00372 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00373 [NONE] `static struct smb_direct_recvmsg *get_first_reassembly(struct smb_direct_transport *t)`
  Review: Low-risk line; verify in surrounding control flow.
- L00374 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00375 [NONE] `	if (!list_empty(&t->reassembly_queue))`
  Review: Low-risk line; verify in surrounding control flow.
- L00376 [NONE] `		return list_first_entry(&t->reassembly_queue,`
  Review: Low-risk line; verify in surrounding control flow.
- L00377 [NONE] `				struct smb_direct_recvmsg, list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00378 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L00379 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00380 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00381 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00382 [NONE] `static void smb_direct_disconnect_rdma_work(struct work_struct *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00383 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00384 [NONE] `	struct smb_direct_transport *t =`
  Review: Low-risk line; verify in surrounding control flow.
- L00385 [NONE] `		container_of(work, struct smb_direct_transport,`
  Review: Low-risk line; verify in surrounding control flow.
- L00386 [NONE] `			     disconnect_work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00387 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00388 [NONE] `	if (cmpxchg(&t->status, SMB_DIRECT_CS_CONNECTED,`
  Review: Low-risk line; verify in surrounding control flow.
- L00389 [NONE] `		    SMB_DIRECT_CS_DISCONNECTING) ==`
  Review: Low-risk line; verify in surrounding control flow.
- L00390 [NONE] `	    SMB_DIRECT_CS_CONNECTED) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00391 [NONE] `		wake_up_interruptible(&t->wait_status);`
  Review: Low-risk line; verify in surrounding control flow.
- L00392 [NONE] `		wake_up_interruptible(&t->wait_reassembly_queue);`
  Review: Low-risk line; verify in surrounding control flow.
- L00393 [NONE] `		wake_up(&t->wait_send_credits);`
  Review: Low-risk line; verify in surrounding control flow.
- L00394 [NONE] `		wake_up(&t->wait_rw_credits);`
  Review: Low-risk line; verify in surrounding control flow.
- L00395 [NONE] `		wake_up(&t->wait_send_pending);`
  Review: Low-risk line; verify in surrounding control flow.
- L00396 [NONE] `		rdma_disconnect(t->cm_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00397 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00398 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00399 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00400 [NONE] `static void`
  Review: Low-risk line; verify in surrounding control flow.
- L00401 [NONE] `smb_direct_disconnect_rdma_connection(struct smb_direct_transport *t)`
  Review: Low-risk line; verify in surrounding control flow.
- L00402 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00403 [NONE] `	if (t->status == SMB_DIRECT_CS_CONNECTED)`
  Review: Low-risk line; verify in surrounding control flow.
- L00404 [NONE] `		queue_work(smb_direct_wq, &t->disconnect_work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00405 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00406 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00407 [NONE] `static void smb_direct_send_immediate_work(struct work_struct *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L00408 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00409 [NONE] `	struct smb_direct_transport *t = container_of(work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00410 [NONE] `			struct smb_direct_transport, send_immediate_work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00411 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00412 [NONE] `	if (t->status != SMB_DIRECT_CS_CONNECTED)`
  Review: Low-risk line; verify in surrounding control flow.
- L00413 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00414 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00415 [NONE] `	smb_direct_post_send_data(t, NULL, NULL, 0, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00416 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00417 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00418 [NONE] `static struct smb_direct_transport *alloc_transport(struct rdma_cm_id *cm_id)`
  Review: Low-risk line; verify in surrounding control flow.
- L00419 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00420 [NONE] `	struct smb_direct_transport *t;`
  Review: Low-risk line; verify in surrounding control flow.
- L00421 [NONE] `	struct ksmbd_conn *conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00422 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00423 [MEM_BOUNDS|] `	t = kzalloc(sizeof(*t), KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00424 [NONE] `	if (!t)`
  Review: Low-risk line; verify in surrounding control flow.
- L00425 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00426 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00427 [NONE] `	t->cm_id = cm_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00428 [NONE] `	cm_id->context = t;`
  Review: Low-risk line; verify in surrounding control flow.
- L00429 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00430 [NONE] `	t->status = SMB_DIRECT_CS_NEW;`
  Review: Low-risk line; verify in surrounding control flow.
- L00431 [NONE] `	init_waitqueue_head(&t->wait_status);`
  Review: Low-risk line; verify in surrounding control flow.
- L00432 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00433 [NONE] `	spin_lock_init(&t->reassembly_queue_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00434 [NONE] `	INIT_LIST_HEAD(&t->reassembly_queue);`
  Review: Low-risk line; verify in surrounding control flow.
- L00435 [NONE] `	t->reassembly_data_length = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00436 [NONE] `	t->reassembly_queue_length = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00437 [NONE] `	init_waitqueue_head(&t->wait_reassembly_queue);`
  Review: Low-risk line; verify in surrounding control flow.
- L00438 [NONE] `	init_waitqueue_head(&t->wait_send_credits);`
  Review: Low-risk line; verify in surrounding control flow.
- L00439 [NONE] `	init_waitqueue_head(&t->wait_rw_credits);`
  Review: Low-risk line; verify in surrounding control flow.
- L00440 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00441 [NONE] `	spin_lock_init(&t->receive_credit_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00442 [NONE] `	spin_lock_init(&t->recvmsg_queue_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00443 [NONE] `	INIT_LIST_HEAD(&t->recvmsg_queue);`
  Review: Low-risk line; verify in surrounding control flow.
- L00444 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00445 [NONE] `	init_waitqueue_head(&t->wait_send_pending);`
  Review: Low-risk line; verify in surrounding control flow.
- L00446 [LIFETIME|] `	atomic_set(&t->send_pending, 0);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00447 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00448 [NONE] `	spin_lock_init(&t->lock_new_recv_credits);`
  Review: Low-risk line; verify in surrounding control flow.
- L00449 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00450 [LIFETIME|] `	atomic_set(&t->recv_posted, 0);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00451 [LIFETIME|] `	atomic_set(&t->total_credits_granted, 0);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00452 [LIFETIME|] `	atomic_set(&t->total_credits_reclaimed, 0);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00453 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00454 [NONE] `	INIT_WORK(&t->post_recv_credits_work,`
  Review: Low-risk line; verify in surrounding control flow.
- L00455 [NONE] `		  smb_direct_post_recv_credits);`
  Review: Low-risk line; verify in surrounding control flow.
- L00456 [NONE] `	INIT_WORK(&t->send_immediate_work, smb_direct_send_immediate_work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00457 [NONE] `	INIT_WORK(&t->disconnect_work, smb_direct_disconnect_rdma_work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00458 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00459 [NONE] `	conn = ksmbd_conn_alloc();`
  Review: Low-risk line; verify in surrounding control flow.
- L00460 [NONE] `	if (!conn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00461 [ERROR_PATH|] `		goto err;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00462 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00463 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00464 [LIFETIME|] `	 * J.5: IPv6 address enumeration RCU locking note.`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00465 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L00466 [NONE] `	 * This code extracts the client address from the RDMA CM route`
  Review: Low-risk line; verify in surrounding control flow.
- L00467 [NONE] `	 * (cm_id->route.addr.dst_addr), which is a struct sockaddr copied`
  Review: Low-risk line; verify in surrounding control flow.
- L00468 [NONE] `	 * during connection setup.  This is NOT an iteration of inet6_dev`
  Review: Low-risk line; verify in surrounding control flow.
- L00469 [LIFETIME|] `	 * address lists, so no rcu_read_lock() is required here.`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00470 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L00471 [LIFETIME|] `	 * The IPv6 addr_list iteration that DOES need an RCU lock is in`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00472 [NONE] `	 * ksmbd_fsctl.c in fsctl_query_iface_info_ioctl() (around the`
  Review: Low-risk line; verify in surrounding control flow.
- L00473 [NONE] `	 * list_for_each_entry() call on idev6->addr_list).  That function`
  Review: Low-risk line; verify in surrounding control flow.
- L00474 [LIFETIME|] `	 * uses the non-RCU list_for_each_entry() instead of`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00475 [NONE] `	 * list_for_each_entry_rcu(), which is a potential use-after-free`
  Review: Low-risk line; verify in surrounding control flow.
- L00476 [NONE] `	 * race.  The fix is in that file (owned by Track F/IOCTL), not here.`
  Review: Low-risk line; verify in surrounding control flow.
- L00477 [NONE] `	 * The duplicate implementation in smb2_ioctl.c already uses`
  Review: Low-risk line; verify in surrounding control flow.
- L00478 [LIFETIME|] `	 * list_for_each_entry_rcu() correctly under rcu_read_lock().`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00479 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00480 [NONE] `	/* Extract client IP from RDMA CM and compute a proper hash`
  Review: Low-risk line; verify in surrounding control flow.
- L00481 [NONE] `	 * so connections don't all land in bucket 0.`
  Review: Low-risk line; verify in surrounding control flow.
- L00482 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00483 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00484 [NONE] `		struct sockaddr *dst = (struct sockaddr *)&cm_id->route.addr.dst_addr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00485 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00486 [NONE] `#if IS_ENABLED(CONFIG_IPV6)`
  Review: Low-risk line; verify in surrounding control flow.
- L00487 [NONE] `		if (dst->sa_family == AF_INET6) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00488 [NONE] `			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)dst;`
  Review: Low-risk line; verify in surrounding control flow.
- L00489 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00490 [MEM_BOUNDS|] `			memcpy(&conn->inet6_addr, &sin6->sin6_addr, 16);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00491 [NONE] `			conn->inet_hash = ipv6_addr_hash(&sin6->sin6_addr);`
  Review: Low-risk line; verify in surrounding control flow.
- L00492 [NONE] `		} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00493 [NONE] `			struct sockaddr_in *sin = (struct sockaddr_in *)dst;`
  Review: Low-risk line; verify in surrounding control flow.
- L00494 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00495 [NONE] `			conn->inet_addr = sin->sin_addr.s_addr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00496 [NONE] `			conn->inet_hash = ipv4_addr_hash(sin->sin_addr.s_addr);`
  Review: Low-risk line; verify in surrounding control flow.
- L00497 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00498 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00499 [NONE] `		{`
  Review: Low-risk line; verify in surrounding control flow.
- L00500 [NONE] `			struct sockaddr_in *sin = (struct sockaddr_in *)dst;`
  Review: Low-risk line; verify in surrounding control flow.
- L00501 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00502 [NONE] `			conn->inet_addr = sin->sin_addr.s_addr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00503 [NONE] `			conn->inet_hash = ipv4_addr_hash(sin->sin_addr.s_addr);`
  Review: Low-risk line; verify in surrounding control flow.
- L00504 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00505 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00506 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00507 [NONE] `	ksmbd_conn_hash_add(conn, conn->inet_hash);`
  Review: Low-risk line; verify in surrounding control flow.
- L00508 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00509 [NONE] `	conn->transport = KSMBD_TRANS(t);`
  Review: Low-risk line; verify in surrounding control flow.
- L00510 [NONE] `	KSMBD_TRANS(t)->conn = conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00511 [NONE] `	KSMBD_TRANS(t)->ops = &ksmbd_smb_direct_transport_ops;`
  Review: Low-risk line; verify in surrounding control flow.
- L00512 [NONE] `	return t;`
  Review: Low-risk line; verify in surrounding control flow.
- L00513 [NONE] `err:`
  Review: Low-risk line; verify in surrounding control flow.
- L00514 [NONE] `	kfree(t);`
  Review: Low-risk line; verify in surrounding control flow.
- L00515 [NONE] `	return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00516 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00517 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00518 [NONE] `static void smb_direct_free_transport(struct ksmbd_transport *kt)`
  Review: Low-risk line; verify in surrounding control flow.
- L00519 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00520 [NONE] `	kfree(SMBD_TRANS(kt));`
  Review: Low-risk line; verify in surrounding control flow.
- L00521 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00522 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00523 [NONE] `static void free_transport(struct smb_direct_transport *t)`
  Review: Low-risk line; verify in surrounding control flow.
- L00524 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00525 [NONE] `	struct smb_direct_recvmsg *recvmsg;`
  Review: Low-risk line; verify in surrounding control flow.
- L00526 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00527 [NONE] `	wake_up_interruptible(&t->wait_send_credits);`
  Review: Low-risk line; verify in surrounding control flow.
- L00528 [NONE] `	wake_up(&t->wait_rw_credits);`
  Review: Low-risk line; verify in surrounding control flow.
- L00529 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00530 [NONE] `	disable_work_sync(&t->disconnect_work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00531 [NONE] `	disable_work_sync(&t->post_recv_credits_work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00532 [NONE] `	disable_work_sync(&t->send_immediate_work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00533 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00534 [NONE] `	if (t->qp)`
  Review: Low-risk line; verify in surrounding control flow.
- L00535 [NONE] `		ib_drain_qp(t->qp);`
  Review: Low-risk line; verify in surrounding control flow.
- L00536 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00537 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00538 [NONE] `	 * After ib_drain_qp all completions have been processed.`
  Review: Low-risk line; verify in surrounding control flow.
- L00539 [NONE] `	 * Reclaim any outstanding credits that were not properly`
  Review: Low-risk line; verify in surrounding control flow.
- L00540 [NONE] `	 * returned during flush-error processing, then audit.`
  Review: Low-risk line; verify in surrounding control flow.
- L00541 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00542 [NONE] `	smb_direct_reclaim_credits(t);`
  Review: Low-risk line; verify in surrounding control flow.
- L00543 [NONE] `	smb_direct_credit_audit(t);`
  Review: Low-risk line; verify in surrounding control flow.
- L00544 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00545 [NONE] `	ksmbd_debug(RDMA, "wait for all send posted to IB to finish\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00546 [LIFETIME|] `	if (atomic_read(&t->send_pending))`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00547 [NONE] `		smb_direct_wait_send_pending(t, __func__);`
  Review: Low-risk line; verify in surrounding control flow.
- L00548 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00549 [NONE] `	if (t->qp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00550 [NONE] `		ib_mr_pool_destroy(t->qp, &t->qp->rdma_mrs);`
  Review: Low-risk line; verify in surrounding control flow.
- L00551 [NONE] `		t->qp = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00552 [NONE] `		rdma_destroy_qp(t->cm_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00553 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00554 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00555 [NONE] `	ksmbd_debug(RDMA, "drain the reassembly queue\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L00556 [NONE] `	do {`
  Review: Low-risk line; verify in surrounding control flow.
- L00557 [LOCK|] `		spin_lock(&t->reassembly_queue_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00558 [NONE] `		recvmsg = get_first_reassembly(t);`
  Review: Low-risk line; verify in surrounding control flow.
- L00559 [NONE] `		if (recvmsg) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00560 [NONE] `			list_del(&recvmsg->list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00561 [LOCK|] `			spin_unlock(&t->reassembly_queue_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00562 [NONE] `			put_recvmsg(t, recvmsg);`
  Review: Low-risk line; verify in surrounding control flow.
- L00563 [NONE] `		} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00564 [LOCK|] `			spin_unlock(&t->reassembly_queue_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00565 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00566 [NONE] `	} while (recvmsg);`
  Review: Low-risk line; verify in surrounding control flow.
- L00567 [NONE] `	t->reassembly_data_length = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00568 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00569 [NONE] `	if (t->send_cq)`
  Review: Low-risk line; verify in surrounding control flow.
- L00570 [NONE] `		ib_free_cq(t->send_cq);`
  Review: Low-risk line; verify in surrounding control flow.
- L00571 [NONE] `	if (t->recv_cq)`
  Review: Low-risk line; verify in surrounding control flow.
- L00572 [NONE] `		ib_free_cq(t->recv_cq);`
  Review: Low-risk line; verify in surrounding control flow.
- L00573 [NONE] `	if (t->pd)`
  Review: Low-risk line; verify in surrounding control flow.
- L00574 [NONE] `		ib_dealloc_pd(t->pd);`
  Review: Low-risk line; verify in surrounding control flow.
- L00575 [NONE] `	if (t->cm_id)`
  Review: Low-risk line; verify in surrounding control flow.
- L00576 [NONE] `		rdma_destroy_id(t->cm_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L00577 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00578 [NONE] `	smb_direct_destroy_pools(t);`
  Review: Low-risk line; verify in surrounding control flow.
- L00579 [NONE] `	ksmbd_conn_free(KSMBD_TRANS(t)->conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L00580 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00581 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00582 [NONE] `static struct smb_direct_sendmsg`
  Review: Low-risk line; verify in surrounding control flow.
- L00583 [NONE] `*smb_direct_alloc_sendmsg(struct smb_direct_transport *t)`
  Review: Low-risk line; verify in surrounding control flow.
- L00584 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00585 [NONE] `	struct smb_direct_sendmsg *msg;`
  Review: Low-risk line; verify in surrounding control flow.
- L00586 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00587 [NONE] `	msg = mempool_alloc(t->sendmsg_mempool, KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L00588 [NONE] `	if (!msg)`
  Review: Low-risk line; verify in surrounding control flow.
- L00589 [NONE] `		return ERR_PTR(-ENOMEM);`
  Review: Low-risk line; verify in surrounding control flow.
- L00590 [NONE] `	msg->transport = t;`
  Review: Low-risk line; verify in surrounding control flow.
- L00591 [NONE] `	INIT_LIST_HEAD(&msg->list);`
  Review: Low-risk line; verify in surrounding control flow.
- L00592 [NONE] `	msg->num_sge = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00593 [NONE] `	return msg;`
  Review: Low-risk line; verify in surrounding control flow.
- L00594 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00595 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00596 [NONE] `static void smb_direct_free_sendmsg(struct smb_direct_transport *t,`
  Review: Low-risk line; verify in surrounding control flow.
- L00597 [NONE] `				    struct smb_direct_sendmsg *msg)`
  Review: Low-risk line; verify in surrounding control flow.
- L00598 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00599 [NONE] `	int i;`
  Review: Low-risk line; verify in surrounding control flow.
- L00600 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00601 [NONE] `	if (msg->num_sge > 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00602 [NONE] `		ib_dma_unmap_single(t->cm_id->device,`
  Review: Low-risk line; verify in surrounding control flow.
- L00603 [NONE] `				    msg->sge[0].addr, msg->sge[0].length,`
  Review: Low-risk line; verify in surrounding control flow.
- L00604 [NONE] `				    DMA_TO_DEVICE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00605 [NONE] `		for (i = 1; i < msg->num_sge; i++)`
  Review: Low-risk line; verify in surrounding control flow.
- L00606 [NONE] `			ib_dma_unmap_page(t->cm_id->device,`
  Review: Low-risk line; verify in surrounding control flow.
- L00607 [NONE] `					  msg->sge[i].addr, msg->sge[i].length,`
  Review: Low-risk line; verify in surrounding control flow.
- L00608 [NONE] `					  DMA_TO_DEVICE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00609 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00610 [NONE] `	mempool_free(msg, t->sendmsg_mempool);`
  Review: Low-risk line; verify in surrounding control flow.
- L00611 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00612 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00613 [NONE] `static int smb_direct_check_recvmsg(struct smb_direct_recvmsg *recvmsg)`
  Review: Low-risk line; verify in surrounding control flow.
- L00614 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00615 [NONE] `	switch (recvmsg->type) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00616 [NONE] `	case SMB_DIRECT_MSG_DATA_TRANSFER: {`
  Review: Low-risk line; verify in surrounding control flow.
- L00617 [NONE] `		struct smb_direct_data_transfer *req =`
  Review: Low-risk line; verify in surrounding control flow.
- L00618 [NONE] `			(struct smb_direct_data_transfer *)recvmsg->packet;`
  Review: Low-risk line; verify in surrounding control flow.
- L00619 [NONE] `		u32 d_offset = le32_to_cpu(req->data_offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00620 [NONE] `		u32 d_length = le32_to_cpu(req->data_length);`
  Review: Low-risk line; verify in surrounding control flow.
- L00621 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00622 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00623 [NONE] `		 * Validate data_offset and data_length against the actual`
  Review: Low-risk line; verify in surrounding control flow.
- L00624 [NONE] `		 * receive buffer size, not just logical structure sizes.`
  Review: Low-risk line; verify in surrounding control flow.
- L00625 [NONE] `		 * A crafted packet could set data_offset beyond the receive`
  Review: Low-risk line; verify in surrounding control flow.
- L00626 [NONE] `		 * buffer, causing out-of-bounds access.`
  Review: Low-risk line; verify in surrounding control flow.
- L00627 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00628 [NONE] `		if (d_offset >= recvmsg->sge.length ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00629 [NONE] `		    d_length > recvmsg->sge.length ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00630 [NONE] `		    d_offset + d_length > recvmsg->sge.length) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00631 [ERROR_PATH|] `			pr_err("data_offset %u + data_length %u exceeds buffer %u\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00632 [NONE] `			       d_offset, d_length, recvmsg->sge.length);`
  Review: Low-risk line; verify in surrounding control flow.
- L00633 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00634 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00635 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00636 [NONE] `		if (d_offset + sizeof(struct smb2_hdr) >`
  Review: Low-risk line; verify in surrounding control flow.
- L00637 [NONE] `		    sizeof(struct smb_direct_data_transfer) + d_length) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00638 [ERROR_PATH|] `			pr_err("Invalid data_offset %u in SMB_DIRECT data transfer\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00639 [NONE] `			       d_offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00640 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00641 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00642 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00643 [NONE] `		if (d_length && d_offset + sizeof(struct smb2_hdr) <=`
  Review: Low-risk line; verify in surrounding control flow.
- L00644 [NONE] `		    recvmsg->sge.length) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00645 [NONE] `			struct smb2_hdr *hdr = (struct smb2_hdr *)`
  Review: Low-risk line; verify in surrounding control flow.
- L00646 [NONE] `				(recvmsg->packet + d_offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00647 [NONE] `			ksmbd_debug(RDMA,`
  Review: Low-risk line; verify in surrounding control flow.
- L00648 [NONE] `				    "CreditGranted: %u, CreditRequested: %u, DataLength: %u, RemainingDataLength: %u, SMB: %x, Command: %u\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00649 [NONE] `				    le16_to_cpu(req->credits_granted),`
  Review: Low-risk line; verify in surrounding control flow.
- L00650 [NONE] `				    le16_to_cpu(req->credits_requested),`
  Review: Low-risk line; verify in surrounding control flow.
- L00651 [NONE] `				    req->data_length,`
  Review: Low-risk line; verify in surrounding control flow.
- L00652 [NONE] `				    req->remaining_data_length,`
  Review: Low-risk line; verify in surrounding control flow.
- L00653 [PROTO_GATE|] `				    hdr->ProtocolId, hdr->Command);`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L00654 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00655 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00656 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00657 [NONE] `	case SMB_DIRECT_MSG_NEGOTIATE_REQ: {`
  Review: Low-risk line; verify in surrounding control flow.
- L00658 [NONE] `		struct smb_direct_negotiate_req *req =`
  Review: Low-risk line; verify in surrounding control flow.
- L00659 [NONE] `			(struct smb_direct_negotiate_req *)recvmsg->packet;`
  Review: Low-risk line; verify in surrounding control flow.
- L00660 [NONE] `		ksmbd_debug(RDMA,`
  Review: Low-risk line; verify in surrounding control flow.
- L00661 [NONE] `			    "MinVersion: %u, MaxVersion: %u, CreditRequested: %u, MaxSendSize: %u, MaxRecvSize: %u, MaxFragmentedSize: %u\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00662 [NONE] `			    le16_to_cpu(req->min_version),`
  Review: Low-risk line; verify in surrounding control flow.
- L00663 [NONE] `			    le16_to_cpu(req->max_version),`
  Review: Low-risk line; verify in surrounding control flow.
- L00664 [NONE] `			    le16_to_cpu(req->credits_requested),`
  Review: Low-risk line; verify in surrounding control flow.
- L00665 [NONE] `			    le32_to_cpu(req->preferred_send_size),`
  Review: Low-risk line; verify in surrounding control flow.
- L00666 [NONE] `			    le32_to_cpu(req->max_receive_size),`
  Review: Low-risk line; verify in surrounding control flow.
- L00667 [NONE] `			    le32_to_cpu(req->max_fragmented_size));`
  Review: Low-risk line; verify in surrounding control flow.
- L00668 [NONE] `		if (le16_to_cpu(req->min_version) > 0x0100 ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00669 [NONE] `		    le16_to_cpu(req->max_version) < 0x0100)`
  Review: Low-risk line; verify in surrounding control flow.
- L00670 [ERROR_PATH|] `			return -EOPNOTSUPP;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00671 [NONE] `		if (le16_to_cpu(req->credits_requested) <= 0 ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00672 [NONE] `		    le32_to_cpu(req->max_receive_size) <= 128 ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00673 [NONE] `		    le32_to_cpu(req->max_fragmented_size) <=`
  Review: Low-risk line; verify in surrounding control flow.
- L00674 [NONE] `					128 * 1024)`
  Review: Low-risk line; verify in surrounding control flow.
- L00675 [ERROR_PATH|] `			return -ECONNABORTED;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00676 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00677 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L00678 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00679 [NONE] `	default:`
  Review: Low-risk line; verify in surrounding control flow.
- L00680 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00681 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00682 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00683 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00684 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00685 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00686 [NONE] ` * smb_direct_credit_audit - verify credit accounting invariants`
  Review: Low-risk line; verify in surrounding control flow.
- L00687 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00688 [NONE] ` * Returns 0 if all invariants hold, negative errno otherwise.`
  Review: Low-risk line; verify in surrounding control flow.
- L00689 [NONE] ` * Caller must NOT hold receive_credit_lock.`
  Review: Low-risk line; verify in surrounding control flow.
- L00690 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00691 [NONE] `static int smb_direct_credit_audit(struct smb_direct_transport *t)`
  Review: Low-risk line; verify in surrounding control flow.
- L00692 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00693 [NONE] `	int recv_creds, avail, posted, total_max;`
  Review: Low-risk line; verify in surrounding control flow.
- L00694 [NONE] `	int granted, reclaimed, leaked;`
  Review: Low-risk line; verify in surrounding control flow.
- L00695 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00696 [LOCK|] `	spin_lock(&t->receive_credit_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00697 [NONE] `	recv_creds = t->recv_credits;`
  Review: Low-risk line; verify in surrounding control flow.
- L00698 [NONE] `	avail = t->count_avail_recvmsg;`
  Review: Low-risk line; verify in surrounding control flow.
- L00699 [NONE] `	total_max = t->recv_credit_max;`
  Review: Low-risk line; verify in surrounding control flow.
- L00700 [LOCK|] `	spin_unlock(&t->receive_credit_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00701 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00702 [LIFETIME|] `	posted = atomic_read(&t->recv_posted);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00703 [LIFETIME|] `	granted = atomic_read(&t->total_credits_granted);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00704 [LIFETIME|] `	reclaimed = atomic_read(&t->total_credits_reclaimed);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00705 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00706 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00707 [NONE] `	 * Invariant 1: recv_credits + count_avail_recvmsg == recv_credit_max`
  Review: Low-risk line; verify in surrounding control flow.
- L00708 [NONE] `	 * This must always hold because each receive buffer is either`
  Review: Low-risk line; verify in surrounding control flow.
- L00709 [NONE] `	 * posted to HW (counted in recv_credits) or available in the`
  Review: Low-risk line; verify in surrounding control flow.
- L00710 [NONE] `	 * free queue (counted in count_avail_recvmsg).`
  Review: Low-risk line; verify in surrounding control flow.
- L00711 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00712 [NONE] `	if (recv_creds + avail != total_max) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00713 [ERROR_PATH|] `		pr_warn_ratelimited(`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00714 [NONE] `			"ksmbd: RDMA credit invariant violation: "`
  Review: Low-risk line; verify in surrounding control flow.
- L00715 [NONE] `			"recv_credits(%d) + avail(%d) != max(%d)\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00716 [NONE] `			recv_creds, avail, total_max);`
  Review: Low-risk line; verify in surrounding control flow.
- L00717 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00718 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00719 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00720 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00721 [NONE] `	 * Invariant 2: recv_posted must be non-negative.`
  Review: Low-risk line; verify in surrounding control flow.
- L00722 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00723 [NONE] `	if (posted < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00724 [ERROR_PATH|] `		pr_warn_ratelimited(`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00725 [NONE] `			"ksmbd: RDMA recv_posted underflow: %d\n", posted);`
  Review: Low-risk line; verify in surrounding control flow.
- L00726 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00727 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00728 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00729 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00730 [NONE] `	 * Invariant 3: cumulative leak check (only meaningful after`
  Review: Low-risk line; verify in surrounding control flow.
- L00731 [NONE] `	 * all completions have been processed, e.g. after ib_drain_qp).`
  Review: Low-risk line; verify in surrounding control flow.
- L00732 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00733 [NONE] `	leaked = granted - reclaimed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00734 [NONE] `	if (t->status == SMB_DIRECT_CS_DISCONNECTED && leaked != 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00735 [ERROR_PATH|] `		pr_warn_ratelimited(`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00736 [NONE] `			"ksmbd: RDMA credit leak detected: "`
  Review: Low-risk line; verify in surrounding control flow.
- L00737 [NONE] `			"granted(%d) - reclaimed(%d) = %d\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00738 [NONE] `			granted, reclaimed, leaked);`
  Review: Low-risk line; verify in surrounding control flow.
- L00739 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00740 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00741 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00742 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00743 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00744 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00745 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00746 [NONE] ` * smb_direct_reclaim_credits - reclaim all outstanding posted credits`
  Review: Low-risk line; verify in surrounding control flow.
- L00747 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00748 [NONE] ` * Called during disconnect/teardown after ib_drain_qp() has ensured all`
  Review: Low-risk line; verify in surrounding control flow.
- L00749 [NONE] ` * completions have been processed.  Any remaining positive recv_posted`
  Review: Low-risk line; verify in surrounding control flow.
- L00750 [NONE] ` * represents credits that were lost (e.g. flush completions that didn't`
  Review: Low-risk line; verify in surrounding control flow.
- L00751 [NONE] ` * properly update recv_credits).  We reset recv_credits and`
  Review: Low-risk line; verify in surrounding control flow.
- L00752 [NONE] ` * count_avail_recvmsg to their correct values so the pool is whole.`
  Review: Low-risk line; verify in surrounding control flow.
- L00753 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00754 [NONE] `static void smb_direct_reclaim_credits(struct smb_direct_transport *t)`
  Review: Low-risk line; verify in surrounding control flow.
- L00755 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00756 [NONE] `	int posted, leaked;`
  Review: Low-risk line; verify in surrounding control flow.
- L00757 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00758 [LIFETIME|] `	posted = atomic_read(&t->recv_posted);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00759 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00760 [LOCK|] `	spin_lock(&t->receive_credit_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00761 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00762 [NONE] `	 * After ib_drain_qp, all posted buffers have completed (either`
  Review: Low-risk line; verify in surrounding control flow.
- L00763 [NONE] `	 * successfully or with flush errors).  Reset recv_credits to 0`
  Review: Low-risk line; verify in surrounding control flow.
- L00764 [NONE] `	 * since nothing is actually posted to HW anymore.  Return all`
  Review: Low-risk line; verify in surrounding control flow.
- L00765 [NONE] `	 * buffers to available pool.`
  Review: Low-risk line; verify in surrounding control flow.
- L00766 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00767 [NONE] `	if (t->recv_credits > 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00768 [NONE] `		ksmbd_debug(RDMA,`
  Review: Low-risk line; verify in surrounding control flow.
- L00769 [NONE] `			    "reclaiming %d outstanding recv credits (posted=%d)\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00770 [NONE] `			    t->recv_credits, posted);`
  Review: Low-risk line; verify in surrounding control flow.
- L00771 [NONE] `		t->count_avail_recvmsg += t->recv_credits;`
  Review: Low-risk line; verify in surrounding control flow.
- L00772 [NONE] `		t->recv_credits = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00773 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00774 [LOCK|] `	spin_unlock(&t->receive_credit_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00775 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00776 [NONE] `	/* Reset posted counter and check for leaks */`
  Review: Low-risk line; verify in surrounding control flow.
- L00777 [LIFETIME|] `	posted = atomic_xchg(&t->recv_posted, 0);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00778 [NONE] `	if (posted != 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00779 [NONE] `		ksmbd_debug(RDMA,`
  Review: Low-risk line; verify in surrounding control flow.
- L00780 [NONE] `			    "cleared %d orphaned recv_posted credits\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00781 [NONE] `			    posted);`
  Review: Low-risk line; verify in surrounding control flow.
- L00782 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00783 [LIFETIME|] `	leaked = atomic_read(&t->total_credits_granted) -`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00784 [LIFETIME|] `		 atomic_read(&t->total_credits_reclaimed);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00785 [NONE] `	if (leaked != 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00786 [ERROR_PATH|] `		pr_warn_ratelimited(`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00787 [NONE] `			"ksmbd: RDMA credit leak on teardown: "`
  Review: Low-risk line; verify in surrounding control flow.
- L00788 [NONE] `			"granted=%d reclaimed=%d delta=%d\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00789 [LIFETIME|] `			atomic_read(&t->total_credits_granted),`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00790 [LIFETIME|] `			atomic_read(&t->total_credits_reclaimed),`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00791 [NONE] `			leaked);`
  Review: Low-risk line; verify in surrounding control flow.
- L00792 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00793 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00794 [NONE] `static void recv_done(struct ib_cq *cq, struct ib_wc *wc)`
  Review: Low-risk line; verify in surrounding control flow.
- L00795 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00796 [NONE] `	struct smb_direct_recvmsg *recvmsg;`
  Review: Low-risk line; verify in surrounding control flow.
- L00797 [NONE] `	struct smb_direct_transport *t;`
  Review: Low-risk line; verify in surrounding control flow.
- L00798 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00799 [NONE] `	recvmsg = container_of(wc->wr_cqe, struct smb_direct_recvmsg, cqe);`
  Review: Low-risk line; verify in surrounding control flow.
- L00800 [NONE] `	t = recvmsg->transport;`
  Review: Low-risk line; verify in surrounding control flow.
- L00801 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00802 [NONE] `	/* Every completion (success or error) means one fewer posted buffer */`
  Review: Low-risk line; verify in surrounding control flow.
- L00803 [LIFETIME|] `	atomic_dec(&t->recv_posted);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00804 [LIFETIME|] `	atomic_inc(&t->total_credits_reclaimed);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00805 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00806 [NONE] `	if (wc->status != IB_WC_SUCCESS || wc->opcode != IB_WC_RECV) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00807 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00808 [NONE] `		 * FIX: On flush errors (from ib_drain_qp during disconnect),`
  Review: Low-risk line; verify in surrounding control flow.
- L00809 [NONE] `		 * we must decrement recv_credits to keep the invariant:`
  Review: Low-risk line; verify in surrounding control flow.
- L00810 [NONE] `		 *   recv_credits + count_avail_recvmsg == recv_credit_max`
  Review: Low-risk line; verify in surrounding control flow.
- L00811 [NONE] `		 *`
  Review: Low-risk line; verify in surrounding control flow.
- L00812 [NONE] `		 * Previously, flush-error completions returned without`
  Review: Low-risk line; verify in surrounding control flow.
- L00813 [NONE] `		 * adjusting recv_credits, causing a credit leak that could`
  Review: Low-risk line; verify in surrounding control flow.
- L00814 [NONE] `		 * prevent new receive buffer postings on connection reuse.`
  Review: Low-risk line; verify in surrounding control flow.
- L00815 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00816 [LOCK|] `		spin_lock(&t->receive_credit_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00817 [NONE] `		if (t->recv_credits > 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00818 [NONE] `			t->recv_credits--;`
  Review: Low-risk line; verify in surrounding control flow.
- L00819 [NONE] `			t->count_avail_recvmsg++;`
  Review: Low-risk line; verify in surrounding control flow.
- L00820 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00821 [LOCK|] `		spin_unlock(&t->receive_credit_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00822 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00823 [NONE] `		put_recvmsg(t, recvmsg);`
  Review: Low-risk line; verify in surrounding control flow.
- L00824 [NONE] `		if (wc->status != IB_WC_WR_FLUSH_ERR) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00825 [ERROR_PATH|] `			pr_err("Recv error. status='%s (%d)' opcode=%d\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00826 [NONE] `			       ib_wc_status_msg(wc->status), wc->status,`
  Review: Low-risk line; verify in surrounding control flow.
- L00827 [NONE] `			       wc->opcode);`
  Review: Low-risk line; verify in surrounding control flow.
- L00828 [NONE] `			smb_direct_disconnect_rdma_connection(t);`
  Review: Low-risk line; verify in surrounding control flow.
- L00829 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00830 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00831 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00832 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00833 [NONE] `	ksmbd_debug(RDMA, "Recv completed. status='%s (%d)', opcode=%d\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L00834 [NONE] `		    ib_wc_status_msg(wc->status), wc->status,`
  Review: Low-risk line; verify in surrounding control flow.
- L00835 [NONE] `		    wc->opcode);`
  Review: Low-risk line; verify in surrounding control flow.
- L00836 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00837 [NONE] `	ib_dma_sync_single_for_cpu(wc->qp->device, recvmsg->sge.addr,`
  Review: Low-risk line; verify in surrounding control flow.
- L00838 [NONE] `				   recvmsg->sge.length, DMA_FROM_DEVICE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00839 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00840 [NONE] `	switch (recvmsg->type) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00841 [NONE] `	case SMB_DIRECT_MSG_NEGOTIATE_REQ:`
  Review: Low-risk line; verify in surrounding control flow.
- L00842 [NONE] `		if (wc->byte_len < sizeof(struct smb_direct_negotiate_req)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00843 [NONE] `			put_recvmsg(t, recvmsg);`
  Review: Low-risk line; verify in surrounding control flow.
- L00844 [NONE] `			smb_direct_disconnect_rdma_connection(t);`
  Review: Low-risk line; verify in surrounding control flow.
- L00845 [NONE] `			return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00846 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00847 [NONE] `		t->negotiation_requested = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00848 [NONE] `		t->full_packet_received = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00849 [NONE] `		t->status = SMB_DIRECT_CS_CONNECTED;`
  Review: Low-risk line; verify in surrounding control flow.
- L00850 [NONE] `		enqueue_reassembly(t, recvmsg, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00851 [NONE] `		wake_up_interruptible(&t->wait_status);`
  Review: Low-risk line; verify in surrounding control flow.
- L00852 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00853 [NONE] `	case SMB_DIRECT_MSG_DATA_TRANSFER: {`
  Review: Low-risk line; verify in surrounding control flow.
- L00854 [NONE] `		struct smb_direct_data_transfer *data_transfer =`
  Review: Low-risk line; verify in surrounding control flow.
- L00855 [NONE] `			(struct smb_direct_data_transfer *)recvmsg->packet;`
  Review: Low-risk line; verify in surrounding control flow.
- L00856 [NONE] `		u32 remaining_data_length, data_offset, data_length;`
  Review: Low-risk line; verify in surrounding control flow.
- L00857 [NONE] `		int avail_recvmsg_count, receive_credits;`
  Review: Low-risk line; verify in surrounding control flow.
- L00858 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00859 [NONE] `		if (wc->byte_len <`
  Review: Low-risk line; verify in surrounding control flow.
- L00860 [NONE] `		    offsetof(struct smb_direct_data_transfer, padding)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00861 [NONE] `			put_recvmsg(t, recvmsg);`
  Review: Low-risk line; verify in surrounding control flow.
- L00862 [NONE] `			smb_direct_disconnect_rdma_connection(t);`
  Review: Low-risk line; verify in surrounding control flow.
- L00863 [NONE] `			return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00864 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00865 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00866 [NONE] `		remaining_data_length = le32_to_cpu(data_transfer->remaining_data_length);`
  Review: Low-risk line; verify in surrounding control flow.
- L00867 [NONE] `		data_length = le32_to_cpu(data_transfer->data_length);`
  Review: Low-risk line; verify in surrounding control flow.
- L00868 [NONE] `		data_offset = le32_to_cpu(data_transfer->data_offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L00869 [NONE] `		if (wc->byte_len < data_offset ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00870 [NONE] `		    wc->byte_len < (u64)data_offset + data_length) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00871 [NONE] `			put_recvmsg(t, recvmsg);`
  Review: Low-risk line; verify in surrounding control flow.
- L00872 [NONE] `			smb_direct_disconnect_rdma_connection(t);`
  Review: Low-risk line; verify in surrounding control flow.
- L00873 [NONE] `			return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00874 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00875 [NONE] `		if (remaining_data_length > t->max_fragmented_recv_size ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00876 [NONE] `		    data_length > t->max_fragmented_recv_size ||`
  Review: Low-risk line; verify in surrounding control flow.
- L00877 [NONE] `		    (u64)remaining_data_length + (u64)data_length >`
  Review: Low-risk line; verify in surrounding control flow.
- L00878 [NONE] `		    (u64)t->max_fragmented_recv_size) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00879 [NONE] `			put_recvmsg(t, recvmsg);`
  Review: Low-risk line; verify in surrounding control flow.
- L00880 [NONE] `			smb_direct_disconnect_rdma_connection(t);`
  Review: Low-risk line; verify in surrounding control flow.
- L00881 [NONE] `			return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00882 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00883 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00884 [NONE] `		if (data_length) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00885 [NONE] `			if (t->full_packet_received)`
  Review: Low-risk line; verify in surrounding control flow.
- L00886 [NONE] `				recvmsg->first_segment = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00887 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00888 [NONE] `			if (le32_to_cpu(data_transfer->remaining_data_length))`
  Review: Low-risk line; verify in surrounding control flow.
- L00889 [NONE] `				t->full_packet_received = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L00890 [NONE] `			else`
  Review: Low-risk line; verify in surrounding control flow.
- L00891 [NONE] `				t->full_packet_received = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00892 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00893 [LOCK|] `			spin_lock(&t->receive_credit_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00894 [NONE] `			if (t->recv_credits <= 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00895 [LOCK|] `				spin_unlock(&t->receive_credit_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00896 [NONE] `				put_recvmsg(t, recvmsg);`
  Review: Low-risk line; verify in surrounding control flow.
- L00897 [NONE] `				smb_direct_disconnect_rdma_connection(t);`
  Review: Low-risk line; verify in surrounding control flow.
- L00898 [NONE] `				return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00899 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00900 [NONE] `			receive_credits = --(t->recv_credits);`
  Review: Low-risk line; verify in surrounding control flow.
- L00901 [NONE] `			avail_recvmsg_count = t->count_avail_recvmsg;`
  Review: Low-risk line; verify in surrounding control flow.
- L00902 [LOCK|] `			spin_unlock(&t->receive_credit_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00903 [NONE] `		} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00904 [LOCK|] `			spin_lock(&t->receive_credit_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00905 [NONE] `			if (t->recv_credits <= 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00906 [LOCK|] `				spin_unlock(&t->receive_credit_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00907 [NONE] `				put_recvmsg(t, recvmsg);`
  Review: Low-risk line; verify in surrounding control flow.
- L00908 [NONE] `				smb_direct_disconnect_rdma_connection(t);`
  Review: Low-risk line; verify in surrounding control flow.
- L00909 [NONE] `				return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00910 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L00911 [NONE] `			receive_credits = --(t->recv_credits);`
  Review: Low-risk line; verify in surrounding control flow.
- L00912 [NONE] `			avail_recvmsg_count = ++(t->count_avail_recvmsg);`
  Review: Low-risk line; verify in surrounding control flow.
- L00913 [LOCK|] `			spin_unlock(&t->receive_credit_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L00914 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00915 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00916 [NONE] `		t->recv_credit_target =`
  Review: Low-risk line; verify in surrounding control flow.
- L00917 [NONE] `				le16_to_cpu(data_transfer->credits_requested);`
  Review: Low-risk line; verify in surrounding control flow.
- L00918 [NONE] `		if (le16_to_cpu(data_transfer->credits_granted) > t->recv_credit_max)`
  Review: Low-risk line; verify in surrounding control flow.
- L00919 [NONE] `			data_transfer->credits_granted = cpu_to_le16(t->recv_credit_max);`
  Review: Low-risk line; verify in surrounding control flow.
- L00920 [LIFETIME|] `		atomic_add(le16_to_cpu(data_transfer->credits_granted),`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00921 [NONE] `			   &t->send_credits);`
  Review: Low-risk line; verify in surrounding control flow.
- L00922 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00923 [NONE] `		if (le16_to_cpu(data_transfer->flags) &`
  Review: Low-risk line; verify in surrounding control flow.
- L00924 [NONE] `		    SMB_DIRECT_RESPONSE_REQUESTED)`
  Review: Low-risk line; verify in surrounding control flow.
- L00925 [NONE] `			queue_work(smb_direct_wq, &t->send_immediate_work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00926 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00927 [LIFETIME|] `		if (atomic_read(&t->send_credits) > 0)`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00928 [NONE] `			wake_up_interruptible(&t->wait_send_credits);`
  Review: Low-risk line; verify in surrounding control flow.
- L00929 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00930 [NONE] `		if (is_receive_credit_post_required(receive_credits, avail_recvmsg_count))`
  Review: Low-risk line; verify in surrounding control flow.
- L00931 [NONE] `			queue_work(smb_direct_wq, &t->post_recv_credits_work);`
  Review: Low-risk line; verify in surrounding control flow.
- L00932 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00933 [NONE] `		if (data_length) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00934 [NONE] `			enqueue_reassembly(t, recvmsg, (int)data_length);`
  Review: Low-risk line; verify in surrounding control flow.
- L00935 [NONE] `			wake_up_interruptible(&t->wait_reassembly_queue);`
  Review: Low-risk line; verify in surrounding control flow.
- L00936 [NONE] `		} else`
  Review: Low-risk line; verify in surrounding control flow.
- L00937 [NONE] `			put_recvmsg(t, recvmsg);`
  Review: Low-risk line; verify in surrounding control flow.
- L00938 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00939 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00940 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00941 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00942 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00943 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00944 [NONE] `	 * This is an internal error!`
  Review: Low-risk line; verify in surrounding control flow.
- L00945 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00946 [NONE] `	WARN_ON_ONCE(recvmsg->type != SMB_DIRECT_MSG_DATA_TRANSFER);`
  Review: Low-risk line; verify in surrounding control flow.
- L00947 [NONE] `	put_recvmsg(t, recvmsg);`
  Review: Low-risk line; verify in surrounding control flow.
- L00948 [NONE] `	smb_direct_disconnect_rdma_connection(t);`
  Review: Low-risk line; verify in surrounding control flow.
- L00949 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00950 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00951 [NONE] `static int smb_direct_post_recv(struct smb_direct_transport *t,`
  Review: Low-risk line; verify in surrounding control flow.
- L00952 [NONE] `				struct smb_direct_recvmsg *recvmsg)`
  Review: Low-risk line; verify in surrounding control flow.
- L00953 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00954 [NONE] `	struct ib_recv_wr wr;`
  Review: Low-risk line; verify in surrounding control flow.
- L00955 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00956 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00957 [NONE] `	recvmsg->sge.addr = ib_dma_map_single(t->cm_id->device,`
  Review: Low-risk line; verify in surrounding control flow.
- L00958 [NONE] `					      recvmsg->packet, t->max_recv_size,`
  Review: Low-risk line; verify in surrounding control flow.
- L00959 [NONE] `					      DMA_FROM_DEVICE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00960 [NONE] `	ret = ib_dma_mapping_error(t->cm_id->device, recvmsg->sge.addr);`
  Review: Low-risk line; verify in surrounding control flow.
- L00961 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00962 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00963 [NONE] `	recvmsg->sge.length = t->max_recv_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L00964 [NONE] `	recvmsg->sge.lkey = t->pd->local_dma_lkey;`
  Review: Low-risk line; verify in surrounding control flow.
- L00965 [NONE] `	recvmsg->cqe.done = recv_done;`
  Review: Low-risk line; verify in surrounding control flow.
- L00966 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00967 [NONE] `	wr.wr_cqe = &recvmsg->cqe;`
  Review: Low-risk line; verify in surrounding control flow.
- L00968 [NONE] `	wr.next = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L00969 [NONE] `	wr.sg_list = &recvmsg->sge;`
  Review: Low-risk line; verify in surrounding control flow.
- L00970 [NONE] `	wr.num_sge = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00971 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00972 [NONE] `	ret = ib_post_recv(t->qp, &wr, NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L00973 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00974 [ERROR_PATH|] `		pr_err("Can't post recv: %d\n", ret);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00975 [NONE] `		ib_dma_unmap_single(t->cm_id->device,`
  Review: Low-risk line; verify in surrounding control flow.
- L00976 [NONE] `				    recvmsg->sge.addr, recvmsg->sge.length,`
  Review: Low-risk line; verify in surrounding control flow.
- L00977 [NONE] `				    DMA_FROM_DEVICE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00978 [NONE] `		recvmsg->sge.length = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00979 [NONE] `		smb_direct_disconnect_rdma_connection(t);`
  Review: Low-risk line; verify in surrounding control flow.
- L00980 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00981 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00982 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00983 [NONE] `	/* Track outstanding posted buffers for leak detection */`
  Review: Low-risk line; verify in surrounding control flow.
- L00984 [LIFETIME|] `	atomic_inc(&t->recv_posted);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00985 [LIFETIME|] `	atomic_inc(&t->total_credits_granted);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00986 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00987 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00988 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00989 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00990 [NONE] `static int smb_direct_read(struct ksmbd_transport *t, char *buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L00991 [NONE] `			   unsigned int size, int max_retries)`
  Review: Low-risk line; verify in surrounding control flow.
- L00992 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00993 [NONE] `	struct smb_direct_recvmsg *recvmsg;`
  Review: Low-risk line; verify in surrounding control flow.
- L00994 [NONE] `	struct smb_direct_data_transfer *data_transfer;`
  Review: Low-risk line; verify in surrounding control flow.
- L00995 [NONE] `	int to_copy, to_read, data_read, offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00996 [NONE] `	u32 data_length, remaining_data_length, data_offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L00997 [NONE] `	int rc;`
  Review: Low-risk line; verify in surrounding control flow.
- L00998 [NONE] `	struct smb_direct_transport *st = smb_trans_direct_transfort(t);`
  Review: Low-risk line; verify in surrounding control flow.
- L00999 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01000 [NONE] `again:`
  Review: Low-risk line; verify in surrounding control flow.
- L01001 [NONE] `	if (!ksmbd_conn_alive(st->transport.conn))`
  Review: Low-risk line; verify in surrounding control flow.
- L01002 [ERROR_PATH|] `		return -ESHUTDOWN;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01003 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01004 [NONE] `	if (st->status != SMB_DIRECT_CS_CONNECTED) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01005 [ERROR_PATH|] `		pr_err("disconnected\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01006 [ERROR_PATH|] `		return -ENOTCONN;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01007 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01008 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01009 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01010 [NONE] `	 * No need to hold the reassembly queue lock all the time as we are`
  Review: Low-risk line; verify in surrounding control flow.
- L01011 [NONE] `	 * the only one reading from the front of the queue. The transport`
  Review: Low-risk line; verify in surrounding control flow.
- L01012 [NONE] `	 * may add more entries to the back of the queue at the same time`
  Review: Low-risk line; verify in surrounding control flow.
- L01013 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01014 [NONE] `	if (st->reassembly_data_length >= size) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01015 [NONE] `		int queue_length;`
  Review: Low-risk line; verify in surrounding control flow.
- L01016 [NONE] `		int queue_removed = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01017 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01018 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01019 [NONE] `		 * Need to make sure reassembly_data_length is read before`
  Review: Low-risk line; verify in surrounding control flow.
- L01020 [NONE] `		 * reading reassembly_queue_length and calling`
  Review: Low-risk line; verify in surrounding control flow.
- L01021 [NONE] `		 * get_first_reassembly. This call is lock free`
  Review: Low-risk line; verify in surrounding control flow.
- L01022 [NONE] `		 * as we never read at the end of the queue which are being`
  Review: Low-risk line; verify in surrounding control flow.
- L01023 [NONE] `		 * updated in SOFTIRQ as more data is received`
  Review: Low-risk line; verify in surrounding control flow.
- L01024 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01025 [NONE] `		virt_rmb();`
  Review: Low-risk line; verify in surrounding control flow.
- L01026 [NONE] `		queue_length = st->reassembly_queue_length;`
  Review: Low-risk line; verify in surrounding control flow.
- L01027 [NONE] `		data_read = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01028 [NONE] `		to_read = size;`
  Review: Low-risk line; verify in surrounding control flow.
- L01029 [NONE] `		offset = st->first_entry_offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L01030 [NONE] `		while (data_read < size) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01031 [NONE] `			recvmsg = get_first_reassembly(st);`
  Review: Low-risk line; verify in surrounding control flow.
- L01032 [NONE] `			data_transfer = smb_direct_recvmsg_payload(recvmsg);`
  Review: Low-risk line; verify in surrounding control flow.
- L01033 [NONE] `			data_length = le32_to_cpu(data_transfer->data_length);`
  Review: Low-risk line; verify in surrounding control flow.
- L01034 [NONE] `			remaining_data_length =`
  Review: Low-risk line; verify in surrounding control flow.
- L01035 [NONE] `				le32_to_cpu(data_transfer->remaining_data_length);`
  Review: Low-risk line; verify in surrounding control flow.
- L01036 [NONE] `			data_offset = le32_to_cpu(data_transfer->data_offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L01037 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01038 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01039 [NONE] `			 * The upper layer expects RFC1002 length at the`
  Review: Low-risk line; verify in surrounding control flow.
- L01040 [NONE] `			 * beginning of the payload. Return it to indicate`
  Review: Low-risk line; verify in surrounding control flow.
- L01041 [NONE] `			 * the total length of the packet. This minimize the`
  Review: Low-risk line; verify in surrounding control flow.
- L01042 [NONE] `			 * change to upper layer packet processing logic. This`
  Review: Low-risk line; verify in surrounding control flow.
- L01043 [NONE] `			 * will be eventually remove when an intermediate`
  Review: Low-risk line; verify in surrounding control flow.
- L01044 [NONE] `			 * transport layer is added`
  Review: Low-risk line; verify in surrounding control flow.
- L01045 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01046 [NONE] `			if (recvmsg->first_segment && size == 4) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01047 [NONE] `				unsigned int rfc1002_len =`
  Review: Low-risk line; verify in surrounding control flow.
- L01048 [NONE] `					data_length + remaining_data_length;`
  Review: Low-risk line; verify in surrounding control flow.
- L01049 [NONE] `				if (rfc1002_len < data_length ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01050 [NONE] `				    rfc1002_len > MAX_STREAM_PROT_LEN) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01051 [ERROR_PATH|] `					pr_err("Invalid rfc1002 length %u\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01052 [NONE] `					       rfc1002_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01053 [ERROR_PATH|] `					return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01054 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L01055 [NONE] `				*((__be32 *)buf) = cpu_to_be32(rfc1002_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01056 [NONE] `				data_read = 4;`
  Review: Low-risk line; verify in surrounding control flow.
- L01057 [NONE] `				recvmsg->first_segment = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L01058 [NONE] `				ksmbd_debug(RDMA,`
  Review: Low-risk line; verify in surrounding control flow.
- L01059 [NONE] `					    "returning rfc1002 length %d\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L01060 [NONE] `					    rfc1002_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01061 [ERROR_PATH|] `				goto read_rfc1002_done;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01062 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01063 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01064 [NONE] `			to_copy = min_t(int, data_length - offset, to_read);`
  Review: Low-risk line; verify in surrounding control flow.
- L01065 [MEM_BOUNDS|] `			memcpy(buf + data_read, (char *)data_transfer + data_offset + offset,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01066 [NONE] `			       to_copy);`
  Review: Low-risk line; verify in surrounding control flow.
- L01067 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01068 [NONE] `			/* move on to the next buffer? */`
  Review: Low-risk line; verify in surrounding control flow.
- L01069 [NONE] `			if (to_copy == data_length - offset) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01070 [NONE] `				queue_length--;`
  Review: Low-risk line; verify in surrounding control flow.
- L01071 [NONE] `				/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01072 [NONE] `				 * No need to lock if we are not at the`
  Review: Low-risk line; verify in surrounding control flow.
- L01073 [NONE] `				 * end of the queue`
  Review: Low-risk line; verify in surrounding control flow.
- L01074 [NONE] `				 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01075 [NONE] `				if (queue_length) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01076 [NONE] `					list_del(&recvmsg->list);`
  Review: Low-risk line; verify in surrounding control flow.
- L01077 [NONE] `				} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L01078 [NONE] `					spin_lock_irq(&st->reassembly_queue_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L01079 [NONE] `					list_del(&recvmsg->list);`
  Review: Low-risk line; verify in surrounding control flow.
- L01080 [NONE] `					spin_unlock_irq(&st->reassembly_queue_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L01081 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L01082 [NONE] `				queue_removed++;`
  Review: Low-risk line; verify in surrounding control flow.
- L01083 [NONE] `				put_recvmsg(st, recvmsg);`
  Review: Low-risk line; verify in surrounding control flow.
- L01084 [NONE] `				offset = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01085 [NONE] `			} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L01086 [NONE] `				offset += to_copy;`
  Review: Low-risk line; verify in surrounding control flow.
- L01087 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01088 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01089 [NONE] `			to_read -= to_copy;`
  Review: Low-risk line; verify in surrounding control flow.
- L01090 [NONE] `			data_read += to_copy;`
  Review: Low-risk line; verify in surrounding control flow.
- L01091 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01092 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01093 [NONE] `		spin_lock_irq(&st->reassembly_queue_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L01094 [NONE] `		st->reassembly_data_length -= data_read;`
  Review: Low-risk line; verify in surrounding control flow.
- L01095 [NONE] `		st->reassembly_queue_length -= queue_removed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01096 [NONE] `		spin_unlock_irq(&st->reassembly_queue_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L01097 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01098 [LOCK|] `		spin_lock(&st->receive_credit_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01099 [NONE] `		st->count_avail_recvmsg += queue_removed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01100 [NONE] `		if (is_receive_credit_post_required(st->recv_credits, st->count_avail_recvmsg)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01101 [LOCK|] `			spin_unlock(&st->receive_credit_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01102 [NONE] `			queue_work(smb_direct_wq, &st->post_recv_credits_work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01103 [NONE] `		} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L01104 [LOCK|] `			spin_unlock(&st->receive_credit_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01105 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01106 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01107 [NONE] `		st->first_entry_offset = offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L01108 [NONE] `		ksmbd_debug(RDMA,`
  Review: Low-risk line; verify in surrounding control flow.
- L01109 [NONE] `			    "returning to thread data_read=%d reassembly_data_length=%d first_entry_offset=%d\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L01110 [NONE] `			    data_read, st->reassembly_data_length,`
  Review: Low-risk line; verify in surrounding control flow.
- L01111 [NONE] `			    st->first_entry_offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L01112 [NONE] `read_rfc1002_done:`
  Review: Low-risk line; verify in surrounding control flow.
- L01113 [NONE] `		return data_read;`
  Review: Low-risk line; verify in surrounding control flow.
- L01114 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01115 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01116 [WAIT_LOOP|] `	ksmbd_debug(RDMA, "wait_event on more data\n");`
  Review: Bounded wait and cancellation path must be guaranteed.
- L01117 [WAIT_LOOP|] `	rc = wait_event_interruptible_timeout(st->wait_reassembly_queue,`
  Review: Bounded wait and cancellation path must be guaranteed.
- L01118 [NONE] `					      st->reassembly_data_length >= size ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01119 [NONE] `					      st->status != SMB_DIRECT_CS_CONNECTED,`
  Review: Low-risk line; verify in surrounding control flow.
- L01120 [NONE] `					      KSMBD_TCP_RECV_TIMEOUT);`
  Review: Low-risk line; verify in surrounding control flow.
- L01121 [NONE] `	if (rc < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01122 [ERROR_PATH|] `		return -EINTR;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01123 [NONE] `	if (rc == 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01124 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01125 [NONE] `		 * Match TCP transport semantics: bounded retries for request`
  Review: Low-risk line; verify in surrounding control flow.
- L01126 [NONE] `		 * body reads, unlimited retries for header reads.`
  Review: Low-risk line; verify in surrounding control flow.
- L01127 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01128 [NONE] `		if (max_retries == 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01129 [ERROR_PATH|] `			return -EAGAIN;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01130 [NONE] `		else if (max_retries > 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01131 [NONE] `			max_retries--;`
  Review: Low-risk line; verify in surrounding control flow.
- L01132 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01133 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01134 [ERROR_PATH|] `	goto again;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01135 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01136 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01137 [NONE] `static void smb_direct_post_recv_credits(struct work_struct *work)`
  Review: Low-risk line; verify in surrounding control flow.
- L01138 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01139 [NONE] `	struct smb_direct_transport *t = container_of(work,`
  Review: Low-risk line; verify in surrounding control flow.
- L01140 [NONE] `		struct smb_direct_transport, post_recv_credits_work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01141 [NONE] `	struct smb_direct_recvmsg *recvmsg;`
  Review: Low-risk line; verify in surrounding control flow.
- L01142 [NONE] `	int receive_credits, credits = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01143 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01144 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01145 [LOCK|] `	spin_lock(&t->receive_credit_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01146 [NONE] `	receive_credits = t->recv_credits;`
  Review: Low-risk line; verify in surrounding control flow.
- L01147 [LOCK|] `	spin_unlock(&t->receive_credit_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01148 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01149 [NONE] `	if (receive_credits < t->recv_credit_target) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01150 [NONE] `		while (true) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01151 [NONE] `			recvmsg = get_free_recvmsg(t);`
  Review: Low-risk line; verify in surrounding control flow.
- L01152 [NONE] `			if (!recvmsg)`
  Review: Low-risk line; verify in surrounding control flow.
- L01153 [NONE] `				break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01154 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01155 [NONE] `			recvmsg->type = SMB_DIRECT_MSG_DATA_TRANSFER;`
  Review: Low-risk line; verify in surrounding control flow.
- L01156 [NONE] `			recvmsg->first_segment = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L01157 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01158 [NONE] `			ret = smb_direct_post_recv(t, recvmsg);`
  Review: Low-risk line; verify in surrounding control flow.
- L01159 [NONE] `			if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01160 [ERROR_PATH|] `				pr_err("Can't post recv: %d\n", ret);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01161 [NONE] `				put_recvmsg(t, recvmsg);`
  Review: Low-risk line; verify in surrounding control flow.
- L01162 [NONE] `				break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01163 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01164 [NONE] `			credits++;`
  Review: Low-risk line; verify in surrounding control flow.
- L01165 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01166 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01167 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01168 [LOCK|] `	spin_lock(&t->receive_credit_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01169 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01170 [NONE] `	 * Bounds check: refuse to grant more credits than available.`
  Review: Low-risk line; verify in surrounding control flow.
- L01171 [NONE] `	 * This should not happen in normal operation, but guards against`
  Review: Low-risk line; verify in surrounding control flow.
- L01172 [NONE] `	 * accounting bugs.`
  Review: Low-risk line; verify in surrounding control flow.
- L01173 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01174 [NONE] `	if (credits > t->count_avail_recvmsg) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01175 [ERROR_PATH|] `		pr_warn_ratelimited(`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01176 [NONE] `			"ksmbd: RDMA credit overcommit: "`
  Review: Low-risk line; verify in surrounding control flow.
- L01177 [NONE] `			"trying to grant %d but only %d available\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L01178 [NONE] `			credits, t->count_avail_recvmsg);`
  Review: Low-risk line; verify in surrounding control flow.
- L01179 [NONE] `		credits = t->count_avail_recvmsg;`
  Review: Low-risk line; verify in surrounding control flow.
- L01180 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01181 [NONE] `	t->recv_credits += credits;`
  Review: Low-risk line; verify in surrounding control flow.
- L01182 [NONE] `	t->count_avail_recvmsg -= credits;`
  Review: Low-risk line; verify in surrounding control flow.
- L01183 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01184 [NONE] `	/* Low watermark warning */`
  Review: Low-risk line; verify in surrounding control flow.
- L01185 [NONE] `	if (t->count_avail_recvmsg <`
  Review: Low-risk line; verify in surrounding control flow.
- L01186 [NONE] `	    t->recv_credit_max * SMB_DIRECT_CREDIT_LOW_WATERMARK_PCT / 100)`
  Review: Low-risk line; verify in surrounding control flow.
- L01187 [ERROR_PATH|] `		pr_warn_ratelimited(`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01188 [NONE] `			"ksmbd: RDMA credit pool low: "`
  Review: Low-risk line; verify in surrounding control flow.
- L01189 [NONE] `			"avail=%d recv_credits=%d max=%d\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L01190 [NONE] `			t->count_avail_recvmsg,`
  Review: Low-risk line; verify in surrounding control flow.
- L01191 [NONE] `			t->recv_credits, t->recv_credit_max);`
  Review: Low-risk line; verify in surrounding control flow.
- L01192 [LOCK|] `	spin_unlock(&t->receive_credit_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01193 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01194 [LOCK|] `	spin_lock(&t->lock_new_recv_credits);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01195 [NONE] `	t->new_recv_credits += credits;`
  Review: Low-risk line; verify in surrounding control flow.
- L01196 [LOCK|] `	spin_unlock(&t->lock_new_recv_credits);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01197 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01198 [NONE] `	if (credits)`
  Review: Low-risk line; verify in surrounding control flow.
- L01199 [NONE] `		queue_work(smb_direct_wq, &t->send_immediate_work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01200 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01201 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01202 [NONE] `static void send_done(struct ib_cq *cq, struct ib_wc *wc)`
  Review: Low-risk line; verify in surrounding control flow.
- L01203 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01204 [NONE] `	struct smb_direct_sendmsg *sendmsg, *sibling;`
  Review: Low-risk line; verify in surrounding control flow.
- L01205 [NONE] `	struct smb_direct_transport *t;`
  Review: Low-risk line; verify in surrounding control flow.
- L01206 [NONE] `	struct list_head *pos, *prev, *end;`
  Review: Low-risk line; verify in surrounding control flow.
- L01207 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01208 [NONE] `	sendmsg = container_of(wc->wr_cqe, struct smb_direct_sendmsg, cqe);`
  Review: Low-risk line; verify in surrounding control flow.
- L01209 [NONE] `	t = sendmsg->transport;`
  Review: Low-risk line; verify in surrounding control flow.
- L01210 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01211 [NONE] `	ksmbd_debug(RDMA, "Send completed. status='%s (%d)', opcode=%d\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L01212 [NONE] `		    ib_wc_status_msg(wc->status), wc->status,`
  Review: Low-risk line; verify in surrounding control flow.
- L01213 [NONE] `		    wc->opcode);`
  Review: Low-risk line; verify in surrounding control flow.
- L01214 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01215 [NONE] `	if (wc->status != IB_WC_SUCCESS || wc->opcode != IB_WC_SEND) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01216 [ERROR_PATH|] `		pr_err("Send error. status='%s (%d)', opcode=%d\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01217 [NONE] `		       ib_wc_status_msg(wc->status), wc->status,`
  Review: Low-risk line; verify in surrounding control flow.
- L01218 [NONE] `		       wc->opcode);`
  Review: Low-risk line; verify in surrounding control flow.
- L01219 [NONE] `		smb_direct_disconnect_rdma_connection(t);`
  Review: Low-risk line; verify in surrounding control flow.
- L01220 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01221 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01222 [LIFETIME|] `	if (atomic_dec_and_test(&t->send_pending))`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01223 [NONE] `		wake_up(&t->wait_send_pending);`
  Review: Low-risk line; verify in surrounding control flow.
- L01224 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01225 [NONE] `	/* iterate and free the list of messages in reverse. the list's head`
  Review: Low-risk line; verify in surrounding control flow.
- L01226 [NONE] `	 * is invalid.`
  Review: Low-risk line; verify in surrounding control flow.
- L01227 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01228 [NONE] `	for (pos = &sendmsg->list, prev = pos->prev, end = sendmsg->list.next;`
  Review: Low-risk line; verify in surrounding control flow.
- L01229 [NONE] `	     prev != end; pos = prev, prev = prev->prev) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01230 [NONE] `		sibling = container_of(pos, struct smb_direct_sendmsg, list);`
  Review: Low-risk line; verify in surrounding control flow.
- L01231 [NONE] `		smb_direct_free_sendmsg(t, sibling);`
  Review: Low-risk line; verify in surrounding control flow.
- L01232 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01233 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01234 [NONE] `	sibling = container_of(pos, struct smb_direct_sendmsg, list);`
  Review: Low-risk line; verify in surrounding control flow.
- L01235 [NONE] `	smb_direct_free_sendmsg(t, sibling);`
  Review: Low-risk line; verify in surrounding control flow.
- L01236 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01237 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01238 [NONE] `static int manage_credits_prior_sending(struct smb_direct_transport *t)`
  Review: Low-risk line; verify in surrounding control flow.
- L01239 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01240 [NONE] `	int new_credits;`
  Review: Low-risk line; verify in surrounding control flow.
- L01241 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01242 [LOCK|] `	spin_lock(&t->lock_new_recv_credits);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01243 [NONE] `	new_credits = t->new_recv_credits;`
  Review: Low-risk line; verify in surrounding control flow.
- L01244 [NONE] `	t->new_recv_credits = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01245 [LOCK|] `	spin_unlock(&t->lock_new_recv_credits);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01246 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01247 [NONE] `	return new_credits;`
  Review: Low-risk line; verify in surrounding control flow.
- L01248 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01249 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01250 [NONE] `static int smb_direct_post_send(struct smb_direct_transport *t,`
  Review: Low-risk line; verify in surrounding control flow.
- L01251 [NONE] `				struct ib_send_wr *wr)`
  Review: Low-risk line; verify in surrounding control flow.
- L01252 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01253 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01254 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01255 [LIFETIME|] `	atomic_inc(&t->send_pending);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01256 [NONE] `	ret = ib_post_send(t->qp, wr, NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L01257 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01258 [ERROR_PATH|] `		pr_err("failed to post send: %d\n", ret);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01259 [LIFETIME|] `		if (atomic_dec_and_test(&t->send_pending))`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01260 [NONE] `			wake_up(&t->wait_send_pending);`
  Review: Low-risk line; verify in surrounding control flow.
- L01261 [NONE] `		smb_direct_disconnect_rdma_connection(t);`
  Review: Low-risk line; verify in surrounding control flow.
- L01262 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01263 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01264 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01265 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01266 [NONE] `static void smb_direct_send_ctx_init(struct smb_direct_transport *t,`
  Review: Low-risk line; verify in surrounding control flow.
- L01267 [NONE] `				     struct smb_direct_send_ctx *send_ctx,`
  Review: Low-risk line; verify in surrounding control flow.
- L01268 [NONE] `				     bool need_invalidate_rkey,`
  Review: Low-risk line; verify in surrounding control flow.
- L01269 [NONE] `				     unsigned int remote_key)`
  Review: Low-risk line; verify in surrounding control flow.
- L01270 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01271 [NONE] `	INIT_LIST_HEAD(&send_ctx->msg_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L01272 [NONE] `	send_ctx->wr_cnt = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01273 [NONE] `	send_ctx->need_invalidate_rkey = need_invalidate_rkey;`
  Review: Low-risk line; verify in surrounding control flow.
- L01274 [NONE] `	send_ctx->remote_key = remote_key;`
  Review: Low-risk line; verify in surrounding control flow.
- L01275 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01276 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01277 [NONE] `static int smb_direct_flush_send_list(struct smb_direct_transport *t,`
  Review: Low-risk line; verify in surrounding control flow.
- L01278 [NONE] `				      struct smb_direct_send_ctx *send_ctx,`
  Review: Low-risk line; verify in surrounding control flow.
- L01279 [NONE] `				      bool is_last)`
  Review: Low-risk line; verify in surrounding control flow.
- L01280 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01281 [NONE] `	struct smb_direct_sendmsg *first, *last;`
  Review: Low-risk line; verify in surrounding control flow.
- L01282 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01283 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01284 [NONE] `	if (list_empty(&send_ctx->msg_list))`
  Review: Low-risk line; verify in surrounding control flow.
- L01285 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01286 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01287 [NONE] `	first = list_first_entry(&send_ctx->msg_list,`
  Review: Low-risk line; verify in surrounding control flow.
- L01288 [NONE] `				 struct smb_direct_sendmsg,`
  Review: Low-risk line; verify in surrounding control flow.
- L01289 [NONE] `				 list);`
  Review: Low-risk line; verify in surrounding control flow.
- L01290 [NONE] `	last = list_last_entry(&send_ctx->msg_list,`
  Review: Low-risk line; verify in surrounding control flow.
- L01291 [NONE] `			       struct smb_direct_sendmsg,`
  Review: Low-risk line; verify in surrounding control flow.
- L01292 [NONE] `			       list);`
  Review: Low-risk line; verify in surrounding control flow.
- L01293 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01294 [NONE] `	last->wr.send_flags = IB_SEND_SIGNALED;`
  Review: Low-risk line; verify in surrounding control flow.
- L01295 [NONE] `	last->wr.wr_cqe = &last->cqe;`
  Review: Low-risk line; verify in surrounding control flow.
- L01296 [NONE] `	if (is_last && send_ctx->need_invalidate_rkey) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01297 [NONE] `		last->wr.opcode = IB_WR_SEND_WITH_INV;`
  Review: Low-risk line; verify in surrounding control flow.
- L01298 [NONE] `		last->wr.ex.invalidate_rkey = send_ctx->remote_key;`
  Review: Low-risk line; verify in surrounding control flow.
- L01299 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01300 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01301 [NONE] `	ret = smb_direct_post_send(t, &first->wr);`
  Review: Low-risk line; verify in surrounding control flow.
- L01302 [NONE] `	if (!ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01303 [NONE] `		smb_direct_send_ctx_init(t, send_ctx,`
  Review: Low-risk line; verify in surrounding control flow.
- L01304 [NONE] `					 send_ctx->need_invalidate_rkey,`
  Review: Low-risk line; verify in surrounding control flow.
- L01305 [NONE] `					 send_ctx->remote_key);`
  Review: Low-risk line; verify in surrounding control flow.
- L01306 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L01307 [LIFETIME|] `		atomic_add(send_ctx->wr_cnt, &t->send_credits);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01308 [NONE] `		wake_up(&t->wait_send_credits);`
  Review: Low-risk line; verify in surrounding control flow.
- L01309 [NONE] `		list_for_each_entry_safe(first, last, &send_ctx->msg_list,`
  Review: Low-risk line; verify in surrounding control flow.
- L01310 [NONE] `					 list) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01311 [NONE] `			smb_direct_free_sendmsg(t, first);`
  Review: Low-risk line; verify in surrounding control flow.
- L01312 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01313 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01314 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01315 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01316 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01317 [NONE] `static int wait_for_credits(struct smb_direct_transport *t,`
  Review: Low-risk line; verify in surrounding control flow.
- L01318 [LIFETIME|] `			    wait_queue_head_t *waitq, atomic_t *total_credits,`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01319 [NONE] `			    int needed)`
  Review: Low-risk line; verify in surrounding control flow.
- L01320 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01321 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01322 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01323 [NONE] `	do {`
  Review: Low-risk line; verify in surrounding control flow.
- L01324 [LIFETIME|] `		if (atomic_sub_return(needed, total_credits) >= 0)`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01325 [NONE] `			return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01326 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01327 [LIFETIME|] `		atomic_add(needed, total_credits);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01328 [WAIT_LOOP|] `		ret = wait_event_interruptible_timeout(*waitq,`
  Review: Bounded wait and cancellation path must be guaranteed.
- L01329 [LIFETIME|] `						       atomic_read(total_credits) >= needed ||`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01330 [NONE] `						       t->status != SMB_DIRECT_CS_CONNECTED,`
  Review: Low-risk line; verify in surrounding control flow.
- L01331 [NONE] `						       SMB_DIRECT_NEGOTIATE_TIMEOUT * HZ);`
  Review: Low-risk line; verify in surrounding control flow.
- L01332 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01333 [NONE] `		if (t->status != SMB_DIRECT_CS_CONNECTED)`
  Review: Low-risk line; verify in surrounding control flow.
- L01334 [ERROR_PATH|] `			return -ENOTCONN;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01335 [NONE] `		else if (ret == 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01336 [ERROR_PATH|] `			pr_err_ratelimited("timeout waiting for RDMA credits (needed=%d avail=%d)\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01337 [LIFETIME|] `					   needed, atomic_read(total_credits));`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01338 [NONE] `			smb_direct_disconnect_rdma_connection(t);`
  Review: Low-risk line; verify in surrounding control flow.
- L01339 [ERROR_PATH|] `			return -ETIMEDOUT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01340 [NONE] `		} else if (ret < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01341 [NONE] `			return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01342 [NONE] `	} while (true);`
  Review: Low-risk line; verify in surrounding control flow.
- L01343 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01344 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01345 [NONE] `static int wait_for_send_credits(struct smb_direct_transport *t,`
  Review: Low-risk line; verify in surrounding control flow.
- L01346 [NONE] `				 struct smb_direct_send_ctx *send_ctx)`
  Review: Low-risk line; verify in surrounding control flow.
- L01347 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01348 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01349 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01350 [NONE] `	if (send_ctx &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01351 [LIFETIME|] `	    (send_ctx->wr_cnt >= 16 || atomic_read(&t->send_credits) <= 1)) {`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01352 [NONE] `		ret = smb_direct_flush_send_list(t, send_ctx, false);`
  Review: Low-risk line; verify in surrounding control flow.
- L01353 [NONE] `		if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L01354 [NONE] `			return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01355 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01356 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01357 [NONE] `	return wait_for_credits(t, &t->wait_send_credits, &t->send_credits, 1);`
  Review: Low-risk line; verify in surrounding control flow.
- L01358 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01359 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01360 [NONE] `static int wait_for_rw_credits(struct smb_direct_transport *t, int credits)`
  Review: Low-risk line; verify in surrounding control flow.
- L01361 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01362 [NONE] `	return wait_for_credits(t, &t->wait_rw_credits, &t->rw_credits, credits);`
  Review: Low-risk line; verify in surrounding control flow.
- L01363 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01364 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01365 [NONE] `static int calc_rw_credits(struct smb_direct_transport *t,`
  Review: Low-risk line; verify in surrounding control flow.
- L01366 [NONE] `			   char *buf, unsigned int len)`
  Review: Low-risk line; verify in surrounding control flow.
- L01367 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01368 [NONE] `	return DIV_ROUND_UP(get_buf_page_count(buf, len),`
  Review: Low-risk line; verify in surrounding control flow.
- L01369 [NONE] `			    t->pages_per_rw_credit);`
  Review: Low-risk line; verify in surrounding control flow.
- L01370 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01371 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01372 [NONE] `static int smb_direct_create_header(struct smb_direct_transport *t,`
  Review: Low-risk line; verify in surrounding control flow.
- L01373 [NONE] `				    int size, int remaining_data_length,`
  Review: Low-risk line; verify in surrounding control flow.
- L01374 [NONE] `				    struct smb_direct_sendmsg **sendmsg_out)`
  Review: Low-risk line; verify in surrounding control flow.
- L01375 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01376 [NONE] `	struct smb_direct_sendmsg *sendmsg;`
  Review: Low-risk line; verify in surrounding control flow.
- L01377 [NONE] `	struct smb_direct_data_transfer *packet;`
  Review: Low-risk line; verify in surrounding control flow.
- L01378 [NONE] `	int header_length;`
  Review: Low-risk line; verify in surrounding control flow.
- L01379 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01380 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01381 [NONE] `	sendmsg = smb_direct_alloc_sendmsg(t);`
  Review: Low-risk line; verify in surrounding control flow.
- L01382 [NONE] `	if (IS_ERR(sendmsg))`
  Review: Low-risk line; verify in surrounding control flow.
- L01383 [NONE] `		return PTR_ERR(sendmsg);`
  Review: Low-risk line; verify in surrounding control flow.
- L01384 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01385 [NONE] `	/* Fill in the packet header */`
  Review: Low-risk line; verify in surrounding control flow.
- L01386 [NONE] `	packet = (struct smb_direct_data_transfer *)sendmsg->packet;`
  Review: Low-risk line; verify in surrounding control flow.
- L01387 [NONE] `	packet->credits_requested = cpu_to_le16(t->send_credit_target);`
  Review: Low-risk line; verify in surrounding control flow.
- L01388 [NONE] `	packet->credits_granted = cpu_to_le16(manage_credits_prior_sending(t));`
  Review: Low-risk line; verify in surrounding control flow.
- L01389 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01390 [NONE] `	packet->flags = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01391 [NONE] `	packet->reserved = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01392 [NONE] `	if (!size)`
  Review: Low-risk line; verify in surrounding control flow.
- L01393 [NONE] `		packet->data_offset = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01394 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L01395 [NONE] `		packet->data_offset = cpu_to_le32(24);`
  Review: Low-risk line; verify in surrounding control flow.
- L01396 [NONE] `	packet->data_length = cpu_to_le32(size);`
  Review: Low-risk line; verify in surrounding control flow.
- L01397 [NONE] `	packet->remaining_data_length = cpu_to_le32(remaining_data_length);`
  Review: Low-risk line; verify in surrounding control flow.
- L01398 [NONE] `	packet->padding = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01399 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01400 [NONE] `	ksmbd_debug(RDMA,`
  Review: Low-risk line; verify in surrounding control flow.
- L01401 [NONE] `		    "credits_requested=%d credits_granted=%d data_offset=%d data_length=%d remaining_data_length=%d\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L01402 [NONE] `		    le16_to_cpu(packet->credits_requested),`
  Review: Low-risk line; verify in surrounding control flow.
- L01403 [NONE] `		    le16_to_cpu(packet->credits_granted),`
  Review: Low-risk line; verify in surrounding control flow.
- L01404 [NONE] `		    le32_to_cpu(packet->data_offset),`
  Review: Low-risk line; verify in surrounding control flow.
- L01405 [NONE] `		    le32_to_cpu(packet->data_length),`
  Review: Low-risk line; verify in surrounding control flow.
- L01406 [NONE] `		    le32_to_cpu(packet->remaining_data_length));`
  Review: Low-risk line; verify in surrounding control flow.
- L01407 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01408 [NONE] `	/* Map the packet to DMA */`
  Review: Low-risk line; verify in surrounding control flow.
- L01409 [NONE] `	header_length = sizeof(struct smb_direct_data_transfer);`
  Review: Low-risk line; verify in surrounding control flow.
- L01410 [NONE] `	/* If this is a packet without payload, don't send padding */`
  Review: Low-risk line; verify in surrounding control flow.
- L01411 [NONE] `	if (!size)`
  Review: Low-risk line; verify in surrounding control flow.
- L01412 [NONE] `		header_length =`
  Review: Low-risk line; verify in surrounding control flow.
- L01413 [NONE] `			offsetof(struct smb_direct_data_transfer, padding);`
  Review: Low-risk line; verify in surrounding control flow.
- L01414 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01415 [NONE] `	sendmsg->sge[0].addr = ib_dma_map_single(t->cm_id->device,`
  Review: Low-risk line; verify in surrounding control flow.
- L01416 [NONE] `						 (void *)packet,`
  Review: Low-risk line; verify in surrounding control flow.
- L01417 [NONE] `						 header_length,`
  Review: Low-risk line; verify in surrounding control flow.
- L01418 [NONE] `						 DMA_TO_DEVICE);`
  Review: Low-risk line; verify in surrounding control flow.
- L01419 [NONE] `	ret = ib_dma_mapping_error(t->cm_id->device, sendmsg->sge[0].addr);`
  Review: Low-risk line; verify in surrounding control flow.
- L01420 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01421 [NONE] `		smb_direct_free_sendmsg(t, sendmsg);`
  Review: Low-risk line; verify in surrounding control flow.
- L01422 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01423 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01424 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01425 [NONE] `	sendmsg->num_sge = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L01426 [NONE] `	sendmsg->sge[0].length = header_length;`
  Review: Low-risk line; verify in surrounding control flow.
- L01427 [NONE] `	sendmsg->sge[0].lkey = t->pd->local_dma_lkey;`
  Review: Low-risk line; verify in surrounding control flow.
- L01428 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01429 [NONE] `	*sendmsg_out = sendmsg;`
  Review: Low-risk line; verify in surrounding control flow.
- L01430 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01431 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01432 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01433 [NONE] `static int get_sg_list(void *buf, int size, struct scatterlist *sg_list, int nentries)`
  Review: Low-risk line; verify in surrounding control flow.
- L01434 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01435 [NONE] `	bool high = is_vmalloc_addr(buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01436 [NONE] `	struct page *page;`
  Review: Low-risk line; verify in surrounding control flow.
- L01437 [NONE] `	int offset, len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01438 [NONE] `	int i = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01439 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01440 [NONE] `	if (size <= 0 || nentries < get_buf_page_count(buf, size))`
  Review: Low-risk line; verify in surrounding control flow.
- L01441 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01442 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01443 [NONE] `	offset = offset_in_page(buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01444 [NONE] `	buf -= offset;`
  Review: Low-risk line; verify in surrounding control flow.
- L01445 [NONE] `	while (size > 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01446 [NONE] `		len = min_t(int, PAGE_SIZE - offset, size);`
  Review: Low-risk line; verify in surrounding control flow.
- L01447 [NONE] `		if (high)`
  Review: Low-risk line; verify in surrounding control flow.
- L01448 [NONE] `			page = vmalloc_to_page(buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01449 [NONE] `		else`
  Review: Low-risk line; verify in surrounding control flow.
- L01450 [NONE] `			page = kmap_to_page(buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01451 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01452 [NONE] `		if (!sg_list)`
  Review: Low-risk line; verify in surrounding control flow.
- L01453 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01454 [NONE] `		sg_set_page(sg_list, page, len, offset);`
  Review: Low-risk line; verify in surrounding control flow.
- L01455 [NONE] `		sg_list = sg_next(sg_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L01456 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01457 [NONE] `		buf += PAGE_SIZE;`
  Review: Low-risk line; verify in surrounding control flow.
- L01458 [NONE] `		size -= len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01459 [NONE] `		offset = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01460 [NONE] `		i++;`
  Review: Low-risk line; verify in surrounding control flow.
- L01461 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01462 [NONE] `	return i;`
  Review: Low-risk line; verify in surrounding control flow.
- L01463 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01464 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01465 [NONE] `static int get_mapped_sg_list(struct ib_device *device, void *buf, int size,`
  Review: Low-risk line; verify in surrounding control flow.
- L01466 [NONE] `			      struct scatterlist *sg_list, int nentries,`
  Review: Low-risk line; verify in surrounding control flow.
- L01467 [NONE] `			      enum dma_data_direction dir)`
  Review: Low-risk line; verify in surrounding control flow.
- L01468 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01469 [NONE] `	int npages;`
  Review: Low-risk line; verify in surrounding control flow.
- L01470 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01471 [NONE] `	npages = get_sg_list(buf, size, sg_list, nentries);`
  Review: Low-risk line; verify in surrounding control flow.
- L01472 [NONE] `	if (npages < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01473 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01474 [NONE] `	return ib_dma_map_sg(device, sg_list, npages, dir);`
  Review: Low-risk line; verify in surrounding control flow.
- L01475 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01476 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01477 [NONE] `static int post_sendmsg(struct smb_direct_transport *t,`
  Review: Low-risk line; verify in surrounding control flow.
- L01478 [NONE] `			struct smb_direct_send_ctx *send_ctx,`
  Review: Low-risk line; verify in surrounding control flow.
- L01479 [NONE] `			struct smb_direct_sendmsg *msg)`
  Review: Low-risk line; verify in surrounding control flow.
- L01480 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01481 [NONE] `	int i;`
  Review: Low-risk line; verify in surrounding control flow.
- L01482 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01483 [NONE] `	for (i = 0; i < msg->num_sge; i++)`
  Review: Low-risk line; verify in surrounding control flow.
- L01484 [NONE] `		ib_dma_sync_single_for_device(t->cm_id->device,`
  Review: Low-risk line; verify in surrounding control flow.
- L01485 [NONE] `					      msg->sge[i].addr, msg->sge[i].length,`
  Review: Low-risk line; verify in surrounding control flow.
- L01486 [NONE] `					      DMA_TO_DEVICE);`
  Review: Low-risk line; verify in surrounding control flow.
- L01487 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01488 [NONE] `	msg->cqe.done = send_done;`
  Review: Low-risk line; verify in surrounding control flow.
- L01489 [NONE] `	msg->wr.opcode = IB_WR_SEND;`
  Review: Low-risk line; verify in surrounding control flow.
- L01490 [NONE] `	msg->wr.sg_list = &msg->sge[0];`
  Review: Low-risk line; verify in surrounding control flow.
- L01491 [NONE] `	msg->wr.num_sge = msg->num_sge;`
  Review: Low-risk line; verify in surrounding control flow.
- L01492 [NONE] `	msg->wr.next = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01493 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01494 [NONE] `	if (send_ctx) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01495 [NONE] `		msg->wr.wr_cqe = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01496 [NONE] `		msg->wr.send_flags = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01497 [NONE] `		if (!list_empty(&send_ctx->msg_list)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01498 [NONE] `			struct smb_direct_sendmsg *last;`
  Review: Low-risk line; verify in surrounding control flow.
- L01499 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01500 [NONE] `			last = list_last_entry(&send_ctx->msg_list,`
  Review: Low-risk line; verify in surrounding control flow.
- L01501 [NONE] `					       struct smb_direct_sendmsg,`
  Review: Low-risk line; verify in surrounding control flow.
- L01502 [NONE] `					       list);`
  Review: Low-risk line; verify in surrounding control flow.
- L01503 [NONE] `			last->wr.next = &msg->wr;`
  Review: Low-risk line; verify in surrounding control flow.
- L01504 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01505 [NONE] `		list_add_tail(&msg->list, &send_ctx->msg_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L01506 [NONE] `		send_ctx->wr_cnt++;`
  Review: Low-risk line; verify in surrounding control flow.
- L01507 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01508 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01509 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01510 [NONE] `	msg->wr.wr_cqe = &msg->cqe;`
  Review: Low-risk line; verify in surrounding control flow.
- L01511 [NONE] `	msg->wr.send_flags = IB_SEND_SIGNALED;`
  Review: Low-risk line; verify in surrounding control flow.
- L01512 [NONE] `	return smb_direct_post_send(t, &msg->wr);`
  Review: Low-risk line; verify in surrounding control flow.
- L01513 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01514 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01515 [NONE] `static int smb_direct_post_send_data(struct smb_direct_transport *t,`
  Review: Low-risk line; verify in surrounding control flow.
- L01516 [NONE] `				     struct smb_direct_send_ctx *send_ctx,`
  Review: Low-risk line; verify in surrounding control flow.
- L01517 [NONE] `				     struct kvec *iov, int niov,`
  Review: Low-risk line; verify in surrounding control flow.
- L01518 [NONE] `				     int remaining_data_length)`
  Review: Low-risk line; verify in surrounding control flow.
- L01519 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01520 [NONE] `	int i, j, ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01521 [NONE] `	struct smb_direct_sendmsg *msg;`
  Review: Low-risk line; verify in surrounding control flow.
- L01522 [NONE] `	int data_length;`
  Review: Low-risk line; verify in surrounding control flow.
- L01523 [NONE] `	struct scatterlist sg[SMB_DIRECT_MAX_SEND_SGES - 1];`
  Review: Low-risk line; verify in surrounding control flow.
- L01524 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01525 [NONE] `	ret = wait_for_send_credits(t, send_ctx);`
  Review: Low-risk line; verify in surrounding control flow.
- L01526 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L01527 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01528 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01529 [NONE] `	data_length = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01530 [NONE] `	for (i = 0; i < niov; i++)`
  Review: Low-risk line; verify in surrounding control flow.
- L01531 [NONE] `		data_length += iov[i].iov_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01532 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01533 [NONE] `	ret = smb_direct_create_header(t, data_length, remaining_data_length,`
  Review: Low-risk line; verify in surrounding control flow.
- L01534 [NONE] `				       &msg);`
  Review: Low-risk line; verify in surrounding control flow.
- L01535 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01536 [LIFETIME|] `		atomic_inc(&t->send_credits);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01537 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01538 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01539 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01540 [NONE] `	for (i = 0; i < niov; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01541 [NONE] `		struct ib_sge *sge;`
  Review: Low-risk line; verify in surrounding control flow.
- L01542 [NONE] `		int sg_cnt;`
  Review: Low-risk line; verify in surrounding control flow.
- L01543 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01544 [NONE] `		sg_init_table(sg, SMB_DIRECT_MAX_SEND_SGES - 1);`
  Review: Low-risk line; verify in surrounding control flow.
- L01545 [NONE] `		sg_cnt = get_mapped_sg_list(t->cm_id->device,`
  Review: Low-risk line; verify in surrounding control flow.
- L01546 [NONE] `					    iov[i].iov_base, iov[i].iov_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01547 [NONE] `					    sg, SMB_DIRECT_MAX_SEND_SGES - 1,`
  Review: Low-risk line; verify in surrounding control flow.
- L01548 [NONE] `					    DMA_TO_DEVICE);`
  Review: Low-risk line; verify in surrounding control flow.
- L01549 [NONE] `		if (sg_cnt <= 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01550 [ERROR_PATH|] `			pr_err("failed to map buffer\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01551 [NONE] `			ret = -ENOMEM;`
  Review: Low-risk line; verify in surrounding control flow.
- L01552 [ERROR_PATH|] `			goto err;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01553 [NONE] `		} else if (sg_cnt + msg->num_sge > SMB_DIRECT_MAX_SEND_SGES) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01554 [ERROR_PATH|] `			pr_err("buffer not fitted into sges\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01555 [NONE] `			ret = -E2BIG;`
  Review: Low-risk line; verify in surrounding control flow.
- L01556 [NONE] `			ib_dma_unmap_sg(t->cm_id->device, sg, sg_cnt,`
  Review: Low-risk line; verify in surrounding control flow.
- L01557 [NONE] `					DMA_TO_DEVICE);`
  Review: Low-risk line; verify in surrounding control flow.
- L01558 [ERROR_PATH|] `			goto err;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01559 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01560 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01561 [NONE] `		for (j = 0; j < sg_cnt; j++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01562 [NONE] `			sge = &msg->sge[msg->num_sge];`
  Review: Low-risk line; verify in surrounding control flow.
- L01563 [NONE] `			sge->addr = sg_dma_address(&sg[j]);`
  Review: Low-risk line; verify in surrounding control flow.
- L01564 [NONE] `			sge->length = sg_dma_len(&sg[j]);`
  Review: Low-risk line; verify in surrounding control flow.
- L01565 [NONE] `			sge->lkey  = t->pd->local_dma_lkey;`
  Review: Low-risk line; verify in surrounding control flow.
- L01566 [NONE] `			msg->num_sge++;`
  Review: Low-risk line; verify in surrounding control flow.
- L01567 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01568 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01569 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01570 [NONE] `	ret = post_sendmsg(t, send_ctx, msg);`
  Review: Low-risk line; verify in surrounding control flow.
- L01571 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L01572 [ERROR_PATH|] `		goto err;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01573 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01574 [NONE] `err:`
  Review: Low-risk line; verify in surrounding control flow.
- L01575 [NONE] `	smb_direct_free_sendmsg(t, msg);`
  Review: Low-risk line; verify in surrounding control flow.
- L01576 [LIFETIME|] `	atomic_inc(&t->send_credits);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01577 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01578 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01579 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01580 [NONE] `static int smb_direct_writev(struct ksmbd_transport *t,`
  Review: Low-risk line; verify in surrounding control flow.
- L01581 [NONE] `			     struct kvec *iov, int niovs, int buflen,`
  Review: Low-risk line; verify in surrounding control flow.
- L01582 [NONE] `			     bool need_invalidate, unsigned int remote_key)`
  Review: Low-risk line; verify in surrounding control flow.
- L01583 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01584 [NONE] `	struct smb_direct_transport *st = smb_trans_direct_transfort(t);`
  Review: Low-risk line; verify in surrounding control flow.
- L01585 [NONE] `	size_t remaining_data_length;`
  Review: Low-risk line; verify in surrounding control flow.
- L01586 [NONE] `	size_t iov_idx;`
  Review: Low-risk line; verify in surrounding control flow.
- L01587 [NONE] `	size_t iov_ofs;`
  Review: Low-risk line; verify in surrounding control flow.
- L01588 [NONE] `	size_t max_iov_size = st->max_send_size -`
  Review: Low-risk line; verify in surrounding control flow.
- L01589 [NONE] `			sizeof(struct smb_direct_data_transfer);`
  Review: Low-risk line; verify in surrounding control flow.
- L01590 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01591 [NONE] `	struct smb_direct_send_ctx send_ctx;`
  Review: Low-risk line; verify in surrounding control flow.
- L01592 [NONE] `	int error = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01593 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01594 [NONE] `	if (st->status != SMB_DIRECT_CS_CONNECTED)`
  Review: Low-risk line; verify in surrounding control flow.
- L01595 [ERROR_PATH|] `		return -ENOTCONN;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01596 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01597 [NONE] `	//FIXME: skip RFC1002 header..`
  Review: Low-risk line; verify in surrounding control flow.
- L01598 [NONE] `	if (WARN_ON_ONCE(niovs <= 1 || iov[0].iov_len != 4))`
  Review: Low-risk line; verify in surrounding control flow.
- L01599 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01600 [NONE] `	buflen -= 4;`
  Review: Low-risk line; verify in surrounding control flow.
- L01601 [NONE] `	iov_idx = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L01602 [NONE] `	iov_ofs = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01603 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01604 [NONE] `	remaining_data_length = buflen;`
  Review: Low-risk line; verify in surrounding control flow.
- L01605 [NONE] `	ksmbd_debug(RDMA, "Sending smb (RDMA): smb_len=%u\n", buflen);`
  Review: Low-risk line; verify in surrounding control flow.
- L01606 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01607 [NONE] `	smb_direct_send_ctx_init(st, &send_ctx, need_invalidate, remote_key);`
  Review: Low-risk line; verify in surrounding control flow.
- L01608 [NONE] `	while (remaining_data_length) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01609 [NONE] `		struct kvec vecs[SMB_DIRECT_MAX_SEND_SGES - 1]; /* minus smbdirect hdr */`
  Review: Low-risk line; verify in surrounding control flow.
- L01610 [NONE] `		size_t possible_bytes = max_iov_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L01611 [NONE] `		size_t possible_vecs;`
  Review: Low-risk line; verify in surrounding control flow.
- L01612 [NONE] `		size_t bytes = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01613 [NONE] `		size_t nvecs = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01614 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01615 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01616 [NONE] `		 * For the last message remaining_data_length should be`
  Review: Low-risk line; verify in surrounding control flow.
- L01617 [NONE] `		 * have been 0 already!`
  Review: Low-risk line; verify in surrounding control flow.
- L01618 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01619 [NONE] `		if (WARN_ON_ONCE(iov_idx >= niovs)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01620 [NONE] `			error = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01621 [ERROR_PATH|] `			goto done;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01622 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01623 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01624 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01625 [NONE] `		 * We have 2 factors which limit the arguments we pass`
  Review: Low-risk line; verify in surrounding control flow.
- L01626 [NONE] `		 * to smb_direct_post_send_data():`
  Review: Low-risk line; verify in surrounding control flow.
- L01627 [NONE] `		 *`
  Review: Low-risk line; verify in surrounding control flow.
- L01628 [NONE] `		 * 1. The number of supported sges for the send,`
  Review: Low-risk line; verify in surrounding control flow.
- L01629 [NONE] `		 *    while one is reserved for the smbdirect header.`
  Review: Low-risk line; verify in surrounding control flow.
- L01630 [NONE] `		 *    And we currently need one SGE per page.`
  Review: Low-risk line; verify in surrounding control flow.
- L01631 [NONE] `		 * 2. The number of negotiated payload bytes per send.`
  Review: Low-risk line; verify in surrounding control flow.
- L01632 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01633 [NONE] `		possible_vecs = min_t(size_t, ARRAY_SIZE(vecs), niovs - iov_idx);`
  Review: Low-risk line; verify in surrounding control flow.
- L01634 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01635 [NONE] `		while (iov_idx < niovs && possible_vecs && possible_bytes) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01636 [NONE] `			struct kvec *v = &vecs[nvecs];`
  Review: Low-risk line; verify in surrounding control flow.
- L01637 [NONE] `			int page_count;`
  Review: Low-risk line; verify in surrounding control flow.
- L01638 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01639 [NONE] `			v->iov_base = ((u8 *)iov[iov_idx].iov_base) + iov_ofs;`
  Review: Low-risk line; verify in surrounding control flow.
- L01640 [NONE] `			v->iov_len = min_t(size_t,`
  Review: Low-risk line; verify in surrounding control flow.
- L01641 [NONE] `					   iov[iov_idx].iov_len - iov_ofs,`
  Review: Low-risk line; verify in surrounding control flow.
- L01642 [NONE] `					   possible_bytes);`
  Review: Low-risk line; verify in surrounding control flow.
- L01643 [NONE] `			page_count = get_buf_page_count(v->iov_base, v->iov_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01644 [NONE] `			if (page_count > possible_vecs) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01645 [NONE] `				/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01646 [NONE] `				 * If the number of pages in the buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L01647 [NONE] `				 * is to much (because we currently require`
  Review: Low-risk line; verify in surrounding control flow.
- L01648 [NONE] `				 * one SGE per page), we need to limit the`
  Review: Low-risk line; verify in surrounding control flow.
- L01649 [NONE] `				 * length.`
  Review: Low-risk line; verify in surrounding control flow.
- L01650 [NONE] `				 *`
  Review: Low-risk line; verify in surrounding control flow.
- L01651 [NONE] `				 * We know possible_vecs is at least 1,`
  Review: Low-risk line; verify in surrounding control flow.
- L01652 [NONE] `				 * so we always keep the first page.`
  Review: Low-risk line; verify in surrounding control flow.
- L01653 [NONE] `				 *`
  Review: Low-risk line; verify in surrounding control flow.
- L01654 [NONE] `				 * We need to calculate the number extra`
  Review: Low-risk line; verify in surrounding control flow.
- L01655 [NONE] `				 * pages (epages) we can also keep.`
  Review: Low-risk line; verify in surrounding control flow.
- L01656 [NONE] `				 *`
  Review: Low-risk line; verify in surrounding control flow.
- L01657 [NONE] `				 * We calculate the number of bytes in the`
  Review: Low-risk line; verify in surrounding control flow.
- L01658 [NONE] `				 * first page (fplen), this should never be`
  Review: Low-risk line; verify in surrounding control flow.
- L01659 [NONE] `				 * larger than v->iov_len because page_count is`
  Review: Low-risk line; verify in surrounding control flow.
- L01660 [NONE] `				 * at least 2, but adding a limitation feels`
  Review: Low-risk line; verify in surrounding control flow.
- L01661 [NONE] `				 * better.`
  Review: Low-risk line; verify in surrounding control flow.
- L01662 [NONE] `				 *`
  Review: Low-risk line; verify in surrounding control flow.
- L01663 [NONE] `				 * Then we calculate the number of bytes (elen)`
  Review: Low-risk line; verify in surrounding control flow.
- L01664 [NONE] `				 * we can keep for the extra pages.`
  Review: Low-risk line; verify in surrounding control flow.
- L01665 [NONE] `				 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01666 [NONE] `				size_t epages = possible_vecs - 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L01667 [NONE] `				size_t fpofs = offset_in_page(v->iov_base);`
  Review: Low-risk line; verify in surrounding control flow.
- L01668 [NONE] `				size_t fplen = min_t(size_t, PAGE_SIZE - fpofs, v->iov_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01669 [NONE] `				size_t elen = min_t(size_t, v->iov_len - fplen, epages*PAGE_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L01670 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01671 [NONE] `				v->iov_len = fplen + elen;`
  Review: Low-risk line; verify in surrounding control flow.
- L01672 [NONE] `				page_count = get_buf_page_count(v->iov_base, v->iov_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01673 [NONE] `				if (WARN_ON_ONCE(page_count > possible_vecs)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01674 [NONE] `					/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01675 [NONE] `					 * Something went wrong in the above`
  Review: Low-risk line; verify in surrounding control flow.
- L01676 [NONE] `					 * logic...`
  Review: Low-risk line; verify in surrounding control flow.
- L01677 [NONE] `					 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01678 [NONE] `					error = -EINVAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01679 [ERROR_PATH|] `					goto done;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01680 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L01681 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01682 [NONE] `			possible_vecs -= page_count;`
  Review: Low-risk line; verify in surrounding control flow.
- L01683 [NONE] `			nvecs += 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L01684 [NONE] `			possible_bytes -= v->iov_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01685 [NONE] `			bytes += v->iov_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01686 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01687 [NONE] `			iov_ofs += v->iov_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01688 [NONE] `			if (iov_ofs >= iov[iov_idx].iov_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01689 [NONE] `				iov_idx += 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L01690 [NONE] `				iov_ofs = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01691 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01692 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01693 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01694 [NONE] `		remaining_data_length -= bytes;`
  Review: Low-risk line; verify in surrounding control flow.
- L01695 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01696 [NONE] `		ret = smb_direct_post_send_data(st, &send_ctx,`
  Review: Low-risk line; verify in surrounding control flow.
- L01697 [NONE] `						vecs, nvecs,`
  Review: Low-risk line; verify in surrounding control flow.
- L01698 [NONE] `						remaining_data_length);`
  Review: Low-risk line; verify in surrounding control flow.
- L01699 [NONE] `		if (unlikely(ret)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01700 [NONE] `			error = ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01701 [ERROR_PATH|] `			goto done;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01702 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01703 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01704 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01705 [NONE] `done:`
  Review: Low-risk line; verify in surrounding control flow.
- L01706 [NONE] `	ret = smb_direct_flush_send_list(st, &send_ctx, true);`
  Review: Low-risk line; verify in surrounding control flow.
- L01707 [NONE] `	if (unlikely(!ret && error))`
  Review: Low-risk line; verify in surrounding control flow.
- L01708 [NONE] `		ret = error;`
  Review: Low-risk line; verify in surrounding control flow.
- L01709 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01710 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01711 [NONE] `	 * As an optimization, we don't wait for individual I/O to finish`
  Review: Low-risk line; verify in surrounding control flow.
- L01712 [NONE] `	 * before sending the next one.`
  Review: Low-risk line; verify in surrounding control flow.
- L01713 [NONE] `	 * Send them all and wait for pending send count to get to 0`
  Review: Low-risk line; verify in surrounding control flow.
- L01714 [NONE] `	 * that means all the I/Os have been out and we are good to return`
  Review: Low-risk line; verify in surrounding control flow.
- L01715 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01716 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01717 [NONE] `	error = smb_direct_wait_send_pending(st, __func__);`
  Review: Low-risk line; verify in surrounding control flow.
- L01718 [NONE] `	if (!ret && error)`
  Review: Low-risk line; verify in surrounding control flow.
- L01719 [NONE] `		ret = error;`
  Review: Low-risk line; verify in surrounding control flow.
- L01720 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01721 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01722 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01723 [NONE] `static void smb_direct_free_rdma_rw_msg(struct smb_direct_transport *t,`
  Review: Low-risk line; verify in surrounding control flow.
- L01724 [NONE] `					struct smb_direct_rdma_rw_msg *msg,`
  Review: Low-risk line; verify in surrounding control flow.
- L01725 [NONE] `					enum dma_data_direction dir)`
  Review: Low-risk line; verify in surrounding control flow.
- L01726 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01727 [NONE] `	rdma_rw_ctx_destroy(&msg->rw_ctx, t->qp, t->qp->port,`
  Review: Low-risk line; verify in surrounding control flow.
- L01728 [NONE] `			    msg->sgt.sgl, msg->sgt.nents, dir);`
  Review: Low-risk line; verify in surrounding control flow.
- L01729 [NONE] `	sg_free_table_chained(&msg->sgt, SG_CHUNK_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L01730 [NONE] `	kfree(msg);`
  Review: Low-risk line; verify in surrounding control flow.
- L01731 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01732 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01733 [NONE] `static void read_write_done(struct ib_cq *cq, struct ib_wc *wc,`
  Review: Low-risk line; verify in surrounding control flow.
- L01734 [NONE] `			    enum dma_data_direction dir)`
  Review: Low-risk line; verify in surrounding control flow.
- L01735 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01736 [NONE] `	struct smb_direct_rdma_rw_msg *msg = container_of(wc->wr_cqe,`
  Review: Low-risk line; verify in surrounding control flow.
- L01737 [NONE] `							  struct smb_direct_rdma_rw_msg, cqe);`
  Review: Low-risk line; verify in surrounding control flow.
- L01738 [NONE] `	struct smb_direct_transport *t = msg->t;`
  Review: Low-risk line; verify in surrounding control flow.
- L01739 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01740 [NONE] `	if (wc->status != IB_WC_SUCCESS) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01741 [NONE] `		msg->status = -EIO;`
  Review: Low-risk line; verify in surrounding control flow.
- L01742 [ERROR_PATH|] `		pr_err("read/write error. opcode = %d, status = %s(%d)\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01743 [NONE] `		       wc->opcode, ib_wc_status_msg(wc->status), wc->status);`
  Review: Low-risk line; verify in surrounding control flow.
- L01744 [NONE] `		if (wc->status != IB_WC_WR_FLUSH_ERR)`
  Review: Low-risk line; verify in surrounding control flow.
- L01745 [NONE] `			smb_direct_disconnect_rdma_connection(t);`
  Review: Low-risk line; verify in surrounding control flow.
- L01746 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01747 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01748 [NONE] `	complete(msg->completion);`
  Review: Low-risk line; verify in surrounding control flow.
- L01749 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01750 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01751 [NONE] `static void read_done(struct ib_cq *cq, struct ib_wc *wc)`
  Review: Low-risk line; verify in surrounding control flow.
- L01752 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01753 [NONE] `	read_write_done(cq, wc, DMA_FROM_DEVICE);`
  Review: Low-risk line; verify in surrounding control flow.
- L01754 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01755 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01756 [NONE] `static void write_done(struct ib_cq *cq, struct ib_wc *wc)`
  Review: Low-risk line; verify in surrounding control flow.
- L01757 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01758 [NONE] `	read_write_done(cq, wc, DMA_TO_DEVICE);`
  Review: Low-risk line; verify in surrounding control flow.
- L01759 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01760 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01761 [NONE] `static int smb_direct_rdma_xmit(struct smb_direct_transport *t,`
  Review: Low-risk line; verify in surrounding control flow.
- L01762 [NONE] `				void *buf, int buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01763 [NONE] `				struct smb2_buffer_desc_v1 *desc,`
  Review: Low-risk line; verify in surrounding control flow.
- L01764 [NONE] `				unsigned int desc_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01765 [NONE] `				bool is_read)`
  Review: Low-risk line; verify in surrounding control flow.
- L01766 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01767 [NONE] `	struct smb_direct_rdma_rw_msg *msg, *next_msg;`
  Review: Low-risk line; verify in surrounding control flow.
- L01768 [NONE] `	int i, ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01769 [NONE] `	DECLARE_COMPLETION_ONSTACK(completion);`
  Review: Low-risk line; verify in surrounding control flow.
- L01770 [NONE] `	struct ib_send_wr *first_wr;`
  Review: Low-risk line; verify in surrounding control flow.
- L01771 [NONE] `	LIST_HEAD(msg_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L01772 [NONE] `	char *desc_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L01773 [NONE] `	int credits_needed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01774 [NONE] `	unsigned int desc_buf_len, desc_num = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01775 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01776 [NONE] `	if (t->status != SMB_DIRECT_CS_CONNECTED)`
  Review: Low-risk line; verify in surrounding control flow.
- L01777 [ERROR_PATH|] `		return -ENOTCONN;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01778 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01779 [NONE] `	if (buf_len > t->max_rdma_rw_size)`
  Review: Low-risk line; verify in surrounding control flow.
- L01780 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01781 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01782 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01783 [NONE] `	 * J.4 (BUG-R01 / BUG-R02): RDMA transform enforcement check.`
  Review: Low-risk line; verify in surrounding control flow.
- L01784 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L01785 [NONE] `	 * MS-SMB2 §2.2.43 and §3.3.5.2 require that when RDMA encryption or`
  Review: Low-risk line; verify in surrounding control flow.
- L01786 [NONE] `	 * signing transforms are negotiated, the server MUST apply the`
  Review: Low-risk line; verify in surrounding control flow.
- L01787 [NONE] `	 * negotiated transform to all RDMA read/write data.`
  Review: Low-risk line; verify in surrounding control flow.
- L01788 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L01789 [NONE] `	 * Currently ksmbd does NOT implement the RDMA Transform Header`
  Review: Low-risk line; verify in surrounding control flow.
- L01790 [PROTO_GATE|] `	 * (ProtocolId 0xFB534D42, MS-SMB2 §2.2.43).`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01791 [NONE] `	 * ksmbd_rdma_transform_supported() is exported but has no callers;`
  Review: Low-risk line; verify in surrounding control flow.
- L01792 [NONE] `	 * conn->rdma_transform_ids[] is populated at negotiate time but the`
  Review: Low-risk line; verify in surrounding control flow.
- L01793 [NONE] `	 * transforms are never applied to RDMA payloads.`
  Review: Low-risk line; verify in surrounding control flow.
- L01794 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L01795 [NONE] `	 * This is a silent security regression: clients that negotiate`
  Review: Low-risk line; verify in surrounding control flow.
- L01796 [PROTO_GATE|] `	 * SMB2_RDMA_TRANSFORM_ENCRYPTION believe their data is protected`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01797 [NONE] `	 * but the server transmits it in plaintext over the RDMA fabric.`
  Review: Low-risk line; verify in surrounding control flow.
- L01798 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L01799 [NONE] `	 * A full fix requires:`
  Review: Low-risk line; verify in surrounding control flow.
- L01800 [PROTO_GATE|] `	 *   1. Defining struct smb2_rdma_transform_hdr (ProtocolId 0xFB534D42).`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01801 [NONE] `	 *   2. Wrapping buf in the RDMA Transform Header before posting.`
  Review: Low-risk line; verify in surrounding control flow.
- L01802 [NONE] `	 *   3. Applying SMB2 encryption (ENCRYPTION) or HMAC-SHA256/AES-CMAC`
  Review: Low-risk line; verify in surrounding control flow.
- L01803 [NONE] `	 *      (SIGNING) over the payload.`
  Review: Low-risk line; verify in surrounding control flow.
- L01804 [NONE] `	 *   4. For reads: verifying and stripping the transform on receipt.`
  Review: Low-risk line; verify in surrounding control flow.
- L01805 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L01806 [NONE] `	 * Until the full implementation is in place, emit a rate-limited`
  Review: Low-risk line; verify in surrounding control flow.
- L01807 [NONE] `	 * warning.  ksmbd_rdma_transform_supported() is called here so the`
  Review: Low-risk line; verify in surrounding control flow.
- L01808 [NONE] `	 * function is exercised and callers can be added incrementally.`
  Review: Low-risk line; verify in surrounding control flow.
- L01809 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01810 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L01811 [NONE] `		struct ksmbd_conn *conn = KSMBD_TRANS(t)->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L01812 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01813 [NONE] `		if (ksmbd_rdma_transform_supported(conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L01814 [PROTO_GATE|] `					SMB2_RDMA_TRANSFORM_ENCRYPTION)) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01815 [ERROR_PATH|] `			pr_warn_ratelimited("ksmbd: RDMA encryption transform negotiated but not applied — data sent plaintext (BUG-R01)\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01816 [NONE] `		} else if (ksmbd_rdma_transform_supported(conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L01817 [PROTO_GATE|] `					SMB2_RDMA_TRANSFORM_SIGNING)) {`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L01818 [ERROR_PATH|] `			pr_warn_ratelimited("ksmbd: RDMA signing transform negotiated but not applied — data sent unsigned (BUG-R01)\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01819 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01820 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01821 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01822 [NONE] `	/* calculate needed credits */`
  Review: Low-risk line; verify in surrounding control flow.
- L01823 [NONE] `	credits_needed = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01824 [NONE] `	desc_buf = buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L01825 [NONE] `	for (i = 0; i < desc_len / sizeof(*desc); i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01826 [NONE] `		if (!buf_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L01827 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01828 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01829 [NONE] `		desc_buf_len = le32_to_cpu(desc[i].length);`
  Review: Low-risk line; verify in surrounding control flow.
- L01830 [NONE] `		if (!desc_buf_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L01831 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01832 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01833 [NONE] `		if (desc_buf_len > buf_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01834 [NONE] `			desc_buf_len = buf_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01835 [NONE] `			desc[i].length = cpu_to_le32(desc_buf_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01836 [NONE] `			buf_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01837 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01838 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01839 [NONE] `		credits_needed += calc_rw_credits(t, desc_buf, desc_buf_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01840 [NONE] `		desc_buf += desc_buf_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01841 [NONE] `		buf_len -= desc_buf_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01842 [NONE] `		desc_num++;`
  Review: Low-risk line; verify in surrounding control flow.
- L01843 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01844 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01845 [NONE] `	ksmbd_debug(RDMA, "RDMA %s, len %#x, needed credits %#x\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L01846 [NONE] `		    is_read ? "read" : "write", buf_len, credits_needed);`
  Review: Low-risk line; verify in surrounding control flow.
- L01847 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01848 [NONE] `	ret = wait_for_rw_credits(t, credits_needed);`
  Review: Low-risk line; verify in surrounding control flow.
- L01849 [NONE] `	if (ret < 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01850 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01851 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01852 [NONE] `	/* build rdma_rw_ctx for each descriptor */`
  Review: Low-risk line; verify in surrounding control flow.
- L01853 [NONE] `	desc_buf = buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L01854 [NONE] `	for (i = 0; i < desc_num; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01855 [MEM_BOUNDS|] `		msg = kzalloc(struct_size(msg, sg_list, SG_CHUNK_SIZE),`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01856 [NONE] `			      KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L01857 [NONE] `		if (!msg) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01858 [NONE] `			ret = -ENOMEM;`
  Review: Low-risk line; verify in surrounding control flow.
- L01859 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01860 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01861 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01862 [NONE] `		desc_buf_len = le32_to_cpu(desc[i].length);`
  Review: Low-risk line; verify in surrounding control flow.
- L01863 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01864 [NONE] `		msg->t = t;`
  Review: Low-risk line; verify in surrounding control flow.
- L01865 [NONE] `		msg->cqe.done = is_read ? read_done : write_done;`
  Review: Low-risk line; verify in surrounding control flow.
- L01866 [NONE] `		msg->completion = &completion;`
  Review: Low-risk line; verify in surrounding control flow.
- L01867 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01868 [NONE] `		msg->sgt.sgl = &msg->sg_list[0];`
  Review: Low-risk line; verify in surrounding control flow.
- L01869 [NONE] `		ret = sg_alloc_table_chained(&msg->sgt,`
  Review: Low-risk line; verify in surrounding control flow.
- L01870 [NONE] `					     get_buf_page_count(desc_buf, desc_buf_len),`
  Review: Low-risk line; verify in surrounding control flow.
- L01871 [NONE] `					     msg->sg_list, SG_CHUNK_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L01872 [NONE] `		if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01873 [NONE] `			kfree(msg);`
  Review: Low-risk line; verify in surrounding control flow.
- L01874 [NONE] `			ret = -ENOMEM;`
  Review: Low-risk line; verify in surrounding control flow.
- L01875 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01876 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01877 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01878 [NONE] `		ret = get_sg_list(desc_buf, desc_buf_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01879 [NONE] `				  msg->sgt.sgl, msg->sgt.orig_nents);`
  Review: Low-risk line; verify in surrounding control flow.
- L01880 [NONE] `		if (ret < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01881 [NONE] `			sg_free_table_chained(&msg->sgt, SG_CHUNK_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L01882 [NONE] `			kfree(msg);`
  Review: Low-risk line; verify in surrounding control flow.
- L01883 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01884 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01885 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01886 [NONE] `		ret = rdma_rw_ctx_init(&msg->rw_ctx, t->qp, t->qp->port,`
  Review: Low-risk line; verify in surrounding control flow.
- L01887 [NONE] `				       msg->sgt.sgl,`
  Review: Low-risk line; verify in surrounding control flow.
- L01888 [NONE] `				       get_buf_page_count(desc_buf, desc_buf_len),`
  Review: Low-risk line; verify in surrounding control flow.
- L01889 [NONE] `				       0,`
  Review: Low-risk line; verify in surrounding control flow.
- L01890 [NONE] `				       le64_to_cpu(desc[i].offset),`
  Review: Low-risk line; verify in surrounding control flow.
- L01891 [NONE] `				       le32_to_cpu(desc[i].token),`
  Review: Low-risk line; verify in surrounding control flow.
- L01892 [NONE] `				       is_read ? DMA_FROM_DEVICE : DMA_TO_DEVICE);`
  Review: Low-risk line; verify in surrounding control flow.
- L01893 [NONE] `		if (ret < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01894 [ERROR_PATH|] `			pr_err("failed to init rdma_rw_ctx: %d\n", ret);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01895 [NONE] `			sg_free_table_chained(&msg->sgt, SG_CHUNK_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L01896 [NONE] `			kfree(msg);`
  Review: Low-risk line; verify in surrounding control flow.
- L01897 [ERROR_PATH|] `			goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01898 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01899 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01900 [NONE] `		list_add_tail(&msg->list, &msg_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L01901 [NONE] `		desc_buf += desc_buf_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01902 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01903 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01904 [NONE] `	/* concatenate work requests of rdma_rw_ctxs */`
  Review: Low-risk line; verify in surrounding control flow.
- L01905 [NONE] `	first_wr = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01906 [NONE] `	list_for_each_entry_reverse(msg, &msg_list, list) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01907 [NONE] `		first_wr = rdma_rw_ctx_wrs(&msg->rw_ctx, t->qp, t->qp->port,`
  Review: Low-risk line; verify in surrounding control flow.
- L01908 [NONE] `					   &msg->cqe, first_wr);`
  Review: Low-risk line; verify in surrounding control flow.
- L01909 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01910 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01911 [NONE] `	ret = ib_post_send(t->qp, first_wr, NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L01912 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01913 [ERROR_PATH|] `		pr_err("failed to post send wr for RDMA R/W: %d\n", ret);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01914 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01915 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01916 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01917 [NONE] `	msg = list_last_entry(&msg_list, struct smb_direct_rdma_rw_msg, list);`
  Review: Low-risk line; verify in surrounding control flow.
- L01918 [NONE] `	if (!wait_for_completion_timeout(&completion,`
  Review: Low-risk line; verify in surrounding control flow.
- L01919 [NONE] `					 SMB_DIRECT_NEGOTIATE_TIMEOUT * HZ)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01920 [ERROR_PATH|] `		pr_err_ratelimited("timeout waiting for RDMA %s completion\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01921 [NONE] `				   is_read ? "read" : "write");`
  Review: Low-risk line; verify in surrounding control flow.
- L01922 [NONE] `		smb_direct_disconnect_rdma_connection(t);`
  Review: Low-risk line; verify in surrounding control flow.
- L01923 [NONE] `		ret = -ETIMEDOUT;`
  Review: Low-risk line; verify in surrounding control flow.
- L01924 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01925 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01926 [NONE] `	ret = msg->status;`
  Review: Low-risk line; verify in surrounding control flow.
- L01927 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L01928 [NONE] `	list_for_each_entry_safe(msg, next_msg, &msg_list, list) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01929 [NONE] `		list_del(&msg->list);`
  Review: Low-risk line; verify in surrounding control flow.
- L01930 [NONE] `		smb_direct_free_rdma_rw_msg(t, msg,`
  Review: Low-risk line; verify in surrounding control flow.
- L01931 [NONE] `					    is_read ? DMA_FROM_DEVICE : DMA_TO_DEVICE);`
  Review: Low-risk line; verify in surrounding control flow.
- L01932 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01933 [LIFETIME|] `	atomic_add(credits_needed, &t->rw_credits);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01934 [NONE] `	wake_up(&t->wait_rw_credits);`
  Review: Low-risk line; verify in surrounding control flow.
- L01935 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01936 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01937 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01938 [NONE] `static int smb_direct_rdma_write(struct ksmbd_transport *t,`
  Review: Low-risk line; verify in surrounding control flow.
- L01939 [NONE] `				 void *buf, unsigned int buflen,`
  Review: Low-risk line; verify in surrounding control flow.
- L01940 [NONE] `				 struct smb2_buffer_desc_v1 *desc,`
  Review: Low-risk line; verify in surrounding control flow.
- L01941 [NONE] `				 unsigned int desc_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L01942 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01943 [NONE] `	return smb_direct_rdma_xmit(smb_trans_direct_transfort(t), buf, buflen,`
  Review: Low-risk line; verify in surrounding control flow.
- L01944 [NONE] `				    desc, desc_len, false);`
  Review: Low-risk line; verify in surrounding control flow.
- L01945 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01946 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01947 [NONE] `static int smb_direct_rdma_read(struct ksmbd_transport *t,`
  Review: Low-risk line; verify in surrounding control flow.
- L01948 [NONE] `				void *buf, unsigned int buflen,`
  Review: Low-risk line; verify in surrounding control flow.
- L01949 [NONE] `				struct smb2_buffer_desc_v1 *desc,`
  Review: Low-risk line; verify in surrounding control flow.
- L01950 [NONE] `				unsigned int desc_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L01951 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01952 [NONE] `	return smb_direct_rdma_xmit(smb_trans_direct_transfort(t), buf, buflen,`
  Review: Low-risk line; verify in surrounding control flow.
- L01953 [NONE] `				    desc, desc_len, true);`
  Review: Low-risk line; verify in surrounding control flow.
- L01954 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01955 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01956 [NONE] `static void smb_direct_disconnect(struct ksmbd_transport *t)`
  Review: Low-risk line; verify in surrounding control flow.
- L01957 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01958 [NONE] `	struct smb_direct_transport *st = smb_trans_direct_transfort(t);`
  Review: Low-risk line; verify in surrounding control flow.
- L01959 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01960 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01961 [NONE] `	ksmbd_debug(RDMA, "Disconnecting cm_id=%p\n", st->cm_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L01962 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01963 [NONE] `	smb_direct_disconnect_rdma_work(&st->disconnect_work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01964 [WAIT_LOOP|] `	ret = wait_event_interruptible_timeout(st->wait_status,`
  Review: Bounded wait and cancellation path must be guaranteed.
- L01965 [NONE] `					       st->status == SMB_DIRECT_CS_DISCONNECTED,`
  Review: Low-risk line; verify in surrounding control flow.
- L01966 [NONE] `					       SMB_DIRECT_NEGOTIATE_TIMEOUT * HZ);`
  Review: Low-risk line; verify in surrounding control flow.
- L01967 [NONE] `	if (!ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L01968 [ERROR_PATH|] `		pr_err_ratelimited("timeout waiting for RDMA disconnect (status=%d)\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01969 [NONE] `				   st->status);`
  Review: Low-risk line; verify in surrounding control flow.
- L01970 [NONE] `	free_transport(st);`
  Review: Low-risk line; verify in surrounding control flow.
- L01971 [NONE] `	if (server_conf.max_connections)`
  Review: Low-risk line; verify in surrounding control flow.
- L01972 [LIFETIME|] `		atomic_dec(&smbd_active_conn);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L01973 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01974 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01975 [NONE] `static void smb_direct_shutdown(struct ksmbd_transport *t)`
  Review: Low-risk line; verify in surrounding control flow.
- L01976 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01977 [NONE] `	struct smb_direct_transport *st = smb_trans_direct_transfort(t);`
  Review: Low-risk line; verify in surrounding control flow.
- L01978 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01979 [NONE] `	ksmbd_debug(RDMA, "smb-direct shutdown cm_id=%p\n", st->cm_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L01980 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01981 [NONE] `	smb_direct_disconnect_rdma_work(&st->disconnect_work);`
  Review: Low-risk line; verify in surrounding control flow.
- L01982 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01983 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01984 [NONE] `static int smb_direct_cm_handler(struct rdma_cm_id *cm_id,`
  Review: Low-risk line; verify in surrounding control flow.
- L01985 [NONE] `				 struct rdma_cm_event *event)`
  Review: Low-risk line; verify in surrounding control flow.
- L01986 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01987 [NONE] `	struct smb_direct_transport *t = cm_id->context;`
  Review: Low-risk line; verify in surrounding control flow.
- L01988 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01989 [NONE] `	ksmbd_debug(RDMA, "RDMA CM event. cm_id=%p event=%s (%d)\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L01990 [NONE] `		    cm_id, rdma_event_msg(event->event), event->event);`
  Review: Low-risk line; verify in surrounding control flow.
- L01991 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01992 [NONE] `	switch (event->event) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01993 [NONE] `	case RDMA_CM_EVENT_ESTABLISHED: {`
  Review: Low-risk line; verify in surrounding control flow.
- L01994 [NONE] `		t->status = SMB_DIRECT_CS_CONNECTED;`
  Review: Low-risk line; verify in surrounding control flow.
- L01995 [NONE] `		wake_up_interruptible(&t->wait_status);`
  Review: Low-risk line; verify in surrounding control flow.
- L01996 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01997 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01998 [NONE] `	case RDMA_CM_EVENT_DEVICE_REMOVAL:`
  Review: Low-risk line; verify in surrounding control flow.
- L01999 [NONE] `	case RDMA_CM_EVENT_DISCONNECTED: {`
  Review: Low-risk line; verify in surrounding control flow.
- L02000 [NONE] `		ib_drain_qp(t->qp);`
  Review: Low-risk line; verify in surrounding control flow.
- L02001 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02002 [NONE] `		t->status = SMB_DIRECT_CS_DISCONNECTED;`
  Review: Low-risk line; verify in surrounding control flow.
- L02003 [NONE] `		wake_up_interruptible(&t->wait_status);`
  Review: Low-risk line; verify in surrounding control flow.
- L02004 [NONE] `		wake_up_interruptible(&t->wait_reassembly_queue);`
  Review: Low-risk line; verify in surrounding control flow.
- L02005 [NONE] `		wake_up(&t->wait_send_credits);`
  Review: Low-risk line; verify in surrounding control flow.
- L02006 [NONE] `		wake_up(&t->wait_rw_credits);`
  Review: Low-risk line; verify in surrounding control flow.
- L02007 [NONE] `		wake_up(&t->wait_send_pending);`
  Review: Low-risk line; verify in surrounding control flow.
- L02008 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L02009 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02010 [NONE] `	case RDMA_CM_EVENT_CONNECT_ERROR: {`
  Review: Low-risk line; verify in surrounding control flow.
- L02011 [NONE] `		t->status = SMB_DIRECT_CS_DISCONNECTED;`
  Review: Low-risk line; verify in surrounding control flow.
- L02012 [NONE] `		wake_up_interruptible(&t->wait_status);`
  Review: Low-risk line; verify in surrounding control flow.
- L02013 [NONE] `		wake_up_interruptible(&t->wait_reassembly_queue);`
  Review: Low-risk line; verify in surrounding control flow.
- L02014 [NONE] `		wake_up(&t->wait_send_credits);`
  Review: Low-risk line; verify in surrounding control flow.
- L02015 [NONE] `		wake_up(&t->wait_rw_credits);`
  Review: Low-risk line; verify in surrounding control flow.
- L02016 [NONE] `		wake_up(&t->wait_send_pending);`
  Review: Low-risk line; verify in surrounding control flow.
- L02017 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L02018 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02019 [NONE] `	default:`
  Review: Low-risk line; verify in surrounding control flow.
- L02020 [ERROR_PATH|] `		pr_err("Unexpected RDMA CM event. cm_id=%p, event=%s (%d)\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02021 [NONE] `		       cm_id, rdma_event_msg(event->event),`
  Review: Low-risk line; verify in surrounding control flow.
- L02022 [NONE] `		       event->event);`
  Review: Low-risk line; verify in surrounding control flow.
- L02023 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L02024 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02025 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02026 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02027 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02028 [NONE] `static void smb_direct_qpair_handler(struct ib_event *event, void *context)`
  Review: Low-risk line; verify in surrounding control flow.
- L02029 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02030 [NONE] `	struct smb_direct_transport *t = context;`
  Review: Low-risk line; verify in surrounding control flow.
- L02031 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02032 [NONE] `	ksmbd_debug(RDMA, "Received QP event. cm_id=%p, event=%s (%d)\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L02033 [NONE] `		    t->cm_id, ib_event_msg(event->event), event->event);`
  Review: Low-risk line; verify in surrounding control flow.
- L02034 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02035 [NONE] `	switch (event->event) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02036 [NONE] `	case IB_EVENT_CQ_ERR:`
  Review: Low-risk line; verify in surrounding control flow.
- L02037 [NONE] `	case IB_EVENT_QP_FATAL:`
  Review: Low-risk line; verify in surrounding control flow.
- L02038 [NONE] `		smb_direct_disconnect_rdma_connection(t);`
  Review: Low-risk line; verify in surrounding control flow.
- L02039 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L02040 [NONE] `	default:`
  Review: Low-risk line; verify in surrounding control flow.
- L02041 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L02042 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02043 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02044 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02045 [NONE] `static int smb_direct_send_negotiate_response(struct smb_direct_transport *t,`
  Review: Low-risk line; verify in surrounding control flow.
- L02046 [NONE] `					      int failed)`
  Review: Low-risk line; verify in surrounding control flow.
- L02047 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02048 [NONE] `	struct smb_direct_sendmsg *sendmsg;`
  Review: Low-risk line; verify in surrounding control flow.
- L02049 [NONE] `	struct smb_direct_negotiate_resp *resp;`
  Review: Low-risk line; verify in surrounding control flow.
- L02050 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L02051 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02052 [NONE] `	sendmsg = smb_direct_alloc_sendmsg(t);`
  Review: Low-risk line; verify in surrounding control flow.
- L02053 [NONE] `	if (IS_ERR(sendmsg))`
  Review: Low-risk line; verify in surrounding control flow.
- L02054 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02055 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02056 [NONE] `	resp = (struct smb_direct_negotiate_resp *)sendmsg->packet;`
  Review: Low-risk line; verify in surrounding control flow.
- L02057 [NONE] `	if (failed) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02058 [NONE] `		memset(resp, 0, sizeof(*resp));`
  Review: Low-risk line; verify in surrounding control flow.
- L02059 [NONE] `		resp->min_version = cpu_to_le16(0x0100);`
  Review: Low-risk line; verify in surrounding control flow.
- L02060 [NONE] `		resp->max_version = cpu_to_le16(0x0100);`
  Review: Low-risk line; verify in surrounding control flow.
- L02061 [PROTO_GATE|] `		resp->status = STATUS_NOT_SUPPORTED;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02062 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L02063 [PROTO_GATE|] `		resp->status = STATUS_SUCCESS;`
  Review: Protocol gate: confirm strict MS-SMB/MS-SMB2 conformance and error codes.
- L02064 [NONE] `		resp->min_version = SMB_DIRECT_VERSION_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L02065 [NONE] `		resp->max_version = SMB_DIRECT_VERSION_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L02066 [NONE] `		resp->negotiated_version = SMB_DIRECT_VERSION_LE;`
  Review: Low-risk line; verify in surrounding control flow.
- L02067 [NONE] `		resp->reserved = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02068 [NONE] `		resp->credits_requested =`
  Review: Low-risk line; verify in surrounding control flow.
- L02069 [NONE] `				cpu_to_le16(t->send_credit_target);`
  Review: Low-risk line; verify in surrounding control flow.
- L02070 [NONE] `		resp->credits_granted = cpu_to_le16(manage_credits_prior_sending(t));`
  Review: Low-risk line; verify in surrounding control flow.
- L02071 [NONE] `		resp->max_readwrite_size = cpu_to_le32(t->max_rdma_rw_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L02072 [NONE] `		resp->preferred_send_size = cpu_to_le32(t->max_send_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L02073 [NONE] `		resp->max_receive_size = cpu_to_le32(t->max_recv_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L02074 [NONE] `		resp->max_fragmented_size =`
  Review: Low-risk line; verify in surrounding control flow.
- L02075 [NONE] `				cpu_to_le32(t->max_fragmented_recv_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L02076 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02077 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02078 [NONE] `	sendmsg->sge[0].addr = ib_dma_map_single(t->cm_id->device,`
  Review: Low-risk line; verify in surrounding control flow.
- L02079 [NONE] `						 (void *)resp, sizeof(*resp),`
  Review: Low-risk line; verify in surrounding control flow.
- L02080 [NONE] `						 DMA_TO_DEVICE);`
  Review: Low-risk line; verify in surrounding control flow.
- L02081 [NONE] `	ret = ib_dma_mapping_error(t->cm_id->device, sendmsg->sge[0].addr);`
  Review: Low-risk line; verify in surrounding control flow.
- L02082 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02083 [NONE] `		smb_direct_free_sendmsg(t, sendmsg);`
  Review: Low-risk line; verify in surrounding control flow.
- L02084 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L02085 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02086 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02087 [NONE] `	sendmsg->num_sge = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L02088 [NONE] `	sendmsg->sge[0].length = sizeof(*resp);`
  Review: Low-risk line; verify in surrounding control flow.
- L02089 [NONE] `	sendmsg->sge[0].lkey = t->pd->local_dma_lkey;`
  Review: Low-risk line; verify in surrounding control flow.
- L02090 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02091 [NONE] `	ret = post_sendmsg(t, NULL, sendmsg);`
  Review: Low-risk line; verify in surrounding control flow.
- L02092 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02093 [NONE] `		smb_direct_free_sendmsg(t, sendmsg);`
  Review: Low-risk line; verify in surrounding control flow.
- L02094 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L02095 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02096 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02097 [NONE] `	return smb_direct_wait_send_pending(t, __func__);`
  Review: Low-risk line; verify in surrounding control flow.
- L02098 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02099 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02100 [NONE] `static int smb_direct_accept_client(struct smb_direct_transport *t)`
  Review: Low-risk line; verify in surrounding control flow.
- L02101 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02102 [NONE] `	struct rdma_conn_param conn_param;`
  Review: Low-risk line; verify in surrounding control flow.
- L02103 [NONE] `	struct ib_port_immutable port_immutable;`
  Review: Low-risk line; verify in surrounding control flow.
- L02104 [NONE] `	u32 ird_ord_hdr[2];`
  Review: Low-risk line; verify in surrounding control flow.
- L02105 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L02106 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02107 [NONE] `	memset(&conn_param, 0, sizeof(conn_param));`
  Review: Low-risk line; verify in surrounding control flow.
- L02108 [NONE] `	conn_param.initiator_depth = min_t(u8, t->cm_id->device->attrs.max_qp_rd_atom,`
  Review: Low-risk line; verify in surrounding control flow.
- L02109 [NONE] `					   SMB_DIRECT_CM_INITIATOR_DEPTH);`
  Review: Low-risk line; verify in surrounding control flow.
- L02110 [NONE] `	conn_param.responder_resources = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02111 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02112 [NONE] `	t->cm_id->device->ops.get_port_immutable(t->cm_id->device,`
  Review: Low-risk line; verify in surrounding control flow.
- L02113 [NONE] `						 t->cm_id->port_num,`
  Review: Low-risk line; verify in surrounding control flow.
- L02114 [NONE] `						 &port_immutable);`
  Review: Low-risk line; verify in surrounding control flow.
- L02115 [NONE] `	if (port_immutable.core_cap_flags & RDMA_CORE_PORT_IWARP) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02116 [NONE] `		ird_ord_hdr[0] = conn_param.responder_resources;`
  Review: Low-risk line; verify in surrounding control flow.
- L02117 [NONE] `		ird_ord_hdr[1] = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L02118 [NONE] `		conn_param.private_data = ird_ord_hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L02119 [NONE] `		conn_param.private_data_len = sizeof(ird_ord_hdr);`
  Review: Low-risk line; verify in surrounding control flow.
- L02120 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L02121 [NONE] `		conn_param.private_data = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02122 [NONE] `		conn_param.private_data_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02123 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02124 [NONE] `	conn_param.retry_count = SMB_DIRECT_CM_RETRY;`
  Review: Low-risk line; verify in surrounding control flow.
- L02125 [NONE] `	conn_param.rnr_retry_count = SMB_DIRECT_CM_RNR_RETRY;`
  Review: Low-risk line; verify in surrounding control flow.
- L02126 [NONE] `	conn_param.flow_control = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02127 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02128 [NONE] `	ret = rdma_accept(t->cm_id, &conn_param);`
  Review: Low-risk line; verify in surrounding control flow.
- L02129 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02130 [ERROR_PATH|] `		pr_err("error at rdma_accept: %d\n", ret);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02131 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L02132 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02133 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02134 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02135 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02136 [NONE] `static int smb_direct_prepare_negotiation(struct smb_direct_transport *t)`
  Review: Low-risk line; verify in surrounding control flow.
- L02137 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02138 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L02139 [NONE] `	struct smb_direct_recvmsg *recvmsg;`
  Review: Low-risk line; verify in surrounding control flow.
- L02140 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02141 [NONE] `	recvmsg = get_free_recvmsg(t);`
  Review: Low-risk line; verify in surrounding control flow.
- L02142 [NONE] `	if (!recvmsg)`
  Review: Low-risk line; verify in surrounding control flow.
- L02143 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02144 [NONE] `	recvmsg->type = SMB_DIRECT_MSG_NEGOTIATE_REQ;`
  Review: Low-risk line; verify in surrounding control flow.
- L02145 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02146 [NONE] `	ret = smb_direct_post_recv(t, recvmsg);`
  Review: Low-risk line; verify in surrounding control flow.
- L02147 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02148 [ERROR_PATH|] `		pr_err("Can't post recv: %d\n", ret);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02149 [ERROR_PATH|] `		goto out_err;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02150 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02151 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02152 [NONE] `	t->negotiation_requested = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L02153 [NONE] `	ret = smb_direct_accept_client(t);`
  Review: Low-risk line; verify in surrounding control flow.
- L02154 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02155 [ERROR_PATH|] `		pr_err("Can't accept client\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02156 [ERROR_PATH|] `		goto out_err;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02157 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02158 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02159 [NONE] `	smb_direct_post_recv_credits(&t->post_recv_credits_work);`
  Review: Low-risk line; verify in surrounding control flow.
- L02160 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02161 [NONE] `out_err:`
  Review: Low-risk line; verify in surrounding control flow.
- L02162 [NONE] `	put_recvmsg(t, recvmsg);`
  Review: Low-risk line; verify in surrounding control flow.
- L02163 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L02164 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02165 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02166 [NONE] `static unsigned int smb_direct_get_max_fr_pages(struct smb_direct_transport *t)`
  Review: Low-risk line; verify in surrounding control flow.
- L02167 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02168 [NONE] `	return min_t(unsigned int,`
  Review: Low-risk line; verify in surrounding control flow.
- L02169 [NONE] `		     t->cm_id->device->attrs.max_fast_reg_page_list_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L02170 [NONE] `		     256);`
  Review: Low-risk line; verify in surrounding control flow.
- L02171 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02172 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02173 [NONE] `static int smb_direct_init_params(struct smb_direct_transport *t,`
  Review: Low-risk line; verify in surrounding control flow.
- L02174 [NONE] `				  struct ib_qp_cap *cap)`
  Review: Low-risk line; verify in surrounding control flow.
- L02175 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02176 [NONE] `	struct ib_device *device = t->cm_id->device;`
  Review: Low-risk line; verify in surrounding control flow.
- L02177 [NONE] `	int max_send_sges, max_rw_wrs, max_send_wrs;`
  Review: Low-risk line; verify in surrounding control flow.
- L02178 [NONE] `	unsigned int max_sge_per_wr, wrs_per_credit;`
  Review: Low-risk line; verify in surrounding control flow.
- L02179 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02180 [NONE] `	/* need 3 more sge. because a SMB_DIRECT header, SMB2 header,`
  Review: Low-risk line; verify in surrounding control flow.
- L02181 [NONE] `	 * SMB2 response could be mapped.`
  Review: Low-risk line; verify in surrounding control flow.
- L02182 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02183 [NONE] `	t->max_send_size = smb_direct_max_send_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L02184 [NONE] `	max_send_sges = DIV_ROUND_UP(t->max_send_size, PAGE_SIZE) + 3;`
  Review: Low-risk line; verify in surrounding control flow.
- L02185 [NONE] `	if (max_send_sges > SMB_DIRECT_MAX_SEND_SGES) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02186 [ERROR_PATH|] `		pr_err("max_send_size %d is too large\n", t->max_send_size);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02187 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02188 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02189 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02190 [NONE] `	/* Calculate the number of work requests for RDMA R/W.`
  Review: Low-risk line; verify in surrounding control flow.
- L02191 [NONE] `	 * The maximum number of pages which can be registered`
  Review: Low-risk line; verify in surrounding control flow.
- L02192 [NONE] `	 * with one Memory region can be transferred with one`
  Review: Low-risk line; verify in surrounding control flow.
- L02193 [NONE] `	 * R/W credit. And at least 4 work requests for each credit`
  Review: Low-risk line; verify in surrounding control flow.
- L02194 [NONE] `	 * are needed for MR registration, RDMA R/W, local & remote`
  Review: Low-risk line; verify in surrounding control flow.
- L02195 [NONE] `	 * MR invalidation.`
  Review: Low-risk line; verify in surrounding control flow.
- L02196 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02197 [NONE] `	t->max_rdma_rw_size = smb_direct_max_read_write_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L02198 [NONE] `	t->pages_per_rw_credit = smb_direct_get_max_fr_pages(t);`
  Review: Low-risk line; verify in surrounding control flow.
- L02199 [NONE] `	if (t->pages_per_rw_credit <= 1)`
  Review: Low-risk line; verify in surrounding control flow.
- L02200 [NONE] `		t->pages_per_rw_credit = 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L02201 [NONE] `	t->max_rw_credits = DIV_ROUND_UP(t->max_rdma_rw_size,`
  Review: Low-risk line; verify in surrounding control flow.
- L02202 [NONE] `					 (t->pages_per_rw_credit - 1) *`
  Review: Low-risk line; verify in surrounding control flow.
- L02203 [NONE] `					 PAGE_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L02204 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02205 [NONE] `	max_sge_per_wr = min_t(unsigned int, device->attrs.max_send_sge,`
  Review: Low-risk line; verify in surrounding control flow.
- L02206 [NONE] `			       device->attrs.max_sge_rd);`
  Review: Low-risk line; verify in surrounding control flow.
- L02207 [NONE] `	max_sge_per_wr = max_t(unsigned int, max_sge_per_wr,`
  Review: Low-risk line; verify in surrounding control flow.
- L02208 [NONE] `			       max_send_sges);`
  Review: Low-risk line; verify in surrounding control flow.
- L02209 [NONE] `	wrs_per_credit = max_t(unsigned int, 4,`
  Review: Low-risk line; verify in surrounding control flow.
- L02210 [NONE] `			       DIV_ROUND_UP(t->pages_per_rw_credit,`
  Review: Low-risk line; verify in surrounding control flow.
- L02211 [NONE] `					    max_sge_per_wr) + 1);`
  Review: Low-risk line; verify in surrounding control flow.
- L02212 [NONE] `	max_rw_wrs = t->max_rw_credits * wrs_per_credit;`
  Review: Low-risk line; verify in surrounding control flow.
- L02213 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02214 [NONE] `	max_send_wrs = smb_direct_send_credit_target + max_rw_wrs;`
  Review: Low-risk line; verify in surrounding control flow.
- L02215 [NONE] `	if (max_send_wrs > device->attrs.max_cqe ||`
  Review: Low-risk line; verify in surrounding control flow.
- L02216 [NONE] `	    max_send_wrs > device->attrs.max_qp_wr) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02217 [ERROR_PATH|] `		pr_err("consider lowering send_credit_target = %d\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02218 [NONE] `		       smb_direct_send_credit_target);`
  Review: Low-risk line; verify in surrounding control flow.
- L02219 [ERROR_PATH|] `		pr_err("Possible CQE overrun, device reporting max_cqe %d max_qp_wr %d\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02220 [NONE] `		       device->attrs.max_cqe, device->attrs.max_qp_wr);`
  Review: Low-risk line; verify in surrounding control flow.
- L02221 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02222 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02223 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02224 [NONE] `	if (smb_direct_receive_credit_max > device->attrs.max_cqe ||`
  Review: Low-risk line; verify in surrounding control flow.
- L02225 [NONE] `	    smb_direct_receive_credit_max > device->attrs.max_qp_wr) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02226 [ERROR_PATH|] `		pr_err("consider lowering receive_credit_max = %d\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02227 [NONE] `		       smb_direct_receive_credit_max);`
  Review: Low-risk line; verify in surrounding control flow.
- L02228 [ERROR_PATH|] `		pr_err("Possible CQE overrun, device reporting max_cpe %d max_qp_wr %d\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02229 [NONE] `		       device->attrs.max_cqe, device->attrs.max_qp_wr);`
  Review: Low-risk line; verify in surrounding control flow.
- L02230 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02231 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02232 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02233 [NONE] `	if (device->attrs.max_send_sge < SMB_DIRECT_MAX_SEND_SGES) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02234 [ERROR_PATH|] `		pr_err("warning: device max_send_sge = %d too small\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02235 [NONE] `		       device->attrs.max_send_sge);`
  Review: Low-risk line; verify in surrounding control flow.
- L02236 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02237 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02238 [NONE] `	if (device->attrs.max_recv_sge < SMB_DIRECT_MAX_RECV_SGES) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02239 [ERROR_PATH|] `		pr_err("warning: device max_recv_sge = %d too small\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02240 [NONE] `		       device->attrs.max_recv_sge);`
  Review: Low-risk line; verify in surrounding control flow.
- L02241 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02242 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02243 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02244 [NONE] `	t->recv_credits = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02245 [NONE] `	t->count_avail_recvmsg = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02246 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02247 [NONE] `	t->recv_credit_max = smb_direct_receive_credit_max;`
  Review: Low-risk line; verify in surrounding control flow.
- L02248 [NONE] `	t->recv_credit_target = 10;`
  Review: Low-risk line; verify in surrounding control flow.
- L02249 [NONE] `	t->new_recv_credits = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02250 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02251 [NONE] `	t->send_credit_target = smb_direct_send_credit_target;`
  Review: Low-risk line; verify in surrounding control flow.
- L02252 [LIFETIME|] `	atomic_set(&t->send_credits, 0);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L02253 [LIFETIME|] `	atomic_set(&t->rw_credits, t->max_rw_credits);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L02254 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02255 [NONE] `	t->max_send_size = smb_direct_max_send_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L02256 [NONE] `	t->max_recv_size = smb_direct_max_receive_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L02257 [NONE] `	t->max_fragmented_recv_size = smb_direct_max_fragmented_recv_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L02258 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02259 [NONE] `	cap->max_send_wr = max_send_wrs;`
  Review: Low-risk line; verify in surrounding control flow.
- L02260 [NONE] `	cap->max_recv_wr = t->recv_credit_max;`
  Review: Low-risk line; verify in surrounding control flow.
- L02261 [NONE] `	cap->max_send_sge = SMB_DIRECT_MAX_SEND_SGES;`
  Review: Low-risk line; verify in surrounding control flow.
- L02262 [NONE] `	cap->max_recv_sge = SMB_DIRECT_MAX_RECV_SGES;`
  Review: Low-risk line; verify in surrounding control flow.
- L02263 [NONE] `	cap->max_inline_data = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02264 [NONE] `	cap->max_rdma_ctxs = t->max_rw_credits;`
  Review: Low-risk line; verify in surrounding control flow.
- L02265 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02266 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02267 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02268 [NONE] `static void smb_direct_destroy_pools(struct smb_direct_transport *t)`
  Review: Low-risk line; verify in surrounding control flow.
- L02269 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02270 [NONE] `	struct smb_direct_recvmsg *recvmsg;`
  Review: Low-risk line; verify in surrounding control flow.
- L02271 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02272 [NONE] `	while ((recvmsg = get_free_recvmsg(t)))`
  Review: Low-risk line; verify in surrounding control flow.
- L02273 [NONE] `		mempool_free(recvmsg, t->recvmsg_mempool);`
  Review: Low-risk line; verify in surrounding control flow.
- L02274 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02275 [NONE] `	mempool_destroy(t->recvmsg_mempool);`
  Review: Low-risk line; verify in surrounding control flow.
- L02276 [NONE] `	t->recvmsg_mempool = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02277 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02278 [NONE] `	kmem_cache_destroy(t->recvmsg_cache);`
  Review: Low-risk line; verify in surrounding control flow.
- L02279 [NONE] `	t->recvmsg_cache = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02280 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02281 [NONE] `	mempool_destroy(t->sendmsg_mempool);`
  Review: Low-risk line; verify in surrounding control flow.
- L02282 [NONE] `	t->sendmsg_mempool = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02283 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02284 [NONE] `	kmem_cache_destroy(t->sendmsg_cache);`
  Review: Low-risk line; verify in surrounding control flow.
- L02285 [NONE] `	t->sendmsg_cache = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02286 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02287 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02288 [NONE] `static int smb_direct_create_pools(struct smb_direct_transport *t)`
  Review: Low-risk line; verify in surrounding control flow.
- L02289 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02290 [NONE] `	char name[80];`
  Review: Low-risk line; verify in surrounding control flow.
- L02291 [NONE] `	int i;`
  Review: Low-risk line; verify in surrounding control flow.
- L02292 [NONE] `	struct smb_direct_recvmsg *recvmsg;`
  Review: Low-risk line; verify in surrounding control flow.
- L02293 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02294 [MEM_BOUNDS|] `	snprintf(name, sizeof(name), "smb_direct_rqst_pool_%p", t);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L02295 [NONE] `	t->sendmsg_cache = kmem_cache_create(name,`
  Review: Low-risk line; verify in surrounding control flow.
- L02296 [NONE] `					     sizeof(struct smb_direct_sendmsg) +`
  Review: Low-risk line; verify in surrounding control flow.
- L02297 [NONE] `					      sizeof(struct smb_direct_negotiate_resp),`
  Review: Low-risk line; verify in surrounding control flow.
- L02298 [NONE] `					     0, SLAB_HWCACHE_ALIGN, NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L02299 [NONE] `	if (!t->sendmsg_cache)`
  Review: Low-risk line; verify in surrounding control flow.
- L02300 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02301 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02302 [NONE] `	t->sendmsg_mempool = mempool_create(t->send_credit_target,`
  Review: Low-risk line; verify in surrounding control flow.
- L02303 [NONE] `					    mempool_alloc_slab, mempool_free_slab,`
  Review: Low-risk line; verify in surrounding control flow.
- L02304 [NONE] `					    t->sendmsg_cache);`
  Review: Low-risk line; verify in surrounding control flow.
- L02305 [NONE] `	if (!t->sendmsg_mempool)`
  Review: Low-risk line; verify in surrounding control flow.
- L02306 [ERROR_PATH|] `		goto err;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02307 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02308 [MEM_BOUNDS|] `	snprintf(name, sizeof(name), "smb_direct_resp_%p", t);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L02309 [NONE] `	t->recvmsg_cache = kmem_cache_create(name,`
  Review: Low-risk line; verify in surrounding control flow.
- L02310 [NONE] `					     sizeof(struct smb_direct_recvmsg) +`
  Review: Low-risk line; verify in surrounding control flow.
- L02311 [NONE] `					      t->max_recv_size,`
  Review: Low-risk line; verify in surrounding control flow.
- L02312 [NONE] `					     0, SLAB_HWCACHE_ALIGN, NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L02313 [NONE] `	if (!t->recvmsg_cache)`
  Review: Low-risk line; verify in surrounding control flow.
- L02314 [ERROR_PATH|] `		goto err;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02315 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02316 [NONE] `	t->recvmsg_mempool =`
  Review: Low-risk line; verify in surrounding control flow.
- L02317 [NONE] `		mempool_create(t->recv_credit_max, mempool_alloc_slab,`
  Review: Low-risk line; verify in surrounding control flow.
- L02318 [NONE] `			       mempool_free_slab, t->recvmsg_cache);`
  Review: Low-risk line; verify in surrounding control flow.
- L02319 [NONE] `	if (!t->recvmsg_mempool)`
  Review: Low-risk line; verify in surrounding control flow.
- L02320 [ERROR_PATH|] `		goto err;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02321 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02322 [NONE] `	INIT_LIST_HEAD(&t->recvmsg_queue);`
  Review: Low-risk line; verify in surrounding control flow.
- L02323 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02324 [NONE] `	for (i = 0; i < t->recv_credit_max; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02325 [NONE] `		recvmsg = mempool_alloc(t->recvmsg_mempool, KSMBD_DEFAULT_GFP);`
  Review: Low-risk line; verify in surrounding control flow.
- L02326 [NONE] `		if (!recvmsg)`
  Review: Low-risk line; verify in surrounding control flow.
- L02327 [ERROR_PATH|] `			goto err;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02328 [NONE] `		recvmsg->transport = t;`
  Review: Low-risk line; verify in surrounding control flow.
- L02329 [NONE] `		recvmsg->sge.length = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02330 [NONE] `		list_add(&recvmsg->list, &t->recvmsg_queue);`
  Review: Low-risk line; verify in surrounding control flow.
- L02331 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02332 [NONE] `	t->count_avail_recvmsg = t->recv_credit_max;`
  Review: Low-risk line; verify in surrounding control flow.
- L02333 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02334 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02335 [NONE] `err:`
  Review: Low-risk line; verify in surrounding control flow.
- L02336 [NONE] `	smb_direct_destroy_pools(t);`
  Review: Low-risk line; verify in surrounding control flow.
- L02337 [ERROR_PATH|] `	return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02338 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02339 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02340 [NONE] `static int smb_direct_create_qpair(struct smb_direct_transport *t,`
  Review: Low-risk line; verify in surrounding control flow.
- L02341 [NONE] `				   struct ib_qp_cap *cap)`
  Review: Low-risk line; verify in surrounding control flow.
- L02342 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02343 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L02344 [NONE] `	struct ib_qp_init_attr qp_attr;`
  Review: Low-risk line; verify in surrounding control flow.
- L02345 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 5, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02346 [NONE] `	int pages_per_rw;`
  Review: Low-risk line; verify in surrounding control flow.
- L02347 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02348 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02349 [NONE] `	t->pd = ib_alloc_pd(t->cm_id->device, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L02350 [NONE] `	if (IS_ERR(t->pd)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02351 [ERROR_PATH|] `		pr_err("Can't create RDMA PD\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02352 [NONE] `		ret = PTR_ERR(t->pd);`
  Review: Low-risk line; verify in surrounding control flow.
- L02353 [NONE] `		t->pd = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02354 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L02355 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02356 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02357 [NONE] `	t->send_cq = ib_alloc_cq(t->cm_id->device, t,`
  Review: Low-risk line; verify in surrounding control flow.
- L02358 [NONE] `				 smb_direct_send_credit_target + cap->max_rdma_ctxs,`
  Review: Low-risk line; verify in surrounding control flow.
- L02359 [NONE] `				 0, IB_POLL_WORKQUEUE);`
  Review: Low-risk line; verify in surrounding control flow.
- L02360 [NONE] `	if (IS_ERR(t->send_cq)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02361 [ERROR_PATH|] `		pr_err("Can't create RDMA send CQ\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02362 [NONE] `		ret = PTR_ERR(t->send_cq);`
  Review: Low-risk line; verify in surrounding control flow.
- L02363 [NONE] `		t->send_cq = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02364 [ERROR_PATH|] `		goto err;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02365 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02366 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02367 [NONE] `	t->recv_cq = ib_alloc_cq(t->cm_id->device, t,`
  Review: Low-risk line; verify in surrounding control flow.
- L02368 [NONE] `				 t->recv_credit_max, 0, IB_POLL_WORKQUEUE);`
  Review: Low-risk line; verify in surrounding control flow.
- L02369 [NONE] `	if (IS_ERR(t->recv_cq)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02370 [ERROR_PATH|] `		pr_err("Can't create RDMA recv CQ\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02371 [NONE] `		ret = PTR_ERR(t->recv_cq);`
  Review: Low-risk line; verify in surrounding control flow.
- L02372 [NONE] `		t->recv_cq = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02373 [ERROR_PATH|] `		goto err;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02374 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02375 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02376 [NONE] `	memset(&qp_attr, 0, sizeof(qp_attr));`
  Review: Low-risk line; verify in surrounding control flow.
- L02377 [NONE] `	qp_attr.event_handler = smb_direct_qpair_handler;`
  Review: Low-risk line; verify in surrounding control flow.
- L02378 [NONE] `	qp_attr.qp_context = t;`
  Review: Low-risk line; verify in surrounding control flow.
- L02379 [NONE] `	qp_attr.cap = *cap;`
  Review: Low-risk line; verify in surrounding control flow.
- L02380 [NONE] `	qp_attr.sq_sig_type = IB_SIGNAL_REQ_WR;`
  Review: Low-risk line; verify in surrounding control flow.
- L02381 [NONE] `	qp_attr.qp_type = IB_QPT_RC;`
  Review: Low-risk line; verify in surrounding control flow.
- L02382 [NONE] `	qp_attr.send_cq = t->send_cq;`
  Review: Low-risk line; verify in surrounding control flow.
- L02383 [NONE] `	qp_attr.recv_cq = t->recv_cq;`
  Review: Low-risk line; verify in surrounding control flow.
- L02384 [NONE] `	qp_attr.port_num = ~0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02385 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02386 [NONE] `	ret = rdma_create_qp(t->cm_id, t->pd, &qp_attr);`
  Review: Low-risk line; verify in surrounding control flow.
- L02387 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02388 [ERROR_PATH|] `		pr_err("Can't create RDMA QP: %d\n", ret);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02389 [ERROR_PATH|] `		goto err;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02390 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02391 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02392 [NONE] `	t->qp = t->cm_id->qp;`
  Review: Low-risk line; verify in surrounding control flow.
- L02393 [NONE] `	t->cm_id->event_handler = smb_direct_cm_handler;`
  Review: Low-risk line; verify in surrounding control flow.
- L02394 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02395 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 5, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02396 [NONE] `	pages_per_rw = DIV_ROUND_UP(t->max_rdma_rw_size, PAGE_SIZE) + 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L02397 [NONE] `	if (pages_per_rw > t->cm_id->device->attrs.max_sgl_rd) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02398 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02399 [NONE] `		ret = ib_mr_pool_init(t->qp, &t->qp->rdma_mrs,`
  Review: Low-risk line; verify in surrounding control flow.
- L02400 [NONE] `				      t->max_rw_credits, IB_MR_TYPE_MEM_REG,`
  Review: Low-risk line; verify in surrounding control flow.
- L02401 [NONE] `				      t->pages_per_rw_credit, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L02402 [NONE] `		if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02403 [ERROR_PATH|] `			pr_err("failed to init mr pool count %d pages %d\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02404 [NONE] `			       t->max_rw_credits, t->pages_per_rw_credit);`
  Review: Low-risk line; verify in surrounding control flow.
- L02405 [ERROR_PATH|] `			goto err;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02406 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02407 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 5, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02408 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02409 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02410 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02411 [NONE] `err:`
  Review: Low-risk line; verify in surrounding control flow.
- L02412 [NONE] `	if (t->qp) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02413 [NONE] `		t->qp = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02414 [NONE] `		rdma_destroy_qp(t->cm_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L02415 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02416 [NONE] `	if (t->recv_cq) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02417 [NONE] `		ib_destroy_cq(t->recv_cq);`
  Review: Low-risk line; verify in surrounding control flow.
- L02418 [NONE] `		t->recv_cq = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02419 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02420 [NONE] `	if (t->send_cq) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02421 [NONE] `		ib_destroy_cq(t->send_cq);`
  Review: Low-risk line; verify in surrounding control flow.
- L02422 [NONE] `		t->send_cq = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02423 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02424 [NONE] `	if (t->pd) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02425 [NONE] `		ib_dealloc_pd(t->pd);`
  Review: Low-risk line; verify in surrounding control flow.
- L02426 [NONE] `		t->pd = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02427 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02428 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L02429 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02430 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02431 [NONE] `static int smb_direct_prepare(struct ksmbd_transport *t)`
  Review: Low-risk line; verify in surrounding control flow.
- L02432 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02433 [NONE] `	struct smb_direct_transport *st = smb_trans_direct_transfort(t);`
  Review: Low-risk line; verify in surrounding control flow.
- L02434 [NONE] `	struct smb_direct_recvmsg *recvmsg;`
  Review: Low-risk line; verify in surrounding control flow.
- L02435 [NONE] `	struct smb_direct_negotiate_req *req;`
  Review: Low-risk line; verify in surrounding control flow.
- L02436 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L02437 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02438 [NONE] `	ksmbd_debug(RDMA, "Waiting for SMB_DIRECT negotiate request\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L02439 [WAIT_LOOP|] `	ret = wait_event_interruptible_timeout(st->wait_status,`
  Review: Bounded wait and cancellation path must be guaranteed.
- L02440 [NONE] `					       st->negotiation_requested ||`
  Review: Low-risk line; verify in surrounding control flow.
- L02441 [NONE] `					       st->status == SMB_DIRECT_CS_DISCONNECTED,`
  Review: Low-risk line; verify in surrounding control flow.
- L02442 [NONE] `					       SMB_DIRECT_NEGOTIATE_TIMEOUT * HZ);`
  Review: Low-risk line; verify in surrounding control flow.
- L02443 [NONE] `	if (ret <= 0 || st->status == SMB_DIRECT_CS_DISCONNECTED)`
  Review: Low-risk line; verify in surrounding control flow.
- L02444 [NONE] `		return ret < 0 ? ret : -ETIMEDOUT;`
  Review: Low-risk line; verify in surrounding control flow.
- L02445 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02446 [NONE] `	recvmsg = get_first_reassembly(st);`
  Review: Low-risk line; verify in surrounding control flow.
- L02447 [NONE] `	if (!recvmsg)`
  Review: Low-risk line; verify in surrounding control flow.
- L02448 [ERROR_PATH|] `		return -ECONNABORTED;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02449 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02450 [NONE] `	ret = smb_direct_check_recvmsg(recvmsg);`
  Review: Low-risk line; verify in surrounding control flow.
- L02451 [NONE] `	if (ret == -ECONNABORTED)`
  Review: Low-risk line; verify in surrounding control flow.
- L02452 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02453 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02454 [NONE] `	req = (struct smb_direct_negotiate_req *)recvmsg->packet;`
  Review: Low-risk line; verify in surrounding control flow.
- L02455 [NONE] `	st->max_recv_size = min_t(int, st->max_recv_size,`
  Review: Low-risk line; verify in surrounding control flow.
- L02456 [NONE] `				  le32_to_cpu(req->preferred_send_size));`
  Review: Low-risk line; verify in surrounding control flow.
- L02457 [NONE] `	st->max_send_size = min_t(int, st->max_send_size,`
  Review: Low-risk line; verify in surrounding control flow.
- L02458 [NONE] `				  le32_to_cpu(req->max_receive_size));`
  Review: Low-risk line; verify in surrounding control flow.
- L02459 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02460 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02461 [NONE] `	 * Enforce minimum buffer sizes to prevent a malicious client from`
  Review: Low-risk line; verify in surrounding control flow.
- L02462 [NONE] `	 * forcing pathologically small buffers that cause excessive`
  Review: Low-risk line; verify in surrounding control flow.
- L02463 [NONE] `	 * fragmentation and degrade server performance (DoS).`
  Review: Low-risk line; verify in surrounding control flow.
- L02464 [NONE] `	 * 8192 accommodates a full SMB2 header plus reasonable payload.`
  Review: Low-risk line; verify in surrounding control flow.
- L02465 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02466 [NONE] `	if (st->max_recv_size < 8192) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02467 [ERROR_PATH|] `		pr_err("RDMA: client max_recv_size too small: %d\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02468 [NONE] `		       st->max_recv_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L02469 [NONE] `		ret = -ECONNABORTED;`
  Review: Low-risk line; verify in surrounding control flow.
- L02470 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02471 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02472 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02473 [NONE] `	if (st->max_send_size < 8192) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02474 [ERROR_PATH|] `		pr_err("RDMA: client max_send_size too small: %d\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02475 [NONE] `		       st->max_send_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L02476 [NONE] `		ret = -ECONNABORTED;`
  Review: Low-risk line; verify in surrounding control flow.
- L02477 [ERROR_PATH|] `		goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02478 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02479 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02480 [NONE] `	st->max_fragmented_send_size =`
  Review: Low-risk line; verify in surrounding control flow.
- L02481 [NONE] `		le32_to_cpu(req->max_fragmented_size);`
  Review: Low-risk line; verify in surrounding control flow.
- L02482 [NONE] `	if (st->max_fragmented_send_size == 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02483 [NONE] `		st->max_fragmented_send_size = smb_direct_max_fragmented_recv_size;`
  Review: Low-risk line; verify in surrounding control flow.
- L02484 [NONE] `	else if (st->max_fragmented_send_size < 131072)`
  Review: Low-risk line; verify in surrounding control flow.
- L02485 [NONE] `		st->max_fragmented_send_size = 131072;`
  Review: Low-risk line; verify in surrounding control flow.
- L02486 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02487 [NONE] `	st->max_fragmented_recv_size =`
  Review: Low-risk line; verify in surrounding control flow.
- L02488 [NONE] `		(st->recv_credit_max * st->max_recv_size) / 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L02489 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02490 [NONE] `	ret = smb_direct_send_negotiate_response(st, ret);`
  Review: Low-risk line; verify in surrounding control flow.
- L02491 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L02492 [NONE] `	spin_lock_irq(&st->reassembly_queue_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L02493 [NONE] `	st->reassembly_queue_length--;`
  Review: Low-risk line; verify in surrounding control flow.
- L02494 [NONE] `	list_del(&recvmsg->list);`
  Review: Low-risk line; verify in surrounding control flow.
- L02495 [NONE] `	spin_unlock_irq(&st->reassembly_queue_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L02496 [NONE] `	put_recvmsg(st, recvmsg);`
  Review: Low-risk line; verify in surrounding control flow.
- L02497 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02498 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L02499 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02500 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02501 [NONE] `static int smb_direct_connect(struct smb_direct_transport *st)`
  Review: Low-risk line; verify in surrounding control flow.
- L02502 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02503 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L02504 [NONE] `	struct ib_qp_cap qp_cap;`
  Review: Low-risk line; verify in surrounding control flow.
- L02505 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02506 [NONE] `	ret = smb_direct_init_params(st, &qp_cap);`
  Review: Low-risk line; verify in surrounding control flow.
- L02507 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02508 [ERROR_PATH|] `		pr_err("Can't configure RDMA parameters\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02509 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L02510 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02511 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02512 [NONE] `	ret = smb_direct_create_pools(st);`
  Review: Low-risk line; verify in surrounding control flow.
- L02513 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02514 [ERROR_PATH|] `		pr_err("Can't init RDMA pool: %d\n", ret);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02515 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L02516 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02517 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02518 [NONE] `	ret = smb_direct_create_qpair(st, &qp_cap);`
  Review: Low-risk line; verify in surrounding control flow.
- L02519 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02520 [ERROR_PATH|] `		pr_err("Can't accept RDMA client: %d\n", ret);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02521 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L02522 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02523 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02524 [NONE] `	ret = smb_direct_prepare_negotiation(st);`
  Review: Low-risk line; verify in surrounding control flow.
- L02525 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02526 [ERROR_PATH|] `		pr_err("Can't negotiate: %d\n", ret);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02527 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L02528 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02529 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02530 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02531 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02532 [NONE] `static bool rdma_frwr_is_supported(struct ib_device_attr *attrs)`
  Review: Low-risk line; verify in surrounding control flow.
- L02533 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02534 [NONE] `	if (!(attrs->device_cap_flags & IB_DEVICE_MEM_MGT_EXTENSIONS))`
  Review: Low-risk line; verify in surrounding control flow.
- L02535 [NONE] `		return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L02536 [NONE] `	if (attrs->max_fast_reg_page_list_len == 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02537 [NONE] `		return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L02538 [NONE] `	return true;`
  Review: Low-risk line; verify in surrounding control flow.
- L02539 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02540 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02541 [NONE] `static int smb_direct_handle_connect_request(struct rdma_cm_id *new_cm_id)`
  Review: Low-risk line; verify in surrounding control flow.
- L02542 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02543 [NONE] `	struct smb_direct_transport *t;`
  Review: Low-risk line; verify in surrounding control flow.
- L02544 [NONE] `	struct task_struct *handler;`
  Review: Low-risk line; verify in surrounding control flow.
- L02545 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L02546 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02547 [NONE] `	if (!rdma_frwr_is_supported(&new_cm_id->device->attrs)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02548 [NONE] `		ksmbd_debug(RDMA,`
  Review: Low-risk line; verify in surrounding control flow.
- L02549 [NONE] `			    "Fast Registration Work Requests is not supported. device capabilities=%llx\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L02550 [NONE] `			    new_cm_id->device->attrs.device_cap_flags);`
  Review: Low-risk line; verify in surrounding control flow.
- L02551 [ERROR_PATH|] `		return -EPROTONOSUPPORT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02552 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02553 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02554 [NONE] `	if (server_conf.max_connections &&`
  Review: Low-risk line; verify in surrounding control flow.
- L02555 [LIFETIME|] `	    atomic_inc_return(&smbd_active_conn) > server_conf.max_connections) {`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L02556 [LIFETIME|] `		atomic_dec(&smbd_active_conn);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L02557 [ERROR_PATH|] `		pr_err_ratelimited("RDMA: max connections reached\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02558 [NONE] `		rdma_reject(new_cm_id, NULL, 0, IB_CM_REJ_CONSUMER_DEFINED);`
  Review: Low-risk line; verify in surrounding control flow.
- L02559 [ERROR_PATH|] `		return -ECONNREFUSED;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02560 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02561 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02562 [NONE] `	t = alloc_transport(new_cm_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L02563 [NONE] `	if (!t) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02564 [NONE] `		if (server_conf.max_connections)`
  Review: Low-risk line; verify in surrounding control flow.
- L02565 [LIFETIME|] `			atomic_dec(&smbd_active_conn);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L02566 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02567 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02568 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02569 [NONE] `	ret = smb_direct_connect(t);`
  Review: Low-risk line; verify in surrounding control flow.
- L02570 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L02571 [ERROR_PATH|] `		goto out_err;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02572 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02573 [NONE] `	handler = kthread_run(ksmbd_conn_handler_loop,`
  Review: Low-risk line; verify in surrounding control flow.
- L02574 [NONE] `			      KSMBD_TRANS(t)->conn, "ksmbd:r%u",`
  Review: Low-risk line; verify in surrounding control flow.
- L02575 [NONE] `			      smb_direct_port);`
  Review: Low-risk line; verify in surrounding control flow.
- L02576 [NONE] `	if (IS_ERR(handler)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02577 [NONE] `		ret = PTR_ERR(handler);`
  Review: Low-risk line; verify in surrounding control flow.
- L02578 [ERROR_PATH|] `		pr_err("Can't start thread\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02579 [ERROR_PATH|] `		goto out_err;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02580 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02581 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02582 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02583 [NONE] `out_err:`
  Review: Low-risk line; verify in surrounding control flow.
- L02584 [NONE] `	free_transport(t);`
  Review: Low-risk line; verify in surrounding control flow.
- L02585 [NONE] `	if (server_conf.max_connections)`
  Review: Low-risk line; verify in surrounding control flow.
- L02586 [LIFETIME|] `		atomic_dec(&smbd_active_conn);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L02587 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L02588 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02589 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02590 [NONE] `static int smb_direct_listen_handler(struct rdma_cm_id *cm_id,`
  Review: Low-risk line; verify in surrounding control flow.
- L02591 [NONE] `				     struct rdma_cm_event *event)`
  Review: Low-risk line; verify in surrounding control flow.
- L02592 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02593 [NONE] `	switch (event->event) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02594 [NONE] `	case RDMA_CM_EVENT_CONNECT_REQUEST: {`
  Review: Low-risk line; verify in surrounding control flow.
- L02595 [NONE] `		int ret = smb_direct_handle_connect_request(cm_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L02596 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02597 [NONE] `		if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02598 [ERROR_PATH|] `			pr_err("Can't create transport: %d\n", ret);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02599 [NONE] `			return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L02600 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02601 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02602 [NONE] `		ksmbd_debug(RDMA, "Received connection request. cm_id=%p\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L02603 [NONE] `			    cm_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L02604 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L02605 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02606 [NONE] `	default:`
  Review: Low-risk line; verify in surrounding control flow.
- L02607 [ERROR_PATH|] `		pr_err("Unexpected listen event. cm_id=%p, event=%s (%d)\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02608 [NONE] `		       cm_id, rdma_event_msg(event->event), event->event);`
  Review: Low-risk line; verify in surrounding control flow.
- L02609 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L02610 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02611 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02612 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02613 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02614 [NONE] `static int smb_direct_listen(int port)`
  Review: Low-risk line; verify in surrounding control flow.
- L02615 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02616 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L02617 [NONE] `	struct rdma_cm_id *cm_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L02618 [NONE] `	struct sockaddr_in sin = {`
  Review: Low-risk line; verify in surrounding control flow.
- L02619 [NONE] `		.sin_family		= AF_INET,`
  Review: Low-risk line; verify in surrounding control flow.
- L02620 [NONE] `		.sin_addr.s_addr	= htonl(INADDR_ANY),`
  Review: Low-risk line; verify in surrounding control flow.
- L02621 [NONE] `		.sin_port		= htons(port),`
  Review: Low-risk line; verify in surrounding control flow.
- L02622 [NONE] `	};`
  Review: Low-risk line; verify in surrounding control flow.
- L02623 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02624 [NONE] `	cm_id = rdma_create_id(&init_net, smb_direct_listen_handler,`
  Review: Low-risk line; verify in surrounding control flow.
- L02625 [NONE] `			       &smb_direct_listener, RDMA_PS_TCP, IB_QPT_RC);`
  Review: Low-risk line; verify in surrounding control flow.
- L02626 [NONE] `	if (IS_ERR(cm_id)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02627 [ERROR_PATH|] `		pr_err("Can't create cm id: %ld\n", PTR_ERR(cm_id));`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02628 [NONE] `		return PTR_ERR(cm_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L02629 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02630 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02631 [NONE] `	ret = rdma_bind_addr(cm_id, (struct sockaddr *)&sin);`
  Review: Low-risk line; verify in surrounding control flow.
- L02632 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02633 [ERROR_PATH|] `		pr_err("Can't bind: %d\n", ret);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02634 [ERROR_PATH|] `		goto err;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02635 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02636 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02637 [NONE] `	smb_direct_listener.cm_id = cm_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L02638 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02639 [NONE] `	ret = rdma_listen(cm_id, 10);`
  Review: Low-risk line; verify in surrounding control flow.
- L02640 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02641 [ERROR_PATH|] `		pr_err("Can't listen: %d\n", ret);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02642 [ERROR_PATH|] `		goto err;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02643 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02644 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02645 [NONE] `err:`
  Review: Low-risk line; verify in surrounding control flow.
- L02646 [NONE] `	smb_direct_listener.cm_id = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02647 [NONE] `	rdma_destroy_id(cm_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L02648 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L02649 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02650 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02651 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02652 [NONE] `static int smb_direct_ib_client_add(struct ib_device *ib_dev)`
  Review: Low-risk line; verify in surrounding control flow.
- L02653 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02654 [NONE] `static void smb_direct_ib_client_add(struct ib_device *ib_dev)`
  Review: Low-risk line; verify in surrounding control flow.
- L02655 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02656 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02657 [NONE] `	struct smb_direct_device *smb_dev;`
  Review: Low-risk line; verify in surrounding control flow.
- L02658 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02659 [NONE] `	/* Set 5445 port if device type is iWARP(No IB) */`
  Review: Low-risk line; verify in surrounding control flow.
- L02660 [NONE] `	if (ib_dev->node_type != RDMA_NODE_IB_CA)`
  Review: Low-risk line; verify in surrounding control flow.
- L02661 [NONE] `		smb_direct_port = SMB_DIRECT_PORT_IWARP;`
  Review: Low-risk line; verify in surrounding control flow.
- L02662 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02663 [NONE] `	if (!ib_dev->ops.get_netdev ||`
  Review: Low-risk line; verify in surrounding control flow.
- L02664 [NONE] `	    !rdma_frwr_is_supported(&ib_dev->attrs))`
  Review: Low-risk line; verify in surrounding control flow.
- L02665 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02666 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02667 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02668 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L02669 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02670 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02671 [MEM_BOUNDS|] `	smb_dev = kzalloc(sizeof(*smb_dev), KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L02672 [NONE] `	if (!smb_dev)`
  Review: Low-risk line; verify in surrounding control flow.
- L02673 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02674 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02675 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02676 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L02677 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02678 [NONE] `	smb_dev->ib_dev = ib_dev;`
  Review: Low-risk line; verify in surrounding control flow.
- L02679 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02680 [NONE] `	write_lock(&smb_direct_device_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L02681 [NONE] `	list_add(&smb_dev->list, &smb_direct_device_list);`
  Review: Low-risk line; verify in surrounding control flow.
- L02682 [NONE] `	write_unlock(&smb_direct_device_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L02683 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02684 [NONE] `	ksmbd_debug(RDMA, "ib device added: name %s\n", ib_dev->name);`
  Review: Low-risk line; verify in surrounding control flow.
- L02685 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02686 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02687 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02688 [NONE] `	return;`
  Review: Low-risk line; verify in surrounding control flow.
- L02689 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02690 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02691 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02692 [NONE] `static void smb_direct_ib_client_remove(struct ib_device *ib_dev,`
  Review: Low-risk line; verify in surrounding control flow.
- L02693 [NONE] `					void *client_data)`
  Review: Low-risk line; verify in surrounding control flow.
- L02694 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02695 [NONE] `	struct smb_direct_device *smb_dev, *tmp;`
  Review: Low-risk line; verify in surrounding control flow.
- L02696 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02697 [NONE] `	write_lock(&smb_direct_device_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L02698 [NONE] `	list_for_each_entry_safe(smb_dev, tmp, &smb_direct_device_list, list) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02699 [NONE] `		if (smb_dev->ib_dev == ib_dev) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02700 [NONE] `			list_del(&smb_dev->list);`
  Review: Low-risk line; verify in surrounding control flow.
- L02701 [NONE] `			kfree(smb_dev);`
  Review: Low-risk line; verify in surrounding control flow.
- L02702 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L02703 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02704 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02705 [NONE] `	write_unlock(&smb_direct_device_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L02706 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02707 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02708 [NONE] `static struct ib_client smb_direct_ib_client = {`
  Review: Low-risk line; verify in surrounding control flow.
- L02709 [NONE] `	.name	= "ksmbd_smb_direct_ib",`
  Review: Low-risk line; verify in surrounding control flow.
- L02710 [NONE] `	.add	= smb_direct_ib_client_add,`
  Review: Low-risk line; verify in surrounding control flow.
- L02711 [NONE] `	.remove	= smb_direct_ib_client_remove,`
  Review: Low-risk line; verify in surrounding control flow.
- L02712 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L02713 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02714 [NONE] `int ksmbd_rdma_init(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L02715 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02716 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L02717 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02718 [NONE] `	smb_direct_listener.cm_id = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02719 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02720 [NONE] `	ret = ib_register_client(&smb_direct_ib_client);`
  Review: Low-risk line; verify in surrounding control flow.
- L02721 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02722 [ERROR_PATH|] `		pr_err("failed to ib_register_client\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02723 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L02724 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02725 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02726 [NONE] `	/* When a client is running out of send credits, the credits are`
  Review: Low-risk line; verify in surrounding control flow.
- L02727 [NONE] `	 * granted by the server's sending a packet using this queue.`
  Review: Low-risk line; verify in surrounding control flow.
- L02728 [NONE] `	 * This avoids the situation that a clients cannot send packets`
  Review: Low-risk line; verify in surrounding control flow.
- L02729 [NONE] `	 * for lack of credits`
  Review: Low-risk line; verify in surrounding control flow.
- L02730 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02731 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 18, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02732 [NONE] `	smb_direct_wq = alloc_workqueue("ksmbd-smb_direct-wq",`
  Review: Low-risk line; verify in surrounding control flow.
- L02733 [NONE] `					WQ_HIGHPRI | WQ_MEM_RECLAIM | WQ_PERCPU,`
  Review: Low-risk line; verify in surrounding control flow.
- L02734 [NONE] `					0);`
  Review: Low-risk line; verify in surrounding control flow.
- L02735 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02736 [NONE] `	smb_direct_wq = alloc_workqueue("ksmbd-smb_direct-wq",`
  Review: Low-risk line; verify in surrounding control flow.
- L02737 [NONE] `					WQ_HIGHPRI | WQ_MEM_RECLAIM, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L02738 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02739 [NONE] `	if (!smb_direct_wq) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02740 [NONE] `		ib_unregister_client(&smb_direct_ib_client);`
  Review: Low-risk line; verify in surrounding control flow.
- L02741 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02742 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02743 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02744 [NONE] `	ret = smb_direct_listen(smb_direct_port);`
  Review: Low-risk line; verify in surrounding control flow.
- L02745 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02746 [NONE] `		destroy_workqueue(smb_direct_wq);`
  Review: Low-risk line; verify in surrounding control flow.
- L02747 [NONE] `		smb_direct_wq = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02748 [NONE] `		ib_unregister_client(&smb_direct_ib_client);`
  Review: Low-risk line; verify in surrounding control flow.
- L02749 [ERROR_PATH|] `		pr_err("Can't listen: %d\n", ret);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02750 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L02751 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02752 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02753 [NONE] `	ksmbd_debug(RDMA, "init RDMA listener. cm_id=%p\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L02754 [NONE] `		    smb_direct_listener.cm_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L02755 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02756 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02757 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02758 [NONE] `void ksmbd_rdma_stop_listening(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L02759 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02760 [NONE] `	if (!smb_direct_listener.cm_id)`
  Review: Low-risk line; verify in surrounding control flow.
- L02761 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L02762 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02763 [NONE] `	ib_unregister_client(&smb_direct_ib_client);`
  Review: Low-risk line; verify in surrounding control flow.
- L02764 [NONE] `	rdma_destroy_id(smb_direct_listener.cm_id);`
  Review: Low-risk line; verify in surrounding control flow.
- L02765 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02766 [NONE] `	smb_direct_listener.cm_id = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02767 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02768 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02769 [NONE] `void ksmbd_rdma_destroy(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L02770 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02771 [NONE] `	if (smb_direct_wq) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02772 [NONE] `		destroy_workqueue(smb_direct_wq);`
  Review: Low-risk line; verify in surrounding control flow.
- L02773 [NONE] `		smb_direct_wq = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02774 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02775 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02776 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02777 [NONE] `static bool ksmbd_find_rdma_capable_netdev(struct net_device *netdev)`
  Review: Low-risk line; verify in surrounding control flow.
- L02778 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02779 [NONE] `	struct smb_direct_device *smb_dev;`
  Review: Low-risk line; verify in surrounding control flow.
- L02780 [NONE] `	int i;`
  Review: Low-risk line; verify in surrounding control flow.
- L02781 [NONE] `	bool rdma_capable = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L02782 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02783 [NONE] `	read_lock(&smb_direct_device_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L02784 [NONE] `	list_for_each_entry(smb_dev, &smb_direct_device_list, list) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02785 [NONE] `		for (i = 0; i < smb_dev->ib_dev->phys_port_cnt; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02786 [NONE] `			struct net_device *ndev;`
  Review: Low-risk line; verify in surrounding control flow.
- L02787 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02788 [NONE] `			ndev = smb_dev->ib_dev->ops.get_netdev(smb_dev->ib_dev,`
  Review: Low-risk line; verify in surrounding control flow.
- L02789 [NONE] `							       i + 1);`
  Review: Low-risk line; verify in surrounding control flow.
- L02790 [NONE] `			if (!ndev)`
  Review: Low-risk line; verify in surrounding control flow.
- L02791 [NONE] `				continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L02792 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02793 [NONE] `			if (ndev == netdev) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02794 [NONE] `				dev_put(ndev);`
  Review: Low-risk line; verify in surrounding control flow.
- L02795 [NONE] `				rdma_capable = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L02796 [ERROR_PATH|] `				goto out;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02797 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L02798 [NONE] `			dev_put(ndev);`
  Review: Low-risk line; verify in surrounding control flow.
- L02799 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02800 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02801 [NONE] `out:`
  Review: Low-risk line; verify in surrounding control flow.
- L02802 [NONE] `	read_unlock(&smb_direct_device_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L02803 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02804 [NONE] `	if (rdma_capable == false) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02805 [NONE] `		struct ib_device *ibdev;`
  Review: Low-risk line; verify in surrounding control flow.
- L02806 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02807 [NONE] `		ibdev = ib_device_get_by_netdev(netdev, RDMA_DRIVER_UNKNOWN);`
  Review: Low-risk line; verify in surrounding control flow.
- L02808 [NONE] `		if (ibdev) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02809 [NONE] `			rdma_capable = rdma_frwr_is_supported(&ibdev->attrs);`
  Review: Low-risk line; verify in surrounding control flow.
- L02810 [NONE] `			ib_device_put(ibdev);`
  Review: Low-risk line; verify in surrounding control flow.
- L02811 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02812 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02813 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02814 [NONE] `	ksmbd_debug(RDMA, "netdev(%s) rdma capable : %s\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L02815 [NONE] `		    netdev->name, rdma_capable ? "true" : "false");`
  Review: Low-risk line; verify in surrounding control flow.
- L02816 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02817 [NONE] `	return rdma_capable;`
  Review: Low-risk line; verify in surrounding control flow.
- L02818 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02819 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02820 [NONE] `bool ksmbd_rdma_capable_netdev(struct net_device *netdev)`
  Review: Low-risk line; verify in surrounding control flow.
- L02821 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02822 [NONE] `        struct net_device *lower_dev;`
  Review: Low-risk line; verify in surrounding control flow.
- L02823 [NONE] `        struct list_head *iter;`
  Review: Low-risk line; verify in surrounding control flow.
- L02824 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02825 [NONE] `        if (ksmbd_find_rdma_capable_netdev(netdev))`
  Review: Low-risk line; verify in surrounding control flow.
- L02826 [NONE] `                return true;`
  Review: Low-risk line; verify in surrounding control flow.
- L02827 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02828 [NONE] `        /* check if netdev is bridge or VLAN */`
  Review: Low-risk line; verify in surrounding control flow.
- L02829 [NONE] `        if (netif_is_bridge_master(netdev) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L02830 [NONE] `            netdev->priv_flags & IFF_802_1Q_VLAN)`
  Review: Low-risk line; verify in surrounding control flow.
- L02831 [NONE] `                netdev_for_each_lower_dev(netdev, lower_dev, iter)`
  Review: Low-risk line; verify in surrounding control flow.
- L02832 [NONE] `                        if (ksmbd_find_rdma_capable_netdev(lower_dev))`
  Review: Low-risk line; verify in surrounding control flow.
- L02833 [NONE] `                                return true;`
  Review: Low-risk line; verify in surrounding control flow.
- L02834 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02835 [NONE] `	/* check if netdev is IPoIB safely without layer violation */`
  Review: Low-risk line; verify in surrounding control flow.
- L02836 [NONE] `	if (netdev->type == ARPHRD_INFINIBAND)`
  Review: Low-risk line; verify in surrounding control flow.
- L02837 [NONE] `		return true;`
  Review: Low-risk line; verify in surrounding control flow.
- L02838 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02839 [NONE] `	return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L02840 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02841 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02842 [NONE] `static const struct ksmbd_transport_ops ksmbd_smb_direct_transport_ops = {`
  Review: Low-risk line; verify in surrounding control flow.
- L02843 [NONE] `	.prepare	= smb_direct_prepare,`
  Review: Low-risk line; verify in surrounding control flow.
- L02844 [NONE] `	.disconnect	= smb_direct_disconnect,`
  Review: Low-risk line; verify in surrounding control flow.
- L02845 [NONE] `	.shutdown	= smb_direct_shutdown,`
  Review: Low-risk line; verify in surrounding control flow.
- L02846 [NONE] `	.writev		= smb_direct_writev,`
  Review: Low-risk line; verify in surrounding control flow.
- L02847 [NONE] `	.read		= smb_direct_read,`
  Review: Low-risk line; verify in surrounding control flow.
- L02848 [NONE] `	.rdma_read	= smb_direct_rdma_read,`
  Review: Low-risk line; verify in surrounding control flow.
- L02849 [NONE] `	.rdma_write	= smb_direct_rdma_write,`
  Review: Low-risk line; verify in surrounding control flow.
- L02850 [NONE] `	.free_transport = smb_direct_free_transport,`
  Review: Low-risk line; verify in surrounding control flow.
- L02851 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
