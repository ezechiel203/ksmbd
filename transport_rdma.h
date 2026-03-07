/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *   Copyright (C) 2017, Microsoft Corporation.
 *   Copyright (C) 2018, LG Electronics.
 */

#ifndef __KSMBD_TRANSPORT_RDMA_H__
#define __KSMBD_TRANSPORT_RDMA_H__

#define SMBD_DEFAULT_IOSIZE (8 * 1024 * 1024)
#define SMBD_MIN_IOSIZE (512 * 1024)
#define SMBD_MAX_IOSIZE (16 * 1024 * 1024)

/*
 * SMB2 RDMA Transform Header [MS-SMB2] 2.2.43
 * Used for encryption/signing of RDMA read/write payloads.
 */
#define SMB2_RDMA_TRANSFORM_PROTO_ID	cpu_to_le32(0x424d53fb)

#define SMB2_RDMA_TRANSFORM_TYPE_NONE		0x0000
#define SMB2_RDMA_TRANSFORM_TYPE_ENCRYPTION	0x0001
#define SMB2_RDMA_TRANSFORM_TYPE_SIGNING	0x0002

struct smb2_rdma_transform_hdr {
	__le32 ProtocolId;	/* 0x424d53fb - SMB2_RDMA_TRANSFORM_PROTO_ID */
	__le16 StructureSize;	/* 20 */
	__le16 TransformCount;	/* Number of transforms applied */
	__le32 Reserved1;
	__le32 Reserved2;
	__le32 Reserved3;
} __packed;

#define SMB2_RDMA_TRANSFORM_HDR_SIZE	20

struct smb2_rdma_transform {
	__le16 Type;			/* ENCRYPTION(1) or SIGNING(2) */
	__le16 Reserved;
	__le32 DataOffset;		/* Offset to transformed data */
	__le32 DataLength;		/* Length of transformed data */
	__le32 RdmaDescriptorOffset;	/* Offset to RDMA descriptor */
	__le32 RdmaDescriptorLength;	/* Length of RDMA descriptor */
} __packed;

#define SMB2_RDMA_TRANSFORM_SIZE	16

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
#ifdef KSMBD_SMBDIRECT
int ksmbd_rdma_init(void);
void ksmbd_rdma_stop_listening(void);
void ksmbd_rdma_destroy(void);
bool ksmbd_rdma_capable_netdev(struct net_device *netdev);
void init_smbd_max_io_size(unsigned int sz);
unsigned int get_smbd_max_read_write_size(void);
#else
static inline int ksmbd_rdma_init(void) { return 0; }
static inline void ksmbd_rdma_stop_listening(void) { }
static inline void ksmbd_rdma_destroy(void) { }
static inline bool ksmbd_rdma_capable_netdev(struct net_device *netdev) { return false; }
static inline void init_smbd_max_io_size(unsigned int sz) { }
static inline unsigned int get_smbd_max_read_write_size(void) { return 0; }
#endif

#endif /* __KSMBD_TRANSPORT_RDMA_H__ */
