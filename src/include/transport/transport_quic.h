/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *   Copyright (C) 2024 Samsung Electronics Co., Ltd.
 *
 *   QUIC transport for SMB over QUIC (MS-SMB2 section 2.1).
 *   Uses a userspace QUIC proxy that terminates TLS 1.3 and forwards
 *   decrypted SMB2 stream data to the kernel via a unix domain socket.
 */

#ifndef __KSMBD_TRANSPORT_QUIC_H__
#define __KSMBD_TRANSPORT_QUIC_H__

/* Default SMB over QUIC port (RFC 9443) */
#define KSMBD_QUIC_PORT		443

/*
 * Abstract unix domain socket name used for communication between the
 * userspace QUIC proxy and the kernel QUIC transport module.
 *
 * Abstract sockets (prefixed with '\0') live in the network namespace
 * rather than the filesystem, so there is no socket file to clean up
 * on server restart and no risk of EADDRINUSE from a stale path.
 * The leading '\0' is added programmatically in create_unix_listener().
 */
#define KSMBD_QUIC_SOCK_NAME	"ksmbd-quic"

/* Receive/send timeouts for the unix domain socket bridge */
#define KSMBD_QUIC_RECV_TIMEOUT	(7 * HZ)
#define KSMBD_QUIC_SEND_TIMEOUT	(5 * HZ)

/* Maximum number of pending connections on the unix socket listener */
#define KSMBD_QUIC_BACKLOG	16

/*
 * Flags communicated from the userspace QUIC proxy to the kernel
 * via a per-connection control header on the unix domain socket.
 */
#define KSMBD_QUIC_F_TLS_VERIFIED	BIT(0)	/* client cert was verified */
#define KSMBD_QUIC_F_EARLY_DATA	BIT(1)	/* 0-RTT data present */

/**
 * struct ksmbd_quic_conn_info - per-connection metadata from proxy
 * @addr_family:	AF_INET or AF_INET6
 * @client_addr:	Client IPv4 or IPv6 address (network byte order)
 * @client_port:	Client port (host byte order)
 * @flags:		KSMBD_QUIC_F_* flags
 * @reserved:		Padding for alignment
 *
 * Sent by the userspace QUIC proxy as the first message on each
 * accepted unix domain socket connection, before any SMB2 data.
 */
struct ksmbd_quic_conn_info {
	__u16		addr_family;	/* AF_INET or AF_INET6 */
	__u16		client_port;
	__u16		flags;
	__u16		reserved;
	union {
		__be32	v4;		/* IPv4 address */
		__u8	v6[16];		/* IPv6 address */
	} client_addr;
} __packed;

#ifdef CONFIG_SMB_SERVER_QUIC
int ksmbd_quic_init(void);
void ksmbd_quic_destroy(void);
#else
static inline int ksmbd_quic_init(void) { return 0; }
static inline void ksmbd_quic_destroy(void) { }
#endif

#endif /* __KSMBD_TRANSPORT_QUIC_H__ */
