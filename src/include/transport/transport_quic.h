/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 Samsung Electronics Co., Ltd.
 *
 * Kernel-native QUIC transport for SMB over QUIC (MS-SMB2 Appendix C).
 *
 * Implements RFC 9000 (QUIC transport) and RFC 9001 (QUIC-TLS) entirely in
 * kernel space using:
 *   - Kernel UDP sockets (sock_create, kernel_sendmsg, kernel_recvmsg)
 *   - Kernel HKDF-SHA-256 (crypto/hkdf.h) for Initial secret derivation
 *   - Kernel AES-128-GCM AEAD (crypto/aead.h) for QUIC packet encryption
 *   - Kernel AES-128-ECB cipher (crypto/internal/cipher.h) for header
 *     protection (RFC 9001 §5.4)
 *   - kTLS (net/tls.h, CONFIG_TLS) for optional TLS record encryption
 *     acceleration after handshake
 *
 * Kconfig:
 *   SMB_SERVER_QUIC selects CRYPTO_AES, CRYPTO_GCM, CRYPTO_HMAC,
 *   CRYPTO_SHA256 and implies TLS.
 *
 * No third-party code (Samba, OpenSSL, etc.) is used or ported.
 * All algorithms are implemented directly from their RFCs using Linux
 * kernel crypto APIs.
 *
 * TLS 1.3 Handshake Delegation (hybrid kernel/userspace model):
 *
 *   The full TLS 1.3 handshake (ClientHello → ServerHello →
 *   EncryptedExtensions → Certificate → CertificateVerify → Finished)
 *   is delegated to the ksmbdctl userspace daemon via a dedicated
 *   Generic Netlink family ("SMBD_QUIC").
 *
 *   Flow:
 *     1. Kernel extracts CRYPTO frame data (ClientHello) from QUIC Initial
 *        packet.
 *     2. Kernel sends KSMBD_QUIC_CMD_HANDSHAKE_REQ to userspace with the
 *        raw ClientHello bytes and connection metadata.
 *     3. Userspace performs the TLS 1.3 handshake, returns
 *        KSMBD_QUIC_CMD_HANDSHAKE_RSP with derived 1-RTT keys and the
 *        server handshake flight bytes.
 *     4. Kernel sends the handshake flight back to the client in QUIC
 *        Initial / Handshake packets.
 *     5. Kernel installs 1-RTT keys and transitions to QUIC_STATE_CONNECTED.
 *
 *   Genl family constants and structs are defined here so both the kernel
 *   module and the ksmbdctl userspace tool share the same ABI.
 */

#ifndef __KSMBD_TRANSPORT_QUIC_H__
#define __KSMBD_TRANSPORT_QUIC_H__

#include <linux/types.h>

/*
 * Default SMB over QUIC port (RFC 9443 / MS-SMB2 Appendix C).
 * Port 443 is the standard HTTPS alternative port also used for
 * SMB over QUIC to traverse firewalls and NAT devices.
 */
#define KSMBD_QUIC_PORT		443

/*
 * Receive/send timeouts for the underlying UDP socket.
 * The RX thread uses MSG_DONTWAIT + wait_event; these timeouts apply to
 * synchronous kernel_recvmsg calls in corner cases.
 */
#define KSMBD_QUIC_RECV_TIMEOUT	(7 * HZ)
#define KSMBD_QUIC_SEND_TIMEOUT	(5 * HZ)

/* =========================================================================
 * QUIC Handshake IPC — Generic Netlink ABI (kernel ↔ ksmbdctl userspace)
 * =========================================================================
 *
 * A dedicated Generic Netlink family ("SMBD_QUIC", version 1) is used
 * for the QUIC TLS 1.3 handshake delegation.  This is separate from the
 * main ksmbd SMBD_GENL family to keep concerns isolated.
 *
 * Commands:
 *   KSMBD_QUIC_CMD_REGISTER         - userspace daemon registration
 *   KSMBD_QUIC_CMD_HANDSHAKE_REQ   - kernel → userspace: send ClientHello
 *   KSMBD_QUIC_CMD_HANDSHAKE_RSP   - userspace → kernel: return keys + flight
 *
 * Attribute policy: all commands carry a single NLA_BINARY attribute at
 * index KSMBD_QUIC_ATTR_PAYLOAD whose payload is the corresponding
 * struct defined below.
 */
#define KSMBD_QUIC_GENL_NAME		"SMBD_QUIC"
#define KSMBD_QUIC_GENL_VERSION		1

/* Max size of the TLS ClientHello we will accept from a QUIC client.
 * RFC 8446 §4.1.2 allows up to 2^24-1 bytes, but in practice ClientHellos
 * fit comfortably in 2 KB. */
#define KSMBD_QUIC_MAX_CLIENT_HELLO	2048

/* Max size of the server handshake flight returned by userspace.
 * This covers ServerHello + EncryptedExtensions + Certificate +
 * CertificateVerify + Finished — typically < 4 KB for a 2048-bit RSA cert,
 * generously sized to allow ECC or larger RSA keys. */
#define KSMBD_QUIC_MAX_HS_DATA		8192

/* Max key / IV sizes (accommodate AES-128-GCM and AES-256-GCM). */
#define KSMBD_QUIC_MAX_CID_LEN		20
#define KSMBD_QUIC_KEY_SIZE		32
#define KSMBD_QUIC_IV_SIZE		12

/* Cipher identifiers returned in ksmbd_quic_handshake_rsp.cipher */
#define KSMBD_QUIC_CIPHER_AES128GCM	0	/* TLS_AES_128_GCM_SHA256 */
#define KSMBD_QUIC_CIPHER_AES256GCM	1	/* TLS_AES_256_GCM_SHA384 */

/**
 * struct ksmbd_quic_handshake_req - kernel → userspace: QUIC handshake request
 *
 * Carries the raw QUIC CRYPTO stream data (i.e., the TLS ClientHello record)
 * from the first QUIC Initial packet, together with connection metadata so
 * userspace can select the right certificate and load the correct server
 * private key.
 *
 * @handle:             IPC correlation handle (matches the RSP handle)
 * @conn_id:            64-bit connection identifier (DCID bytes as u64, BE)
 * @peer_addr:          Peer's IPv4-mapped-IPv6 address (16 bytes, net order)
 * @peer_port:          Peer's UDP source port (host order)
 * @dcid_len:           Length of @dcid[]
 * @retry_validated:    True if the connection already passed Retry validation
 * @dcid:               CID the client is using as the server DCID
 * @client_hello_len:   Number of valid bytes in @client_hello[]
 * @client_hello:       Raw TLS record bytes (ClientHello), including the
 *                      TLS record header (type=22, version, length).
 */
struct ksmbd_quic_handshake_req {
	__u32	handle;
	__u64	conn_id;
	__u8	peer_addr[16];
	__u16	peer_port;
	__u16	pad;
	__u8	dcid_len;
	__u8	retry_validated;
	__u8	pad2[2];
	__u8	dcid[KSMBD_QUIC_MAX_CID_LEN];
	__u32	client_hello_len;
	__u8	client_hello[KSMBD_QUIC_MAX_CLIENT_HELLO];
} __packed;

/**
 * struct ksmbd_quic_handshake_rsp - userspace → kernel: QUIC handshake result
 *
 * Returned by ksmbdctl after performing the TLS 1.3 handshake.  Contains:
 *   - Handshake packet-space traffic secrets (server write, client write).
 *   - 1-RTT application traffic secrets (server write, client write).
 *   - The server handshake flight bytes (ServerHello through Finished),
 *     split into the bytes that belong in the QUIC Initial packet number
 *     space and the bytes that belong in the QUIC Handshake packet number
 *     space.
 *
 * @handle:             IPC correlation handle (matches the REQ handle)
 * @conn_id:            Connection identifier (must match REQ conn_id)
 * @success:            1 if handshake succeeded, 0 if it failed
 * @cipher:             KSMBD_QUIC_CIPHER_* — which AEAD suite was negotiated
 * @hs_write_key:       Server Handshake write key
 * @hs_write_iv:        Server Handshake write IV
 * @hs_write_hp:        Server Handshake header-protection key
 * @hs_read_key:        Client Handshake write key
 * @hs_read_iv:         Client Handshake write IV
 * @hs_read_hp:         Client Handshake header-protection key
 * @app_write_key:      Server 1-RTT write key
 * @app_write_iv:       Server 1-RTT write IV
 * @app_write_hp:       Server 1-RTT header-protection key
 * @app_read_key:       Client 1-RTT write key
 * @app_read_iv:        Client 1-RTT write IV
 * @app_read_hp:        Client 1-RTT header-protection key
 * @initial_data_len:   Number of bytes in @hs_data[] that belong in QUIC
 *                      Initial packets (typically ServerHello)
 * @handshake_data_len: Number of bytes in @hs_data[] that belong in QUIC
 *                      Handshake packets (EncryptedExtensions..Finished)
 * @hs_data_len:        Number of valid bytes in @hs_data[]
 * @hs_data:            Server handshake flight (ServerHello + EncryptedExts +
 *                      Certificate + CertificateVerify + Finished).
 *                      Kernel wraps these in QUIC Initial/Handshake packets
 *                      and sends them to the client.
 */
struct ksmbd_quic_handshake_rsp {
	__u32	handle;
	__u64	conn_id;
	__u8	success;
	__u8	cipher;
	__u8	pad[2];
	__u8	hs_write_key[KSMBD_QUIC_KEY_SIZE];
	__u8	hs_write_iv[KSMBD_QUIC_IV_SIZE];
	__u8	hs_write_hp[KSMBD_QUIC_KEY_SIZE];
	__u8	hs_read_key[KSMBD_QUIC_KEY_SIZE];
	__u8	hs_read_iv[KSMBD_QUIC_IV_SIZE];
	__u8	hs_read_hp[KSMBD_QUIC_KEY_SIZE];
	__u8	app_write_key[KSMBD_QUIC_KEY_SIZE];
	__u8	app_write_iv[KSMBD_QUIC_IV_SIZE];
	__u8	app_write_hp[KSMBD_QUIC_KEY_SIZE];
	__u8	app_read_key[KSMBD_QUIC_KEY_SIZE];
	__u8	app_read_iv[KSMBD_QUIC_IV_SIZE];
	__u8	app_read_hp[KSMBD_QUIC_KEY_SIZE];
	__u32	initial_data_len;
	__u32	handshake_data_len;
	__u32	hs_data_len;
	__u8	hs_data[KSMBD_QUIC_MAX_HS_DATA];
} __packed;

/**
 * enum ksmbd_quic_cmd - Generic Netlink commands for SMBD_QUIC family
 * @KSMBD_QUIC_CMD_REGISTER:      Userspace daemon registers with kernel
 * @KSMBD_QUIC_CMD_HANDSHAKE_REQ: Kernel sends ClientHello to userspace
 * @KSMBD_QUIC_CMD_HANDSHAKE_RSP: Userspace returns keys + handshake data
 * @__KSMBD_QUIC_CMD_MAX:         Sentinel
 *
 * Command IDs start at 1; genl rejects cmd=0 since kernel 6.1.
 */
enum ksmbd_quic_cmd {
	KSMBD_QUIC_CMD_REGISTER = 1,
	KSMBD_QUIC_CMD_HANDSHAKE_REQ,
	KSMBD_QUIC_CMD_HANDSHAKE_RSP,
	__KSMBD_QUIC_CMD_MAX,
};
#define KSMBD_QUIC_CMD_MAX (__KSMBD_QUIC_CMD_MAX - 1)

/**
 * enum ksmbd_quic_attr - QUIC genl attribute types
 * @KSMBD_QUIC_ATTR_UNSPEC: Reserved (must be 0)
 * @KSMBD_QUIC_ATTR_PAYLOAD: Binary payload (handshake req/rsp struct)
 * @KSMBD_QUIC_ATTR_WRITE_HP: Optional server write header-protection key
 * @KSMBD_QUIC_ATTR_READ_HP: Optional client write header-protection key
 *
 * The genl policy is indexed by attribute type, not by command number.
 * All QUIC genl commands carry a single NLA_BINARY attribute at index
 * KSMBD_QUIC_ATTR_PAYLOAD.
 */
enum ksmbd_quic_attr {
	KSMBD_QUIC_ATTR_UNSPEC = 0,
	KSMBD_QUIC_ATTR_PAYLOAD,
	KSMBD_QUIC_ATTR_WRITE_HP,
	KSMBD_QUIC_ATTR_READ_HP,
	__KSMBD_QUIC_ATTR_MAX,
};
#define KSMBD_QUIC_ATTR_MAX (__KSMBD_QUIC_ATTR_MAX - 1)

#if defined(CONFIG_SMB_SERVER_QUIC) || defined(KSMBD_TRANSPORT_QUIC_IMPL)
int ksmbd_quic_init(void);
void ksmbd_quic_destroy(void);
#else
static inline int ksmbd_quic_init(void) { return 0; }
static inline void ksmbd_quic_destroy(void) { }
#endif

#endif /* __KSMBD_TRANSPORT_QUIC_H__ */
