# Line-by-line Review: src/include/transport/transport_quic.h

- L00001 [NONE] `/* SPDX-License-Identifier: GPL-2.0-or-later */`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` * Copyright (C) 2024 Samsung Electronics Co., Ltd.`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ` * Kernel-native QUIC transport for SMB over QUIC (MS-SMB2 Appendix C).`
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] ` * Implements RFC 9000 (QUIC transport) and RFC 9001 (QUIC-TLS) entirely in`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] ` * kernel space using:`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] ` *   - Kernel UDP sockets (sock_create, kernel_sendmsg, kernel_recvmsg)`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] ` *   - Kernel HKDF-SHA-256 (crypto/hkdf.h) for Initial secret derivation`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] ` *   - Kernel AES-128-GCM AEAD (crypto/aead.h) for QUIC packet encryption`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] ` *   - Kernel AES-128-ECB cipher (crypto/internal/cipher.h) for header`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] ` *     protection (RFC 9001 §5.4)`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] ` *   - kTLS (net/tls.h, CONFIG_TLS) for optional TLS record encryption`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] ` *     acceleration after handshake`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] ` * Kconfig:`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] ` *   SMB_SERVER_QUIC selects CRYPTO_AES, CRYPTO_GCM, CRYPTO_HMAC,`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] ` *   CRYPTO_SHA256 and implies TLS.`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] ` * No third-party code (Samba, OpenSSL, etc.) is used or ported.`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] ` * All algorithms are implemented directly from their RFCs using Linux`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] ` * kernel crypto APIs.`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] ` * TLS 1.3 Handshake Delegation (hybrid kernel/userspace model):`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] ` *   The full TLS 1.3 handshake (ClientHello → ServerHello →`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] ` *   EncryptedExtensions → Certificate → CertificateVerify → Finished)`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] ` *   is delegated to the ksmbdctl userspace daemon via a dedicated`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] ` *   Generic Netlink family ("SMBD_QUIC").`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] ` *   Flow:`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] ` *     1. Kernel extracts CRYPTO frame data (ClientHello) from QUIC Initial`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] ` *        packet.`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] ` *     2. Kernel sends KSMBD_QUIC_CMD_HANDSHAKE_REQ to userspace with the`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] ` *        raw ClientHello bytes and connection metadata.`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] ` *     3. Userspace performs the TLS 1.3 handshake, returns`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] ` *        KSMBD_QUIC_CMD_HANDSHAKE_RSP with derived 1-RTT keys and the`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] ` *        server handshake flight bytes.`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] ` *     4. Kernel sends the handshake flight back to the client in QUIC`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] ` *        Initial / Handshake packets.`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] ` *     5. Kernel installs 1-RTT keys and transitions to QUIC_STATE_CONNECTED.`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] ` *   Genl family constants and structs are defined here so both the kernel`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] ` *   module and the ksmbdctl userspace tool share the same ABI.`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] `#ifndef __KSMBD_TRANSPORT_QUIC_H__`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `#define __KSMBD_TRANSPORT_QUIC_H__`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] `#include <linux/types.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] ` * Default SMB over QUIC port (RFC 9443 / MS-SMB2 Appendix C).`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] ` * Port 443 is the standard HTTPS alternative port also used for`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] ` * SMB over QUIC to traverse firewalls and NAT devices.`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] `#define KSMBD_QUIC_PORT		443`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] ` * Receive/send timeouts for the underlying UDP socket.`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [WAIT_LOOP|] ` * The RX thread uses MSG_DONTWAIT + wait_event; these timeouts apply to`
  Review: Bounded wait and cancellation path must be guaranteed.
- L00063 [NONE] ` * synchronous kernel_recvmsg calls in corner cases.`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `#define KSMBD_QUIC_RECV_TIMEOUT	(7 * HZ)`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] `#define KSMBD_QUIC_SEND_TIMEOUT	(5 * HZ)`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `/* =========================================================================`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] ` * QUIC Handshake IPC — Generic Netlink ABI (kernel ↔ ksmbdctl userspace)`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] ` * =========================================================================`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] ` * A dedicated Generic Netlink family ("SMBD_QUIC", version 1) is used`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] ` * for the QUIC TLS 1.3 handshake delegation.  This is separate from the`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] ` * main ksmbd SMBD_GENL family to keep concerns isolated.`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] ` * Commands:`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] ` *   KSMBD_QUIC_CMD_UNSPEC          - unused placeholder`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] ` *   KSMBD_QUIC_CMD_HANDSHAKE_REQ   - kernel → userspace: send ClientHello`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] ` *   KSMBD_QUIC_CMD_HANDSHAKE_RSP   - userspace → kernel: return keys + flight`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] ` * Attribute policy: each command carries a single NLA_BINARY attribute`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] ` * (same index as the command) whose payload is the corresponding struct`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] ` * defined below.`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] `#define KSMBD_QUIC_GENL_NAME		"SMBD_QUIC"`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] `#define KSMBD_QUIC_GENL_VERSION		1`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] `/* Max size of the TLS ClientHello we will accept from a QUIC client.`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] ` * RFC 8446 §4.1.2 allows up to 2^24-1 bytes, but in practice ClientHellos`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] ` * fit comfortably in 2 KB. */`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] `#define KSMBD_QUIC_MAX_CLIENT_HELLO	2048`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] `/* Max size of the server handshake flight returned by userspace.`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] ` * This covers ServerHello + EncryptedExtensions + Certificate +`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] ` * CertificateVerify + Finished — typically < 4 KB for a 2048-bit RSA cert,`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] ` * generously sized to allow ECC or larger RSA keys. */`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] `#define KSMBD_QUIC_MAX_HS_DATA		8192`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] `/* Max key / IV sizes (accommodate AES-128-GCM and AES-256-GCM). */`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] `#define KSMBD_QUIC_KEY_SIZE		32`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] `#define KSMBD_QUIC_IV_SIZE		12`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] `/* Cipher identifiers returned in ksmbd_quic_handshake_rsp.cipher */`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] `#define KSMBD_QUIC_CIPHER_AES128GCM	0	/* TLS_AES_128_GCM_SHA256 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] `#define KSMBD_QUIC_CIPHER_AES256GCM	1	/* TLS_AES_256_GCM_SHA384 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] ` * struct ksmbd_quic_handshake_req - kernel → userspace: QUIC handshake request`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] ` * Carries the raw QUIC CRYPTO stream data (i.e., the TLS ClientHello record)`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] ` * from the first QUIC Initial packet, together with connection metadata so`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] ` * userspace can select the right certificate and load the correct server`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] ` * private key.`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] ` * @handle:             IPC correlation handle (matches the RSP handle)`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] ` * @conn_id:            64-bit connection identifier (DCID bytes as u64, BE)`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] ` * @peer_addr:          Peer's IPv4-mapped-IPv6 address (16 bytes, net order)`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] ` * @peer_port:          Peer's UDP source port (host order)`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] ` * @client_hello_len:   Number of valid bytes in @client_hello[]`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] ` * @client_hello:       Raw TLS record bytes (ClientHello), including the`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] ` *                      TLS record header (type=22, version, length).`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] `struct ksmbd_quic_handshake_req {`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] `	__u32	handle;`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] `	__u64	conn_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] `	__u8	peer_addr[16];`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] `	__u16	peer_port;`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] `	__u16	pad;`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] `	__u32	client_hello_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] `	__u8	client_hello[KSMBD_QUIC_MAX_CLIENT_HELLO];`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] ` * struct ksmbd_quic_handshake_rsp - userspace → kernel: QUIC handshake result`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] ` * Returned by ksmbdctl after performing the TLS 1.3 handshake.  Contains:`
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] ` *   - The 1-RTT application traffic secrets (write key/IV from the server's`
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] ` *     perspective, read key/IV from the server's perspective).`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] ` *   - The server handshake flight bytes (ServerHello through Finished) that`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] ` *     the kernel must send back to the client inside QUIC Initial/Handshake`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] ` *     packets.`
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] ` * @handle:             IPC correlation handle (matches the REQ handle)`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] ` * @conn_id:            Connection identifier (must match REQ conn_id)`
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] ` * @success:            1 if handshake succeeded, 0 if it failed`
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] ` * @cipher:             KSMBD_QUIC_CIPHER_* — which AEAD suite was negotiated`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] ` * @write_key:          Server write key (AEAD key for sending to client)`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] ` * @write_iv:           Server write IV (base nonce)`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] ` * @read_key:           Client write key (AEAD key for receiving from client)`
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] ` * @read_iv:            Client write IV (base nonce)`
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] ` * @hs_data_len:        Number of valid bytes in @hs_data[]`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] ` * @hs_data:            Server handshake flight (ServerHello + EncryptedExts +`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] ` *                      Certificate + CertificateVerify + Finished).`
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] ` *                      Kernel wraps these in QUIC Initial/Handshake packets`
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] ` *                      and sends them to the client.`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] `struct ksmbd_quic_handshake_rsp {`
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] `	__u32	handle;`
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] `	__u64	conn_id;`
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [NONE] `	__u8	success;`
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] `	__u8	cipher;`
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] `	__u8	pad[2];`
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] `	__u8	write_key[KSMBD_QUIC_KEY_SIZE];`
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] `	__u8	write_iv[KSMBD_QUIC_IV_SIZE];`
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] `	__u8	read_key[KSMBD_QUIC_KEY_SIZE];`
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] `	__u8	read_iv[KSMBD_QUIC_IV_SIZE];`
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] `	__u32	hs_data_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] `	__u8	hs_data[KSMBD_QUIC_MAX_HS_DATA];`
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] ` * enum ksmbd_quic_cmd - Generic Netlink commands for SMBD_QUIC family`
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] ` * @KSMBD_QUIC_CMD_UNSPEC:        Unused placeholder (genl convention)`
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [NONE] ` * @KSMBD_QUIC_CMD_HANDSHAKE_REQ: Kernel sends ClientHello to userspace`
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [NONE] ` * @KSMBD_QUIC_CMD_HANDSHAKE_RSP: Userspace returns keys + handshake data`
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [NONE] ` * @__KSMBD_QUIC_CMD_MAX:         Sentinel`
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00178 [NONE] `enum ksmbd_quic_cmd {`
  Review: Low-risk line; verify in surrounding control flow.
- L00179 [NONE] `	KSMBD_QUIC_CMD_UNSPEC = 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L00180 [NONE] `	KSMBD_QUIC_CMD_HANDSHAKE_REQ,`
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [NONE] `	KSMBD_QUIC_CMD_HANDSHAKE_RSP,`
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [NONE] `	__KSMBD_QUIC_CMD_MAX,`
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00184 [NONE] `#define KSMBD_QUIC_CMD_MAX (__KSMBD_QUIC_CMD_MAX - 1)`
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00186 [NONE] `#ifdef CONFIG_SMB_SERVER_QUIC`
  Review: Low-risk line; verify in surrounding control flow.
- L00187 [NONE] `int ksmbd_quic_init(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00188 [NONE] `void ksmbd_quic_destroy(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L00190 [NONE] `static inline int ksmbd_quic_init(void) { return 0; }`
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [NONE] `static inline void ksmbd_quic_destroy(void) { }`
  Review: Low-risk line; verify in surrounding control flow.
- L00192 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00193 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00194 [NONE] `#endif /* __KSMBD_TRANSPORT_QUIC_H__ */`
  Review: Low-risk line; verify in surrounding control flow.
