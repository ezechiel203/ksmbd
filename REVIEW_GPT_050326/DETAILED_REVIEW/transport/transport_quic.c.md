# Line-by-line Review: src/transport/transport_quic.c

- L00001 [NONE] `// SPDX-License-Identifier: GPL-2.0-or-later`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` * Copyright (C) 2024 Samsung Electronics Co., Ltd.`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ` * Kernel-native QUIC transport for ksmbd — SMB over QUIC (MS-SMB2 Appendix C).`
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] ` * This replaces the userspace-proxy approach with a kernel UDP socket that`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] ` * handles QUIC packet framing directly per RFC 9000/RFC 9001.`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] ` * Architecture:`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] ` *   SMB Client --(QUIC/TLS 1.3 over UDP port 443)--> [ksmbd kernel module]`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] ` * QUIC crypto dependencies (all kernel-internal, NO third-party code):`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] ` *   - HKDF-SHA-256    : crypto/hkdf.h  (kernel >= 6.9, RFC 5869)`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] ` *   - AES-128-GCM     : crypto/aead.h  (RFC 9001 §5)`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] ` *   - AES-128-ECB     : crypto/internal/cipher.h (packet number protection,`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] ` *                        RFC 9001 §5.4)`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] ` *   - kTLS            : net/tls.h (CONFIG_TLS) for TLS record encryption`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] ` * SMB over QUIC specifics (MS-SMB2 Appendix C, RFC 9443):`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] ` *   - No RFC1002 NetBIOS 4-byte length prefix on QUIC (unlike TCP).`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] ` *   - Each SMB session maps to one bidirectional QUIC stream (stream ID 0).`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] ` *   - Port 443 (HTTPS alternative port, also used for SMB over QUIC).`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] ` * Implementation notes:`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] ` *   - QUIC Initial packets: long-header, AEAD-AES-128-GCM, keys from HKDF.`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] ` *   - QUIC 1-RTT packets: short-header, AEAD, keys from TLS 1.3 handshake.`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] ` *   - kTLS path: after handshake, SOL_TLS/TLS_TX/TLS_RX installed into UDP`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] ` *     socket for hardware-offloaded or software TLS record encryption.`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] ` *   - Listener: UDP socket bound to port 443; rx thread dispatches packets.`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] ` * TLS 1.3 Handshake Delegation:`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] ` *   The full TLS 1.3 handshake is delegated to the ksmbdctl userspace daemon`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] ` *   via a dedicated Generic Netlink family (SMBD_QUIC).  When a QUIC Initial`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] ` *   packet is received:`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] ` *     1. CRYPTO frame data (ClientHello) is extracted.`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] ` *     2. A KSMBD_QUIC_CMD_HANDSHAKE_REQ is sent to userspace.`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] ` *     3. Userspace performs TLS 1.3, returns KSMBD_QUIC_CMD_HANDSHAKE_RSP`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] ` *        with 1-RTT session keys and the server handshake flight.`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] ` *     4. Kernel transmits the server flight in QUIC Initial/Handshake packets.`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] ` *     5. 1-RTT keys are installed; state transitions to CONNECTED.`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] ` * Kconfig dependencies (see comment in Kconfig):`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] ` *   SMB_SERVER_QUIC selects CRYPTO_AES, CRYPTO_GCM, CRYPTO_HMAC,`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] ` *   CRYPTO_SHA256; imply TLS for optional kTLS acceleration.`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `#define SUBMOD_NAME	"smb_quic"`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] `#include <linux/kthread.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] `#include <linux/net.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `#include <linux/stddef.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `#include <linux/file.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] `#include <linux/freezer.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `#include <linux/hashtable.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] `#include <linux/cred.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] `#include <linux/pid.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] `#include <linux/udp.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] `#include <linux/in.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] `#include <linux/in6.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] `#include <linux/socket.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] `#include <linux/version.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] `#include <linux/random.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `#include <linux/slab.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] `#include <linux/skbuff.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] `#include <linux/wait.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `#include <linux/spinlock.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] `#include <linux/completion.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] `#include <linux/jhash.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] `#include <linux/rwsem.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] `#include <linux/idr.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] `#include <net/sock.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] `#include <net/ip.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] `#include <net/udp.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] `#include <net/genetlink.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] `#include <crypto/hash.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] `#include <crypto/hkdf.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] `#include <crypto/aead.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] `#include <crypto/internal/cipher.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] `#include <uapi/linux/tls.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] `#if IS_ENABLED(CONFIG_TLS)`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] `#include <net/tls.h>`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] `#include "glob.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] `#include "connection.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] `#include "smb_common.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] `#include "server.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] `#include "transport_quic.h"`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] `/* =========================================================================`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] ` * QUIC constants (RFC 9000, RFC 9001)`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] ` * =========================================================================`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] `/* QUIC version 1 (RFC 9000 §15) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] `#define QUIC_VERSION_1			0x00000001U`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] `/* Long-header first-byte flags (RFC 9000 §17.2) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] `#define QUIC_HDR_FORM_LONG		0x80	/* Header Form = 1 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] `#define QUIC_HDR_FIXED_BIT		0x40	/* Fixed Bit = 1 (MUST be 1) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] `#define QUIC_LONG_TYPE_INITIAL		0x00	/* Packet Type = Initial */`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] `#define QUIC_LONG_TYPE_HANDSHAKE	0x20	/* Packet Type = Handshake */`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] `#define QUIC_LONG_TYPE_RETRY		0x30	/* Packet Type = Retry */`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] `/* Short-header first-byte flags (RFC 9000 §17.3) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] `#define QUIC_HDR_SHORT_SPIN		0x20	/* Spin bit */`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] `#define QUIC_HDR_SHORT_KEY_PHASE	0x04	/* Key phase */`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] `#define QUIC_HDR_SHORT_PKT_NUM_MASK	0x03	/* Packet number length - 1 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] `/* Max DCID / SCID length (RFC 9000 §17.2) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] `#define QUIC_MAX_CID_LEN		20`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] `/* QUIC Initial salt for QUIC v1 (RFC 9001 §A.1) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] `static const u8 quic_v1_initial_salt[20] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] `	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] `	0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] `	0xcc, 0xbb, 0x7f, 0x0a`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] `/* HKDF label prefix for QUIC (RFC 9001 §5.1) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] `#define QUIC_HKDF_LABEL_PREFIX		"tls13 quic "`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] `/* QUIC Initial key/IV/HP label strings (RFC 9001 §5.2) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] `#define QUIC_LABEL_CLIENT_IN		"client in"`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] `#define QUIC_LABEL_SERVER_IN		"server in"`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] `#define QUIC_LABEL_QUIC_KEY		"quic key"`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] `#define QUIC_LABEL_QUIC_IV		"quic iv"`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] `#define QUIC_LABEL_QUIC_HP		"quic hp"`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] `/* AES-128-GCM parameters */`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] `#define QUIC_AEAD_KEY_SIZE		16`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] `#define QUIC_AEAD_IV_SIZE		12`
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] `#define QUIC_AEAD_TAG_SIZE		16`
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] `#define QUIC_HP_KEY_SIZE		16`
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] `/* Maximum QUIC packet size we process (one UDP datagram) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] `#define QUIC_MAX_PKT_SIZE		1500`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] `/* Maximum SMB PDU size buffered per connection */`
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] `#define QUIC_STREAM_BUF_SIZE		(128 * 1024)`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] `/* QUIC STREAM frame type bits (RFC 9000 §19.8) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] `#define QUIC_FRAME_STREAM		0x08`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] `#define QUIC_FRAME_STREAM_FIN		0x01`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] `#define QUIC_FRAME_STREAM_LEN		0x02`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] `#define QUIC_FRAME_STREAM_OFF		0x04`
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] `#define QUIC_FRAME_PADDING		0x00`
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] `#define QUIC_FRAME_PING			0x01`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] `#define QUIC_FRAME_CRYPTO		0x06`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] `#define QUIC_FRAME_ACK			0x02`
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] ` * CONNECTION_CLOSE frame types (RFC 9000 §19.19):`
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] ` *   0x1c — carries a QUIC transport error code`
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] ` *   0x1d — carries an application protocol error code`
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [NONE] `#define QUIC_FRAME_CONNECTION_CLOSE		0x1c`
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] `#define QUIC_FRAME_CONNECTION_CLOSE_APP		0x1d`
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] `/* QUIC transport error codes (RFC 9000 §20) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] `#define QUIC_ERR_NO_ERROR			0x00`
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] `#define QUIC_ERR_INTERNAL_ERROR			0x01`
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] `#define QUIC_ERR_CONNECTION_REFUSED		0x02`
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] `#define QUIC_ERR_FLOW_CONTROL_ERROR		0x03`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] `#define QUIC_ERR_STREAM_LIMIT_ERROR		0x04`
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] `#define QUIC_ERR_STREAM_STATE_ERROR		0x05`
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] `#define QUIC_ERR_FINAL_SIZE_ERROR		0x06`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] `#define QUIC_ERR_FRAME_ENCODING_ERROR		0x07`
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] `#define QUIC_ERR_TRANSPORT_PARAMETER_ERROR	0x08`
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] `#define QUIC_ERR_CONNECTION_ID_LIMIT_ERROR	0x09`
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [NONE] `#define QUIC_ERR_PROTOCOL_VIOLATION		0x0a`
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [NONE] `#define QUIC_ERR_INVALID_TOKEN			0x0b`
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [NONE] `#define QUIC_ERR_APPLICATION_ERROR		0x0c`
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [NONE] `#define QUIC_ERR_CRYPTO_BUFFER_EXCEEDED		0x0d`
  Review: Low-risk line; verify in surrounding control flow.
- L00178 [NONE] `#define QUIC_ERR_KEY_UPDATE_ERROR		0x0e`
  Review: Low-risk line; verify in surrounding control flow.
- L00179 [NONE] `#define QUIC_ERR_AEAD_LIMIT_REACHED		0x0f`
  Review: Low-risk line; verify in surrounding control flow.
- L00180 [NONE] `#define QUIC_ERR_CRYPTO_BASE			0x0100	/* + TLS alert code */`
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [NONE] `/* Max ClientHello data we buffer from CRYPTO frames (same as header define) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [NONE] `#define QUIC_MAX_CRYPTO_DATA	KSMBD_QUIC_MAX_CLIENT_HELLO`
  Review: Low-risk line; verify in surrounding control flow.
- L00184 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [NONE] `/* Handshake IPC wait timeout: 30 seconds to allow cert load + TLS handshake */`
  Review: Low-risk line; verify in surrounding control flow.
- L00186 [NONE] `#define QUIC_HS_IPC_TIMEOUT_MS	30000`
  Review: Low-risk line; verify in surrounding control flow.
- L00187 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00188 [NONE] `/* Connection state machine */`
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [NONE] `enum quic_conn_state {`
  Review: Low-risk line; verify in surrounding control flow.
- L00190 [NONE] `	QUIC_STATE_INITIAL = 0,	/* Waiting for Initial packet */`
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [NONE] `	QUIC_STATE_HANDSHAKE,	/* TLS handshake in progress */`
  Review: Low-risk line; verify in surrounding control flow.
- L00192 [NONE] `	QUIC_STATE_CONNECTED,	/* 1-RTT: data can flow */`
  Review: Low-risk line; verify in surrounding control flow.
- L00193 [NONE] `	QUIC_STATE_CLOSING,	/* CONNECTION_CLOSE sent/received */`
  Review: Low-risk line; verify in surrounding control flow.
- L00194 [NONE] `	QUIC_STATE_CLOSED,	/* Connection fully closed */`
  Review: Low-risk line; verify in surrounding control flow.
- L00195 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00196 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00197 [NONE] `/* =========================================================================`
  Review: Low-risk line; verify in surrounding control flow.
- L00198 [NONE] ` * Per-connection QUIC state`
  Review: Low-risk line; verify in surrounding control flow.
- L00199 [NONE] ` * =========================================================================`
  Review: Low-risk line; verify in surrounding control flow.
- L00200 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00201 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00202 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00203 [NONE] ` * struct ksmbd_quic_crypto - AEAD keys for one QUIC packet number space`
  Review: Low-risk line; verify in surrounding control flow.
- L00204 [NONE] ` * @key:	AEAD encryption/decryption key`
  Review: Low-risk line; verify in surrounding control flow.
- L00205 [NONE] ` * @iv:		AEAD IV (base nonce)`
  Review: Low-risk line; verify in surrounding control flow.
- L00206 [NONE] ` * @hp:		Header protection key (AES-128-ECB)`
  Review: Low-risk line; verify in surrounding control flow.
- L00207 [NONE] ` * @key_len:	Valid length of @key`
  Review: Low-risk line; verify in surrounding control flow.
- L00208 [NONE] ` * @ready:	true when keys have been derived`
  Review: Low-risk line; verify in surrounding control flow.
- L00209 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00210 [NONE] `struct ksmbd_quic_crypto {`
  Review: Low-risk line; verify in surrounding control flow.
- L00211 [NONE] `	u8	key[QUIC_AEAD_KEY_SIZE];`
  Review: Low-risk line; verify in surrounding control flow.
- L00212 [NONE] `	u8	iv[QUIC_AEAD_IV_SIZE];`
  Review: Low-risk line; verify in surrounding control flow.
- L00213 [NONE] `	u8	hp[QUIC_HP_KEY_SIZE];`
  Review: Low-risk line; verify in surrounding control flow.
- L00214 [NONE] `	u8	key_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00215 [NONE] `	bool	ready;`
  Review: Low-risk line; verify in surrounding control flow.
- L00216 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00217 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00218 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00219 [NONE] ` * struct ksmbd_quic_app_crypto - 1-RTT (application) AEAD keys`
  Review: Low-risk line; verify in surrounding control flow.
- L00220 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00221 [NONE] ` * These keys are derived by the TLS 1.3 handshake (performed in userspace)`
  Review: Low-risk line; verify in surrounding control flow.
- L00222 [NONE] ` * and installed into the kernel after the handshake completes.`
  Review: Low-risk line; verify in surrounding control flow.
- L00223 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00224 [NONE] ` * @write_key:	Server write key (used to encrypt packets sent to client)`
  Review: Low-risk line; verify in surrounding control flow.
- L00225 [NONE] ` * @write_iv:	Server write IV (base nonce for AEAD)`
  Review: Low-risk line; verify in surrounding control flow.
- L00226 [NONE] ` * @read_key:	Client write key (used to decrypt packets received from client)`
  Review: Low-risk line; verify in surrounding control flow.
- L00227 [NONE] ` * @read_iv:	Client write IV`
  Review: Low-risk line; verify in surrounding control flow.
- L00228 [NONE] ` * @key_len:	Key length in bytes (16 for AES-128-GCM, 32 for AES-256-GCM)`
  Review: Low-risk line; verify in surrounding control flow.
- L00229 [NONE] ` * @ready:	true once keys have been installed from the handshake result`
  Review: Low-risk line; verify in surrounding control flow.
- L00230 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00231 [NONE] `struct ksmbd_quic_app_crypto {`
  Review: Low-risk line; verify in surrounding control flow.
- L00232 [NONE] `	u8	write_key[KSMBD_QUIC_KEY_SIZE];`
  Review: Low-risk line; verify in surrounding control flow.
- L00233 [NONE] `	u8	write_iv[KSMBD_QUIC_IV_SIZE];`
  Review: Low-risk line; verify in surrounding control flow.
- L00234 [NONE] `	u8	read_key[KSMBD_QUIC_KEY_SIZE];`
  Review: Low-risk line; verify in surrounding control flow.
- L00235 [NONE] `	u8	read_iv[KSMBD_QUIC_IV_SIZE];`
  Review: Low-risk line; verify in surrounding control flow.
- L00236 [NONE] `	u8	key_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00237 [NONE] `	bool	ready;`
  Review: Low-risk line; verify in surrounding control flow.
- L00238 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00239 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00240 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00241 [NONE] ` * struct ksmbd_quic_conn - kernel-native QUIC per-connection state`
  Review: Low-risk line; verify in surrounding control flow.
- L00242 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00243 [NONE] ` * Each accepted QUIC connection (identified by its DCID) owns one of these.`
  Review: Low-risk line; verify in surrounding control flow.
- L00244 [NONE] ` * Created when we receive the first Initial packet from a new peer.`
  Review: Low-risk line; verify in surrounding control flow.
- L00245 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00246 [NONE] ` * @hlist:	Hash list node (keyed on dcid, stored in quic_conn_table)`
  Review: Low-risk line; verify in surrounding control flow.
- L00247 [NONE] ` * @state:	Connection state machine (enum quic_conn_state)`
  Review: Low-risk line; verify in surrounding control flow.
- L00248 [NONE] ` * @peer:	Peer UDP address (filled from recvmsg)`
  Review: Low-risk line; verify in surrounding control flow.
- L00249 [NONE] ` * @peer_addrlen: Length of @peer`
  Review: Low-risk line; verify in surrounding control flow.
- L00250 [NONE] ` * @dcid:	Destination CID (our SCID as seen by the peer)`
  Review: Low-risk line; verify in surrounding control flow.
- L00251 [NONE] ` * @scid:	Source CID (peer's DCID as seen by us)`
  Review: Low-risk line; verify in surrounding control flow.
- L00252 [NONE] ` * @dcid_len:	Length of @dcid`
  Review: Low-risk line; verify in surrounding control flow.
- L00253 [NONE] ` * @scid_len:	Length of @scid`
  Review: Low-risk line; verify in surrounding control flow.
- L00254 [NONE] ` * @initial_tx:	TX crypto for Initial packet number space`
  Review: Low-risk line; verify in surrounding control flow.
- L00255 [NONE] ` * @initial_rx:	RX crypto for Initial packet number space`
  Review: Low-risk line; verify in surrounding control flow.
- L00256 [NONE] ` * @app_crypto:	1-RTT application traffic keys (installed after TLS handshake)`
  Review: Low-risk line; verify in surrounding control flow.
- L00257 [NONE] ` * @send_pkt_num: Next packet number to use (monotonically increasing)`
  Review: Low-risk line; verify in surrounding control flow.
- L00258 [NONE] ` * @recv_pkt_num: Largest received packet number (for ACK generation)`
  Review: Low-risk line; verify in surrounding control flow.
- L00259 [NONE] ` * @lock:	Spinlock protecting this struct`
  Review: Low-risk line; verify in surrounding control flow.
- L00260 [NONE] ` * @stream_buf: Reassembly buffer for incoming SMB PDU data from STREAM frames`
  Review: Low-risk line; verify in surrounding control flow.
- L00261 [NONE] ` * @stream_len: Number of bytes currently in @stream_buf`
  Review: Low-risk line; verify in surrounding control flow.
- L00262 [NONE] ` * @stream_max: Allocated size of @stream_buf`
  Review: Low-risk line; verify in surrounding control flow.
- L00263 [NONE] ` * @crypto_buf:	Buffer for CRYPTO stream data (ClientHello bytes from Initial)`
  Review: Low-risk line; verify in surrounding control flow.
- L00264 [NONE] ` * @crypto_len:	Number of bytes buffered in @crypto_buf`
  Review: Low-risk line; verify in surrounding control flow.
- L00265 [NONE] ` * @hs_done:	Completion: signalled when handshake IPC response arrives`
  Review: Low-risk line; verify in surrounding control flow.
- L00266 [NONE] ` * @wait:	Wait queue: SMB handler thread sleeps here for data`
  Review: Low-risk line; verify in surrounding control flow.
- L00267 [NONE] ` * @smb_conn:	ksmbd connection object (non-NULL once CONNECTED)`
  Review: Low-risk line; verify in surrounding control flow.
- L00268 [NONE] ` * @udp_sock:	Shared UDP listener socket (we send via this)`
  Review: Low-risk line; verify in surrounding control flow.
- L00269 [NONE] ` * @ipc_handle:	IPC correlation handle for the pending HANDSHAKE_REQ`
  Review: Low-risk line; verify in surrounding control flow.
- L00270 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00271 [NONE] `struct ksmbd_quic_conn {`
  Review: Low-risk line; verify in surrounding control flow.
- L00272 [NONE] `	struct hlist_node		hlist;`
  Review: Low-risk line; verify in surrounding control flow.
- L00273 [NONE] `	enum quic_conn_state		state;`
  Review: Low-risk line; verify in surrounding control flow.
- L00274 [NONE] `	struct sockaddr_storage		peer;`
  Review: Low-risk line; verify in surrounding control flow.
- L00275 [NONE] `	int				peer_addrlen;`
  Review: Low-risk line; verify in surrounding control flow.
- L00276 [NONE] `	u8				dcid[QUIC_MAX_CID_LEN];`
  Review: Low-risk line; verify in surrounding control flow.
- L00277 [NONE] `	u8				scid[QUIC_MAX_CID_LEN];`
  Review: Low-risk line; verify in surrounding control flow.
- L00278 [NONE] `	u8				dcid_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00279 [NONE] `	u8				scid_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00280 [NONE] `	struct ksmbd_quic_crypto	initial_tx;`
  Review: Low-risk line; verify in surrounding control flow.
- L00281 [NONE] `	struct ksmbd_quic_crypto	initial_rx;`
  Review: Low-risk line; verify in surrounding control flow.
- L00282 [NONE] `	struct ksmbd_quic_app_crypto	app_crypto;`
  Review: Low-risk line; verify in surrounding control flow.
- L00283 [NONE] `	u64				send_pkt_num;`
  Review: Low-risk line; verify in surrounding control flow.
- L00284 [NONE] `	u64				recv_pkt_num;`
  Review: Low-risk line; verify in surrounding control flow.
- L00285 [NONE] `	spinlock_t			lock;`
  Review: Low-risk line; verify in surrounding control flow.
- L00286 [NONE] `	/* SMB PDU reassembly buffer (data from QUIC STREAM frames) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00287 [NONE] `	u8				*stream_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00288 [NONE] `	size_t				stream_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00289 [NONE] `	size_t				stream_max;`
  Review: Low-risk line; verify in surrounding control flow.
- L00290 [NONE] `	/* CRYPTO stream buffer (ClientHello from Initial packets) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00291 [NONE] `	u8				crypto_buf[QUIC_MAX_CRYPTO_DATA];`
  Review: Low-risk line; verify in surrounding control flow.
- L00292 [NONE] `	size_t				crypto_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00293 [NONE] `	/* Handshake IPC synchronisation */`
  Review: Low-risk line; verify in surrounding control flow.
- L00294 [NONE] `	struct completion		hs_done;`
  Review: Low-risk line; verify in surrounding control flow.
- L00295 [NONE] `	int				ipc_handle;`
  Review: Low-risk line; verify in surrounding control flow.
- L00296 [NONE] `	wait_queue_head_t		wait;`
  Review: Low-risk line; verify in surrounding control flow.
- L00297 [NONE] `	struct ksmbd_conn		*smb_conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00298 [NONE] `	struct socket			*udp_sock;`
  Review: Low-risk line; verify in surrounding control flow.
- L00299 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00300 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00301 [NONE] `/* =========================================================================`
  Review: Low-risk line; verify in surrounding control flow.
- L00302 [NONE] ` * Per-connection transport wrapper (plugs into ksmbd_transport_ops)`
  Review: Low-risk line; verify in surrounding control flow.
- L00303 [NONE] ` * =========================================================================`
  Review: Low-risk line; verify in surrounding control flow.
- L00304 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00305 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00306 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00307 [NONE] ` * struct quic_transport - ksmbd transport adapter for a QUIC connection`
  Review: Low-risk line; verify in surrounding control flow.
- L00308 [NONE] ` * @transport:	Embedded ksmbd_transport (must be first for container_of)`
  Review: Low-risk line; verify in surrounding control flow.
- L00309 [NONE] ` * @qconn:	Underlying QUIC connection state`
  Review: Low-risk line; verify in surrounding control flow.
- L00310 [NONE] ` * @iov:	Reusable iovec scratch buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00311 [NONE] ` * @nr_iov:	Number of segments in @iov`
  Review: Low-risk line; verify in surrounding control flow.
- L00312 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00313 [NONE] `struct quic_transport {`
  Review: Low-risk line; verify in surrounding control flow.
- L00314 [NONE] `	struct ksmbd_transport		transport;`
  Review: Low-risk line; verify in surrounding control flow.
- L00315 [NONE] `	struct ksmbd_quic_conn		*qconn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00316 [NONE] `	struct kvec			*iov;`
  Review: Low-risk line; verify in surrounding control flow.
- L00317 [NONE] `	unsigned int			nr_iov;`
  Review: Low-risk line; verify in surrounding control flow.
- L00318 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00319 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00320 [NONE] `static const struct ksmbd_transport_ops ksmbd_quic_transport_ops;`
  Review: Low-risk line; verify in surrounding control flow.
- L00321 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00322 [NONE] `#define KSMBD_TRANS(t)	(&(t)->transport)`
  Review: Low-risk line; verify in surrounding control flow.
- L00323 [NONE] `#define QUIC_TRANS(t)	((struct quic_transport *)container_of(t, \`
  Review: Low-risk line; verify in surrounding control flow.
- L00324 [NONE] `				struct quic_transport, transport))`
  Review: Low-risk line; verify in surrounding control flow.
- L00325 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00326 [NONE] `/* =========================================================================`
  Review: Low-risk line; verify in surrounding control flow.
- L00327 [NONE] ` * Global listener state`
  Review: Low-risk line; verify in surrounding control flow.
- L00328 [NONE] ` * =========================================================================`
  Review: Low-risk line; verify in surrounding control flow.
- L00329 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00330 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00331 [NONE] `static struct task_struct	*quic_listener_kthread;`
  Review: Low-risk line; verify in surrounding control flow.
- L00332 [NONE] `static struct socket		*quic_udp_sock;		/* shared UDP socket */`
  Review: Low-risk line; verify in surrounding control flow.
- L00333 [LIFETIME|] `static atomic_t			 quic_active_conns;`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L00334 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00335 [NONE] `/* Hash table for active QUIC connections, keyed on DCID bytes */`
  Review: Low-risk line; verify in surrounding control flow.
- L00336 [NONE] `#define QUIC_CONN_HASH_BITS	8`
  Review: Low-risk line; verify in surrounding control flow.
- L00337 [NONE] `static DEFINE_HASHTABLE(quic_conn_table, QUIC_CONN_HASH_BITS);`
  Review: Low-risk line; verify in surrounding control flow.
- L00338 [NONE] `static DEFINE_SPINLOCK(quic_conn_table_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00339 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00340 [NONE] `/* =========================================================================`
  Review: Low-risk line; verify in surrounding control flow.
- L00341 [NONE] ` * QUIC variable-length integer encoding/decoding (RFC 9000 §16)`
  Review: Low-risk line; verify in surrounding control flow.
- L00342 [NONE] ` * =========================================================================`
  Review: Low-risk line; verify in surrounding control flow.
- L00343 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00344 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00345 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00346 [NONE] ` * ksmbd_quic_put_varint() - encode a QUIC variable-length integer`
  Review: Low-risk line; verify in surrounding control flow.
- L00347 [NONE] ` * @buf:	Destination buffer (must have at least 8 bytes available)`
  Review: Low-risk line; verify in surrounding control flow.
- L00348 [NONE] ` * @val:	Value to encode (must be < 2^62)`
  Review: Low-risk line; verify in surrounding control flow.
- L00349 [NONE] ` * @len_out:	Set to the number of bytes written`
  Review: Low-risk line; verify in surrounding control flow.
- L00350 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00351 [NONE] ` * Return: 0 on success, -ERANGE if val is too large.`
  Review: Low-risk line; verify in surrounding control flow.
- L00352 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00353 [NONE] `static int ksmbd_quic_put_varint(u8 *buf, u64 val, int *len_out)`
  Review: Low-risk line; verify in surrounding control flow.
- L00354 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00355 [NONE] `	if (val < 64) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00356 [NONE] `		buf[0] = (u8)val;`
  Review: Low-risk line; verify in surrounding control flow.
- L00357 [NONE] `		*len_out = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00358 [NONE] `	} else if (val < 16384) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00359 [NONE] `		buf[0] = 0x40 | (u8)(val >> 8);`
  Review: Low-risk line; verify in surrounding control flow.
- L00360 [NONE] `		buf[1] = (u8)val;`
  Review: Low-risk line; verify in surrounding control flow.
- L00361 [NONE] `		*len_out = 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00362 [NONE] `	} else if (val < 1073741824ULL) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00363 [NONE] `		put_unaligned_be32((u32)(0x80000000UL | val), buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00364 [NONE] `		*len_out = 4;`
  Review: Low-risk line; verify in surrounding control flow.
- L00365 [NONE] `	} else if (val < (1ULL << 62)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00366 [NONE] `		put_unaligned_be64(0xC000000000000000ULL | val, buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00367 [NONE] `		*len_out = 8;`
  Review: Low-risk line; verify in surrounding control flow.
- L00368 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00369 [ERROR_PATH|] `		return -ERANGE;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00370 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00371 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00372 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00373 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00374 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00375 [NONE] ` * ksmbd_quic_get_varint() - decode a QUIC variable-length integer`
  Review: Low-risk line; verify in surrounding control flow.
- L00376 [NONE] ` * @buf:	Source buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00377 [NONE] ` * @len:	Available bytes in buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00378 [NONE] ` * @val_out:	Set to the decoded value`
  Review: Low-risk line; verify in surrounding control flow.
- L00379 [NONE] ` * @consumed:	Set to the number of bytes consumed`
  Review: Low-risk line; verify in surrounding control flow.
- L00380 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00381 [NONE] ` * Return: 0 on success, -EINVAL if the buffer is too short.`
  Review: Low-risk line; verify in surrounding control flow.
- L00382 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00383 [NONE] `static int ksmbd_quic_get_varint(const u8 *buf, size_t len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00384 [NONE] `				 u64 *val_out, int *consumed)`
  Review: Low-risk line; verify in surrounding control flow.
- L00385 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00386 [NONE] `	u8 first;`
  Review: Low-risk line; verify in surrounding control flow.
- L00387 [NONE] `	int nbytes;`
  Review: Low-risk line; verify in surrounding control flow.
- L00388 [NONE] `	u64 val;`
  Review: Low-risk line; verify in surrounding control flow.
- L00389 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00390 [NONE] `	if (!len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00391 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00392 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00393 [NONE] `	first = buf[0];`
  Review: Low-risk line; verify in surrounding control flow.
- L00394 [NONE] `	switch (first >> 6) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00395 [NONE] `	case 0:`
  Review: Low-risk line; verify in surrounding control flow.
- L00396 [NONE] `		*val_out = first & 0x3f;`
  Review: Low-risk line; verify in surrounding control flow.
- L00397 [NONE] `		*consumed = 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L00398 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00399 [NONE] `	case 1:`
  Review: Low-risk line; verify in surrounding control flow.
- L00400 [NONE] `		if (len < 2)`
  Review: Low-risk line; verify in surrounding control flow.
- L00401 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00402 [NONE] `		*val_out = ((u64)(first & 0x3f) << 8) | buf[1];`
  Review: Low-risk line; verify in surrounding control flow.
- L00403 [NONE] `		*consumed = 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00404 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00405 [NONE] `	case 2:`
  Review: Low-risk line; verify in surrounding control flow.
- L00406 [NONE] `		if (len < 4)`
  Review: Low-risk line; verify in surrounding control flow.
- L00407 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00408 [NONE] `		val = ((u64)(first & 0x3f) << 24) |`
  Review: Low-risk line; verify in surrounding control flow.
- L00409 [NONE] `		      ((u64)buf[1] << 16) |`
  Review: Low-risk line; verify in surrounding control flow.
- L00410 [NONE] `		      ((u64)buf[2] << 8) |`
  Review: Low-risk line; verify in surrounding control flow.
- L00411 [NONE] `		       (u64)buf[3];`
  Review: Low-risk line; verify in surrounding control flow.
- L00412 [NONE] `		*val_out = val;`
  Review: Low-risk line; verify in surrounding control flow.
- L00413 [NONE] `		*consumed = 4;`
  Review: Low-risk line; verify in surrounding control flow.
- L00414 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00415 [NONE] `	case 3:`
  Review: Low-risk line; verify in surrounding control flow.
- L00416 [NONE] `		if (len < 8)`
  Review: Low-risk line; verify in surrounding control flow.
- L00417 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00418 [NONE] `		nbytes = 8;`
  Review: Low-risk line; verify in surrounding control flow.
- L00419 [NONE] `		val = ((u64)(first & 0x3f) << 56) |`
  Review: Low-risk line; verify in surrounding control flow.
- L00420 [NONE] `		      ((u64)buf[1] << 48) |`
  Review: Low-risk line; verify in surrounding control flow.
- L00421 [NONE] `		      ((u64)buf[2] << 40) |`
  Review: Low-risk line; verify in surrounding control flow.
- L00422 [NONE] `		      ((u64)buf[3] << 32) |`
  Review: Low-risk line; verify in surrounding control flow.
- L00423 [NONE] `		      ((u64)buf[4] << 24) |`
  Review: Low-risk line; verify in surrounding control flow.
- L00424 [NONE] `		      ((u64)buf[5] << 16) |`
  Review: Low-risk line; verify in surrounding control flow.
- L00425 [NONE] `		      ((u64)buf[6] << 8) |`
  Review: Low-risk line; verify in surrounding control flow.
- L00426 [NONE] `		       (u64)buf[7];`
  Review: Low-risk line; verify in surrounding control flow.
- L00427 [NONE] `		*val_out = val;`
  Review: Low-risk line; verify in surrounding control flow.
- L00428 [NONE] `		*consumed = nbytes;`
  Review: Low-risk line; verify in surrounding control flow.
- L00429 [NONE] `		return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00430 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00431 [ERROR_PATH|] `	return -EINVAL; /* unreachable */`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00432 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00433 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00434 [NONE] `/* =========================================================================`
  Review: Low-risk line; verify in surrounding control flow.
- L00435 [NONE] ` * QUIC-TLS HKDF (RFC 9001 §5, using kernel crypto/hkdf.h)`
  Review: Low-risk line; verify in surrounding control flow.
- L00436 [NONE] ` * =========================================================================`
  Review: Low-risk line; verify in surrounding control flow.
- L00437 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00438 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00439 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00440 [NONE] ` * ksmbd_quic_hkdf_expand_label() - QUIC-specific HKDF-Expand-Label (RFC 9001)`
  Review: Low-risk line; verify in surrounding control flow.
- L00441 [NONE] ` * @secret:	PRK input (from a prior HKDF-Extract)`
  Review: Low-risk line; verify in surrounding control flow.
- L00442 [NONE] ` * @secret_len:	Length of @secret`
  Review: Low-risk line; verify in surrounding control flow.
- L00443 [NONE] ` * @label:	Label string (e.g. "quic key"), without the "tls13 " prefix`
  Review: Low-risk line; verify in surrounding control flow.
- L00444 [NONE] ` * @context:	Context bytes (typically empty for QUIC initial secrets)`
  Review: Low-risk line; verify in surrounding control flow.
- L00445 [NONE] ` * @ctx_len:	Length of @context`
  Review: Low-risk line; verify in surrounding control flow.
- L00446 [NONE] ` * @out:	Output keying material`
  Review: Low-risk line; verify in surrounding control flow.
- L00447 [NONE] ` * @out_len:	Required output length`
  Review: Low-risk line; verify in surrounding control flow.
- L00448 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00449 [NONE] ` * Builds the HkdfLabel structure (RFC 8446 §3.4 / RFC 9001 §5.1):`
  Review: Low-risk line; verify in surrounding control flow.
- L00450 [NONE] ` *   struct {`
  Review: Low-risk line; verify in surrounding control flow.
- L00451 [NONE] ` *     uint16 length;`
  Review: Low-risk line; verify in surrounding control flow.
- L00452 [NONE] ` *     opaque label<7..255>;   // "tls13 quic " + label`
  Review: Low-risk line; verify in surrounding control flow.
- L00453 [NONE] ` *     opaque context<0..255>;`
  Review: Low-risk line; verify in surrounding control flow.
- L00454 [NONE] ` *   } HkdfLabel;`
  Review: Low-risk line; verify in surrounding control flow.
- L00455 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00456 [NONE] ` * Then calls the kernel's hkdf_expand() (crypto/hkdf.h).`
  Review: Low-risk line; verify in surrounding control flow.
- L00457 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00458 [NONE] ` * Return: 0 on success, negative errno on failure.`
  Review: Low-risk line; verify in surrounding control flow.
- L00459 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00460 [NONE] `static int ksmbd_quic_hkdf_expand_label(const u8 *secret, size_t secret_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00461 [NONE] `					 const char *label,`
  Review: Low-risk line; verify in surrounding control flow.
- L00462 [NONE] `					 const u8 *context, size_t ctx_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00463 [NONE] `					 u8 *out, size_t out_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00464 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00465 [NONE] `	struct crypto_shash *hmac_tfm;`
  Review: Low-risk line; verify in surrounding control flow.
- L00466 [NONE] `	/* HkdfLabel: 2-byte length + 1-byte label_len + label + 1-byte ctx_len + ctx */`
  Review: Low-risk line; verify in surrounding control flow.
- L00467 [NONE] `	u8 hkdf_label[2 + 1 + 255 + 1 + 255];`
  Review: Low-risk line; verify in surrounding control flow.
- L00468 [NONE] `	size_t label_full_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00469 [NONE] `	size_t label_len_byte;`
  Review: Low-risk line; verify in surrounding control flow.
- L00470 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00471 [NONE] `	u8 *p = hkdf_label;`
  Review: Low-risk line; verify in surrounding control flow.
- L00472 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00473 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00474 [NONE] `	 * Full label = "tls13 quic " + caller's label`
  Review: Low-risk line; verify in surrounding control flow.
- L00475 [NONE] `	 * RFC 9001 §5.1 says use "tls13 " prefix (from RFC 8446) then`
  Review: Low-risk line; verify in surrounding control flow.
- L00476 [NONE] `	 * the QUIC-specific label.`
  Review: Low-risk line; verify in surrounding control flow.
- L00477 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00478 [NONE] `	label_full_len = strlen(QUIC_HKDF_LABEL_PREFIX) + strlen(label);`
  Review: Low-risk line; verify in surrounding control flow.
- L00479 [NONE] `	if (label_full_len > 255 || ctx_len > 255 || out_len > 0xFFFF)`
  Review: Low-risk line; verify in surrounding control flow.
- L00480 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00481 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00482 [NONE] `	/* length (2 bytes, big-endian) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00483 [NONE] `	put_unaligned_be16((u16)out_len, p);`
  Review: Low-risk line; verify in surrounding control flow.
- L00484 [NONE] `	p += 2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00485 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00486 [NONE] `	/* label length byte + label bytes */`
  Review: Low-risk line; verify in surrounding control flow.
- L00487 [NONE] `	label_len_byte = label_full_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00488 [NONE] `	*p++ = (u8)label_len_byte;`
  Review: Low-risk line; verify in surrounding control flow.
- L00489 [MEM_BOUNDS|] `	memcpy(p, QUIC_HKDF_LABEL_PREFIX, strlen(QUIC_HKDF_LABEL_PREFIX));`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00490 [NONE] `	p += strlen(QUIC_HKDF_LABEL_PREFIX);`
  Review: Low-risk line; verify in surrounding control flow.
- L00491 [MEM_BOUNDS|] `	memcpy(p, label, strlen(label));`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00492 [NONE] `	p += strlen(label);`
  Review: Low-risk line; verify in surrounding control flow.
- L00493 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00494 [NONE] `	/* context length byte + context bytes */`
  Review: Low-risk line; verify in surrounding control flow.
- L00495 [NONE] `	*p++ = (u8)ctx_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00496 [NONE] `	if (ctx_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L00497 [MEM_BOUNDS|] `		memcpy(p, context, ctx_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00498 [NONE] `	p += ctx_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00499 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00500 [NONE] `	/* Allocate HMAC-SHA256 transform for HKDF */`
  Review: Low-risk line; verify in surrounding control flow.
- L00501 [NONE] `	hmac_tfm = crypto_alloc_shash("hmac(sha256)", 0, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00502 [NONE] `	if (IS_ERR(hmac_tfm))`
  Review: Low-risk line; verify in surrounding control flow.
- L00503 [NONE] `		return PTR_ERR(hmac_tfm);`
  Review: Low-risk line; verify in surrounding control flow.
- L00504 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00505 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00506 [NONE] `	 * Set the PRK as the HMAC key (hkdf_expand treats the key as PRK).`
  Review: Low-risk line; verify in surrounding control flow.
- L00507 [NONE] `	 * crypto_shash_setkey sets the HMAC key for hkdf_expand.`
  Review: Low-risk line; verify in surrounding control flow.
- L00508 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00509 [NONE] `	ret = crypto_shash_setkey(hmac_tfm, secret, secret_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00510 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00511 [ERROR_PATH|] `		goto out_free;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00512 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00513 [NONE] `	ret = hkdf_expand(hmac_tfm,`
  Review: Low-risk line; verify in surrounding control flow.
- L00514 [NONE] `			  hkdf_label, (unsigned int)(p - hkdf_label),`
  Review: Low-risk line; verify in surrounding control flow.
- L00515 [NONE] `			  out, (unsigned int)out_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00516 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00517 [NONE] `out_free:`
  Review: Low-risk line; verify in surrounding control flow.
- L00518 [NONE] `	crypto_free_shash(hmac_tfm);`
  Review: Low-risk line; verify in surrounding control flow.
- L00519 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00520 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00521 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00522 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00523 [NONE] ` * ksmbd_quic_derive_initial_secrets() - derive QUIC Initial packet keys`
  Review: Low-risk line; verify in surrounding control flow.
- L00524 [NONE] ` * @qconn:	QUIC connection; @dcid must be set before calling`
  Review: Low-risk line; verify in surrounding control flow.
- L00525 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00526 [NONE] ` * Implements RFC 9001 §A.1:`
  Review: Low-risk line; verify in surrounding control flow.
- L00527 [NONE] ` *   initial_secret = HKDF-Extract(initial_salt, DCID)`
  Review: Low-risk line; verify in surrounding control flow.
- L00528 [NONE] ` *   client_secret  = HKDF-Expand-Label(initial_secret, "client in", "", 32)`
  Review: Low-risk line; verify in surrounding control flow.
- L00529 [NONE] ` *   server_secret  = HKDF-Expand-Label(initial_secret, "server in", "", 32)`
  Review: Low-risk line; verify in surrounding control flow.
- L00530 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00531 [NONE] ` * Then derives key/IV/HP for each direction:`
  Review: Low-risk line; verify in surrounding control flow.
- L00532 [NONE] ` *   key = HKDF-Expand-Label(secret, "quic key", "", 16)`
  Review: Low-risk line; verify in surrounding control flow.
- L00533 [NONE] ` *   iv  = HKDF-Expand-Label(secret, "quic iv", "", 12)`
  Review: Low-risk line; verify in surrounding control flow.
- L00534 [NONE] ` *   hp  = HKDF-Expand-Label(secret, "quic hp", "", 16)`
  Review: Low-risk line; verify in surrounding control flow.
- L00535 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00536 [NONE] ` * Return: 0 on success, negative errno on failure.`
  Review: Low-risk line; verify in surrounding control flow.
- L00537 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00538 [NONE] `static int ksmbd_quic_derive_initial_secrets(struct ksmbd_quic_conn *qconn)`
  Review: Low-risk line; verify in surrounding control flow.
- L00539 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00540 [NONE] `	struct crypto_shash *hmac_tfm;`
  Review: Low-risk line; verify in surrounding control flow.
- L00541 [NONE] `	u8 initial_secret[32];`
  Review: Low-risk line; verify in surrounding control flow.
- L00542 [NONE] `	u8 client_secret[32];`
  Review: Low-risk line; verify in surrounding control flow.
- L00543 [NONE] `	u8 server_secret[32];`
  Review: Low-risk line; verify in surrounding control flow.
- L00544 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00545 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00546 [NONE] `	/* HKDF-Extract(salt=initial_salt, IKM=DCID) → initial_secret */`
  Review: Low-risk line; verify in surrounding control flow.
- L00547 [NONE] `	hmac_tfm = crypto_alloc_shash("hmac(sha256)", 0, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00548 [NONE] `	if (IS_ERR(hmac_tfm))`
  Review: Low-risk line; verify in surrounding control flow.
- L00549 [NONE] `		return PTR_ERR(hmac_tfm);`
  Review: Low-risk line; verify in surrounding control flow.
- L00550 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00551 [NONE] `	ret = hkdf_extract(hmac_tfm,`
  Review: Low-risk line; verify in surrounding control flow.
- L00552 [NONE] `			   qconn->dcid, qconn->dcid_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00553 [NONE] `			   quic_v1_initial_salt, sizeof(quic_v1_initial_salt),`
  Review: Low-risk line; verify in surrounding control flow.
- L00554 [NONE] `			   initial_secret);`
  Review: Low-risk line; verify in surrounding control flow.
- L00555 [NONE] `	crypto_free_shash(hmac_tfm);`
  Review: Low-risk line; verify in surrounding control flow.
- L00556 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00557 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00558 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00559 [NONE] `	/* client_secret = HKDF-Expand-Label(initial_secret, "client in", "", 32) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00560 [NONE] `	ret = ksmbd_quic_hkdf_expand_label(initial_secret, sizeof(initial_secret),`
  Review: Low-risk line; verify in surrounding control flow.
- L00561 [NONE] `					   QUIC_LABEL_CLIENT_IN,`
  Review: Low-risk line; verify in surrounding control flow.
- L00562 [NONE] `					   NULL, 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L00563 [NONE] `					   client_secret, sizeof(client_secret));`
  Review: Low-risk line; verify in surrounding control flow.
- L00564 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00565 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00566 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00567 [NONE] `	/* server_secret = HKDF-Expand-Label(initial_secret, "server in", "", 32) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00568 [NONE] `	ret = ksmbd_quic_hkdf_expand_label(initial_secret, sizeof(initial_secret),`
  Review: Low-risk line; verify in surrounding control flow.
- L00569 [NONE] `					   QUIC_LABEL_SERVER_IN,`
  Review: Low-risk line; verify in surrounding control flow.
- L00570 [NONE] `					   NULL, 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L00571 [NONE] `					   server_secret, sizeof(server_secret));`
  Review: Low-risk line; verify in surrounding control flow.
- L00572 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00573 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00574 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00575 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00576 [NONE] `	 * RX keys = client_in (we receive from client)`
  Review: Low-risk line; verify in surrounding control flow.
- L00577 [NONE] `	 * TX keys = server_in (we send from server)`
  Review: Low-risk line; verify in surrounding control flow.
- L00578 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00579 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00580 [NONE] `	/* rx key */`
  Review: Low-risk line; verify in surrounding control flow.
- L00581 [NONE] `	ret = ksmbd_quic_hkdf_expand_label(client_secret, sizeof(client_secret),`
  Review: Low-risk line; verify in surrounding control flow.
- L00582 [NONE] `					   QUIC_LABEL_QUIC_KEY, NULL, 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L00583 [NONE] `					   qconn->initial_rx.key, QUIC_AEAD_KEY_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00584 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00585 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00586 [NONE] `	/* rx iv */`
  Review: Low-risk line; verify in surrounding control flow.
- L00587 [NONE] `	ret = ksmbd_quic_hkdf_expand_label(client_secret, sizeof(client_secret),`
  Review: Low-risk line; verify in surrounding control flow.
- L00588 [NONE] `					   QUIC_LABEL_QUIC_IV, NULL, 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L00589 [NONE] `					   qconn->initial_rx.iv, QUIC_AEAD_IV_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00590 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00591 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00592 [NONE] `	/* rx hp */`
  Review: Low-risk line; verify in surrounding control flow.
- L00593 [NONE] `	ret = ksmbd_quic_hkdf_expand_label(client_secret, sizeof(client_secret),`
  Review: Low-risk line; verify in surrounding control flow.
- L00594 [NONE] `					   QUIC_LABEL_QUIC_HP, NULL, 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L00595 [NONE] `					   qconn->initial_rx.hp, QUIC_HP_KEY_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00596 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00597 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00598 [NONE] `	qconn->initial_rx.key_len = QUIC_AEAD_KEY_SIZE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00599 [NONE] `	qconn->initial_rx.ready = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00600 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00601 [NONE] `	/* tx key */`
  Review: Low-risk line; verify in surrounding control flow.
- L00602 [NONE] `	ret = ksmbd_quic_hkdf_expand_label(server_secret, sizeof(server_secret),`
  Review: Low-risk line; verify in surrounding control flow.
- L00603 [NONE] `					   QUIC_LABEL_QUIC_KEY, NULL, 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L00604 [NONE] `					   qconn->initial_tx.key, QUIC_AEAD_KEY_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00605 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00606 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00607 [NONE] `	/* tx iv */`
  Review: Low-risk line; verify in surrounding control flow.
- L00608 [NONE] `	ret = ksmbd_quic_hkdf_expand_label(server_secret, sizeof(server_secret),`
  Review: Low-risk line; verify in surrounding control flow.
- L00609 [NONE] `					   QUIC_LABEL_QUIC_IV, NULL, 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L00610 [NONE] `					   qconn->initial_tx.iv, QUIC_AEAD_IV_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00611 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00612 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00613 [NONE] `	/* tx hp */`
  Review: Low-risk line; verify in surrounding control flow.
- L00614 [NONE] `	ret = ksmbd_quic_hkdf_expand_label(server_secret, sizeof(server_secret),`
  Review: Low-risk line; verify in surrounding control flow.
- L00615 [NONE] `					   QUIC_LABEL_QUIC_HP, NULL, 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L00616 [NONE] `					   qconn->initial_tx.hp, QUIC_HP_KEY_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00617 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00618 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00619 [NONE] `	qconn->initial_tx.key_len = QUIC_AEAD_KEY_SIZE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00620 [NONE] `	qconn->initial_tx.ready = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L00621 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00622 [NONE] `	/* Scrub sensitive material from stack */`
  Review: Low-risk line; verify in surrounding control flow.
- L00623 [NONE] `	memzero_explicit(initial_secret, sizeof(initial_secret));`
  Review: Low-risk line; verify in surrounding control flow.
- L00624 [NONE] `	memzero_explicit(client_secret, sizeof(client_secret));`
  Review: Low-risk line; verify in surrounding control flow.
- L00625 [NONE] `	memzero_explicit(server_secret, sizeof(server_secret));`
  Review: Low-risk line; verify in surrounding control flow.
- L00626 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00627 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00628 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00629 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00630 [NONE] `/* =========================================================================`
  Review: Low-risk line; verify in surrounding control flow.
- L00631 [NONE] ` * QUIC packet number header protection (RFC 9001 §5.4)`
  Review: Low-risk line; verify in surrounding control flow.
- L00632 [NONE] ` * =========================================================================`
  Review: Low-risk line; verify in surrounding control flow.
- L00633 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00634 [NONE] ` * The packet number field in both long- and short-header packets is`
  Review: Low-risk line; verify in surrounding control flow.
- L00635 [NONE] ` * protected by XOR-ing with the first pkt_num_len bytes of:`
  Review: Low-risk line; verify in surrounding control flow.
- L00636 [NONE] ` *   AES-128-ECB(hp_key, sample)`
  Review: Low-risk line; verify in surrounding control flow.
- L00637 [NONE] ` * where sample is 16 bytes taken from the ciphertext starting at offset 4`
  Review: Low-risk line; verify in surrounding control flow.
- L00638 [NONE] ` * from the start of the packet number field.`
  Review: Low-risk line; verify in surrounding control flow.
- L00639 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00640 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00641 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00642 [NONE] ` * ksmbd_quic_apply_header_protection() - encrypt or decrypt packet number`
  Review: Low-risk line; verify in surrounding control flow.
- L00643 [NONE] ` * @pkt_num_bytes: Pointer to the packet number field in the packet buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00644 [NONE] ` * @pkt_num_len:   Number of bytes in the packet number (1-4)`
  Review: Low-risk line; verify in surrounding control flow.
- L00645 [NONE] ` * @hp_key:        16-byte header protection key`
  Review: Low-risk line; verify in surrounding control flow.
- L00646 [NONE] ` * @ciphertext_sample: 16 bytes of ciphertext starting 4 bytes after pktnum`
  Review: Low-risk line; verify in surrounding control flow.
- L00647 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00648 [NONE] ` * This function is its own inverse (XOR is reversible), so the same`
  Review: Low-risk line; verify in surrounding control flow.
- L00649 [NONE] ` * function is used for both protection and removal.`
  Review: Low-risk line; verify in surrounding control flow.
- L00650 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00651 [NONE] `static void __maybe_unused`
  Review: Low-risk line; verify in surrounding control flow.
- L00652 [NONE] `ksmbd_quic_apply_header_protection(u8 *pkt_num_bytes,`
  Review: Low-risk line; verify in surrounding control flow.
- L00653 [NONE] `				   int pkt_num_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00654 [NONE] `				   const u8 *hp_key,`
  Review: Low-risk line; verify in surrounding control flow.
- L00655 [NONE] `				   const u8 *ciphertext_sample)`
  Review: Low-risk line; verify in surrounding control flow.
- L00656 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00657 [NONE] `	struct crypto_cipher *tfm;`
  Review: Low-risk line; verify in surrounding control flow.
- L00658 [NONE] `	u8 mask[16];`
  Review: Low-risk line; verify in surrounding control flow.
- L00659 [NONE] `	int i;`
  Review: Low-risk line; verify in surrounding control flow.
- L00660 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00661 [NONE] `	tfm = crypto_alloc_cipher("aes", 0, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00662 [NONE] `	if (IS_ERR(tfm)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00663 [ERROR_PATH|] `		pr_warn_ratelimited("QUIC: cannot allocate AES cipher for HP: %ld\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00664 [NONE] `				    PTR_ERR(tfm));`
  Review: Low-risk line; verify in surrounding control flow.
- L00665 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00666 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00667 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00668 [NONE] `	if (crypto_cipher_setkey(tfm, hp_key, QUIC_HP_KEY_SIZE)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00669 [ERROR_PATH|] `		pr_warn_ratelimited("QUIC: AES HP key setup failed\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00670 [NONE] `		crypto_free_cipher(tfm);`
  Review: Low-risk line; verify in surrounding control flow.
- L00671 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L00672 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00673 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00674 [NONE] `	/* mask = AES-ECB(hp_key, sample) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00675 [NONE] `	crypto_cipher_encrypt_one(tfm, mask, ciphertext_sample);`
  Review: Low-risk line; verify in surrounding control flow.
- L00676 [NONE] `	crypto_free_cipher(tfm);`
  Review: Low-risk line; verify in surrounding control flow.
- L00677 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00678 [NONE] `	/* XOR the packet number bytes with the mask */`
  Review: Low-risk line; verify in surrounding control flow.
- L00679 [NONE] `	for (i = 0; i < pkt_num_len && i < 4; i++)`
  Review: Low-risk line; verify in surrounding control flow.
- L00680 [NONE] `		pkt_num_bytes[i] ^= mask[i];`
  Review: Low-risk line; verify in surrounding control flow.
- L00681 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00682 [NONE] `	memzero_explicit(mask, sizeof(mask));`
  Review: Low-risk line; verify in surrounding control flow.
- L00683 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00684 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00685 [NONE] `/* =========================================================================`
  Review: Low-risk line; verify in surrounding control flow.
- L00686 [NONE] ` * QUIC AEAD encrypt/decrypt (RFC 9001 §5.3)`
  Review: Low-risk line; verify in surrounding control flow.
- L00687 [NONE] ` * =========================================================================`
  Review: Low-risk line; verify in surrounding control flow.
- L00688 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00689 [NONE] ` * QUIC uses AEAD-AES-128-GCM with:`
  Review: Low-risk line; verify in surrounding control flow.
- L00690 [NONE] ` *   nonce = IV XOR (zero-padded packet number)`
  Review: Low-risk line; verify in surrounding control flow.
- L00691 [NONE] ` *   AAD   = QUIC packet header (up to but not including the payload)`
  Review: Low-risk line; verify in surrounding control flow.
- L00692 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00693 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00694 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00695 [NONE] ` * ksmbd_quic_aead_crypt() - AEAD encrypt or decrypt a QUIC payload`
  Review: Low-risk line; verify in surrounding control flow.
- L00696 [NONE] ` * @key:	16-byte AEAD key`
  Review: Low-risk line; verify in surrounding control flow.
- L00697 [NONE] ` * @iv:		12-byte AEAD base IV`
  Review: Low-risk line; verify in surrounding control flow.
- L00698 [NONE] ` * @pkt_num:	Packet number (XOR'd into nonce, RFC 9001 §5.3)`
  Review: Low-risk line; verify in surrounding control flow.
- L00699 [NONE] ` * @aad:	Additional authenticated data (packet header)`
  Review: Low-risk line; verify in surrounding control flow.
- L00700 [NONE] ` * @aad_len:	Length of @aad`
  Review: Low-risk line; verify in surrounding control flow.
- L00701 [NONE] ` * @in:		Input buffer (plaintext for encrypt, ciphertext+tag for decrypt)`
  Review: Low-risk line; verify in surrounding control flow.
- L00702 [NONE] ` * @in_len:	Length of @in`
  Review: Low-risk line; verify in surrounding control flow.
- L00703 [NONE] ` * @out:	Output buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L00704 [NONE] ` * @out_len:	On input: size of @out.  On success: bytes written.`
  Review: Low-risk line; verify in surrounding control flow.
- L00705 [NONE] ` * @encrypt:	true = encrypt, false = decrypt`
  Review: Low-risk line; verify in surrounding control flow.
- L00706 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00707 [NONE] ` * Return: 0 on success, negative errno on failure.`
  Review: Low-risk line; verify in surrounding control flow.
- L00708 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00709 [NONE] `static int __maybe_unused`
  Review: Low-risk line; verify in surrounding control flow.
- L00710 [NONE] `ksmbd_quic_aead_crypt(const u8 *key, const u8 *iv, u64 pkt_num,`
  Review: Low-risk line; verify in surrounding control flow.
- L00711 [NONE] `		      const u8 *aad, size_t aad_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00712 [NONE] `		      const u8 *in, size_t in_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00713 [NONE] `		      u8 *out, size_t *out_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00714 [NONE] `		      bool encrypt)`
  Review: Low-risk line; verify in surrounding control flow.
- L00715 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00716 [NONE] `	struct crypto_aead *tfm;`
  Review: Low-risk line; verify in surrounding control flow.
- L00717 [NONE] `	struct aead_request *req;`
  Review: Low-risk line; verify in surrounding control flow.
- L00718 [NONE] `	struct scatterlist sg_in[2], sg_out[2];`
  Review: Low-risk line; verify in surrounding control flow.
- L00719 [NONE] `	u8 nonce[QUIC_AEAD_IV_SIZE];`
  Review: Low-risk line; verify in surrounding control flow.
- L00720 [NONE] `	u8 *aad_buf, *work_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L00721 [NONE] `	size_t work_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00722 [NONE] `	int ret, i;`
  Review: Low-risk line; verify in surrounding control flow.
- L00723 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00724 [NONE] `	/* nonce = IV XOR (pkt_num encoded big-endian into right 8 bytes) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00725 [MEM_BOUNDS|] `	memcpy(nonce, iv, QUIC_AEAD_IV_SIZE);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00726 [NONE] `	for (i = 0; i < 8; i++)`
  Review: Low-risk line; verify in surrounding control flow.
- L00727 [NONE] `		nonce[QUIC_AEAD_IV_SIZE - 1 - i] ^= (u8)(pkt_num >> (8 * i));`
  Review: Low-risk line; verify in surrounding control flow.
- L00728 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00729 [NONE] `	tfm = crypto_alloc_aead("gcm(aes)", 0, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L00730 [NONE] `	if (IS_ERR(tfm))`
  Review: Low-risk line; verify in surrounding control flow.
- L00731 [NONE] `		return PTR_ERR(tfm);`
  Review: Low-risk line; verify in surrounding control flow.
- L00732 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00733 [NONE] `	ret = crypto_aead_setkey(tfm, key, QUIC_AEAD_KEY_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00734 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00735 [ERROR_PATH|] `		goto free_tfm;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00736 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00737 [NONE] `	ret = crypto_aead_setauthsize(tfm, QUIC_AEAD_TAG_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00738 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L00739 [ERROR_PATH|] `		goto free_tfm;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00740 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00741 [NONE] `	req = aead_request_alloc(tfm, GFP_KERNEL);`
  Review: Low-risk line; verify in surrounding control flow.
- L00742 [NONE] `	if (!req) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00743 [NONE] `		ret = -ENOMEM;`
  Review: Low-risk line; verify in surrounding control flow.
- L00744 [ERROR_PATH|] `		goto free_tfm;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00745 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00746 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00747 [NONE] `	/* AAD buffer (must be DMA-able, use kmalloc) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00748 [NONE] `	aad_buf = kmemdup(aad, aad_len, GFP_KERNEL);`
  Review: Low-risk line; verify in surrounding control flow.
- L00749 [NONE] `	if (!aad_buf) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00750 [NONE] `		ret = -ENOMEM;`
  Review: Low-risk line; verify in surrounding control flow.
- L00751 [ERROR_PATH|] `		goto free_req;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00752 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00753 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00754 [NONE] `	if (encrypt) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00755 [NONE] `		/* output = ciphertext (in_len bytes) + tag (16 bytes) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00756 [NONE] `		work_len = in_len + QUIC_AEAD_TAG_SIZE;`
  Review: Low-risk line; verify in surrounding control flow.
- L00757 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00758 [NONE] `		/* input includes tag; output is plaintext (in_len - 16) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00759 [NONE] `		work_len = in_len; /* includes tag */`
  Review: Low-risk line; verify in surrounding control flow.
- L00760 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00761 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00762 [MEM_BOUNDS|] `	work_buf = kmalloc(work_len, GFP_KERNEL);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00763 [NONE] `	if (!work_buf) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00764 [NONE] `		ret = -ENOMEM;`
  Review: Low-risk line; verify in surrounding control flow.
- L00765 [ERROR_PATH|] `		goto free_aad;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00766 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00767 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00768 [NONE] `	if (encrypt) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00769 [MEM_BOUNDS|] `		memcpy(work_buf, in, in_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00770 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00771 [MEM_BOUNDS|] `		memcpy(work_buf, in, in_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00772 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00773 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00774 [NONE] `	sg_init_one(&sg_in[0], aad_buf, aad_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00775 [NONE] `	sg_init_one(&sg_out[0], work_buf, work_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00776 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00777 [NONE] `	aead_request_set_tfm(req, tfm);`
  Review: Low-risk line; verify in surrounding control flow.
- L00778 [NONE] `	aead_request_set_callback(req, 0, NULL, NULL);`
  Review: Low-risk line; verify in surrounding control flow.
- L00779 [NONE] `	aead_request_set_crypt(req, sg_out, sg_out,`
  Review: Low-risk line; verify in surrounding control flow.
- L00780 [NONE] `			       encrypt ? in_len : in_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L00781 [NONE] `			       nonce);`
  Review: Low-risk line; verify in surrounding control flow.
- L00782 [NONE] `	aead_request_set_ad(req, aad_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00783 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00784 [NONE] `	if (encrypt)`
  Review: Low-risk line; verify in surrounding control flow.
- L00785 [NONE] `		ret = crypto_aead_encrypt(req);`
  Review: Low-risk line; verify in surrounding control flow.
- L00786 [NONE] `	else`
  Review: Low-risk line; verify in surrounding control flow.
- L00787 [NONE] `		ret = crypto_aead_decrypt(req);`
  Review: Low-risk line; verify in surrounding control flow.
- L00788 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00789 [NONE] `	if (!ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00790 [NONE] `		size_t copy_len = encrypt ? (in_len + QUIC_AEAD_TAG_SIZE)`
  Review: Low-risk line; verify in surrounding control flow.
- L00791 [NONE] `					  : (in_len - QUIC_AEAD_TAG_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L00792 [NONE] `		if (copy_len > *out_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00793 [NONE] `			ret = -ENOSPC;`
  Review: Low-risk line; verify in surrounding control flow.
- L00794 [NONE] `		} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L00795 [MEM_BOUNDS|] `			memcpy(out, work_buf, copy_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00796 [NONE] `			*out_len = copy_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L00797 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L00798 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00799 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00800 [NONE] `	kfree(work_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00801 [NONE] `free_aad:`
  Review: Low-risk line; verify in surrounding control flow.
- L00802 [NONE] `	kfree(aad_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L00803 [NONE] `free_req:`
  Review: Low-risk line; verify in surrounding control flow.
- L00804 [NONE] `	aead_request_free(req);`
  Review: Low-risk line; verify in surrounding control flow.
- L00805 [NONE] `free_tfm:`
  Review: Low-risk line; verify in surrounding control flow.
- L00806 [NONE] `	crypto_free_aead(tfm);`
  Review: Low-risk line; verify in surrounding control flow.
- L00807 [NONE] `	memzero_explicit(nonce, sizeof(nonce));`
  Review: Low-risk line; verify in surrounding control flow.
- L00808 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00809 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00810 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00811 [NONE] `/* =========================================================================`
  Review: Low-risk line; verify in surrounding control flow.
- L00812 [NONE] ` * kTLS integration (CONFIG_TLS)`
  Review: Low-risk line; verify in surrounding control flow.
- L00813 [NONE] ` * =========================================================================`
  Review: Low-risk line; verify in surrounding control flow.
- L00814 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00815 [NONE] ` * After a TLS 1.3 handshake completes, we can offload TLS record encryption`
  Review: Low-risk line; verify in surrounding control flow.
- L00816 [NONE] ` * to the kernel's TLS implementation by installing session keys via SOL_TLS.`
  Review: Low-risk line; verify in surrounding control flow.
- L00817 [NONE] ` * This is optional acceleration; the software QUIC crypto path above handles`
  Review: Low-risk line; verify in surrounding control flow.
- L00818 [NONE] ` * encryption without kTLS.`
  Review: Low-risk line; verify in surrounding control flow.
- L00819 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00820 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00821 [NONE] `#if IS_ENABLED(CONFIG_TLS)`
  Review: Low-risk line; verify in surrounding control flow.
- L00822 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00823 [NONE] ` * ksmbd_quic_install_ktls_keys() - install TLS 1.3 session keys into kTLS`
  Review: Low-risk line; verify in surrounding control flow.
- L00824 [NONE] ` * @sock:	Socket to configure`
  Review: Low-risk line; verify in surrounding control flow.
- L00825 [NONE] ` * @write_key:	16-byte AES-GCM write key`
  Review: Low-risk line; verify in surrounding control flow.
- L00826 [NONE] ` * @write_iv:	8-byte write IV (implicit part, not the explicit nonce)`
  Review: Low-risk line; verify in surrounding control flow.
- L00827 [NONE] ` * @write_salt:	4-byte write salt`
  Review: Low-risk line; verify in surrounding control flow.
- L00828 [NONE] ` * @read_key:	16-byte AES-GCM read key`
  Review: Low-risk line; verify in surrounding control flow.
- L00829 [NONE] ` * @read_iv:	8-byte read IV`
  Review: Low-risk line; verify in surrounding control flow.
- L00830 [NONE] ` * @read_salt:	4-byte read salt`
  Review: Low-risk line; verify in surrounding control flow.
- L00831 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00832 [NONE] ` * Uses sock_setsockopt() with SOL_TLS/TLS_TX and SOL_TLS/TLS_RX to push`
  Review: Low-risk line; verify in surrounding control flow.
- L00833 [NONE] ` * the TLS 1.3 AES-128-GCM session keys into the kernel TLS implementation.`
  Review: Low-risk line; verify in surrounding control flow.
- L00834 [NONE] ` * After this call the socket's send/recv paths automatically perform TLS`
  Review: Low-risk line; verify in surrounding control flow.
- L00835 [NONE] ` * record layer encryption/decryption in software (or via NIC offload).`
  Review: Low-risk line; verify in surrounding control flow.
- L00836 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00837 [NONE] ` * Return: 0 on success, negative errno on failure.`
  Review: Low-risk line; verify in surrounding control flow.
- L00838 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00839 [NONE] ` * Note: The tls12_crypto_info_aes_gcm_128 struct is from`
  Review: Low-risk line; verify in surrounding control flow.
- L00840 [NONE] ` * <uapi/linux/tls.h>.  The .info.version field must be TLS_1_3_VERSION`
  Review: Low-risk line; verify in surrounding control flow.
- L00841 [NONE] ` * for TLS 1.3.`
  Review: Low-risk line; verify in surrounding control flow.
- L00842 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00843 [NONE] `static int __maybe_unused`
  Review: Low-risk line; verify in surrounding control flow.
- L00844 [NONE] `ksmbd_quic_install_ktls_keys(struct socket *sock,`
  Review: Low-risk line; verify in surrounding control flow.
- L00845 [NONE] `			     const u8 *write_key,`
  Review: Low-risk line; verify in surrounding control flow.
- L00846 [NONE] `			     const u8 *write_iv,`
  Review: Low-risk line; verify in surrounding control flow.
- L00847 [NONE] `			     const u8 *write_salt,`
  Review: Low-risk line; verify in surrounding control flow.
- L00848 [NONE] `			     const u8 *read_key,`
  Review: Low-risk line; verify in surrounding control flow.
- L00849 [NONE] `			     const u8 *read_iv,`
  Review: Low-risk line; verify in surrounding control flow.
- L00850 [NONE] `			     const u8 *read_salt)`
  Review: Low-risk line; verify in surrounding control flow.
- L00851 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L00852 [NONE] `	struct tls12_crypto_info_aes_gcm_128 tx_info = {};`
  Review: Low-risk line; verify in surrounding control flow.
- L00853 [NONE] `	struct tls12_crypto_info_aes_gcm_128 rx_info = {};`
  Review: Low-risk line; verify in surrounding control flow.
- L00854 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00855 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00856 [NONE] `	/* TX (write) direction */`
  Review: Low-risk line; verify in surrounding control flow.
- L00857 [NONE] `	tx_info.info.version    = TLS_1_3_VERSION;`
  Review: Low-risk line; verify in surrounding control flow.
- L00858 [NONE] `	tx_info.info.cipher_type = TLS_CIPHER_AES_GCM_128;`
  Review: Low-risk line; verify in surrounding control flow.
- L00859 [MEM_BOUNDS|] `	memcpy(tx_info.key,  write_key,  TLS_CIPHER_AES_GCM_128_KEY_SIZE);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00860 [MEM_BOUNDS|] `	memcpy(tx_info.iv,   write_iv,   TLS_CIPHER_AES_GCM_128_IV_SIZE);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00861 [MEM_BOUNDS|] `	memcpy(tx_info.salt, write_salt, TLS_CIPHER_AES_GCM_128_SALT_SIZE);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00862 [NONE] `	/* rec_seq starts at 0 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00863 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00864 [NONE] `	ret = sock_setsockopt(sock, SOL_TLS, TLS_TX,`
  Review: Low-risk line; verify in surrounding control flow.
- L00865 [NONE] `			      KERNEL_SOCKPTR(&tx_info), sizeof(tx_info));`
  Review: Low-risk line; verify in surrounding control flow.
- L00866 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00867 [ERROR_PATH|] `		pr_warn_ratelimited("QUIC: kTLS TLS_TX setup failed: %d\n", ret);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00868 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00869 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00870 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00871 [NONE] `	/* RX (read) direction */`
  Review: Low-risk line; verify in surrounding control flow.
- L00872 [NONE] `	rx_info.info.version    = TLS_1_3_VERSION;`
  Review: Low-risk line; verify in surrounding control flow.
- L00873 [NONE] `	rx_info.info.cipher_type = TLS_CIPHER_AES_GCM_128;`
  Review: Low-risk line; verify in surrounding control flow.
- L00874 [MEM_BOUNDS|] `	memcpy(rx_info.key,  read_key,  TLS_CIPHER_AES_GCM_128_KEY_SIZE);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00875 [MEM_BOUNDS|] `	memcpy(rx_info.iv,   read_iv,   TLS_CIPHER_AES_GCM_128_IV_SIZE);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00876 [MEM_BOUNDS|] `	memcpy(rx_info.salt, read_salt, TLS_CIPHER_AES_GCM_128_SALT_SIZE);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L00877 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00878 [NONE] `	ret = sock_setsockopt(sock, SOL_TLS, TLS_RX,`
  Review: Low-risk line; verify in surrounding control flow.
- L00879 [NONE] `			      KERNEL_SOCKPTR(&rx_info), sizeof(rx_info));`
  Review: Low-risk line; verify in surrounding control flow.
- L00880 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L00881 [ERROR_PATH|] `		pr_warn_ratelimited("QUIC: kTLS TLS_RX setup failed: %d\n", ret);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L00882 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L00883 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L00884 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00885 [NONE] `	/* Scrub key material from stack */`
  Review: Low-risk line; verify in surrounding control flow.
- L00886 [NONE] `	memzero_explicit(&tx_info, sizeof(tx_info));`
  Review: Low-risk line; verify in surrounding control flow.
- L00887 [NONE] `	memzero_explicit(&rx_info, sizeof(rx_info));`
  Review: Low-risk line; verify in surrounding control flow.
- L00888 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L00889 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L00890 [NONE] `#endif /* IS_ENABLED(CONFIG_TLS) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00891 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00892 [NONE] `/* Forward declaration needed by the IPC response handler (defined below) */`
  Review: Low-risk line; verify in surrounding control flow.
- L00893 [NONE] `static void quic_send_handshake_data(struct ksmbd_quic_conn *qconn,`
  Review: Low-risk line; verify in surrounding control flow.
- L00894 [NONE] `				     const u8 *data, size_t len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00895 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00896 [NONE] `/* =========================================================================`
  Review: Low-risk line; verify in surrounding control flow.
- L00897 [NONE] ` * QUIC Handshake IPC — dedicated Generic Netlink family (SMBD_QUIC)`
  Review: Low-risk line; verify in surrounding control flow.
- L00898 [NONE] ` * =========================================================================`
  Review: Low-risk line; verify in surrounding control flow.
- L00899 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00900 [NONE] ` * We register a separate genl family "SMBD_QUIC" (version 1) for the`
  Review: Low-risk line; verify in surrounding control flow.
- L00901 [NONE] ` * QUIC TLS 1.3 handshake delegation.  This keeps QUIC IPC isolated from`
  Review: Low-risk line; verify in surrounding control flow.
- L00902 [NONE] ` * the main ksmbd genl family (SMBD_GENL).`
  Review: Low-risk line; verify in surrounding control flow.
- L00903 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00904 [NONE] ` * Pending request table:`
  Review: Low-risk line; verify in surrounding control flow.
- L00905 [NONE] ` *   A small hash table maps IPC correlation handles to per-connection`
  Review: Low-risk line; verify in surrounding control flow.
- L00906 [NONE] ` *   completion objects.  When the userspace response arrives via`
  Review: Low-risk line; verify in surrounding control flow.
- L00907 [NONE] ` *   quic_hs_ipc_handle_rsp(), the completion is signalled and the`
  Review: Low-risk line; verify in surrounding control flow.
- L00908 [NONE] ` *   response is copied into the connection struct.`
  Review: Low-risk line; verify in surrounding control flow.
- L00909 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00910 [NONE] ` * Thread safety:`
  Review: Low-risk line; verify in surrounding control flow.
- L00911 [NONE] ` *   quic_hs_table_lock protects the pending table.`
  Review: Low-risk line; verify in surrounding control flow.
- L00912 [NONE] ` *   Individual connections are protected by qconn->lock.`
  Review: Low-risk line; verify in surrounding control flow.
- L00913 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00914 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00915 [NONE] `/* IDA for QUIC handshake IPC handle allocation */`
  Review: Low-risk line; verify in surrounding control flow.
- L00916 [NONE] `static DEFINE_IDA(quic_hs_ida);`
  Review: Low-risk line; verify in surrounding control flow.
- L00917 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00918 [NONE] `/* Pending IPC table */`
  Review: Low-risk line; verify in surrounding control flow.
- L00919 [NONE] `#define QUIC_HS_TABLE_BITS	4`
  Review: Low-risk line; verify in surrounding control flow.
- L00920 [NONE] `static DEFINE_HASHTABLE(quic_hs_table, QUIC_HS_TABLE_BITS);`
  Review: Low-risk line; verify in surrounding control flow.
- L00921 [NONE] `static DEFINE_RWLOCK(quic_hs_table_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00922 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00923 [NONE] `/* PID of the ksmbdctl userspace process registered for QUIC IPC */`
  Review: Low-risk line; verify in surrounding control flow.
- L00924 [NONE] `static unsigned int quic_tools_pid;`
  Review: Low-risk line; verify in surrounding control flow.
- L00925 [NONE] `static DEFINE_SPINLOCK(quic_tools_pid_lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L00926 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00927 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00928 [NONE] ` * struct quic_hs_pending - pending handshake IPC entry`
  Review: Low-risk line; verify in surrounding control flow.
- L00929 [NONE] ` * @handle:	IPC correlation handle`
  Review: Low-risk line; verify in surrounding control flow.
- L00930 [NONE] ` * @hlist:	Hash table linkage (keyed on @handle)`
  Review: Low-risk line; verify in surrounding control flow.
- L00931 [NONE] ` * @qconn:	Owning QUIC connection (we write the RSP into it)`
  Review: Low-risk line; verify in surrounding control flow.
- L00932 [NONE] ` * @done:	Completion: signalled when RSP arrives`
  Review: Low-risk line; verify in surrounding control flow.
- L00933 [NONE] ` * @success:	true if handshake succeeded (set from RSP)`
  Review: Low-risk line; verify in surrounding control flow.
- L00934 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00935 [NONE] `struct quic_hs_pending {`
  Review: Low-risk line; verify in surrounding control flow.
- L00936 [NONE] `	unsigned int		handle;`
  Review: Low-risk line; verify in surrounding control flow.
- L00937 [NONE] `	struct hlist_node	hlist;`
  Review: Low-risk line; verify in surrounding control flow.
- L00938 [NONE] `	struct ksmbd_quic_conn	*qconn;`
  Review: Low-risk line; verify in surrounding control flow.
- L00939 [NONE] `	struct completion	done;`
  Review: Low-risk line; verify in surrounding control flow.
- L00940 [NONE] `	bool			success;`
  Review: Low-risk line; verify in surrounding control flow.
- L00941 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00942 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00943 [NONE] `/* Forward declaration — genl handler needs the ops table below. */`
  Review: Low-risk line; verify in surrounding control flow.
- L00944 [NONE] `static int quic_hs_ipc_handle_rsp(struct sk_buff *skb, struct genl_info *info);`
  Review: Low-risk line; verify in surrounding control flow.
- L00945 [NONE] `static int quic_hs_ipc_handle_register(struct sk_buff *skb,`
  Review: Low-risk line; verify in surrounding control flow.
- L00946 [NONE] `				       struct genl_info *info);`
  Review: Low-risk line; verify in surrounding control flow.
- L00947 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00948 [NONE] `static const struct nla_policy quic_hs_nl_policy[KSMBD_QUIC_CMD_MAX + 1] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00949 [NONE] `	[KSMBD_QUIC_CMD_UNSPEC] = { .len = 0 },`
  Review: Low-risk line; verify in surrounding control flow.
- L00950 [NONE] `	[KSMBD_QUIC_CMD_HANDSHAKE_REQ] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00951 [NONE] `		.type = NLA_BINARY,`
  Review: Low-risk line; verify in surrounding control flow.
- L00952 [NONE] `		.len  = sizeof(struct ksmbd_quic_handshake_req),`
  Review: Low-risk line; verify in surrounding control flow.
- L00953 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00954 [NONE] `	[KSMBD_QUIC_CMD_HANDSHAKE_RSP] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00955 [NONE] `		.type = NLA_BINARY,`
  Review: Low-risk line; verify in surrounding control flow.
- L00956 [NONE] `		.len  = sizeof(struct ksmbd_quic_handshake_rsp),`
  Review: Low-risk line; verify in surrounding control flow.
- L00957 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00958 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00959 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00960 [NONE] `static const struct genl_ops quic_hs_genl_ops[] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00961 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00962 [NONE] `		.cmd   = KSMBD_QUIC_CMD_UNSPEC,`
  Review: Low-risk line; verify in surrounding control flow.
- L00963 [NONE] `		.doit  = quic_hs_ipc_handle_register,`
  Review: Low-risk line; verify in surrounding control flow.
- L00964 [NONE] `		.flags = GENL_ADMIN_PERM,`
  Review: Low-risk line; verify in surrounding control flow.
- L00965 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00966 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00967 [NONE] `		.cmd   = KSMBD_QUIC_CMD_HANDSHAKE_REQ,`
  Review: Low-risk line; verify in surrounding control flow.
- L00968 [NONE] `		/* kernel sends; not a valid incoming command from userspace */`
  Review: Low-risk line; verify in surrounding control flow.
- L00969 [NONE] `		.flags = GENL_ADMIN_PERM,`
  Review: Low-risk line; verify in surrounding control flow.
- L00970 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00971 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L00972 [NONE] `		.cmd   = KSMBD_QUIC_CMD_HANDSHAKE_RSP,`
  Review: Low-risk line; verify in surrounding control flow.
- L00973 [NONE] `		.doit  = quic_hs_ipc_handle_rsp,`
  Review: Low-risk line; verify in surrounding control flow.
- L00974 [NONE] `		.flags = GENL_ADMIN_PERM,`
  Review: Low-risk line; verify in surrounding control flow.
- L00975 [NONE] `	},`
  Review: Low-risk line; verify in surrounding control flow.
- L00976 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00977 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00978 [NONE] `static struct genl_family quic_hs_genl_family = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00979 [NONE] `	.name		= KSMBD_QUIC_GENL_NAME,`
  Review: Low-risk line; verify in surrounding control flow.
- L00980 [NONE] `	.version	= KSMBD_QUIC_GENL_VERSION,`
  Review: Low-risk line; verify in surrounding control flow.
- L00981 [NONE] `	.hdrsize	= 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L00982 [NONE] `	.maxattr	= KSMBD_QUIC_CMD_MAX,`
  Review: Low-risk line; verify in surrounding control flow.
- L00983 [NONE] `	.netnsok	= true,`
  Review: Low-risk line; verify in surrounding control flow.
- L00984 [NONE] `	.module		= THIS_MODULE,`
  Review: Low-risk line; verify in surrounding control flow.
- L00985 [NONE] `	.ops		= quic_hs_genl_ops,`
  Review: Low-risk line; verify in surrounding control flow.
- L00986 [NONE] `	.n_ops		= ARRAY_SIZE(quic_hs_genl_ops),`
  Review: Low-risk line; verify in surrounding control flow.
- L00987 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L00988 [NONE] `	.resv_start_op	= KSMBD_QUIC_CMD_HANDSHAKE_REQ,`
  Review: Low-risk line; verify in surrounding control flow.
- L00989 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00990 [NONE] `	.policy		= quic_hs_nl_policy,`
  Review: Low-risk line; verify in surrounding control flow.
- L00991 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00992 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00993 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L00994 [NONE] ` * quic_hs_ipc_handle_register() - userspace daemon registers with SMBD_QUIC`
  Review: Low-risk line; verify in surrounding control flow.
- L00995 [NONE] ` * @skb:	Incoming netlink message`
  Review: Low-risk line; verify in surrounding control flow.
- L00996 [NONE] ` * @info:	Parsed genl info`
  Review: Low-risk line; verify in surrounding control flow.
- L00997 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00998 [NONE] ` * The ksmbdctl daemon sends KSMBD_QUIC_CMD_UNSPEC when it starts, telling`
  Review: Low-risk line; verify in surrounding control flow.
- L00999 [NONE] ` * us its PID so we can send handshake requests to it.`
  Review: Low-risk line; verify in surrounding control flow.
- L01000 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01001 [NONE] ` * Return: 0 always (non-fatal if it fails — we just won't do handshakes)`
  Review: Low-risk line; verify in surrounding control flow.
- L01002 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01003 [NONE] `static int quic_hs_ipc_handle_register(struct sk_buff *skb,`
  Review: Low-risk line; verify in surrounding control flow.
- L01004 [NONE] `					struct genl_info *info)`
  Review: Low-risk line; verify in surrounding control flow.
- L01005 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01006 [NONE] `	if (!netlink_capable(skb, CAP_NET_ADMIN))`
  Review: Low-risk line; verify in surrounding control flow.
- L01007 [ERROR_PATH|] `		return -EPERM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01008 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01009 [LOCK|] `	spin_lock(&quic_tools_pid_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01010 [NONE] `	quic_tools_pid = info->snd_portid;`
  Review: Low-risk line; verify in surrounding control flow.
- L01011 [LOCK|] `	spin_unlock(&quic_tools_pid_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01012 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01013 [NONE] `	pr_info("ksmbd QUIC: userspace handshake daemon registered (pid=%u)\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L01014 [NONE] `		info->snd_portid);`
  Review: Low-risk line; verify in surrounding control flow.
- L01015 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01016 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01017 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01018 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01019 [NONE] ` * quic_hs_ipc_handle_rsp() - receive HANDSHAKE_RSP from userspace daemon`
  Review: Low-risk line; verify in surrounding control flow.
- L01020 [NONE] ` * @skb:	Incoming netlink message`
  Review: Low-risk line; verify in surrounding control flow.
- L01021 [NONE] ` * @info:	Parsed genl info`
  Review: Low-risk line; verify in surrounding control flow.
- L01022 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01023 [NONE] ` * Looks up the pending entry by handle, copies the keys and handshake data`
  Review: Low-risk line; verify in surrounding control flow.
- L01024 [NONE] ` * into the connection struct, and signals the waiting kernel thread.`
  Review: Low-risk line; verify in surrounding control flow.
- L01025 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01026 [NONE] ` * Return: 0 on success, negative errno on failure.`
  Review: Low-risk line; verify in surrounding control flow.
- L01027 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01028 [NONE] `static int quic_hs_ipc_handle_rsp(struct sk_buff *skb, struct genl_info *info)`
  Review: Low-risk line; verify in surrounding control flow.
- L01029 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01030 [NONE] `	struct nlattr *attr;`
  Review: Low-risk line; verify in surrounding control flow.
- L01031 [NONE] `	struct ksmbd_quic_handshake_rsp *rsp;`
  Review: Low-risk line; verify in surrounding control flow.
- L01032 [NONE] `	struct quic_hs_pending *entry = NULL, *iter;`
  Review: Low-risk line; verify in surrounding control flow.
- L01033 [NONE] `	unsigned long flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L01034 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01035 [NONE] `	if (!netlink_capable(skb, CAP_NET_ADMIN))`
  Review: Low-risk line; verify in surrounding control flow.
- L01036 [ERROR_PATH|] `		return -EPERM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01037 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01038 [NONE] `	attr = info->attrs[KSMBD_QUIC_CMD_HANDSHAKE_RSP];`
  Review: Low-risk line; verify in surrounding control flow.
- L01039 [NONE] `	if (!attr)`
  Review: Low-risk line; verify in surrounding control flow.
- L01040 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01041 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01042 [NONE] `	if (nla_len(attr) < (int)sizeof(struct ksmbd_quic_handshake_rsp))`
  Review: Low-risk line; verify in surrounding control flow.
- L01043 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01044 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01045 [NONE] `	rsp = nla_data(attr);`
  Review: Low-risk line; verify in surrounding control flow.
- L01046 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01047 [NONE] `	/* Validate hs_data_len to prevent overflow */`
  Review: Low-risk line; verify in surrounding control flow.
- L01048 [NONE] `	if (rsp->hs_data_len > KSMBD_QUIC_MAX_HS_DATA)`
  Review: Low-risk line; verify in surrounding control flow.
- L01049 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01050 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01051 [NONE] `	/* Look up the pending entry */`
  Review: Low-risk line; verify in surrounding control flow.
- L01052 [NONE] `	read_lock_irqsave(&quic_hs_table_lock, flags);`
  Review: Low-risk line; verify in surrounding control flow.
- L01053 [NONE] `	hash_for_each_possible(quic_hs_table, iter, hlist, rsp->handle) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01054 [NONE] `		if (iter->handle == rsp->handle) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01055 [NONE] `			entry = iter;`
  Review: Low-risk line; verify in surrounding control flow.
- L01056 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01057 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01058 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01059 [NONE] `	read_unlock_irqrestore(&quic_hs_table_lock, flags);`
  Review: Low-risk line; verify in surrounding control flow.
- L01060 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01061 [NONE] `	if (!entry) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01062 [ERROR_PATH|] `		pr_warn_ratelimited("QUIC IPC: RSP for unknown handle %u\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01063 [NONE] `				    rsp->handle);`
  Review: Low-risk line; verify in surrounding control flow.
- L01064 [ERROR_PATH|] `		return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01065 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01066 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01067 [NONE] `	/* Copy keys and status into the connection struct */`
  Review: Low-risk line; verify in surrounding control flow.
- L01068 [NONE] `	if (rsp->success && entry->qconn) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01069 [NONE] `		struct ksmbd_quic_conn *qconn = entry->qconn;`
  Review: Low-risk line; verify in surrounding control flow.
- L01070 [NONE] `		unsigned long qflags;`
  Review: Low-risk line; verify in surrounding control flow.
- L01071 [NONE] `		u8 key_len = (rsp->cipher == KSMBD_QUIC_CIPHER_AES256GCM)`
  Review: Low-risk line; verify in surrounding control flow.
- L01072 [NONE] `				? 32 : 16;`
  Review: Low-risk line; verify in surrounding control flow.
- L01073 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01074 [NONE] `		spin_lock_irqsave(&qconn->lock, qflags);`
  Review: Low-risk line; verify in surrounding control flow.
- L01075 [MEM_BOUNDS|] `		memcpy(qconn->app_crypto.write_key, rsp->write_key, key_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01076 [MEM_BOUNDS|] `		memcpy(qconn->app_crypto.write_iv, rsp->write_iv,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01077 [NONE] `		       KSMBD_QUIC_IV_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L01078 [MEM_BOUNDS|] `		memcpy(qconn->app_crypto.read_key, rsp->read_key, key_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01079 [MEM_BOUNDS|] `		memcpy(qconn->app_crypto.read_iv, rsp->read_iv,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01080 [NONE] `		       KSMBD_QUIC_IV_SIZE);`
  Review: Low-risk line; verify in surrounding control flow.
- L01081 [NONE] `		qconn->app_crypto.key_len = key_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01082 [NONE] `		qconn->app_crypto.ready = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L01083 [NONE] `		spin_unlock_irqrestore(&qconn->lock, qflags);`
  Review: Low-risk line; verify in surrounding control flow.
- L01084 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01085 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01086 [NONE] `		 * Send the server handshake flight back to the client.`
  Review: Low-risk line; verify in surrounding control flow.
- L01087 [NONE] `		 * This is called from the genl receive context (process context`
  Review: Low-risk line; verify in surrounding control flow.
- L01088 [NONE] `		 * via netlink workqueue), which is safe for sendmsg.`
  Review: Low-risk line; verify in surrounding control flow.
- L01089 [NONE] `		 * Declared below; body implemented in the send-handshake section.`
  Review: Low-risk line; verify in surrounding control flow.
- L01090 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01091 [NONE] `		if (rsp->hs_data_len > 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01092 [NONE] `			quic_send_handshake_data(qconn, rsp->hs_data,`
  Review: Low-risk line; verify in surrounding control flow.
- L01093 [NONE] `						 rsp->hs_data_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01094 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01095 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01096 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01097 [NONE] `	entry->success = !!rsp->success;`
  Review: Low-risk line; verify in surrounding control flow.
- L01098 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01099 [NONE] `	/* Scrub key material from the response buffer on the stack */`
  Review: Low-risk line; verify in surrounding control flow.
- L01100 [NONE] `	memzero_explicit(rsp->write_key, sizeof(rsp->write_key));`
  Review: Low-risk line; verify in surrounding control flow.
- L01101 [NONE] `	memzero_explicit(rsp->write_iv, sizeof(rsp->write_iv));`
  Review: Low-risk line; verify in surrounding control flow.
- L01102 [NONE] `	memzero_explicit(rsp->read_key, sizeof(rsp->read_key));`
  Review: Low-risk line; verify in surrounding control flow.
- L01103 [NONE] `	memzero_explicit(rsp->read_iv, sizeof(rsp->read_iv));`
  Review: Low-risk line; verify in surrounding control flow.
- L01104 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01105 [NONE] `	complete(&entry->done);`
  Review: Low-risk line; verify in surrounding control flow.
- L01106 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01107 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01108 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01109 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01110 [NONE] ` * quic_hs_ipc_alloc_handle() - allocate a unique IPC correlation handle`
  Review: Low-risk line; verify in surrounding control flow.
- L01111 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01112 [NONE] ` * Return: non-negative handle on success, negative errno on failure.`
  Review: Low-risk line; verify in surrounding control flow.
- L01113 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01114 [NONE] `static int quic_hs_ipc_alloc_handle(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L01115 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01116 [NONE] `	return ida_alloc_min(&quic_hs_ida, 1, GFP_KERNEL);`
  Review: Low-risk line; verify in surrounding control flow.
- L01117 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01118 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01119 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01120 [NONE] ` * quic_hs_ipc_free_handle() - release an IPC correlation handle`
  Review: Low-risk line; verify in surrounding control flow.
- L01121 [NONE] ` * @handle:	Handle previously returned by quic_hs_ipc_alloc_handle()`
  Review: Low-risk line; verify in surrounding control flow.
- L01122 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01123 [NONE] `static void quic_hs_ipc_free_handle(int handle)`
  Review: Low-risk line; verify in surrounding control flow.
- L01124 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01125 [NONE] `	if (handle >= 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01126 [NONE] `		ida_free(&quic_hs_ida, handle);`
  Review: Low-risk line; verify in surrounding control flow.
- L01127 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01128 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01129 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01130 [NONE] ` * quic_hs_ipc_send_req() - send a HANDSHAKE_REQ to the userspace daemon`
  Review: Low-risk line; verify in surrounding control flow.
- L01131 [NONE] ` * @qconn:	QUIC connection carrying the ClientHello`
  Review: Low-risk line; verify in surrounding control flow.
- L01132 [NONE] ` * @handle:	IPC correlation handle`
  Review: Low-risk line; verify in surrounding control flow.
- L01133 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01134 [NONE] ` * Builds and sends a KSMBD_QUIC_CMD_HANDSHAKE_REQ via the SMBD_QUIC genl`
  Review: Low-risk line; verify in surrounding control flow.
- L01135 [NONE] ` * family to the registered ksmbdctl daemon process.`
  Review: Low-risk line; verify in surrounding control flow.
- L01136 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01137 [NONE] ` * Return: 0 on success, negative errno on failure.`
  Review: Low-risk line; verify in surrounding control flow.
- L01138 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01139 [NONE] `static int quic_hs_ipc_send_req(struct ksmbd_quic_conn *qconn, int handle)`
  Review: Low-risk line; verify in surrounding control flow.
- L01140 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01141 [NONE] `	struct ksmbd_quic_handshake_req *req;`
  Review: Low-risk line; verify in surrounding control flow.
- L01142 [NONE] `	struct sk_buff *skb;`
  Review: Low-risk line; verify in surrounding control flow.
- L01143 [NONE] `	void *hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L01144 [NONE] `	unsigned int tools_pid;`
  Review: Low-risk line; verify in surrounding control flow.
- L01145 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01146 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01147 [LOCK|] `	spin_lock(&quic_tools_pid_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01148 [NONE] `	tools_pid = quic_tools_pid;`
  Review: Low-risk line; verify in surrounding control flow.
- L01149 [LOCK|] `	spin_unlock(&quic_tools_pid_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01150 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01151 [NONE] `	if (!tools_pid) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01152 [ERROR_PATH|] `		pr_warn_ratelimited("QUIC: no userspace handshake daemon registered\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01153 [ERROR_PATH|] `		return -ENOENT;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01154 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01155 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01156 [NONE] `	skb = genlmsg_new(sizeof(*req), GFP_KERNEL);`
  Review: Low-risk line; verify in surrounding control flow.
- L01157 [NONE] `	if (!skb)`
  Review: Low-risk line; verify in surrounding control flow.
- L01158 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01159 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01160 [NONE] `	hdr = genlmsg_put(skb, 0, 0, &quic_hs_genl_family, 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L01161 [NONE] `			  KSMBD_QUIC_CMD_HANDSHAKE_REQ);`
  Review: Low-risk line; verify in surrounding control flow.
- L01162 [NONE] `	if (!hdr) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01163 [NONE] `		nlmsg_free(skb);`
  Review: Low-risk line; verify in surrounding control flow.
- L01164 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01165 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01166 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01167 [MEM_BOUNDS|] `	req = kzalloc(sizeof(*req), GFP_KERNEL);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01168 [NONE] `	if (!req) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01169 [NONE] `		genlmsg_cancel(skb, hdr);`
  Review: Low-risk line; verify in surrounding control flow.
- L01170 [NONE] `		nlmsg_free(skb);`
  Review: Low-risk line; verify in surrounding control flow.
- L01171 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01172 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01173 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01174 [NONE] `	req->handle = (u32)handle;`
  Review: Low-risk line; verify in surrounding control flow.
- L01175 [NONE] `	/* Store DCID as big-endian u64 (use first 8 bytes, zero-padded) */`
  Review: Low-risk line; verify in surrounding control flow.
- L01176 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L01177 [NONE] `		u64 cid = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01178 [NONE] `		int i, n = min_t(int, qconn->dcid_len, 8);`
  Review: Low-risk line; verify in surrounding control flow.
- L01179 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01180 [NONE] `		for (i = 0; i < n; i++)`
  Review: Low-risk line; verify in surrounding control flow.
- L01181 [NONE] `			cid = (cid << 8) | qconn->dcid[i];`
  Review: Low-risk line; verify in surrounding control flow.
- L01182 [NONE] `		req->conn_id = cpu_to_be64(cid);`
  Review: Low-risk line; verify in surrounding control flow.
- L01183 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01184 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01185 [NONE] `	/* Peer address */`
  Review: Low-risk line; verify in surrounding control flow.
- L01186 [NONE] `	if (qconn->peer.ss_family == AF_INET6) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01187 [NONE] `		struct sockaddr_in6 *sin6 =`
  Review: Low-risk line; verify in surrounding control flow.
- L01188 [NONE] `			(struct sockaddr_in6 *)&qconn->peer;`
  Review: Low-risk line; verify in surrounding control flow.
- L01189 [MEM_BOUNDS|] `		memcpy(req->peer_addr, &sin6->sin6_addr, 16);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01190 [NONE] `		req->peer_port = ntohs(sin6->sin6_port);`
  Review: Low-risk line; verify in surrounding control flow.
- L01191 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L01192 [NONE] `		struct sockaddr_in *sin = (struct sockaddr_in *)&qconn->peer;`
  Review: Low-risk line; verify in surrounding control flow.
- L01193 [NONE] `		/* IPv4-mapped IPv6 encoding */`
  Review: Low-risk line; verify in surrounding control flow.
- L01194 [NONE] `		req->peer_addr[10] = 0xff;`
  Review: Low-risk line; verify in surrounding control flow.
- L01195 [NONE] `		req->peer_addr[11] = 0xff;`
  Review: Low-risk line; verify in surrounding control flow.
- L01196 [MEM_BOUNDS|] `		memcpy(req->peer_addr + 12, &sin->sin_addr, 4);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01197 [NONE] `		req->peer_port = ntohs(sin->sin_port);`
  Review: Low-risk line; verify in surrounding control flow.
- L01198 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01199 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01200 [NONE] `	/* ClientHello bytes */`
  Review: Low-risk line; verify in surrounding control flow.
- L01201 [NONE] `	req->client_hello_len = (u32)min_t(size_t, qconn->crypto_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01202 [NONE] `					   KSMBD_QUIC_MAX_CLIENT_HELLO);`
  Review: Low-risk line; verify in surrounding control flow.
- L01203 [MEM_BOUNDS|] `	memcpy(req->client_hello, qconn->crypto_buf, req->client_hello_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01204 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01205 [NONE] `	ret = nla_put(skb, KSMBD_QUIC_CMD_HANDSHAKE_REQ, sizeof(*req), req);`
  Review: Low-risk line; verify in surrounding control flow.
- L01206 [NONE] `	kfree(req);`
  Review: Low-risk line; verify in surrounding control flow.
- L01207 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01208 [NONE] `		genlmsg_cancel(skb, hdr);`
  Review: Low-risk line; verify in surrounding control flow.
- L01209 [NONE] `		nlmsg_free(skb);`
  Review: Low-risk line; verify in surrounding control flow.
- L01210 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01211 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01212 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01213 [NONE] `	genlmsg_end(skb, hdr);`
  Review: Low-risk line; verify in surrounding control flow.
- L01214 [NONE] `	ret = genlmsg_unicast(&init_net, skb, tools_pid);`
  Review: Low-risk line; verify in surrounding control flow.
- L01215 [NONE] `	return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01216 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01217 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01218 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01219 [NONE] ` * quic_hs_ipc_request() - perform a synchronous QUIC handshake IPC round-trip`
  Review: Low-risk line; verify in surrounding control flow.
- L01220 [NONE] ` * @qconn:	QUIC connection (crypto_buf must be populated with ClientHello)`
  Review: Low-risk line; verify in surrounding control flow.
- L01221 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01222 [NONE] ` * Allocates a handle, registers a pending entry, sends the HANDSHAKE_REQ,`
  Review: Low-risk line; verify in surrounding control flow.
- L01223 [NONE] ` * and blocks (up to QUIC_HS_IPC_TIMEOUT_MS) for the userspace response.`
  Review: Low-risk line; verify in surrounding control flow.
- L01224 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01225 [NONE] ` * Return: true if handshake succeeded, false on failure or timeout.`
  Review: Low-risk line; verify in surrounding control flow.
- L01226 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01227 [NONE] `static bool quic_hs_ipc_request(struct ksmbd_quic_conn *qconn)`
  Review: Low-risk line; verify in surrounding control flow.
- L01228 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01229 [NONE] `	struct quic_hs_pending pending;`
  Review: Low-risk line; verify in surrounding control flow.
- L01230 [NONE] `	unsigned long flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L01231 [NONE] `	bool success = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L01232 [NONE] `	int handle, ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01233 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01234 [NONE] `	handle = quic_hs_ipc_alloc_handle();`
  Review: Low-risk line; verify in surrounding control flow.
- L01235 [NONE] `	if (handle < 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01236 [ERROR_PATH|] `		pr_warn_ratelimited("QUIC IPC: handle allocation failed\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01237 [NONE] `		return false;`
  Review: Low-risk line; verify in surrounding control flow.
- L01238 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01239 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01240 [NONE] `	pending.handle  = (unsigned int)handle;`
  Review: Low-risk line; verify in surrounding control flow.
- L01241 [NONE] `	pending.qconn   = qconn;`
  Review: Low-risk line; verify in surrounding control flow.
- L01242 [NONE] `	pending.success = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L01243 [NONE] `	init_completion(&pending.done);`
  Review: Low-risk line; verify in surrounding control flow.
- L01244 [NONE] `	INIT_HLIST_NODE(&pending.hlist);`
  Review: Low-risk line; verify in surrounding control flow.
- L01245 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01246 [NONE] `	/* Register in the pending table */`
  Review: Low-risk line; verify in surrounding control flow.
- L01247 [NONE] `	write_lock_irqsave(&quic_hs_table_lock, flags);`
  Review: Low-risk line; verify in surrounding control flow.
- L01248 [NONE] `	hash_add(quic_hs_table, &pending.hlist, pending.handle);`
  Review: Low-risk line; verify in surrounding control flow.
- L01249 [NONE] `	write_unlock_irqrestore(&quic_hs_table_lock, flags);`
  Review: Low-risk line; verify in surrounding control flow.
- L01250 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01251 [NONE] `	qconn->ipc_handle = handle;`
  Review: Low-risk line; verify in surrounding control flow.
- L01252 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01253 [NONE] `	ret = quic_hs_ipc_send_req(qconn, handle);`
  Review: Low-risk line; verify in surrounding control flow.
- L01254 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01255 [ERROR_PATH|] `		pr_warn_ratelimited("QUIC IPC: send REQ failed: %d\n", ret);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01256 [ERROR_PATH|] `		goto out_remove;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01257 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01258 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01259 [NONE] `	/* Wait for userspace response */`
  Review: Low-risk line; verify in surrounding control flow.
- L01260 [NONE] `	ret = wait_for_completion_timeout(&pending.done,`
  Review: Low-risk line; verify in surrounding control flow.
- L01261 [NONE] `			msecs_to_jiffies(QUIC_HS_IPC_TIMEOUT_MS));`
  Review: Low-risk line; verify in surrounding control flow.
- L01262 [NONE] `	if (!ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01263 [ERROR_PATH|] `		pr_warn_ratelimited("QUIC IPC: handshake timeout (handle=%u)\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01264 [NONE] `				    handle);`
  Review: Low-risk line; verify in surrounding control flow.
- L01265 [ERROR_PATH|] `		goto out_remove;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01266 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01267 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01268 [NONE] `	success = pending.success;`
  Review: Low-risk line; verify in surrounding control flow.
- L01269 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01270 [NONE] `out_remove:`
  Review: Low-risk line; verify in surrounding control flow.
- L01271 [NONE] `	write_lock_irqsave(&quic_hs_table_lock, flags);`
  Review: Low-risk line; verify in surrounding control flow.
- L01272 [NONE] `	hash_del(&pending.hlist);`
  Review: Low-risk line; verify in surrounding control flow.
- L01273 [NONE] `	write_unlock_irqrestore(&quic_hs_table_lock, flags);`
  Review: Low-risk line; verify in surrounding control flow.
- L01274 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01275 [NONE] `	quic_hs_ipc_free_handle(handle);`
  Review: Low-risk line; verify in surrounding control flow.
- L01276 [NONE] `	qconn->ipc_handle = -1;`
  Review: Low-risk line; verify in surrounding control flow.
- L01277 [NONE] `	return success;`
  Review: Low-risk line; verify in surrounding control flow.
- L01278 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01279 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01280 [NONE] `/* =========================================================================`
  Review: Low-risk line; verify in surrounding control flow.
- L01281 [NONE] ` * QUIC CONNECTION_CLOSE frame sender (RFC 9000 §19.19)`
  Review: Low-risk line; verify in surrounding control flow.
- L01282 [NONE] ` * =========================================================================`
  Review: Low-risk line; verify in surrounding control flow.
- L01283 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01284 [NONE] ` * Sends a CONNECTION_CLOSE frame (type 0x1c) to the peer in a QUIC Initial`
  Review: Low-risk line; verify in surrounding control flow.
- L01285 [NONE] ` * long-header packet.  This is the correct packet number space to use when`
  Review: Low-risk line; verify in surrounding control flow.
- L01286 [NONE] ` * closing a connection that never progressed past the Initial phase (RFC 9000`
  Review: Low-risk line; verify in surrounding control flow.
- L01287 [NONE] ` * §10.2.3).`
  Review: Low-risk line; verify in surrounding control flow.
- L01288 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01289 [NONE] ` * For simplicity we send the CONNECTION_CLOSE unencrypted with a stub header`
  Review: Low-risk line; verify in surrounding control flow.
- L01290 [NONE] ` * (no AEAD — same as the current writev path).  A production implementation`
  Review: Low-risk line; verify in surrounding control flow.
- L01291 [NONE] ` * would encrypt it with the Initial TX keys.`
  Review: Low-risk line; verify in surrounding control flow.
- L01292 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01293 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01294 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01295 [NONE] ` * quic_send_connection_close() - send a CONNECTION_CLOSE to the peer`
  Review: Low-risk line; verify in surrounding control flow.
- L01296 [NONE] ` * @qconn:	QUIC connection`
  Review: Low-risk line; verify in surrounding control flow.
- L01297 [NONE] ` * @error_code:	QUIC transport error code (QUIC_ERR_*)`
  Review: Low-risk line; verify in surrounding control flow.
- L01298 [NONE] ` * @reason:	Human-readable reason phrase (may be NULL)`
  Review: Low-risk line; verify in surrounding control flow.
- L01299 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01300 [NONE] ` * Builds a QUIC Initial long-header packet containing a CONNECTION_CLOSE`
  Review: Low-risk line; verify in surrounding control flow.
- L01301 [NONE] ` * frame and sends it to @qconn->peer via @qconn->udp_sock.`
  Review: Low-risk line; verify in surrounding control flow.
- L01302 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01303 [NONE] ` * This function is safe to call from process context (sendmsg path).`
  Review: Low-risk line; verify in surrounding control flow.
- L01304 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01305 [NONE] `static void quic_send_connection_close(struct ksmbd_quic_conn *qconn,`
  Review: Low-risk line; verify in surrounding control flow.
- L01306 [NONE] `				       u64 error_code, const char *reason)`
  Review: Low-risk line; verify in surrounding control flow.
- L01307 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01308 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01309 [NONE] `	 * Packet layout (simplified, not AEAD-encrypted):`
  Review: Low-risk line; verify in surrounding control flow.
- L01310 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L01311 [NONE] `	 * Long header (RFC 9000 §17.2):`
  Review: Low-risk line; verify in surrounding control flow.
- L01312 [NONE] `	 *   [0]      first byte: 0xC0 (Long, Fixed, Initial type 0x00)`
  Review: Low-risk line; verify in surrounding control flow.
- L01313 [NONE] `	 *   [1..4]   version:    QUIC_VERSION_1`
  Review: Low-risk line; verify in surrounding control flow.
- L01314 [NONE] `	 *   [5]      DCID len`
  Review: Low-risk line; verify in surrounding control flow.
- L01315 [NONE] `	 *   [6..5+dlen] DCID (peer's SCID = their expected DCID)`
  Review: Low-risk line; verify in surrounding control flow.
- L01316 [NONE] `	 *   [6+dlen] SCID len`
  Review: Low-risk line; verify in surrounding control flow.
- L01317 [NONE] `	 *   [7+dlen..6+dlen+slen] SCID (our DCID)`
  Review: Low-risk line; verify in surrounding control flow.
- L01318 [NONE] `	 *   Token length: 0x00 (no token)`
  Review: Low-risk line; verify in surrounding control flow.
- L01319 [NONE] `	 *   Payload length: varint (CONNECTION_CLOSE frame size)`
  Review: Low-risk line; verify in surrounding control flow.
- L01320 [NONE] `	 *   Packet number: 1 byte (stub)`
  Review: Low-risk line; verify in surrounding control flow.
- L01321 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L01322 [NONE] `	 * CONNECTION_CLOSE frame (RFC 9000 §19.19):`
  Review: Low-risk line; verify in surrounding control flow.
- L01323 [NONE] `	 *   frame type: 0x1c (1 byte)`
  Review: Low-risk line; verify in surrounding control flow.
- L01324 [NONE] `	 *   error code: varint`
  Review: Low-risk line; verify in surrounding control flow.
- L01325 [NONE] `	 *   frame type triggering error: varint (0 = unspecified)`
  Review: Low-risk line; verify in surrounding control flow.
- L01326 [NONE] `	 *   reason phrase length: varint`
  Review: Low-risk line; verify in surrounding control flow.
- L01327 [NONE] `	 *   reason phrase: bytes`
  Review: Low-risk line; verify in surrounding control flow.
- L01328 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01329 [NONE] `	u8 pkt[256];`
  Review: Low-risk line; verify in surrounding control flow.
- L01330 [NONE] `	u8 *p = pkt;`
  Review: Low-risk line; verify in surrounding control flow.
- L01331 [NONE] `	size_t reason_len = reason ? strlen(reason) : 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01332 [NONE] `	size_t frame_len, payload_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01333 [NONE] `	struct msghdr msg = {};`
  Review: Low-risk line; verify in surrounding control flow.
- L01334 [NONE] `	struct kvec iov;`
  Review: Low-risk line; verify in surrounding control flow.
- L01335 [NONE] `	u8 frame[64];`
  Review: Low-risk line; verify in surrounding control flow.
- L01336 [NONE] `	u8 *fp = frame;`
  Review: Low-risk line; verify in surrounding control flow.
- L01337 [NONE] `	int vl;`
  Review: Low-risk line; verify in surrounding control flow.
- L01338 [NONE] `	unsigned long flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L01339 [NONE] `	u64 pkt_num;`
  Review: Low-risk line; verify in surrounding control flow.
- L01340 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01341 [NONE] `	/* Build CONNECTION_CLOSE frame */`
  Review: Low-risk line; verify in surrounding control flow.
- L01342 [NONE] `	*fp++ = QUIC_FRAME_CONNECTION_CLOSE;`
  Review: Low-risk line; verify in surrounding control flow.
- L01343 [NONE] `	/* error code */`
  Review: Low-risk line; verify in surrounding control flow.
- L01344 [NONE] `	if (ksmbd_quic_put_varint(fp, error_code, &vl))`
  Review: Low-risk line; verify in surrounding control flow.
- L01345 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L01346 [NONE] `	fp += vl;`
  Review: Low-risk line; verify in surrounding control flow.
- L01347 [NONE] `	/* frame type that triggered the error (0 = not applicable) */`
  Review: Low-risk line; verify in surrounding control flow.
- L01348 [NONE] `	if (ksmbd_quic_put_varint(fp, 0, &vl))`
  Review: Low-risk line; verify in surrounding control flow.
- L01349 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L01350 [NONE] `	fp += vl;`
  Review: Low-risk line; verify in surrounding control flow.
- L01351 [NONE] `	/* reason phrase length */`
  Review: Low-risk line; verify in surrounding control flow.
- L01352 [NONE] `	if (reason_len > 63)`
  Review: Low-risk line; verify in surrounding control flow.
- L01353 [NONE] `		reason_len = 63;`
  Review: Low-risk line; verify in surrounding control flow.
- L01354 [NONE] `	if (ksmbd_quic_put_varint(fp, reason_len, &vl))`
  Review: Low-risk line; verify in surrounding control flow.
- L01355 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L01356 [NONE] `	fp += vl;`
  Review: Low-risk line; verify in surrounding control flow.
- L01357 [NONE] `	/* reason phrase */`
  Review: Low-risk line; verify in surrounding control flow.
- L01358 [NONE] `	if (reason_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01359 [MEM_BOUNDS|] `		memcpy(fp, reason, reason_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01360 [NONE] `		fp += reason_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01361 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01362 [NONE] `	frame_len = fp - frame;`
  Review: Low-risk line; verify in surrounding control flow.
- L01363 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01364 [NONE] `	/* Long header */`
  Review: Low-risk line; verify in surrounding control flow.
- L01365 [NONE] `	*p++ = QUIC_HDR_FORM_LONG | QUIC_HDR_FIXED_BIT | QUIC_LONG_TYPE_INITIAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01366 [NONE] `	put_unaligned_be32(QUIC_VERSION_1, p);`
  Review: Low-risk line; verify in surrounding control flow.
- L01367 [NONE] `	p += 4;`
  Review: Low-risk line; verify in surrounding control flow.
- L01368 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01369 [NONE] `	/* DCID = peer's SCID (their expected destination) */`
  Review: Low-risk line; verify in surrounding control flow.
- L01370 [NONE] `	*p++ = qconn->scid_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01371 [MEM_BOUNDS|] `	memcpy(p, qconn->scid, qconn->scid_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01372 [NONE] `	p += qconn->scid_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01373 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01374 [NONE] `	/* SCID = our DCID */`
  Review: Low-risk line; verify in surrounding control flow.
- L01375 [NONE] `	*p++ = qconn->dcid_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01376 [MEM_BOUNDS|] `	memcpy(p, qconn->dcid, qconn->dcid_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01377 [NONE] `	p += qconn->dcid_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01378 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01379 [NONE] `	/* Token length = 0 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01380 [NONE] `	*p++ = 0x00;`
  Review: Low-risk line; verify in surrounding control flow.
- L01381 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01382 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01383 [NONE] `	 * Payload length = 1 (packet number) + frame_len.`
  Review: Low-risk line; verify in surrounding control flow.
- L01384 [NONE] `	 * Encode as varint.`
  Review: Low-risk line; verify in surrounding control flow.
- L01385 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01386 [NONE] `	payload_len = 1 + frame_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01387 [NONE] `	if (ksmbd_quic_put_varint(p, payload_len, &vl))`
  Review: Low-risk line; verify in surrounding control flow.
- L01388 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L01389 [NONE] `	p += vl;`
  Review: Low-risk line; verify in surrounding control flow.
- L01390 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01391 [NONE] `	/* Packet number (1 byte, stub) */`
  Review: Low-risk line; verify in surrounding control flow.
- L01392 [NONE] `	spin_lock_irqsave(&qconn->lock, flags);`
  Review: Low-risk line; verify in surrounding control flow.
- L01393 [NONE] `	pkt_num = qconn->send_pkt_num++;`
  Review: Low-risk line; verify in surrounding control flow.
- L01394 [NONE] `	spin_unlock_irqrestore(&qconn->lock, flags);`
  Review: Low-risk line; verify in surrounding control flow.
- L01395 [NONE] `	*p++ = (u8)(pkt_num & 0xFF);`
  Review: Low-risk line; verify in surrounding control flow.
- L01396 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01397 [NONE] `	/* CONNECTION_CLOSE frame */`
  Review: Low-risk line; verify in surrounding control flow.
- L01398 [NONE] `	if ((size_t)(p - pkt) + frame_len > sizeof(pkt))`
  Review: Low-risk line; verify in surrounding control flow.
- L01399 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L01400 [MEM_BOUNDS|] `	memcpy(p, frame, frame_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01401 [NONE] `	p += frame_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01402 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01403 [NONE] `	msg.msg_name    = &qconn->peer;`
  Review: Low-risk line; verify in surrounding control flow.
- L01404 [NONE] `	msg.msg_namelen = qconn->peer_addrlen;`
  Review: Low-risk line; verify in surrounding control flow.
- L01405 [NONE] `	msg.msg_flags   = MSG_NOSIGNAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01406 [NONE] `	iov.iov_base    = pkt;`
  Review: Low-risk line; verify in surrounding control flow.
- L01407 [NONE] `	iov.iov_len     = p - pkt;`
  Review: Low-risk line; verify in surrounding control flow.
- L01408 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01409 [NONE] `	kernel_sendmsg(qconn->udp_sock, &msg, &iov, 1, iov.iov_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01410 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01411 [NONE] `	ksmbd_debug(CONN, "QUIC: sent CONNECTION_CLOSE (err=0x%llx reason=%s)\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L01412 [NONE] `		    error_code, reason ? reason : "");`
  Review: Low-risk line; verify in surrounding control flow.
- L01413 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01414 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01415 [NONE] `/* =========================================================================`
  Review: Low-risk line; verify in surrounding control flow.
- L01416 [NONE] ` * QUIC CRYPTO frame parsing (RFC 9000 §19.6)`
  Review: Low-risk line; verify in surrounding control flow.
- L01417 [NONE] ` * =========================================================================`
  Review: Low-risk line; verify in surrounding control flow.
- L01418 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01419 [NONE] ` * CRYPTO frames carry TLS handshake data in QUIC Initial packets.`
  Review: Low-risk line; verify in surrounding control flow.
- L01420 [NONE] ` * The frame format is:`
  Review: Low-risk line; verify in surrounding control flow.
- L01421 [NONE] ` *   Type:    0x06 (1 byte)`
  Review: Low-risk line; verify in surrounding control flow.
- L01422 [NONE] ` *   Offset:  variable-length integer (byte offset into the CRYPTO stream)`
  Review: Low-risk line; verify in surrounding control flow.
- L01423 [NONE] ` *   Length:  variable-length integer`
  Review: Low-risk line; verify in surrounding control flow.
- L01424 [NONE] ` *   Data:    TLS record bytes`
  Review: Low-risk line; verify in surrounding control flow.
- L01425 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01426 [NONE] ` * We buffer the data into qconn->crypto_buf, respecting the Offset field`
  Review: Low-risk line; verify in surrounding control flow.
- L01427 [NONE] ` * for in-order reassembly.  In practice the entire ClientHello fits in a`
  Review: Low-risk line; verify in surrounding control flow.
- L01428 [NONE] ` * single Initial packet, so the offset is typically 0.`
  Review: Low-risk line; verify in surrounding control flow.
- L01429 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01430 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01431 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01432 [NONE] ` * quic_parse_crypto_frames() - extract CRYPTO frame data from Initial payload`
  Review: Low-risk line; verify in surrounding control flow.
- L01433 [NONE] ` * @qconn:	QUIC connection (crypto_buf is updated)`
  Review: Low-risk line; verify in surrounding control flow.
- L01434 [NONE] ` * @payload:	Decrypted packet payload (frame stream)`
  Review: Low-risk line; verify in surrounding control flow.
- L01435 [NONE] ` * @payload_len: Length of @payload`
  Review: Low-risk line; verify in surrounding control flow.
- L01436 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01437 [NONE] ` * Scans all frames in the payload; for each CRYPTO frame with offset 0`
  Review: Low-risk line; verify in surrounding control flow.
- L01438 [NONE] ` * (or a contiguous extension), appends the data to qconn->crypto_buf.`
  Review: Low-risk line; verify in surrounding control flow.
- L01439 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01440 [NONE] ` * Also handles PADDING (0x00) and PING (0x01) frames gracefully.`
  Review: Low-risk line; verify in surrounding control flow.
- L01441 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01442 [NONE] ` * Return: number of CRYPTO bytes appended (>= 0), or -EINVAL on parse error.`
  Review: Low-risk line; verify in surrounding control flow.
- L01443 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01444 [NONE] `static int quic_parse_crypto_frames(struct ksmbd_quic_conn *qconn,`
  Review: Low-risk line; verify in surrounding control flow.
- L01445 [NONE] `				    const u8 *payload, size_t payload_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L01446 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01447 [NONE] `	int total_crypto = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01448 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01449 [NONE] `	while (payload_len > 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01450 [NONE] `		u8 frame_type = payload[0];`
  Review: Low-risk line; verify in surrounding control flow.
- L01451 [NONE] `		const u8 *fp = payload + 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L01452 [NONE] `		size_t fp_rem = payload_len - 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L01453 [NONE] `		u64 offset, length;`
  Review: Low-risk line; verify in surrounding control flow.
- L01454 [NONE] `		int consumed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01455 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01456 [NONE] `		/* PADDING: single 0x00 byte */`
  Review: Low-risk line; verify in surrounding control flow.
- L01457 [NONE] `		if (frame_type == QUIC_FRAME_PADDING) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01458 [NONE] `			payload++;`
  Review: Low-risk line; verify in surrounding control flow.
- L01459 [NONE] `			payload_len--;`
  Review: Low-risk line; verify in surrounding control flow.
- L01460 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L01461 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01462 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01463 [NONE] `		/* PING: single 0x01 byte, no data */`
  Review: Low-risk line; verify in surrounding control flow.
- L01464 [NONE] `		if (frame_type == QUIC_FRAME_PING) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01465 [NONE] `			payload++;`
  Review: Low-risk line; verify in surrounding control flow.
- L01466 [NONE] `			payload_len--;`
  Review: Low-risk line; verify in surrounding control flow.
- L01467 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L01468 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01469 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01470 [NONE] `		/* ACK frame: variable length — skip by consuming its fields */`
  Review: Low-risk line; verify in surrounding control flow.
- L01471 [NONE] `		if (frame_type == QUIC_FRAME_ACK ||`
  Review: Low-risk line; verify in surrounding control flow.
- L01472 [NONE] `		    frame_type == (QUIC_FRAME_ACK | 0x01)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01473 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01474 [NONE] `			 * ACK frame has: Largest Acknowledged (varint),`
  Review: Low-risk line; verify in surrounding control flow.
- L01475 [NONE] `			 * ACK Delay (varint), ACK Range Count (varint),`
  Review: Low-risk line; verify in surrounding control flow.
- L01476 [NONE] `			 * First ACK Range (varint), then ACK Range Count`
  Review: Low-risk line; verify in surrounding control flow.
- L01477 [NONE] `			 * pairs.  For simplicity: parse and skip the first`
  Review: Low-risk line; verify in surrounding control flow.
- L01478 [NONE] `			 * 4 varints, then skip ACK Range Count * 2 varints.`
  Review: Low-risk line; verify in surrounding control flow.
- L01479 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01480 [NONE] `			u64 largest_ack, ack_delay, range_count, first_range;`
  Review: Low-risk line; verify in surrounding control flow.
- L01481 [NONE] `			u64 gap, range_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01482 [NONE] `			u64 i;`
  Review: Low-risk line; verify in surrounding control flow.
- L01483 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01484 [NONE] `			if (ksmbd_quic_get_varint(fp, fp_rem,`
  Review: Low-risk line; verify in surrounding control flow.
- L01485 [NONE] `						  &largest_ack, &consumed))`
  Review: Low-risk line; verify in surrounding control flow.
- L01486 [NONE] `				break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01487 [NONE] `			fp += consumed; fp_rem -= consumed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01488 [NONE] `			if (ksmbd_quic_get_varint(fp, fp_rem,`
  Review: Low-risk line; verify in surrounding control flow.
- L01489 [NONE] `						  &ack_delay, &consumed))`
  Review: Low-risk line; verify in surrounding control flow.
- L01490 [NONE] `				break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01491 [NONE] `			fp += consumed; fp_rem -= consumed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01492 [NONE] `			if (ksmbd_quic_get_varint(fp, fp_rem,`
  Review: Low-risk line; verify in surrounding control flow.
- L01493 [NONE] `						  &range_count, &consumed))`
  Review: Low-risk line; verify in surrounding control flow.
- L01494 [NONE] `				break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01495 [NONE] `			fp += consumed; fp_rem -= consumed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01496 [NONE] `			if (ksmbd_quic_get_varint(fp, fp_rem,`
  Review: Low-risk line; verify in surrounding control flow.
- L01497 [NONE] `						  &first_range, &consumed))`
  Review: Low-risk line; verify in surrounding control flow.
- L01498 [NONE] `				break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01499 [NONE] `			fp += consumed; fp_rem -= consumed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01500 [NONE] `			for (i = 0; i < range_count; i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01501 [NONE] `				if (ksmbd_quic_get_varint(fp, fp_rem,`
  Review: Low-risk line; verify in surrounding control flow.
- L01502 [NONE] `							  &gap, &consumed))`
  Review: Low-risk line; verify in surrounding control flow.
- L01503 [ERROR_PATH|] `					goto done_ack;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01504 [NONE] `				fp += consumed; fp_rem -= consumed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01505 [NONE] `				if (ksmbd_quic_get_varint(fp, fp_rem,`
  Review: Low-risk line; verify in surrounding control flow.
- L01506 [NONE] `							  &range_len, &consumed))`
  Review: Low-risk line; verify in surrounding control flow.
- L01507 [ERROR_PATH|] `					goto done_ack;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01508 [NONE] `				fp += consumed; fp_rem -= consumed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01509 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01510 [NONE] `done_ack:`
  Review: Low-risk line; verify in surrounding control flow.
- L01511 [NONE] `			payload    = fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L01512 [NONE] `			payload_len = fp_rem;`
  Review: Low-risk line; verify in surrounding control flow.
- L01513 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L01514 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01515 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01516 [NONE] `		/* CRYPTO frame (0x06) */`
  Review: Low-risk line; verify in surrounding control flow.
- L01517 [NONE] `		if (frame_type == QUIC_FRAME_CRYPTO) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01518 [NONE] `			if (ksmbd_quic_get_varint(fp, fp_rem,`
  Review: Low-risk line; verify in surrounding control flow.
- L01519 [NONE] `						  &offset, &consumed))`
  Review: Low-risk line; verify in surrounding control flow.
- L01520 [NONE] `				break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01521 [NONE] `			fp += consumed; fp_rem -= consumed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01522 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01523 [NONE] `			if (ksmbd_quic_get_varint(fp, fp_rem,`
  Review: Low-risk line; verify in surrounding control flow.
- L01524 [NONE] `						  &length, &consumed))`
  Review: Low-risk line; verify in surrounding control flow.
- L01525 [NONE] `				break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01526 [NONE] `			fp += consumed; fp_rem -= consumed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01527 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01528 [NONE] `			if (length > fp_rem)`
  Review: Low-risk line; verify in surrounding control flow.
- L01529 [NONE] `				break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01530 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01531 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01532 [NONE] `			 * Append to crypto_buf.  We only handle the simple`
  Review: Low-risk line; verify in surrounding control flow.
- L01533 [NONE] `			 * case where offset == 0 or continues from the last`
  Review: Low-risk line; verify in surrounding control flow.
- L01534 [NONE] `			 * byte we received.  Out-of-order fragments are dropped`
  Review: Low-risk line; verify in surrounding control flow.
- L01535 [NONE] `			 * (the client will retransmit).`
  Review: Low-risk line; verify in surrounding control flow.
- L01536 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01537 [NONE] `			if (offset == qconn->crypto_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01538 [NONE] `				size_t space = QUIC_MAX_CRYPTO_DATA`
  Review: Low-risk line; verify in surrounding control flow.
- L01539 [NONE] `					       - qconn->crypto_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01540 [NONE] `				size_t copy = min_t(size_t, (size_t)length,`
  Review: Low-risk line; verify in surrounding control flow.
- L01541 [NONE] `						    space);`
  Review: Low-risk line; verify in surrounding control flow.
- L01542 [NONE] `				if (copy > 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01543 [MEM_BOUNDS|] `					memcpy(qconn->crypto_buf +`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01544 [NONE] `					       qconn->crypto_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01545 [NONE] `					       fp, copy);`
  Review: Low-risk line; verify in surrounding control flow.
- L01546 [NONE] `					qconn->crypto_len += copy;`
  Review: Low-risk line; verify in surrounding control flow.
- L01547 [NONE] `					total_crypto += (int)copy;`
  Review: Low-risk line; verify in surrounding control flow.
- L01548 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L01549 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L01550 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01551 [NONE] `			fp += length;`
  Review: Low-risk line; verify in surrounding control flow.
- L01552 [NONE] `			fp_rem -= length;`
  Review: Low-risk line; verify in surrounding control flow.
- L01553 [NONE] `			payload     = fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L01554 [NONE] `			payload_len = fp_rem;`
  Review: Low-risk line; verify in surrounding control flow.
- L01555 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L01556 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01557 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01558 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01559 [NONE] `		 * Unknown frame type: we cannot skip it without knowing its`
  Review: Low-risk line; verify in surrounding control flow.
- L01560 [NONE] `		 * length, so stop parsing here.`
  Review: Low-risk line; verify in surrounding control flow.
- L01561 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01562 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L01563 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01564 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01565 [NONE] `	return total_crypto;`
  Review: Low-risk line; verify in surrounding control flow.
- L01566 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01567 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01568 [NONE] `/* =========================================================================`
  Review: Low-risk line; verify in surrounding control flow.
- L01569 [NONE] ` * QUIC server handshake flight sender`
  Review: Low-risk line; verify in surrounding control flow.
- L01570 [NONE] ` * =========================================================================`
  Review: Low-risk line; verify in surrounding control flow.
- L01571 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01572 [NONE] ` * After the TLS 1.3 handshake completes in userspace, the server must send`
  Review: Low-risk line; verify in surrounding control flow.
- L01573 [NONE] ` * the handshake flight (ServerHello + EncryptedExtensions + Certificate +`
  Review: Low-risk line; verify in surrounding control flow.
- L01574 [NONE] ` * CertificateVerify + Finished) back to the client.`
  Review: Low-risk line; verify in surrounding control flow.
- L01575 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01576 [NONE] ` * RFC 9000 §12.3 / RFC 9001 §4.1:`
  Review: Low-risk line; verify in surrounding control flow.
- L01577 [NONE] ` *   - ServerHello lives in the Initial packet number space.`
  Review: Low-risk line; verify in surrounding control flow.
- L01578 [NONE] ` *   - EncryptedExtensions through Finished live in the Handshake packet`
  Review: Low-risk line; verify in surrounding control flow.
- L01579 [NONE] ` *     number space.`
  Review: Low-risk line; verify in surrounding control flow.
- L01580 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01581 [NONE] ` * For simplicity in this implementation we send all handshake data in a`
  Review: Low-risk line; verify in surrounding control flow.
- L01582 [NONE] ` * single QUIC Initial long-header packet containing one CRYPTO frame.`
  Review: Low-risk line; verify in surrounding control flow.
- L01583 [NONE] ` * A production implementation would split across Initial and Handshake`
  Review: Low-risk line; verify in surrounding control flow.
- L01584 [NONE] ` * packets as required by the RFC, and would AEAD-encrypt each packet.`
  Review: Low-risk line; verify in surrounding control flow.
- L01585 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01586 [NONE] ` * The @data buffer from userspace contains the concatenated TLS records`
  Review: Low-risk line; verify in surrounding control flow.
- L01587 [NONE] ` * for the server flight.  We wrap them in a CRYPTO frame and send as a`
  Review: Low-risk line; verify in surrounding control flow.
- L01588 [NONE] ` * QUIC Initial packet using the server Initial TX keys.`
  Review: Low-risk line; verify in surrounding control flow.
- L01589 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01590 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01591 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01592 [NONE] ` * quic_send_handshake_data() - send server TLS flight to the client`
  Review: Low-risk line; verify in surrounding control flow.
- L01593 [NONE] ` * @qconn:	QUIC connection`
  Review: Low-risk line; verify in surrounding control flow.
- L01594 [NONE] ` * @data:	Server handshake flight bytes (TLS records)`
  Review: Low-risk line; verify in surrounding control flow.
- L01595 [NONE] ` * @len:	Number of bytes in @data`
  Review: Low-risk line; verify in surrounding control flow.
- L01596 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01597 [NONE] ` * Wraps @data in a QUIC CRYPTO frame inside a QUIC Initial long-header`
  Review: Low-risk line; verify in surrounding control flow.
- L01598 [NONE] ` * packet and sends it to @qconn->peer.`
  Review: Low-risk line; verify in surrounding control flow.
- L01599 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01600 [NONE] ` * Called from quic_hs_ipc_handle_rsp() (genl receive path, process context).`
  Review: Low-risk line; verify in surrounding control flow.
- L01601 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01602 [NONE] `static void quic_send_handshake_data(struct ksmbd_quic_conn *qconn,`
  Review: Low-risk line; verify in surrounding control flow.
- L01603 [NONE] `				     const u8 *data, size_t len)`
  Review: Low-risk line; verify in surrounding control flow.
- L01604 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01605 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01606 [NONE] `	 * Build: Initial long-header + CRYPTO frame + data.`
  Review: Low-risk line; verify in surrounding control flow.
- L01607 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L01608 [NONE] `	 * We fragment if len > (QUIC_MAX_PKT_SIZE - headers).`
  Review: Low-risk line; verify in surrounding control flow.
- L01609 [NONE] `	 * Maximum header overhead: 1 + 4 + 1+20 + 1+20 + 1 + 8 + 1 + 8 = 65 b`
  Review: Low-risk line; verify in surrounding control flow.
- L01610 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01611 [NONE] `	const size_t max_data_per_pkt = QUIC_MAX_PKT_SIZE - 80;`
  Review: Low-risk line; verify in surrounding control flow.
- L01612 [NONE] `	size_t offset_in_crypto = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01613 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01614 [NONE] `	while (len > 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01615 [NONE] `		size_t chunk = min_t(size_t, len, max_data_per_pkt);`
  Review: Low-risk line; verify in surrounding control flow.
- L01616 [NONE] `		u8 pkt[QUIC_MAX_PKT_SIZE];`
  Review: Low-risk line; verify in surrounding control flow.
- L01617 [NONE] `		u8 *p = pkt;`
  Review: Low-risk line; verify in surrounding control flow.
- L01618 [NONE] `		unsigned long flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L01619 [NONE] `		u64 pkt_num;`
  Review: Low-risk line; verify in surrounding control flow.
- L01620 [NONE] `		struct msghdr msg = {};`
  Review: Low-risk line; verify in surrounding control flow.
- L01621 [NONE] `		struct kvec iov;`
  Review: Low-risk line; verify in surrounding control flow.
- L01622 [NONE] `		size_t payload_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01623 [NONE] `		int vl;`
  Review: Low-risk line; verify in surrounding control flow.
- L01624 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01625 [NONE] `		/* Long header: Initial type */`
  Review: Low-risk line; verify in surrounding control flow.
- L01626 [NONE] `		*p++ = QUIC_HDR_FORM_LONG | QUIC_HDR_FIXED_BIT`
  Review: Low-risk line; verify in surrounding control flow.
- L01627 [NONE] `			| QUIC_LONG_TYPE_INITIAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01628 [NONE] `		put_unaligned_be32(QUIC_VERSION_1, p);`
  Review: Low-risk line; verify in surrounding control flow.
- L01629 [NONE] `		p += 4;`
  Review: Low-risk line; verify in surrounding control flow.
- L01630 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01631 [NONE] `		/* DCID = peer's SCID */`
  Review: Low-risk line; verify in surrounding control flow.
- L01632 [NONE] `		*p++ = qconn->scid_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01633 [MEM_BOUNDS|] `		memcpy(p, qconn->scid, qconn->scid_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01634 [NONE] `		p += qconn->scid_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01635 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01636 [NONE] `		/* SCID = our DCID */`
  Review: Low-risk line; verify in surrounding control flow.
- L01637 [NONE] `		*p++ = qconn->dcid_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01638 [MEM_BOUNDS|] `		memcpy(p, qconn->dcid, qconn->dcid_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01639 [NONE] `		p += qconn->dcid_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01640 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01641 [NONE] `		/* Token length = 0 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01642 [NONE] `		*p++ = 0x00;`
  Review: Low-risk line; verify in surrounding control flow.
- L01643 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01644 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L01645 [NONE] `		 * Payload = 1-byte pkt_num + CRYPTO frame:`
  Review: Low-risk line; verify in surrounding control flow.
- L01646 [NONE] `		 *   type(1) + offset(varint) + length(varint) + chunk`
  Review: Low-risk line; verify in surrounding control flow.
- L01647 [NONE] `		 *`
  Review: Low-risk line; verify in surrounding control flow.
- L01648 [NONE] `		 * Compute payload length for the varint Length field.`
  Review: Low-risk line; verify in surrounding control flow.
- L01649 [NONE] `		 * Worst-case varints are 8 bytes each; in practice < 4.`
  Review: Low-risk line; verify in surrounding control flow.
- L01650 [NONE] `		 * Precompute: frame header size = 1 + 8 + 8 = 17 max.`
  Review: Low-risk line; verify in surrounding control flow.
- L01651 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L01652 [NONE] `		payload_len = 1 /* pkt_num */ + 1 /* frame type */`
  Review: Low-risk line; verify in surrounding control flow.
- L01653 [NONE] `			      + 8 /* offset varint max */`
  Review: Low-risk line; verify in surrounding control flow.
- L01654 [NONE] `			      + 8 /* length varint max */`
  Review: Low-risk line; verify in surrounding control flow.
- L01655 [NONE] `			      + chunk;`
  Review: Low-risk line; verify in surrounding control flow.
- L01656 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01657 [NONE] `		if (ksmbd_quic_put_varint(p, payload_len, &vl))`
  Review: Low-risk line; verify in surrounding control flow.
- L01658 [NONE] `			return;`
  Review: Low-risk line; verify in surrounding control flow.
- L01659 [NONE] `		p += vl;`
  Review: Low-risk line; verify in surrounding control flow.
- L01660 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01661 [NONE] `		/* Packet number */`
  Review: Low-risk line; verify in surrounding control flow.
- L01662 [NONE] `		spin_lock_irqsave(&qconn->lock, flags);`
  Review: Low-risk line; verify in surrounding control flow.
- L01663 [NONE] `		pkt_num = qconn->send_pkt_num++;`
  Review: Low-risk line; verify in surrounding control flow.
- L01664 [NONE] `		spin_unlock_irqrestore(&qconn->lock, flags);`
  Review: Low-risk line; verify in surrounding control flow.
- L01665 [NONE] `		*p++ = (u8)(pkt_num & 0xFF);`
  Review: Low-risk line; verify in surrounding control flow.
- L01666 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01667 [NONE] `		/* CRYPTO frame */`
  Review: Low-risk line; verify in surrounding control flow.
- L01668 [NONE] `		*p++ = QUIC_FRAME_CRYPTO;`
  Review: Low-risk line; verify in surrounding control flow.
- L01669 [NONE] `		if (ksmbd_quic_put_varint(p, offset_in_crypto, &vl))`
  Review: Low-risk line; verify in surrounding control flow.
- L01670 [NONE] `			return;`
  Review: Low-risk line; verify in surrounding control flow.
- L01671 [NONE] `		p += vl;`
  Review: Low-risk line; verify in surrounding control flow.
- L01672 [NONE] `		if (ksmbd_quic_put_varint(p, chunk, &vl))`
  Review: Low-risk line; verify in surrounding control flow.
- L01673 [NONE] `			return;`
  Review: Low-risk line; verify in surrounding control flow.
- L01674 [NONE] `		p += vl;`
  Review: Low-risk line; verify in surrounding control flow.
- L01675 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01676 [NONE] `		/* Bounds check before copy */`
  Review: Low-risk line; verify in surrounding control flow.
- L01677 [NONE] `		if ((size_t)(p - pkt) + chunk > sizeof(pkt))`
  Review: Low-risk line; verify in surrounding control flow.
- L01678 [NONE] `			return;`
  Review: Low-risk line; verify in surrounding control flow.
- L01679 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01680 [MEM_BOUNDS|] `		memcpy(p, data, chunk);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01681 [NONE] `		p += chunk;`
  Review: Low-risk line; verify in surrounding control flow.
- L01682 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01683 [NONE] `		msg.msg_name    = &qconn->peer;`
  Review: Low-risk line; verify in surrounding control flow.
- L01684 [NONE] `		msg.msg_namelen = qconn->peer_addrlen;`
  Review: Low-risk line; verify in surrounding control flow.
- L01685 [NONE] `		msg.msg_flags   = MSG_NOSIGNAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01686 [NONE] `		iov.iov_base    = pkt;`
  Review: Low-risk line; verify in surrounding control flow.
- L01687 [NONE] `		iov.iov_len     = p - pkt;`
  Review: Low-risk line; verify in surrounding control flow.
- L01688 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01689 [NONE] `		kernel_sendmsg(qconn->udp_sock, &msg, &iov, 1, iov.iov_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01690 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01691 [NONE] `		data             += chunk;`
  Review: Low-risk line; verify in surrounding control flow.
- L01692 [NONE] `		len              -= chunk;`
  Review: Low-risk line; verify in surrounding control flow.
- L01693 [NONE] `		offset_in_crypto += chunk;`
  Review: Low-risk line; verify in surrounding control flow.
- L01694 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01695 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01696 [NONE] `	ksmbd_debug(CONN, "QUIC: sent handshake flight (%zu bytes)\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L01697 [NONE] `		    offset_in_crypto);`
  Review: Low-risk line; verify in surrounding control flow.
- L01698 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01699 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01700 [NONE] `/* =========================================================================`
  Review: Low-risk line; verify in surrounding control flow.
- L01701 [NONE] ` * QUIC connection table management`
  Review: Low-risk line; verify in surrounding control flow.
- L01702 [NONE] ` * =========================================================================`
  Review: Low-risk line; verify in surrounding control flow.
- L01703 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01704 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01705 [NONE] `static u32 quic_dcid_hash(const u8 *dcid, u8 len)`
  Review: Low-risk line; verify in surrounding control flow.
- L01706 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01707 [NONE] `	return jhash(dcid, len, 0);`
  Review: Low-risk line; verify in surrounding control flow.
- L01708 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01709 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01710 [NONE] `static struct ksmbd_quic_conn *quic_conn_lookup(const u8 *dcid, u8 len)`
  Review: Low-risk line; verify in surrounding control flow.
- L01711 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01712 [NONE] `	struct ksmbd_quic_conn *qconn;`
  Review: Low-risk line; verify in surrounding control flow.
- L01713 [NONE] `	u32 key = quic_dcid_hash(dcid, len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01714 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01715 [NONE] `	hash_for_each_possible_rcu(quic_conn_table, qconn, hlist, key) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01716 [NONE] `		if (qconn->dcid_len == len &&`
  Review: Low-risk line; verify in surrounding control flow.
- L01717 [NONE] `		    memcmp(qconn->dcid, dcid, len) == 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01718 [NONE] `			return qconn;`
  Review: Low-risk line; verify in surrounding control flow.
- L01719 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01720 [NONE] `	return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01721 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01722 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01723 [NONE] `static void quic_conn_insert(struct ksmbd_quic_conn *qconn)`
  Review: Low-risk line; verify in surrounding control flow.
- L01724 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01725 [NONE] `	u32 key = quic_dcid_hash(qconn->dcid, qconn->dcid_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01726 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01727 [LOCK|] `	spin_lock(&quic_conn_table_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01728 [NONE] `	hash_add_rcu(quic_conn_table, &qconn->hlist, key);`
  Review: Low-risk line; verify in surrounding control flow.
- L01729 [LOCK|] `	spin_unlock(&quic_conn_table_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01730 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01731 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01732 [NONE] `static void quic_conn_remove(struct ksmbd_quic_conn *qconn)`
  Review: Low-risk line; verify in surrounding control flow.
- L01733 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01734 [LOCK|] `	spin_lock(&quic_conn_table_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01735 [NONE] `	hash_del_rcu(&qconn->hlist);`
  Review: Low-risk line; verify in surrounding control flow.
- L01736 [LOCK|] `	spin_unlock(&quic_conn_table_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L01737 [NONE] `	synchronize_rcu();`
  Review: Low-risk line; verify in surrounding control flow.
- L01738 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01739 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01740 [NONE] `/* =========================================================================`
  Review: Low-risk line; verify in surrounding control flow.
- L01741 [NONE] ` * QUIC connection allocation/free`
  Review: Low-risk line; verify in surrounding control flow.
- L01742 [NONE] ` * =========================================================================`
  Review: Low-risk line; verify in surrounding control flow.
- L01743 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01744 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01745 [NONE] `static struct ksmbd_quic_conn *quic_conn_alloc(struct socket *udp_sock)`
  Review: Low-risk line; verify in surrounding control flow.
- L01746 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01747 [NONE] `	struct ksmbd_quic_conn *qconn;`
  Review: Low-risk line; verify in surrounding control flow.
- L01748 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01749 [MEM_BOUNDS|] `	qconn = kzalloc(sizeof(*qconn), KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01750 [NONE] `	if (!qconn)`
  Review: Low-risk line; verify in surrounding control flow.
- L01751 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01752 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01753 [MEM_BOUNDS|] `	qconn->stream_buf = kvmalloc(QUIC_STREAM_BUF_SIZE, KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01754 [NONE] `	if (!qconn->stream_buf) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01755 [NONE] `		kfree(qconn);`
  Review: Low-risk line; verify in surrounding control flow.
- L01756 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01757 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01758 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01759 [NONE] `	qconn->stream_max = QUIC_STREAM_BUF_SIZE;`
  Review: Low-risk line; verify in surrounding control flow.
- L01760 [NONE] `	spin_lock_init(&qconn->lock);`
  Review: Low-risk line; verify in surrounding control flow.
- L01761 [NONE] `	init_waitqueue_head(&qconn->wait);`
  Review: Low-risk line; verify in surrounding control flow.
- L01762 [NONE] `	init_completion(&qconn->hs_done);`
  Review: Low-risk line; verify in surrounding control flow.
- L01763 [NONE] `	qconn->udp_sock = udp_sock;`
  Review: Low-risk line; verify in surrounding control flow.
- L01764 [NONE] `	qconn->state    = QUIC_STATE_INITIAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L01765 [NONE] `	qconn->ipc_handle = -1;`
  Review: Low-risk line; verify in surrounding control flow.
- L01766 [NONE] `	INIT_HLIST_NODE(&qconn->hlist);`
  Review: Low-risk line; verify in surrounding control flow.
- L01767 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01768 [NONE] `	return qconn;`
  Review: Low-risk line; verify in surrounding control flow.
- L01769 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01770 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01771 [NONE] `static void quic_conn_free(struct ksmbd_quic_conn *qconn)`
  Review: Low-risk line; verify in surrounding control flow.
- L01772 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01773 [NONE] `	if (!qconn)`
  Review: Low-risk line; verify in surrounding control flow.
- L01774 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L01775 [NONE] `	kvfree(qconn->stream_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L01776 [NONE] `	kfree(qconn);`
  Review: Low-risk line; verify in surrounding control flow.
- L01777 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01778 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01779 [NONE] `/* =========================================================================`
  Review: Low-risk line; verify in surrounding control flow.
- L01780 [NONE] ` * QUIC Initial packet parsing (RFC 9000 §17.2.2)`
  Review: Low-risk line; verify in surrounding control flow.
- L01781 [NONE] ` * =========================================================================`
  Review: Low-risk line; verify in surrounding control flow.
- L01782 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01783 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01784 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01785 [NONE] ` * quic_parse_initial_packet() - parse a received QUIC Initial packet`
  Review: Low-risk line; verify in surrounding control flow.
- L01786 [NONE] ` * @pkt:	Raw UDP payload (the QUIC packet)`
  Review: Low-risk line; verify in surrounding control flow.
- L01787 [NONE] ` * @pkt_len:	Length of @pkt`
  Review: Low-risk line; verify in surrounding control flow.
- L01788 [NONE] ` * @dcid_out:	Filled with the Destination CID from the packet header`
  Review: Low-risk line; verify in surrounding control flow.
- L01789 [NONE] ` * @dcid_len_out: Length of the DCID`
  Review: Low-risk line; verify in surrounding control flow.
- L01790 [NONE] ` * @scid_out:	Filled with the Source CID`
  Review: Low-risk line; verify in surrounding control flow.
- L01791 [NONE] ` * @scid_len_out: Length of the SCID`
  Review: Low-risk line; verify in surrounding control flow.
- L01792 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01793 [NONE] ` * Only parses the unprotected header fields (DCID, SCID, token, pkt num`
  Review: Low-risk line; verify in surrounding control flow.
- L01794 [NONE] ` * length).  Does NOT decrypt or verify the packet — that requires keys`
  Review: Low-risk line; verify in surrounding control flow.
- L01795 [NONE] ` * derived from the DCID, which we call derive_initial_secrets() after.`
  Review: Low-risk line; verify in surrounding control flow.
- L01796 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01797 [NONE] ` * Return: 0 on success, -EINVAL if the packet is malformed.`
  Review: Low-risk line; verify in surrounding control flow.
- L01798 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01799 [NONE] `static int quic_parse_initial_packet(const u8 *pkt, size_t pkt_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L01800 [NONE] `				     u8 *dcid_out, u8 *dcid_len_out,`
  Review: Low-risk line; verify in surrounding control flow.
- L01801 [NONE] `				     u8 *scid_out, u8 *scid_len_out)`
  Review: Low-risk line; verify in surrounding control flow.
- L01802 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01803 [NONE] `	const u8 *p = pkt;`
  Review: Low-risk line; verify in surrounding control flow.
- L01804 [NONE] `	size_t remaining = pkt_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01805 [NONE] `	u8 first_byte;`
  Review: Low-risk line; verify in surrounding control flow.
- L01806 [NONE] `	u32 version;`
  Review: Low-risk line; verify in surrounding control flow.
- L01807 [NONE] `	u8 dcid_len, scid_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01808 [NONE] `	u64 token_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01809 [NONE] `	int consumed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01810 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01811 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01812 [NONE] `	/* Minimum: 1 (first byte) + 4 (version) + 1 (dcid_len) */`
  Review: Low-risk line; verify in surrounding control flow.
- L01813 [NONE] `	if (remaining < 6)`
  Review: Low-risk line; verify in surrounding control flow.
- L01814 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01815 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01816 [NONE] `	first_byte = *p++;`
  Review: Low-risk line; verify in surrounding control flow.
- L01817 [NONE] `	remaining--;`
  Review: Low-risk line; verify in surrounding control flow.
- L01818 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01819 [NONE] `	/* Must be a long-header Initial packet */`
  Review: Low-risk line; verify in surrounding control flow.
- L01820 [NONE] `	if (!(first_byte & QUIC_HDR_FORM_LONG))`
  Review: Low-risk line; verify in surrounding control flow.
- L01821 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01822 [NONE] `	if (!(first_byte & QUIC_HDR_FIXED_BIT))`
  Review: Low-risk line; verify in surrounding control flow.
- L01823 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01824 [NONE] `	if ((first_byte & 0x30) != QUIC_LONG_TYPE_INITIAL)`
  Review: Low-risk line; verify in surrounding control flow.
- L01825 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01826 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01827 [NONE] `	/* Version (4 bytes) */`
  Review: Low-risk line; verify in surrounding control flow.
- L01828 [NONE] `	if (remaining < 4)`
  Review: Low-risk line; verify in surrounding control flow.
- L01829 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01830 [NONE] `	version = get_unaligned_be32(p);`
  Review: Low-risk line; verify in surrounding control flow.
- L01831 [NONE] `	p += 4;`
  Review: Low-risk line; verify in surrounding control flow.
- L01832 [NONE] `	remaining -= 4;`
  Review: Low-risk line; verify in surrounding control flow.
- L01833 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01834 [NONE] `	if (version != QUIC_VERSION_1) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01835 [NONE] `		/* Version Negotiation would be the correct response;`
  Review: Low-risk line; verify in surrounding control flow.
- L01836 [NONE] `		 * for now just reject unsupported versions. */`
  Review: Low-risk line; verify in surrounding control flow.
- L01837 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01838 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01839 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01840 [NONE] `	/* DCID Length (1 byte) + DCID */`
  Review: Low-risk line; verify in surrounding control flow.
- L01841 [NONE] `	if (!remaining)`
  Review: Low-risk line; verify in surrounding control flow.
- L01842 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01843 [NONE] `	dcid_len = *p++;`
  Review: Low-risk line; verify in surrounding control flow.
- L01844 [NONE] `	remaining--;`
  Review: Low-risk line; verify in surrounding control flow.
- L01845 [NONE] `	if (dcid_len > QUIC_MAX_CID_LEN)`
  Review: Low-risk line; verify in surrounding control flow.
- L01846 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01847 [NONE] `	if (remaining < dcid_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L01848 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01849 [MEM_BOUNDS|] `	memcpy(dcid_out, p, dcid_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01850 [NONE] `	*dcid_len_out = dcid_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01851 [NONE] `	p += dcid_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01852 [NONE] `	remaining -= dcid_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01853 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01854 [NONE] `	/* SCID Length (1 byte) + SCID */`
  Review: Low-risk line; verify in surrounding control flow.
- L01855 [NONE] `	if (!remaining)`
  Review: Low-risk line; verify in surrounding control flow.
- L01856 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01857 [NONE] `	scid_len = *p++;`
  Review: Low-risk line; verify in surrounding control flow.
- L01858 [NONE] `	remaining--;`
  Review: Low-risk line; verify in surrounding control flow.
- L01859 [NONE] `	if (scid_len > QUIC_MAX_CID_LEN)`
  Review: Low-risk line; verify in surrounding control flow.
- L01860 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01861 [NONE] `	if (remaining < scid_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L01862 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01863 [MEM_BOUNDS|] `	memcpy(scid_out, p, scid_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01864 [NONE] `	*scid_len_out = scid_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01865 [NONE] `	p += scid_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01866 [NONE] `	remaining -= scid_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01867 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01868 [NONE] `	/* Token Length (variable-length integer) */`
  Review: Low-risk line; verify in surrounding control flow.
- L01869 [NONE] `	ret = ksmbd_quic_get_varint(p, remaining, &token_len, &consumed);`
  Review: Low-risk line; verify in surrounding control flow.
- L01870 [NONE] `	if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L01871 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L01872 [NONE] `	p += consumed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01873 [NONE] `	remaining -= consumed;`
  Review: Low-risk line; verify in surrounding control flow.
- L01874 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01875 [NONE] `	/* Token bytes */`
  Review: Low-risk line; verify in surrounding control flow.
- L01876 [NONE] `	if (remaining < token_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L01877 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01878 [NONE] `	/* (we do not process the token in this implementation) */`
  Review: Low-risk line; verify in surrounding control flow.
- L01879 [NONE] `	p += token_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01880 [NONE] `	remaining -= token_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01881 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01882 [NONE] `	/* Packet Length (variable-length integer) — tells us payload+pktnum size */`
  Review: Low-risk line; verify in surrounding control flow.
- L01883 [NONE] `	/* (we don't need to parse further for the initial CID extraction) */`
  Review: Low-risk line; verify in surrounding control flow.
- L01884 [NONE] `	(void)p;`
  Review: Low-risk line; verify in surrounding control flow.
- L01885 [NONE] `	(void)remaining;`
  Review: Low-risk line; verify in surrounding control flow.
- L01886 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01887 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01888 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01889 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01890 [NONE] `/* =========================================================================`
  Review: Low-risk line; verify in surrounding control flow.
- L01891 [NONE] ` * QUIC stream data handling`
  Review: Low-risk line; verify in surrounding control flow.
- L01892 [NONE] ` * =========================================================================`
  Review: Low-risk line; verify in surrounding control flow.
- L01893 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01894 [NONE] ` * When we receive a QUIC STREAM frame carrying SMB data, we append it to`
  Review: Low-risk line; verify in surrounding control flow.
- L01895 [NONE] ` * the per-connection reassembly buffer and wake the SMB handler thread.`
  Review: Low-risk line; verify in surrounding control flow.
- L01896 [NONE] ` * The SMB handler thread calls our .read transport op which blocks until`
  Review: Low-risk line; verify in surrounding control flow.
- L01897 [NONE] ` * enough data is available.`
  Review: Low-risk line; verify in surrounding control flow.
- L01898 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01899 [NONE] ` * NOTE: No RFC1002 4-byte NetBIOS length prefix is added (SMB over QUIC`
  Review: Low-risk line; verify in surrounding control flow.
- L01900 [NONE] ` * specifics, MS-SMB2 Appendix C).  The connection handler loop must be`
  Review: Low-risk line; verify in surrounding control flow.
- L01901 [NONE] ` * aware of this; we set conn->transport to our QUIC transport ops which`
  Review: Low-risk line; verify in surrounding control flow.
- L01902 [NONE] ` * report the fact via KSMBD_TRANS_QUIC.`
  Review: Low-risk line; verify in surrounding control flow.
- L01903 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01904 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01905 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01906 [NONE] ` * quic_stream_append() - append received STREAM data to the reassembly buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L01907 [NONE] ` * @qconn:	QUIC connection`
  Review: Low-risk line; verify in surrounding control flow.
- L01908 [NONE] ` * @data:	Data bytes from a QUIC STREAM frame payload`
  Review: Low-risk line; verify in surrounding control flow.
- L01909 [NONE] ` * @len:	Number of bytes to append`
  Review: Low-risk line; verify in surrounding control flow.
- L01910 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01911 [NONE] ` * Called from the RX thread (or future CRYPTO/handshake path) when STREAM`
  Review: Low-risk line; verify in surrounding control flow.
- L01912 [NONE] ` * frame data arrives for the SMB stream (stream ID 0).`
  Review: Low-risk line; verify in surrounding control flow.
- L01913 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01914 [NONE] ` * Return: 0 on success, -ENOMEM if the buffer would overflow.`
  Review: Low-risk line; verify in surrounding control flow.
- L01915 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01916 [NONE] `static int quic_stream_append(struct ksmbd_quic_conn *qconn,`
  Review: Low-risk line; verify in surrounding control flow.
- L01917 [NONE] `			      const u8 *data, size_t len)`
  Review: Low-risk line; verify in surrounding control flow.
- L01918 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01919 [NONE] `	unsigned long flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L01920 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01921 [NONE] `	spin_lock_irqsave(&qconn->lock, flags);`
  Review: Low-risk line; verify in surrounding control flow.
- L01922 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01923 [NONE] `	if (qconn->stream_len + len > qconn->stream_max) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01924 [NONE] `		spin_unlock_irqrestore(&qconn->lock, flags);`
  Review: Low-risk line; verify in surrounding control flow.
- L01925 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01926 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L01927 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01928 [MEM_BOUNDS|] `	memcpy(qconn->stream_buf + qconn->stream_len, data, len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01929 [NONE] `	qconn->stream_len += len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01930 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01931 [NONE] `	spin_unlock_irqrestore(&qconn->lock, flags);`
  Review: Low-risk line; verify in surrounding control flow.
- L01932 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01933 [NONE] `	wake_up_interruptible(&qconn->wait);`
  Review: Low-risk line; verify in surrounding control flow.
- L01934 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01935 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L01936 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01937 [NONE] `/* =========================================================================`
  Review: Low-risk line; verify in surrounding control flow.
- L01938 [NONE] ` * QUIC transport ops: read / write / disconnect / shutdown`
  Review: Low-risk line; verify in surrounding control flow.
- L01939 [NONE] ` * =========================================================================`
  Review: Low-risk line; verify in surrounding control flow.
- L01940 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01941 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01942 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L01943 [NONE] ` * ksmbd_quic_read() - transport ops read: read SMB data from QUIC stream`
  Review: Low-risk line; verify in surrounding control flow.
- L01944 [NONE] ` * @t:		ksmbd transport instance`
  Review: Low-risk line; verify in surrounding control flow.
- L01945 [NONE] ` * @buf:	Destination buffer`
  Review: Low-risk line; verify in surrounding control flow.
- L01946 [NONE] ` * @to_read:	Number of bytes to read`
  Review: Low-risk line; verify in surrounding control flow.
- L01947 [NONE] ` * @max_retries: Retry limit (negative = unlimited, matches TCP semantics)`
  Review: Low-risk line; verify in surrounding control flow.
- L01948 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01949 [NONE] ` * Blocks until @to_read bytes are available in the QUIC stream reassembly`
  Review: Low-risk line; verify in surrounding control flow.
- L01950 [NONE] ` * buffer, then copies them out.  No RFC1002 NetBIOS prefix is handled here;`
  Review: Low-risk line; verify in surrounding control flow.
- L01951 [NONE] ` * the QUIC transport carries raw SMB PDUs in STREAM frames.`
  Review: Low-risk line; verify in surrounding control flow.
- L01952 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L01953 [NONE] ` * Return: Number of bytes read, or negative errno.`
  Review: Low-risk line; verify in surrounding control flow.
- L01954 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L01955 [NONE] `static int ksmbd_quic_read(struct ksmbd_transport *t, char *buf,`
  Review: Low-risk line; verify in surrounding control flow.
- L01956 [NONE] `			   unsigned int to_read, int max_retries)`
  Review: Low-risk line; verify in surrounding control flow.
- L01957 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L01958 [NONE] `	struct quic_transport *qt = QUIC_TRANS(t);`
  Review: Low-risk line; verify in surrounding control flow.
- L01959 [NONE] `	struct ksmbd_quic_conn *qconn = qt->qconn;`
  Review: Low-risk line; verify in surrounding control flow.
- L01960 [NONE] `	struct ksmbd_conn *conn = t->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L01961 [NONE] `	int retries = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L01962 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01963 [NONE] `	while (true) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01964 [NONE] `		unsigned long flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L01965 [NONE] `		size_t avail;`
  Review: Low-risk line; verify in surrounding control flow.
- L01966 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01967 [NONE] `		try_to_freeze();`
  Review: Low-risk line; verify in surrounding control flow.
- L01968 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01969 [NONE] `		if (!ksmbd_conn_alive(conn))`
  Review: Low-risk line; verify in surrounding control flow.
- L01970 [ERROR_PATH|] `			return -ESHUTDOWN;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01971 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01972 [NONE] `		if (ksmbd_conn_need_reconnect(conn))`
  Review: Low-risk line; verify in surrounding control flow.
- L01973 [ERROR_PATH|] `			return -EAGAIN;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01974 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01975 [NONE] `		spin_lock_irqsave(&qconn->lock, flags);`
  Review: Low-risk line; verify in surrounding control flow.
- L01976 [NONE] `		avail = qconn->stream_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L01977 [NONE] `		spin_unlock_irqrestore(&qconn->lock, flags);`
  Review: Low-risk line; verify in surrounding control flow.
- L01978 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01979 [NONE] `		if (avail >= to_read) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01980 [NONE] `			/* Consume @to_read bytes from the front of the buffer */`
  Review: Low-risk line; verify in surrounding control flow.
- L01981 [NONE] `			spin_lock_irqsave(&qconn->lock, flags);`
  Review: Low-risk line; verify in surrounding control flow.
- L01982 [MEM_BOUNDS|] `			memcpy(buf, qconn->stream_buf, to_read);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01983 [NONE] `			qconn->stream_len -= to_read;`
  Review: Low-risk line; verify in surrounding control flow.
- L01984 [MEM_BOUNDS|] `			memmove(qconn->stream_buf,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L01985 [NONE] `				qconn->stream_buf + to_read,`
  Review: Low-risk line; verify in surrounding control flow.
- L01986 [NONE] `				qconn->stream_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L01987 [NONE] `			spin_unlock_irqrestore(&qconn->lock, flags);`
  Review: Low-risk line; verify in surrounding control flow.
- L01988 [NONE] `			return (int)to_read;`
  Review: Low-risk line; verify in surrounding control flow.
- L01989 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01990 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L01991 [NONE] `		/* Not enough data yet — wait for the RX thread */`
  Review: Low-risk line; verify in surrounding control flow.
- L01992 [NONE] `		if (max_retries == 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L01993 [ERROR_PATH|] `			return -EAGAIN;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01994 [NONE] `		if (max_retries > 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L01995 [NONE] `			if (retries >= max_retries)`
  Review: Low-risk line; verify in surrounding control flow.
- L01996 [ERROR_PATH|] `				return -EAGAIN;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L01997 [NONE] `			retries++;`
  Review: Low-risk line; verify in surrounding control flow.
- L01998 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L01999 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02000 [WAIT_LOOP|] `		wait_event_interruptible_timeout(qconn->wait,`
  Review: Bounded wait and cancellation path must be guaranteed.
- L02001 [NONE] `			qconn->stream_len >= to_read ||`
  Review: Low-risk line; verify in surrounding control flow.
- L02002 [NONE] `			!ksmbd_conn_alive(conn),`
  Review: Low-risk line; verify in surrounding control flow.
- L02003 [NONE] `			HZ);`
  Review: Low-risk line; verify in surrounding control flow.
- L02004 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02005 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02006 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02007 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L02008 [NONE] ` * ksmbd_quic_writev() - transport ops write: send SMB data over QUIC stream`
  Review: Low-risk line; verify in surrounding control flow.
- L02009 [NONE] ` * @t:			ksmbd transport instance`
  Review: Low-risk line; verify in surrounding control flow.
- L02010 [NONE] ` * @iov:		IO vector with data to send`
  Review: Low-risk line; verify in surrounding control flow.
- L02011 [NONE] ` * @nvecs:		Number of iovec segments`
  Review: Low-risk line; verify in surrounding control flow.
- L02012 [NONE] ` * @size:		Total bytes to send`
  Review: Low-risk line; verify in surrounding control flow.
- L02013 [NONE] ` * @need_invalidate:	Unused (RDMA-specific)`
  Review: Low-risk line; verify in surrounding control flow.
- L02014 [NONE] ` * @remote_key:		Unused (RDMA-specific)`
  Review: Low-risk line; verify in surrounding control flow.
- L02015 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L02016 [NONE] ` * Wraps the SMB PDU data in a QUIC STREAM frame (type 0x0A = STREAM with`
  Review: Low-risk line; verify in surrounding control flow.
- L02017 [NONE] ` * LEN+OFF bits set but for simplicity we use type 0x0A for stream 0) and`
  Review: Low-risk line; verify in surrounding control flow.
- L02018 [NONE] ` * sends it as a short-header QUIC packet over the UDP socket.`
  Review: Low-risk line; verify in surrounding control flow.
- L02019 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L02020 [NONE] ` * For the Initial/Handshake phase (state != CONNECTED), we drop writes`
  Review: Low-risk line; verify in surrounding control flow.
- L02021 [ERROR_PATH|] ` * and return -ENOTCONN.  Full 1-RTT encryption is the production path;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02022 [NONE] ` * the current implementation emits unencrypted STREAM frames for`
  Review: Low-risk line; verify in surrounding control flow.
- L02023 [NONE] ` * demonstration / test with a cooperating client.  Production deployments`
  Review: Low-risk line; verify in surrounding control flow.
- L02024 [NONE] ` * MUST have TLS 1.3 handshake complete before reaching CONNECTED state.`
  Review: Low-risk line; verify in surrounding control flow.
- L02025 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L02026 [NONE] ` * Return: Number of bytes sent, or negative errno.`
  Review: Low-risk line; verify in surrounding control flow.
- L02027 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L02028 [NONE] `static int ksmbd_quic_writev(struct ksmbd_transport *t, struct kvec *iov,`
  Review: Low-risk line; verify in surrounding control flow.
- L02029 [NONE] `			     int nvecs, int size, bool need_invalidate,`
  Review: Low-risk line; verify in surrounding control flow.
- L02030 [NONE] `			     unsigned int remote_key)`
  Review: Low-risk line; verify in surrounding control flow.
- L02031 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02032 [NONE] `	struct quic_transport *qt = QUIC_TRANS(t);`
  Review: Low-risk line; verify in surrounding control flow.
- L02033 [NONE] `	struct ksmbd_quic_conn *qconn = qt->qconn;`
  Review: Low-risk line; verify in surrounding control flow.
- L02034 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02035 [NONE] `	 * QUIC short-header packet layout (RFC 9000 §17.3):`
  Review: Low-risk line; verify in surrounding control flow.
- L02036 [NONE] `	 *   [0]   : 0x40 | pkt_num_len-1  (Header Form=0, Fixed=1)`
  Review: Low-risk line; verify in surrounding control flow.
- L02037 [NONE] `	 *   [1..n]: DCID (peer's CID, stored in qconn->scid)`
  Review: Low-risk line; verify in surrounding control flow.
- L02038 [NONE] `	 *   [n+1..]: Packet Number (1-4 bytes)`
  Review: Low-risk line; verify in surrounding control flow.
- L02039 [NONE] `	 *   payload: STREAM frame`
  Review: Low-risk line; verify in surrounding control flow.
- L02040 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L02041 [NONE] `	 * We emit a 1-byte packet number for simplicity.`
  Review: Low-risk line; verify in surrounding control flow.
- L02042 [NONE] `	 * In a production implementation this would be encrypted with AEAD`
  Review: Low-risk line; verify in surrounding control flow.
- L02043 [NONE] `	 * and the packet number would be header-protected.`
  Review: Low-risk line; verify in surrounding control flow.
- L02044 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02045 [NONE] `	u8 hdr[1 + QUIC_MAX_CID_LEN + 4]; /* first byte + DCID + pktnum */`
  Review: Low-risk line; verify in surrounding control flow.
- L02046 [NONE] `	u8 stream_hdr[16]; /* STREAM frame header */`
  Review: Low-risk line; verify in surrounding control flow.
- L02047 [NONE] `	struct msghdr msg = {};`
  Review: Low-risk line; verify in surrounding control flow.
- L02048 [NONE] `	struct kvec tx_iov[3 + 16]; /* hdr + stream_hdr + caller iovs */`
  Review: Low-risk line; verify in surrounding control flow.
- L02049 [NONE] `	int ntx = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02050 [NONE] `	unsigned long flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L02051 [NONE] `	u64 pkt_num;`
  Review: Low-risk line; verify in surrounding control flow.
- L02052 [NONE] `	int varint_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L02053 [NONE] `	u8 *p;`
  Review: Low-risk line; verify in surrounding control flow.
- L02054 [NONE] `	int i, total = 0, sent;`
  Review: Low-risk line; verify in surrounding control flow.
- L02055 [NONE] `	int max_retries = 1000;`
  Review: Low-risk line; verify in surrounding control flow.
- L02056 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02057 [NONE] `	if (qconn->state != QUIC_STATE_CONNECTED)`
  Review: Low-risk line; verify in surrounding control flow.
- L02058 [ERROR_PATH|] `		return -ENOTCONN;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02059 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02060 [NONE] `	/* Build QUIC short-header */`
  Review: Low-risk line; verify in surrounding control flow.
- L02061 [NONE] `	p = hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L02062 [NONE] `	*p++ = QUIC_HDR_FIXED_BIT | 0x00; /* short header, pkt_num_len = 1 byte */`
  Review: Low-risk line; verify in surrounding control flow.
- L02063 [NONE] `	/* Peer's CID (our SCID = their DCID) */`
  Review: Low-risk line; verify in surrounding control flow.
- L02064 [MEM_BOUNDS|] `	memcpy(p, qconn->scid, qconn->scid_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L02065 [NONE] `	p += qconn->scid_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L02066 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02067 [NONE] `	spin_lock_irqsave(&qconn->lock, flags);`
  Review: Low-risk line; verify in surrounding control flow.
- L02068 [NONE] `	pkt_num = qconn->send_pkt_num++;`
  Review: Low-risk line; verify in surrounding control flow.
- L02069 [NONE] `	spin_unlock_irqrestore(&qconn->lock, flags);`
  Review: Low-risk line; verify in surrounding control flow.
- L02070 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02071 [NONE] `	/* 1-byte packet number (truncated to 8 bits — sufficient for lab use) */`
  Review: Low-risk line; verify in surrounding control flow.
- L02072 [NONE] `	*p++ = (u8)(pkt_num & 0xFF);`
  Review: Low-risk line; verify in surrounding control flow.
- L02073 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02074 [NONE] `	tx_iov[ntx].iov_base = hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L02075 [NONE] `	tx_iov[ntx].iov_len  = p - hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L02076 [NONE] `	ntx++;`
  Review: Low-risk line; verify in surrounding control flow.
- L02077 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02078 [NONE] `	/* Build QUIC STREAM frame header for stream 0 with LEN bit set */`
  Review: Low-risk line; verify in surrounding control flow.
- L02079 [NONE] `	/* Type: 0x08 (STREAM) | 0x02 (LEN) = 0x0A */`
  Review: Low-risk line; verify in surrounding control flow.
- L02080 [NONE] `	p = stream_hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L02081 [NONE] `	*p++ = QUIC_FRAME_STREAM | QUIC_FRAME_STREAM_LEN; /* 0x0A */`
  Review: Low-risk line; verify in surrounding control flow.
- L02082 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02083 [NONE] `	/* Stream ID = 0 (varint) */`
  Review: Low-risk line; verify in surrounding control flow.
- L02084 [NONE] `	ksmbd_quic_put_varint(p, 0, &varint_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L02085 [NONE] `	p += varint_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L02086 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02087 [NONE] `	/* Length of stream data (varint) */`
  Review: Low-risk line; verify in surrounding control flow.
- L02088 [NONE] `	ksmbd_quic_put_varint(p, (u64)size, &varint_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L02089 [NONE] `	p += varint_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L02090 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02091 [NONE] `	tx_iov[ntx].iov_base = stream_hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L02092 [NONE] `	tx_iov[ntx].iov_len  = p - stream_hdr;`
  Review: Low-risk line; verify in surrounding control flow.
- L02093 [NONE] `	ntx++;`
  Review: Low-risk line; verify in surrounding control flow.
- L02094 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02095 [NONE] `	/* Append caller's data iovecs */`
  Review: Low-risk line; verify in surrounding control flow.
- L02096 [NONE] `	for (i = 0; i < nvecs && ntx < (int)ARRAY_SIZE(tx_iov); i++) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02097 [NONE] `		tx_iov[ntx].iov_base = iov[i].iov_base;`
  Review: Low-risk line; verify in surrounding control flow.
- L02098 [NONE] `		tx_iov[ntx].iov_len  = iov[i].iov_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L02099 [NONE] `		ntx++;`
  Review: Low-risk line; verify in surrounding control flow.
- L02100 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02101 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02102 [NONE] `	msg.msg_name    = &qconn->peer;`
  Review: Low-risk line; verify in surrounding control flow.
- L02103 [NONE] `	msg.msg_namelen = qconn->peer_addrlen;`
  Review: Low-risk line; verify in surrounding control flow.
- L02104 [NONE] `	msg.msg_flags   = MSG_NOSIGNAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02105 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02106 [NONE] `	/* Total size = header + stream_hdr + payload */`
  Review: Low-risk line; verify in surrounding control flow.
- L02107 [NONE] `	total = (int)(tx_iov[0].iov_len + tx_iov[1].iov_len) + size;`
  Review: Low-risk line; verify in surrounding control flow.
- L02108 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02109 [NONE] `	while (total > 0 && max_retries-- > 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02110 [NONE] `		if (!ksmbd_conn_alive(t->conn))`
  Review: Low-risk line; verify in surrounding control flow.
- L02111 [ERROR_PATH|] `			return -ESHUTDOWN;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02112 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02113 [NONE] `		sent = kernel_sendmsg(qconn->udp_sock, &msg,`
  Review: Low-risk line; verify in surrounding control flow.
- L02114 [NONE] `				      tx_iov, ntx, total);`
  Review: Low-risk line; verify in surrounding control flow.
- L02115 [NONE] `		if (sent == -EINTR || sent == -EAGAIN) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02116 [WAIT_LOOP|] `			usleep_range(1000, 2000);`
  Review: Bounded wait and cancellation path must be guaranteed.
- L02117 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L02118 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02119 [NONE] `		if (sent <= 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02120 [NONE] `			return sent ? sent : -EIO;`
  Review: Low-risk line; verify in surrounding control flow.
- L02121 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02122 [NONE] `		total -= sent;`
  Review: Low-risk line; verify in surrounding control flow.
- L02123 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02124 [NONE] `		 * UDP sendmsg either sends the whole datagram or fails;`
  Review: Low-risk line; verify in surrounding control flow.
- L02125 [NONE] `		 * for UDP we expect a full send in one call.`
  Review: Low-risk line; verify in surrounding control flow.
- L02126 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02127 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L02128 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02129 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02130 [NONE] `	return size;`
  Review: Low-risk line; verify in surrounding control flow.
- L02131 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02132 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02133 [NONE] `static void ksmbd_quic_shutdown(struct ksmbd_transport *t);`
  Review: Low-risk line; verify in surrounding control flow.
- L02134 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02135 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L02136 [NONE] ` * ksmbd_quic_free_transport() - free QUIC transport resources`
  Review: Low-risk line; verify in surrounding control flow.
- L02137 [NONE] ` * @kt:		ksmbd transport instance`
  Review: Low-risk line; verify in surrounding control flow.
- L02138 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L02139 [NONE] `static void ksmbd_quic_free_transport(struct ksmbd_transport *kt)`
  Review: Low-risk line; verify in surrounding control flow.
- L02140 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02141 [NONE] `	struct quic_transport *t = QUIC_TRANS(kt);`
  Review: Low-risk line; verify in surrounding control flow.
- L02142 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02143 [NONE] `	if (t->qconn) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02144 [NONE] `		quic_conn_remove(t->qconn);`
  Review: Low-risk line; verify in surrounding control flow.
- L02145 [NONE] `		quic_conn_free(t->qconn);`
  Review: Low-risk line; verify in surrounding control flow.
- L02146 [NONE] `		t->qconn = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02147 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02148 [NONE] `	kfree(t->iov);`
  Review: Low-risk line; verify in surrounding control flow.
- L02149 [NONE] `	kfree(t);`
  Review: Low-risk line; verify in surrounding control flow.
- L02150 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02151 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02152 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L02153 [NONE] ` * free_transport() - shut down and free a QUIC connection`
  Review: Low-risk line; verify in surrounding control flow.
- L02154 [NONE] ` * @t:		QUIC transport instance`
  Review: Low-risk line; verify in surrounding control flow.
- L02155 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L02156 [NONE] `static void free_transport(struct quic_transport *t)`
  Review: Low-risk line; verify in surrounding control flow.
- L02157 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02158 [NONE] `	if (t->qconn) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02159 [NONE] `		/* Wake any waiting reader so the handler thread can exit */`
  Review: Low-risk line; verify in surrounding control flow.
- L02160 [NONE] `		wake_up_all(&t->qconn->wait);`
  Review: Low-risk line; verify in surrounding control flow.
- L02161 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02162 [NONE] `	ksmbd_conn_free(KSMBD_TRANS(t)->conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L02163 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02164 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02165 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L02166 [NONE] ` * ksmbd_quic_shutdown() - transport ops shutdown callback`
  Review: Low-risk line; verify in surrounding control flow.
- L02167 [NONE] ` * @t:		ksmbd transport instance`
  Review: Low-risk line; verify in surrounding control flow.
- L02168 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L02169 [NONE] ` * Called by stop_sessions() during graceful server teardown.`
  Review: Low-risk line; verify in surrounding control flow.
- L02170 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L02171 [NONE] `static void ksmbd_quic_shutdown(struct ksmbd_transport *t)`
  Review: Low-risk line; verify in surrounding control flow.
- L02172 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02173 [NONE] `	struct quic_transport *qt = QUIC_TRANS(t);`
  Review: Low-risk line; verify in surrounding control flow.
- L02174 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02175 [NONE] `	if (qt->qconn) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02176 [NONE] `		WRITE_ONCE(qt->qconn->state, QUIC_STATE_CLOSING);`
  Review: Low-risk line; verify in surrounding control flow.
- L02177 [NONE] `		wake_up_all(&qt->qconn->wait);`
  Review: Low-risk line; verify in surrounding control flow.
- L02178 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02179 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02180 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02181 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L02182 [NONE] ` * ksmbd_quic_disconnect() - transport ops disconnect callback`
  Review: Low-risk line; verify in surrounding control flow.
- L02183 [NONE] ` * @t:		ksmbd transport instance`
  Review: Low-risk line; verify in surrounding control flow.
- L02184 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L02185 [NONE] ` * Sends CONNECTION_CLOSE to the peer and tears down the QUIC connection.`
  Review: Low-risk line; verify in surrounding control flow.
- L02186 [NONE] ` * If a TLS handshake IPC is in progress, it is cancelled by removing the`
  Review: Low-risk line; verify in surrounding control flow.
- L02187 [NONE] ` * pending entry from the table (the waiting thread will see a timeout).`
  Review: Low-risk line; verify in surrounding control flow.
- L02188 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L02189 [NONE] `static void ksmbd_quic_disconnect(struct ksmbd_transport *t)`
  Review: Low-risk line; verify in surrounding control flow.
- L02190 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02191 [NONE] `	struct quic_transport *qt = QUIC_TRANS(t);`
  Review: Low-risk line; verify in surrounding control flow.
- L02192 [NONE] `	struct ksmbd_quic_conn *qconn = qt->qconn;`
  Review: Low-risk line; verify in surrounding control flow.
- L02193 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02194 [NONE] `	if (qconn && qconn->state != QUIC_STATE_CLOSED) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02195 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02196 [NONE] `		 * Send CONNECTION_CLOSE only if we reached at least HANDSHAKE`
  Review: Low-risk line; verify in surrounding control flow.
- L02197 [NONE] `		 * state (we have valid Initial TX keys).  Skip for`
  Review: Low-risk line; verify in surrounding control flow.
- L02198 [NONE] `		 * connections that were closed before Initial key derivation.`
  Review: Low-risk line; verify in surrounding control flow.
- L02199 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02200 [NONE] `		if (qconn->state == QUIC_STATE_CONNECTED ||`
  Review: Low-risk line; verify in surrounding control flow.
- L02201 [NONE] `		    qconn->state == QUIC_STATE_HANDSHAKE) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02202 [NONE] `			quic_send_connection_close(qconn,`
  Review: Low-risk line; verify in surrounding control flow.
- L02203 [NONE] `				QUIC_ERR_NO_ERROR,`
  Review: Low-risk line; verify in surrounding control flow.
- L02204 [NONE] `				"server disconnect");`
  Review: Low-risk line; verify in surrounding control flow.
- L02205 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02206 [NONE] `		WRITE_ONCE(qconn->state, QUIC_STATE_CLOSED);`
  Review: Low-risk line; verify in surrounding control flow.
- L02207 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02208 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02209 [NONE] `	free_transport(qt);`
  Review: Low-risk line; verify in surrounding control flow.
- L02210 [NONE] `	if (server_conf.max_connections)`
  Review: Low-risk line; verify in surrounding control flow.
- L02211 [LIFETIME|] `		atomic_dec(&quic_active_conns);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L02212 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02213 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02214 [NONE] `/* =========================================================================`
  Review: Low-risk line; verify in surrounding control flow.
- L02215 [NONE] ` * New QUIC connection: allocate transport + SMB conn + handler thread`
  Review: Low-risk line; verify in surrounding control flow.
- L02216 [NONE] ` * =========================================================================`
  Review: Low-risk line; verify in surrounding control flow.
- L02217 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L02218 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02219 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L02220 [NONE] ` * quic_alloc_transport() - allocate quic_transport and ksmbd_conn for a new peer`
  Review: Low-risk line; verify in surrounding control flow.
- L02221 [NONE] ` * @qconn:	Pre-allocated QUIC connection state`
  Review: Low-risk line; verify in surrounding control flow.
- L02222 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L02223 [NONE] ` * Return: quic_transport on success, NULL on allocation failure.`
  Review: Low-risk line; verify in surrounding control flow.
- L02224 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L02225 [NONE] `static struct quic_transport *quic_alloc_transport(struct ksmbd_quic_conn *qconn)`
  Review: Low-risk line; verify in surrounding control flow.
- L02226 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02227 [NONE] `	struct quic_transport *t;`
  Review: Low-risk line; verify in surrounding control flow.
- L02228 [NONE] `	struct ksmbd_conn *conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L02229 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02230 [MEM_BOUNDS|] `	t = kzalloc(sizeof(*t), KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L02231 [NONE] `	if (!t)`
  Review: Low-risk line; verify in surrounding control flow.
- L02232 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02233 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02234 [NONE] `	t->qconn = qconn;`
  Review: Low-risk line; verify in surrounding control flow.
- L02235 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02236 [NONE] `	conn = ksmbd_conn_alloc();`
  Review: Low-risk line; verify in surrounding control flow.
- L02237 [NONE] `	if (!conn) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02238 [NONE] `		kfree(t);`
  Review: Low-risk line; verify in surrounding control flow.
- L02239 [NONE] `		return NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02240 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02241 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02242 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02243 [NONE] `	 * SMB over QUIC always implies transport-layer security (TLS 1.3).`
  Review: Low-risk line; verify in surrounding control flow.
- L02244 [NONE] `	 * Set transport_secured = true so that SMB3 encryption requirements`
  Review: Low-risk line; verify in surrounding control flow.
- L02245 [NONE] `	 * are satisfied by the transport (not by SMB-layer encryption).`
  Review: Low-risk line; verify in surrounding control flow.
- L02246 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02247 [NONE] `	conn->transport_secured = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L02248 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02249 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02250 [NONE] `	 * Set peer address for per-IP connection limiting.`
  Review: Low-risk line; verify in surrounding control flow.
- L02251 [NONE] `	 * We store the peer's IPv4/IPv6 address from qconn->peer.`
  Review: Low-risk line; verify in surrounding control flow.
- L02252 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02253 [NONE] `	if (qconn->peer.ss_family == AF_INET6) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02254 [NONE] `		struct sockaddr_in6 *sin6 =`
  Review: Low-risk line; verify in surrounding control flow.
- L02255 [NONE] `			(struct sockaddr_in6 *)&qconn->peer;`
  Review: Low-risk line; verify in surrounding control flow.
- L02256 [NONE] `#if IS_ENABLED(CONFIG_IPV6)`
  Review: Low-risk line; verify in surrounding control flow.
- L02257 [MEM_BOUNDS|] `		memcpy(&conn->inet6_addr, &sin6->sin6_addr, 16);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L02258 [NONE] `		conn->inet_hash = ipv6_addr_hash(&sin6->sin6_addr);`
  Review: Low-risk line; verify in surrounding control flow.
- L02259 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02260 [NONE] `		/* Fallback: use lower 32 bits of IPv6 for hashing */`
  Review: Low-risk line; verify in surrounding control flow.
- L02261 [MEM_BOUNDS|] `		memcpy(&conn->inet_addr,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L02262 [NONE] `		       ((u8 *)&sin6->sin6_addr) + 12, 4);`
  Review: Low-risk line; verify in surrounding control flow.
- L02263 [NONE] `		conn->inet_hash = ipv4_addr_hash(conn->inet_addr);`
  Review: Low-risk line; verify in surrounding control flow.
- L02264 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02265 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L02266 [NONE] `		struct sockaddr_in *sin =`
  Review: Low-risk line; verify in surrounding control flow.
- L02267 [NONE] `			(struct sockaddr_in *)&qconn->peer;`
  Review: Low-risk line; verify in surrounding control flow.
- L02268 [NONE] `		conn->inet_addr = sin->sin_addr.s_addr;`
  Review: Low-risk line; verify in surrounding control flow.
- L02269 [NONE] `		conn->inet_hash = ipv4_addr_hash(conn->inet_addr);`
  Review: Low-risk line; verify in surrounding control flow.
- L02270 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02271 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02272 [NONE] `	ksmbd_conn_hash_add(conn, conn->inet_hash);`
  Review: Low-risk line; verify in surrounding control flow.
- L02273 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02274 [NONE] `	conn->transport = KSMBD_TRANS(t);`
  Review: Low-risk line; verify in surrounding control flow.
- L02275 [NONE] `	KSMBD_TRANS(t)->conn = conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L02276 [NONE] `	KSMBD_TRANS(t)->ops = &ksmbd_quic_transport_ops;`
  Review: Low-risk line; verify in surrounding control flow.
- L02277 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02278 [NONE] `	qconn->smb_conn = conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L02279 [NONE] `	return t;`
  Review: Low-risk line; verify in surrounding control flow.
- L02280 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02281 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02282 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L02283 [NONE] ` * ksmbd_quic_new_connection() - start handler thread for a new QUIC connection`
  Review: Low-risk line; verify in surrounding control flow.
- L02284 [NONE] ` * @qconn:	QUIC connection (already inserted into conn table)`
  Review: Low-risk line; verify in surrounding control flow.
- L02285 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L02286 [NONE] ` * Return: 0 on success, negative errno on failure.`
  Review: Low-risk line; verify in surrounding control flow.
- L02287 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L02288 [NONE] `static int ksmbd_quic_new_connection(struct ksmbd_quic_conn *qconn)`
  Review: Low-risk line; verify in surrounding control flow.
- L02289 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02290 [NONE] `	struct quic_transport *t;`
  Review: Low-risk line; verify in surrounding control flow.
- L02291 [NONE] `	struct task_struct *handler;`
  Review: Low-risk line; verify in surrounding control flow.
- L02292 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02293 [NONE] `	t = quic_alloc_transport(qconn);`
  Review: Low-risk line; verify in surrounding control flow.
- L02294 [NONE] `	if (!t)`
  Review: Low-risk line; verify in surrounding control flow.
- L02295 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02296 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02297 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02298 [NONE] `	 * Per-IP connection limit check (mirrors TCP transport logic).`
  Review: Low-risk line; verify in surrounding control flow.
- L02299 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02300 [NONE] `	if (server_conf.max_ip_connections) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02301 [NONE] `		struct ksmbd_conn *conn = KSMBD_TRANS(t)->conn;`
  Review: Low-risk line; verify in surrounding control flow.
- L02302 [NONE] `		struct ksmbd_conn *entry;`
  Review: Low-risk line; verify in surrounding control flow.
- L02303 [NONE] `		unsigned int max_ip_conns = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02304 [NONE] `		unsigned int bkt;`
  Review: Low-risk line; verify in surrounding control flow.
- L02305 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02306 [NONE] `		bkt = hash_min(conn->inet_hash, CONN_HASH_BITS);`
  Review: Low-risk line; verify in surrounding control flow.
- L02307 [LOCK|] `		spin_lock(&conn_hash[bkt].lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L02308 [NONE] `		hlist_for_each_entry(entry, &conn_hash[bkt].head, hlist) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02309 [NONE] `			if (entry->inet_hash != conn->inet_hash)`
  Review: Low-risk line; verify in surrounding control flow.
- L02310 [NONE] `				continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L02311 [NONE] `			if (ksmbd_conn_exiting(entry) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L02312 [NONE] `			    ksmbd_conn_releasing(entry))`
  Review: Low-risk line; verify in surrounding control flow.
- L02313 [NONE] `				continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L02314 [NONE] `			if (entry->inet_addr == conn->inet_addr)`
  Review: Low-risk line; verify in surrounding control flow.
- L02315 [NONE] `				max_ip_conns++;`
  Review: Low-risk line; verify in surrounding control flow.
- L02316 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02317 [LOCK|] `		spin_unlock(&conn_hash[bkt].lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L02318 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02319 [NONE] `		if (max_ip_conns > server_conf.max_ip_connections) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02320 [NONE] `			pr_info_ratelimited("QUIC: per-IP limit exceeded (%u/%u)\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L02321 [NONE] `					    max_ip_conns,`
  Review: Low-risk line; verify in surrounding control flow.
- L02322 [NONE] `					    server_conf.max_ip_connections);`
  Review: Low-risk line; verify in surrounding control flow.
- L02323 [NONE] `			ksmbd_conn_free(KSMBD_TRANS(t)->conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L02324 [NONE] `			kfree(t);`
  Review: Low-risk line; verify in surrounding control flow.
- L02325 [ERROR_PATH|] `			return -EAGAIN;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02326 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02327 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02328 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02329 [NONE] `	if (qconn->peer.ss_family == AF_INET6) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02330 [NONE] `#if IS_ENABLED(CONFIG_IPV6)`
  Review: Low-risk line; verify in surrounding control flow.
- L02331 [NONE] `		handler = kthread_run(ksmbd_conn_handler_loop,`
  Review: Low-risk line; verify in surrounding control flow.
- L02332 [NONE] `				      KSMBD_TRANS(t)->conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L02333 [NONE] `				      "ksmbd-quic:%pI6c",`
  Review: Low-risk line; verify in surrounding control flow.
- L02334 [NONE] `				      &KSMBD_TRANS(t)->conn->inet6_addr);`
  Review: Low-risk line; verify in surrounding control flow.
- L02335 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L02336 [NONE] `		handler = kthread_run(ksmbd_conn_handler_loop,`
  Review: Low-risk line; verify in surrounding control flow.
- L02337 [NONE] `				      KSMBD_TRANS(t)->conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L02338 [NONE] `				      "ksmbd-quic:%pI4",`
  Review: Low-risk line; verify in surrounding control flow.
- L02339 [NONE] `				      &KSMBD_TRANS(t)->conn->inet_addr);`
  Review: Low-risk line; verify in surrounding control flow.
- L02340 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02341 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L02342 [NONE] `		handler = kthread_run(ksmbd_conn_handler_loop,`
  Review: Low-risk line; verify in surrounding control flow.
- L02343 [NONE] `				      KSMBD_TRANS(t)->conn,`
  Review: Low-risk line; verify in surrounding control flow.
- L02344 [NONE] `				      "ksmbd-quic:%pI4",`
  Review: Low-risk line; verify in surrounding control flow.
- L02345 [NONE] `				      &KSMBD_TRANS(t)->conn->inet_addr);`
  Review: Low-risk line; verify in surrounding control flow.
- L02346 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02347 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02348 [NONE] `	if (IS_ERR(handler)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02349 [ERROR_PATH|] `		pr_err("QUIC: cannot start connection handler: %ld\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02350 [NONE] `		       PTR_ERR(handler));`
  Review: Low-risk line; verify in surrounding control flow.
- L02351 [NONE] `		ksmbd_conn_free(KSMBD_TRANS(t)->conn);`
  Review: Low-risk line; verify in surrounding control flow.
- L02352 [NONE] `		kfree(t);`
  Review: Low-risk line; verify in surrounding control flow.
- L02353 [NONE] `		return PTR_ERR(handler);`
  Review: Low-risk line; verify in surrounding control flow.
- L02354 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02355 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02356 [LIFETIME|] `	atomic_inc(&quic_active_conns);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L02357 [NONE] `	ksmbd_debug(CONN, "QUIC: new connection handler started\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L02358 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02359 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02360 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02361 [NONE] `/* =========================================================================`
  Review: Low-risk line; verify in surrounding control flow.
- L02362 [NONE] ` * QUIC Initial packet processing`
  Review: Low-risk line; verify in surrounding control flow.
- L02363 [NONE] ` * =========================================================================`
  Review: Low-risk line; verify in surrounding control flow.
- L02364 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L02365 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02366 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L02367 [NONE] ` * quic_send_version_negotiation() - send a QUIC Version Negotiation packet`
  Review: Low-risk line; verify in surrounding control flow.
- L02368 [NONE] ` * @udp_sock:	UDP socket to send from`
  Review: Low-risk line; verify in surrounding control flow.
- L02369 [NONE] ` * @peer:	Peer address`
  Review: Low-risk line; verify in surrounding control flow.
- L02370 [NONE] ` * @peer_len:	Peer address length`
  Review: Low-risk line; verify in surrounding control flow.
- L02371 [NONE] ` * @dcid:	Client's DCID (becomes our SCID in the VN packet)`
  Review: Low-risk line; verify in surrounding control flow.
- L02372 [NONE] ` * @dcid_len:	Length of @dcid`
  Review: Low-risk line; verify in surrounding control flow.
- L02373 [NONE] ` * @scid:	Client's SCID (becomes our DCID in the VN packet)`
  Review: Low-risk line; verify in surrounding control flow.
- L02374 [NONE] ` * @scid_len:	Length of @scid`
  Review: Low-risk line; verify in surrounding control flow.
- L02375 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L02376 [NONE] ` * Sends a Version Negotiation packet listing QUIC v1 as the supported`
  Review: Low-risk line; verify in surrounding control flow.
- L02377 [NONE] ` * version.  Called when we receive a non-v1 Initial packet.`
  Review: Low-risk line; verify in surrounding control flow.
- L02378 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L02379 [NONE] `static void quic_send_version_negotiation(struct socket *udp_sock,`
  Review: Low-risk line; verify in surrounding control flow.
- L02380 [NONE] `					  struct sockaddr_storage *peer,`
  Review: Low-risk line; verify in surrounding control flow.
- L02381 [NONE] `					  int peer_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L02382 [NONE] `					  const u8 *dcid, u8 dcid_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L02383 [NONE] `					  const u8 *scid, u8 scid_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L02384 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02385 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02386 [NONE] `	 * Version Negotiation packet (RFC 9000 §17.2.1):`
  Review: Low-risk line; verify in surrounding control flow.
- L02387 [NONE] `	 *   first_byte: 0x80 | random (long header, type ignored)`
  Review: Low-risk line; verify in surrounding control flow.
- L02388 [NONE] `	 *   version: 0x00000000 (VN packet indicator)`
  Review: Low-risk line; verify in surrounding control flow.
- L02389 [NONE] `	 *   DCID_len + DCID (= client's SCID)`
  Review: Low-risk line; verify in surrounding control flow.
- L02390 [NONE] `	 *   SCID_len + SCID (= client's DCID)`
  Review: Low-risk line; verify in surrounding control flow.
- L02391 [NONE] `	 *   Supported Versions: list of 4-byte version numbers`
  Review: Low-risk line; verify in surrounding control flow.
- L02392 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02393 [NONE] `	u8 pkt[1 + 4 + 1 + QUIC_MAX_CID_LEN + 1 + QUIC_MAX_CID_LEN + 4];`
  Review: Low-risk line; verify in surrounding control flow.
- L02394 [NONE] `	u8 *p = pkt;`
  Review: Low-risk line; verify in surrounding control flow.
- L02395 [NONE] `	struct msghdr msg = {};`
  Review: Low-risk line; verify in surrounding control flow.
- L02396 [NONE] `	struct kvec iov;`
  Review: Low-risk line; verify in surrounding control flow.
- L02397 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02398 [NONE] `	get_random_bytes(p, 1);`
  Review: Low-risk line; verify in surrounding control flow.
- L02399 [NONE] `	*p |= 0x80; /* long header */`
  Review: Low-risk line; verify in surrounding control flow.
- L02400 [NONE] `	p++;`
  Review: Low-risk line; verify in surrounding control flow.
- L02401 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02402 [NONE] `	/* Version = 0 (VN packet) */`
  Review: Low-risk line; verify in surrounding control flow.
- L02403 [NONE] `	put_unaligned_be32(0x00000000, p);`
  Review: Low-risk line; verify in surrounding control flow.
- L02404 [NONE] `	p += 4;`
  Review: Low-risk line; verify in surrounding control flow.
- L02405 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02406 [NONE] `	/* DCID = client's SCID */`
  Review: Low-risk line; verify in surrounding control flow.
- L02407 [NONE] `	*p++ = scid_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L02408 [MEM_BOUNDS|] `	memcpy(p, scid, scid_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L02409 [NONE] `	p += scid_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L02410 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02411 [NONE] `	/* SCID = client's DCID */`
  Review: Low-risk line; verify in surrounding control flow.
- L02412 [NONE] `	*p++ = dcid_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L02413 [MEM_BOUNDS|] `	memcpy(p, dcid, dcid_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L02414 [NONE] `	p += dcid_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L02415 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02416 [NONE] `	/* Supported version: QUIC v1 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02417 [NONE] `	put_unaligned_be32(QUIC_VERSION_1, p);`
  Review: Low-risk line; verify in surrounding control flow.
- L02418 [NONE] `	p += 4;`
  Review: Low-risk line; verify in surrounding control flow.
- L02419 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02420 [NONE] `	msg.msg_name    = peer;`
  Review: Low-risk line; verify in surrounding control flow.
- L02421 [NONE] `	msg.msg_namelen = peer_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L02422 [NONE] `	msg.msg_flags   = MSG_NOSIGNAL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02423 [NONE] `	iov.iov_base    = pkt;`
  Review: Low-risk line; verify in surrounding control flow.
- L02424 [NONE] `	iov.iov_len     = p - pkt;`
  Review: Low-risk line; verify in surrounding control flow.
- L02425 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02426 [NONE] `	kernel_sendmsg(udp_sock, &msg, &iov, 1, iov.iov_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L02427 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02428 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02429 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L02430 [NONE] ` * quic_extract_payload_from_initial() - locate the decrypted payload in an`
  Review: Low-risk line; verify in surrounding control flow.
- L02431 [NONE] ` *   Initial packet after the header fields have been parsed.`
  Review: Low-risk line; verify in surrounding control flow.
- L02432 [NONE] ` * @pkt:	Raw QUIC Initial packet`
  Review: Low-risk line; verify in surrounding control flow.
- L02433 [NONE] ` * @pkt_len:	Length of @pkt`
  Review: Low-risk line; verify in surrounding control flow.
- L02434 [NONE] ` * @payload_out: Set to point into @pkt at the first frame byte`
  Review: Low-risk line; verify in surrounding control flow.
- L02435 [NONE] ` * @payload_len_out: Set to the number of payload bytes`
  Review: Low-risk line; verify in surrounding control flow.
- L02436 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L02437 [NONE] ` * Skips the long header fields (first byte, version, DCID, SCID, token,`
  Review: Low-risk line; verify in surrounding control flow.
- L02438 [NONE] ` * length varint, packet number) and returns a pointer to the first frame.`
  Review: Low-risk line; verify in surrounding control flow.
- L02439 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L02440 [NONE] ` * NOTE: This does NOT decrypt the payload — the payload is treated as`
  Review: Low-risk line; verify in surrounding control flow.
- L02441 [NONE] ` * plaintext.  In the current implementation we rely on the client cooperating`
  Review: Low-risk line; verify in surrounding control flow.
- L02442 [NONE] ` * (e.g., during testing with a simple QUIC client that does not apply AEAD`
  Review: Low-risk line; verify in surrounding control flow.
- L02443 [NONE] ` * to the Initial payload).  A production implementation would apply`
  Review: Low-risk line; verify in surrounding control flow.
- L02444 [NONE] ` * AEAD decryption using qconn->initial_rx before calling this function.`
  Review: Low-risk line; verify in surrounding control flow.
- L02445 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L02446 [NONE] ` * Return: 0 on success, -EINVAL on parse error.`
  Review: Low-risk line; verify in surrounding control flow.
- L02447 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L02448 [NONE] `static int quic_extract_payload_from_initial(const u8 *pkt, size_t pkt_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L02449 [NONE] `					     const u8 **payload_out,`
  Review: Low-risk line; verify in surrounding control flow.
- L02450 [NONE] `					     size_t *payload_len_out)`
  Review: Low-risk line; verify in surrounding control flow.
- L02451 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02452 [NONE] `	const u8 *p = pkt;`
  Review: Low-risk line; verify in surrounding control flow.
- L02453 [NONE] `	size_t remaining = pkt_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L02454 [NONE] `	u8 first_byte, dcid_len, scid_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L02455 [NONE] `	u64 token_len, pkt_payload_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L02456 [NONE] `	int consumed;`
  Review: Low-risk line; verify in surrounding control flow.
- L02457 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02458 [NONE] `	if (remaining < 7)`
  Review: Low-risk line; verify in surrounding control flow.
- L02459 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02460 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02461 [NONE] `	first_byte = *p++; remaining--;`
  Review: Low-risk line; verify in surrounding control flow.
- L02462 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02463 [NONE] `	/* Skip version */`
  Review: Low-risk line; verify in surrounding control flow.
- L02464 [NONE] `	p += 4; remaining -= 4;`
  Review: Low-risk line; verify in surrounding control flow.
- L02465 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02466 [NONE] `	/* DCID */`
  Review: Low-risk line; verify in surrounding control flow.
- L02467 [NONE] `	dcid_len = *p++; remaining--;`
  Review: Low-risk line; verify in surrounding control flow.
- L02468 [NONE] `	if (dcid_len > QUIC_MAX_CID_LEN || remaining < dcid_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L02469 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02470 [NONE] `	p += dcid_len; remaining -= dcid_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L02471 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02472 [NONE] `	/* SCID */`
  Review: Low-risk line; verify in surrounding control flow.
- L02473 [ERROR_PATH|] `	if (!remaining) return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02474 [NONE] `	scid_len = *p++; remaining--;`
  Review: Low-risk line; verify in surrounding control flow.
- L02475 [NONE] `	if (scid_len > QUIC_MAX_CID_LEN || remaining < scid_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L02476 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02477 [NONE] `	p += scid_len; remaining -= scid_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L02478 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02479 [NONE] `	/* Token length + token */`
  Review: Low-risk line; verify in surrounding control flow.
- L02480 [NONE] `	if (ksmbd_quic_get_varint(p, remaining, &token_len, &consumed))`
  Review: Low-risk line; verify in surrounding control flow.
- L02481 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02482 [NONE] `	p += consumed; remaining -= consumed;`
  Review: Low-risk line; verify in surrounding control flow.
- L02483 [NONE] `	if (remaining < token_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L02484 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02485 [NONE] `	p += token_len; remaining -= token_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L02486 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02487 [NONE] `	/* Packet payload length varint */`
  Review: Low-risk line; verify in surrounding control flow.
- L02488 [NONE] `	if (ksmbd_quic_get_varint(p, remaining, &pkt_payload_len, &consumed))`
  Review: Low-risk line; verify in surrounding control flow.
- L02489 [ERROR_PATH|] `		return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02490 [NONE] `	p += consumed; remaining -= consumed;`
  Review: Low-risk line; verify in surrounding control flow.
- L02491 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02492 [NONE] `	/* Packet number length from first byte bits 0-1 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02493 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L02494 [NONE] `		u8 pkt_num_len = (first_byte & 0x03) + 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L02495 [NONE] `		if (remaining < pkt_num_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L02496 [ERROR_PATH|] `			return -EINVAL;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02497 [NONE] `		p += pkt_num_len; remaining -= pkt_num_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L02498 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02499 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02500 [NONE] `		 * pkt_payload_len includes the packet number field.`
  Review: Low-risk line; verify in surrounding control flow.
- L02501 [NONE] `		 * After removing the pkt_num bytes, the frame data follows.`
  Review: Low-risk line; verify in surrounding control flow.
- L02502 [NONE] `		 * Clamp to actual remaining bytes.`
  Review: Low-risk line; verify in surrounding control flow.
- L02503 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02504 [NONE] `		(void)pkt_payload_len; /* used for completeness */`
  Review: Low-risk line; verify in surrounding control flow.
- L02505 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02506 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02507 [NONE] `	*payload_out     = p;`
  Review: Low-risk line; verify in surrounding control flow.
- L02508 [NONE] `	*payload_len_out = remaining;`
  Review: Low-risk line; verify in surrounding control flow.
- L02509 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02510 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02511 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02512 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L02513 [NONE] ` * quic_process_initial_packet() - process a received QUIC Initial packet`
  Review: Low-risk line; verify in surrounding control flow.
- L02514 [NONE] ` * @udp_sock:	UDP listener socket`
  Review: Low-risk line; verify in surrounding control flow.
- L02515 [NONE] ` * @pkt:	Raw packet bytes`
  Review: Low-risk line; verify in surrounding control flow.
- L02516 [NONE] ` * @pkt_len:	Packet length`
  Review: Low-risk line; verify in surrounding control flow.
- L02517 [NONE] ` * @peer:	Sender's address`
  Review: Low-risk line; verify in surrounding control flow.
- L02518 [NONE] ` * @peer_len:	Sender address length`
  Review: Low-risk line; verify in surrounding control flow.
- L02519 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L02520 [NONE] ` * Full handshake state machine:`
  Review: Low-risk line; verify in surrounding control flow.
- L02521 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L02522 [NONE] ` *   1. Parse the long header to extract DCID / SCID.`
  Review: Low-risk line; verify in surrounding control flow.
- L02523 [NONE] ` *   2. If no existing connection: allocate ksmbd_quic_conn, derive Initial`
  Review: Low-risk line; verify in surrounding control flow.
- L02524 [NONE] ` *      keys (HKDF from DCID, RFC 9001 §A.1), insert into conn table.`
  Review: Low-risk line; verify in surrounding control flow.
- L02525 [NONE] ` *   3. Extract the packet payload and parse CRYPTO frames to buffer the`
  Review: Low-risk line; verify in surrounding control flow.
- L02526 [NONE] ` *      ClientHello data into qconn->crypto_buf.`
  Review: Low-risk line; verify in surrounding control flow.
- L02527 [NONE] ` *   4. Delegate the TLS 1.3 handshake to the ksmbdctl userspace daemon via`
  Review: Low-risk line; verify in surrounding control flow.
- L02528 [NONE] ` *      the SMBD_QUIC Generic Netlink family (quic_hs_ipc_request).`
  Review: Low-risk line; verify in surrounding control flow.
- L02529 [NONE] ` *      If a daemon is not registered, fall back to stub CONNECTED mode for`
  Review: Low-risk line; verify in surrounding control flow.
- L02530 [NONE] ` *      backward compatibility with existing test infrastructure.`
  Review: Low-risk line; verify in surrounding control flow.
- L02531 [NONE] ` *   5. On handshake success: install 1-RTT keys, transition to CONNECTED,`
  Review: Low-risk line; verify in surrounding control flow.
- L02532 [NONE] ` *      spawn the SMB handler thread.`
  Review: Low-risk line; verify in surrounding control flow.
- L02533 [NONE] ` *   6. On handshake failure: send CONNECTION_CLOSE, free the connection.`
  Review: Low-risk line; verify in surrounding control flow.
- L02534 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L02535 [NONE] ` * For existing QUIC connections (retransmitted Initial packets): extract`
  Review: Low-risk line; verify in surrounding control flow.
- L02536 [NONE] ` * any new CRYPTO data and update the buffer; do not create a new connection.`
  Review: Low-risk line; verify in surrounding control flow.
- L02537 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L02538 [NONE] `static void quic_process_initial_packet(struct socket *udp_sock,`
  Review: Low-risk line; verify in surrounding control flow.
- L02539 [NONE] `					const u8 *pkt, size_t pkt_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L02540 [NONE] `					struct sockaddr_storage *peer,`
  Review: Low-risk line; verify in surrounding control flow.
- L02541 [NONE] `					int peer_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L02542 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02543 [NONE] `	u8 dcid[QUIC_MAX_CID_LEN];`
  Review: Low-risk line; verify in surrounding control flow.
- L02544 [NONE] `	u8 scid[QUIC_MAX_CID_LEN];`
  Review: Low-risk line; verify in surrounding control flow.
- L02545 [NONE] `	u8 dcid_len = 0, scid_len = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02546 [NONE] `	struct ksmbd_quic_conn *qconn;`
  Review: Low-risk line; verify in surrounding control flow.
- L02547 [NONE] `	const u8 *payload;`
  Review: Low-risk line; verify in surrounding control flow.
- L02548 [NONE] `	size_t payload_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L02549 [NONE] `	bool new_conn = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L02550 [NONE] `	bool hs_ok;`
  Review: Low-risk line; verify in surrounding control flow.
- L02551 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L02552 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02553 [NONE] `	ret = quic_parse_initial_packet(pkt, pkt_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L02554 [NONE] `					dcid, &dcid_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L02555 [NONE] `					scid, &scid_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L02556 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02557 [NONE] `		ksmbd_debug(CONN, "QUIC: malformed Initial packet: %d\n", ret);`
  Review: Low-risk line; verify in surrounding control flow.
- L02558 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L02559 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02560 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02561 [NONE] `	/* Check if we already have a connection for this DCID */`
  Review: Low-risk line; verify in surrounding control flow.
- L02562 [LIFETIME|] `	rcu_read_lock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L02563 [NONE] `	qconn = quic_conn_lookup(dcid, dcid_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L02564 [LIFETIME|] `	rcu_read_unlock();`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L02565 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02566 [NONE] `	if (qconn) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02567 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02568 [NONE] `		 * Retransmitted Initial from an existing connection.`
  Review: Low-risk line; verify in surrounding control flow.
- L02569 [NONE] `		 * Extract any additional CRYPTO data and update the buffer.`
  Review: Low-risk line; verify in surrounding control flow.
- L02570 [NONE] `		 * Do not create a new connection or re-run the handshake.`
  Review: Low-risk line; verify in surrounding control flow.
- L02571 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02572 [NONE] `		if (READ_ONCE(qconn->state) == QUIC_STATE_HANDSHAKE) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02573 [NONE] `			if (!quic_extract_payload_from_initial(pkt, pkt_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L02574 [NONE] `							       &payload,`
  Review: Low-risk line; verify in surrounding control flow.
- L02575 [NONE] `							       &payload_len))`
  Review: Low-risk line; verify in surrounding control flow.
- L02576 [NONE] `				quic_parse_crypto_frames(qconn, payload,`
  Review: Low-risk line; verify in surrounding control flow.
- L02577 [NONE] `							 payload_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L02578 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02579 [NONE] `		ksmbd_debug(CONN, "QUIC: retransmitted Initial for known DCID\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L02580 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L02581 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02582 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02583 [NONE] `	/* New connection */`
  Review: Low-risk line; verify in surrounding control flow.
- L02584 [NONE] `	if (server_conf.max_connections &&`
  Review: Low-risk line; verify in surrounding control flow.
- L02585 [LIFETIME|] `	    atomic_read(&quic_active_conns) >= (int)server_conf.max_connections) {`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L02586 [NONE] `		pr_info_ratelimited("QUIC: max connections reached\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L02587 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L02588 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02589 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02590 [NONE] `	qconn = quic_conn_alloc(udp_sock);`
  Review: Low-risk line; verify in surrounding control flow.
- L02591 [NONE] `	if (!qconn) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02592 [ERROR_PATH|] `		pr_warn_ratelimited("QUIC: cannot allocate connection\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02593 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L02594 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02595 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02596 [NONE] `	/* Our DCID = client's DCID (the CID they sent packets to us with) */`
  Review: Low-risk line; verify in surrounding control flow.
- L02597 [MEM_BOUNDS|] `	memcpy(qconn->dcid, dcid, dcid_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L02598 [NONE] `	qconn->dcid_len = dcid_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L02599 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02600 [NONE] `	/* Client's SCID (they'll use as DCID for our packets) */`
  Review: Low-risk line; verify in surrounding control flow.
- L02601 [MEM_BOUNDS|] `	memcpy(qconn->scid, scid, scid_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L02602 [NONE] `	qconn->scid_len = scid_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L02603 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02604 [MEM_BOUNDS|] `	memcpy(&qconn->peer, peer, peer_len);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L02605 [NONE] `	qconn->peer_addrlen = peer_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L02606 [NONE] `	qconn->udp_sock = udp_sock;`
  Review: Low-risk line; verify in surrounding control flow.
- L02607 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02608 [NONE] `	/* Derive Initial packet keys (RFC 9001 §A.1) */`
  Review: Low-risk line; verify in surrounding control flow.
- L02609 [NONE] `	ret = ksmbd_quic_derive_initial_secrets(qconn);`
  Review: Low-risk line; verify in surrounding control flow.
- L02610 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02611 [ERROR_PATH|] `		pr_warn_ratelimited("QUIC: Initial secret derivation failed: %d\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02612 [NONE] `				    ret);`
  Review: Low-risk line; verify in surrounding control flow.
- L02613 [NONE] `		quic_conn_free(qconn);`
  Review: Low-risk line; verify in surrounding control flow.
- L02614 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L02615 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02616 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02617 [NONE] `	/* Insert into conn table so retransmits are handled correctly */`
  Review: Low-risk line; verify in surrounding control flow.
- L02618 [NONE] `	qconn->state = QUIC_STATE_HANDSHAKE;`
  Review: Low-risk line; verify in surrounding control flow.
- L02619 [NONE] `	quic_conn_insert(qconn);`
  Review: Low-risk line; verify in surrounding control flow.
- L02620 [NONE] `	new_conn = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L02621 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02622 [NONE] `	/* Extract CRYPTO frame data (ClientHello) from this Initial packet */`
  Review: Low-risk line; verify in surrounding control flow.
- L02623 [NONE] `	if (!quic_extract_payload_from_initial(pkt, pkt_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L02624 [NONE] `					       &payload, &payload_len)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02625 [NONE] `		ret = quic_parse_crypto_frames(qconn, payload, payload_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L02626 [NONE] `		if (ret > 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02627 [NONE] `			ksmbd_debug(CONN,`
  Review: Low-risk line; verify in surrounding control flow.
- L02628 [NONE] `				    "QUIC: buffered %d CRYPTO bytes from Initial\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L02629 [NONE] `				    ret);`
  Review: Low-risk line; verify in surrounding control flow.
- L02630 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02631 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02632 [NONE] `	ksmbd_debug(CONN, "QUIC: new connection from %pIS (dcid_len=%u, crypto=%zu)\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L02633 [NONE] `		    peer, dcid_len, qconn->crypto_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L02634 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02635 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02636 [NONE] `	 * TLS 1.3 Handshake Delegation.`
  Review: Low-risk line; verify in surrounding control flow.
- L02637 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L02638 [NONE] `	 * If a QUIC handshake daemon has registered, perform the full TLS 1.3`
  Review: Low-risk line; verify in surrounding control flow.
- L02639 [NONE] `	 * handshake via the SMBD_QUIC netlink family.`
  Review: Low-risk line; verify in surrounding control flow.
- L02640 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L02641 [NONE] `	 * If no daemon is registered (quic_tools_pid == 0), fall back to the`
  Review: Low-risk line; verify in surrounding control flow.
- L02642 [NONE] `	 * stub CONNECTED mode for backward compatibility with the existing QUIC`
  Review: Low-risk line; verify in surrounding control flow.
- L02643 [NONE] `	 * proxy test infrastructure.  In stub mode no encryption is applied at`
  Review: Low-risk line; verify in surrounding control flow.
- L02644 [NONE] `	 * the application layer (the QUIC proxy handles TLS externally).`
  Review: Low-risk line; verify in surrounding control flow.
- L02645 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02646 [NONE] `	{`
  Review: Low-risk line; verify in surrounding control flow.
- L02647 [NONE] `		unsigned int tools_pid;`
  Review: Low-risk line; verify in surrounding control flow.
- L02648 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02649 [LOCK|] `		spin_lock(&quic_tools_pid_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L02650 [NONE] `		tools_pid = quic_tools_pid;`
  Review: Low-risk line; verify in surrounding control flow.
- L02651 [LOCK|] `		spin_unlock(&quic_tools_pid_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L02652 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02653 [NONE] `		if (tools_pid && qconn->crypto_len > 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02654 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02655 [NONE] `			 * Full TLS 1.3 handshake path.`
  Review: Low-risk line; verify in surrounding control flow.
- L02656 [NONE] `			 *`
  Review: Low-risk line; verify in surrounding control flow.
- L02657 [NONE] `			 * quic_hs_ipc_request() blocks here (up to 30 s)`
  Review: Low-risk line; verify in surrounding control flow.
- L02658 [NONE] `			 * waiting for the userspace daemon to return the`
  Review: Low-risk line; verify in surrounding control flow.
- L02659 [NONE] `			 * session keys and server handshake flight.`
  Review: Low-risk line; verify in surrounding control flow.
- L02660 [NONE] `			 *`
  Review: Low-risk line; verify in surrounding control flow.
- L02661 [NONE] `			 * This is called from the RX thread which is NOT the`
  Review: Low-risk line; verify in surrounding control flow.
- L02662 [NONE] `			 * connection handler loop, so blocking here is safe.`
  Review: Low-risk line; verify in surrounding control flow.
- L02663 [NONE] `			 * The RX thread will not process further packets for`
  Review: Low-risk line; verify in surrounding control flow.
- L02664 [NONE] `			 * this connection until the handshake completes`
  Review: Low-risk line; verify in surrounding control flow.
- L02665 [NONE] `			 * (retransmits are handled by the DCID lookup above).`
  Review: Low-risk line; verify in surrounding control flow.
- L02666 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02667 [NONE] `			hs_ok = quic_hs_ipc_request(qconn);`
  Review: Low-risk line; verify in surrounding control flow.
- L02668 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02669 [NONE] `			if (!hs_ok) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02670 [ERROR_PATH|] `				pr_warn_ratelimited(`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02671 [NONE] `					"QUIC: handshake failed for %pIS\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L02672 [NONE] `					peer);`
  Review: Low-risk line; verify in surrounding control flow.
- L02673 [NONE] `				quic_send_connection_close(`
  Review: Low-risk line; verify in surrounding control flow.
- L02674 [NONE] `					qconn,`
  Review: Low-risk line; verify in surrounding control flow.
- L02675 [NONE] `					QUIC_ERR_CRYPTO_BASE + 40 /* TLS alert handshake_failure */,`
  Review: Low-risk line; verify in surrounding control flow.
- L02676 [NONE] `					"TLS 1.3 handshake failed");`
  Review: Low-risk line; verify in surrounding control flow.
- L02677 [NONE] `				quic_conn_remove(qconn);`
  Review: Low-risk line; verify in surrounding control flow.
- L02678 [NONE] `				quic_conn_free(qconn);`
  Review: Low-risk line; verify in surrounding control flow.
- L02679 [NONE] `				return;`
  Review: Low-risk line; verify in surrounding control flow.
- L02680 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L02681 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02682 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02683 [NONE] `			 * Install 1-RTT keys via kTLS if available.`
  Review: Low-risk line; verify in surrounding control flow.
- L02684 [NONE] `			 * The keys were already copied into qconn->app_crypto`
  Review: Low-risk line; verify in surrounding control flow.
- L02685 [NONE] `			 * by quic_hs_ipc_handle_rsp().`
  Review: Low-risk line; verify in surrounding control flow.
- L02686 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02687 [NONE] `#if IS_ENABLED(CONFIG_TLS)`
  Review: Low-risk line; verify in surrounding control flow.
- L02688 [NONE] `			if (qconn->app_crypto.ready) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02689 [NONE] `				u8 zero_salt[4] = {};`
  Review: Low-risk line; verify in surrounding control flow.
- L02690 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02691 [NONE] `				ret = ksmbd_quic_install_ktls_keys(`
  Review: Low-risk line; verify in surrounding control flow.
- L02692 [NONE] `					udp_sock,`
  Review: Low-risk line; verify in surrounding control flow.
- L02693 [NONE] `					qconn->app_crypto.write_key,`
  Review: Low-risk line; verify in surrounding control flow.
- L02694 [NONE] `					qconn->app_crypto.write_iv + 4,`
  Review: Low-risk line; verify in surrounding control flow.
- L02695 [NONE] `					zero_salt,`
  Review: Low-risk line; verify in surrounding control flow.
- L02696 [NONE] `					qconn->app_crypto.read_key,`
  Review: Low-risk line; verify in surrounding control flow.
- L02697 [NONE] `					qconn->app_crypto.read_iv + 4,`
  Review: Low-risk line; verify in surrounding control flow.
- L02698 [NONE] `					zero_salt);`
  Review: Low-risk line; verify in surrounding control flow.
- L02699 [NONE] `				if (ret)`
  Review: Low-risk line; verify in surrounding control flow.
- L02700 [ERROR_PATH|] `					pr_warn_ratelimited(`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02701 [NONE] `						"QUIC: kTLS key install failed: %d (continuing without offload)\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L02702 [NONE] `						ret);`
  Review: Low-risk line; verify in surrounding control flow.
- L02703 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L02704 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L02705 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02706 [NONE] `			WRITE_ONCE(qconn->state, QUIC_STATE_CONNECTED);`
  Review: Low-risk line; verify in surrounding control flow.
- L02707 [NONE] `			pr_info("ksmbd: QUIC TLS 1.3 handshake complete for %pIS\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L02708 [NONE] `				peer);`
  Review: Low-risk line; verify in surrounding control flow.
- L02709 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02710 [NONE] `		} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L02711 [NONE] `			/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02712 [NONE] `			 * Stub / fallback path: no handshake daemon registered`
  Review: Low-risk line; verify in surrounding control flow.
- L02713 [NONE] `			 * or no ClientHello data available.  Transition directly`
  Review: Low-risk line; verify in surrounding control flow.
- L02714 [NONE] `			 * to CONNECTED so the existing test infrastructure`
  Review: Low-risk line; verify in surrounding control flow.
- L02715 [NONE] `			 * (QUIC proxy, simple test clients) continues to work.`
  Review: Low-risk line; verify in surrounding control flow.
- L02716 [NONE] `			 *`
  Review: Low-risk line; verify in surrounding control flow.
- L02717 [NONE] `			 * Production deployments MUST have the handshake daemon`
  Review: Low-risk line; verify in surrounding control flow.
- L02718 [NONE] `			 * running; this fallback is for development/testing only.`
  Review: Low-risk line; verify in surrounding control flow.
- L02719 [NONE] `			 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02720 [NONE] `			if (tools_pid && qconn->crypto_len == 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02721 [ERROR_PATH|] `				pr_warn_ratelimited(`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02722 [NONE] `					"QUIC: no ClientHello data; falling back to stub mode\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L02723 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02724 [NONE] `			WRITE_ONCE(qconn->state, QUIC_STATE_CONNECTED);`
  Review: Low-risk line; verify in surrounding control flow.
- L02725 [NONE] `			ksmbd_debug(CONN,`
  Review: Low-risk line; verify in surrounding control flow.
- L02726 [NONE] `				    "QUIC: stub handshake complete (no daemon) for %pIS\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L02727 [NONE] `				    peer);`
  Review: Low-risk line; verify in surrounding control flow.
- L02728 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02729 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02730 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02731 [NONE] `	ret = ksmbd_quic_new_connection(qconn);`
  Review: Low-risk line; verify in surrounding control flow.
- L02732 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02733 [NONE] `		quic_conn_remove(qconn);`
  Review: Low-risk line; verify in surrounding control flow.
- L02734 [NONE] `		quic_conn_free(qconn);`
  Review: Low-risk line; verify in surrounding control flow.
- L02735 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02736 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02737 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02738 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L02739 [NONE] ` * quic_process_short_header_packet() - process a 1-RTT QUIC packet`
  Review: Low-risk line; verify in surrounding control flow.
- L02740 [NONE] ` * @udp_sock:	UDP listener socket`
  Review: Low-risk line; verify in surrounding control flow.
- L02741 [NONE] ` * @pkt:	Raw packet bytes`
  Review: Low-risk line; verify in surrounding control flow.
- L02742 [NONE] ` * @pkt_len:	Packet length`
  Review: Low-risk line; verify in surrounding control flow.
- L02743 [NONE] ` * @peer:	Sender's address`
  Review: Low-risk line; verify in surrounding control flow.
- L02744 [NONE] ` * @peer_len:	Sender address length`
  Review: Low-risk line; verify in surrounding control flow.
- L02745 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L02746 [NONE] ` * Looks up the connection by DCID, then processes STREAM frames carrying`
  Review: Low-risk line; verify in surrounding control flow.
- L02747 [NONE] ` * SMB data.  In a full implementation this would decrypt the packet with`
  Review: Low-risk line; verify in surrounding control flow.
- L02748 [NONE] ` * the 1-RTT AEAD keys; currently we parse the frame assuming unencrypted`
  Review: Low-risk line; verify in surrounding control flow.
- L02749 [NONE] ` * STREAM data (for test integration with the existing proxy path or a`
  Review: Low-risk line; verify in surrounding control flow.
- L02750 [NONE] ` * minimal QUIC client that does not enforce encryption on the STREAM payload`
  Review: Low-risk line; verify in surrounding control flow.
- L02751 [NONE] ` * after the handshake stub).`
  Review: Low-risk line; verify in surrounding control flow.
- L02752 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L02753 [NONE] `static void quic_process_short_header_packet(struct socket *udp_sock,`
  Review: Low-risk line; verify in surrounding control flow.
- L02754 [NONE] `					     const u8 *pkt, size_t pkt_len,`
  Review: Low-risk line; verify in surrounding control flow.
- L02755 [NONE] `					     struct sockaddr_storage *peer,`
  Review: Low-risk line; verify in surrounding control flow.
- L02756 [NONE] `					     int peer_len)`
  Review: Low-risk line; verify in surrounding control flow.
- L02757 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02758 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02759 [NONE] `	 * Short header (RFC 9000 §17.3):`
  Review: Low-risk line; verify in surrounding control flow.
- L02760 [NONE] `	 *   byte 0: 0x40 | spin | reserved | key_phase | pkt_num_len-1`
  Review: Low-risk line; verify in surrounding control flow.
- L02761 [NONE] `	 *   DCID: fixed length (from connection state)`
  Review: Low-risk line; verify in surrounding control flow.
- L02762 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L02763 [NONE] `	 * We don't know DCID length a priori from the packet alone; we must`
  Review: Low-risk line; verify in surrounding control flow.
- L02764 [NONE] `	 * try each known connection's dcid_len.  For our use case with small`
  Review: Low-risk line; verify in surrounding control flow.
- L02765 [NONE] `	 * numbers of connections a linear scan is acceptable.`
  Review: Low-risk line; verify in surrounding control flow.
- L02766 [NONE] `	 *`
  Review: Low-risk line; verify in surrounding control flow.
- L02767 [NONE] `	 * A production implementation would use a routing table keyed on the`
  Review: Low-risk line; verify in surrounding control flow.
- L02768 [NONE] `	 * first N bytes of the DCID.`
  Review: Low-risk line; verify in surrounding control flow.
- L02769 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02770 [NONE] `	struct ksmbd_quic_conn *qconn = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02771 [NONE] `	const u8 *payload;`
  Review: Low-risk line; verify in surrounding control flow.
- L02772 [NONE] `	size_t payload_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L02773 [NONE] `	u8 pkt_num_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L02774 [NONE] `	int bkt;`
  Review: Low-risk line; verify in surrounding control flow.
- L02775 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02776 [NONE] `	/* Scan the connection table for a matching DCID prefix */`
  Review: Low-risk line; verify in surrounding control flow.
- L02777 [LOCK|] `	spin_lock(&quic_conn_table_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L02778 [NONE] `	hash_for_each(quic_conn_table, bkt, qconn, hlist) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02779 [NONE] `		u8 cid_len = qconn->dcid_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L02780 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02781 [NONE] `		if (pkt_len < (size_t)(1 + cid_len + 1))`
  Review: Low-risk line; verify in surrounding control flow.
- L02782 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L02783 [NONE] `		if (memcmp(pkt + 1, qconn->dcid, cid_len) == 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02784 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L02785 [NONE] `		qconn = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L02786 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02787 [LOCK|] `	spin_unlock(&quic_conn_table_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L02788 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02789 [NONE] `	if (!qconn) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02790 [NONE] `		ksmbd_debug(CONN, "QUIC: short-header packet for unknown DCID\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L02791 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L02792 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02793 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02794 [NONE] `	pkt_num_len = (pkt[0] & QUIC_HDR_SHORT_PKT_NUM_MASK) + 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L02795 [NONE] `	payload = pkt + 1 + qconn->dcid_len + pkt_num_len;`
  Review: Low-risk line; verify in surrounding control flow.
- L02796 [NONE] `	payload_len = pkt_len - (1 + qconn->dcid_len + pkt_num_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L02797 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02798 [NONE] `	if ((ssize_t)payload_len <= 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L02799 [NONE] `		return;`
  Review: Low-risk line; verify in surrounding control flow.
- L02800 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02801 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02802 [NONE] `	 * Parse QUIC frames in the decrypted payload.`
  Review: Low-risk line; verify in surrounding control flow.
- L02803 [NONE] `	 * For STREAM frames (type 0x08..0x0F) carrying stream ID 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L02804 [NONE] `	 * append the data to the SMB reassembly buffer.`
  Review: Low-risk line; verify in surrounding control flow.
- L02805 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02806 [NONE] `	while (payload_len > 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02807 [NONE] `		u8 frame_type = payload[0];`
  Review: Low-risk line; verify in surrounding control flow.
- L02808 [NONE] `		const u8 *fp = payload + 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L02809 [NONE] `		size_t fp_rem = payload_len - 1;`
  Review: Low-risk line; verify in surrounding control flow.
- L02810 [NONE] `		u64 stream_id, offset, length;`
  Review: Low-risk line; verify in surrounding control flow.
- L02811 [NONE] `		int consumed;`
  Review: Low-risk line; verify in surrounding control flow.
- L02812 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02813 [NONE] `		if (frame_type == QUIC_FRAME_PADDING) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02814 [NONE] `			/* PADDING: entire frame is one 0x00 byte */`
  Review: Low-risk line; verify in surrounding control flow.
- L02815 [NONE] `			payload++;`
  Review: Low-risk line; verify in surrounding control flow.
- L02816 [NONE] `			payload_len--;`
  Review: Low-risk line; verify in surrounding control flow.
- L02817 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L02818 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02819 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02820 [NONE] `		if (frame_type == QUIC_FRAME_PING) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02821 [NONE] `			/* PING: 1 byte, elicits ACK but no data */`
  Review: Low-risk line; verify in surrounding control flow.
- L02822 [NONE] `			payload++;`
  Review: Low-risk line; verify in surrounding control flow.
- L02823 [NONE] `			payload_len--;`
  Review: Low-risk line; verify in surrounding control flow.
- L02824 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L02825 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02826 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02827 [NONE] `		if ((frame_type & 0xF8) == QUIC_FRAME_STREAM) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02828 [NONE] `			bool has_off = !!(frame_type & QUIC_FRAME_STREAM_OFF);`
  Review: Low-risk line; verify in surrounding control flow.
- L02829 [NONE] `			bool has_len = !!(frame_type & QUIC_FRAME_STREAM_LEN);`
  Review: Low-risk line; verify in surrounding control flow.
- L02830 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02831 [NONE] `			/* Stream ID */`
  Review: Low-risk line; verify in surrounding control flow.
- L02832 [NONE] `			if (ksmbd_quic_get_varint(fp, fp_rem,`
  Review: Low-risk line; verify in surrounding control flow.
- L02833 [NONE] `						  &stream_id, &consumed))`
  Review: Low-risk line; verify in surrounding control flow.
- L02834 [NONE] `				break;`
  Review: Low-risk line; verify in surrounding control flow.
- L02835 [NONE] `			fp += consumed; fp_rem -= consumed;`
  Review: Low-risk line; verify in surrounding control flow.
- L02836 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02837 [NONE] `			/* Optional Offset */`
  Review: Low-risk line; verify in surrounding control flow.
- L02838 [NONE] `			offset = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02839 [NONE] `			if (has_off) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02840 [NONE] `				if (ksmbd_quic_get_varint(fp, fp_rem,`
  Review: Low-risk line; verify in surrounding control flow.
- L02841 [NONE] `							  &offset, &consumed))`
  Review: Low-risk line; verify in surrounding control flow.
- L02842 [NONE] `					break;`
  Review: Low-risk line; verify in surrounding control flow.
- L02843 [NONE] `				fp += consumed; fp_rem -= consumed;`
  Review: Low-risk line; verify in surrounding control flow.
- L02844 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L02845 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02846 [NONE] `			/* Optional Length */`
  Review: Low-risk line; verify in surrounding control flow.
- L02847 [NONE] `			if (has_len) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02848 [NONE] `				if (ksmbd_quic_get_varint(fp, fp_rem,`
  Review: Low-risk line; verify in surrounding control flow.
- L02849 [NONE] `							  &length, &consumed))`
  Review: Low-risk line; verify in surrounding control flow.
- L02850 [NONE] `					break;`
  Review: Low-risk line; verify in surrounding control flow.
- L02851 [NONE] `				fp += consumed; fp_rem -= consumed;`
  Review: Low-risk line; verify in surrounding control flow.
- L02852 [NONE] `			} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L02853 [NONE] `				/* No Length field: data extends to end of packet */`
  Review: Low-risk line; verify in surrounding control flow.
- L02854 [NONE] `				length = fp_rem;`
  Review: Low-risk line; verify in surrounding control flow.
- L02855 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L02856 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02857 [NONE] `			if (length > fp_rem)`
  Review: Low-risk line; verify in surrounding control flow.
- L02858 [NONE] `				break;`
  Review: Low-risk line; verify in surrounding control flow.
- L02859 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02860 [NONE] `			/* Only stream 0 carries SMB data */`
  Review: Low-risk line; verify in surrounding control flow.
- L02861 [NONE] `			if (stream_id == 0 && qconn->smb_conn) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02862 [NONE] `				quic_stream_append(qconn, fp, (size_t)length);`
  Review: Low-risk line; verify in surrounding control flow.
- L02863 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L02864 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02865 [NONE] `			fp += length; fp_rem -= length;`
  Review: Low-risk line; verify in surrounding control flow.
- L02866 [NONE] `			payload = fp;`
  Review: Low-risk line; verify in surrounding control flow.
- L02867 [NONE] `			payload_len = fp_rem;`
  Review: Low-risk line; verify in surrounding control flow.
- L02868 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L02869 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02870 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02871 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02872 [NONE] `		 * Unknown / unhandled frame type: skip.`
  Review: Low-risk line; verify in surrounding control flow.
- L02873 [NONE] `		 * In a production implementation we'd handle ACK, CRYPTO,`
  Review: Low-risk line; verify in surrounding control flow.
- L02874 [NONE] `		 * CONNECTION_CLOSE, etc.`
  Review: Low-risk line; verify in surrounding control flow.
- L02875 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02876 [NONE] `		break;`
  Review: Low-risk line; verify in surrounding control flow.
- L02877 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02878 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L02879 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02880 [NONE] `/* =========================================================================`
  Review: Low-risk line; verify in surrounding control flow.
- L02881 [NONE] ` * UDP listener thread — receives all QUIC datagrams`
  Review: Low-risk line; verify in surrounding control flow.
- L02882 [NONE] ` * =========================================================================`
  Review: Low-risk line; verify in surrounding control flow.
- L02883 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L02884 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02885 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L02886 [NONE] ` * ksmbd_quic_rx_thread() - UDP listener receive loop`
  Review: Low-risk line; verify in surrounding control flow.
- L02887 [NONE] ` * @arg:	Unused`
  Review: Low-risk line; verify in surrounding control flow.
- L02888 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L02889 [NONE] ` * Receives UDP datagrams on the QUIC listener socket and dispatches them`
  Review: Low-risk line; verify in surrounding control flow.
- L02890 [NONE] ` * to either quic_process_initial_packet() (long-header Initial) or`
  Review: Low-risk line; verify in surrounding control flow.
- L02891 [NONE] ` * quic_process_short_header_packet() (short-header 1-RTT).`
  Review: Low-risk line; verify in surrounding control flow.
- L02892 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L02893 [NONE] ` * Return: 0 (thread function)`
  Review: Low-risk line; verify in surrounding control flow.
- L02894 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L02895 [NONE] `static int ksmbd_quic_rx_thread(void *arg)`
  Review: Low-risk line; verify in surrounding control flow.
- L02896 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L02897 [NONE] `	u8 *pkt_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L02898 [NONE] `	struct sockaddr_storage peer;`
  Review: Low-risk line; verify in surrounding control flow.
- L02899 [NONE] `	struct msghdr msg;`
  Review: Low-risk line; verify in surrounding control flow.
- L02900 [NONE] `	struct kvec iov;`
  Review: Low-risk line; verify in surrounding control flow.
- L02901 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L02902 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02903 [MEM_BOUNDS|] `	pkt_buf = kmalloc(QUIC_MAX_PKT_SIZE, KSMBD_DEFAULT_GFP);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L02904 [NONE] `	if (!pkt_buf) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02905 [ERROR_PATH|] `		pr_err("QUIC: RX thread: cannot allocate packet buffer\n");`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02906 [ERROR_PATH|] `		return -ENOMEM;`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02907 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L02908 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02909 [NONE] `	set_freezable();`
  Review: Low-risk line; verify in surrounding control flow.
- L02910 [NONE] `	ksmbd_debug(CONN, "QUIC: RX thread started\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L02911 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02912 [NONE] `	while (!kthread_should_stop()) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02913 [NONE] `		if (try_to_freeze())`
  Review: Low-risk line; verify in surrounding control flow.
- L02914 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L02915 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02916 [NONE] `		if (!quic_udp_sock)`
  Review: Low-risk line; verify in surrounding control flow.
- L02917 [NONE] `			break;`
  Review: Low-risk line; verify in surrounding control flow.
- L02918 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02919 [NONE] `		memset(&msg, 0, sizeof(msg));`
  Review: Low-risk line; verify in surrounding control flow.
- L02920 [NONE] `		memset(&peer, 0, sizeof(peer));`
  Review: Low-risk line; verify in surrounding control flow.
- L02921 [NONE] `		msg.msg_name    = &peer;`
  Review: Low-risk line; verify in surrounding control flow.
- L02922 [NONE] `		msg.msg_namelen = sizeof(peer);`
  Review: Low-risk line; verify in surrounding control flow.
- L02923 [NONE] `		iov.iov_base    = pkt_buf;`
  Review: Low-risk line; verify in surrounding control flow.
- L02924 [NONE] `		iov.iov_len     = QUIC_MAX_PKT_SIZE;`
  Review: Low-risk line; verify in surrounding control flow.
- L02925 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02926 [NONE] `		ret = kernel_recvmsg(quic_udp_sock, &msg, &iov, 1,`
  Review: Low-risk line; verify in surrounding control flow.
- L02927 [NONE] `				     QUIC_MAX_PKT_SIZE, MSG_DONTWAIT);`
  Review: Low-risk line; verify in surrounding control flow.
- L02928 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02929 [NONE] `		if (ret == -EAGAIN || ret == -EWOULDBLOCK) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02930 [NONE] `			/* No data: yield and retry */`
  Review: Low-risk line; verify in surrounding control flow.
- L02931 [WAIT_LOOP|] `			wait_event_interruptible_timeout(`
  Review: Bounded wait and cancellation path must be guaranteed.
- L02932 [NONE] `				quic_udp_sock->sk->sk_wq->wait,`
  Review: Low-risk line; verify in surrounding control flow.
- L02933 [NONE] `				!skb_queue_empty(&quic_udp_sock->sk->sk_receive_queue) ||`
  Review: Low-risk line; verify in surrounding control flow.
- L02934 [NONE] `				kthread_should_stop(),`
  Review: Low-risk line; verify in surrounding control flow.
- L02935 [NONE] `				HZ / 10);`
  Review: Low-risk line; verify in surrounding control flow.
- L02936 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L02937 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02938 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02939 [NONE] `		if (ret == -EINTR || ret <= 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02940 [NONE] `			if (kthread_should_stop())`
  Review: Low-risk line; verify in surrounding control flow.
- L02941 [NONE] `				break;`
  Review: Low-risk line; verify in surrounding control flow.
- L02942 [NONE] `			if (ret < 0 && ret != -EINTR)`
  Review: Low-risk line; verify in surrounding control flow.
- L02943 [ERROR_PATH|] `				pr_warn_ratelimited("QUIC: recvmsg error: %d\n", ret);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L02944 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L02945 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L02946 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02947 [NONE] `		if (ret < 1)`
  Review: Low-risk line; verify in surrounding control flow.
- L02948 [NONE] `			continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L02949 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02950 [NONE] `		/*`
  Review: Low-risk line; verify in surrounding control flow.
- L02951 [NONE] `		 * Dispatch based on Header Form bit (RFC 9000 §17.2 / §17.3)`
  Review: Low-risk line; verify in surrounding control flow.
- L02952 [NONE] `		 *   bit 7 = 1 → long header`
  Review: Low-risk line; verify in surrounding control flow.
- L02953 [NONE] `		 *   bit 7 = 0 → short header`
  Review: Low-risk line; verify in surrounding control flow.
- L02954 [NONE] `		 */`
  Review: Low-risk line; verify in surrounding control flow.
- L02955 [NONE] `		if (pkt_buf[0] & QUIC_HDR_FORM_LONG) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02956 [NONE] `			/* Long-header packet */`
  Review: Low-risk line; verify in surrounding control flow.
- L02957 [NONE] `			u8 pkt_type = (pkt_buf[0] >> 4) & 0x03;`
  Review: Low-risk line; verify in surrounding control flow.
- L02958 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02959 [NONE] `			/* Check QUIC version (bytes 1-4) */`
  Review: Low-risk line; verify in surrounding control flow.
- L02960 [NONE] `			if (ret >= 5) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02961 [NONE] `				u32 ver = get_unaligned_be32(pkt_buf + 1);`
  Review: Low-risk line; verify in surrounding control flow.
- L02962 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02963 [NONE] `				if (ver != QUIC_VERSION_1 && ver != 0) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02964 [NONE] `					/* Send Version Negotiation */`
  Review: Low-risk line; verify in surrounding control flow.
- L02965 [NONE] `					u8 dcid[QUIC_MAX_CID_LEN];`
  Review: Low-risk line; verify in surrounding control flow.
- L02966 [NONE] `					u8 scid[QUIC_MAX_CID_LEN];`
  Review: Low-risk line; verify in surrounding control flow.
- L02967 [NONE] `					u8 dl = 0, sl = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02968 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02969 [NONE] `					if (ret > 5) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02970 [NONE] `						dl = pkt_buf[5];`
  Review: Low-risk line; verify in surrounding control flow.
- L02971 [NONE] `						if (dl > QUIC_MAX_CID_LEN)`
  Review: Low-risk line; verify in surrounding control flow.
- L02972 [NONE] `							dl = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02973 [NONE] `						else if (ret > 6 + dl) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02974 [MEM_BOUNDS|] `							memcpy(dcid, pkt_buf + 6, dl);`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L02975 [NONE] `							sl = pkt_buf[6 + dl];`
  Review: Low-risk line; verify in surrounding control flow.
- L02976 [NONE] `							if (sl > QUIC_MAX_CID_LEN)`
  Review: Low-risk line; verify in surrounding control flow.
- L02977 [NONE] `								sl = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L02978 [NONE] `							else if (ret > 7 + dl + sl)`
  Review: Low-risk line; verify in surrounding control flow.
- L02979 [MEM_BOUNDS|] `								memcpy(scid,`
  Review: Validate allocation size, overflow checks, and copy bounds.
- L02980 [NONE] `								       pkt_buf + 7 + dl,`
  Review: Low-risk line; verify in surrounding control flow.
- L02981 [NONE] `								       sl);`
  Review: Low-risk line; verify in surrounding control flow.
- L02982 [NONE] `						}`
  Review: Low-risk line; verify in surrounding control flow.
- L02983 [NONE] `					}`
  Review: Low-risk line; verify in surrounding control flow.
- L02984 [NONE] `					quic_send_version_negotiation(`
  Review: Low-risk line; verify in surrounding control flow.
- L02985 [NONE] `						quic_udp_sock, &peer,`
  Review: Low-risk line; verify in surrounding control flow.
- L02986 [NONE] `						msg.msg_namelen,`
  Review: Low-risk line; verify in surrounding control flow.
- L02987 [NONE] `						dcid, dl, scid, sl);`
  Review: Low-risk line; verify in surrounding control flow.
- L02988 [NONE] `					continue;`
  Review: Low-risk line; verify in surrounding control flow.
- L02989 [NONE] `				}`
  Review: Low-risk line; verify in surrounding control flow.
- L02990 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L02991 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L02992 [NONE] `			/* Initial packet type = 0x00 (bits 5:4 of first byte) */`
  Review: Low-risk line; verify in surrounding control flow.
- L02993 [NONE] `			if (pkt_type == 0x00) {`
  Review: Low-risk line; verify in surrounding control flow.
- L02994 [NONE] `				quic_process_initial_packet(`
  Review: Low-risk line; verify in surrounding control flow.
- L02995 [NONE] `					quic_udp_sock, pkt_buf, ret,`
  Review: Low-risk line; verify in surrounding control flow.
- L02996 [NONE] `					&peer, msg.msg_namelen);`
  Review: Low-risk line; verify in surrounding control flow.
- L02997 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L02998 [NONE] `			/* Handshake / 0-RTT packets: not handled yet */`
  Review: Low-risk line; verify in surrounding control flow.
- L02999 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03000 [NONE] `		} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L03001 [NONE] `			/* Short-header 1-RTT packet */`
  Review: Low-risk line; verify in surrounding control flow.
- L03002 [NONE] `			if (pkt_buf[0] & QUIC_HDR_FIXED_BIT) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03003 [NONE] `				quic_process_short_header_packet(`
  Review: Low-risk line; verify in surrounding control flow.
- L03004 [NONE] `					quic_udp_sock, pkt_buf, ret,`
  Review: Low-risk line; verify in surrounding control flow.
- L03005 [NONE] `					&peer, msg.msg_namelen);`
  Review: Low-risk line; verify in surrounding control flow.
- L03006 [NONE] `			}`
  Review: Low-risk line; verify in surrounding control flow.
- L03007 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L03008 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03009 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03010 [NONE] `	kfree(pkt_buf);`
  Review: Low-risk line; verify in surrounding control flow.
- L03011 [NONE] `	ksmbd_debug(CONN, "QUIC: RX thread exiting\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L03012 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L03013 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L03014 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03015 [NONE] `/* =========================================================================`
  Review: Low-risk line; verify in surrounding control flow.
- L03016 [NONE] ` * UDP socket creation and binding`
  Review: Low-risk line; verify in surrounding control flow.
- L03017 [NONE] ` * =========================================================================`
  Review: Low-risk line; verify in surrounding control flow.
- L03018 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L03019 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03020 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L03021 [NONE] ` * create_udp_listener() - create and bind the UDP QUIC listener socket`
  Review: Low-risk line; verify in surrounding control flow.
- L03022 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L03023 [NONE] ` * Creates a UDP socket (IPPROTO_UDP) bound to INADDR_ANY on port 443.`
  Review: Low-risk line; verify in surrounding control flow.
- L03024 [NONE] ` * Tries IPv6 first (dual-stack), falls back to IPv4 if IPv6 is not available.`
  Review: Low-risk line; verify in surrounding control flow.
- L03025 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L03026 [NONE] ` * Return: 0 on success, negative errno on failure.`
  Review: Low-risk line; verify in surrounding control flow.
- L03027 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L03028 [NONE] `static int create_udp_listener(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L03029 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L03030 [NONE] `	struct socket *sock;`
  Review: Low-risk line; verify in surrounding control flow.
- L03031 [NONE] `	struct sockaddr_in6 sin6;`
  Review: Low-risk line; verify in surrounding control flow.
- L03032 [NONE] `	struct sockaddr_in sin;`
  Review: Low-risk line; verify in surrounding control flow.
- L03033 [NONE] `	bool ipv4 = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L03034 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L03035 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03036 [NONE] `	/* Try IPv6 (dual-stack) first */`
  Review: Low-risk line; verify in surrounding control flow.
- L03037 [NONE] `	ret = sock_create_kern(current->nsproxy->net_ns, PF_INET6,`
  Review: Low-risk line; verify in surrounding control flow.
- L03038 [NONE] `			       SOCK_DGRAM, IPPROTO_UDP, &sock);`
  Review: Low-risk line; verify in surrounding control flow.
- L03039 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03040 [NONE] `		if (ret != -EAFNOSUPPORT)`
  Review: Low-risk line; verify in surrounding control flow.
- L03041 [ERROR_PATH|] `			pr_err("QUIC: cannot create IPv6 UDP socket: %d, trying IPv4\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03042 [NONE] `			       ret);`
  Review: Low-risk line; verify in surrounding control flow.
- L03043 [NONE] `		ret = sock_create_kern(current->nsproxy->net_ns, PF_INET,`
  Review: Low-risk line; verify in surrounding control flow.
- L03044 [NONE] `				       SOCK_DGRAM, IPPROTO_UDP, &sock);`
  Review: Low-risk line; verify in surrounding control flow.
- L03045 [NONE] `		if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03046 [ERROR_PATH|] `			pr_err("QUIC: cannot create IPv4 UDP socket: %d\n", ret);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03047 [NONE] `			return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L03048 [NONE] `		}`
  Review: Low-risk line; verify in surrounding control flow.
- L03049 [NONE] `		ipv4 = true;`
  Review: Low-risk line; verify in surrounding control flow.
- L03050 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03051 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03052 [NONE] `	if (!ipv4) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03053 [NONE] `		/* Allow IPv4 clients via IPv6 dual-stack */`
  Review: Low-risk line; verify in surrounding control flow.
- L03054 [NONE] `		lock_sock(sock->sk);`
  Review: Low-risk line; verify in surrounding control flow.
- L03055 [NONE] `		sock->sk->sk_ipv6only = false;`
  Review: Low-risk line; verify in surrounding control flow.
- L03056 [NONE] `		release_sock(sock->sk);`
  Review: Low-risk line; verify in surrounding control flow.
- L03057 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03058 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03059 [NONE] `	/* SO_REUSEADDR to allow restart without TIME_WAIT delay */`
  Review: Low-risk line; verify in surrounding control flow.
- L03060 [NONE] `	sock_set_reuseaddr(sock->sk);`
  Review: Low-risk line; verify in surrounding control flow.
- L03061 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03062 [NONE] `	if (ipv4) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03063 [NONE] `		sin.sin_family      = AF_INET;`
  Review: Low-risk line; verify in surrounding control flow.
- L03064 [NONE] `		sin.sin_addr.s_addr = htonl(INADDR_ANY);`
  Review: Low-risk line; verify in surrounding control flow.
- L03065 [NONE] `		sin.sin_port        = htons(KSMBD_QUIC_PORT);`
  Review: Low-risk line; verify in surrounding control flow.
- L03066 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 19, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L03067 [NONE] `		ret = kernel_bind(sock, (struct sockaddr_unsized *)&sin,`
  Review: Low-risk line; verify in surrounding control flow.
- L03068 [NONE] `				  sizeof(sin));`
  Review: Low-risk line; verify in surrounding control flow.
- L03069 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L03070 [NONE] `		ret = kernel_bind(sock, (struct sockaddr *)&sin, sizeof(sin));`
  Review: Low-risk line; verify in surrounding control flow.
- L03071 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L03072 [NONE] `	} else {`
  Review: Low-risk line; verify in surrounding control flow.
- L03073 [NONE] `		sin6.sin6_family   = AF_INET6;`
  Review: Low-risk line; verify in surrounding control flow.
- L03074 [NONE] `		sin6.sin6_addr     = in6addr_any;`
  Review: Low-risk line; verify in surrounding control flow.
- L03075 [NONE] `		sin6.sin6_port     = htons(KSMBD_QUIC_PORT);`
  Review: Low-risk line; verify in surrounding control flow.
- L03076 [NONE] `		sin6.sin6_flowinfo = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L03077 [NONE] `		sin6.sin6_scope_id = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L03078 [NONE] `#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 19, 0)`
  Review: Low-risk line; verify in surrounding control flow.
- L03079 [NONE] `		ret = kernel_bind(sock, (struct sockaddr_unsized *)&sin6,`
  Review: Low-risk line; verify in surrounding control flow.
- L03080 [NONE] `				  sizeof(sin6));`
  Review: Low-risk line; verify in surrounding control flow.
- L03081 [NONE] `#else`
  Review: Low-risk line; verify in surrounding control flow.
- L03082 [NONE] `		ret = kernel_bind(sock, (struct sockaddr *)&sin6, sizeof(sin6));`
  Review: Low-risk line; verify in surrounding control flow.
- L03083 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L03084 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03085 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03086 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03087 [ERROR_PATH|] `		pr_err("QUIC: cannot bind UDP socket to port %u: %d\n",`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03088 [NONE] `		       KSMBD_QUIC_PORT, ret);`
  Review: Low-risk line; verify in surrounding control flow.
- L03089 [NONE] `		sock_release(sock);`
  Review: Low-risk line; verify in surrounding control flow.
- L03090 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L03091 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03092 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03093 [NONE] `	quic_udp_sock = sock;`
  Review: Low-risk line; verify in surrounding control flow.
- L03094 [NONE] `	pr_info("ksmbd: QUIC UDP listener on port %u (%s)\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L03095 [NONE] `		KSMBD_QUIC_PORT, ipv4 ? "IPv4" : "IPv6 dual-stack");`
  Review: Low-risk line; verify in surrounding control flow.
- L03096 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L03097 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L03098 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03099 [NONE] `/* =========================================================================`
  Review: Low-risk line; verify in surrounding control flow.
- L03100 [NONE] ` * Public init / destroy`
  Review: Low-risk line; verify in surrounding control flow.
- L03101 [NONE] ` * =========================================================================`
  Review: Low-risk line; verify in surrounding control flow.
- L03102 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L03103 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03104 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L03105 [NONE] ` * ksmbd_quic_init() - initialise the kernel-native QUIC transport`
  Review: Low-risk line; verify in surrounding control flow.
- L03106 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L03107 [NONE] ` * Creates the UDP listener socket, starts the RX thread, and registers`
  Review: Low-risk line; verify in surrounding control flow.
- L03108 [NONE] ` * the SMBD_QUIC Generic Netlink family for TLS handshake delegation.`
  Review: Low-risk line; verify in surrounding control flow.
- L03109 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L03110 [NONE] ` * Return: 0 on success, negative errno on failure.`
  Review: Low-risk line; verify in surrounding control flow.
- L03111 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L03112 [NONE] `int ksmbd_quic_init(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L03113 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L03114 [NONE] `	int ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L03115 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03116 [LIFETIME|] `	atomic_set(&quic_active_conns, 0);`
  Review: Validate refcount/atomic transitions and teardown ordering.
- L03117 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03118 [NONE] `	/* Register the SMBD_QUIC genl family for handshake IPC */`
  Review: Low-risk line; verify in surrounding control flow.
- L03119 [NONE] `	ret = genl_register_family(&quic_hs_genl_family);`
  Review: Low-risk line; verify in surrounding control flow.
- L03120 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03121 [ERROR_PATH|] `		pr_err("QUIC: cannot register handshake genl family: %d\n", ret);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03122 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L03123 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03124 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03125 [NONE] `	ret = create_udp_listener();`
  Review: Low-risk line; verify in surrounding control flow.
- L03126 [NONE] `	if (ret) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03127 [NONE] `		genl_unregister_family(&quic_hs_genl_family);`
  Review: Low-risk line; verify in surrounding control flow.
- L03128 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L03129 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03130 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03131 [NONE] `	quic_listener_kthread = kthread_run(ksmbd_quic_rx_thread, NULL,`
  Review: Low-risk line; verify in surrounding control flow.
- L03132 [NONE] `					    "ksmbd-quic-rx");`
  Review: Low-risk line; verify in surrounding control flow.
- L03133 [NONE] `	if (IS_ERR(quic_listener_kthread)) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03134 [NONE] `		ret = PTR_ERR(quic_listener_kthread);`
  Review: Low-risk line; verify in surrounding control flow.
- L03135 [NONE] `		quic_listener_kthread = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L03136 [ERROR_PATH|] `		pr_err("QUIC: cannot start RX thread: %d\n", ret);`
  Review: Error path: ensure graceful unwind and no resource leak.
- L03137 [NONE] `		sock_release(quic_udp_sock);`
  Review: Low-risk line; verify in surrounding control flow.
- L03138 [NONE] `		quic_udp_sock = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L03139 [NONE] `		genl_unregister_family(&quic_hs_genl_family);`
  Review: Low-risk line; verify in surrounding control flow.
- L03140 [NONE] `		return ret;`
  Review: Low-risk line; verify in surrounding control flow.
- L03141 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03142 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03143 [NONE] `	pr_info("ksmbd: kernel-native QUIC transport initialized (RFC 9000/9001)\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L03144 [NONE] `	pr_info("ksmbd: QUIC: HKDF-SHA256 + AES-128-GCM + header protection enabled\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L03145 [NONE] `	pr_info("ksmbd: QUIC: TLS 1.3 handshake delegation via genl family '%s'\n",`
  Review: Low-risk line; verify in surrounding control flow.
- L03146 [NONE] `		KSMBD_QUIC_GENL_NAME);`
  Review: Low-risk line; verify in surrounding control flow.
- L03147 [NONE] `#if IS_ENABLED(CONFIG_TLS)`
  Review: Low-risk line; verify in surrounding control flow.
- L03148 [NONE] `	pr_info("ksmbd: QUIC: kTLS acceleration available\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L03149 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L03150 [NONE] `	return 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L03151 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L03152 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03153 [NONE] `/**`
  Review: Low-risk line; verify in surrounding control flow.
- L03154 [NONE] ` * ksmbd_quic_destroy() - tear down the kernel-native QUIC transport`
  Review: Low-risk line; verify in surrounding control flow.
- L03155 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L03156 [NONE] ` * Stops the RX thread, releases the UDP socket, removes all active`
  Review: Low-risk line; verify in surrounding control flow.
- L03157 [NONE] ` * connections from the hash table, and unregisters the SMBD_QUIC genl family.`
  Review: Low-risk line; verify in surrounding control flow.
- L03158 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L03159 [NONE] `void ksmbd_quic_destroy(void)`
  Review: Low-risk line; verify in surrounding control flow.
- L03160 [NONE] `{`
  Review: Low-risk line; verify in surrounding control flow.
- L03161 [NONE] `	struct ksmbd_quic_conn *qconn;`
  Review: Low-risk line; verify in surrounding control flow.
- L03162 [NONE] `	int bkt;`
  Review: Low-risk line; verify in surrounding control flow.
- L03163 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03164 [NONE] `	if (quic_listener_kthread) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03165 [NONE] `		kthread_stop(quic_listener_kthread);`
  Review: Low-risk line; verify in surrounding control flow.
- L03166 [NONE] `		quic_listener_kthread = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L03167 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03168 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03169 [NONE] `	if (quic_udp_sock) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03170 [NONE] `		kernel_sock_shutdown(quic_udp_sock, SHUT_RDWR);`
  Review: Low-risk line; verify in surrounding control flow.
- L03171 [NONE] `		sock_release(quic_udp_sock);`
  Review: Low-risk line; verify in surrounding control flow.
- L03172 [NONE] `		quic_udp_sock = NULL;`
  Review: Low-risk line; verify in surrounding control flow.
- L03173 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03174 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03175 [NONE] `	/* Clean up any remaining QUIC connections */`
  Review: Low-risk line; verify in surrounding control flow.
- L03176 [LOCK|] `	spin_lock(&quic_conn_table_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L03177 [NONE] `	hash_for_each(quic_conn_table, bkt, qconn, hlist) {`
  Review: Low-risk line; verify in surrounding control flow.
- L03178 [NONE] `		WRITE_ONCE(qconn->state, QUIC_STATE_CLOSED);`
  Review: Low-risk line; verify in surrounding control flow.
- L03179 [NONE] `		wake_up_all(&qconn->wait);`
  Review: Low-risk line; verify in surrounding control flow.
- L03180 [NONE] `	}`
  Review: Low-risk line; verify in surrounding control flow.
- L03181 [LOCK|] `	spin_unlock(&quic_conn_table_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L03182 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03183 [NONE] `	/* Unregister the SMBD_QUIC handshake genl family */`
  Review: Low-risk line; verify in surrounding control flow.
- L03184 [NONE] `	genl_unregister_family(&quic_hs_genl_family);`
  Review: Low-risk line; verify in surrounding control flow.
- L03185 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03186 [NONE] `	/* Reset the tools PID */`
  Review: Low-risk line; verify in surrounding control flow.
- L03187 [LOCK|] `	spin_lock(&quic_tools_pid_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L03188 [NONE] `	quic_tools_pid = 0;`
  Review: Low-risk line; verify in surrounding control flow.
- L03189 [LOCK|] `	spin_unlock(&quic_tools_pid_lock);`
  Review: Verify lock pairing, scope minimization, and no sleep-in-atomic violations.
- L03190 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03191 [NONE] `	/* Drain the IDA */`
  Review: Low-risk line; verify in surrounding control flow.
- L03192 [NONE] `	ida_destroy(&quic_hs_ida);`
  Review: Low-risk line; verify in surrounding control flow.
- L03193 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03194 [NONE] `	ksmbd_debug(CONN, "QUIC: kernel-native transport destroyed\n");`
  Review: Low-risk line; verify in surrounding control flow.
- L03195 [NONE] `}`
  Review: Low-risk line; verify in surrounding control flow.
- L03196 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03197 [NONE] `/* =========================================================================`
  Review: Low-risk line; verify in surrounding control flow.
- L03198 [NONE] ` * Transport ops table`
  Review: Low-risk line; verify in surrounding control flow.
- L03199 [NONE] ` * =========================================================================`
  Review: Low-risk line; verify in surrounding control flow.
- L03200 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L03201 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L03202 [NONE] `static const struct ksmbd_transport_ops ksmbd_quic_transport_ops = {`
  Review: Low-risk line; verify in surrounding control flow.
- L03203 [NONE] `	.read		= ksmbd_quic_read,`
  Review: Low-risk line; verify in surrounding control flow.
- L03204 [NONE] `	.writev		= ksmbd_quic_writev,`
  Review: Low-risk line; verify in surrounding control flow.
- L03205 [NONE] `	.shutdown	= ksmbd_quic_shutdown,`
  Review: Low-risk line; verify in surrounding control flow.
- L03206 [NONE] `	.disconnect	= ksmbd_quic_disconnect,`
  Review: Low-risk line; verify in surrounding control flow.
- L03207 [NONE] `	.free_transport	= ksmbd_quic_free_transport,`
  Review: Low-risk line; verify in surrounding control flow.
- L03208 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
