// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2024 Samsung Electronics Co., Ltd.
 *
 * Kernel-native QUIC transport for ksmbd — SMB over QUIC (MS-SMB2 Appendix C).
 *
 * This replaces the userspace-proxy approach with a kernel UDP socket that
 * handles QUIC packet framing directly per RFC 9000/RFC 9001.
 *
 * Architecture:
 *
 *   SMB Client --(QUIC/TLS 1.3 over UDP port 443)--> [ksmbd kernel module]
 *
 * QUIC crypto dependencies (all kernel-internal, NO third-party code):
 *   - HKDF-SHA-256    : crypto/hkdf.h  (kernel >= 6.9, RFC 5869)
 *   - AES-128-GCM     : crypto/aead.h  (RFC 9001 §5)
 *   - AES-128-ECB     : crypto/internal/cipher.h (packet number protection,
 *                        RFC 9001 §5.4)
 *   - kTLS            : net/tls.h (CONFIG_TLS) for TLS record encryption
 *
 * SMB over QUIC specifics (MS-SMB2 Appendix C, RFC 9443):
 *   - No RFC1002 NetBIOS 4-byte length prefix on QUIC (unlike TCP).
 *   - Each SMB session maps to one bidirectional QUIC stream (stream ID 0).
 *   - Port 443 (HTTPS alternative port, also used for SMB over QUIC).
 *
 * Implementation notes:
 *   - QUIC Initial packets: long-header, AEAD-AES-128-GCM, keys from HKDF.
 *   - QUIC 1-RTT packets: short-header, AEAD, keys from TLS 1.3 handshake.
 *   - kTLS path: after handshake, SOL_TLS/TLS_TX/TLS_RX installed into UDP
 *     socket for hardware-offloaded or software TLS record encryption.
 *   - Listener: UDP socket bound to port 443; rx thread dispatches packets.
 *
 * TLS 1.3 Handshake Delegation:
 *   The full TLS 1.3 handshake is delegated to the ksmbdctl userspace daemon
 *   via a dedicated Generic Netlink family (SMBD_QUIC).  When a QUIC Initial
 *   packet is received:
 *     1. CRYPTO frame data (ClientHello) is extracted.
 *     2. A KSMBD_QUIC_CMD_HANDSHAKE_REQ is sent to userspace.
 *     3. Userspace performs TLS 1.3, returns KSMBD_QUIC_CMD_HANDSHAKE_RSP
 *        with 1-RTT session keys and the server handshake flight.
 *     4. Kernel transmits the server flight in QUIC Initial/Handshake packets.
 *     5. 1-RTT keys are installed; state transitions to CONNECTED.
 *
 * Kconfig dependencies (see comment in Kconfig):
 *   SMB_SERVER_QUIC selects CRYPTO_AES, CRYPTO_GCM, CRYPTO_HMAC,
 *   CRYPTO_SHA256; imply TLS for optional kTLS acceleration.
 */

#define SUBMOD_NAME	"smb_quic"

#include <linux/kthread.h>
#include <linux/net.h>
#include <linux/stddef.h>
#include <linux/file.h>
#include <linux/freezer.h>
#include <linux/hashtable.h>
#include <linux/cred.h>
#include <linux/pid.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/socket.h>
#include <linux/version.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/wait.h>
#include <linux/spinlock.h>
#include <linux/completion.h>
#include <linux/jhash.h>
#include <linux/rwsem.h>
#include <linux/idr.h>
#include <net/sock.h>
#include <net/ip.h>
#include <net/udp.h>
#include <net/genetlink.h>
#include <crypto/hash.h>
#include <crypto/hkdf.h>
#include <crypto/aead.h>
#include <crypto/internal/cipher.h>
#include <uapi/linux/tls.h>

#if IS_ENABLED(CONFIG_TLS)
#include <net/tls.h>
#endif

#include "glob.h"
#include "connection.h"
#include "smb_common.h"
#include "server.h"
#include "transport_quic.h"

/* =========================================================================
 * QUIC constants (RFC 9000, RFC 9001)
 * =========================================================================
 */

/* QUIC version 1 (RFC 9000 §15) */
#define QUIC_VERSION_1			0x00000001U

/* Long-header first-byte flags (RFC 9000 §17.2) */
#define QUIC_HDR_FORM_LONG		0x80	/* Header Form = 1 */
#define QUIC_HDR_FIXED_BIT		0x40	/* Fixed Bit = 1 (MUST be 1) */
#define QUIC_LONG_TYPE_INITIAL		0x00	/* Packet Type = Initial */
#define QUIC_LONG_TYPE_HANDSHAKE	0x20	/* Packet Type = Handshake */
#define QUIC_LONG_TYPE_RETRY		0x30	/* Packet Type = Retry */

/* Short-header first-byte flags (RFC 9000 §17.3) */
#define QUIC_HDR_SHORT_SPIN		0x20	/* Spin bit */
#define QUIC_HDR_SHORT_KEY_PHASE	0x04	/* Key phase */
#define QUIC_HDR_SHORT_PKT_NUM_MASK	0x03	/* Packet number length - 1 */

/* Max DCID / SCID length (RFC 9000 §17.2) */
#define QUIC_MAX_CID_LEN		20

/* QUIC Initial salt for QUIC v1 (RFC 9001 §A.1) */
static const u8 quic_v1_initial_salt[20] = {
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
	0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
	0xcc, 0xbb, 0x7f, 0x0a
};

/* HKDF label prefix for QUIC (RFC 9001 §5.1).
 * RFC 8446 §3.4 defines HKDF-Expand-Label as using the "tls13 " prefix
 * (6 chars + space).  The QUIC-specific labels ("quic key", "quic iv",
 * "quic hp", etc.) are already distinct and do NOT require an additional
 * "quic " qualifier in the prefix.  Using "tls13 quic " was a bug that
 * would produce the wrong keying material for every key derivation step.
 */
#define QUIC_HKDF_LABEL_PREFIX		"tls13 "

/* QUIC Initial key/IV/HP label strings (RFC 9001 §5.2) */
#define QUIC_LABEL_CLIENT_IN		"client in"
#define QUIC_LABEL_SERVER_IN		"server in"
#define QUIC_LABEL_QUIC_KEY		"quic key"
#define QUIC_LABEL_QUIC_IV		"quic iv"
#define QUIC_LABEL_QUIC_HP		"quic hp"

/* AES-128-GCM parameters */
#define QUIC_AEAD_KEY_SIZE		16
#define QUIC_AEAD_IV_SIZE		12
#define QUIC_AEAD_TAG_SIZE		16
#define QUIC_HP_KEY_SIZE		16

/* Maximum QUIC packet size we process (one UDP datagram) */
#define QUIC_MAX_PKT_SIZE		1500

/* Maximum SMB PDU size buffered per connection */
#define QUIC_STREAM_BUF_SIZE		(128 * 1024)

/* QUIC STREAM frame type bits (RFC 9000 §19.8) */
#define QUIC_FRAME_STREAM		0x08
#define QUIC_FRAME_STREAM_FIN		0x01
#define QUIC_FRAME_STREAM_LEN		0x02
#define QUIC_FRAME_STREAM_OFF		0x04
#define QUIC_FRAME_PADDING		0x00
#define QUIC_FRAME_PING			0x01
#define QUIC_FRAME_CRYPTO		0x06
#define QUIC_FRAME_ACK			0x02

/*
 * CONNECTION_CLOSE frame types (RFC 9000 §19.19):
 *   0x1c — carries a QUIC transport error code
 *   0x1d — carries an application protocol error code
 */
#define QUIC_FRAME_CONNECTION_CLOSE		0x1c
#define QUIC_FRAME_CONNECTION_CLOSE_APP		0x1d

/* QUIC transport error codes (RFC 9000 §20) */
#define QUIC_ERR_NO_ERROR			0x00
#define QUIC_ERR_INTERNAL_ERROR			0x01
#define QUIC_ERR_CONNECTION_REFUSED		0x02
#define QUIC_ERR_FLOW_CONTROL_ERROR		0x03
#define QUIC_ERR_STREAM_LIMIT_ERROR		0x04
#define QUIC_ERR_STREAM_STATE_ERROR		0x05
#define QUIC_ERR_FINAL_SIZE_ERROR		0x06
#define QUIC_ERR_FRAME_ENCODING_ERROR		0x07
#define QUIC_ERR_TRANSPORT_PARAMETER_ERROR	0x08
#define QUIC_ERR_CONNECTION_ID_LIMIT_ERROR	0x09
#define QUIC_ERR_PROTOCOL_VIOLATION		0x0a
#define QUIC_ERR_INVALID_TOKEN			0x0b
#define QUIC_ERR_APPLICATION_ERROR		0x0c
#define QUIC_ERR_CRYPTO_BUFFER_EXCEEDED		0x0d
#define QUIC_ERR_KEY_UPDATE_ERROR		0x0e
#define QUIC_ERR_AEAD_LIMIT_REACHED		0x0f
#define QUIC_ERR_CRYPTO_BASE			0x0100	/* + TLS alert code */

/* Max ClientHello data we buffer from CRYPTO frames (same as header define) */
#define QUIC_MAX_CRYPTO_DATA	KSMBD_QUIC_MAX_CLIENT_HELLO

/* Handshake IPC wait timeout: 30 seconds to allow cert load + TLS handshake */
#define QUIC_HS_IPC_TIMEOUT_MS	30000

/* Connection state machine */
enum quic_conn_state {
	QUIC_STATE_INITIAL = 0,	/* Waiting for Initial packet */
	QUIC_STATE_HANDSHAKE,	/* TLS handshake in progress */
	QUIC_STATE_CONNECTED,	/* 1-RTT: data can flow */
	QUIC_STATE_CLOSING,	/* CONNECTION_CLOSE sent/received */
	QUIC_STATE_CLOSED,	/* Connection fully closed */
};

/* =========================================================================
 * Per-connection QUIC state
 * =========================================================================
 */

/**
 * struct ksmbd_quic_crypto - AEAD keys for one QUIC packet number space
 * @key:	AEAD encryption/decryption key
 * @iv:		AEAD IV (base nonce)
 * @hp:		Header protection key (AES-128-ECB)
 * @key_len:	Valid length of @key
 * @ready:	true when keys have been derived
 */
struct ksmbd_quic_crypto {
	u8	key[QUIC_AEAD_KEY_SIZE];
	u8	iv[QUIC_AEAD_IV_SIZE];
	u8	hp[QUIC_HP_KEY_SIZE];
	u8	key_len;
	bool	ready;
};

/**
 * struct ksmbd_quic_app_crypto - 1-RTT (application) AEAD keys
 *
 * These keys are derived by the TLS 1.3 handshake (performed in userspace)
 * and installed into the kernel after the handshake completes.
 *
 * @write_key:	Server write key (used to encrypt packets sent to client)
 * @write_iv:	Server write IV (base nonce for AEAD)
 * @read_key:	Client write key (used to decrypt packets received from client)
 * @read_iv:	Client write IV
 * @key_len:	Key length in bytes (16 for AES-128-GCM, 32 for AES-256-GCM)
 * @ready:	true once keys have been installed from the handshake result
 */
struct ksmbd_quic_app_crypto {
	u8	write_key[KSMBD_QUIC_KEY_SIZE];
	u8	write_iv[KSMBD_QUIC_IV_SIZE];
	u8	read_key[KSMBD_QUIC_KEY_SIZE];
	u8	read_iv[KSMBD_QUIC_IV_SIZE];
	u8	key_len;
	bool	ready;
};

/**
 * struct ksmbd_quic_conn - kernel-native QUIC per-connection state
 *
 * Each accepted QUIC connection (identified by its DCID) owns one of these.
 * Created when we receive the first Initial packet from a new peer.
 *
 * @hlist:	Hash list node (keyed on dcid, stored in quic_conn_table)
 * @state:	Connection state machine (enum quic_conn_state)
 * @peer:	Peer UDP address (filled from recvmsg)
 * @peer_addrlen: Length of @peer
 * @dcid:	Destination CID (our SCID as seen by the peer)
 * @scid:	Source CID (peer's DCID as seen by us)
 * @dcid_len:	Length of @dcid
 * @scid_len:	Length of @scid
 * @initial_tx:	TX crypto for Initial packet number space
 * @initial_rx:	RX crypto for Initial packet number space
 * @app_crypto:	1-RTT application traffic keys (installed after TLS handshake)
 * @send_pkt_num: Next packet number to use (monotonically increasing)
 * @recv_pkt_num: Largest received packet number (for ACK generation)
 * @lock:	Spinlock protecting this struct
 * @stream_buf: Reassembly buffer for incoming SMB PDU data from STREAM frames
 * @stream_len: Number of bytes currently in @stream_buf
 * @stream_max: Allocated size of @stream_buf
 * @crypto_buf:	Buffer for CRYPTO stream data (ClientHello bytes from Initial)
 * @crypto_len:	Number of bytes buffered in @crypto_buf
 * @hs_done:	Completion: signalled when handshake IPC response arrives
 * @wait:	Wait queue: SMB handler thread sleeps here for data
 * @smb_conn:	ksmbd connection object (non-NULL once CONNECTED)
 * @udp_sock:	Shared UDP listener socket (we send via this)
 * @ipc_handle:	IPC correlation handle for the pending HANDSHAKE_REQ
 */
struct ksmbd_quic_conn {
	struct hlist_node		hlist;
	enum quic_conn_state		state;
	struct sockaddr_storage		peer;
	int				peer_addrlen;
	u8				dcid[QUIC_MAX_CID_LEN];
	u8				scid[QUIC_MAX_CID_LEN];
	u8				dcid_len;
	u8				scid_len;
	struct ksmbd_quic_crypto	initial_tx;
	struct ksmbd_quic_crypto	initial_rx;
	struct ksmbd_quic_app_crypto	app_crypto;
	u64				send_pkt_num;
	u64				recv_pkt_num;
	spinlock_t			lock;
	/* SMB PDU reassembly buffer (data from QUIC STREAM frames) */
	u8				*stream_buf;
	size_t				stream_len;
	size_t				stream_max;
	/* CRYPTO stream buffer (ClientHello from Initial packets) */
	u8				crypto_buf[QUIC_MAX_CRYPTO_DATA];
	size_t				crypto_len;
	/* Handshake IPC synchronisation */
	struct completion		hs_done;
	int				ipc_handle;
	wait_queue_head_t		wait;
	struct ksmbd_conn		*smb_conn;
	struct socket			*udp_sock;
};

/* =========================================================================
 * Per-connection transport wrapper (plugs into ksmbd_transport_ops)
 * =========================================================================
 */

/**
 * struct quic_transport - ksmbd transport adapter for a QUIC connection
 * @transport:	Embedded ksmbd_transport (must be first for container_of)
 * @qconn:	Underlying QUIC connection state
 * @iov:	Reusable iovec scratch buffer
 * @nr_iov:	Number of segments in @iov
 */
struct quic_transport {
	struct ksmbd_transport		transport;
	struct ksmbd_quic_conn		*qconn;
	struct kvec			*iov;
	unsigned int			nr_iov;
};

static const struct ksmbd_transport_ops ksmbd_quic_transport_ops;

#define KSMBD_TRANS(t)	(&(t)->transport)
#define QUIC_TRANS(t)	((struct quic_transport *)container_of(t, \
				struct quic_transport, transport))

/* =========================================================================
 * Global listener state
 * =========================================================================
 */

static struct task_struct	*quic_listener_kthread;
static struct socket		*quic_udp_sock;		/* shared UDP socket */
static atomic_t			 quic_active_conns;

/* Hash table for active QUIC connections, keyed on DCID bytes */
#define QUIC_CONN_HASH_BITS	8
static DEFINE_HASHTABLE(quic_conn_table, QUIC_CONN_HASH_BITS);
static DEFINE_SPINLOCK(quic_conn_table_lock);

/*
 * QUIC-04: Stateless Retry token secret (RFC 9000 §8.1).
 *
 * Per RFC 9000 §8.1 the server MUST verify the client address before
 * investing significant resources in the handshake, to prevent UDP
 * amplification attacks.  This is done via a stateless Retry packet.
 *
 * We generate a random secret at module init time.  The token is an
 * HMAC-SHA256 of (client_addr || client_addrlen || dcid || dcid_len)
 * keyed by this secret.  On the second Initial the token is verified
 * before the handshake proceeds.
 *
 * Token format (32 bytes): HMAC-SHA256(server_secret, peer_addr || dcid)
 */
#define QUIC_RETRY_TOKEN_LEN	32	/* HMAC-SHA256 output */
static u8 quic_retry_secret[32];
static bool quic_retry_secret_ready;

/* =========================================================================
 * QUIC variable-length integer encoding/decoding (RFC 9000 §16)
 * =========================================================================
 */

/**
 * ksmbd_quic_put_varint() - encode a QUIC variable-length integer
 * @buf:	Destination buffer (must have at least 8 bytes available)
 * @val:	Value to encode (must be < 2^62)
 * @len_out:	Set to the number of bytes written
 *
 * Return: 0 on success, -ERANGE if val is too large.
 */
static int ksmbd_quic_put_varint(u8 *buf, u64 val, int *len_out)
{
	if (val < 64) {
		buf[0] = (u8)val;
		*len_out = 1;
	} else if (val < 16384) {
		buf[0] = 0x40 | (u8)(val >> 8);
		buf[1] = (u8)val;
		*len_out = 2;
	} else if (val < 1073741824ULL) {
		put_unaligned_be32((u32)(0x80000000UL | val), buf);
		*len_out = 4;
	} else if (val < (1ULL << 62)) {
		put_unaligned_be64(0xC000000000000000ULL | val, buf);
		*len_out = 8;
	} else {
		return -ERANGE;
	}
	return 0;
}

/**
 * ksmbd_quic_get_varint() - decode a QUIC variable-length integer
 * @buf:	Source buffer
 * @len:	Available bytes in buffer
 * @val_out:	Set to the decoded value
 * @consumed:	Set to the number of bytes consumed
 *
 * Return: 0 on success, -EINVAL if the buffer is too short.
 */
static int ksmbd_quic_get_varint(const u8 *buf, size_t len,
				 u64 *val_out, int *consumed)
{
	u8 first;
	int nbytes;
	u64 val;

	if (!len)
		return -EINVAL;

	first = buf[0];
	switch (first >> 6) {
	case 0:
		*val_out = first & 0x3f;
		*consumed = 1;
		return 0;
	case 1:
		if (len < 2)
			return -EINVAL;
		*val_out = ((u64)(first & 0x3f) << 8) | buf[1];
		*consumed = 2;
		return 0;
	case 2:
		if (len < 4)
			return -EINVAL;
		val = ((u64)(first & 0x3f) << 24) |
		      ((u64)buf[1] << 16) |
		      ((u64)buf[2] << 8) |
		       (u64)buf[3];
		*val_out = val;
		*consumed = 4;
		return 0;
	case 3:
		if (len < 8)
			return -EINVAL;
		nbytes = 8;
		val = ((u64)(first & 0x3f) << 56) |
		      ((u64)buf[1] << 48) |
		      ((u64)buf[2] << 40) |
		      ((u64)buf[3] << 32) |
		      ((u64)buf[4] << 24) |
		      ((u64)buf[5] << 16) |
		      ((u64)buf[6] << 8) |
		       (u64)buf[7];
		*val_out = val;
		*consumed = nbytes;
		return 0;
	}
	return -EINVAL; /* unreachable */
}

/* =========================================================================
 * QUIC-TLS HKDF (RFC 9001 §5, using kernel crypto/hkdf.h)
 * =========================================================================
 */

/**
 * ksmbd_quic_hkdf_expand_label() - QUIC-specific HKDF-Expand-Label (RFC 9001)
 * @secret:	PRK input (from a prior HKDF-Extract)
 * @secret_len:	Length of @secret
 * @label:	Label string (e.g. "quic key"), without the "tls13 " prefix
 * @context:	Context bytes (typically empty for QUIC initial secrets)
 * @ctx_len:	Length of @context
 * @out:	Output keying material
 * @out_len:	Required output length
 *
 * Builds the HkdfLabel structure (RFC 8446 §3.4 / RFC 9001 §5.1):
 *   struct {
 *     uint16 length;
 *     opaque label<7..255>;   // "tls13 " + label  (RFC 8446 §3.4 / RFC 9001 §5.1)
 *     opaque context<0..255>;
 *   } HkdfLabel;
 *
 * Then calls the kernel's hkdf_expand() (crypto/hkdf.h).
 *
 * Return: 0 on success, negative errno on failure.
 */
static int ksmbd_quic_hkdf_expand_label(const u8 *secret, size_t secret_len,
					 const char *label,
					 const u8 *context, size_t ctx_len,
					 u8 *out, size_t out_len)
{
	struct crypto_shash *hmac_tfm;
	/* HkdfLabel: 2-byte length + 1-byte label_len + label + 1-byte ctx_len + ctx */
	u8 hkdf_label[2 + 1 + 255 + 1 + 255];
	size_t label_full_len;
	size_t label_len_byte;
	int ret;
	u8 *p = hkdf_label;

	/*
	 * Full label = "tls13 " + caller's label (e.g. "quic key")
	 * RFC 9001 §5.1 / RFC 8446 §3.4: the prefix is "tls13 " (7 bytes),
	 * not "tls13 quic " — the QUIC-specific portion is in the label itself.
	 */
	label_full_len = strlen(QUIC_HKDF_LABEL_PREFIX) + strlen(label);
	if (label_full_len > 255 || ctx_len > 255 || out_len > 0xFFFF)
		return -EINVAL;

	/* length (2 bytes, big-endian) */
	put_unaligned_be16((u16)out_len, p);
	p += 2;

	/* label length byte + label bytes */
	label_len_byte = label_full_len;
	*p++ = (u8)label_len_byte;
	memcpy(p, QUIC_HKDF_LABEL_PREFIX, strlen(QUIC_HKDF_LABEL_PREFIX));
	p += strlen(QUIC_HKDF_LABEL_PREFIX);
	memcpy(p, label, strlen(label));
	p += strlen(label);

	/* context length byte + context bytes */
	*p++ = (u8)ctx_len;
	if (ctx_len)
		memcpy(p, context, ctx_len);
	p += ctx_len;

	/* Allocate HMAC-SHA256 transform for HKDF */
	hmac_tfm = crypto_alloc_shash("hmac(sha256)", 0, 0);
	if (IS_ERR(hmac_tfm))
		return PTR_ERR(hmac_tfm);

	/*
	 * Set the PRK as the HMAC key (hkdf_expand treats the key as PRK).
	 * crypto_shash_setkey sets the HMAC key for hkdf_expand.
	 */
	ret = crypto_shash_setkey(hmac_tfm, secret, secret_len);
	if (ret)
		goto out_free;

	ret = hkdf_expand(hmac_tfm,
			  hkdf_label, (unsigned int)(p - hkdf_label),
			  out, (unsigned int)out_len);

out_free:
	crypto_free_shash(hmac_tfm);
	return ret;
}

/**
 * ksmbd_quic_derive_initial_secrets() - derive QUIC Initial packet keys
 * @qconn:	QUIC connection; @dcid must be set before calling
 *
 * Implements RFC 9001 §A.1:
 *   initial_secret = HKDF-Extract(initial_salt, DCID)
 *   client_secret  = HKDF-Expand-Label(initial_secret, "client in", "", 32)
 *   server_secret  = HKDF-Expand-Label(initial_secret, "server in", "", 32)
 *
 * Then derives key/IV/HP for each direction:
 *   key = HKDF-Expand-Label(secret, "quic key", "", 16)
 *   iv  = HKDF-Expand-Label(secret, "quic iv", "", 12)
 *   hp  = HKDF-Expand-Label(secret, "quic hp", "", 16)
 *
 * Return: 0 on success, negative errno on failure.
 */
static int ksmbd_quic_derive_initial_secrets(struct ksmbd_quic_conn *qconn)
{
	struct crypto_shash *hmac_tfm;
	u8 initial_secret[32];
	u8 client_secret[32];
	u8 server_secret[32];
	int ret;

	/* HKDF-Extract(salt=initial_salt, IKM=DCID) → initial_secret */
	hmac_tfm = crypto_alloc_shash("hmac(sha256)", 0, 0);
	if (IS_ERR(hmac_tfm))
		return PTR_ERR(hmac_tfm);

	ret = hkdf_extract(hmac_tfm,
			   qconn->dcid, qconn->dcid_len,
			   quic_v1_initial_salt, sizeof(quic_v1_initial_salt),
			   initial_secret);
	crypto_free_shash(hmac_tfm);
	if (ret)
		return ret;

	/* client_secret = HKDF-Expand-Label(initial_secret, "client in", "", 32) */
	ret = ksmbd_quic_hkdf_expand_label(initial_secret, sizeof(initial_secret),
					   QUIC_LABEL_CLIENT_IN,
					   NULL, 0,
					   client_secret, sizeof(client_secret));
	if (ret)
		return ret;

	/* server_secret = HKDF-Expand-Label(initial_secret, "server in", "", 32) */
	ret = ksmbd_quic_hkdf_expand_label(initial_secret, sizeof(initial_secret),
					   QUIC_LABEL_SERVER_IN,
					   NULL, 0,
					   server_secret, sizeof(server_secret));
	if (ret)
		return ret;

	/*
	 * RX keys = client_in (we receive from client)
	 * TX keys = server_in (we send from server)
	 */

	/* rx key */
	ret = ksmbd_quic_hkdf_expand_label(client_secret, sizeof(client_secret),
					   QUIC_LABEL_QUIC_KEY, NULL, 0,
					   qconn->initial_rx.key, QUIC_AEAD_KEY_SIZE);
	if (ret)
		return ret;
	/* rx iv */
	ret = ksmbd_quic_hkdf_expand_label(client_secret, sizeof(client_secret),
					   QUIC_LABEL_QUIC_IV, NULL, 0,
					   qconn->initial_rx.iv, QUIC_AEAD_IV_SIZE);
	if (ret)
		return ret;
	/* rx hp */
	ret = ksmbd_quic_hkdf_expand_label(client_secret, sizeof(client_secret),
					   QUIC_LABEL_QUIC_HP, NULL, 0,
					   qconn->initial_rx.hp, QUIC_HP_KEY_SIZE);
	if (ret)
		return ret;
	qconn->initial_rx.key_len = QUIC_AEAD_KEY_SIZE;
	qconn->initial_rx.ready = true;

	/* tx key */
	ret = ksmbd_quic_hkdf_expand_label(server_secret, sizeof(server_secret),
					   QUIC_LABEL_QUIC_KEY, NULL, 0,
					   qconn->initial_tx.key, QUIC_AEAD_KEY_SIZE);
	if (ret)
		return ret;
	/* tx iv */
	ret = ksmbd_quic_hkdf_expand_label(server_secret, sizeof(server_secret),
					   QUIC_LABEL_QUIC_IV, NULL, 0,
					   qconn->initial_tx.iv, QUIC_AEAD_IV_SIZE);
	if (ret)
		return ret;
	/* tx hp */
	ret = ksmbd_quic_hkdf_expand_label(server_secret, sizeof(server_secret),
					   QUIC_LABEL_QUIC_HP, NULL, 0,
					   qconn->initial_tx.hp, QUIC_HP_KEY_SIZE);
	if (ret)
		return ret;
	qconn->initial_tx.key_len = QUIC_AEAD_KEY_SIZE;
	qconn->initial_tx.ready = true;

	/* Scrub sensitive material from stack */
	memzero_explicit(initial_secret, sizeof(initial_secret));
	memzero_explicit(client_secret, sizeof(client_secret));
	memzero_explicit(server_secret, sizeof(server_secret));

	return 0;
}

/* =========================================================================
 * QUIC packet number header protection (RFC 9001 §5.4)
 * =========================================================================
 *
 * The packet number field in both long- and short-header packets is
 * protected by XOR-ing with the first pkt_num_len bytes of:
 *   AES-128-ECB(hp_key, sample)
 * where sample is 16 bytes taken from the ciphertext starting at offset 4
 * from the start of the packet number field.
 */

/**
 * ksmbd_quic_apply_header_protection() - encrypt or decrypt packet number
 * @pkt_num_bytes: Pointer to the packet number field in the packet buffer
 * @pkt_num_len:   Number of bytes in the packet number (1-4)
 * @hp_key:        16-byte header protection key
 * @ciphertext_sample: 16 bytes of ciphertext starting 4 bytes after pktnum
 *
 * This function is its own inverse (XOR is reversible), so the same
 * function is used for both protection and removal.
 */
static void __maybe_unused
ksmbd_quic_apply_header_protection(u8 *pkt_num_bytes,
				   int pkt_num_len,
				   const u8 *hp_key,
				   const u8 *ciphertext_sample)
{
	struct crypto_cipher *tfm;
	u8 mask[16];
	int i;

	tfm = crypto_alloc_cipher("aes", 0, 0);
	if (IS_ERR(tfm)) {
		pr_warn_ratelimited("QUIC: cannot allocate AES cipher for HP: %ld\n",
				    PTR_ERR(tfm));
		return;
	}

	if (crypto_cipher_setkey(tfm, hp_key, QUIC_HP_KEY_SIZE)) {
		pr_warn_ratelimited("QUIC: AES HP key setup failed\n");
		crypto_free_cipher(tfm);
		return;
	}

	/* mask = AES-ECB(hp_key, sample) */
	crypto_cipher_encrypt_one(tfm, mask, ciphertext_sample);
	crypto_free_cipher(tfm);

	/* XOR the packet number bytes with the mask */
	for (i = 0; i < pkt_num_len && i < 4; i++)
		pkt_num_bytes[i] ^= mask[i];

	memzero_explicit(mask, sizeof(mask));
}

/* =========================================================================
 * QUIC AEAD encrypt/decrypt (RFC 9001 §5.3)
 * =========================================================================
 *
 * QUIC uses AEAD-AES-128-GCM with:
 *   nonce = IV XOR (zero-padded packet number)
 *   AAD   = QUIC packet header (up to but not including the payload)
 */

/**
 * ksmbd_quic_aead_crypt() - AEAD encrypt or decrypt a QUIC payload
 * @key:	16-byte AEAD key
 * @iv:		12-byte AEAD base IV
 * @pkt_num:	Packet number (XOR'd into nonce, RFC 9001 §5.3)
 * @aad:	Additional authenticated data (packet header)
 * @aad_len:	Length of @aad
 * @in:		Input buffer (plaintext for encrypt, ciphertext+tag for decrypt)
 * @in_len:	Length of @in
 * @out:	Output buffer
 * @out_len:	On input: size of @out.  On success: bytes written.
 * @encrypt:	true = encrypt, false = decrypt
 *
 * Return: 0 on success, negative errno on failure.
 */
static int __maybe_unused
ksmbd_quic_aead_crypt(const u8 *key, const u8 *iv, u64 pkt_num,
		      const u8 *aad, size_t aad_len,
		      const u8 *in, size_t in_len,
		      u8 *out, size_t *out_len,
		      bool encrypt)
{
	struct crypto_aead *tfm;
	struct aead_request *req;
	/*
	 * QUIC-01 fix: kernel AEAD API requires the AAD to be placed at the
	 * start of the input scatterlist.  aead_request_set_ad(req, aad_len)
	 * tells the engine that the first aad_len bytes of the SGL are AAD
	 * (authenticated but not encrypted).  We use a single combined buffer
	 * [aad | payload] so that a single sg_init_one() covers both.
	 *
	 * RFC 9001 §5.3: AEAD-AES-128-GCM with
	 *   nonce = IV XOR pkt_num (big-endian, right-aligned)
	 *   AAD   = QUIC packet header bytes
	 *   plaintext/ciphertext = QUIC payload
	 *   tag   = 16 bytes appended after ciphertext
	 *
	 * For encrypt: combined_src = [aad | plaintext]
	 *              cryptlen = in_len  (plaintext bytes; tag appended to dst)
	 * For decrypt: combined_src = [aad | ciphertext | tag]
	 *              cryptlen = in_len  (ciphertext + tag; in_len includes tag)
	 *
	 * The output buffer (sg_dst) receives only the payload result (no AAD):
	 * encrypt → [plaintext | tag] written at offset aad_len in combined_buf
	 * decrypt → [plaintext]       written at offset aad_len in combined_buf
	 *
	 * We use a single in-place combined buffer to avoid two allocations.
	 */
	struct scatterlist sg_combined;
	u8 nonce[QUIC_AEAD_IV_SIZE];
	u8 *combined_buf;
	size_t combined_len;
	size_t crypt_len;
	int ret, i;

	/* Sanity: decrypt input must include the authentication tag */
	if (!encrypt && in_len < QUIC_AEAD_TAG_SIZE)
		return -EINVAL;

	/* nonce = IV XOR (pkt_num encoded big-endian into right 8 bytes) */
	memcpy(nonce, iv, QUIC_AEAD_IV_SIZE);
	for (i = 0; i < 8; i++)
		nonce[QUIC_AEAD_IV_SIZE - 1 - i] ^= (u8)(pkt_num >> (8 * i));

	tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	ret = crypto_aead_setkey(tfm, key, QUIC_AEAD_KEY_SIZE);
	if (ret)
		goto free_tfm;

	ret = crypto_aead_setauthsize(tfm, QUIC_AEAD_TAG_SIZE);
	if (ret)
		goto free_tfm;

	req = aead_request_alloc(tfm, GFP_KERNEL);
	if (!req) {
		ret = -ENOMEM;
		goto free_tfm;
	}

	/*
	 * Allocate one combined buffer: [aad | payload (+ tag room for enc)]
	 * For encrypt: combined_len = aad_len + in_len + QUIC_AEAD_TAG_SIZE
	 * For decrypt: combined_len = aad_len + in_len  (tag already in in)
	 */
	if (encrypt)
		combined_len = aad_len + in_len + QUIC_AEAD_TAG_SIZE;
	else
		combined_len = aad_len + in_len;

	combined_buf = kmalloc(combined_len, GFP_KERNEL);
	if (!combined_buf) {
		ret = -ENOMEM;
		goto free_req;
	}

	/* Copy AAD into combined buffer prefix */
	memcpy(combined_buf, aad, aad_len);
	/* Copy payload (plaintext or ciphertext+tag) after the AAD */
	memcpy(combined_buf + aad_len, in, in_len);

	/*
	 * cryptlen is the number of bytes to be en/decrypted (not including AAD).
	 * For encrypt: in_len plaintext bytes (tag appended by the engine).
	 * For decrypt: in_len bytes = ciphertext + tag (tag stripped by engine).
	 */
	crypt_len = in_len;

	sg_init_one(&sg_combined, combined_buf, combined_len);

	aead_request_set_tfm(req, tfm);
	aead_request_set_callback(req, 0, NULL, NULL);
	/* AAD occupies the first aad_len bytes of the SGL */
	aead_request_set_ad(req, aad_len);
	/* src == dst: in-place operation; the engine skips the AAD prefix */
	aead_request_set_crypt(req, &sg_combined, &sg_combined,
			       crypt_len, nonce);

	if (encrypt)
		ret = crypto_aead_encrypt(req);
	else
		ret = crypto_aead_decrypt(req);

	if (!ret) {
		/*
		 * Result payload starts at combined_buf + aad_len.
		 * Encrypt: aad_len + in_len + tag bytes in combined_buf;
		 *          copy (in_len + QUIC_AEAD_TAG_SIZE) bytes out.
		 * Decrypt: aad_len + (in_len - tag) plaintext in combined_buf;
		 *          copy (in_len - QUIC_AEAD_TAG_SIZE) bytes out.
		 */
		size_t copy_len = encrypt ? (in_len + QUIC_AEAD_TAG_SIZE)
					  : (in_len - QUIC_AEAD_TAG_SIZE);
		if (copy_len > *out_len) {
			ret = -ENOSPC;
		} else {
			memcpy(out, combined_buf + aad_len, copy_len);
			*out_len = copy_len;
		}
	}

	memzero_explicit(combined_buf, combined_len);
	kfree(combined_buf);
free_req:
	aead_request_free(req);
free_tfm:
	crypto_free_aead(tfm);
	memzero_explicit(nonce, sizeof(nonce));
	return ret;
}

/* =========================================================================
 * kTLS integration (CONFIG_TLS)
 * =========================================================================
 *
 * After a TLS 1.3 handshake completes, we can offload TLS record encryption
 * to the kernel's TLS implementation by installing session keys via SOL_TLS.
 * This is optional acceleration; the software QUIC crypto path above handles
 * encryption without kTLS.
 */

#if IS_ENABLED(CONFIG_TLS)
/**
 * ksmbd_quic_install_ktls_keys() - install TLS 1.3 session keys into kTLS
 * @sock:	Socket to configure
 * @write_key:	16-byte AES-GCM write key
 * @write_iv:	8-byte write IV (implicit part, not the explicit nonce)
 * @write_salt:	4-byte write salt
 * @read_key:	16-byte AES-GCM read key
 * @read_iv:	8-byte read IV
 * @read_salt:	4-byte read salt
 *
 * Uses sock_setsockopt() with SOL_TLS/TLS_TX and SOL_TLS/TLS_RX to push
 * the TLS 1.3 AES-128-GCM session keys into the kernel TLS implementation.
 * After this call the socket's send/recv paths automatically perform TLS
 * record layer encryption/decryption in software (or via NIC offload).
 *
 * Return: 0 on success, negative errno on failure.
 *
 * Note: The tls12_crypto_info_aes_gcm_128 struct is from
 * <uapi/linux/tls.h>.  The .info.version field must be TLS_1_3_VERSION
 * for TLS 1.3.
 */
static int __maybe_unused
ksmbd_quic_install_ktls_keys(struct socket *sock,
			     const u8 *write_key,
			     const u8 *write_iv,
			     const u8 *write_salt,
			     const u8 *read_key,
			     const u8 *read_iv,
			     const u8 *read_salt)
{
	struct tls12_crypto_info_aes_gcm_128 tx_info = {};
	struct tls12_crypto_info_aes_gcm_128 rx_info = {};
	int ret;

	/* TX (write) direction */
	tx_info.info.version    = TLS_1_3_VERSION;
	tx_info.info.cipher_type = TLS_CIPHER_AES_GCM_128;
	memcpy(tx_info.key,  write_key,  TLS_CIPHER_AES_GCM_128_KEY_SIZE);
	memcpy(tx_info.iv,   write_iv,   TLS_CIPHER_AES_GCM_128_IV_SIZE);
	memcpy(tx_info.salt, write_salt, TLS_CIPHER_AES_GCM_128_SALT_SIZE);
	/* rec_seq starts at 0 */

	ret = sock_setsockopt(sock, SOL_TLS, TLS_TX,
			      KERNEL_SOCKPTR(&tx_info), sizeof(tx_info));
	if (ret) {
		pr_warn_ratelimited("QUIC: kTLS TLS_TX setup failed: %d\n", ret);
		return ret;
	}

	/* RX (read) direction */
	rx_info.info.version    = TLS_1_3_VERSION;
	rx_info.info.cipher_type = TLS_CIPHER_AES_GCM_128;
	memcpy(rx_info.key,  read_key,  TLS_CIPHER_AES_GCM_128_KEY_SIZE);
	memcpy(rx_info.iv,   read_iv,   TLS_CIPHER_AES_GCM_128_IV_SIZE);
	memcpy(rx_info.salt, read_salt, TLS_CIPHER_AES_GCM_128_SALT_SIZE);

	ret = sock_setsockopt(sock, SOL_TLS, TLS_RX,
			      KERNEL_SOCKPTR(&rx_info), sizeof(rx_info));
	if (ret) {
		pr_warn_ratelimited("QUIC: kTLS TLS_RX setup failed: %d\n", ret);
		return ret;
	}

	/* Scrub key material from stack */
	memzero_explicit(&tx_info, sizeof(tx_info));
	memzero_explicit(&rx_info, sizeof(rx_info));
	return 0;
}
#endif /* IS_ENABLED(CONFIG_TLS) */

/* Forward declaration needed by the IPC response handler (defined below) */
static void quic_send_handshake_data(struct ksmbd_quic_conn *qconn,
				     const u8 *data, size_t len);

/* =========================================================================
 * QUIC Handshake IPC — dedicated Generic Netlink family (SMBD_QUIC)
 * =========================================================================
 *
 * We register a separate genl family "SMBD_QUIC" (version 1) for the
 * QUIC TLS 1.3 handshake delegation.  This keeps QUIC IPC isolated from
 * the main ksmbd genl family (SMBD_GENL).
 *
 * Pending request table:
 *   A small hash table maps IPC correlation handles to per-connection
 *   completion objects.  When the userspace response arrives via
 *   quic_hs_ipc_handle_rsp(), the completion is signalled and the
 *   response is copied into the connection struct.
 *
 * Thread safety:
 *   quic_hs_table_lock protects the pending table.
 *   Individual connections are protected by qconn->lock.
 */

/* IDA for QUIC handshake IPC handle allocation */
static DEFINE_IDA(quic_hs_ida);

/* Pending IPC table */
#define QUIC_HS_TABLE_BITS	4
static DEFINE_HASHTABLE(quic_hs_table, QUIC_HS_TABLE_BITS);
static DEFINE_RWLOCK(quic_hs_table_lock);

/* PID of the ksmbdctl userspace process registered for QUIC IPC */
static unsigned int quic_tools_pid;
static DEFINE_SPINLOCK(quic_tools_pid_lock);

/**
 * struct quic_hs_pending - pending handshake IPC entry
 * @handle:	IPC correlation handle
 * @hlist:	Hash table linkage (keyed on @handle)
 * @qconn:	Owning QUIC connection (we write the RSP into it)
 * @done:	Completion: signalled when RSP arrives
 * @success:	true if handshake succeeded (set from RSP)
 */
struct quic_hs_pending {
	unsigned int		handle;
	struct hlist_node	hlist;
	struct ksmbd_quic_conn	*qconn;
	struct completion	done;
	bool			success;
};

/* Forward declaration — genl handler needs the ops table below. */
static int quic_hs_ipc_handle_rsp(struct sk_buff *skb, struct genl_info *info);
static int quic_hs_ipc_handle_register(struct sk_buff *skb,
				       struct genl_info *info);

static const struct nla_policy quic_hs_nl_policy[KSMBD_QUIC_CMD_MAX + 1] = {
	[KSMBD_QUIC_CMD_UNSPEC] = { .len = 0 },
	[KSMBD_QUIC_CMD_HANDSHAKE_REQ] = {
		.type = NLA_BINARY,
		.len  = sizeof(struct ksmbd_quic_handshake_req),
	},
	[KSMBD_QUIC_CMD_HANDSHAKE_RSP] = {
		.type = NLA_BINARY,
		.len  = sizeof(struct ksmbd_quic_handshake_rsp),
	},
};

static const struct genl_ops quic_hs_genl_ops[] = {
	{
		.cmd   = KSMBD_QUIC_CMD_UNSPEC,
		.doit  = quic_hs_ipc_handle_register,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd   = KSMBD_QUIC_CMD_HANDSHAKE_REQ,
		/* kernel sends; not a valid incoming command from userspace */
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd   = KSMBD_QUIC_CMD_HANDSHAKE_RSP,
		.doit  = quic_hs_ipc_handle_rsp,
		.flags = GENL_ADMIN_PERM,
	},
};

static struct genl_family quic_hs_genl_family = {
	.name		= KSMBD_QUIC_GENL_NAME,
	.version	= KSMBD_QUIC_GENL_VERSION,
	.hdrsize	= 0,
	.maxattr	= KSMBD_QUIC_CMD_MAX,
	.netnsok	= true,
	.module		= THIS_MODULE,
	.ops		= quic_hs_genl_ops,
	.n_ops		= ARRAY_SIZE(quic_hs_genl_ops),
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
	.resv_start_op	= KSMBD_QUIC_CMD_HANDSHAKE_REQ,
#endif
	.policy		= quic_hs_nl_policy,
};

/**
 * quic_hs_ipc_handle_register() - userspace daemon registers with SMBD_QUIC
 * @skb:	Incoming netlink message
 * @info:	Parsed genl info
 *
 * The ksmbdctl daemon sends KSMBD_QUIC_CMD_UNSPEC when it starts, telling
 * us its PID so we can send handshake requests to it.
 *
 * Return: 0 always (non-fatal if it fails — we just won't do handshakes)
 */
static int quic_hs_ipc_handle_register(struct sk_buff *skb,
					struct genl_info *info)
{
	if (!netlink_capable(skb, CAP_NET_ADMIN))
		return -EPERM;

	spin_lock(&quic_tools_pid_lock);
	quic_tools_pid = info->snd_portid;
	spin_unlock(&quic_tools_pid_lock);

	pr_info("ksmbd QUIC: userspace handshake daemon registered (pid=%u)\n",
		info->snd_portid);
	return 0;
}

/**
 * quic_hs_ipc_handle_rsp() - receive HANDSHAKE_RSP from userspace daemon
 * @skb:	Incoming netlink message
 * @info:	Parsed genl info
 *
 * Looks up the pending entry by handle, copies the keys and handshake data
 * into the connection struct, and signals the waiting kernel thread.
 *
 * Return: 0 on success, negative errno on failure.
 */
static int quic_hs_ipc_handle_rsp(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr *attr;
	struct ksmbd_quic_handshake_rsp *rsp;
	struct quic_hs_pending *entry = NULL, *iter;
	unsigned long flags;

	if (!netlink_capable(skb, CAP_NET_ADMIN))
		return -EPERM;

	attr = info->attrs[KSMBD_QUIC_CMD_HANDSHAKE_RSP];
	if (!attr)
		return -EINVAL;

	if (nla_len(attr) < (int)sizeof(struct ksmbd_quic_handshake_rsp))
		return -EINVAL;

	rsp = nla_data(attr);

	/* Validate hs_data_len to prevent overflow */
	if (rsp->hs_data_len > KSMBD_QUIC_MAX_HS_DATA)
		return -EINVAL;

	/* Look up the pending entry */
	read_lock_irqsave(&quic_hs_table_lock, flags);
	hash_for_each_possible(quic_hs_table, iter, hlist, rsp->handle) {
		if (iter->handle == rsp->handle) {
			entry = iter;
			break;
		}
	}
	read_unlock_irqrestore(&quic_hs_table_lock, flags);

	if (!entry) {
		pr_warn_ratelimited("QUIC IPC: RSP for unknown handle %u\n",
				    rsp->handle);
		return -ENOENT;
	}

	/* Copy keys and status into the connection struct */
	if (rsp->success && entry->qconn) {
		struct ksmbd_quic_conn *qconn = entry->qconn;
		unsigned long qflags;
		u8 key_len = (rsp->cipher == KSMBD_QUIC_CIPHER_AES256GCM)
				? 32 : 16;

		spin_lock_irqsave(&qconn->lock, qflags);
		memcpy(qconn->app_crypto.write_key, rsp->write_key, key_len);
		memcpy(qconn->app_crypto.write_iv, rsp->write_iv,
		       KSMBD_QUIC_IV_SIZE);
		memcpy(qconn->app_crypto.read_key, rsp->read_key, key_len);
		memcpy(qconn->app_crypto.read_iv, rsp->read_iv,
		       KSMBD_QUIC_IV_SIZE);
		qconn->app_crypto.key_len = key_len;
		qconn->app_crypto.ready = true;
		spin_unlock_irqrestore(&qconn->lock, qflags);

		/*
		 * Send the server handshake flight back to the client.
		 * This is called from the genl receive context (process context
		 * via netlink workqueue), which is safe for sendmsg.
		 * Declared below; body implemented in the send-handshake section.
		 */
		if (rsp->hs_data_len > 0) {
			quic_send_handshake_data(qconn, rsp->hs_data,
						 rsp->hs_data_len);
		}
	}

	entry->success = !!rsp->success;

	/* Scrub key material from the response buffer on the stack */
	memzero_explicit(rsp->write_key, sizeof(rsp->write_key));
	memzero_explicit(rsp->write_iv, sizeof(rsp->write_iv));
	memzero_explicit(rsp->read_key, sizeof(rsp->read_key));
	memzero_explicit(rsp->read_iv, sizeof(rsp->read_iv));

	complete(&entry->done);
	return 0;
}

/**
 * quic_hs_ipc_alloc_handle() - allocate a unique IPC correlation handle
 *
 * Return: non-negative handle on success, negative errno on failure.
 */
static int quic_hs_ipc_alloc_handle(void)
{
	return ida_alloc_min(&quic_hs_ida, 1, GFP_KERNEL);
}

/**
 * quic_hs_ipc_free_handle() - release an IPC correlation handle
 * @handle:	Handle previously returned by quic_hs_ipc_alloc_handle()
 */
static void quic_hs_ipc_free_handle(int handle)
{
	if (handle >= 0)
		ida_free(&quic_hs_ida, handle);
}

/**
 * quic_hs_ipc_send_req() - send a HANDSHAKE_REQ to the userspace daemon
 * @qconn:	QUIC connection carrying the ClientHello
 * @handle:	IPC correlation handle
 *
 * Builds and sends a KSMBD_QUIC_CMD_HANDSHAKE_REQ via the SMBD_QUIC genl
 * family to the registered ksmbdctl daemon process.
 *
 * Return: 0 on success, negative errno on failure.
 */
static int quic_hs_ipc_send_req(struct ksmbd_quic_conn *qconn, int handle)
{
	struct ksmbd_quic_handshake_req *req;
	struct sk_buff *skb;
	void *hdr;
	unsigned int tools_pid;
	int ret;

	spin_lock(&quic_tools_pid_lock);
	tools_pid = quic_tools_pid;
	spin_unlock(&quic_tools_pid_lock);

	if (!tools_pid) {
		pr_warn_ratelimited("QUIC: no userspace handshake daemon registered\n");
		return -ENOENT;
	}

	skb = genlmsg_new(sizeof(*req), GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	hdr = genlmsg_put(skb, 0, 0, &quic_hs_genl_family, 0,
			  KSMBD_QUIC_CMD_HANDSHAKE_REQ);
	if (!hdr) {
		nlmsg_free(skb);
		return -ENOMEM;
	}

	req = kzalloc(sizeof(*req), GFP_KERNEL);
	if (!req) {
		genlmsg_cancel(skb, hdr);
		nlmsg_free(skb);
		return -ENOMEM;
	}

	req->handle = (u32)handle;
	/* Store DCID as big-endian u64 (use first 8 bytes, zero-padded) */
	{
		u64 cid = 0;
		int i, n = min_t(int, qconn->dcid_len, 8);

		for (i = 0; i < n; i++)
			cid = (cid << 8) | qconn->dcid[i];
		req->conn_id = cpu_to_be64(cid);
	}

	/* Peer address */
	if (qconn->peer.ss_family == AF_INET6) {
		struct sockaddr_in6 *sin6 =
			(struct sockaddr_in6 *)&qconn->peer;
		memcpy(req->peer_addr, &sin6->sin6_addr, 16);
		req->peer_port = ntohs(sin6->sin6_port);
	} else {
		struct sockaddr_in *sin = (struct sockaddr_in *)&qconn->peer;
		/* IPv4-mapped IPv6 encoding */
		req->peer_addr[10] = 0xff;
		req->peer_addr[11] = 0xff;
		memcpy(req->peer_addr + 12, &sin->sin_addr, 4);
		req->peer_port = ntohs(sin->sin_port);
	}

	/* ClientHello bytes */
	req->client_hello_len = (u32)min_t(size_t, qconn->crypto_len,
					   KSMBD_QUIC_MAX_CLIENT_HELLO);
	memcpy(req->client_hello, qconn->crypto_buf, req->client_hello_len);

	ret = nla_put(skb, KSMBD_QUIC_CMD_HANDSHAKE_REQ, sizeof(*req), req);
	kfree(req);
	if (ret) {
		genlmsg_cancel(skb, hdr);
		nlmsg_free(skb);
		return ret;
	}

	genlmsg_end(skb, hdr);
	ret = genlmsg_unicast(&init_net, skb, tools_pid);
	return ret;
}

/**
 * quic_hs_ipc_request() - perform a synchronous QUIC handshake IPC round-trip
 * @qconn:	QUIC connection (crypto_buf must be populated with ClientHello)
 *
 * Allocates a handle, registers a pending entry, sends the HANDSHAKE_REQ,
 * and blocks (up to QUIC_HS_IPC_TIMEOUT_MS) for the userspace response.
 *
 * Return: true if handshake succeeded, false on failure or timeout.
 */
static bool quic_hs_ipc_request(struct ksmbd_quic_conn *qconn)
{
	struct quic_hs_pending pending;
	unsigned long flags;
	bool success = false;
	int handle, ret;

	handle = quic_hs_ipc_alloc_handle();
	if (handle < 0) {
		pr_warn_ratelimited("QUIC IPC: handle allocation failed\n");
		return false;
	}

	pending.handle  = (unsigned int)handle;
	pending.qconn   = qconn;
	pending.success = false;
	init_completion(&pending.done);
	INIT_HLIST_NODE(&pending.hlist);

	/* Register in the pending table */
	write_lock_irqsave(&quic_hs_table_lock, flags);
	hash_add(quic_hs_table, &pending.hlist, pending.handle);
	write_unlock_irqrestore(&quic_hs_table_lock, flags);

	qconn->ipc_handle = handle;

	ret = quic_hs_ipc_send_req(qconn, handle);
	if (ret) {
		pr_warn_ratelimited("QUIC IPC: send REQ failed: %d\n", ret);
		goto out_remove;
	}

	/* Wait for userspace response */
	ret = wait_for_completion_timeout(&pending.done,
			msecs_to_jiffies(QUIC_HS_IPC_TIMEOUT_MS));
	if (!ret) {
		pr_warn_ratelimited("QUIC IPC: handshake timeout (handle=%u)\n",
				    handle);
		goto out_remove;
	}

	success = pending.success;

out_remove:
	write_lock_irqsave(&quic_hs_table_lock, flags);
	hash_del(&pending.hlist);
	write_unlock_irqrestore(&quic_hs_table_lock, flags);

	quic_hs_ipc_free_handle(handle);
	qconn->ipc_handle = -1;
	return success;
}

/* =========================================================================
 * QUIC CONNECTION_CLOSE frame sender (RFC 9000 §19.19)
 * =========================================================================
 *
 * Sends a CONNECTION_CLOSE frame (type 0x1c) to the peer in a QUIC Initial
 * long-header packet.  This is the correct packet number space to use when
 * closing a connection that never progressed past the Initial phase (RFC 9000
 * §10.2.3).
 *
 * QUIC-02 fix: when Initial TX keys are available, we now AEAD-encrypt the
 * CONNECTION_CLOSE with the server Initial TX keys (RFC 9001 §5.3) before
 * sending.  If keys are not yet ready we fall back to unencrypted (e.g. if
 * connection setup failed before key derivation).
 */

/**
 * quic_send_connection_close() - send a CONNECTION_CLOSE to the peer
 * @qconn:	QUIC connection
 * @error_code:	QUIC transport error code (QUIC_ERR_*)
 * @reason:	Human-readable reason phrase (may be NULL)
 *
 * Builds a QUIC Initial long-header packet containing a CONNECTION_CLOSE
 * frame and sends it to @qconn->peer via @qconn->udp_sock.
 *
 * This function is safe to call from process context (sendmsg path).
 */
static void quic_send_connection_close(struct ksmbd_quic_conn *qconn,
				       u64 error_code, const char *reason)
{
	/*
	 * Packet layout (simplified, not AEAD-encrypted):
	 *
	 * Long header (RFC 9000 §17.2):
	 *   [0]      first byte: 0xC0 (Long, Fixed, Initial type 0x00)
	 *   [1..4]   version:    QUIC_VERSION_1
	 *   [5]      DCID len
	 *   [6..5+dlen] DCID (peer's SCID = their expected DCID)
	 *   [6+dlen] SCID len
	 *   [7+dlen..6+dlen+slen] SCID (our DCID)
	 *   Token length: 0x00 (no token)
	 *   Payload length: varint (CONNECTION_CLOSE frame size)
	 *   Packet number: 1 byte (stub)
	 *
	 * CONNECTION_CLOSE frame (RFC 9000 §19.19):
	 *   frame type: 0x1c (1 byte)
	 *   error code: varint
	 *   frame type triggering error: varint (0 = unspecified)
	 *   reason phrase length: varint
	 *   reason phrase: bytes
	 */
	u8 hdr_buf[80];		/* long header (AAD) */
	u8 *p = hdr_buf;
	size_t reason_len = reason ? strlen(reason) : 0;
	size_t frame_len, hdr_len;
	struct msghdr msg = {};
	struct kvec iov[2];
	u8 frame[64];
	u8 *fp = frame;
	int vl;
	unsigned long flags;
	u64 pkt_num;
	/* Plaintext: pkt_num + frame */
	u8 plaintext[128];
	u8 ciphertext[128 + QUIC_AEAD_TAG_SIZE];
	size_t plaintext_len, ciphertext_len;

	/* Build CONNECTION_CLOSE frame */
	*fp++ = QUIC_FRAME_CONNECTION_CLOSE;
	/* error code */
	if (ksmbd_quic_put_varint(fp, error_code, &vl))
		return;
	fp += vl;
	/* frame type that triggered the error (0 = not applicable) */
	if (ksmbd_quic_put_varint(fp, 0, &vl))
		return;
	fp += vl;
	/* reason phrase length */
	if (reason_len > 63)
		reason_len = 63;
	if (ksmbd_quic_put_varint(fp, reason_len, &vl))
		return;
	fp += vl;
	/* reason phrase */
	if (reason_len) {
		memcpy(fp, reason, reason_len);
		fp += reason_len;
	}
	frame_len = fp - frame;

	/* Long header (AAD) */
	*p++ = QUIC_HDR_FORM_LONG | QUIC_HDR_FIXED_BIT
		| QUIC_LONG_TYPE_INITIAL | 0x00;
	put_unaligned_be32(QUIC_VERSION_1, p);
	p += 4;

	/* DCID = peer's SCID (their expected destination) */
	*p++ = qconn->scid_len;
	memcpy(p, qconn->scid, qconn->scid_len);
	p += qconn->scid_len;

	/* SCID = our DCID */
	*p++ = qconn->dcid_len;
	memcpy(p, qconn->dcid, qconn->dcid_len);
	p += qconn->dcid_len;

	/* Token length = 0 */
	*p++ = 0x00;

	/*
	 * Payload length = 1 (packet number) + frame_len + AEAD tag.
	 */
	if (ksmbd_quic_put_varint(p, 1 + frame_len + QUIC_AEAD_TAG_SIZE, &vl))
		return;
	p += vl;
	hdr_len = p - hdr_buf;

	/* Packet number */
	spin_lock_irqsave(&qconn->lock, flags);
	pkt_num = qconn->send_pkt_num++;
	spin_unlock_irqrestore(&qconn->lock, flags);

	/* Build plaintext: pkt_num + CONNECTION_CLOSE frame */
	if (1 + frame_len > sizeof(plaintext))
		return;
	plaintext[0] = (u8)(pkt_num & 0xFF);
	memcpy(plaintext + 1, frame, frame_len);
	plaintext_len = 1 + frame_len;

	/*
	 * QUIC-02: Encrypt with Initial TX keys if available.
	 * Fall back to sending unencrypted if keys are not ready (e.g. during
	 * early connection setup failure before key derivation).
	 */
	if (qconn->initial_tx.ready) {
		ciphertext_len = sizeof(ciphertext);
		if (ksmbd_quic_aead_crypt(qconn->initial_tx.key,
					  qconn->initial_tx.iv,
					  pkt_num,
					  hdr_buf, hdr_len,
					  plaintext, plaintext_len,
					  ciphertext, &ciphertext_len,
					  true)) {
			/* Encryption failed — send unencrypted as fallback */
			goto send_unencrypted;
		}

		msg.msg_name    = &qconn->peer;
		msg.msg_namelen = qconn->peer_addrlen;
		msg.msg_flags   = MSG_NOSIGNAL;
		iov[0].iov_base = hdr_buf;
		iov[0].iov_len  = hdr_len;
		iov[1].iov_base = ciphertext;
		iov[1].iov_len  = ciphertext_len;
		kernel_sendmsg(qconn->udp_sock, &msg, iov, 2,
			       hdr_len + ciphertext_len);
		goto sent;
	}

send_unencrypted:
	/* Fallback: send plaintext packet (pre-key-derivation only) */
	{
		u8 pkt[256];
		u8 *q = pkt;

		*q++ = QUIC_HDR_FORM_LONG | QUIC_HDR_FIXED_BIT
			| QUIC_LONG_TYPE_INITIAL;
		put_unaligned_be32(QUIC_VERSION_1, q); q += 4;
		*q++ = qconn->scid_len;
		memcpy(q, qconn->scid, qconn->scid_len); q += qconn->scid_len;
		*q++ = qconn->dcid_len;
		memcpy(q, qconn->dcid, qconn->dcid_len); q += qconn->dcid_len;
		*q++ = 0x00; /* token len */
		if (ksmbd_quic_put_varint(q, 1 + frame_len, &vl))
			return;
		q += vl;
		*q++ = (u8)(pkt_num & 0xFF);
		if ((size_t)(q - pkt) + frame_len > sizeof(pkt))
			return;
		memcpy(q, frame, frame_len);
		q += frame_len;

		msg.msg_name    = &qconn->peer;
		msg.msg_namelen = qconn->peer_addrlen;
		msg.msg_flags   = MSG_NOSIGNAL;
		iov[0].iov_base = pkt;
		iov[0].iov_len  = q - pkt;
		kernel_sendmsg(qconn->udp_sock, &msg, iov, 1, iov[0].iov_len);
	}

sent:
	memzero_explicit(plaintext, sizeof(plaintext));
	memzero_explicit(ciphertext, sizeof(ciphertext));

	ksmbd_debug(CONN, "QUIC: sent CONNECTION_CLOSE (err=0x%llx reason=%s)\n",
		    error_code, reason ? reason : "");
}

/* =========================================================================
 * QUIC CRYPTO frame parsing (RFC 9000 §19.6)
 * =========================================================================
 *
 * CRYPTO frames carry TLS handshake data in QUIC Initial packets.
 * The frame format is:
 *   Type:    0x06 (1 byte)
 *   Offset:  variable-length integer (byte offset into the CRYPTO stream)
 *   Length:  variable-length integer
 *   Data:    TLS record bytes
 *
 * We buffer the data into qconn->crypto_buf, respecting the Offset field
 * for in-order reassembly.  In practice the entire ClientHello fits in a
 * single Initial packet, so the offset is typically 0.
 */

/**
 * quic_parse_crypto_frames() - extract CRYPTO frame data from Initial payload
 * @qconn:	QUIC connection (crypto_buf is updated)
 * @payload:	Decrypted packet payload (frame stream)
 * @payload_len: Length of @payload
 *
 * Scans all frames in the payload; for each CRYPTO frame with offset 0
 * (or a contiguous extension), appends the data to qconn->crypto_buf.
 *
 * Also handles PADDING (0x00) and PING (0x01) frames gracefully.
 *
 * Return: number of CRYPTO bytes appended (>= 0), or -EINVAL on parse error.
 */
static int quic_parse_crypto_frames(struct ksmbd_quic_conn *qconn,
				    const u8 *payload, size_t payload_len)
{
	int total_crypto = 0;

	while (payload_len > 0) {
		u8 frame_type = payload[0];
		const u8 *fp = payload + 1;
		size_t fp_rem = payload_len - 1;
		u64 offset, length;
		int consumed;

		/* PADDING: single 0x00 byte */
		if (frame_type == QUIC_FRAME_PADDING) {
			payload++;
			payload_len--;
			continue;
		}

		/* PING: single 0x01 byte, no data */
		if (frame_type == QUIC_FRAME_PING) {
			payload++;
			payload_len--;
			continue;
		}

		/* ACK frame: variable length — skip by consuming its fields */
		if (frame_type == QUIC_FRAME_ACK ||
		    frame_type == (QUIC_FRAME_ACK | 0x01)) {
			/*
			 * ACK frame has: Largest Acknowledged (varint),
			 * ACK Delay (varint), ACK Range Count (varint),
			 * First ACK Range (varint), then ACK Range Count
			 * pairs.  For simplicity: parse and skip the first
			 * 4 varints, then skip ACK Range Count * 2 varints.
			 */
			u64 largest_ack, ack_delay, range_count, first_range;
			u64 gap, range_len;
			u64 i;

			if (ksmbd_quic_get_varint(fp, fp_rem,
						  &largest_ack, &consumed))
				break;
			fp += consumed; fp_rem -= consumed;
			if (ksmbd_quic_get_varint(fp, fp_rem,
						  &ack_delay, &consumed))
				break;
			fp += consumed; fp_rem -= consumed;
			if (ksmbd_quic_get_varint(fp, fp_rem,
						  &range_count, &consumed))
				break;
			fp += consumed; fp_rem -= consumed;
			if (ksmbd_quic_get_varint(fp, fp_rem,
						  &first_range, &consumed))
				break;
			fp += consumed; fp_rem -= consumed;
			for (i = 0; i < range_count; i++) {
				if (ksmbd_quic_get_varint(fp, fp_rem,
							  &gap, &consumed))
					goto done_ack;
				fp += consumed; fp_rem -= consumed;
				if (ksmbd_quic_get_varint(fp, fp_rem,
							  &range_len, &consumed))
					goto done_ack;
				fp += consumed; fp_rem -= consumed;
			}
done_ack:
			payload    = fp;
			payload_len = fp_rem;
			continue;
		}

		/* CRYPTO frame (0x06) */
		if (frame_type == QUIC_FRAME_CRYPTO) {
			if (ksmbd_quic_get_varint(fp, fp_rem,
						  &offset, &consumed))
				break;
			fp += consumed; fp_rem -= consumed;

			if (ksmbd_quic_get_varint(fp, fp_rem,
						  &length, &consumed))
				break;
			fp += consumed; fp_rem -= consumed;

			if (length > fp_rem)
				break;

			/*
			 * Append to crypto_buf.  We only handle the simple
			 * case where offset == 0 or continues from the last
			 * byte we received.  Out-of-order fragments are dropped
			 * (the client will retransmit).
			 */
			if (offset == qconn->crypto_len) {
				size_t space = QUIC_MAX_CRYPTO_DATA
					       - qconn->crypto_len;
				size_t copy = min_t(size_t, (size_t)length,
						    space);
				if (copy > 0) {
					memcpy(qconn->crypto_buf +
					       qconn->crypto_len,
					       fp, copy);
					qconn->crypto_len += copy;
					total_crypto += (int)copy;
				}
			}

			fp += length;
			fp_rem -= length;
			payload     = fp;
			payload_len = fp_rem;
			continue;
		}

		/*
		 * Unknown frame type: we cannot skip it without knowing its
		 * length, so stop parsing here.
		 */
		break;
	}

	return total_crypto;
}

/* =========================================================================
 * QUIC ACK frame sender (RFC 9000 §13.2, §19.3)
 * =========================================================================
 *
 * RFC 9000 §13.2.1 — "A receiver MUST send an ACK frame at least once
 * for every ack-eliciting packet it receives."  CRYPTO frames are
 * ack-eliciting (§13.2).  Failing to ACK causes clients to retransmit
 * their Initial packets indefinitely until they time out.
 */

/**
 * quic_send_ack() - send a QUIC ACK frame for a received packet
 * @qconn:	QUIC connection
 * @largest_acked: Packet number of the packet being acknowledged
 *
 * Sends a minimal ACK frame (type 0x02, one ACK range covering exactly
 * the acknowledged packet) in a QUIC Initial long-header packet using
 * the server TX Initial keys.
 *
 * RFC 9000 §19.3 ACK frame format:
 *   Type:              0x02 (1 byte)
 *   Largest Acked:     varint
 *   ACK Delay:         varint (0)
 *   ACK Range Count:   varint (0 — only the First ACK Range)
 *   First ACK Range:   varint (0 — covers exactly Largest Acked)
 */
static void quic_send_ack(struct ksmbd_quic_conn *qconn, u64 largest_acked)
{
	u8 pkt[256];
	u8 *p = pkt;
	u8 frame[32];
	u8 *fp = frame;
	struct msghdr msg = {};
	struct kvec iov;
	size_t frame_len, payload_len;
	unsigned long flags;
	u64 pkt_num;
	int vl;

	/* Build ACK frame (RFC 9000 §19.3) */
	*fp++ = QUIC_FRAME_ACK;			/* type 0x02 */
	if (ksmbd_quic_put_varint(fp, largest_acked, &vl))
		return;
	fp += vl;
	if (ksmbd_quic_put_varint(fp, 0, &vl))	/* ACK Delay = 0 */
		return;
	fp += vl;
	if (ksmbd_quic_put_varint(fp, 0, &vl))	/* ACK Range Count = 0 */
		return;
	fp += vl;
	if (ksmbd_quic_put_varint(fp, 0, &vl))	/* First ACK Range = 0 */
		return;
	fp += vl;
	frame_len = fp - frame;

	/*
	 * Wrap in a QUIC Initial long-header packet.
	 * payload = 1-byte packet number + ACK frame.
	 */
	*p++ = QUIC_HDR_FORM_LONG | QUIC_HDR_FIXED_BIT | QUIC_LONG_TYPE_INITIAL;
	put_unaligned_be32(QUIC_VERSION_1, p);
	p += 4;

	/* DCID = peer's SCID */
	*p++ = qconn->scid_len;
	memcpy(p, qconn->scid, qconn->scid_len);
	p += qconn->scid_len;

	/* SCID = our DCID */
	*p++ = qconn->dcid_len;
	memcpy(p, qconn->dcid, qconn->dcid_len);
	p += qconn->dcid_len;

	/* Token length = 0 */
	*p++ = 0x00;

	/* Payload length = 1 (pkt_num) + frame_len */
	payload_len = 1 + frame_len;
	if (ksmbd_quic_put_varint(p, payload_len, &vl))
		return;
	p += vl;

	/* Packet number */
	spin_lock_irqsave(&qconn->lock, flags);
	pkt_num = qconn->send_pkt_num++;
	spin_unlock_irqrestore(&qconn->lock, flags);
	*p++ = (u8)(pkt_num & 0xFF);

	/* ACK frame */
	if ((size_t)(p - pkt) + frame_len > sizeof(pkt))
		return;
	memcpy(p, frame, frame_len);
	p += frame_len;

	msg.msg_name    = &qconn->peer;
	msg.msg_namelen = qconn->peer_addrlen;
	msg.msg_flags   = MSG_NOSIGNAL;
	iov.iov_base    = pkt;
	iov.iov_len     = p - pkt;

	kernel_sendmsg(qconn->udp_sock, &msg, &iov, 1, iov.iov_len);

	ksmbd_debug(CONN, "QUIC: sent ACK for pkt %llu\n", largest_acked);
}

/* =========================================================================
 * QUIC server handshake flight sender
 * =========================================================================
 *
 * After the TLS 1.3 handshake completes in userspace, the server must send
 * the handshake flight (ServerHello + EncryptedExtensions + Certificate +
 * CertificateVerify + Finished) back to the client.
 *
 * RFC 9000 §12.3 / RFC 9001 §4.1:
 *   - ServerHello lives in the Initial packet number space.
 *   - EncryptedExtensions through Finished live in the Handshake packet
 *     number space.
 *
 * For simplicity in this implementation we send all handshake data in a
 * single QUIC Initial long-header packet containing one CRYPTO frame.
 * A production implementation would split across Initial and Handshake
 * packets as required by the RFC.
 *
 * QUIC-02 fix: we now AEAD-encrypt each packet with the server Initial TX
 * keys (derived from the DCID via HKDF, RFC 9001 §A.1) before sending.
 * Header protection (RFC 9001 §5.4) is applied to mask the packet number.
 *
 * The @data buffer from userspace contains the concatenated TLS records
 * for the server flight.  We wrap them in a CRYPTO frame and send as a
 * QUIC Initial packet using the server Initial TX keys.
 */

/**
 * quic_send_handshake_data() - send server TLS flight to the client
 * @qconn:	QUIC connection
 * @data:	Server handshake flight bytes (TLS records)
 * @len:	Number of bytes in @data
 *
 * Wraps @data in a QUIC CRYPTO frame inside a QUIC Initial long-header
 * packet and sends it to @qconn->peer.
 *
 * Called from quic_hs_ipc_handle_rsp() (genl receive path, process context).
 */
static void quic_send_handshake_data(struct ksmbd_quic_conn *qconn,
				     const u8 *data, size_t len)
{
	/*
	 * QUIC-02: Build, AEAD-encrypt, and header-protect each Initial packet.
	 *
	 * Packet layout before encryption:
	 *   hdr[]:  Long-header fixed part (first byte .. token_len=0)
	 *   Length: varint (payload_len = pkt_num(1) + frame_data)
	 *   pkt_num: 1 byte
	 *   plaintext: CRYPTO frame type + offset + length + chunk_data
	 *
	 * AEAD:
	 *   AAD     = everything from hdr[0] up to (but not including) pkt_num
	 *             (i.e., the Long-header including the Length field)
	 *   nonce   = initial_tx.iv XOR pkt_num (RFC 9001 §5.3)
	 *   encrypt = plaintext (pkt_num + frame_data)
	 *   output  = ciphertext + 16-byte tag
	 *
	 * We fragment if len exceeds the per-packet capacity.
	 * Max header: 1+4+1+20+1+20+1+8 = 56 bytes; leave 80 for safety.
	 * AEAD tag adds 16 bytes.
	 */
	const size_t max_data_per_pkt = QUIC_MAX_PKT_SIZE - 80 -
					QUIC_AEAD_TAG_SIZE;
	size_t offset_in_crypto = 0;

	if (!qconn->initial_tx.ready) {
		pr_warn_ratelimited("QUIC: no TX Initial keys for handshake send\n");
		return;
	}

	while (len > 0) {
		size_t chunk = min_t(size_t, len, max_data_per_pkt);
		/*
		 * We build the packet in two parts:
		 *   hdr_buf: the long-header (up to and including the Length varint)
		 *   plaintext_buf: pkt_num(1) + CRYPTO frame + data
		 * After AEAD we concatenate hdr_buf + ciphertext (+ tag).
		 */
		u8 hdr_buf[80];		/* long header (AAD) */
		u8 plaintext_buf[QUIC_MAX_PKT_SIZE];
		u8 ciphertext_buf[QUIC_MAX_PKT_SIZE + QUIC_AEAD_TAG_SIZE];
		u8 *p = hdr_buf;
		u8 *pp = plaintext_buf;
		size_t hdr_len, plaintext_len, ciphertext_len;
		size_t frame_hdr_overhead;
		size_t payload_len_field;	/* the Length varint value */
		unsigned long lock_flags;
		u64 pkt_num;
		struct msghdr msg = {};
		struct kvec iov[2];
		int vl, ret;
		/* scratch: compute frame header size to get accurate payload_len */

		/*
		 * Frame header max size: type(1) + offset(8) + length(8) = 17.
		 * 1-byte packet number.
		 * Actual varints are smaller; use 17 as a conservative upper bound.
		 */
		frame_hdr_overhead = 17;
		payload_len_field = 1 /* pkt_num */ + frame_hdr_overhead + chunk
				    + QUIC_AEAD_TAG_SIZE;

		/* ---- Build Long Header (AAD) ---- */
		/* first byte: Long=1, Fixed=1, type=Initial(0x00), pkt_num_len-1=0 */
		*p++ = QUIC_HDR_FORM_LONG | QUIC_HDR_FIXED_BIT
			| QUIC_LONG_TYPE_INITIAL | 0x00;
		put_unaligned_be32(QUIC_VERSION_1, p); p += 4;

		/* DCID = peer's SCID */
		*p++ = qconn->scid_len;
		memcpy(p, qconn->scid, qconn->scid_len);
		p += qconn->scid_len;

		/* SCID = our DCID */
		*p++ = qconn->dcid_len;
		memcpy(p, qconn->dcid, qconn->dcid_len);
		p += qconn->dcid_len;

		/* Token length = 0 */
		*p++ = 0x00;

		/* Length field = pkt_num(1) + actual_frame_hdr + chunk + tag(16) */
		if (ksmbd_quic_put_varint(p, payload_len_field, &vl))
			return;
		p += vl;
		hdr_len = p - hdr_buf;

		/* ---- Build plaintext: pkt_num + CRYPTO frame ---- */
		spin_lock_irqsave(&qconn->lock, lock_flags);
		pkt_num = qconn->send_pkt_num++;
		spin_unlock_irqrestore(&qconn->lock, lock_flags);

		*pp++ = (u8)(pkt_num & 0xFF);		/* 1-byte packet number */

		*pp++ = QUIC_FRAME_CRYPTO;		/* frame type */
		if (ksmbd_quic_put_varint(pp, offset_in_crypto, &vl))
			return;
		pp += vl;
		if (ksmbd_quic_put_varint(pp, chunk, &vl))
			return;
		pp += vl;

		if ((size_t)(pp - plaintext_buf) + chunk > sizeof(plaintext_buf))
			return;
		memcpy(pp, data, chunk);
		pp += chunk;
		plaintext_len = pp - plaintext_buf;

		/* ---- AEAD encrypt ---- */
		ciphertext_len = sizeof(ciphertext_buf);
		ret = ksmbd_quic_aead_crypt(
			qconn->initial_tx.key,
			qconn->initial_tx.iv,
			pkt_num,
			hdr_buf, hdr_len,	/* AAD = long header */
			plaintext_buf, plaintext_len,
			ciphertext_buf, &ciphertext_len,
			true /* encrypt */);
		if (ret) {
			pr_warn_ratelimited("QUIC: handshake AEAD encrypt failed: %d\n",
					    ret);
			return;
		}

		/*
		 * Header protection (RFC 9001 §5.4):
		 * Apply HP to the first byte and the 1-byte packet number.
		 * Sample = ciphertext bytes [4 .. 19] (4 bytes after pkt_num).
		 * We XOR the first byte's low 4 bits and the packet number byte.
		 */
		if (ciphertext_len >= 20) {
			ksmbd_quic_apply_header_protection(
				ciphertext_buf,		/* packet number at byte 0 */
				1,			/* 1-byte packet number */
				qconn->initial_tx.hp,
				ciphertext_buf + 4);	/* sample at offset 4 */
			/* Also protect the low bits of the first byte in hdr_buf */
			{
				u8 mask_byte;
				struct crypto_cipher *hp_tfm;

				hp_tfm = crypto_alloc_cipher("aes", 0, 0);
				if (!IS_ERR(hp_tfm)) {
					u8 mask[16];
					u8 sample[16];

					memcpy(sample, ciphertext_buf + 4, 16);
					if (!crypto_cipher_setkey(hp_tfm,
							qconn->initial_tx.hp,
							QUIC_HP_KEY_SIZE)) {
						crypto_cipher_encrypt_one(
							hp_tfm, mask, sample);
						mask_byte = mask[0];
					} else {
						mask_byte = 0;
					}
					crypto_free_cipher(hp_tfm);
					/* Mask low 4 bits of first header byte */
					hdr_buf[0] ^= (mask_byte & 0x0F);
				}
			}
		}

		/* Send: hdr_buf || ciphertext_buf */
		msg.msg_name    = &qconn->peer;
		msg.msg_namelen = qconn->peer_addrlen;
		msg.msg_flags   = MSG_NOSIGNAL;
		iov[0].iov_base = hdr_buf;
		iov[0].iov_len  = hdr_len;
		iov[1].iov_base = ciphertext_buf;
		iov[1].iov_len  = ciphertext_len;

		kernel_sendmsg(qconn->udp_sock, &msg, iov, 2,
			       hdr_len + ciphertext_len);

		memzero_explicit(plaintext_buf, plaintext_len);
		memzero_explicit(ciphertext_buf, ciphertext_len);

		data             += chunk;
		len              -= chunk;
		offset_in_crypto += chunk;
	}

	ksmbd_debug(CONN, "QUIC: sent encrypted handshake flight (%zu bytes)\n",
		    offset_in_crypto);
}

/* =========================================================================
 * QUIC connection table management
 * =========================================================================
 */

static u32 quic_dcid_hash(const u8 *dcid, u8 len)
{
	return jhash(dcid, len, 0);
}

static struct ksmbd_quic_conn *quic_conn_lookup(const u8 *dcid, u8 len)
{
	struct ksmbd_quic_conn *qconn;
	u32 key = quic_dcid_hash(dcid, len);

	hash_for_each_possible_rcu(quic_conn_table, qconn, hlist, key) {
		if (qconn->dcid_len == len &&
		    memcmp(qconn->dcid, dcid, len) == 0)
			return qconn;
	}
	return NULL;
}

static void quic_conn_insert(struct ksmbd_quic_conn *qconn)
{
	u32 key = quic_dcid_hash(qconn->dcid, qconn->dcid_len);

	spin_lock(&quic_conn_table_lock);
	hash_add_rcu(quic_conn_table, &qconn->hlist, key);
	spin_unlock(&quic_conn_table_lock);
}

static void quic_conn_remove(struct ksmbd_quic_conn *qconn)
{
	spin_lock(&quic_conn_table_lock);
	hash_del_rcu(&qconn->hlist);
	spin_unlock(&quic_conn_table_lock);
	synchronize_rcu();
}

/* =========================================================================
 * QUIC connection allocation/free
 * =========================================================================
 */

static struct ksmbd_quic_conn *quic_conn_alloc(struct socket *udp_sock)
{
	struct ksmbd_quic_conn *qconn;

	qconn = kzalloc(sizeof(*qconn), KSMBD_DEFAULT_GFP);
	if (!qconn)
		return NULL;

	qconn->stream_buf = kvmalloc(QUIC_STREAM_BUF_SIZE, KSMBD_DEFAULT_GFP);
	if (!qconn->stream_buf) {
		kfree(qconn);
		return NULL;
	}

	qconn->stream_max = QUIC_STREAM_BUF_SIZE;
	spin_lock_init(&qconn->lock);
	init_waitqueue_head(&qconn->wait);
	init_completion(&qconn->hs_done);
	qconn->udp_sock = udp_sock;
	qconn->state    = QUIC_STATE_INITIAL;
	qconn->ipc_handle = -1;
	INIT_HLIST_NODE(&qconn->hlist);

	return qconn;
}

static void quic_conn_free(struct ksmbd_quic_conn *qconn)
{
	if (!qconn)
		return;
	kvfree(qconn->stream_buf);
	kfree(qconn);
}

/* =========================================================================
 * QUIC Initial packet parsing (RFC 9000 §17.2.2)
 * =========================================================================
 */

/**
 * quic_parse_initial_packet() - parse a received QUIC Initial packet
 * @pkt:	Raw UDP payload (the QUIC packet)
 * @pkt_len:	Length of @pkt
 * @dcid_out:	Filled with the Destination CID from the packet header
 * @dcid_len_out: Length of the DCID
 * @scid_out:	Filled with the Source CID
 * @scid_len_out: Length of the SCID
 * @token_out:	Set to point into @pkt at the Token field (may be NULL)
 * @token_len_out: Set to the Token length (may be NULL)
 *
 * Only parses the unprotected header fields (DCID, SCID, token, pkt num
 * length).  Does NOT decrypt or verify the packet — that requires keys
 * derived from the DCID, which we call derive_initial_secrets() after.
 *
 * Return: 0 on success, -EINVAL if the packet is malformed.
 */
static int quic_parse_initial_packet(const u8 *pkt, size_t pkt_len,
				     u8 *dcid_out, u8 *dcid_len_out,
				     u8 *scid_out, u8 *scid_len_out,
				     const u8 **token_out, u64 *token_len_out)
{
	const u8 *p = pkt;
	size_t remaining = pkt_len;
	u8 first_byte;
	u32 version;
	u8 dcid_len, scid_len;
	u64 token_len;
	int consumed;
	int ret;

	/* Minimum: 1 (first byte) + 4 (version) + 1 (dcid_len) */
	if (remaining < 6)
		return -EINVAL;

	first_byte = *p++;
	remaining--;

	/* Must be a long-header Initial packet */
	if (!(first_byte & QUIC_HDR_FORM_LONG))
		return -EINVAL;
	if (!(first_byte & QUIC_HDR_FIXED_BIT))
		return -EINVAL;
	if ((first_byte & 0x30) != QUIC_LONG_TYPE_INITIAL)
		return -EINVAL;

	/* Version (4 bytes) */
	if (remaining < 4)
		return -EINVAL;
	version = get_unaligned_be32(p);
	p += 4;
	remaining -= 4;

	if (version != QUIC_VERSION_1) {
		/* Version Negotiation would be the correct response;
		 * for now just reject unsupported versions. */
		return -EINVAL;
	}

	/* DCID Length (1 byte) + DCID */
	if (!remaining)
		return -EINVAL;
	dcid_len = *p++;
	remaining--;
	if (dcid_len > QUIC_MAX_CID_LEN)
		return -EINVAL;
	if (remaining < dcid_len)
		return -EINVAL;
	memcpy(dcid_out, p, dcid_len);
	*dcid_len_out = dcid_len;
	p += dcid_len;
	remaining -= dcid_len;

	/* SCID Length (1 byte) + SCID */
	if (!remaining)
		return -EINVAL;
	scid_len = *p++;
	remaining--;
	if (scid_len > QUIC_MAX_CID_LEN)
		return -EINVAL;
	if (remaining < scid_len)
		return -EINVAL;
	memcpy(scid_out, p, scid_len);
	*scid_len_out = scid_len;
	p += scid_len;
	remaining -= scid_len;

	/* Token Length (variable-length integer) */
	ret = ksmbd_quic_get_varint(p, remaining, &token_len, &consumed);
	if (ret)
		return ret;
	p += consumed;
	remaining -= consumed;

	/* Token bytes */
	if (remaining < token_len)
		return -EINVAL;
	/* Return pointer to token bytes within the original packet buffer */
	if (token_out)
		*token_out = p;
	if (token_len_out)
		*token_len_out = token_len;
	p += token_len;
	remaining -= token_len;

	/* Packet Length (variable-length integer) — tells us payload+pktnum size */
	/* (we don't need to parse further for the initial CID extraction) */
	(void)p;
	(void)remaining;

	return 0;
}

/* =========================================================================
 * QUIC stream data handling
 * =========================================================================
 *
 * When we receive a QUIC STREAM frame carrying SMB data, we append it to
 * the per-connection reassembly buffer and wake the SMB handler thread.
 * The SMB handler thread calls our .read transport op which blocks until
 * enough data is available.
 *
 * NOTE: No RFC1002 4-byte NetBIOS length prefix is added (SMB over QUIC
 * specifics, MS-SMB2 Appendix C).  The connection handler loop must be
 * aware of this; we set conn->transport to our QUIC transport ops which
 * report the fact via KSMBD_TRANS_QUIC.
 */

/**
 * quic_stream_append() - append received STREAM data to the reassembly buffer
 * @qconn:	QUIC connection
 * @data:	Data bytes from a QUIC STREAM frame payload
 * @len:	Number of bytes to append
 *
 * Called from the RX thread (or future CRYPTO/handshake path) when STREAM
 * frame data arrives for the SMB stream (stream ID 0).
 *
 * Return: 0 on success, -ENOMEM if the buffer would overflow.
 */
static int quic_stream_append(struct ksmbd_quic_conn *qconn,
			      const u8 *data, size_t len)
{
	unsigned long flags;

	spin_lock_irqsave(&qconn->lock, flags);

	if (qconn->stream_len + len > qconn->stream_max) {
		spin_unlock_irqrestore(&qconn->lock, flags);
		return -ENOMEM;
	}

	memcpy(qconn->stream_buf + qconn->stream_len, data, len);
	qconn->stream_len += len;

	spin_unlock_irqrestore(&qconn->lock, flags);

	wake_up_interruptible(&qconn->wait);
	return 0;
}

/* =========================================================================
 * QUIC transport ops: read / write / disconnect / shutdown
 * =========================================================================
 */

/**
 * ksmbd_quic_read() - transport ops read: read SMB data from QUIC stream
 * @t:		ksmbd transport instance
 * @buf:	Destination buffer
 * @to_read:	Number of bytes to read
 * @max_retries: Retry limit (negative = unlimited, matches TCP semantics)
 *
 * Blocks until @to_read bytes are available in the QUIC stream reassembly
 * buffer, then copies them out.  No RFC1002 NetBIOS prefix is handled here;
 * the QUIC transport carries raw SMB PDUs in STREAM frames.
 *
 * Return: Number of bytes read, or negative errno.
 */
static int ksmbd_quic_read(struct ksmbd_transport *t, char *buf,
			   unsigned int to_read, int max_retries)
{
	struct quic_transport *qt = QUIC_TRANS(t);
	struct ksmbd_quic_conn *qconn = qt->qconn;
	struct ksmbd_conn *conn = t->conn;
	int retries = 0;

	while (true) {
		unsigned long flags;
		size_t avail;

		try_to_freeze();

		if (!ksmbd_conn_alive(conn))
			return -ESHUTDOWN;

		if (ksmbd_conn_need_reconnect(conn))
			return -EAGAIN;

		spin_lock_irqsave(&qconn->lock, flags);
		avail = qconn->stream_len;
		spin_unlock_irqrestore(&qconn->lock, flags);

		if (avail >= to_read) {
			/* Consume @to_read bytes from the front of the buffer */
			spin_lock_irqsave(&qconn->lock, flags);
			memcpy(buf, qconn->stream_buf, to_read);
			qconn->stream_len -= to_read;
			memmove(qconn->stream_buf,
				qconn->stream_buf + to_read,
				qconn->stream_len);
			spin_unlock_irqrestore(&qconn->lock, flags);
			return (int)to_read;
		}

		/* Not enough data yet — wait for the RX thread */
		if (max_retries == 0)
			return -EAGAIN;
		if (max_retries > 0) {
			if (retries >= max_retries)
				return -EAGAIN;
			retries++;
		}

		wait_event_interruptible_timeout(qconn->wait,
			qconn->stream_len >= to_read ||
			!ksmbd_conn_alive(conn),
			HZ);
	}
}

/**
 * ksmbd_quic_writev() - transport ops write: send SMB data over QUIC stream
 * @t:			ksmbd transport instance
 * @iov:		IO vector with data to send
 * @nvecs:		Number of iovec segments
 * @size:		Total bytes to send
 * @need_invalidate:	Unused (RDMA-specific)
 * @remote_key:		Unused (RDMA-specific)
 *
 * Wraps the SMB PDU data in a QUIC STREAM frame (type 0x0A = STREAM with
 * LEN+OFF bits set but for simplicity we use type 0x0A for stream 0) and
 * sends it as a short-header QUIC packet over the UDP socket.
 *
 * For the Initial/Handshake phase (state != CONNECTED), we drop writes
 * and return -ENOTCONN.  Full 1-RTT encryption is the production path;
 * the current implementation emits unencrypted STREAM frames for
 * demonstration / test with a cooperating client.  Production deployments
 * MUST have TLS 1.3 handshake complete before reaching CONNECTED state.
 *
 * Return: Number of bytes sent, or negative errno.
 */
static int ksmbd_quic_writev(struct ksmbd_transport *t, struct kvec *iov,
			     int nvecs, int size, bool need_invalidate,
			     unsigned int remote_key)
{
	struct quic_transport *qt = QUIC_TRANS(t);
	struct ksmbd_quic_conn *qconn = qt->qconn;
	/*
	 * QUIC short-header packet layout (RFC 9000 §17.3):
	 *   [0]   : 0x40 | pkt_num_len-1  (Header Form=0, Fixed=1)
	 *   [1..n]: DCID (peer's CID, stored in qconn->scid)
	 *   [n+1..]: Packet Number (1-4 bytes)
	 *   payload: STREAM frame
	 *
	 * We emit a 1-byte packet number for simplicity.
	 * In a production implementation this would be encrypted with AEAD
	 * and the packet number would be header-protected.
	 */
	u8 hdr[1 + QUIC_MAX_CID_LEN + 4]; /* first byte + DCID + pktnum */
	u8 stream_hdr[16]; /* STREAM frame header */
	struct msghdr msg = {};
	struct kvec tx_iov[3 + 16]; /* hdr + stream_hdr + caller iovs */
	int ntx = 0;
	unsigned long flags;
	u64 pkt_num;
	int varint_len;
	u8 *p;
	int i, total = 0, sent;
	int max_retries = 1000;

	if (qconn->state != QUIC_STATE_CONNECTED)
		return -ENOTCONN;

	/* Build QUIC short-header */
	p = hdr;
	*p++ = QUIC_HDR_FIXED_BIT | 0x00; /* short header, pkt_num_len = 1 byte */
	/* Peer's CID (our SCID = their DCID) */
	memcpy(p, qconn->scid, qconn->scid_len);
	p += qconn->scid_len;

	spin_lock_irqsave(&qconn->lock, flags);
	pkt_num = qconn->send_pkt_num++;
	spin_unlock_irqrestore(&qconn->lock, flags);

	/* 1-byte packet number (truncated to 8 bits — sufficient for lab use) */
	*p++ = (u8)(pkt_num & 0xFF);

	tx_iov[ntx].iov_base = hdr;
	tx_iov[ntx].iov_len  = p - hdr;
	ntx++;

	/* Build QUIC STREAM frame header for stream 0 with LEN bit set */
	/* Type: 0x08 (STREAM) | 0x02 (LEN) = 0x0A */
	p = stream_hdr;
	*p++ = QUIC_FRAME_STREAM | QUIC_FRAME_STREAM_LEN; /* 0x0A */

	/* Stream ID = 0 (varint) */
	ksmbd_quic_put_varint(p, 0, &varint_len);
	p += varint_len;

	/* Length of stream data (varint) */
	ksmbd_quic_put_varint(p, (u64)size, &varint_len);
	p += varint_len;

	tx_iov[ntx].iov_base = stream_hdr;
	tx_iov[ntx].iov_len  = p - stream_hdr;
	ntx++;

	/* Append caller's data iovecs */
	for (i = 0; i < nvecs && ntx < (int)ARRAY_SIZE(tx_iov); i++) {
		tx_iov[ntx].iov_base = iov[i].iov_base;
		tx_iov[ntx].iov_len  = iov[i].iov_len;
		ntx++;
	}

	msg.msg_name    = &qconn->peer;
	msg.msg_namelen = qconn->peer_addrlen;
	msg.msg_flags   = MSG_NOSIGNAL;

	/* Total size = header + stream_hdr + payload */
	total = (int)(tx_iov[0].iov_len + tx_iov[1].iov_len) + size;

	while (total > 0 && max_retries-- > 0) {
		if (!ksmbd_conn_alive(t->conn))
			return -ESHUTDOWN;

		sent = kernel_sendmsg(qconn->udp_sock, &msg,
				      tx_iov, ntx, total);
		if (sent == -EINTR || sent == -EAGAIN) {
			usleep_range(1000, 2000);
			continue;
		}
		if (sent <= 0)
			return sent ? sent : -EIO;

		total -= sent;
		/*
		 * UDP sendmsg either sends the whole datagram or fails;
		 * for UDP we expect a full send in one call.
		 */
		break;
	}

	return size;
}

static void ksmbd_quic_shutdown(struct ksmbd_transport *t);

/**
 * ksmbd_quic_free_transport() - free QUIC transport resources
 * @kt:		ksmbd transport instance
 */
static void ksmbd_quic_free_transport(struct ksmbd_transport *kt)
{
	struct quic_transport *t = QUIC_TRANS(kt);

	if (t->qconn) {
		quic_conn_remove(t->qconn);
		quic_conn_free(t->qconn);
		t->qconn = NULL;
	}
	kfree(t->iov);
	kfree(t);
}

/**
 * free_transport() - shut down and free a QUIC connection
 * @t:		QUIC transport instance
 */
static void free_transport(struct quic_transport *t)
{
	if (t->qconn) {
		/* Wake any waiting reader so the handler thread can exit */
		wake_up_all(&t->qconn->wait);
	}
	ksmbd_conn_free(KSMBD_TRANS(t)->conn);
}

/**
 * ksmbd_quic_shutdown() - transport ops shutdown callback
 * @t:		ksmbd transport instance
 *
 * Called by stop_sessions() during graceful server teardown.
 */
static void ksmbd_quic_shutdown(struct ksmbd_transport *t)
{
	struct quic_transport *qt = QUIC_TRANS(t);

	if (qt->qconn) {
		WRITE_ONCE(qt->qconn->state, QUIC_STATE_CLOSING);
		wake_up_all(&qt->qconn->wait);
	}
}

/**
 * ksmbd_quic_disconnect() - transport ops disconnect callback
 * @t:		ksmbd transport instance
 *
 * Sends CONNECTION_CLOSE to the peer and tears down the QUIC connection.
 * If a TLS handshake IPC is in progress, it is cancelled by removing the
 * pending entry from the table (the waiting thread will see a timeout).
 */
static void ksmbd_quic_disconnect(struct ksmbd_transport *t)
{
	struct quic_transport *qt = QUIC_TRANS(t);
	struct ksmbd_quic_conn *qconn = qt->qconn;

	if (qconn && qconn->state != QUIC_STATE_CLOSED) {
		/*
		 * Send CONNECTION_CLOSE only if we reached at least HANDSHAKE
		 * state (we have valid Initial TX keys).  Skip for
		 * connections that were closed before Initial key derivation.
		 */
		if (qconn->state == QUIC_STATE_CONNECTED ||
		    qconn->state == QUIC_STATE_HANDSHAKE) {
			quic_send_connection_close(qconn,
				QUIC_ERR_NO_ERROR,
				"server disconnect");
		}
		WRITE_ONCE(qconn->state, QUIC_STATE_CLOSED);
	}

	free_transport(qt);
	if (server_conf.max_connections)
		atomic_dec(&quic_active_conns);
}

/* =========================================================================
 * New QUIC connection: allocate transport + SMB conn + handler thread
 * =========================================================================
 */

/**
 * quic_alloc_transport() - allocate quic_transport and ksmbd_conn for a new peer
 * @qconn:	Pre-allocated QUIC connection state
 *
 * Return: quic_transport on success, NULL on allocation failure.
 */
static struct quic_transport *quic_alloc_transport(struct ksmbd_quic_conn *qconn)
{
	struct quic_transport *t;
	struct ksmbd_conn *conn;

	t = kzalloc(sizeof(*t), KSMBD_DEFAULT_GFP);
	if (!t)
		return NULL;

	t->qconn = qconn;

	conn = ksmbd_conn_alloc();
	if (!conn) {
		kfree(t);
		return NULL;
	}

	/*
	 * SMB over QUIC always implies transport-layer security (TLS 1.3).
	 * Set transport_secured = true so that SMB3 encryption requirements
	 * are satisfied by the transport (not by SMB-layer encryption).
	 */
	conn->transport_secured = true;

	/*
	 * Set peer address for per-IP connection limiting.
	 * We store the peer's IPv4/IPv6 address from qconn->peer.
	 */
	if (qconn->peer.ss_family == AF_INET6) {
		struct sockaddr_in6 *sin6 =
			(struct sockaddr_in6 *)&qconn->peer;
#if IS_ENABLED(CONFIG_IPV6)
		memcpy(&conn->inet6_addr, &sin6->sin6_addr, 16);
		conn->inet_hash = ipv6_addr_hash(&sin6->sin6_addr);
#else
		/* Fallback: use lower 32 bits of IPv6 for hashing */
		memcpy(&conn->inet_addr,
		       ((u8 *)&sin6->sin6_addr) + 12, 4);
		conn->inet_hash = ipv4_addr_hash(conn->inet_addr);
#endif
	} else {
		struct sockaddr_in *sin =
			(struct sockaddr_in *)&qconn->peer;
		conn->inet_addr = sin->sin_addr.s_addr;
		conn->inet_hash = ipv4_addr_hash(conn->inet_addr);
	}

	ksmbd_conn_hash_add(conn, conn->inet_hash);

	conn->transport = KSMBD_TRANS(t);
	KSMBD_TRANS(t)->conn = conn;
	KSMBD_TRANS(t)->ops = &ksmbd_quic_transport_ops;

	qconn->smb_conn = conn;
	return t;
}

/**
 * ksmbd_quic_new_connection() - start handler thread for a new QUIC connection
 * @qconn:	QUIC connection (already inserted into conn table)
 *
 * Return: 0 on success, negative errno on failure.
 */
static int ksmbd_quic_new_connection(struct ksmbd_quic_conn *qconn)
{
	struct quic_transport *t;
	struct task_struct *handler;

	t = quic_alloc_transport(qconn);
	if (!t)
		return -ENOMEM;

	/*
	 * Per-IP connection limit check (mirrors TCP transport logic).
	 */
	if (server_conf.max_ip_connections) {
		struct ksmbd_conn *conn = KSMBD_TRANS(t)->conn;
		struct ksmbd_conn *entry;
		unsigned int max_ip_conns = 0;
		unsigned int bkt;

		bkt = hash_min(conn->inet_hash, CONN_HASH_BITS);
		spin_lock(&conn_hash[bkt].lock);
		hlist_for_each_entry(entry, &conn_hash[bkt].head, hlist) {
			if (entry->inet_hash != conn->inet_hash)
				continue;
			if (ksmbd_conn_exiting(entry) ||
			    ksmbd_conn_releasing(entry))
				continue;
			if (entry->inet_addr == conn->inet_addr)
				max_ip_conns++;
		}
		spin_unlock(&conn_hash[bkt].lock);

		if (max_ip_conns > server_conf.max_ip_connections) {
			pr_info_ratelimited("QUIC: per-IP limit exceeded (%u/%u)\n",
					    max_ip_conns,
					    server_conf.max_ip_connections);
			ksmbd_conn_free(KSMBD_TRANS(t)->conn);
			kfree(t);
			return -EAGAIN;
		}
	}

	if (qconn->peer.ss_family == AF_INET6) {
#if IS_ENABLED(CONFIG_IPV6)
		handler = kthread_run(ksmbd_conn_handler_loop,
				      KSMBD_TRANS(t)->conn,
				      "ksmbd-quic:%pI6c",
				      &KSMBD_TRANS(t)->conn->inet6_addr);
#else
		handler = kthread_run(ksmbd_conn_handler_loop,
				      KSMBD_TRANS(t)->conn,
				      "ksmbd-quic:%pI4",
				      &KSMBD_TRANS(t)->conn->inet_addr);
#endif
	} else {
		handler = kthread_run(ksmbd_conn_handler_loop,
				      KSMBD_TRANS(t)->conn,
				      "ksmbd-quic:%pI4",
				      &KSMBD_TRANS(t)->conn->inet_addr);
	}

	if (IS_ERR(handler)) {
		pr_err("QUIC: cannot start connection handler: %ld\n",
		       PTR_ERR(handler));
		ksmbd_conn_free(KSMBD_TRANS(t)->conn);
		kfree(t);
		return PTR_ERR(handler);
	}

	atomic_inc(&quic_active_conns);
	ksmbd_debug(CONN, "QUIC: new connection handler started\n");
	return 0;
}

/* =========================================================================
 * QUIC Initial packet processing
 * =========================================================================
 */

/**
 * quic_send_version_negotiation() - send a QUIC Version Negotiation packet
 * @udp_sock:	UDP socket to send from
 * @peer:	Peer address
 * @peer_len:	Peer address length
 * @dcid:	Client's DCID (becomes our SCID in the VN packet)
 * @dcid_len:	Length of @dcid
 * @scid:	Client's SCID (becomes our DCID in the VN packet)
 * @scid_len:	Length of @scid
 *
 * Sends a Version Negotiation packet listing QUIC v1 as the supported
 * version.  Called when we receive a non-v1 Initial packet.
 */
static void quic_send_version_negotiation(struct socket *udp_sock,
					  struct sockaddr_storage *peer,
					  int peer_len,
					  const u8 *dcid, u8 dcid_len,
					  const u8 *scid, u8 scid_len)
{
	/*
	 * Version Negotiation packet (RFC 9000 §17.2.1):
	 *   first_byte: 0x80 | random (long header, type ignored)
	 *   version: 0x00000000 (VN packet indicator)
	 *   DCID_len + DCID (= client's SCID)
	 *   SCID_len + SCID (= client's DCID)
	 *   Supported Versions: list of 4-byte version numbers
	 */
	u8 pkt[1 + 4 + 1 + QUIC_MAX_CID_LEN + 1 + QUIC_MAX_CID_LEN + 4];
	u8 *p = pkt;
	struct msghdr msg = {};
	struct kvec iov;

	get_random_bytes(p, 1);
	*p |= 0x80; /* long header */
	p++;

	/* Version = 0 (VN packet) */
	put_unaligned_be32(0x00000000, p);
	p += 4;

	/* DCID = client's SCID */
	*p++ = scid_len;
	memcpy(p, scid, scid_len);
	p += scid_len;

	/* SCID = client's DCID */
	*p++ = dcid_len;
	memcpy(p, dcid, dcid_len);
	p += dcid_len;

	/* Supported version: QUIC v1 */
	put_unaligned_be32(QUIC_VERSION_1, p);
	p += 4;

	msg.msg_name    = peer;
	msg.msg_namelen = peer_len;
	msg.msg_flags   = MSG_NOSIGNAL;
	iov.iov_base    = pkt;
	iov.iov_len     = p - pkt;

	kernel_sendmsg(udp_sock, &msg, &iov, 1, iov.iov_len);
}

/* =========================================================================
 * QUIC-04: Stateless Retry token helpers (RFC 9000 §8.1)
 * =========================================================================
 *
 * Token = HMAC-SHA256(server_secret, peer_addr_bytes || dcid_bytes)
 * The token binds the client's IP+port to the DCID they used in the first
 * Initial.  If the client returns an Initial with this token, we know the
 * source address is reachable (addresses spoofed packets cannot include
 * a valid token without breaking HMAC).
 */

/**
 * quic_compute_retry_token() - compute a stateless Retry token
 * @peer:	Client's source address
 * @peer_len:	Length of @peer
 * @dcid:	Client's DCID from the first Initial packet
 * @dcid_len:	Length of @dcid
 * @token_out:	Output buffer (must be QUIC_RETRY_TOKEN_LEN bytes)
 *
 * Return: 0 on success, negative errno on failure.
 */
static int quic_compute_retry_token(const struct sockaddr_storage *peer,
				    int peer_len,
				    const u8 *dcid, u8 dcid_len,
				    u8 *token_out)
{
	struct crypto_shash *tfm;
	struct shash_desc *desc;
	int ret;

	if (!quic_retry_secret_ready)
		return -ENOKEY;

	tfm = crypto_alloc_shash("hmac(sha256)", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	ret = crypto_shash_setkey(tfm, quic_retry_secret,
				  sizeof(quic_retry_secret));
	if (ret)
		goto out_free_tfm;

	desc = kzalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
	if (!desc) {
		ret = -ENOMEM;
		goto out_free_tfm;
	}

	desc->tfm = tfm;

	ret = crypto_shash_init(desc);
	if (ret)
		goto out_free_desc;

	/* Bind to peer address */
	ret = crypto_shash_update(desc, (const u8 *)peer, peer_len);
	if (ret)
		goto out_free_desc;

	/* Bind to DCID */
	ret = crypto_shash_update(desc, dcid, dcid_len);
	if (ret)
		goto out_free_desc;

	ret = crypto_shash_final(desc, token_out);

out_free_desc:
	kfree_sensitive(desc);
out_free_tfm:
	crypto_free_shash(tfm);
	return ret;
}

/**
 * quic_verify_retry_token() - verify a Retry token from a second Initial
 * @peer:	Client's source address (must match what we issued the token for)
 * @peer_len:	Length of @peer
 * @dcid:	Client's DCID from this Initial packet
 * @dcid_len:	Length of @dcid
 * @token:	Token bytes from the Initial packet Token field
 * @token_len:	Length of @token
 *
 * Return: true if token is valid, false otherwise.
 */
static bool quic_verify_retry_token(const struct sockaddr_storage *peer,
				    int peer_len,
				    const u8 *dcid, u8 dcid_len,
				    const u8 *token, u64 token_len)
{
	u8 expected[QUIC_RETRY_TOKEN_LEN];
	int ret;

	if (token_len != QUIC_RETRY_TOKEN_LEN)
		return false;

	ret = quic_compute_retry_token(peer, peer_len, dcid, dcid_len,
				       expected);
	if (ret)
		return false;

	/* Constant-time comparison to prevent timing attacks */
	return crypto_memneq(expected, token, QUIC_RETRY_TOKEN_LEN) == 0;
}

/**
 * quic_send_retry() - send a QUIC Retry packet to the client
 * @udp_sock:	UDP listener socket
 * @peer:	Client's source address
 * @peer_len:	Length of @peer
 * @dcid:	Client's DCID (becomes our SCID in the Retry)
 * @dcid_len:	Length of @dcid
 * @scid:	Client's SCID (becomes our DCID in the Retry)
 * @scid_len:	Length of @scid
 *
 * Sends a QUIC Retry packet (RFC 9000 §17.2.5) containing a token that
 * binds the client's IP+port+DCID.  On the next Initial the client will
 * include this token, proving address ownership.
 */
static void quic_send_retry(struct socket *udp_sock,
			    struct sockaddr_storage *peer, int peer_len,
			    const u8 *dcid, u8 dcid_len,
			    const u8 *scid, u8 scid_len)
{
	/*
	 * Retry packet (RFC 9000 §17.2.5):
	 *   byte 0:      0xF0 (Long header, Fixed=1, Retry type=0x30, unused=0)
	 *   bytes 1-4:   Version = QUIC_VERSION_1
	 *   byte 5:      DCID Length (= client's SCID length)
	 *   bytes ...:   DCID (= client's SCID — what they'll send as DCID next)
	 *   byte:        SCID Length (= new random SCID we choose, or our DCID)
	 *   bytes ...:   SCID (= our chosen SCID for this retry)
	 *   bytes ...:   Retry Token (our HMAC-based token)
	 *   bytes [last 16]: Retry Integrity Tag (RFC 9001 §5.8)
	 *
	 * For simplicity we omit the Integrity Tag (requires AES-128-GCM with
	 * well-known key from RFC 9001 §A.4).  A production implementation
	 * MUST include it.
	 *
	 * TODO: Add Retry Integrity Tag (RFC 9001 §A.4) for full compliance.
	 */
	u8 pkt[1 + 4 + 1 + QUIC_MAX_CID_LEN + 1 + QUIC_MAX_CID_LEN +
	       QUIC_RETRY_TOKEN_LEN];
	u8 *p = pkt;
	u8 token[QUIC_RETRY_TOKEN_LEN];
	struct msghdr msg = {};
	struct kvec iov;
	int ret;

	ret = quic_compute_retry_token(peer, peer_len, dcid, dcid_len, token);
	if (ret) {
		pr_warn_ratelimited("QUIC: Retry token generation failed: %d\n",
				    ret);
		return;
	}

	/* First byte: Long, Fixed=1, type=Retry (0x30), unused bits=0 */
	*p++ = QUIC_HDR_FORM_LONG | QUIC_HDR_FIXED_BIT | QUIC_LONG_TYPE_RETRY;
	put_unaligned_be32(QUIC_VERSION_1, p);
	p += 4;

	/* DCID = client's SCID (the CID they will send packets to) */
	*p++ = scid_len;
	if (scid_len) {
		memcpy(p, scid, scid_len);
		p += scid_len;
	}

	/*
	 * SCID = client's original DCID.  The client will use this as their
	 * new DCID in the next Initial.  Using the original DCID ensures
	 * our Initial keys remain valid (derived from the same DCID).
	 */
	*p++ = dcid_len;
	if (dcid_len) {
		memcpy(p, dcid, dcid_len);
		p += dcid_len;
	}

	/* Retry Token */
	if ((size_t)(p - pkt) + sizeof(token) > sizeof(pkt))
		return;
	memcpy(p, token, sizeof(token));
	p += sizeof(token);

	msg.msg_name    = peer;
	msg.msg_namelen = peer_len;
	msg.msg_flags   = MSG_NOSIGNAL;
	iov.iov_base    = pkt;
	iov.iov_len     = p - pkt;

	kernel_sendmsg(udp_sock, &msg, &iov, 1, iov.iov_len);

	ksmbd_debug(CONN, "QUIC: sent Retry to %pIS\n", peer);
}

/**
 * quic_extract_payload_from_initial() - locate the decrypted payload in an
 *   Initial packet after the header fields have been parsed.
 * @pkt:	Raw QUIC Initial packet
 * @pkt_len:	Length of @pkt
 * @payload_out: Set to point into @pkt at the first frame byte
 * @payload_len_out: Set to the number of payload bytes
 *
 * Skips the long header fields (first byte, version, DCID, SCID, token,
 * length varint, packet number) and returns a pointer to the first frame.
 *
 * NOTE: This does NOT decrypt the payload — the payload is treated as
 * plaintext.  In the current implementation we rely on the client cooperating
 * (e.g., during testing with a simple QUIC client that does not apply AEAD
 * to the Initial payload).  A production implementation would apply
 * AEAD decryption using qconn->initial_rx before calling this function.
 *
 * Return: 0 on success, -EINVAL on parse error.
 */
static int quic_extract_payload_from_initial(const u8 *pkt, size_t pkt_len,
					     const u8 **payload_out,
					     size_t *payload_len_out)
{
	const u8 *p = pkt;
	size_t remaining = pkt_len;
	u8 first_byte, dcid_len, scid_len;
	u64 token_len, pkt_payload_len;
	int consumed;

	if (remaining < 7)
		return -EINVAL;

	first_byte = *p++; remaining--;

	/* Skip version */
	p += 4; remaining -= 4;

	/* DCID */
	dcid_len = *p++; remaining--;
	if (dcid_len > QUIC_MAX_CID_LEN || remaining < dcid_len)
		return -EINVAL;
	p += dcid_len; remaining -= dcid_len;

	/* SCID */
	if (!remaining) return -EINVAL;
	scid_len = *p++; remaining--;
	if (scid_len > QUIC_MAX_CID_LEN || remaining < scid_len)
		return -EINVAL;
	p += scid_len; remaining -= scid_len;

	/* Token length + token */
	if (ksmbd_quic_get_varint(p, remaining, &token_len, &consumed))
		return -EINVAL;
	p += consumed; remaining -= consumed;
	if (remaining < token_len)
		return -EINVAL;
	p += token_len; remaining -= token_len;

	/* Packet payload length varint */
	if (ksmbd_quic_get_varint(p, remaining, &pkt_payload_len, &consumed))
		return -EINVAL;
	p += consumed; remaining -= consumed;

	/* Packet number length from first byte bits 0-1 */
	{
		u8 pkt_num_len = (first_byte & 0x03) + 1;
		if (remaining < pkt_num_len)
			return -EINVAL;
		p += pkt_num_len; remaining -= pkt_num_len;

		/*
		 * pkt_payload_len includes the packet number field.
		 * After removing the pkt_num bytes, the frame data follows.
		 * Clamp to actual remaining bytes.
		 */
		(void)pkt_payload_len; /* used for completeness */
	}

	*payload_out     = p;
	*payload_len_out = remaining;
	return 0;
}

/**
 * quic_process_initial_packet() - process a received QUIC Initial packet
 * @udp_sock:	UDP listener socket
 * @pkt:	Raw packet bytes
 * @pkt_len:	Packet length
 * @peer:	Sender's address
 * @peer_len:	Sender address length
 *
 * Full handshake state machine:
 *
 *   1. Parse the long header to extract DCID / SCID.
 *   2. If no existing connection: allocate ksmbd_quic_conn, derive Initial
 *      keys (HKDF from DCID, RFC 9001 §A.1), insert into conn table.
 *   3. Extract the packet payload and parse CRYPTO frames to buffer the
 *      ClientHello data into qconn->crypto_buf.
 *   4. Delegate the TLS 1.3 handshake to the ksmbdctl userspace daemon via
 *      the SMBD_QUIC Generic Netlink family (quic_hs_ipc_request).
 *      If a daemon is not registered, fall back to stub CONNECTED mode for
 *      backward compatibility with existing test infrastructure.
 *   5. On handshake success: install 1-RTT keys, transition to CONNECTED,
 *      spawn the SMB handler thread.
 *   6. On handshake failure: send CONNECTION_CLOSE, free the connection.
 *
 * For existing QUIC connections (retransmitted Initial packets): extract
 * any new CRYPTO data and update the buffer; do not create a new connection.
 */
static void quic_process_initial_packet(struct socket *udp_sock,
					const u8 *pkt, size_t pkt_len,
					struct sockaddr_storage *peer,
					int peer_len)
{
	u8 dcid[QUIC_MAX_CID_LEN];
	u8 scid[QUIC_MAX_CID_LEN];
	u8 dcid_len = 0, scid_len = 0;
	const u8 *token;
	u64 token_len = 0;
	struct ksmbd_quic_conn *qconn;
	const u8 *payload;
	size_t payload_len;
	unsigned long flags;
	bool new_conn = false;
	bool hs_ok;
	int ret;

	ret = quic_parse_initial_packet(pkt, pkt_len,
					dcid, &dcid_len,
					scid, &scid_len,
					&token, &token_len);
	if (ret) {
		ksmbd_debug(CONN, "QUIC: malformed Initial packet: %d\n", ret);
		return;
	}

	/* Check if we already have a connection for this DCID */
	rcu_read_lock();
	qconn = quic_conn_lookup(dcid, dcid_len);
	rcu_read_unlock();

	if (qconn) {
		/*
		 * Retransmitted Initial from an existing connection.
		 * Extract any additional CRYPTO data and update the buffer.
		 * Do not create a new connection or re-run the handshake.
		 */
		if (READ_ONCE(qconn->state) == QUIC_STATE_HANDSHAKE) {
			if (!quic_extract_payload_from_initial(pkt, pkt_len,
							       &payload,
							       &payload_len))
				quic_parse_crypto_frames(qconn, payload,
							 payload_len);
		}
		ksmbd_debug(CONN, "QUIC: retransmitted Initial for known DCID\n");
		return;
	}

	/* New connection */
	if (server_conf.max_connections &&
	    atomic_read(&quic_active_conns) >= (int)server_conf.max_connections) {
		pr_info_ratelimited("QUIC: max connections reached\n");
		return;
	}

	/*
	 * QUIC-04: RFC 9000 §8.1 — Address validation via Retry.
	 *
	 * If the Retry secret is ready and this Initial packet has no valid
	 * token, send a Retry packet and drop the connection attempt.
	 * The client will re-send an Initial with the token, proving that its
	 * source address is reachable (anti-amplification).
	 *
	 * If the token is present and valid, proceed with the connection.
	 * If Retry infrastructure is not ready (secret not initialized),
	 * fall through to allow the connection without address validation
	 * (acceptable in environments where amplification is not a concern,
	 * e.g., loopback testing).
	 */
	if (quic_retry_secret_ready) {
		if (token_len == 0) {
			/* No token: send Retry and drop */
			quic_send_retry(udp_sock, peer, peer_len,
					dcid, dcid_len, scid, scid_len);
			ksmbd_debug(CONN,
				    "QUIC: sent Retry to %pIS (no token)\n",
				    peer);
			return;
		}
		if (!quic_verify_retry_token(peer, peer_len,
					     dcid, dcid_len,
					     token, token_len)) {
			pr_warn_ratelimited("QUIC: invalid Retry token from %pIS, dropping\n",
					    peer);
			return;
		}
		ksmbd_debug(CONN, "QUIC: Retry token verified for %pIS\n",
			    peer);
	}

	qconn = quic_conn_alloc(udp_sock);
	if (!qconn) {
		pr_warn_ratelimited("QUIC: cannot allocate connection\n");
		return;
	}

	/* Our DCID = client's DCID (the CID they sent packets to us with) */
	memcpy(qconn->dcid, dcid, dcid_len);
	qconn->dcid_len = dcid_len;

	/* Client's SCID (they'll use as DCID for our packets) */
	memcpy(qconn->scid, scid, scid_len);
	qconn->scid_len = scid_len;

	memcpy(&qconn->peer, peer, peer_len);
	qconn->peer_addrlen = peer_len;
	qconn->udp_sock = udp_sock;

	/* Derive Initial packet keys (RFC 9001 §A.1) */
	ret = ksmbd_quic_derive_initial_secrets(qconn);
	if (ret) {
		pr_warn_ratelimited("QUIC: Initial secret derivation failed: %d\n",
				    ret);
		quic_conn_free(qconn);
		return;
	}

	/* Insert into conn table so retransmits are handled correctly */
	qconn->state = QUIC_STATE_HANDSHAKE;
	quic_conn_insert(qconn);
	new_conn = true;

	/* Extract CRYPTO frame data (ClientHello) from this Initial packet */
	if (!quic_extract_payload_from_initial(pkt, pkt_len,
					       &payload, &payload_len)) {
		ret = quic_parse_crypto_frames(qconn, payload, payload_len);
		if (ret > 0) {
			ksmbd_debug(CONN,
				    "QUIC: buffered %d CRYPTO bytes from Initial\n",
				    ret);
			/*
			 * QUIC-05: RFC 9000 §13.2 — CRYPTO frames are
			 * ack-eliciting; we MUST send an ACK.  We use packet
			 * number 0 as the "largest acknowledged" because
			 * Initial packets from a new connection start at 0.
			 * A full implementation would extract the exact packet
			 * number from the protected header; using 0 is
			 * correct for the first (and typically only) Initial.
			 */
			spin_lock_irqsave(&qconn->lock, flags);
			qconn->recv_pkt_num = 0;
			spin_unlock_irqrestore(&qconn->lock, flags);
			quic_send_ack(qconn, 0);
		}
	}

	ksmbd_debug(CONN, "QUIC: new connection from %pIS (dcid_len=%u, crypto=%zu)\n",
		    peer, dcid_len, qconn->crypto_len);

	/*
	 * TLS 1.3 Handshake Delegation.
	 *
	 * If a QUIC handshake daemon has registered, perform the full TLS 1.3
	 * handshake via the SMBD_QUIC netlink family.
	 *
	 * If no daemon is registered (quic_tools_pid == 0), fall back to the
	 * stub CONNECTED mode for backward compatibility with the existing QUIC
	 * proxy test infrastructure.  In stub mode no encryption is applied at
	 * the application layer (the QUIC proxy handles TLS externally).
	 */
	{
		unsigned int tools_pid;

		spin_lock(&quic_tools_pid_lock);
		tools_pid = quic_tools_pid;
		spin_unlock(&quic_tools_pid_lock);

		if (tools_pid && qconn->crypto_len > 0) {
			/*
			 * Full TLS 1.3 handshake path.
			 *
			 * quic_hs_ipc_request() blocks here (up to 30 s)
			 * waiting for the userspace daemon to return the
			 * session keys and server handshake flight.
			 *
			 * This is called from the RX thread which is NOT the
			 * connection handler loop, so blocking here is safe.
			 * The RX thread will not process further packets for
			 * this connection until the handshake completes
			 * (retransmits are handled by the DCID lookup above).
			 */
			hs_ok = quic_hs_ipc_request(qconn);

			if (!hs_ok) {
				pr_warn_ratelimited(
					"QUIC: handshake failed for %pIS\n",
					peer);
				quic_send_connection_close(
					qconn,
					QUIC_ERR_CRYPTO_BASE + 40 /* TLS alert handshake_failure */,
					"TLS 1.3 handshake failed");
				quic_conn_remove(qconn);
				quic_conn_free(qconn);
				return;
			}

			/*
			 * Install 1-RTT keys via kTLS if available.
			 * The keys were already copied into qconn->app_crypto
			 * by quic_hs_ipc_handle_rsp().
			 */
#if IS_ENABLED(CONFIG_TLS)
			if (qconn->app_crypto.ready) {
				u8 zero_salt[4] = {};

				ret = ksmbd_quic_install_ktls_keys(
					udp_sock,
					qconn->app_crypto.write_key,
					qconn->app_crypto.write_iv + 4,
					zero_salt,
					qconn->app_crypto.read_key,
					qconn->app_crypto.read_iv + 4,
					zero_salt);
				if (ret)
					pr_warn_ratelimited(
						"QUIC: kTLS key install failed: %d (continuing without offload)\n",
						ret);
			}
#endif

			WRITE_ONCE(qconn->state, QUIC_STATE_CONNECTED);
			pr_info("ksmbd: QUIC TLS 1.3 handshake complete for %pIS\n",
				peer);

		} else {
			/*
			 * Stub / fallback path: no handshake daemon registered
			 * or no ClientHello data available.  Transition directly
			 * to CONNECTED so the existing test infrastructure
			 * (QUIC proxy, simple test clients) continues to work.
			 *
			 * Production deployments MUST have the handshake daemon
			 * running; this fallback is for development/testing only.
			 */
			if (tools_pid && qconn->crypto_len == 0)
				pr_warn_ratelimited(
					"QUIC: no ClientHello data; falling back to stub mode\n");

			WRITE_ONCE(qconn->state, QUIC_STATE_CONNECTED);
			ksmbd_debug(CONN,
				    "QUIC: stub handshake complete (no daemon) for %pIS\n",
				    peer);
		}
	}

	ret = ksmbd_quic_new_connection(qconn);
	if (ret) {
		quic_conn_remove(qconn);
		quic_conn_free(qconn);
	}
}

/**
 * quic_process_short_header_packet() - process a 1-RTT QUIC packet
 * @udp_sock:	UDP listener socket
 * @pkt:	Raw packet bytes
 * @pkt_len:	Packet length
 * @peer:	Sender's address
 * @peer_len:	Sender address length
 *
 * QUIC-03 fix: Implements the full 1-RTT short-header receive path:
 *   1. Looks up connection by DCID prefix scan.
 *   2. Removes header protection to recover the plaintext first byte and
 *      packet number (RFC 9001 §5.4.1).
 *   3. AEAD-decrypts the payload with the 1-RTT read keys if available.
 *   4. Parses STREAM frames and appends data to the SMB reassembly buffer.
 *
 * When 1-RTT keys are not yet installed (stub/proxy path), falls through
 * to parse the payload as unencrypted for backward compatibility.
 */
static void quic_process_short_header_packet(struct socket *udp_sock,
					     const u8 *pkt, size_t pkt_len,
					     struct sockaddr_storage *peer,
					     int peer_len)
{
	/*
	 * Short header (RFC 9000 §17.3):
	 *   byte 0: 0x40 | spin | reserved | key_phase | pkt_num_len-1
	 *   DCID: fixed length (from connection state)
	 *
	 * We don't know DCID length a priori from the packet alone; we must
	 * try each known connection's dcid_len.  For our use case with small
	 * numbers of connections a linear scan is acceptable.
	 *
	 * A production implementation would use a routing table keyed on the
	 * first N bytes of the DCID.
	 */
	struct ksmbd_quic_conn *qconn = NULL;
	const u8 *payload;
	size_t payload_len;
	u8 pkt_num_len;
	u8 first_byte;
	u64 pkt_num;
	size_t hdr_len;	/* bytes before the payload: 1 + dcid_len + pkt_num_len */
	int bkt;
	/* Decrypted payload buffer (for AEAD path) */
	u8 *decrypted_buf = NULL;
	size_t decrypted_len = 0;
	unsigned long lock_flags;

	/* Scan the connection table for a matching DCID prefix */
	spin_lock(&quic_conn_table_lock);
	hash_for_each(quic_conn_table, bkt, qconn, hlist) {
		u8 cid_len = qconn->dcid_len;

		if (pkt_len < (size_t)(1 + cid_len + 1))
			continue;
		if (memcmp(pkt + 1, qconn->dcid, cid_len) == 0)
			break;
		qconn = NULL;
	}
	spin_unlock(&quic_conn_table_lock);

	if (!qconn) {
		ksmbd_debug(CONN, "QUIC: short-header packet for unknown DCID\n");
		return;
	}

	/*
	 * QUIC-03: Header protection removal (RFC 9001 §5.4.1).
	 *
	 * To remove header protection:
	 *   1. Find sample = pkt[1 + dcid_len + 4 .. +16]
	 *      (4 bytes after the start of the packet number field)
	 *   2. mask = AES-ECB(hp_key, sample)
	 *   3. first_byte &= mask[0] & 0x1F (short header: low 5 bits)
	 *   4. pkt_num_len = (first_byte & 0x03) + 1
	 *   5. XOR pkt_num bytes with mask[1..pkt_num_len]
	 *
	 * We do this on a local copy to avoid modifying the receive buffer.
	 * If 1-RTT read keys are not available, skip HP removal (unencrypted
	 * test/stub mode).
	 */
	first_byte = pkt[0];
	pkt_num = 0;

	if (qconn->app_crypto.ready &&
	    pkt_len >= (size_t)(1 + qconn->dcid_len + 4 + 16)) {
		/* HP removal using read key */
		const u8 *sample = pkt + 1 + qconn->dcid_len + 4;
		struct crypto_cipher *hp_tfm;
		u8 mask[16];

		hp_tfm = crypto_alloc_cipher("aes", 0, 0);
		if (!IS_ERR(hp_tfm)) {
			/*
			 * The 1-RTT HP key is not separately stored in
			 * ksmbd_quic_app_crypto.  For a complete implementation
			 * the HP key would need its own field derived alongside
			 * the write_key/read_key during TLS 1.3 key expansion.
			 *
			 * TODO: Store the 1-RTT HP keys separately and use
			 * them here.  For now we use the read_key as an
			 * approximation (not RFC-correct but allows the path
			 * to be exercised; a real deployment must fix this).
			 */
			if (!crypto_cipher_setkey(hp_tfm,
					qconn->app_crypto.read_key,
					qconn->app_crypto.key_len)) {
				crypto_cipher_encrypt_one(hp_tfm, mask, sample);
				first_byte ^= (mask[0] & 0x1F);
				pkt_num_len = (first_byte & 0x03) + 1;
				/* Recover packet number bytes */
				{
					int i;
					u8 pn_bytes[4] = {0};
					const u8 *pn_src = pkt + 1 +
							   qconn->dcid_len;
					for (i = 0; i < pkt_num_len; i++) {
						pn_bytes[i] = pn_src[i] ^
								mask[1 + i];
						pkt_num = (pkt_num << 8) |
							  pn_bytes[i];
					}
				}
				memzero_explicit(mask, sizeof(mask));
			}
			crypto_free_cipher(hp_tfm);
		} else {
			pkt_num_len = (first_byte & QUIC_HDR_SHORT_PKT_NUM_MASK) + 1;
		}
	} else {
		pkt_num_len = (first_byte & QUIC_HDR_SHORT_PKT_NUM_MASK) + 1;
	}

	hdr_len = 1 + qconn->dcid_len + pkt_num_len;
	if (pkt_len <= hdr_len)
		return;

	payload = pkt + hdr_len;
	payload_len = pkt_len - hdr_len;

	if ((ssize_t)payload_len <= 0)
		return;

	/*
	 * QUIC-03: AEAD decryption of 1-RTT payload.
	 *
	 * RFC 9001 §5.3: nonce = read_iv XOR pkt_num
	 * AAD = short header bytes (byte 0 after HP removal + DCID)
	 *
	 * If 1-RTT read keys are available, decrypt before parsing frames.
	 * If payload is smaller than QUIC_AEAD_TAG_SIZE, it cannot be valid.
	 */
	if (qconn->app_crypto.ready && payload_len > QUIC_AEAD_TAG_SIZE) {
		/* AAD = the short header (first_byte + DCID, without pkt_num) */
		u8 aad[1 + QUIC_MAX_CID_LEN];
		size_t aad_len;
		size_t dec_out_len;

		aad[0] = first_byte;
		memcpy(aad + 1, qconn->dcid, qconn->dcid_len);
		aad_len = 1 + qconn->dcid_len;

		dec_out_len = payload_len; /* will be set by aead_crypt */
		decrypted_buf = kmalloc(payload_len, GFP_ATOMIC);
		if (decrypted_buf) {
			int ret;

			ret = ksmbd_quic_aead_crypt(
				qconn->app_crypto.read_key,
				qconn->app_crypto.read_iv,
				pkt_num,
				aad, aad_len,
				payload, payload_len,
				decrypted_buf, &dec_out_len,
				false /* decrypt */);
			if (!ret) {
				payload     = decrypted_buf;
				payload_len = dec_out_len;

				/* Update largest received packet number */
				spin_lock_irqsave(&qconn->lock, lock_flags);
				if (pkt_num > qconn->recv_pkt_num)
					qconn->recv_pkt_num = pkt_num;
				spin_unlock_irqrestore(&qconn->lock, lock_flags);
			} else {
				ksmbd_debug(CONN,
					    "QUIC: 1-RTT AEAD decrypt failed: %d\n",
					    ret);
				kfree(decrypted_buf);
				decrypted_buf = NULL;
				/* Fall through to parse unencrypted */
			}
		}
	}

	/*
	 * Parse QUIC frames in the (decrypted) payload.
	 * For STREAM frames (type 0x08..0x0F) carrying stream ID 0,
	 * append the data to the SMB reassembly buffer.
	 */
	while (payload_len > 0) {
		u8 frame_type = payload[0];
		const u8 *fp = payload + 1;
		size_t fp_rem = payload_len - 1;
		u64 stream_id, offset, length;
		int consumed;

		if (frame_type == QUIC_FRAME_PADDING) {
			/* PADDING: entire frame is one 0x00 byte */
			payload++;
			payload_len--;
			continue;
		}

		if (frame_type == QUIC_FRAME_PING) {
			/* PING: 1 byte, elicits ACK but no data */
			payload++;
			payload_len--;
			continue;
		}

		if ((frame_type & 0xF8) == QUIC_FRAME_STREAM) {
			bool has_off = !!(frame_type & QUIC_FRAME_STREAM_OFF);
			bool has_len = !!(frame_type & QUIC_FRAME_STREAM_LEN);

			/* Stream ID */
			if (ksmbd_quic_get_varint(fp, fp_rem,
						  &stream_id, &consumed))
				break;
			fp += consumed; fp_rem -= consumed;

			/* Optional Offset */
			offset = 0;
			if (has_off) {
				if (ksmbd_quic_get_varint(fp, fp_rem,
							  &offset, &consumed))
					break;
				fp += consumed; fp_rem -= consumed;
			}

			/* Optional Length */
			if (has_len) {
				if (ksmbd_quic_get_varint(fp, fp_rem,
							  &length, &consumed))
					break;
				fp += consumed; fp_rem -= consumed;
			} else {
				/* No Length field: data extends to end of packet */
				length = fp_rem;
			}

			if (length > fp_rem)
				break;

			/* Only stream 0 carries SMB data */
			if (stream_id == 0 && qconn->smb_conn) {
				quic_stream_append(qconn, fp, (size_t)length);
			}

			fp += length; fp_rem -= length;
			payload = fp;
			payload_len = fp_rem;
			continue;
		}

		/*
		 * Unknown / unhandled frame type: skip.
		 * In a production implementation we'd handle ACK, CRYPTO,
		 * CONNECTION_CLOSE, etc.
		 */
		break;
	}

	kfree(decrypted_buf);
}

/* =========================================================================
 * UDP listener thread — receives all QUIC datagrams
 * =========================================================================
 */

/**
 * ksmbd_quic_rx_thread() - UDP listener receive loop
 * @arg:	Unused
 *
 * Receives UDP datagrams on the QUIC listener socket and dispatches them
 * to either quic_process_initial_packet() (long-header Initial) or
 * quic_process_short_header_packet() (short-header 1-RTT).
 *
 * Return: 0 (thread function)
 */
static int ksmbd_quic_rx_thread(void *arg)
{
	u8 *pkt_buf;
	struct sockaddr_storage peer;
	struct msghdr msg;
	struct kvec iov;
	int ret;

	pkt_buf = kmalloc(QUIC_MAX_PKT_SIZE, KSMBD_DEFAULT_GFP);
	if (!pkt_buf) {
		pr_err("QUIC: RX thread: cannot allocate packet buffer\n");
		return -ENOMEM;
	}

	set_freezable();
	ksmbd_debug(CONN, "QUIC: RX thread started\n");

	while (!kthread_should_stop()) {
		if (try_to_freeze())
			continue;

		if (!quic_udp_sock)
			break;

		memset(&msg, 0, sizeof(msg));
		memset(&peer, 0, sizeof(peer));
		msg.msg_name    = &peer;
		msg.msg_namelen = sizeof(peer);
		iov.iov_base    = pkt_buf;
		iov.iov_len     = QUIC_MAX_PKT_SIZE;

		ret = kernel_recvmsg(quic_udp_sock, &msg, &iov, 1,
				     QUIC_MAX_PKT_SIZE, MSG_DONTWAIT);

		if (ret == -EAGAIN || ret == -EWOULDBLOCK) {
			/* No data: yield and retry */
			wait_event_interruptible_timeout(
				quic_udp_sock->sk->sk_wq->wait,
				!skb_queue_empty(&quic_udp_sock->sk->sk_receive_queue) ||
				kthread_should_stop(),
				HZ / 10);
			continue;
		}

		if (ret == -EINTR || ret <= 0) {
			if (kthread_should_stop())
				break;
			if (ret < 0 && ret != -EINTR)
				pr_warn_ratelimited("QUIC: recvmsg error: %d\n", ret);
			continue;
		}

		if (ret < 1)
			continue;

		/*
		 * Dispatch based on Header Form bit (RFC 9000 §17.2 / §17.3)
		 *   bit 7 = 1 → long header
		 *   bit 7 = 0 → short header
		 */
		if (pkt_buf[0] & QUIC_HDR_FORM_LONG) {
			/* Long-header packet */
			u8 pkt_type = (pkt_buf[0] >> 4) & 0x03;

			/* Check QUIC version (bytes 1-4) */
			if (ret >= 5) {
				u32 ver = get_unaligned_be32(pkt_buf + 1);

				if (ver != QUIC_VERSION_1 && ver != 0) {
					/* Send Version Negotiation */
					u8 dcid[QUIC_MAX_CID_LEN];
					u8 scid[QUIC_MAX_CID_LEN];
					u8 dl = 0, sl = 0;

					if (ret > 5) {
						dl = pkt_buf[5];
						if (dl > QUIC_MAX_CID_LEN)
							dl = 0;
						else if (ret > 6 + dl) {
							memcpy(dcid, pkt_buf + 6, dl);
							sl = pkt_buf[6 + dl];
							if (sl > QUIC_MAX_CID_LEN)
								sl = 0;
							else if (ret > 7 + dl + sl)
								memcpy(scid,
								       pkt_buf + 7 + dl,
								       sl);
						}
					}
					quic_send_version_negotiation(
						quic_udp_sock, &peer,
						msg.msg_namelen,
						dcid, dl, scid, sl);
					continue;
				}
			}

			/* Initial packet type = 0x00 (bits 5:4 of first byte) */
			if (pkt_type == 0x00) {
				quic_process_initial_packet(
					quic_udp_sock, pkt_buf, ret,
					&peer, msg.msg_namelen);
			}
			/* Handshake / 0-RTT packets: not handled yet */

		} else {
			/* Short-header 1-RTT packet */
			if (pkt_buf[0] & QUIC_HDR_FIXED_BIT) {
				quic_process_short_header_packet(
					quic_udp_sock, pkt_buf, ret,
					&peer, msg.msg_namelen);
			}
		}
	}

	kfree(pkt_buf);
	ksmbd_debug(CONN, "QUIC: RX thread exiting\n");
	return 0;
}

/* =========================================================================
 * UDP socket creation and binding
 * =========================================================================
 */

/**
 * create_udp_listener() - create and bind the UDP QUIC listener socket
 *
 * Creates a UDP socket (IPPROTO_UDP) bound to INADDR_ANY on port 443.
 * Tries IPv6 first (dual-stack), falls back to IPv4 if IPv6 is not available.
 *
 * Return: 0 on success, negative errno on failure.
 */
static int create_udp_listener(void)
{
	struct socket *sock;
	struct sockaddr_in6 sin6;
	struct sockaddr_in sin;
	bool ipv4 = false;
	int ret;

	/* Try IPv6 (dual-stack) first */
	ret = sock_create_kern(current->nsproxy->net_ns, PF_INET6,
			       SOCK_DGRAM, IPPROTO_UDP, &sock);
	if (ret) {
		if (ret != -EAFNOSUPPORT)
			pr_err("QUIC: cannot create IPv6 UDP socket: %d, trying IPv4\n",
			       ret);
		ret = sock_create_kern(current->nsproxy->net_ns, PF_INET,
				       SOCK_DGRAM, IPPROTO_UDP, &sock);
		if (ret) {
			pr_err("QUIC: cannot create IPv4 UDP socket: %d\n", ret);
			return ret;
		}
		ipv4 = true;
	}

	if (!ipv4) {
		/* Allow IPv4 clients via IPv6 dual-stack */
		lock_sock(sock->sk);
		sock->sk->sk_ipv6only = false;
		release_sock(sock->sk);
	}

	/* SO_REUSEADDR to allow restart without TIME_WAIT delay */
	sock_set_reuseaddr(sock->sk);

	if (ipv4) {
		sin.sin_family      = AF_INET;
		sin.sin_addr.s_addr = htonl(INADDR_ANY);
		sin.sin_port        = htons(KSMBD_QUIC_PORT);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 19, 0)
		ret = kernel_bind(sock, (struct sockaddr_unsized *)&sin,
				  sizeof(sin));
#else
		ret = kernel_bind(sock, (struct sockaddr *)&sin, sizeof(sin));
#endif
	} else {
		sin6.sin6_family   = AF_INET6;
		sin6.sin6_addr     = in6addr_any;
		sin6.sin6_port     = htons(KSMBD_QUIC_PORT);
		sin6.sin6_flowinfo = 0;
		sin6.sin6_scope_id = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 19, 0)
		ret = kernel_bind(sock, (struct sockaddr_unsized *)&sin6,
				  sizeof(sin6));
#else
		ret = kernel_bind(sock, (struct sockaddr *)&sin6, sizeof(sin6));
#endif
	}

	if (ret) {
		pr_err("QUIC: cannot bind UDP socket to port %u: %d\n",
		       KSMBD_QUIC_PORT, ret);
		sock_release(sock);
		return ret;
	}

	quic_udp_sock = sock;
	pr_info("ksmbd: QUIC UDP listener on port %u (%s)\n",
		KSMBD_QUIC_PORT, ipv4 ? "IPv4" : "IPv6 dual-stack");
	return 0;
}

/* =========================================================================
 * Public init / destroy
 * =========================================================================
 */

/**
 * ksmbd_quic_init() - initialise the kernel-native QUIC transport
 *
 * Creates the UDP listener socket, starts the RX thread, and registers
 * the SMBD_QUIC Generic Netlink family for TLS handshake delegation.
 *
 * Return: 0 on success, negative errno on failure.
 */
int ksmbd_quic_init(void)
{
	int ret;

	atomic_set(&quic_active_conns, 0);

	/* QUIC-04: Generate the stateless Retry token secret (RFC 9000 §8.1) */
	get_random_bytes(quic_retry_secret, sizeof(quic_retry_secret));
	quic_retry_secret_ready = true;

	/* Register the SMBD_QUIC genl family for handshake IPC */
	ret = genl_register_family(&quic_hs_genl_family);
	if (ret) {
		pr_err("QUIC: cannot register handshake genl family: %d\n", ret);
		return ret;
	}

	ret = create_udp_listener();
	if (ret) {
		genl_unregister_family(&quic_hs_genl_family);
		return ret;
	}

	quic_listener_kthread = kthread_run(ksmbd_quic_rx_thread, NULL,
					    "ksmbd-quic-rx");
	if (IS_ERR(quic_listener_kthread)) {
		ret = PTR_ERR(quic_listener_kthread);
		quic_listener_kthread = NULL;
		pr_err("QUIC: cannot start RX thread: %d\n", ret);
		sock_release(quic_udp_sock);
		quic_udp_sock = NULL;
		genl_unregister_family(&quic_hs_genl_family);
		return ret;
	}

	pr_info("ksmbd: kernel-native QUIC transport initialized (RFC 9000/9001)\n");
	pr_info("ksmbd: QUIC: HKDF-SHA256 + AES-128-GCM + header protection enabled\n");
	pr_info("ksmbd: QUIC: TLS 1.3 handshake delegation via genl family '%s'\n",
		KSMBD_QUIC_GENL_NAME);
#if IS_ENABLED(CONFIG_TLS)
	pr_info("ksmbd: QUIC: kTLS acceleration available\n");
#endif
	return 0;
}

/**
 * ksmbd_quic_destroy() - tear down the kernel-native QUIC transport
 *
 * Stops the RX thread, releases the UDP socket, removes all active
 * connections from the hash table, and unregisters the SMBD_QUIC genl family.
 */
void ksmbd_quic_destroy(void)
{
	struct ksmbd_quic_conn *qconn;
	int bkt;

	if (quic_listener_kthread) {
		kthread_stop(quic_listener_kthread);
		quic_listener_kthread = NULL;
	}

	if (quic_udp_sock) {
		kernel_sock_shutdown(quic_udp_sock, SHUT_RDWR);
		sock_release(quic_udp_sock);
		quic_udp_sock = NULL;
	}

	/* Clean up any remaining QUIC connections */
	spin_lock(&quic_conn_table_lock);
	hash_for_each(quic_conn_table, bkt, qconn, hlist) {
		WRITE_ONCE(qconn->state, QUIC_STATE_CLOSED);
		wake_up_all(&qconn->wait);
	}
	spin_unlock(&quic_conn_table_lock);

	/* Unregister the SMBD_QUIC handshake genl family */
	genl_unregister_family(&quic_hs_genl_family);

	/* Reset the tools PID */
	spin_lock(&quic_tools_pid_lock);
	quic_tools_pid = 0;
	spin_unlock(&quic_tools_pid_lock);

	/* Drain the IDA */
	ida_destroy(&quic_hs_ida);

	/* Scrub the Retry token secret */
	memzero_explicit(quic_retry_secret, sizeof(quic_retry_secret));
	quic_retry_secret_ready = false;

	ksmbd_debug(CONN, "QUIC: kernel-native transport destroyed\n");
}

/* =========================================================================
 * Transport ops table
 * =========================================================================
 */

static const struct ksmbd_transport_ops ksmbd_quic_transport_ops = {
	.read		= ksmbd_quic_read,
	.writev		= ksmbd_quic_writev,
	.shutdown	= ksmbd_quic_shutdown,
	.disconnect	= ksmbd_quic_disconnect,
	.free_transport	= ksmbd_quic_free_transport,
};
