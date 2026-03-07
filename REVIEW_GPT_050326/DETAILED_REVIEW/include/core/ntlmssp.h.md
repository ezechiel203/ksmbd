# Line-by-line Review: src/include/core/ntlmssp.h

- L00001 [NONE] `/* SPDX-License-Identifier: LGPL-2.1+ */`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` *   Copyright (c) International Business Machines  Corp., 2002,2007`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` *   Author(s): Steve French (sfrench@us.ibm.com)`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] `#ifndef __KSMBD_NTLMSSP_H`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] `#define __KSMBD_NTLMSSP_H`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `#define NTLMSSP_SIGNATURE "NTLMSSP"`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] `/* Security blob target info data */`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `#define TGT_Name        "KSMBD"`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] ` * Size of the crypto key returned on the negotiate SMB in bytes`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `#define CIFS_CRYPTO_KEY_SIZE	(8)`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `#define CIFS_KEY_SIZE	(40)`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] ` * Size of encrypted user password in bytes`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `#define CIFS_ENCPWD_SIZE	(16)`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `#define CIFS_CPHTXT_SIZE	(16)`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `/* Message Types */`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `#define NtLmNegotiate     cpu_to_le32(1)`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] `#define NtLmChallenge     cpu_to_le32(2)`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `#define NtLmAuthenticate  cpu_to_le32(3)`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `#define UnknownMessage    cpu_to_le32(8)`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `/* Negotiate Flags */`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] `#define NTLMSSP_NEGOTIATE_UNICODE         0x01 /* Text strings are unicode */`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `#define NTLMSSP_NEGOTIATE_OEM             0x02 /* Text strings are in OEM */`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `#define NTLMSSP_REQUEST_TARGET            0x04 /* Srv returns its auth realm */`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `/* define reserved9                       0x08 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `#define NTLMSSP_NEGOTIATE_SIGN          0x0010 /* Request signing capability */`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] `#define NTLMSSP_NEGOTIATE_SEAL          0x0020 /* Request confidentiality */`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] `#define NTLMSSP_NEGOTIATE_DGRAM         0x0040`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] `#define NTLMSSP_NEGOTIATE_LM_KEY        0x0080 /* Use LM session key */`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] `/* defined reserved 8                   0x0100 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] `#define NTLMSSP_NEGOTIATE_NTLM          0x0200 /* NTLM authentication */`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] `#define NTLMSSP_NEGOTIATE_NT_ONLY       0x0400 /* Lanman not allowed */`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] `#define NTLMSSP_ANONYMOUS               0x0800`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] `#define NTLMSSP_NEGOTIATE_DOMAIN_SUPPLIED 0x1000 /* reserved6 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] `#define NTLMSSP_NEGOTIATE_WORKSTATION_SUPPLIED 0x2000`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] `#define NTLMSSP_NEGOTIATE_LOCAL_CALL    0x4000 /* client/server same machine */`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `#define NTLMSSP_NEGOTIATE_ALWAYS_SIGN   0x8000 /* Sign. All security levels  */`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] `#define NTLMSSP_TARGET_TYPE_DOMAIN     0x10000`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] `#define NTLMSSP_TARGET_TYPE_SERVER     0x20000`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] `#define NTLMSSP_TARGET_TYPE_SHARE      0x40000`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `#define NTLMSSP_NEGOTIATE_EXTENDED_SEC 0x80000 /* NB:not related to NTLMv2 pwd*/`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `/* #define NTLMSSP_REQUEST_INIT_RESP     0x100000 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] `#define NTLMSSP_NEGOTIATE_IDENTIFY    0x100000`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `#define NTLMSSP_REQUEST_ACCEPT_RESP   0x200000 /* reserved5 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] `#define NTLMSSP_REQUEST_NON_NT_KEY    0x400000`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] `#define NTLMSSP_NEGOTIATE_TARGET_INFO 0x800000`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] `/* #define reserved4                 0x1000000 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] `#define NTLMSSP_NEGOTIATE_VERSION    0x2000000 /* we do not set */`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] `/* #define reserved3                 0x4000000 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] `/* #define reserved2                 0x8000000 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] `/* #define reserved1                0x10000000 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] `#define NTLMSSP_NEGOTIATE_128       0x20000000`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `#define NTLMSSP_NEGOTIATE_KEY_XCH   0x40000000`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] `#define NTLMSSP_NEGOTIATE_56        0x80000000`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `/* Define AV Pair Field IDs */`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] `enum av_field_type {`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] `	NTLMSSP_AV_EOL = 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] `	NTLMSSP_AV_NB_COMPUTER_NAME,`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] `	NTLMSSP_AV_NB_DOMAIN_NAME,`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] `	NTLMSSP_AV_DNS_COMPUTER_NAME,`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] `	NTLMSSP_AV_DNS_DOMAIN_NAME,`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] `	NTLMSSP_AV_DNS_TREE_NAME,`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] `	NTLMSSP_AV_FLAGS,`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] `	NTLMSSP_AV_TIMESTAMP,`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] `	NTLMSSP_AV_RESTRICTION,`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] `	NTLMSSP_AV_TARGET_NAME,`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] `	NTLMSSP_AV_CHANNEL_BINDINGS`
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] `/* Although typedefs are not commonly used for structure definitions */`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] `/* in the Linux kernel, in this particular case they are useful      */`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] `/* to more closely match the standards document for NTLMSSP from     */`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] `/* OpenGroup and to make the code more closely match the standard in */`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] `/* appearance */`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] `struct security_buffer {`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] `	__le16 Length;`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] `	__le16 MaximumLength;`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] `	__le32 BufferOffset;	/* offset to buffer */`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] `struct target_info {`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] `	__le16 Type;`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] `	__le16 Length;`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] `	__u8 Content[];`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] `struct negotiate_message {`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] `	__u8 Signature[sizeof(NTLMSSP_SIGNATURE)];`
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] `	__le32 MessageType;     /* NtLmNegotiate = 1 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] `	__le32 NegotiateFlags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] `	struct security_buffer DomainName;	/* RFC 1001 style and ASCII */`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] `	struct security_buffer WorkstationName;	/* RFC 1001 and ASCII */`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] `	 * struct security_buffer for version info not present since we`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] `	 * do not set the version is present flag`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] `	char DomainString[];`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] `	/* followed by WorkstationString */`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] `struct challenge_message {`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] `	__u8 Signature[sizeof(NTLMSSP_SIGNATURE)];`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] `	__le32 MessageType;   /* NtLmChallenge = 2 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] `	struct security_buffer TargetName;`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] `	__le32 NegotiateFlags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] `	__u8 Challenge[CIFS_CRYPTO_KEY_SIZE];`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] `	__u8 Reserved[8];`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] `	struct security_buffer TargetInfoArray;`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] `	 * struct security_buffer for version info not present since we`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] `	 * do not set the version is present flag`
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] `struct authenticate_message {`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] `	__u8 Signature[sizeof(NTLMSSP_SIGNATURE)];`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] `	__le32 MessageType;  /* NtLmsAuthenticate = 3 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] `	struct security_buffer LmChallengeResponse;`
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] `	struct security_buffer NtChallengeResponse;`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] `	struct security_buffer DomainName;`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] `	struct security_buffer UserName;`
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] `	struct security_buffer WorkstationName;`
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] `	struct security_buffer SessionKey;`
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] `	__le32 NegotiateFlags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] `	/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] `	 * struct security_buffer for version info not present since we`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] `	 * do not set the version is present flag`
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] `	 */`
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] `	char UserString[];`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] `struct ntlmv2_resp {`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] `	char ntlmv2_hash[CIFS_ENCPWD_SIZE];`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] `	__le32 blob_signature;`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] `	__le32 reserved;`
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] `	__le64  time;`
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] `	__le64 client_chal; /* random */`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] `	__le32 reserved2;`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] `	/* array of name entries could follow ending in minimum 4 byte struct */`
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] `} __packed;`
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] `/* per smb session structure/fields */`
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] `struct ntlmssp_auth {`
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] `	/* whether session key is per smb session */`
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] `	bool		sesskey_per_smbsess;`
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [NONE] `	/* sent by client in type 1 ntlmsssp exchange */`
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] `	__u32		client_flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] `	/* sent by server in type 2 ntlmssp exchange */`
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] `	__u32		conn_flags;`
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] `	/* sent to server */`
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] `	unsigned char	ciphertext[CIFS_CPHTXT_SIZE];`
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] `	/* used by ntlmssp */`
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] `	char		cryptkey[CIFS_CRYPTO_KEY_SIZE];`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] `#endif /* __KSMBD_NTLMSSP_H */`
  Review: Low-risk line; verify in surrounding control flow.
