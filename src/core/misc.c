// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2016 Namjae Jeon <linkinjeon@kernel.org>
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/xattr.h>
#include <linux/fs.h>
#include <linux/unicode.h>

#include "misc.h"
#include "smb_common.h"
#include "connection.h"
#include "vfs.h"

#if IS_ENABLED(CONFIG_KUNIT)
#include <kunit/visibility.h>
#else
#define EXPORT_SYMBOL_IF_KUNIT(sym)
#endif

#include "mgmt/share_config.h"

/**
 * match_pattern() - compare a string with a pattern which might include
 * wildcard '*', '?', and the MS-DOS special wildcards '<', '>', '"'.
 *
 * MS-DOS/Windows wildcard semantics (MS-SMB2 §3.3.5.17, MS-FSCC §2.1.4):
 *   '*' — matches any sequence of zero or more characters
 *   '?' — matches any single character
 *   '<' (DOS_STAR) — matches any sequence of characters up to but not
 *                    including the last '.' in the name (the extension
 *                    separator).  If the name has no dot, behaves like '*'.
 *                    Examples: pattern "<.txt" matches "foo.txt" but not
 *                    "foo.bar.txt"; pattern "<" alone matches any name.
 *   '>' (DOS_QM)   — matches any single character, or end-of-string when
 *                    the next pattern character is a dot
 *   '"' (DOS_DOT)  — matches a '.' or end-of-string (allows patterns like
 *                    "*." to match names without an extension, e.g., "foo")
 *
 * @str:	string to compare with a pattern
 * @len:	string length
 * @pattern:	pattern string which might include wildcards
 *
 * Return:	true if pattern matched with the string, false otherwise
 */
int match_pattern(const char *str, size_t len, const char *pattern)
{
	const char *s = str;
	const char *p = pattern;
	bool star = false;
	/*
	 * For DOS_STAR ('<'): track whether the wildcard is a '<' so that
	 * we can prevent it from matching the last '.' and extension.
	 * last_dot_pos points to the last '.' in the string (or NULL if none).
	 */
	const char *last_dot = NULL;
	bool dos_star = false;
	size_t i;

	/* Locate the last '.' in the string for DOS_STAR handling */
	for (i = 0; i < len; i++) {
		if (str[i] == '.')
			last_dot = str + i;
	}

	while (*s && len) {
		switch (*p) {
		case '?':
			/* Standard: matches any single character */
			s++;
			len--;
			p++;
			break;
		case '*':
			/* Standard '*': matches any sequence */
			star = true;
			dos_star = false;
			str = s;
			if (!*++p)
				return true;
			pattern = p;
			break;
		case '<':
			/*
			 * DOS_STAR '<': like '*' but when backtracking, will
			 * not advance past the last '.' in the string.
			 * If there is no last dot, behaves exactly like '*'.
			 */
			star = true;
			dos_star = (last_dot != NULL);
			str = s;
			if (!*++p)
				return true;
			pattern = p;
			break;
		case '>':
			/*
			 * DOS_QM '>': matches any single character, OR
			 * matches end-of-string when the next pattern char
			 * is '.'.
			 */
			if (!len && p[1] == '.') {
				/* End-of-string before a dot: skip '>' */
				p++;
			} else {
				s++;
				len--;
				p++;
			}
			break;
		case '"':
			/*
			 * DOS_DOT '"': matches '.' or end-of-string.
			 * Allows patterns like "*." to match names without
			 * an extension (e.g., "foo" with no dot).
			 */
			if (*s == '.') {
				s++;
				len--;
				p++;
			} else {
				if (!star)
					return false;
				/* Backtrack, but respect DOS_STAR boundary */
				if (dos_star && last_dot && str >= last_dot) {
					return false;
				}
				str++;
				len--;
				s = str;
				p = pattern;
			}
			break;
		default:
			if (tolower(*s) == tolower(*p)) {
				s++;
				len--;
				p++;
			} else {
				if (!star)
					return false;
				/*
				 * Backtrack: for DOS_STAR ('<'), do not let
				 * the match position advance past the last
				 * dot in the original string.  This prevents
				 * '<' from "eating" the last extension.
				 */
				if (dos_star && last_dot && str >= last_dot) {
					return false;
				}
				str++;
				len--;
				s = str;
				p = pattern;
			}
			break;
		}
	}

	/* Skip trailing '*' and '<' wildcards (both match empty string) */
	while (*p == '*' || *p == '<')
		++p;
	/* '"' (DOS_DOT) at end-of-pattern matches end-of-string */
	while (*p == '"')
		++p;
	/* '>' (DOS_QM) at end-of-pattern matches end-of-string */
	while (*p == '>')
		++p;
	return !*p;
}
EXPORT_SYMBOL_IF_KUNIT(match_pattern);

/*
 * is_char_allowed() - check for valid character
 * @ch:		input character to be checked
 *
 * Return:	1 if char is allowed, otherwise 0
 */
static inline int is_char_allowed(char ch)
{
	/* check for control chars, wildcards etc. */
	if (!(ch & 0x80) &&
	    (ch <= 0x1f ||
	     ch == '?' || ch == '"' || ch == '<' ||
	     ch == '>' || ch == '|' || ch == '*'))
		return 0;

	return 1;
}

int ksmbd_validate_filename(char *filename)
{
	while (*filename) {
		char c = *filename;

		filename++;
		if (!is_char_allowed(c)) {
			ksmbd_debug(VFS, "File name validation failed: 0x%x\n", c);
			return -ENOENT;
		}
	}

	return 0;
}

/**
 * ksmbd_validate_utf16_filename() - validate a UTF-16LE filename on the wire
 * @name:	UTF-16LE filename bytes (not NUL-terminated)
 * @name_len:	length in bytes (must be even)
 *
 * Validates filename at the Unicode code-point level, BEFORE any conversion
 * to the local charset.  This avoids false rejections caused by UTF-16→UTF-8
 * conversion failures that replace unrepresentable code points with '?'.
 *
 * Only rejects code points that Windows itself forbids in file names:
 *   - U+0000  (embedded NUL)
 *   - U+FFFF  (not a character)
 *   - U+0001..U+001F  (C0 control characters)
 *   - U+0022  '"'
 *   - U+002A  '*'
 *   - U+003C  '<'
 *   - U+003E  '>'
 *   - U+003F  '?'
 *   - U+007C  '|'
 *
 * Path separators ('/' and '\') are allowed; the caller passes the full
 * path including directory components.  Unicode combining characters,
 * surrogate pairs, fullwidth forms, and precomposed/decomposed forms are
 * all allowed — Windows NTFS accepts them natively.
 *
 * Return: 0 if the name is valid, -EINVAL otherwise.
 */
int ksmbd_validate_utf16_filename(const __le16 *name, size_t name_len)
{
	size_t i;
	u16 cp;

	if (name_len & 1)
		return -EINVAL;

	for (i = 0; i < name_len / 2; i++) {
		cp = le16_to_cpu(name[i]);

		/*
		 * Stop validating at the first ':' — everything after
		 * it is a stream name where Windows allows characters
		 * (like '*', '?', '<', '>', '|', '"') that are forbidden
		 * in base filenames.  Only NUL is universally forbidden.
		 */
		if (cp == ':')
			break;

		if (cp == 0x0000 || cp == 0xFFFF)
			return -EINVAL;

		if (cp >= 0x0001 && cp <= 0x001F)
			return -EINVAL;

		if (cp == 0x0022 || /* '"' */
		    cp == 0x002A || /* '*' */
		    cp == 0x003C || /* '<' */
		    cp == 0x003E || /* '>' */
		    cp == 0x003F || /* '?' */
		    cp == 0x007C)   /* '|' */
			return -EINVAL;
	}

	return 0;
}

static int ksmbd_validate_stream_name(char *stream_name)
{
	while (*stream_name) {
		char c = *stream_name;

		stream_name++;
		if (c == '/' || c == ':' || c == '\\') {
			pr_err("Stream name validation failed: %c\n", c);
			return -ENOENT;
		}
	}

	return 0;
}

int parse_stream_name(char *filename, char **stream_name, int *s_type)
{
	char *stream_type;
	char *s_name;
	int rc = 0;

	s_name = filename;
	filename = strsep(&s_name, ":");
	if (!s_name) {
		*stream_name = NULL;
		return -ENOENT;
	}
	ksmbd_debug(SMB, "filename : %s, streams : %s\n", filename, s_name);

	/* Default to DATA_STREAM per MS-SMB2 when no :$TYPE suffix */
	*s_type = DATA_STREAM;

	if (strchr(s_name, ':')) {
		stream_type = s_name;
		s_name = strsep(&stream_type, ":");

		rc = ksmbd_validate_stream_name(s_name);
		if (rc < 0) {
			*stream_name = s_name;
			rc = -ENOENT;
			goto out;
		}

		ksmbd_debug(SMB, "stream name : %s, stream type : %s\n", s_name,
			    stream_type);
		if (!strncasecmp("$data", stream_type, 5))
			*s_type = DATA_STREAM;
		else if (!strncasecmp("$index_allocation", stream_type, 17))
			*s_type = DIR_STREAM;
		else
			rc = -ENOENT;
	}

	/*
	 * An empty stream name with $DATA type (e.g., "file::$DATA")
	 * refers to the default unnamed data stream, which is the
	 * file itself. Treat this as a non-stream open by returning
	 * -ENOENT with a NULL stream_name.
	 */
	if (!rc && (!s_name[0]) && *s_type == DATA_STREAM) {
		*stream_name = NULL;
		return -ENOENT;
	}

	*stream_name = s_name;
out:
	return rc;
}
EXPORT_SYMBOL_IF_KUNIT(parse_stream_name);

/**
 * convert_to_nt_pathname() - extract and return windows path string
 *      whose share directory prefix was removed from file path
 * @share: ksmbd_share_config pointer
 * @path: path to report
 *
 * Return : windows path string or error
 */

char *convert_to_nt_pathname(struct ksmbd_share_config *share,
			     const struct path *path)
{
	char *pathname, *ab_pathname, *nt_pathname;
	int share_path_len = share->path_sz;
	size_t ab_pathname_len;
	int prefix;

	pathname = kmalloc(PATH_MAX, KSMBD_DEFAULT_GFP);
	if (!pathname)
		return ERR_PTR(-EACCES);

	ab_pathname = d_path(path, pathname, PATH_MAX);
	if (IS_ERR(ab_pathname)) {
		nt_pathname = ERR_PTR(-EACCES);
		goto free_pathname;
	}

	if (strncmp(ab_pathname, share->path, share_path_len)) {
		nt_pathname = ERR_PTR(-EACCES);
		goto free_pathname;
	}

	ab_pathname_len = strlen(&ab_pathname[share_path_len]);
	prefix = ab_pathname[share_path_len] == '\0' ? 1 : 0;
	nt_pathname = kmalloc(prefix + ab_pathname_len + 1, KSMBD_DEFAULT_GFP);
	if (!nt_pathname) {
		nt_pathname = ERR_PTR(-ENOMEM);
		goto free_pathname;
	}

	if (prefix)
		*nt_pathname = '/';
	memcpy(nt_pathname + prefix, &ab_pathname[share_path_len],
	       ab_pathname_len + 1);

	ksmbd_conv_path_to_windows(nt_pathname);

free_pathname:
	kfree(pathname);
	return nt_pathname;
}

int get_nlink(struct kstat *st)
{
	int nlink;

	nlink = st->nlink;
	/* Avoid underflow on mount points or pseudo-filesystems */
	if (S_ISDIR(st->mode))
		nlink = (nlink > 1) ? nlink - 1 : 0;

	return nlink;
}

void ksmbd_conv_path_to_unix(char *path)
{
	strreplace(path, '\\', '/');
}

void ksmbd_strip_last_slash(char *path)
{
	int len = strlen(path);

	while (len && path[len - 1] == '/') {
		path[len - 1] = '\0';
		len--;
	}
}

void ksmbd_conv_path_to_windows(char *path)
{
	strreplace(path, '/', '\\');
}

char *ksmbd_casefold_sharename(struct unicode_map *um, const char *name)
{
	char *cf_name, *orig_cf_name;
	int cf_len;

	cf_name = kzalloc(KSMBD_REQ_MAX_SHARE_NAME, KSMBD_DEFAULT_GFP);
	if (!cf_name)
		return ERR_PTR(-ENOMEM);

	if (IS_ENABLED(CONFIG_UNICODE) && um) {
		const struct qstr q_name = {.name = name, .len = strlen(name)};

		cf_len = utf8_casefold(um, &q_name, cf_name,
				       KSMBD_REQ_MAX_SHARE_NAME);
		if (cf_len < 0)
			goto out_ascii;

		return cf_name;
	}

out_ascii:
	cf_len = strscpy(cf_name, name, KSMBD_REQ_MAX_SHARE_NAME);
	if (cf_len < 0) {
		kfree(cf_name);
		return ERR_PTR(-E2BIG);
	}

	orig_cf_name = cf_name;
	for (; *cf_name; ++cf_name)
		*cf_name = isascii(*cf_name) ? tolower(*cf_name) : *cf_name;
	return orig_cf_name;
}

/**
 * ksmbd_extract_sharename() - get share name from tree connect request
 * @treename:	buffer containing tree name and share name
 *
 * Return:      share name on success, otherwise error
 */
char *ksmbd_extract_sharename(struct unicode_map *um, const char *treename)
{
	const char *name = treename, *pos = strrchr(name, '\\');

	if (pos)
		name = (pos + 1);

	/* caller has to free the memory */
	return ksmbd_casefold_sharename(um, name);
}

/**
 * convert_to_unix_name() - convert windows name to unix format
 * @share:	ksmbd_share_config pointer
 * @name:	file name that is relative to share
 *
 * Return:	converted name on success, otherwise NULL
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
char *convert_to_unix_name(struct ksmbd_share_config *share, const char *name)
{
	int no_slash = 0, name_len, path_len;
	char *new_name;

	if (name[0] == '/')
		name++;

	path_len = share->path_sz;
	name_len = strlen(name);
	new_name = kmalloc(path_len + name_len + 2, KSMBD_DEFAULT_GFP);
	if (!new_name)
		return ERR_PTR(-ENOMEM);

	memcpy(new_name, share->path, path_len);
	if (new_name[path_len - 1] != '/') {
		new_name[path_len] = '/';
		no_slash = 1;
	}

	memcpy(new_name + path_len + no_slash, name, name_len);
	path_len += name_len + no_slash;
	new_name[path_len] = 0x00;
	return new_name;
}
#else
static char *normalize_path(const char *path)
{
	size_t path_len, remain_path_len, out_path_len;
	char *out_path, *out_next;
	int i, pre_dotdot_cnt = 0, slash_cnt = 0;
	bool is_last;

	path_len = strlen(path);
	remain_path_len = path_len;

	out_path = kzalloc(path_len + 2, KSMBD_DEFAULT_GFP);
	if (!out_path)
		return ERR_PTR(-ENOMEM);
	out_path_len = 0;
	out_next = out_path;

	do {
		const char *name = path + path_len - remain_path_len;
		char *next = strchrnul(name, '/');
		size_t name_len = next - name;

		is_last = !next[0];
		if (name_len == 2 && name[0] == '.' && name[1] == '.') {
			pre_dotdot_cnt++;
			/* handle the case that path ends with "/.." */
			if (is_last)
				goto follow_dotdot;
		} else {
			if (pre_dotdot_cnt) {
follow_dotdot:
				slash_cnt = 0;
				for (i = out_path_len - 1; i >= 0; i--) {
					if (out_path[i] == '/' &&
					    ++slash_cnt == pre_dotdot_cnt + 1)
						break;
				}

				if (i < 0 &&
				    slash_cnt != pre_dotdot_cnt) {
					kfree(out_path);
					return ERR_PTR(-EINVAL);
				}

				out_next = &out_path[i+1];
				*out_next = '\0';
				out_path_len = i + 1;

			}

			if (name_len != 0 &&
			    !(name_len == 1 && name[0] == '.') &&
			    !(name_len == 2 && name[0] == '.' && name[1] == '.')) {
				snprintf(out_next, name_len + 2, "%.*s/", (int)name_len, name);
				out_next += name_len + 1;
				out_path_len += name_len + 1;
			}
			pre_dotdot_cnt = 0;
		}

		remain_path_len -= name_len + 1;
	} while (!is_last);

	if (out_path_len > 0)
		out_path[out_path_len-1] = '\0';
	return out_path;
}

char *convert_to_unix_name(struct ksmbd_share_config *share, const char *name)
{
	int no_slash = 0, name_len, path_len;
	char *new_name, *norm_name;

	if (name[0] == '/')
		name++;

	norm_name = normalize_path(name);
	if (IS_ERR(norm_name))
		return norm_name;

	path_len = share->path_sz;
	name_len = strlen(norm_name);
	new_name = kmalloc(path_len + name_len + 2, KSMBD_DEFAULT_GFP);
	if (!new_name) {
		kfree(norm_name);
		return ERR_PTR(-ENOMEM);
	}

	memcpy(new_name, share->path, path_len);
	if (new_name[path_len - 1] != '/') {
		new_name[path_len] = '/';
		no_slash = 1;
	}

	memcpy(new_name + path_len + no_slash, norm_name, name_len);
	path_len += name_len + no_slash;
	new_name[path_len] = 0x00;
	kfree(norm_name);

	return new_name;
}
#endif

char *ksmbd_convert_dir_info_name(struct ksmbd_dir_info *d_info,
				  const struct nls_table *local_nls,
				  int *conv_len)
{
	char *conv;
	int  sz = min(4 * d_info->name_len, PATH_MAX);

	if (!sz)
		return NULL;

	conv = kmalloc(sz + 2, KSMBD_DEFAULT_GFP);
	if (!conv)
		return NULL;

	/*
	 * Convert directory entry name from local charset to UTF-16LE.
	 * smbConvertToUTF16() returns the count of UTF-16 code units written.
	 * Multiply by 2 to get byte length for the wire format.
	 * The buffer is allocated at 4x the name length, which is sufficient
	 * since each UTF-8 byte produces at most one UTF-16 code unit (2 bytes).
	 */
	*conv_len = smbConvertToUTF16((__le16 *)conv, d_info->name,
				      d_info->name_len, local_nls, 0);
	*conv_len *= 2;

	/* We allocate buffer twice bigger than needed. */
	conv[*conv_len] = 0x00;
	conv[*conv_len + 1] = 0x00;
	return conv;
}

/*
 * Convert the NT UTC (based 1601-01-01, in hundred nanosecond units)
 * into Unix UTC (based 1970-01-01, in seconds).
 */
struct timespec64 ksmbd_NTtimeToUnix(__le64 ntutc)
{
	struct timespec64 ts;

	/* Subtract the NTFS time offset, then convert to 1s intervals. */
	s64 t = le64_to_cpu(ntutc) - NTFS_TIME_OFFSET;
	u64 abs_t;

	/*
	 * Unfortunately can not use normal 64 bit division on 32 bit arch, but
	 * the alternative, do_div, does not work with negative numbers so have
	 * to special case them
	 */
	if (t < 0) {
		abs_t = -t;
		ts.tv_nsec = do_div(abs_t, 10000000) * 100;
		ts.tv_nsec = -ts.tv_nsec;
		ts.tv_sec = -abs_t;
	} else {
		abs_t = t;
		ts.tv_nsec = do_div(abs_t, 10000000) * 100;
		ts.tv_sec = abs_t;
	}

	return ts;
}

/* Convert the Unix UTC into NT UTC. */
u64 ksmbd_UnixTimeToNT(struct timespec64 t)
{
	/* Convert to 100ns intervals and then add the NTFS time offset. */
	return (u64)t.tv_sec * 10000000 + t.tv_nsec / 100 + NTFS_TIME_OFFSET;
}

long long ksmbd_systime(void)
{
	struct timespec64	ts;

	ktime_get_real_ts64(&ts);
	return ksmbd_UnixTimeToNT(ts);
}
