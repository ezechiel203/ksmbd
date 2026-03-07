# Line-by-line Review: src/include/core/misc.h

- L00001 [NONE] `/* SPDX-License-Identifier: GPL-2.0-or-later */`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` *   Copyright (C) 2018 Samsung Electronics Co., Ltd.`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] `#ifndef __KSMBD_MISC_H__`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] `#define __KSMBD_MISC_H__`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] `struct ksmbd_share_config;`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `struct nls_table;`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] `struct kstat;`
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] `struct ksmbd_file;`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] `int match_pattern(const char *str, size_t len, const char *pattern);`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] `int ksmbd_validate_filename(char *filename);`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `int parse_stream_name(char *filename, char **stream_name, int *s_type);`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] `char *convert_to_nt_pathname(struct ksmbd_share_config *share,`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] `			     const struct path *path);`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] `int get_nlink(struct kstat *st);`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] `void ksmbd_conv_path_to_unix(char *path);`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] `void ksmbd_strip_last_slash(char *path);`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] `void ksmbd_conv_path_to_windows(char *path);`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `char *ksmbd_casefold_sharename(struct unicode_map *um, const char *name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `char *ksmbd_extract_sharename(struct unicode_map *um, const char *treename);`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `char *convert_to_unix_name(struct ksmbd_share_config *share, const char *name);`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `#define KSMBD_DIR_INFO_ALIGNMENT	8`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `struct ksmbd_dir_info;`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] `char *ksmbd_convert_dir_info_name(struct ksmbd_dir_info *d_info,`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `				  const struct nls_table *local_nls,`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `				  int *conv_len);`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `#define NTFS_TIME_OFFSET	((u64)(369 * 365 + 89) * 24 * 3600 * 10000000)`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] `struct timespec64 ksmbd_NTtimeToUnix(__le64 ntutc);`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `u64 ksmbd_UnixTimeToNT(struct timespec64 t);`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `long long ksmbd_systime(void);`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `#endif /* __KSMBD_MISC_H__ */`
  Review: Low-risk line; verify in surrounding control flow.
