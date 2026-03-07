/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *   Copyright (C) 2021 Samsung Electronics Co., Ltd.
 *
 *   smb2_dir.h - KUnit-testable function declarations for
 *   SMB2 QUERY_DIRECTORY handler (smb2_dir.c).
 */
#ifndef __KSMBD_SMB2_DIR_H__
#define __KSMBD_SMB2_DIR_H__

#include "smb2pdu.h"
#include "smb_common.h"

#if IS_ENABLED(CONFIG_KUNIT)

/* readdir_info_level_struct_sz - return base struct size for directory info level */
int readdir_info_level_struct_sz(int info_level);

/* verify_info_level - validate FileInformationClass for QUERY_DIRECTORY */
int verify_info_level(int info_level);

#endif /* CONFIG_KUNIT */
#endif /* __KSMBD_SMB2_DIR_H__ */
