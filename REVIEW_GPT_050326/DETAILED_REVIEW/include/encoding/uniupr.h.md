# Line-by-line Review: src/include/encoding/uniupr.h

- L00001 [NONE] `/* SPDX-License-Identifier: GPL-2.0-or-later */`
  Review: Low-risk line; verify in surrounding control flow.
- L00002 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00003 [NONE] ` *   Some of the source code in this file came from fs/cifs/uniupr.h`
  Review: Low-risk line; verify in surrounding control flow.
- L00004 [NONE] ` *   Copyright (c) International Business Machines  Corp., 2000,2002`
  Review: Low-risk line; verify in surrounding control flow.
- L00005 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00006 [NONE] ` * uniupr.h - Unicode compressed case ranges`
  Review: Low-risk line; verify in surrounding control flow.
- L00007 [NONE] ` *`
  Review: Low-risk line; verify in surrounding control flow.
- L00008 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00009 [NONE] `#ifndef __KSMBD_UNIUPR_H`
  Review: Low-risk line; verify in surrounding control flow.
- L00010 [NONE] `#define __KSMBD_UNIUPR_H`
  Review: Low-risk line; verify in surrounding control flow.
- L00011 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00012 [NONE] `#ifndef UNIUPR_NOUPPER`
  Review: Low-risk line; verify in surrounding control flow.
- L00013 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00014 [NONE] ` * Latin upper case`
  Review: Low-risk line; verify in surrounding control flow.
- L00015 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00016 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00017 [NONE] ` * These arrays are defined here and declared 'extern' in unicode.h.`
  Review: Low-risk line; verify in surrounding control flow.
- L00018 [NONE] ` * This header must only be included from a single translation unit (unicode.c)`
  Review: Low-risk line; verify in surrounding control flow.
- L00019 [NONE] ` * to avoid multiple definition errors. The arrays require external linkage`
  Review: Low-risk line; verify in surrounding control flow.
- L00020 [NONE] ` * because inline functions in unicode.h (UniToupper) reference them from`
  Review: Low-risk line; verify in surrounding control flow.
- L00021 [NONE] ` * other translation units.`
  Review: Low-risk line; verify in surrounding control flow.
- L00022 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00023 [NONE] `signed char SmbUniUpperTable[512] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00024 [NONE] `	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,	/* 000-00f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00025 [NONE] `	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,	/* 010-01f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00026 [NONE] `	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,	/* 020-02f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00027 [NONE] `	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,	/* 030-03f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00028 [NONE] `	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,	/* 040-04f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00029 [NONE] `	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,	/* 050-05f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00030 [NONE] `	0, -32, -32, -32, -32, -32, -32, -32, -32, -32, -32,`
  Review: Low-risk line; verify in surrounding control flow.
- L00031 [NONE] `				-32, -32, -32, -32, -32,	/* 060-06f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00032 [NONE] `	-32, -32, -32, -32, -32, -32, -32, -32, -32, -32,`
  Review: Low-risk line; verify in surrounding control flow.
- L00033 [NONE] `				-32, 0, 0, 0, 0, 0,	/* 070-07f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00034 [NONE] `	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,	/* 080-08f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00035 [NONE] `	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,	/* 090-09f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00036 [NONE] `	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,	/* 0a0-0af */`
  Review: Low-risk line; verify in surrounding control flow.
- L00037 [NONE] `	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,	/* 0b0-0bf */`
  Review: Low-risk line; verify in surrounding control flow.
- L00038 [NONE] `	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,	/* 0c0-0cf */`
  Review: Low-risk line; verify in surrounding control flow.
- L00039 [NONE] `	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,	/* 0d0-0df */`
  Review: Low-risk line; verify in surrounding control flow.
- L00040 [NONE] `	-32, -32, -32, -32, -32, -32, -32, -32, -32, -32,`
  Review: Low-risk line; verify in surrounding control flow.
- L00041 [NONE] `			 -32, -32, -32, -32, -32, -32,	/* 0e0-0ef */`
  Review: Low-risk line; verify in surrounding control flow.
- L00042 [NONE] `	-32, -32, -32, -32, -32, -32, -32, 0, -32, -32,`
  Review: Low-risk line; verify in surrounding control flow.
- L00043 [NONE] `			 -32, -32, -32, -32, -32, 121,	/* 0f0-0ff */`
  Review: Low-risk line; verify in surrounding control flow.
- L00044 [NONE] `	0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1,	/* 100-10f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00045 [NONE] `	0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1,	/* 110-11f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00046 [NONE] `	0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1,	/* 120-12f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00047 [NONE] `	0, 0, 0, -1, 0, -1, 0, -1, 0, 0, -1, 0, -1, 0, -1, 0,	/* 130-13f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00048 [NONE] `	-1, 0, -1, 0, -1, 0, -1, 0, -1, 0, 0, -1, 0, -1, 0, -1,	/* 140-14f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00049 [NONE] `	0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1,	/* 150-15f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00050 [NONE] `	0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1,	/* 160-16f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00051 [NONE] `	0, -1, 0, -1, 0, -1, 0, -1, 0, 0, -1, 0, -1, 0, -1, 0,	/* 170-17f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00052 [NONE] `	0, 0, 0, -1, 0, -1, 0, 0, -1, 0, 0, 0, -1, 0, 0, 0,	/* 180-18f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00053 [NONE] `	0, 0, -1, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0,	/* 190-19f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00054 [NONE] `	0, -1, 0, -1, 0, -1, 0, 0, -1, 0, 0, 0, 0, -1, 0, 0,	/* 1a0-1af */`
  Review: Low-risk line; verify in surrounding control flow.
- L00055 [NONE] `	-1, 0, 0, 0, -1, 0, -1, 0, 0, -1, 0, 0, 0, -1, 0, 0,	/* 1b0-1bf */`
  Review: Low-risk line; verify in surrounding control flow.
- L00056 [NONE] `	0, 0, 0, 0, 0, -1, -2, 0, -1, -2, 0, -1, -2, 0, -1, 0,	/* 1c0-1cf */`
  Review: Low-risk line; verify in surrounding control flow.
- L00057 [NONE] `	-1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1, -79, 0, -1, /* 1d0-1df */`
  Review: Low-risk line; verify in surrounding control flow.
- L00058 [NONE] `	0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1,	/* 1e0-1ef */`
  Review: Low-risk line; verify in surrounding control flow.
- L00059 [NONE] `	0, 0, -1, -2, 0, -1, 0, 0, 0, -1, 0, -1, 0, -1, 0, -1,	/* 1f0-1ff */`
  Review: Low-risk line; verify in surrounding control flow.
- L00060 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00061 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00062 [NONE] `/* Upper case range - Greek */`
  Review: Low-risk line; verify in surrounding control flow.
- L00063 [NONE] `static signed char UniCaseRangeU03a0[47] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00064 [NONE] `	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -38, -37, -37, -37,	/* 3a0-3af */`
  Review: Low-risk line; verify in surrounding control flow.
- L00065 [NONE] `	0, -32, -32, -32, -32, -32, -32, -32, -32, -32, -32, -32,`
  Review: Low-risk line; verify in surrounding control flow.
- L00066 [NONE] `					 -32, -32, -32, -32,	/* 3b0-3bf */`
  Review: Low-risk line; verify in surrounding control flow.
- L00067 [NONE] `	-32, -32, -31, -32, -32, -32, -32, -32, -32, -32, -32, -32, -64,`
  Review: Low-risk line; verify in surrounding control flow.
- L00068 [NONE] `	-63, -63,`
  Review: Low-risk line; verify in surrounding control flow.
- L00069 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00070 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00071 [NONE] `/* Upper case range - Cyrillic */`
  Review: Low-risk line; verify in surrounding control flow.
- L00072 [NONE] `static signed char UniCaseRangeU0430[48] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00073 [NONE] `	-32, -32, -32, -32, -32, -32, -32, -32, -32, -32, -32, -32,`
  Review: Low-risk line; verify in surrounding control flow.
- L00074 [NONE] `					 -32, -32, -32, -32,	/* 430-43f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00075 [NONE] `	-32, -32, -32, -32, -32, -32, -32, -32, -32, -32, -32, -32,`
  Review: Low-risk line; verify in surrounding control flow.
- L00076 [NONE] `					 -32, -32, -32, -32,	/* 440-44f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00077 [NONE] `	0, -80, -80, -80, -80, -80, -80, -80, -80, -80, -80,`
  Review: Low-risk line; verify in surrounding control flow.
- L00078 [NONE] `					 -80, -80, 0, -80, -80,	/* 450-45f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00079 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00080 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00081 [NONE] `/* Upper case range - Extended cyrillic */`
  Review: Low-risk line; verify in surrounding control flow.
- L00082 [NONE] `static signed char UniCaseRangeU0490[61] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00083 [NONE] `	0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1,	/* 490-49f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00084 [NONE] `	0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1,	/* 4a0-4af */`
  Review: Low-risk line; verify in surrounding control flow.
- L00085 [NONE] `	0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1,	/* 4b0-4bf */`
  Review: Low-risk line; verify in surrounding control flow.
- L00086 [NONE] `	0, 0, -1, 0, -1, 0, 0, 0, -1, 0, 0, 0, -1,`
  Review: Low-risk line; verify in surrounding control flow.
- L00087 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00088 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00089 [NONE] `/* Upper case range - Extended latin and greek */`
  Review: Low-risk line; verify in surrounding control flow.
- L00090 [NONE] `static signed char UniCaseRangeU1e00[509] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00091 [NONE] `	0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1,	/* 1e00-1e0f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00092 [NONE] `	0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1,	/* 1e10-1e1f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00093 [NONE] `	0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1,	/* 1e20-1e2f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00094 [NONE] `	0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1,	/* 1e30-1e3f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00095 [NONE] `	0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1,	/* 1e40-1e4f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00096 [NONE] `	0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1,	/* 1e50-1e5f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00097 [NONE] `	0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1,	/* 1e60-1e6f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00098 [NONE] `	0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1,	/* 1e70-1e7f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00099 [NONE] `	0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1,	/* 1e80-1e8f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00100 [NONE] `	0, -1, 0, -1, 0, -1, 0, 0, 0, 0, 0, -59, 0, -1, 0, -1,	/* 1e90-1e9f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00101 [NONE] `	0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1,	/* 1ea0-1eaf */`
  Review: Low-risk line; verify in surrounding control flow.
- L00102 [NONE] `	0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1,	/* 1eb0-1ebf */`
  Review: Low-risk line; verify in surrounding control flow.
- L00103 [NONE] `	0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1,	/* 1ec0-1ecf */`
  Review: Low-risk line; verify in surrounding control flow.
- L00104 [NONE] `	0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1,	/* 1ed0-1edf */`
  Review: Low-risk line; verify in surrounding control flow.
- L00105 [NONE] `	0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, -1,	/* 1ee0-1eef */`
  Review: Low-risk line; verify in surrounding control flow.
- L00106 [NONE] `	0, -1, 0, -1, 0, -1, 0, -1, 0, -1, 0, 0, 0, 0, 0, 0,	/* 1ef0-1eff */`
  Review: Low-risk line; verify in surrounding control flow.
- L00107 [NONE] `	8, 8, 8, 8, 8, 8, 8, 8, 0, 0, 0, 0, 0, 0, 0, 0,	/* 1f00-1f0f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00108 [NONE] `	8, 8, 8, 8, 8, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,	/* 1f10-1f1f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00109 [NONE] `	8, 8, 8, 8, 8, 8, 8, 8, 0, 0, 0, 0, 0, 0, 0, 0,	/* 1f20-1f2f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00110 [NONE] `	8, 8, 8, 8, 8, 8, 8, 8, 0, 0, 0, 0, 0, 0, 0, 0,	/* 1f30-1f3f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00111 [NONE] `	8, 8, 8, 8, 8, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,	/* 1f40-1f4f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00112 [NONE] `	0, 8, 0, 8, 0, 8, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0,	/* 1f50-1f5f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00113 [NONE] `	8, 8, 8, 8, 8, 8, 8, 8, 0, 0, 0, 0, 0, 0, 0, 0,	/* 1f60-1f6f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00114 [NONE] `	74, 74, 86, 86, 86, 86, 100, 100, 0, 0, 112, 112,`
  Review: Low-risk line; verify in surrounding control flow.
- L00115 [NONE] `				 126, 126, 0, 0,	/* 1f70-1f7f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00116 [NONE] `	8, 8, 8, 8, 8, 8, 8, 8, 0, 0, 0, 0, 0, 0, 0, 0,	/* 1f80-1f8f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00117 [NONE] `	8, 8, 8, 8, 8, 8, 8, 8, 0, 0, 0, 0, 0, 0, 0, 0,	/* 1f90-1f9f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00118 [NONE] `	8, 8, 8, 8, 8, 8, 8, 8, 0, 0, 0, 0, 0, 0, 0, 0,	/* 1fa0-1faf */`
  Review: Low-risk line; verify in surrounding control flow.
- L00119 [NONE] `	8, 8, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,	/* 1fb0-1fbf */`
  Review: Low-risk line; verify in surrounding control flow.
- L00120 [NONE] `	0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,	/* 1fc0-1fcf */`
  Review: Low-risk line; verify in surrounding control flow.
- L00121 [NONE] `	8, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,	/* 1fd0-1fdf */`
  Review: Low-risk line; verify in surrounding control flow.
- L00122 [NONE] `	8, 8, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,	/* 1fe0-1fef */`
  Review: Low-risk line; verify in surrounding control flow.
- L00123 [NONE] `	0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L00124 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00125 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00126 [NONE] `/* Upper case range - Wide latin */`
  Review: Low-risk line; verify in surrounding control flow.
- L00127 [NONE] `static signed char UniCaseRangeUff40[27] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00128 [NONE] `	0, -32, -32, -32, -32, -32, -32, -32, -32, -32, -32,`
  Review: Low-risk line; verify in surrounding control flow.
- L00129 [NONE] `			 -32, -32, -32, -32, -32,	/* ff40-ff4f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00130 [NONE] `	-32, -32, -32, -32, -32, -32, -32, -32, -32, -32, -32,`
  Review: Low-risk line; verify in surrounding control flow.
- L00131 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00132 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00133 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00134 [NONE] ` * Upper Case Range`
  Review: Low-risk line; verify in surrounding control flow.
- L00135 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00136 [NONE] `const struct UniCaseRange SmbUniUpperRange[] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00137 [NONE] `	{0x03a0, 0x03ce, UniCaseRangeU03a0},`
  Review: Low-risk line; verify in surrounding control flow.
- L00138 [NONE] `	{0x0430, 0x045f, UniCaseRangeU0430},`
  Review: Low-risk line; verify in surrounding control flow.
- L00139 [NONE] `	{0x0490, 0x04cc, UniCaseRangeU0490},`
  Review: Low-risk line; verify in surrounding control flow.
- L00140 [NONE] `	{0x1e00, 0x1ffc, UniCaseRangeU1e00},`
  Review: Low-risk line; verify in surrounding control flow.
- L00141 [NONE] `	{0xff40, 0xff5a, UniCaseRangeUff40},`
  Review: Low-risk line; verify in surrounding control flow.
- L00142 [NONE] `	{0}`
  Review: Low-risk line; verify in surrounding control flow.
- L00143 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00144 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00145 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00146 [NONE] `#ifndef UNIUPR_NOLOWER`
  Review: Low-risk line; verify in surrounding control flow.
- L00147 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00148 [NONE] ` * Latin lower case`
  Review: Low-risk line; verify in surrounding control flow.
- L00149 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00150 [NONE] `static signed char CifsUniLowerTable[512] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00151 [NONE] `	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,	/* 000-00f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00152 [NONE] `	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,	/* 010-01f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00153 [NONE] `	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,	/* 020-02f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00154 [NONE] `	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,	/* 030-03f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00155 [NONE] `	0, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,`
  Review: Low-risk line; verify in surrounding control flow.
- L00156 [NONE] `					 32, 32, 32,	/* 040-04f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00157 [NONE] `	32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 0, 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L00158 [NONE] `					 0, 0, 0,	/* 050-05f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00159 [NONE] `	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,	/* 060-06f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00160 [NONE] `	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,	/* 070-07f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00161 [NONE] `	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,	/* 080-08f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00162 [NONE] `	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,	/* 090-09f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00163 [NONE] `	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,	/* 0a0-0af */`
  Review: Low-risk line; verify in surrounding control flow.
- L00164 [NONE] `	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,	/* 0b0-0bf */`
  Review: Low-risk line; verify in surrounding control flow.
- L00165 [NONE] `	32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,`
  Review: Low-risk line; verify in surrounding control flow.
- L00166 [NONE] `				 32, 32, 32, 32,	/* 0c0-0cf */`
  Review: Low-risk line; verify in surrounding control flow.
- L00167 [NONE] `	32, 32, 32, 32, 32, 32, 32, 0, 32, 32, 32, 32,`
  Review: Low-risk line; verify in surrounding control flow.
- L00168 [NONE] `					 32, 32, 32, 0,	/* 0d0-0df */`
  Review: Low-risk line; verify in surrounding control flow.
- L00169 [NONE] `	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,	/* 0e0-0ef */`
  Review: Low-risk line; verify in surrounding control flow.
- L00170 [NONE] `	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,	/* 0f0-0ff */`
  Review: Low-risk line; verify in surrounding control flow.
- L00171 [NONE] `	1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0,	/* 100-10f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00172 [NONE] `	1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0,	/* 110-11f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00173 [NONE] `	1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0,	/* 120-12f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00174 [NONE] `	0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1,	/* 130-13f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00175 [NONE] `	0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0,	/* 140-14f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00176 [NONE] `	1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0,	/* 150-15f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00177 [NONE] `	1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0,	/* 160-16f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00178 [NONE] `	1, 0, 1, 0, 1, 0, 1, 0, -121, 1, 0, 1, 0, 1, 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L00179 [NONE] `						 0,	/* 170-17f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00180 [NONE] `	0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 79,`
  Review: Low-risk line; verify in surrounding control flow.
- L00181 [NONE] `						 0,	/* 180-18f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00182 [NONE] `	0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0,	/* 190-19f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00183 [NONE] `	1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1,	/* 1a0-1af */`
  Review: Low-risk line; verify in surrounding control flow.
- L00184 [NONE] `	0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0,	/* 1b0-1bf */`
  Review: Low-risk line; verify in surrounding control flow.
- L00185 [NONE] `	0, 0, 0, 0, 2, 1, 0, 2, 1, 0, 2, 1, 0, 1, 0, 1,	/* 1c0-1cf */`
  Review: Low-risk line; verify in surrounding control flow.
- L00186 [NONE] `	0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0,	/* 1d0-1df */`
  Review: Low-risk line; verify in surrounding control flow.
- L00187 [NONE] `	1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0,	/* 1e0-1ef */`
  Review: Low-risk line; verify in surrounding control flow.
- L00188 [NONE] `	0, 2, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0,	/* 1f0-1ff */`
  Review: Low-risk line; verify in surrounding control flow.
- L00189 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00190 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00191 [NONE] `/* Lower case range - Greek */`
  Review: Low-risk line; verify in surrounding control flow.
- L00192 [NONE] `static signed char UniCaseRangeL0380[44] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00193 [NONE] `	0, 0, 0, 0, 0, 0, 38, 0, 37, 37, 37, 0, 64, 0, 63, 63,	/* 380-38f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00194 [NONE] `	0, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,`
  Review: Low-risk line; verify in surrounding control flow.
- L00195 [NONE] `						 32, 32, 32,	/* 390-39f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00196 [NONE] `	32, 32, 0, 32, 32, 32, 32, 32, 32, 32, 32, 32,`
  Review: Low-risk line; verify in surrounding control flow.
- L00197 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00198 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00199 [NONE] `/* Lower case range - Cyrillic */`
  Review: Low-risk line; verify in surrounding control flow.
- L00200 [NONE] `static signed char UniCaseRangeL0400[48] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00201 [NONE] `	0, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80,`
  Review: Low-risk line; verify in surrounding control flow.
- L00202 [NONE] `					 0, 80, 80,	/* 400-40f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00203 [NONE] `	32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,`
  Review: Low-risk line; verify in surrounding control flow.
- L00204 [NONE] `					 32, 32, 32,	/* 410-41f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00205 [NONE] `	32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,`
  Review: Low-risk line; verify in surrounding control flow.
- L00206 [NONE] `					 32, 32, 32,	/* 420-42f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00207 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00208 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00209 [NONE] `/* Lower case range - Extended cyrillic */`
  Review: Low-risk line; verify in surrounding control flow.
- L00210 [NONE] `static signed char UniCaseRangeL0490[60] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00211 [NONE] `	1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0,	/* 490-49f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00212 [NONE] `	1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0,	/* 4a0-4af */`
  Review: Low-risk line; verify in surrounding control flow.
- L00213 [NONE] `	1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0,	/* 4b0-4bf */`
  Review: Low-risk line; verify in surrounding control flow.
- L00214 [NONE] `	0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1,`
  Review: Low-risk line; verify in surrounding control flow.
- L00215 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00216 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00217 [NONE] `/* Lower case range - Extended latin and greek */`
  Review: Low-risk line; verify in surrounding control flow.
- L00218 [NONE] `static signed char UniCaseRangeL1e00[504] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00219 [NONE] `	1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0,	/* 1e00-1e0f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00220 [NONE] `	1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0,	/* 1e10-1e1f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00221 [NONE] `	1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0,	/* 1e20-1e2f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00222 [NONE] `	1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0,	/* 1e30-1e3f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00223 [NONE] `	1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0,	/* 1e40-1e4f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00224 [NONE] `	1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0,	/* 1e50-1e5f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00225 [NONE] `	1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0,	/* 1e60-1e6f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00226 [NONE] `	1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0,	/* 1e70-1e7f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00227 [NONE] `	1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0,	/* 1e80-1e8f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00228 [NONE] `	1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0,	/* 1e90-1e9f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00229 [NONE] `	1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0,	/* 1ea0-1eaf */`
  Review: Low-risk line; verify in surrounding control flow.
- L00230 [NONE] `	1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0,	/* 1eb0-1ebf */`
  Review: Low-risk line; verify in surrounding control flow.
- L00231 [NONE] `	1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0,	/* 1ec0-1ecf */`
  Review: Low-risk line; verify in surrounding control flow.
- L00232 [NONE] `	1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0,	/* 1ed0-1edf */`
  Review: Low-risk line; verify in surrounding control flow.
- L00233 [NONE] `	1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0,	/* 1ee0-1eef */`
  Review: Low-risk line; verify in surrounding control flow.
- L00234 [NONE] `	1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0,	/* 1ef0-1eff */`
  Review: Low-risk line; verify in surrounding control flow.
- L00235 [NONE] `	0, 0, 0, 0, 0, 0, 0, 0, -8, -8, -8, -8, -8, -8, -8, -8,	/* 1f00-1f0f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00236 [NONE] `	0, 0, 0, 0, 0, 0, 0, 0, -8, -8, -8, -8, -8, -8, 0, 0,	/* 1f10-1f1f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00237 [NONE] `	0, 0, 0, 0, 0, 0, 0, 0, -8, -8, -8, -8, -8, -8, -8, -8,	/* 1f20-1f2f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00238 [NONE] `	0, 0, 0, 0, 0, 0, 0, 0, -8, -8, -8, -8, -8, -8, -8, -8,	/* 1f30-1f3f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00239 [NONE] `	0, 0, 0, 0, 0, 0, 0, 0, -8, -8, -8, -8, -8, -8, 0, 0,	/* 1f40-1f4f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00240 [NONE] `	0, 0, 0, 0, 0, 0, 0, 0, 0, -8, 0, -8, 0, -8, 0, -8,	/* 1f50-1f5f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00241 [NONE] `	0, 0, 0, 0, 0, 0, 0, 0, -8, -8, -8, -8, -8, -8, -8, -8,	/* 1f60-1f6f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00242 [NONE] `	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,	/* 1f70-1f7f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00243 [NONE] `	0, 0, 0, 0, 0, 0, 0, 0, -8, -8, -8, -8, -8, -8, -8, -8,	/* 1f80-1f8f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00244 [NONE] `	0, 0, 0, 0, 0, 0, 0, 0, -8, -8, -8, -8, -8, -8, -8, -8,	/* 1f90-1f9f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00245 [NONE] `	0, 0, 0, 0, 0, 0, 0, 0, -8, -8, -8, -8, -8, -8, -8, -8,	/* 1fa0-1faf */`
  Review: Low-risk line; verify in surrounding control flow.
- L00246 [NONE] `	0, 0, 0, 0, 0, 0, 0, 0, -8, -8, -74, -74, -9, 0, 0, 0,	/* 1fb0-1fbf */`
  Review: Low-risk line; verify in surrounding control flow.
- L00247 [NONE] `	0, 0, 0, 0, 0, 0, 0, 0, -86, -86, -86, -86, -9, 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L00248 [NONE] `							 0, 0,	/* 1fc0-1fcf */`
  Review: Low-risk line; verify in surrounding control flow.
- L00249 [NONE] `	0, 0, 0, 0, 0, 0, 0, 0, -8, -8, -100, -100, 0, 0, 0, 0,	/* 1fd0-1fdf */`
  Review: Low-risk line; verify in surrounding control flow.
- L00250 [NONE] `	0, 0, 0, 0, 0, 0, 0, 0, -8, -8, -112, -112, -7, 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L00251 [NONE] `							 0, 0,	/* 1fe0-1fef */`
  Review: Low-risk line; verify in surrounding control flow.
- L00252 [NONE] `	0, 0, 0, 0, 0, 0, 0, 0,`
  Review: Low-risk line; verify in surrounding control flow.
- L00253 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00254 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00255 [NONE] `/* Lower case range - Wide latin */`
  Review: Low-risk line; verify in surrounding control flow.
- L00256 [NONE] `static signed char UniCaseRangeLff20[27] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00257 [NONE] `	0, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,`
  Review: Low-risk line; verify in surrounding control flow.
- L00258 [NONE] `							 32,	/* ff20-ff2f */`
  Review: Low-risk line; verify in surrounding control flow.
- L00259 [NONE] `	32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,`
  Review: Low-risk line; verify in surrounding control flow.
- L00260 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00261 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00262 [NONE] `/*`
  Review: Low-risk line; verify in surrounding control flow.
- L00263 [NONE] ` * Lower Case Range`
  Review: Low-risk line; verify in surrounding control flow.
- L00264 [NONE] ` */`
  Review: Low-risk line; verify in surrounding control flow.
- L00265 [NONE] `static const struct UniCaseRange CifsUniLowerRange[] = {`
  Review: Low-risk line; verify in surrounding control flow.
- L00266 [NONE] `	{0x0380, 0x03ab, UniCaseRangeL0380},`
  Review: Low-risk line; verify in surrounding control flow.
- L00267 [NONE] `	{0x0400, 0x042f, UniCaseRangeL0400},`
  Review: Low-risk line; verify in surrounding control flow.
- L00268 [NONE] `	{0x0490, 0x04cb, UniCaseRangeL0490},`
  Review: Low-risk line; verify in surrounding control flow.
- L00269 [NONE] `	{0x1e00, 0x1ff7, UniCaseRangeL1e00},`
  Review: Low-risk line; verify in surrounding control flow.
- L00270 [NONE] `	{0xff20, 0xff3a, UniCaseRangeLff20},`
  Review: Low-risk line; verify in surrounding control flow.
- L00271 [NONE] `	{0}`
  Review: Low-risk line; verify in surrounding control flow.
- L00272 [NONE] `};`
  Review: Low-risk line; verify in surrounding control flow.
- L00273 [NONE] `#endif`
  Review: Low-risk line; verify in surrounding control flow.
- L00274 [NONE] ``
  Review: Low-risk line; verify in surrounding control flow.
- L00275 [NONE] `#endif /* __KSMBD_UNIUPR_H */`
  Review: Low-risk line; verify in surrounding control flow.
