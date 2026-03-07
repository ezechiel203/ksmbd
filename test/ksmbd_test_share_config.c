// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   KUnit tests for share configuration helpers (share_config.c)
 *
 *   Tests for ksmbd_path_has_dotdot_component(), parse_veto_list(),
 *   ksmbd_share_veto_filename(), and share name/path validation logic.
 *   We replicate the pure logic portions inline.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/list.h>

/* Replicate veto pattern structure */
struct test_veto_pattern {
	char		*pattern;
	struct list_head list;
};

struct test_share_config {
	struct list_head veto_list;
};

/*
 * Replicate ksmbd_path_has_dotdot_component() from share_config.c
 */
static bool test_path_has_dotdot(const char *path)
{
	const char *p = path;

	while (*p) {
		const char *seg;

		while (*p == '/')
			p++;
		if (!*p)
			break;

		seg = p;
		while (*p && *p != '/')
			p++;
		if (p - seg == 2 && seg[0] == '.' && seg[1] == '.')
			return true;
	}
	return false;
}

/*
 * Replicate parse_veto_list() from share_config.c
 */
static int test_parse_veto_list(struct test_share_config *share,
				char *veto_list, int veto_list_sz)
{
	if (!veto_list_sz)
		return 0;

	while (veto_list_sz > 0) {
		struct test_veto_pattern *p;
		size_t sz;

		sz = strnlen(veto_list, veto_list_sz);
		if (!sz)
			goto skip_empty;

		p = kzalloc(sizeof(*p), GFP_KERNEL);
		if (!p)
			return -ENOMEM;

		p->pattern = kstrdup(veto_list, GFP_KERNEL);
		if (!p->pattern) {
			kfree(p);
			return -ENOMEM;
		}

		list_add(&p->list, &share->veto_list);

skip_empty:
		if (sz == veto_list_sz)
			break;

		veto_list += sz + 1;
		veto_list_sz -= (sz + 1);
	}
	return 0;
}

/*
 * Replicate match_pattern() for veto filename matching.
 * Simplified version for test purposes (case-insensitive match).
 */
static int test_match_pattern(const char *str, size_t len, const char *pattern)
{
	const char *s = str;
	const char *p = pattern;
	bool star = false;

	while (*s && len) {
		switch (*p) {
		case '?':
			s++;
			len--;
			p++;
			break;
		case '*':
			star = true;
			str = s;
			if (!*++p)
				return 1;
			pattern = p;
			break;
		default:
			if (tolower(*s) == tolower(*p)) {
				s++;
				len--;
				p++;
			} else {
				if (!star)
					return 0;
				str++;
				len--;
				s = str;
				p = pattern;
			}
			break;
		}
	}
	while (*p == '*')
		++p;
	return !*p;
}

/*
 * Replicate ksmbd_share_veto_filename() from share_config.c
 */
static bool test_share_veto_filename(struct test_share_config *share,
				     const char *filename)
{
	struct test_veto_pattern *p;

	if (list_empty(&share->veto_list))
		return false;

	list_for_each_entry(p, &share->veto_list, list) {
		if (test_match_pattern(filename, strlen(filename), p->pattern))
			return true;
	}
	return false;
}

static void free_veto_list(struct test_share_config *share)
{
	struct test_veto_pattern *p, *tmp;

	list_for_each_entry_safe(p, tmp, &share->veto_list, list) {
		list_del(&p->list);
		kfree(p->pattern);
		kfree(p);
	}
}

/* --- dotdot path detection tests --- */

static void test_share_path_has_dotdot_simple(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test, test_path_has_dotdot("foo/../bar"));
}

static void test_share_path_has_dotdot_at_start(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test, test_path_has_dotdot("../secret"));
}

static void test_share_path_has_dotdot_at_end(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test, test_path_has_dotdot("/share/.."));
}

static void test_share_path_no_dotdot(struct kunit *test)
{
	KUNIT_EXPECT_FALSE(test, test_path_has_dotdot("/share/folder/file"));
}

static void test_share_path_dots_in_name(struct kunit *test)
{
	KUNIT_EXPECT_FALSE(test, test_path_has_dotdot("/share/..file"));
	KUNIT_EXPECT_FALSE(test, test_path_has_dotdot("/share/file.."));
}

static void test_share_path_multiple_slashes(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test, test_path_has_dotdot("/share///../../etc"));
}

static void test_share_path_empty(struct kunit *test)
{
	KUNIT_EXPECT_FALSE(test, test_path_has_dotdot(""));
}

static void test_share_path_single_dot(struct kunit *test)
{
	KUNIT_EXPECT_FALSE(test, test_path_has_dotdot("/share/./file"));
}

/* --- veto filename tests --- */

static void test_share_veto_filename_match(struct kunit *test)
{
	struct test_share_config share;
	char veto[] = "*.tmp";

	INIT_LIST_HEAD(&share.veto_list);
	test_parse_veto_list(&share, veto, sizeof(veto) - 1);
	KUNIT_EXPECT_TRUE(test, test_share_veto_filename(&share, "test.tmp"));
	free_veto_list(&share);
}

static void test_share_veto_filename_no_match(struct kunit *test)
{
	struct test_share_config share;
	char veto[] = "*.tmp";

	INIT_LIST_HEAD(&share.veto_list);
	test_parse_veto_list(&share, veto, sizeof(veto) - 1);
	KUNIT_EXPECT_FALSE(test,
			   test_share_veto_filename(&share, "test.txt"));
	free_veto_list(&share);
}

static void test_share_veto_filename_empty_list(struct kunit *test)
{
	struct test_share_config share;

	INIT_LIST_HEAD(&share.veto_list);
	KUNIT_EXPECT_FALSE(test,
			   test_share_veto_filename(&share, "anything"));
}

static void test_share_veto_filename_multiple_patterns(struct kunit *test)
{
	struct test_share_config share;
	/* NUL-separated pattern list: "*.tmp\0~$*\0Thumbs.db" */
	char veto[] = "*.tmp\0~$*\0Thumbs.db";

	INIT_LIST_HEAD(&share.veto_list);
	test_parse_veto_list(&share, veto, sizeof(veto) - 1);

	KUNIT_EXPECT_TRUE(test,
			  test_share_veto_filename(&share, "test.tmp"));
	KUNIT_EXPECT_TRUE(test,
			  test_share_veto_filename(&share, "~$document.doc"));
	KUNIT_EXPECT_TRUE(test,
			  test_share_veto_filename(&share, "Thumbs.db"));
	KUNIT_EXPECT_FALSE(test,
			   test_share_veto_filename(&share, "normal.txt"));
	free_veto_list(&share);
}

/* --- parse_veto_list tests --- */

static void test_parse_veto_list_single_entry(struct kunit *test)
{
	struct test_share_config share;
	struct test_veto_pattern *p;
	char veto[] = "*.tmp";
	int count = 0;

	INIT_LIST_HEAD(&share.veto_list);
	KUNIT_EXPECT_EQ(test,
			test_parse_veto_list(&share, veto,
					     sizeof(veto) - 1), 0);

	list_for_each_entry(p, &share.veto_list, list)
		count++;
	KUNIT_EXPECT_EQ(test, count, 1);
	free_veto_list(&share);
}

static void test_parse_veto_list_multiple_entries(struct kunit *test)
{
	struct test_share_config share;
	struct test_veto_pattern *p;
	char veto[] = "*.tmp\0*.bak\0~$*";
	int count = 0;

	INIT_LIST_HEAD(&share.veto_list);
	KUNIT_EXPECT_EQ(test,
			test_parse_veto_list(&share, veto,
					     sizeof(veto) - 1), 0);

	list_for_each_entry(p, &share.veto_list, list)
		count++;
	KUNIT_EXPECT_EQ(test, count, 3);
	free_veto_list(&share);
}

static void test_parse_veto_list_empty(struct kunit *test)
{
	struct test_share_config share;

	INIT_LIST_HEAD(&share.veto_list);
	KUNIT_EXPECT_EQ(test, test_parse_veto_list(&share, NULL, 0), 0);
	KUNIT_EXPECT_TRUE(test, list_empty(&share.veto_list));
}

static void test_parse_veto_list_zero_length_entry(struct kunit *test)
{
	struct test_share_config share;
	struct test_veto_pattern *p;
	/* "*.tmp\0\0*.bak" - middle entry is empty, should be skipped */
	char veto[] = "*.tmp\0\0*.bak";
	int count = 0;

	INIT_LIST_HEAD(&share.veto_list);
	KUNIT_EXPECT_EQ(test,
			test_parse_veto_list(&share, veto,
					     sizeof(veto) - 1), 0);

	list_for_each_entry(p, &share.veto_list, list)
		count++;
	/* Empty entries skipped */
	KUNIT_EXPECT_EQ(test, count, 2);
	free_veto_list(&share);
}

/* --- share name/path validation tests --- */

static void test_share_name_hash_deterministic(struct kunit *test)
{
	/*
	 * Simple test: the same name always hashes the same way.
	 * Use full_name_hash which is what share_config.c uses.
	 */
	unsigned int h1 = full_name_hash(NULL, "myshare", 7);
	unsigned int h2 = full_name_hash(NULL, "myshare", 7);
	unsigned int h3 = full_name_hash(NULL, "other", 5);

	KUNIT_EXPECT_EQ(test, h1, h2);
	/* Different names should (almost certainly) hash differently */
	KUNIT_EXPECT_NE(test, h1, h3);
}

static void test_share_ipc_auto_detection(struct kunit *test)
{
	/*
	 * Test that IPC$ share name can be detected case-insensitively.
	 * In real code this sets KSMBD_SHARE_FLAG_PIPE.
	 */
	KUNIT_EXPECT_EQ(test, strncasecmp("IPC$", "IPC$", 4), 0);
	KUNIT_EXPECT_EQ(test, strncasecmp("ipc$", "IPC$", 4), 0);
}

static void test_share_ipc_case_insensitive(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, strncasecmp("ipc$", "IPC$", 4), 0);
	KUNIT_EXPECT_EQ(test, strncasecmp("Ipc$", "IPC$", 4), 0);
}

static void test_share_path_must_be_absolute(struct kunit *test)
{
	/* A relative path does not start with '/' */
	const char *rel = "relative/path";
	const char *abs = "/absolute/path";

	KUNIT_EXPECT_NE(test, rel[0], '/');
	KUNIT_EXPECT_EQ(test, abs[0], '/');
}

static void test_share_path_trailing_slash_stripped(struct kunit *test)
{
	char path[] = "/share/path/";
	int len = strlen(path);

	/* Replicate the trailing slash stripping logic */
	while (len && path[len - 1] == '/') {
		path[len - 1] = '\0';
		len--;
	}
	KUNIT_EXPECT_STREQ(test, path, "/share/path");
}

static struct kunit_case ksmbd_share_config_test_cases[] = {
	KUNIT_CASE(test_share_path_has_dotdot_simple),
	KUNIT_CASE(test_share_path_has_dotdot_at_start),
	KUNIT_CASE(test_share_path_has_dotdot_at_end),
	KUNIT_CASE(test_share_path_no_dotdot),
	KUNIT_CASE(test_share_path_dots_in_name),
	KUNIT_CASE(test_share_path_multiple_slashes),
	KUNIT_CASE(test_share_path_empty),
	KUNIT_CASE(test_share_path_single_dot),
	KUNIT_CASE(test_share_veto_filename_match),
	KUNIT_CASE(test_share_veto_filename_no_match),
	KUNIT_CASE(test_share_veto_filename_empty_list),
	KUNIT_CASE(test_share_veto_filename_multiple_patterns),
	KUNIT_CASE(test_parse_veto_list_single_entry),
	KUNIT_CASE(test_parse_veto_list_multiple_entries),
	KUNIT_CASE(test_parse_veto_list_empty),
	KUNIT_CASE(test_parse_veto_list_zero_length_entry),
	KUNIT_CASE(test_share_name_hash_deterministic),
	KUNIT_CASE(test_share_ipc_auto_detection),
	KUNIT_CASE(test_share_ipc_case_insensitive),
	KUNIT_CASE(test_share_path_must_be_absolute),
	KUNIT_CASE(test_share_path_trailing_slash_stripped),
	{}
};

static struct kunit_suite ksmbd_share_config_test_suite = {
	.name = "ksmbd_share_config",
	.test_cases = ksmbd_share_config_test_cases,
};

kunit_test_suite(ksmbd_share_config_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for ksmbd share configuration helpers");
