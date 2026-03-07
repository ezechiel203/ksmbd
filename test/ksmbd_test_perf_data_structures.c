// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2026 ksmbd contributors
 *
 *   KUnit micro-benchmark tests for ksmbd internal data structures.
 *
 *   Measures performance of hash table lookups, ID allocation, list
 *   traversals, and other data structure operations that are on the
 *   critical path of SMB request processing.
 *
 *   All data structures are replicated locally (self-contained pattern).
 *   These mirrors are intentional: the benchmarks measure generic data
 *   structure performance (hash table, xarray, linked list) in isolation,
 *   without requiring live ksmbd module state (connection tables, session
 *   xarrays, oplock lists, etc.). Wiring to production exports would
 *   require full connection/session lifecycle setup which is inappropriate
 *   for micro-benchmarks.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/ktime.h>
#include <linux/random.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/hashtable.h>
#include <linux/xarray.h>
#include <linux/idr.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/rwsem.h>
#include <linux/jhash.h>
#include <linux/hash.h>
#include <linux/cache.h>

/* ========================================================================
 * Configurable iteration counts
 * ======================================================================== */

#define DS_ITERS		10000
#define DS_ITERS_HEAVY		100000

/* ========================================================================
 * Benchmark reporting macros
 * ======================================================================== */

#define BENCH_REPORT(test, name, iters, total_ns, extra)		\
	kunit_info(test,						\
		   "BENCHMARK: %s iters=%u total_ns=%llu "		\
		   "per_iter_ns=%llu %s\n",				\
		   (name), (unsigned int)(iters),			\
		   (unsigned long long)(total_ns),			\
		   (unsigned long long)((total_ns) / (iters)),		\
		   (extra))

/* ========================================================================
 * Connection hash table -- replicated from connection.c
 *
 * ksmbd uses a hash table indexed by client IP address for fast
 * connection lookup. We replicate the structure with 256 buckets.
 * ======================================================================== */

#define PERF_CONN_HASH_BITS	8

struct perf_conn_entry {
	u32			addr;
	u64			session_id;
	struct hlist_node	hnode;
};

static DEFINE_HASHTABLE(perf_conn_table, PERF_CONN_HASH_BITS);

static void perf_conn_table_insert(struct perf_conn_entry *entry)
{
	hash_add(perf_conn_table, &entry->hnode, entry->addr);
}

static struct perf_conn_entry *perf_conn_table_lookup(u32 addr)
{
	struct perf_conn_entry *entry;

	hash_for_each_possible(perf_conn_table, entry, hnode, addr) {
		if (entry->addr == addr)
			return entry;
	}
	return NULL;
}

/* ========================================================================
 * Benchmark 1: Connection hash table lookup -- 1000 lookups in 256 buckets
 * ======================================================================== */

static void test_perf_conn_hash_lookup(struct kunit *test)
{
	struct perf_conn_entry *entries;
	u64 start, elapsed;
	int i;
	unsigned int found_count = 0;

	entries = kzalloc(1000 * sizeof(*entries), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, entries);

	hash_init(perf_conn_table);

	/* Insert 1000 connections */
	for (i = 0; i < 1000; i++) {
		entries[i].addr = (u32)(0xC0A80000 + i); /* 192.168.x.y */
		entries[i].session_id = (u64)i + 1;
		perf_conn_table_insert(&entries[i]);
	}

	/* Verify lookup works */
	{
		struct perf_conn_entry *e;

		e = perf_conn_table_lookup(0xC0A80000);
		KUNIT_ASSERT_NOT_NULL(test, e);
		KUNIT_ASSERT_EQ(test, e->session_id, 1ULL);
	}

	/* Benchmark: 1000 lookups per iteration */
	start = ktime_get_ns();
	for (i = 0; i < DS_ITERS; i++) {
		int j;

		for (j = 0; j < 1000; j++) {
			u32 addr = 0xC0A80000 + (j ^ (i & 0xFF));
			struct perf_conn_entry *e;

			e = perf_conn_table_lookup(addr);
			if (e)
				found_count++;
		}
	}
	elapsed = ktime_get_ns() - start;

	KUNIT_EXPECT_GT(test, found_count, 0U);

	BENCH_REPORT(test, "conn_hash_1000_lookups",
		     DS_ITERS, elapsed, "1000_lookups_per_iter");

	kfree(entries);
}

/* ========================================================================
 * File ID lookup -- IDR/xarray performance
 *
 * ksmbd uses xarray (via IDR) for volatile file ID allocation and lookup.
 * ======================================================================== */

struct perf_file_entry {
	u64 persistent_id;
	u64 volatile_id;
	u32 access_mask;
};

/* ========================================================================
 * Benchmark 2: File ID lookup via xarray
 * ======================================================================== */

static void test_perf_file_id_lookup(struct kunit *test)
{
	struct xarray xa;
	struct perf_file_entry *entries;
	u64 start, elapsed;
	int i;
	unsigned int found_count = 0;

	xa_init(&xa);

	entries = kzalloc(1000 * sizeof(*entries), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, entries);

	/* Insert 1000 file entries */
	for (i = 0; i < 1000; i++) {
		entries[i].persistent_id = (u64)i + 1;
		entries[i].volatile_id = (u64)i;
		entries[i].access_mask = 0x1F01FF;
		xa_store(&xa, i, &entries[i], GFP_KERNEL);
	}

	/* Verify */
	{
		struct perf_file_entry *e = xa_load(&xa, 0);

		KUNIT_ASSERT_NOT_NULL(test, e);
		KUNIT_ASSERT_EQ(test, e->persistent_id, 1ULL);
	}

	/* Benchmark */
	start = ktime_get_ns();
	for (i = 0; i < DS_ITERS; i++) {
		int j;

		for (j = 0; j < 1000; j++) {
			unsigned long idx = (j + i) % 1000;
			struct perf_file_entry *e = xa_load(&xa, idx);

			if (e)
				found_count++;
		}
	}
	elapsed = ktime_get_ns() - start;

	KUNIT_EXPECT_EQ(test, found_count, (unsigned int)(DS_ITERS * 1000));

	BENCH_REPORT(test, "file_id_xarray_1000_lookups",
		     DS_ITERS, elapsed, "1000_lookups_per_iter");

	xa_destroy(&xa);
	kfree(entries);
}

/* ========================================================================
 * Oplock list -- replicated from oplock.c
 *
 * ksmbd maintains a linked list of oplock_info per ksmbd_inode.
 * ======================================================================== */

struct perf_oplock_entry {
	int			level;
	u64			fid;
	atomic_t		refcount;
	struct list_head	op_entry;
};

/* ========================================================================
 * Benchmark 3: Oplock list traversal -- walk list of 100 oplocks
 * ======================================================================== */

static void test_perf_oplock_list_walk(struct kunit *test)
{
	struct list_head oplock_list;
	struct perf_oplock_entry *entries;
	u64 start, elapsed;
	int i;
	unsigned int walk_count = 0;

	INIT_LIST_HEAD(&oplock_list);

	entries = kzalloc(100 * sizeof(*entries), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, entries);

	/* Insert 100 oplock entries */
	for (i = 0; i < 100; i++) {
		entries[i].level = (i % 4); /* none/exclusive/batch/read */
		entries[i].fid = (u64)i + 1;
		atomic_set(&entries[i].refcount, 1);
		list_add_tail(&entries[i].op_entry, &oplock_list);
	}

	/* Verify */
	{
		struct perf_oplock_entry *e;
		int count = 0;

		list_for_each_entry(e, &oplock_list, op_entry)
			count++;
		KUNIT_ASSERT_EQ(test, count, 100);
	}

	/* Benchmark: walk entire list looking for a specific FID */
	start = ktime_get_ns();
	for (i = 0; i < DS_ITERS; i++) {
		struct perf_oplock_entry *e;
		u64 target_fid = (u64)(i % 100) + 1;

		list_for_each_entry(e, &oplock_list, op_entry) {
			if (e->fid == target_fid) {
				walk_count++;
				break;
			}
		}
	}
	elapsed = ktime_get_ns() - start;

	KUNIT_EXPECT_EQ(test, walk_count, (unsigned int)DS_ITERS);

	BENCH_REPORT(test, "oplock_list_walk_100",
		     DS_ITERS, elapsed, "search_in_100_entries");

	kfree(entries);
}

/* ========================================================================
 * Lock list -- replicated from vfs_cache.h
 *
 * ksmbd maintains lock lists per file for byte-range lock checking.
 * ======================================================================== */

struct perf_lock_entry {
	unsigned long long	start;
	unsigned long long	end;
	unsigned int		flags;
	struct list_head	llist;
};

/* Check if two lock ranges overlap */
static bool perf_locks_overlap(struct perf_lock_entry *a,
			       struct perf_lock_entry *b)
{
	return a->start <= b->end && b->start <= a->end;
}

/* ========================================================================
 * Benchmark 4: Lock list scan -- check 1000 locks for overlap
 * ======================================================================== */

static void test_perf_lock_scan(struct kunit *test)
{
	struct list_head lock_list;
	struct perf_lock_entry *entries;
	u64 start, elapsed;
	int i;
	unsigned int overlap_count = 0;

	INIT_LIST_HEAD(&lock_list);

	entries = kzalloc(1000 * sizeof(*entries), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, entries);

	/* Insert 1000 non-overlapping locks (each 1024 bytes) */
	for (i = 0; i < 1000; i++) {
		entries[i].start = (unsigned long long)i * 1024;
		entries[i].end = entries[i].start + 1023;
		entries[i].flags = 0;
		list_add_tail(&entries[i].llist, &lock_list);
	}

	/* Verify: lock at offset 512 should overlap with entry 0 */
	{
		struct perf_lock_entry test_lock = {
			.start = 512, .end = 600
		};
		struct perf_lock_entry *e;
		bool found = false;

		list_for_each_entry(e, &lock_list, llist) {
			if (perf_locks_overlap(e, &test_lock)) {
				found = true;
				break;
			}
		}
		KUNIT_ASSERT_TRUE(test, found);
	}

	/* Benchmark: check for overlap at random positions */
	start = ktime_get_ns();
	for (i = 0; i < DS_ITERS; i++) {
		struct perf_lock_entry test_lock;
		struct perf_lock_entry *e;

		/* Position lock at middle of some existing range */
		test_lock.start = ((i * 37) % 1000) * 1024 + 100;
		test_lock.end = test_lock.start + 200;

		list_for_each_entry(e, &lock_list, llist) {
			if (perf_locks_overlap(e, &test_lock)) {
				overlap_count++;
				break;
			}
		}
	}
	elapsed = ktime_get_ns() - start;

	KUNIT_EXPECT_GT(test, overlap_count, 0U);

	BENCH_REPORT(test, "lock_scan_1000_entries",
		     DS_ITERS, elapsed, "overlap_check_per_iter");

	kfree(entries);
}

/* ========================================================================
 * Lease table -- replicated from oplock.c
 *
 * Lease table maps client GUID to a list of leases. Lookup by lease key
 * traverses the per-client lease list.
 * ======================================================================== */

#define PERF_LEASE_KEY_SIZE	16

struct perf_lease_entry {
	u8			lease_key[PERF_LEASE_KEY_SIZE];
	__le32			state;
	struct list_head	lease_entry;
};

struct perf_lease_table {
	u8			client_guid[16];
	struct list_head	lease_list;
	struct list_head	l_entry;
};

/* ========================================================================
 * Benchmark 5: Lease table lookup -- find lease by key
 * ======================================================================== */

static void test_perf_lease_lookup(struct kunit *test)
{
	struct perf_lease_table ltable;
	struct perf_lease_entry *entries;
	u64 start, elapsed;
	int i;
	unsigned int found_count = 0;

	INIT_LIST_HEAD(&ltable.lease_list);
	get_random_bytes(ltable.client_guid, 16);

	entries = kzalloc(100 * sizeof(*entries), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, entries);

	/* Insert 100 leases with unique keys */
	for (i = 0; i < 100; i++) {
		memset(entries[i].lease_key, 0, PERF_LEASE_KEY_SIZE);
		entries[i].lease_key[0] = (u8)(i & 0xFF);
		entries[i].lease_key[1] = (u8)((i >> 8) & 0xFF);
		entries[i].state = cpu_to_le32(0x07); /* RWH */
		list_add_tail(&entries[i].lease_entry, &ltable.lease_list);
	}

	/* Verify */
	{
		struct perf_lease_entry *e;
		u8 search_key[PERF_LEASE_KEY_SIZE] = {0};
		bool found = false;

		search_key[0] = 50;
		list_for_each_entry(e, &ltable.lease_list, lease_entry) {
			if (memcmp(e->lease_key, search_key,
				   PERF_LEASE_KEY_SIZE) == 0) {
				found = true;
				break;
			}
		}
		KUNIT_ASSERT_TRUE(test, found);
	}

	/* Benchmark */
	start = ktime_get_ns();
	for (i = 0; i < DS_ITERS; i++) {
		struct perf_lease_entry *e;
		u8 search_key[PERF_LEASE_KEY_SIZE] = {0};

		search_key[0] = (u8)(i % 100);
		list_for_each_entry(e, &ltable.lease_list, lease_entry) {
			if (memcmp(e->lease_key, search_key,
				   PERF_LEASE_KEY_SIZE) == 0) {
				found_count++;
				break;
			}
		}
	}
	elapsed = ktime_get_ns() - start;

	KUNIT_EXPECT_EQ(test, found_count, (unsigned int)DS_ITERS);

	BENCH_REPORT(test, "lease_lookup_100_entries",
		     DS_ITERS, elapsed, "memcmp_search_per_iter");

	kfree(entries);
}

/* ========================================================================
 * Session table -- replicated from connection.c / user_session.c
 *
 * ksmbd uses xarray for session lookup by session ID.
 * ======================================================================== */

struct perf_session_entry {
	u64 session_id;
	u16 dialect;
	u32 flags;
};

/* ========================================================================
 * Benchmark 6: Session table lookup -- find session by ID
 * ======================================================================== */

static void test_perf_session_lookup(struct kunit *test)
{
	struct xarray sessions;
	struct perf_session_entry *entries;
	u64 start, elapsed;
	int i;
	unsigned int found_count = 0;

	xa_init(&sessions);

	entries = kzalloc(256 * sizeof(*entries), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, entries);

	/* Insert 256 sessions */
	for (i = 0; i < 256; i++) {
		entries[i].session_id = ((u64)(i + 1) << 32) | (i + 1);
		entries[i].dialect = 0x0311; /* SMB 3.1.1 */
		entries[i].flags = 0;
		xa_store(&sessions, i + 1, &entries[i], GFP_KERNEL);
	}

	/* Verify */
	{
		struct perf_session_entry *s = xa_load(&sessions, 1);

		KUNIT_ASSERT_NOT_NULL(test, s);
		KUNIT_ASSERT_EQ(test, s->dialect, 0x0311);
	}

	/* Benchmark */
	start = ktime_get_ns();
	for (i = 0; i < DS_ITERS_HEAVY; i++) {
		unsigned long idx = (i % 256) + 1;
		struct perf_session_entry *s = xa_load(&sessions, idx);

		if (s)
			found_count++;
	}
	elapsed = ktime_get_ns() - start;

	KUNIT_EXPECT_EQ(test, found_count, (unsigned int)DS_ITERS_HEAVY);

	BENCH_REPORT(test, "session_xarray_lookup",
		     DS_ITERS_HEAVY, elapsed, "ops/sec");

	xa_destroy(&sessions);
	kfree(entries);
}

/* ========================================================================
 * Share config lookup -- replicated from share_config.c
 *
 * Share configs are stored in a hash table keyed by share name hash.
 * ======================================================================== */

#define PERF_SHARE_HASH_BITS	6

struct perf_share_config {
	char			name[80];
	u32			name_hash;
	unsigned int		flags;
	struct hlist_node	hnode;
};

static DEFINE_HASHTABLE(perf_share_table, PERF_SHARE_HASH_BITS);

static u32 perf_share_name_hash(const char *name)
{
	return jhash(name, strlen(name), 0);
}

static struct perf_share_config *perf_share_lookup(const char *name)
{
	u32 h = perf_share_name_hash(name);
	struct perf_share_config *sc;

	hash_for_each_possible(perf_share_table, sc, hnode, h) {
		if (strcmp(sc->name, name) == 0)
			return sc;
	}
	return NULL;
}

/* ========================================================================
 * Benchmark 7: Share config lookup -- find share by name hash
 * ======================================================================== */

static void test_perf_share_lookup(struct kunit *test)
{
	struct perf_share_config *shares;
	u64 start, elapsed;
	int i;
	unsigned int found_count = 0;
	char names[32][80];

	hash_init(perf_share_table);

	shares = kzalloc(32 * sizeof(*shares), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, shares);

	/* Insert 32 shares with typical names */
	for (i = 0; i < 32; i++) {
		snprintf(names[i], 80, "share_%02d_department_%c",
			 i, 'A' + (i % 26));
		strscpy(shares[i].name, names[i], 80);
		shares[i].name_hash = perf_share_name_hash(names[i]);
		shares[i].flags = 0x1234;
		hash_add(perf_share_table, &shares[i].hnode,
			 shares[i].name_hash);
	}

	/* Verify */
	{
		struct perf_share_config *sc = perf_share_lookup(names[0]);

		KUNIT_ASSERT_NOT_NULL(test, sc);
		KUNIT_ASSERT_EQ(test, sc->flags, 0x1234U);
	}

	/* Benchmark */
	start = ktime_get_ns();
	for (i = 0; i < DS_ITERS_HEAVY; i++) {
		struct perf_share_config *sc;

		sc = perf_share_lookup(names[i % 32]);
		if (sc)
			found_count++;
	}
	elapsed = ktime_get_ns() - start;

	KUNIT_EXPECT_EQ(test, found_count, (unsigned int)DS_ITERS_HEAVY);

	BENCH_REPORT(test, "share_config_hash_lookup",
		     DS_ITERS_HEAVY, elapsed, "ops/sec");

	kfree(shares);
}

/* ========================================================================
 * VFS inode hash -- replicated from vfs_cache.c
 *
 * ksmbd maintains a hash table of ksmbd_inode structures keyed by
 * inode number for fast lookup during file operations.
 * ======================================================================== */

#define PERF_INODE_HASH_BITS	10
#define PERF_INODE_HASH_SIZE	(1 << PERF_INODE_HASH_BITS)
#define PERF_INODE_HASH_MASK	(PERF_INODE_HASH_SIZE - 1)

struct perf_ksmbd_inode {
	unsigned long		ino;
	unsigned long		sb_hash;
	atomic_t		m_count;
	unsigned int		m_flags;
	struct hlist_node	m_hash;
};

static struct hlist_head perf_inode_hashtable[PERF_INODE_HASH_SIZE];

static unsigned int perf_inode_hash(unsigned long sb, unsigned long ino)
{
	unsigned long tmp;

	tmp = (ino * sb) ^ (GOLDEN_RATIO_PRIME + ino) / L1_CACHE_BYTES;
	tmp = tmp ^ ((tmp ^ GOLDEN_RATIO_PRIME) >> PERF_INODE_HASH_BITS);
	return tmp & PERF_INODE_HASH_MASK;
}

static struct perf_ksmbd_inode *perf_inode_lookup(unsigned long sb,
						  unsigned long ino)
{
	unsigned int bucket = perf_inode_hash(sb, ino);
	struct perf_ksmbd_inode *ci;

	hlist_for_each_entry(ci, &perf_inode_hashtable[bucket], m_hash) {
		if (ci->ino == ino && ci->sb_hash == sb)
			return ci;
	}
	return NULL;
}

/* ========================================================================
 * Benchmark 8: VFS inode hash lookup
 * ======================================================================== */

static void test_perf_inode_hash_lookup(struct kunit *test)
{
	struct perf_ksmbd_inode *inodes;
	unsigned long fake_sb = 0xDEADBEEF12345678UL;
	u64 start, elapsed;
	int i;
	unsigned int found_count = 0;

	/* Initialize hash table */
	for (i = 0; i < PERF_INODE_HASH_SIZE; i++)
		INIT_HLIST_HEAD(&perf_inode_hashtable[i]);

	inodes = kzalloc(1000 * sizeof(*inodes), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, inodes);

	/* Insert 1000 inodes */
	for (i = 0; i < 1000; i++) {
		unsigned int bucket;

		inodes[i].ino = (unsigned long)(i + 1) * 4096;
		inodes[i].sb_hash = fake_sb;
		atomic_set(&inodes[i].m_count, 1);
		inodes[i].m_flags = 0;

		bucket = perf_inode_hash(fake_sb, inodes[i].ino);
		hlist_add_head(&inodes[i].m_hash,
			       &perf_inode_hashtable[bucket]);
	}

	/* Verify */
	{
		struct perf_ksmbd_inode *ci;

		ci = perf_inode_lookup(fake_sb, 4096);
		KUNIT_ASSERT_NOT_NULL(test, ci);
		KUNIT_ASSERT_EQ(test, ci->ino, 4096UL);
	}

	/* Benchmark */
	start = ktime_get_ns();
	for (i = 0; i < DS_ITERS; i++) {
		int j;

		for (j = 0; j < 100; j++) {
			unsigned long ino = ((unsigned long)((j + i) % 1000) + 1) * 4096;
			struct perf_ksmbd_inode *ci;

			ci = perf_inode_lookup(fake_sb, ino);
			if (ci)
				found_count++;
		}
	}
	elapsed = ktime_get_ns() - start;

	KUNIT_EXPECT_EQ(test, found_count, (unsigned int)(DS_ITERS * 100));

	BENCH_REPORT(test, "inode_hash_100_lookups",
		     DS_ITERS, elapsed, "100_lookups_per_iter");

	kfree(inodes);
}

/* ========================================================================
 * Test suite registration
 * ======================================================================== */

static struct kunit_case ksmbd_perf_data_structures_cases[] = {
	KUNIT_CASE(test_perf_conn_hash_lookup),
	KUNIT_CASE(test_perf_file_id_lookup),
	KUNIT_CASE(test_perf_oplock_list_walk),
	KUNIT_CASE(test_perf_lock_scan),
	KUNIT_CASE(test_perf_lease_lookup),
	KUNIT_CASE(test_perf_session_lookup),
	KUNIT_CASE(test_perf_share_lookup),
	KUNIT_CASE(test_perf_inode_hash_lookup),
	{}
};

static struct kunit_suite ksmbd_perf_data_structures_suite = {
	.name = "ksmbd_perf_data_structures",
	.test_cases = ksmbd_perf_data_structures_cases,
};

kunit_test_suite(ksmbd_perf_data_structures_suite);

MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit micro-benchmarks for ksmbd internal data structures");
