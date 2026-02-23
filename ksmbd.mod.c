#include <linux/module.h>
#include <linux/export-internal.h>
#include <linux/compiler.h>

MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

KSYMTAB_FUNC(ksmbd_register_hook, "_gpl", "");
KSYMTAB_FUNC(ksmbd_unregister_hook, "_gpl", "");

SYMBOL_CRC(ksmbd_register_hook, 0x0705f42c, "_gpl");
SYMBOL_CRC(ksmbd_unregister_hook, 0xb79cee8e, "_gpl");

static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0xfa535a6e, "netdev_lower_get_next" },
	{ 0x0e37bdfe, "in6addr_any" },
	{ 0x63843d6c, "ib_mr_pool_destroy" },
	{ 0xc45d298e, "is_vmalloc_addr" },
	{ 0x435a8dfc, "vfs_fsync_range" },
	{ 0xd98156e2, "ida_alloc_range" },
	{ 0x6dce98f6, "vfs_removexattr" },
	{ 0xd124a4f1, "try_module_get" },
	{ 0x4ccd3848, "vfs_listxattr" },
	{ 0xd272d446, "rtnl_unlock" },
	{ 0xdb5c5ac9, "__init_rwsem" },
	{ 0x60b4d862, "ib_unregister_client" },
	{ 0x8e791ac6, "make_vfsgid" },
	{ 0xad6cccc1, "vfs_setxattr" },
	{ 0x4a17e238, "inode_to_bdi" },
	{ 0x95e7f442, "notify_change" },
	{ 0x5244a5dc, "idr_find" },
	{ 0x591a33c0, "vfs_getattr" },
	{ 0x2182515b, "__num_online_cpus" },
	{ 0xd272d446, "__rcu_read_lock" },
	{ 0xd2324953, "rdma_rw_ctx_destroy" },
	{ 0x178ab13a, "rdma_event_msg" },
	{ 0xb697aaa1, "vfs_rename" },
	{ 0x534ed5f3, "__msecs_to_jiffies" },
	{ 0xd710adbf, "__kmalloc_noprof" },
	{ 0xc94f00c2, "vmalloc_to_page" },
	{ 0x903e2e6d, "netif_get_flags" },
	{ 0x66146e3c, "lookup_one_unlocked" },
	{ 0xfbe7861b, "memmove" },
	{ 0x40a621c5, "snprintf" },
	{ 0x65026e43, "complete" },
	{ 0x49733ad6, "queue_work_on" },
	{ 0x4efd6424, "qid_valid" },
	{ 0xdd45951a, "sysfs_streq" },
	{ 0xd272d446, "__SCT__preempt_schedule" },
	{ 0x1764efa6, "__ib_alloc_pd" },
	{ 0xcd51c662, "iterate_dir" },
	{ 0xc87f4bab, "finish_wait" },
	{ 0xb0605e43, "dma_unmap_page_attrs" },
	{ 0x32043021, "abort_creds" },
	{ 0xd4121e05, "kernel_bind" },
	{ 0x7a102c0a, "utf8_load" },
	{ 0x5e505530, "set_freezable" },
	{ 0x10cb5f48, "load_nls_default" },
	{ 0x9b3986cc, "current_time" },
	{ 0xefa311be, "genlmsg_put" },
	{ 0x17dcc243, "fsnotify_put_mark" },
	{ 0xfbe7861b, "memcpy" },
	{ 0x3cbd8974, "from_vfsuid" },
	{ 0xcb8b6ec6, "kfree" },
	{ 0xda44a623, "sprint_oid" },
	{ 0x6f1e66c6, "seq_lseek" },
	{ 0x283c9533, "ib_mr_pool_init" },
	{ 0x62e676b1, "follow_down" },
	{ 0xe758f079, "sg_free_table_chained" },
	{ 0xaa040079, "kern_path_create" },
	{ 0x075cbd92, "crypto_alloc_aead" },
	{ 0xe53c6cf1, "groups_alloc" },
	{ 0x0feb1e94, "usleep_range_state" },
	{ 0x0db8d68d, "prepare_to_wait_event" },
	{ 0xe2f59f75, "out_of_line_wait_on_bit" },
	{ 0xf41396be, "crypto_aead_setauthsize" },
	{ 0x5e505530, "kthread_should_stop" },
	{ 0x47dc53e4, "crypto_aead_decrypt" },
	{ 0x0150efe8, "do_splice_direct" },
	{ 0x16ab4215, "__wake_up" },
	{ 0x367d7d88, "kernel_accept" },
	{ 0xb14708fa, "__module_get" },
	{ 0x755821f2, "ib_event_msg" },
	{ 0x1b821b52, "kernel_recvmsg" },
	{ 0x87294d95, "vfs_unlink" },
	{ 0xde338d9a, "_raw_spin_lock" },
	{ 0xe2878ef1, "mempool_free" },
	{ 0xa33df1be, "vfs_truncate" },
	{ 0x3fc737ed, "path_put" },
	{ 0x1f98a88f, "rdma_disconnect" },
	{ 0xad0e2c27, "vfs_copy_file_range" },
	{ 0xd272d446, "__fentry__" },
	{ 0xdd6830c7, "sysfs_emit" },
	{ 0x4cb7f3c8, "make_vfsuid" },
	{ 0x4560dde6, "match_wildcard" },
	{ 0x54ee534d, "__put_cred" },
	{ 0x55e4af36, "utf8_casefold" },
	{ 0x59dd1646, "static_key_count" },
	{ 0xae7ab2fe, "wake_up_process" },
	{ 0x17fb0101, "vfs_mkdir" },
	{ 0x4b132375, "dev_driver_string" },
	{ 0x462ecb4a, "static_key_disable" },
	{ 0xef5a197a, "vfs_statfs" },
	{ 0x519ffa96, "crypto_destroy_tfm" },
	{ 0x31eae322, "path_is_under" },
	{ 0x09dd69e9, "__refrigerator" },
	{ 0x5a844b26, "__x86_indirect_thunk_rax" },
	{ 0x303cd268, "dma_map_page_attrs" },
	{ 0x44decd6f, "freezer_active" },
	{ 0xbbec67a9, "fsnotify_alloc_group" },
	{ 0xe8213e80, "_printk" },
	{ 0xde338d9a, "_raw_spin_lock_irq" },
	{ 0x2d88a3ab, "disable_work_sync" },
	{ 0x95b255b8, "vfs_iter_read" },
	{ 0xd63bc22b, "vfs_fallocate" },
	{ 0x5629a063, "strncasecmp" },
	{ 0xbd03ed67, "__ref_stack_chk_guard" },
	{ 0xff7fbdd1, "___ratelimit" },
	{ 0x6ac784f4, "schedule_timeout" },
	{ 0xd272d446, "schedule" },
	{ 0xd272d446, "__stack_chk_fail" },
	{ 0x5fe3f23a, "__rdma_create_kernel_id" },
	{ 0x2520ea93, "refcount_warn_saturate" },
	{ 0x8ce83585, "queue_delayed_work_on" },
	{ 0xd4c931e4, "load_nls" },
	{ 0x59fac341, "make_kuid" },
	{ 0xfd018218, "mnt_want_write" },
	{ 0x9479a1e8, "strnlen" },
	{ 0x255d3d76, "__alloc_skb" },
	{ 0x30af48ca, "locks_init_lock" },
	{ 0x38c8be28, "idr_get_next" },
	{ 0x7ee64ca0, "netlink_capable" },
	{ 0x5a844b26, "__x86_indirect_thunk_rdx" },
	{ 0x296b9459, "strrchr" },
	{ 0x5ad1edcf, "get_inode_acl" },
	{ 0x29d12a64, "bit_wait" },
	{ 0x7472752b, "init_task" },
	{ 0xb14708fa, "module_put" },
	{ 0x2962dc8d, "ib_device_get_by_netdev" },
	{ 0xf2ce4a1a, "rdma_bind_addr" },
	{ 0x126dafe3, "ib_register_client" },
	{ 0x90a48d82, "__ubsan_handle_out_of_bounds" },
	{ 0xbd03ed67, "page_offset_base" },
	{ 0xd70733be, "sized_strscpy" },
	{ 0xb917e1e9, "utf8_to_utf32" },
	{ 0x36b0cbe1, "rdma_create_qp" },
	{ 0x44decd6f, "hugetlb_optimize_vmemmap_key" },
	{ 0x07d50c57, "idr_remove" },
	{ 0xbe846f86, "putname" },
	{ 0x4706a93f, "vfs_remove_acl" },
	{ 0x46c12dd3, "kstrndup" },
	{ 0xf437b04b, "mempool_alloc_noprof" },
	{ 0xfe867a0d, "crypto_aead_setkey" },
	{ 0x3f7ce9b9, "__dma_sync_single_for_cpu" },
	{ 0xaec059b7, "rdma_rw_ctx_wrs" },
	{ 0x7a5ffe84, "init_wait_entry" },
	{ 0xf9cc9768, "vfs_get_link" },
	{ 0x08c3ab39, "fput" },
	{ 0xa59da3c0, "down_write" },
	{ 0x06e36f3a, "init_net" },
	{ 0xa59da3c0, "up_write" },
	{ 0xe9beea87, "crypto_shash_setkey" },
	{ 0xd272d446, "synchronize_rcu" },
	{ 0x4c1e7250, "mempool_free_slab" },
	{ 0xd272d446, "__rcu_read_unlock" },
	{ 0x47dc53e4, "crypto_aead_encrypt" },
	{ 0xb33c8a8a, "sk_skb_reason_drop" },
	{ 0xa38f8c89, "kmemdup_nul" },
	{ 0x4e005ba3, "netlink_unicast" },
	{ 0x97c20d46, "xa_load" },
	{ 0x17545440, "strstr" },
	{ 0xbd03ed67, "random_kmalloc_seed" },
	{ 0xa2d18a65, "fsnotify_init_mark" },
	{ 0xd7a59a65, "vmalloc_noprof" },
	{ 0x12b75ee8, "kernel_sock_shutdown" },
	{ 0x7b611b34, "idr_preload" },
	{ 0xbeb1d261, "destroy_workqueue" },
	{ 0x8bc8f40f, "crc32_le" },
	{ 0x9e3a8e47, "_raw_write_lock" },
	{ 0xf46d5bf3, "mutex_lock" },
	{ 0xe981281f, "kmem_cache_free" },
	{ 0xa68b38ad, "crypto_shash_init" },
	{ 0xe182ab80, "debugfs_remove" },
	{ 0xa90f8f94, "posix_acl_alloc" },
	{ 0x2435d559, "strncmp" },
	{ 0x5e92bedf, "__ib_alloc_cq" },
	{ 0xde338d9a, "_raw_spin_unlock_irq" },
	{ 0xd6d11a41, "nla_put" },
	{ 0xabec6e21, "from_kgid" },
	{ 0x6848eb64, "const_current_task" },
	{ 0xef6dacad, "vfs_getxattr" },
	{ 0xf8faa012, "kfree_sensitive" },
	{ 0x4c3d335e, "ida_free" },
	{ 0xbd03ed67, "phys_base" },
	{ 0xa2d18a65, "fsnotify_destroy_mark" },
	{ 0xd50230da, "sock_sendmsg" },
	{ 0x1be52d8a, "rdma_listen" },
	{ 0x5ae8543b, "from_vfsgid" },
	{ 0x962cecbf, "class_unregister" },
	{ 0x9e3a8e47, "_raw_read_unlock" },
	{ 0x680628e7, "ktime_get_real_ts64" },
	{ 0x3ce9f876, "rdma_destroy_qp" },
	{ 0x9e3a8e47, "_raw_write_unlock" },
	{ 0x402db74e, "memcmp" },
	{ 0x83b8fb02, "lock_sock_nested" },
	{ 0x228b1f9c, "kthread_stop" },
	{ 0x173ec8da, "sscanf" },
	{ 0xc1e6c71e, "__mutex_init" },
	{ 0xfad5355c, "set_posix_acl" },
	{ 0xe54e0a6b, "__fortify_panic" },
	{ 0xe199f25f, "jiffies_to_msecs" },
	{ 0xe5417d28, "freezing_slow_path" },
	{ 0xb82edfb3, "idr_alloc_cyclic" },
	{ 0x9b4b48a0, "_ctype" },
	{ 0x93236d39, "utf8_strncasecmp" },
	{ 0x255dfd5a, "idr_destroy" },
	{ 0x353e20f6, "sock_set_reuseaddr" },
	{ 0x6a874ce8, "locks_alloc_lock" },
	{ 0x3cafe49b, "from_kuid" },
	{ 0xdc84876e, "getname_kernel" },
	{ 0x0e9cab28, "memset" },
	{ 0xefb92f93, "kern_path" },
	{ 0x84aebb33, "vfs_lock_file" },
	{ 0x77496f26, "iov_iter_bvec" },
	{ 0xf330da6d, "kernel_read" },
	{ 0x65026e43, "wait_for_completion" },
	{ 0x75251f3a, "mempool_alloc_slab" },
	{ 0xd272d446, "__x86_return_thunk" },
	{ 0xdd0e0f53, "kmem_cache_alloc_noprof" },
	{ 0x386e4ba3, "kmemdup_noprof" },
	{ 0x5403c125, "__init_waitqueue_head" },
	{ 0x6c535bbc, "make_kgid" },
	{ 0x7fd710be, "__kmem_cache_create_args" },
	{ 0xe60b82c4, "fsnotify_put_group" },
	{ 0xabec6e21, "from_kgid_munged" },
	{ 0x4a2b4431, "__crypto_memneq" },
	{ 0xec203997, "kasprintf" },
	{ 0x6ba81560, "unlock_rename" },
	{ 0x5f5ce246, "vfs_rmdir" },
	{ 0x91e68589, "ib_destroy_cq_user" },
	{ 0xaef1f20d, "system_long_wq" },
	{ 0xa59da3c0, "down_read" },
	{ 0x888b8f57, "strcmp" },
	{ 0x9c48fcbe, "skb_trim" },
	{ 0xbd1c4f4e, "lookup_one_qstr_excl" },
	{ 0xfd285498, "unregister_netdevice_notifier" },
	{ 0x058c185a, "jiffies" },
	{ 0x956153f0, "dquot_get_dqblk" },
	{ 0x02996a3c, "kthread_create_on_node" },
	{ 0xd5eea791, "mnt_drop_write" },
	{ 0xce4af33b, "kstrdup" },
	{ 0x97c20d46, "xa_erase" },
	{ 0x67d5e21b, "seq_read" },
	{ 0x478da5e6, "ib_wc_status_msg" },
	{ 0xbd03ed67, "vmemmap_base" },
	{ 0x3fc737ed, "path_get" },
	{ 0xc48322da, "vfs_path_parent_lookup" },
	{ 0x82fd7238, "__ubsan_handle_shift_out_of_bounds" },
	{ 0xb9fcd065, "call_rcu" },
	{ 0x7ec472ba, "__preempt_count" },
	{ 0x0b5966cf, "kernel_listen" },
	{ 0x8f273388, "ib_dma_virt_map_sg" },
	{ 0xa4c0178c, "kvfree_call_rcu" },
	{ 0xf1de9e85, "vfree" },
	{ 0x6f5f0d82, "utf8_unload" },
	{ 0x15f878ac, "vfs_fsync" },
	{ 0xa5c7582d, "strsep" },
	{ 0xf46d5bf3, "mutex_unlock" },
	{ 0x26abcf32, "crypto_shash_finup" },
	{ 0x85acaba2, "cancel_delayed_work_sync" },
	{ 0x800c1eb4, "mktime64" },
	{ 0x8d643b6c, "mempool_create_node_noprof" },
	{ 0x1cb7049a, "sock_create_kern" },
	{ 0x99e6b256, "ib_free_cq" },
	{ 0xc9b96cf8, "groups_free" },
	{ 0x3ce9f876, "rdma_destroy_id" },
	{ 0x3f7ce9b9, "__dma_sync_single_for_device" },
	{ 0x0cd54f4b, "init_user_ns" },
	{ 0x3017bf34, "xa_destroy" },
	{ 0x78e5fdc4, "file_path" },
	{ 0x3fa0942c, "vfs_path_lookup" },
	{ 0x22a38397, "dentry_open" },
	{ 0x1b18b841, "xa_find" },
	{ 0x9c5b2f7e, "seq_write" },
	{ 0x79ff0b65, "mempool_destroy" },
	{ 0x979fb516, "__folio_put" },
	{ 0xc7aebaf5, "radix_tree_tagged" },
	{ 0x957c6137, "__kmalloc_cache_noprof" },
	{ 0x75738bed, "__warn_printk" },
	{ 0xfd285498, "register_netdevice_notifier" },
	{ 0xe1c26d73, "seq_printf" },
	{ 0x35c3c277, "rdma_accept" },
	{ 0xe3b1d074, "dput" },
	{ 0xba435eeb, "xa_store" },
	{ 0x8295115f, "lockref_get" },
	{ 0x71798f7e, "delayed_work_timer_fn" },
	{ 0x636c8577, "lookup_noperm_unlocked" },
	{ 0xdd1538f1, "utf16s_to_utf8s" },
	{ 0x7fd36f2e, "time64_to_tm" },
	{ 0x75a45b00, "vfs_clone_file_range" },
	{ 0x9e3a8e47, "_raw_read_lock" },
	{ 0xb6b5894f, "sock_release" },
	{ 0x0232ea06, "vfs_llseek" },
	{ 0x5954e9cb, "debugfs_create_file_full" },
	{ 0xd272d446, "rtnl_lock" },
	{ 0x71e090c6, "alloc_pages_noprof" },
	{ 0xfce0cfe1, "blkdev_issue_flush" },
	{ 0x4bcda72c, "single_release" },
	{ 0x02f9bbf0, "timer_init_key" },
	{ 0x224a53e7, "get_random_bytes" },
	{ 0x9ec34e98, "tcp_sock_set_nodelay" },
	{ 0x05a878f0, "ib_drain_qp" },
	{ 0xf430742f, "ib_dealloc_pd_user" },
	{ 0xc0cd09d2, "done_path_create" },
	{ 0x5a844b26, "__x86_indirect_thunk_r12" },
	{ 0xc4a449e7, "vfs_link" },
	{ 0xbee974b0, "dma_unmap_sg_attrs" },
	{ 0xc9b96cf8, "groups_sort" },
	{ 0x90221e4d, "genl_unregister_family" },
	{ 0x477e57ba, "dget_parent" },
	{ 0x3cafe49b, "from_kuid_munged" },
	{ 0x610c6dc1, "prepare_kernel_cred" },
	{ 0x1b18b841, "xa_find_after" },
	{ 0xdf4bee3d, "alloc_workqueue_noprof" },
	{ 0xa422e2f3, "lock_rename_child" },
	{ 0xd272d446, "rcu_barrier" },
	{ 0x40c98cda, "locks_delete_block" },
	{ 0xe4de56b4, "__ubsan_handle_load_invalid_value" },
	{ 0x43a349ca, "strlen" },
	{ 0xe8e0a5a9, "wake_up_bit" },
	{ 0x373ecd0f, "asn1_ber_decoder" },
	{ 0x798bf110, "inode_permission" },
	{ 0xf1de9e85, "kvfree" },
	{ 0x0fc70956, "single_open" },
	{ 0x03e5f586, "ib_device_put" },
	{ 0x296b9459, "strchr" },
	{ 0x8c4c0b59, "crypto_alloc_shash" },
	{ 0x7c07e6b1, "debugfs_create_dir" },
	{ 0xf734005e, "genl_register_family" },
	{ 0x0232ea06, "generic_file_llseek" },
	{ 0xde338d9a, "_raw_spin_unlock" },
	{ 0x38ea0628, "sg_alloc_table_chained" },
	{ 0xcc8d9ef4, "kernel_sendmsg" },
	{ 0x27b873b8, "get_max_files" },
	{ 0xa20ec1ad, "__kvmalloc_node_noprof" },
	{ 0x82445383, "strreplace" },
	{ 0x55a2a1cf, "unload_nls" },
	{ 0x296b9459, "strchrnul" },
	{ 0xa59da3c0, "up_read" },
	{ 0x5a844b26, "__x86_indirect_thunk_r8" },
	{ 0x8c9cfcae, "class_register" },
	{ 0x67b2ba98, "sysfs_emit_at" },
	{ 0x0940597e, "utf8s_to_utf16s" },
	{ 0x9cb91b7f, "sg_init_table" },
	{ 0x5e21460c, "sock_setsockopt" },
	{ 0x67628f51, "msleep" },
	{ 0x30af48ca, "locks_free_lock" },
	{ 0x035045de, "fsnotify_add_mark" },
	{ 0x34143a09, "set_groups" },
	{ 0x7851be11, "__SCT__might_resched" },
	{ 0x78339609, "kmalloc_caches" },
	{ 0x9c70c945, "inode_set_ctime_to_ts" },
	{ 0xfbe26b10, "krealloc_noprof" },
	{ 0xe59ceead, "kernel_write" },
	{ 0x6da5974d, "kmem_cache_destroy" },
	{ 0x353e20f6, "release_sock" },
	{ 0x082b811a, "dma_map_sg_attrs" },
	{ 0xaef1f20d, "system_wq" },
	{ 0xb3d105d8, "d_path" },
	{ 0xf7cde4ed, "vfs_create" },
	{ 0xa2e9db51, "rdma_rw_ctx_init" },
	{ 0x462ecb4a, "static_key_enable" },
	{ 0x984622ae, "module_layout" },
};

static const u32 ____version_ext_crcs[]
__used __section("__version_ext_crcs") = {
	0xfa535a6e,
	0x0e37bdfe,
	0x63843d6c,
	0xc45d298e,
	0x435a8dfc,
	0xd98156e2,
	0x6dce98f6,
	0xd124a4f1,
	0x4ccd3848,
	0xd272d446,
	0xdb5c5ac9,
	0x60b4d862,
	0x8e791ac6,
	0xad6cccc1,
	0x4a17e238,
	0x95e7f442,
	0x5244a5dc,
	0x591a33c0,
	0x2182515b,
	0xd272d446,
	0xd2324953,
	0x178ab13a,
	0xb697aaa1,
	0x534ed5f3,
	0xd710adbf,
	0xc94f00c2,
	0x903e2e6d,
	0x66146e3c,
	0xfbe7861b,
	0x40a621c5,
	0x65026e43,
	0x49733ad6,
	0x4efd6424,
	0xdd45951a,
	0xd272d446,
	0x1764efa6,
	0xcd51c662,
	0xc87f4bab,
	0xb0605e43,
	0x32043021,
	0xd4121e05,
	0x7a102c0a,
	0x5e505530,
	0x10cb5f48,
	0x9b3986cc,
	0xefa311be,
	0x17dcc243,
	0xfbe7861b,
	0x3cbd8974,
	0xcb8b6ec6,
	0xda44a623,
	0x6f1e66c6,
	0x283c9533,
	0x62e676b1,
	0xe758f079,
	0xaa040079,
	0x075cbd92,
	0xe53c6cf1,
	0x0feb1e94,
	0x0db8d68d,
	0xe2f59f75,
	0xf41396be,
	0x5e505530,
	0x47dc53e4,
	0x0150efe8,
	0x16ab4215,
	0x367d7d88,
	0xb14708fa,
	0x755821f2,
	0x1b821b52,
	0x87294d95,
	0xde338d9a,
	0xe2878ef1,
	0xa33df1be,
	0x3fc737ed,
	0x1f98a88f,
	0xad0e2c27,
	0xd272d446,
	0xdd6830c7,
	0x4cb7f3c8,
	0x4560dde6,
	0x54ee534d,
	0x55e4af36,
	0x59dd1646,
	0xae7ab2fe,
	0x17fb0101,
	0x4b132375,
	0x462ecb4a,
	0xef5a197a,
	0x519ffa96,
	0x31eae322,
	0x09dd69e9,
	0x5a844b26,
	0x303cd268,
	0x44decd6f,
	0xbbec67a9,
	0xe8213e80,
	0xde338d9a,
	0x2d88a3ab,
	0x95b255b8,
	0xd63bc22b,
	0x5629a063,
	0xbd03ed67,
	0xff7fbdd1,
	0x6ac784f4,
	0xd272d446,
	0xd272d446,
	0x5fe3f23a,
	0x2520ea93,
	0x8ce83585,
	0xd4c931e4,
	0x59fac341,
	0xfd018218,
	0x9479a1e8,
	0x255d3d76,
	0x30af48ca,
	0x38c8be28,
	0x7ee64ca0,
	0x5a844b26,
	0x296b9459,
	0x5ad1edcf,
	0x29d12a64,
	0x7472752b,
	0xb14708fa,
	0x2962dc8d,
	0xf2ce4a1a,
	0x126dafe3,
	0x90a48d82,
	0xbd03ed67,
	0xd70733be,
	0xb917e1e9,
	0x36b0cbe1,
	0x44decd6f,
	0x07d50c57,
	0xbe846f86,
	0x4706a93f,
	0x46c12dd3,
	0xf437b04b,
	0xfe867a0d,
	0x3f7ce9b9,
	0xaec059b7,
	0x7a5ffe84,
	0xf9cc9768,
	0x08c3ab39,
	0xa59da3c0,
	0x06e36f3a,
	0xa59da3c0,
	0xe9beea87,
	0xd272d446,
	0x4c1e7250,
	0xd272d446,
	0x47dc53e4,
	0xb33c8a8a,
	0xa38f8c89,
	0x4e005ba3,
	0x97c20d46,
	0x17545440,
	0xbd03ed67,
	0xa2d18a65,
	0xd7a59a65,
	0x12b75ee8,
	0x7b611b34,
	0xbeb1d261,
	0x8bc8f40f,
	0x9e3a8e47,
	0xf46d5bf3,
	0xe981281f,
	0xa68b38ad,
	0xe182ab80,
	0xa90f8f94,
	0x2435d559,
	0x5e92bedf,
	0xde338d9a,
	0xd6d11a41,
	0xabec6e21,
	0x6848eb64,
	0xef6dacad,
	0xf8faa012,
	0x4c3d335e,
	0xbd03ed67,
	0xa2d18a65,
	0xd50230da,
	0x1be52d8a,
	0x5ae8543b,
	0x962cecbf,
	0x9e3a8e47,
	0x680628e7,
	0x3ce9f876,
	0x9e3a8e47,
	0x402db74e,
	0x83b8fb02,
	0x228b1f9c,
	0x173ec8da,
	0xc1e6c71e,
	0xfad5355c,
	0xe54e0a6b,
	0xe199f25f,
	0xe5417d28,
	0xb82edfb3,
	0x9b4b48a0,
	0x93236d39,
	0x255dfd5a,
	0x353e20f6,
	0x6a874ce8,
	0x3cafe49b,
	0xdc84876e,
	0x0e9cab28,
	0xefb92f93,
	0x84aebb33,
	0x77496f26,
	0xf330da6d,
	0x65026e43,
	0x75251f3a,
	0xd272d446,
	0xdd0e0f53,
	0x386e4ba3,
	0x5403c125,
	0x6c535bbc,
	0x7fd710be,
	0xe60b82c4,
	0xabec6e21,
	0x4a2b4431,
	0xec203997,
	0x6ba81560,
	0x5f5ce246,
	0x91e68589,
	0xaef1f20d,
	0xa59da3c0,
	0x888b8f57,
	0x9c48fcbe,
	0xbd1c4f4e,
	0xfd285498,
	0x058c185a,
	0x956153f0,
	0x02996a3c,
	0xd5eea791,
	0xce4af33b,
	0x97c20d46,
	0x67d5e21b,
	0x478da5e6,
	0xbd03ed67,
	0x3fc737ed,
	0xc48322da,
	0x82fd7238,
	0xb9fcd065,
	0x7ec472ba,
	0x0b5966cf,
	0x8f273388,
	0xa4c0178c,
	0xf1de9e85,
	0x6f5f0d82,
	0x15f878ac,
	0xa5c7582d,
	0xf46d5bf3,
	0x26abcf32,
	0x85acaba2,
	0x800c1eb4,
	0x8d643b6c,
	0x1cb7049a,
	0x99e6b256,
	0xc9b96cf8,
	0x3ce9f876,
	0x3f7ce9b9,
	0x0cd54f4b,
	0x3017bf34,
	0x78e5fdc4,
	0x3fa0942c,
	0x22a38397,
	0x1b18b841,
	0x9c5b2f7e,
	0x79ff0b65,
	0x979fb516,
	0xc7aebaf5,
	0x957c6137,
	0x75738bed,
	0xfd285498,
	0xe1c26d73,
	0x35c3c277,
	0xe3b1d074,
	0xba435eeb,
	0x8295115f,
	0x71798f7e,
	0x636c8577,
	0xdd1538f1,
	0x7fd36f2e,
	0x75a45b00,
	0x9e3a8e47,
	0xb6b5894f,
	0x0232ea06,
	0x5954e9cb,
	0xd272d446,
	0x71e090c6,
	0xfce0cfe1,
	0x4bcda72c,
	0x02f9bbf0,
	0x224a53e7,
	0x9ec34e98,
	0x05a878f0,
	0xf430742f,
	0xc0cd09d2,
	0x5a844b26,
	0xc4a449e7,
	0xbee974b0,
	0xc9b96cf8,
	0x90221e4d,
	0x477e57ba,
	0x3cafe49b,
	0x610c6dc1,
	0x1b18b841,
	0xdf4bee3d,
	0xa422e2f3,
	0xd272d446,
	0x40c98cda,
	0xe4de56b4,
	0x43a349ca,
	0xe8e0a5a9,
	0x373ecd0f,
	0x798bf110,
	0xf1de9e85,
	0x0fc70956,
	0x03e5f586,
	0x296b9459,
	0x8c4c0b59,
	0x7c07e6b1,
	0xf734005e,
	0x0232ea06,
	0xde338d9a,
	0x38ea0628,
	0xcc8d9ef4,
	0x27b873b8,
	0xa20ec1ad,
	0x82445383,
	0x55a2a1cf,
	0x296b9459,
	0xa59da3c0,
	0x5a844b26,
	0x8c9cfcae,
	0x67b2ba98,
	0x0940597e,
	0x9cb91b7f,
	0x5e21460c,
	0x67628f51,
	0x30af48ca,
	0x035045de,
	0x34143a09,
	0x7851be11,
	0x78339609,
	0x9c70c945,
	0xfbe26b10,
	0xe59ceead,
	0x6da5974d,
	0x353e20f6,
	0x082b811a,
	0xaef1f20d,
	0xb3d105d8,
	0xf7cde4ed,
	0xa2e9db51,
	0x462ecb4a,
	0x984622ae,
};
static const char ____version_ext_names[]
__used __section("__version_ext_names") =
	"netdev_lower_get_next\0"
	"in6addr_any\0"
	"ib_mr_pool_destroy\0"
	"is_vmalloc_addr\0"
	"vfs_fsync_range\0"
	"ida_alloc_range\0"
	"vfs_removexattr\0"
	"try_module_get\0"
	"vfs_listxattr\0"
	"rtnl_unlock\0"
	"__init_rwsem\0"
	"ib_unregister_client\0"
	"make_vfsgid\0"
	"vfs_setxattr\0"
	"inode_to_bdi\0"
	"notify_change\0"
	"idr_find\0"
	"vfs_getattr\0"
	"__num_online_cpus\0"
	"__rcu_read_lock\0"
	"rdma_rw_ctx_destroy\0"
	"rdma_event_msg\0"
	"vfs_rename\0"
	"__msecs_to_jiffies\0"
	"__kmalloc_noprof\0"
	"vmalloc_to_page\0"
	"netif_get_flags\0"
	"lookup_one_unlocked\0"
	"memmove\0"
	"snprintf\0"
	"complete\0"
	"queue_work_on\0"
	"qid_valid\0"
	"sysfs_streq\0"
	"__SCT__preempt_schedule\0"
	"__ib_alloc_pd\0"
	"iterate_dir\0"
	"finish_wait\0"
	"dma_unmap_page_attrs\0"
	"abort_creds\0"
	"kernel_bind\0"
	"utf8_load\0"
	"set_freezable\0"
	"load_nls_default\0"
	"current_time\0"
	"genlmsg_put\0"
	"fsnotify_put_mark\0"
	"memcpy\0"
	"from_vfsuid\0"
	"kfree\0"
	"sprint_oid\0"
	"seq_lseek\0"
	"ib_mr_pool_init\0"
	"follow_down\0"
	"sg_free_table_chained\0"
	"kern_path_create\0"
	"crypto_alloc_aead\0"
	"groups_alloc\0"
	"usleep_range_state\0"
	"prepare_to_wait_event\0"
	"out_of_line_wait_on_bit\0"
	"crypto_aead_setauthsize\0"
	"kthread_should_stop\0"
	"crypto_aead_decrypt\0"
	"do_splice_direct\0"
	"__wake_up\0"
	"kernel_accept\0"
	"__module_get\0"
	"ib_event_msg\0"
	"kernel_recvmsg\0"
	"vfs_unlink\0"
	"_raw_spin_lock\0"
	"mempool_free\0"
	"vfs_truncate\0"
	"path_put\0"
	"rdma_disconnect\0"
	"vfs_copy_file_range\0"
	"__fentry__\0"
	"sysfs_emit\0"
	"make_vfsuid\0"
	"match_wildcard\0"
	"__put_cred\0"
	"utf8_casefold\0"
	"static_key_count\0"
	"wake_up_process\0"
	"vfs_mkdir\0"
	"dev_driver_string\0"
	"static_key_disable\0"
	"vfs_statfs\0"
	"crypto_destroy_tfm\0"
	"path_is_under\0"
	"__refrigerator\0"
	"__x86_indirect_thunk_rax\0"
	"dma_map_page_attrs\0"
	"freezer_active\0"
	"fsnotify_alloc_group\0"
	"_printk\0"
	"_raw_spin_lock_irq\0"
	"disable_work_sync\0"
	"vfs_iter_read\0"
	"vfs_fallocate\0"
	"strncasecmp\0"
	"__ref_stack_chk_guard\0"
	"___ratelimit\0"
	"schedule_timeout\0"
	"schedule\0"
	"__stack_chk_fail\0"
	"__rdma_create_kernel_id\0"
	"refcount_warn_saturate\0"
	"queue_delayed_work_on\0"
	"load_nls\0"
	"make_kuid\0"
	"mnt_want_write\0"
	"strnlen\0"
	"__alloc_skb\0"
	"locks_init_lock\0"
	"idr_get_next\0"
	"netlink_capable\0"
	"__x86_indirect_thunk_rdx\0"
	"strrchr\0"
	"get_inode_acl\0"
	"bit_wait\0"
	"init_task\0"
	"module_put\0"
	"ib_device_get_by_netdev\0"
	"rdma_bind_addr\0"
	"ib_register_client\0"
	"__ubsan_handle_out_of_bounds\0"
	"page_offset_base\0"
	"sized_strscpy\0"
	"utf8_to_utf32\0"
	"rdma_create_qp\0"
	"hugetlb_optimize_vmemmap_key\0"
	"idr_remove\0"
	"putname\0"
	"vfs_remove_acl\0"
	"kstrndup\0"
	"mempool_alloc_noprof\0"
	"crypto_aead_setkey\0"
	"__dma_sync_single_for_cpu\0"
	"rdma_rw_ctx_wrs\0"
	"init_wait_entry\0"
	"vfs_get_link\0"
	"fput\0"
	"down_write\0"
	"init_net\0"
	"up_write\0"
	"crypto_shash_setkey\0"
	"synchronize_rcu\0"
	"mempool_free_slab\0"
	"__rcu_read_unlock\0"
	"crypto_aead_encrypt\0"
	"sk_skb_reason_drop\0"
	"kmemdup_nul\0"
	"netlink_unicast\0"
	"xa_load\0"
	"strstr\0"
	"random_kmalloc_seed\0"
	"fsnotify_init_mark\0"
	"vmalloc_noprof\0"
	"kernel_sock_shutdown\0"
	"idr_preload\0"
	"destroy_workqueue\0"
	"crc32_le\0"
	"_raw_write_lock\0"
	"mutex_lock\0"
	"kmem_cache_free\0"
	"crypto_shash_init\0"
	"debugfs_remove\0"
	"posix_acl_alloc\0"
	"strncmp\0"
	"__ib_alloc_cq\0"
	"_raw_spin_unlock_irq\0"
	"nla_put\0"
	"from_kgid\0"
	"const_current_task\0"
	"vfs_getxattr\0"
	"kfree_sensitive\0"
	"ida_free\0"
	"phys_base\0"
	"fsnotify_destroy_mark\0"
	"sock_sendmsg\0"
	"rdma_listen\0"
	"from_vfsgid\0"
	"class_unregister\0"
	"_raw_read_unlock\0"
	"ktime_get_real_ts64\0"
	"rdma_destroy_qp\0"
	"_raw_write_unlock\0"
	"memcmp\0"
	"lock_sock_nested\0"
	"kthread_stop\0"
	"sscanf\0"
	"__mutex_init\0"
	"set_posix_acl\0"
	"__fortify_panic\0"
	"jiffies_to_msecs\0"
	"freezing_slow_path\0"
	"idr_alloc_cyclic\0"
	"_ctype\0"
	"utf8_strncasecmp\0"
	"idr_destroy\0"
	"sock_set_reuseaddr\0"
	"locks_alloc_lock\0"
	"from_kuid\0"
	"getname_kernel\0"
	"memset\0"
	"kern_path\0"
	"vfs_lock_file\0"
	"iov_iter_bvec\0"
	"kernel_read\0"
	"wait_for_completion\0"
	"mempool_alloc_slab\0"
	"__x86_return_thunk\0"
	"kmem_cache_alloc_noprof\0"
	"kmemdup_noprof\0"
	"__init_waitqueue_head\0"
	"make_kgid\0"
	"__kmem_cache_create_args\0"
	"fsnotify_put_group\0"
	"from_kgid_munged\0"
	"__crypto_memneq\0"
	"kasprintf\0"
	"unlock_rename\0"
	"vfs_rmdir\0"
	"ib_destroy_cq_user\0"
	"system_long_wq\0"
	"down_read\0"
	"strcmp\0"
	"skb_trim\0"
	"lookup_one_qstr_excl\0"
	"unregister_netdevice_notifier\0"
	"jiffies\0"
	"dquot_get_dqblk\0"
	"kthread_create_on_node\0"
	"mnt_drop_write\0"
	"kstrdup\0"
	"xa_erase\0"
	"seq_read\0"
	"ib_wc_status_msg\0"
	"vmemmap_base\0"
	"path_get\0"
	"vfs_path_parent_lookup\0"
	"__ubsan_handle_shift_out_of_bounds\0"
	"call_rcu\0"
	"__preempt_count\0"
	"kernel_listen\0"
	"ib_dma_virt_map_sg\0"
	"kvfree_call_rcu\0"
	"vfree\0"
	"utf8_unload\0"
	"vfs_fsync\0"
	"strsep\0"
	"mutex_unlock\0"
	"crypto_shash_finup\0"
	"cancel_delayed_work_sync\0"
	"mktime64\0"
	"mempool_create_node_noprof\0"
	"sock_create_kern\0"
	"ib_free_cq\0"
	"groups_free\0"
	"rdma_destroy_id\0"
	"__dma_sync_single_for_device\0"
	"init_user_ns\0"
	"xa_destroy\0"
	"file_path\0"
	"vfs_path_lookup\0"
	"dentry_open\0"
	"xa_find\0"
	"seq_write\0"
	"mempool_destroy\0"
	"__folio_put\0"
	"radix_tree_tagged\0"
	"__kmalloc_cache_noprof\0"
	"__warn_printk\0"
	"register_netdevice_notifier\0"
	"seq_printf\0"
	"rdma_accept\0"
	"dput\0"
	"xa_store\0"
	"lockref_get\0"
	"delayed_work_timer_fn\0"
	"lookup_noperm_unlocked\0"
	"utf16s_to_utf8s\0"
	"time64_to_tm\0"
	"vfs_clone_file_range\0"
	"_raw_read_lock\0"
	"sock_release\0"
	"vfs_llseek\0"
	"debugfs_create_file_full\0"
	"rtnl_lock\0"
	"alloc_pages_noprof\0"
	"blkdev_issue_flush\0"
	"single_release\0"
	"timer_init_key\0"
	"get_random_bytes\0"
	"tcp_sock_set_nodelay\0"
	"ib_drain_qp\0"
	"ib_dealloc_pd_user\0"
	"done_path_create\0"
	"__x86_indirect_thunk_r12\0"
	"vfs_link\0"
	"dma_unmap_sg_attrs\0"
	"groups_sort\0"
	"genl_unregister_family\0"
	"dget_parent\0"
	"from_kuid_munged\0"
	"prepare_kernel_cred\0"
	"xa_find_after\0"
	"alloc_workqueue_noprof\0"
	"lock_rename_child\0"
	"rcu_barrier\0"
	"locks_delete_block\0"
	"__ubsan_handle_load_invalid_value\0"
	"strlen\0"
	"wake_up_bit\0"
	"asn1_ber_decoder\0"
	"inode_permission\0"
	"kvfree\0"
	"single_open\0"
	"ib_device_put\0"
	"strchr\0"
	"crypto_alloc_shash\0"
	"debugfs_create_dir\0"
	"genl_register_family\0"
	"generic_file_llseek\0"
	"_raw_spin_unlock\0"
	"sg_alloc_table_chained\0"
	"kernel_sendmsg\0"
	"get_max_files\0"
	"__kvmalloc_node_noprof\0"
	"strreplace\0"
	"unload_nls\0"
	"strchrnul\0"
	"up_read\0"
	"__x86_indirect_thunk_r8\0"
	"class_register\0"
	"sysfs_emit_at\0"
	"utf8s_to_utf16s\0"
	"sg_init_table\0"
	"sock_setsockopt\0"
	"msleep\0"
	"locks_free_lock\0"
	"fsnotify_add_mark\0"
	"set_groups\0"
	"__SCT__might_resched\0"
	"kmalloc_caches\0"
	"inode_set_ctime_to_ts\0"
	"krealloc_noprof\0"
	"kernel_write\0"
	"kmem_cache_destroy\0"
	"release_sock\0"
	"dma_map_sg_attrs\0"
	"system_wq\0"
	"d_path\0"
	"vfs_create\0"
	"rdma_rw_ctx_init\0"
	"static_key_enable\0"
	"module_layout\0"
;

MODULE_INFO(depends, "ib_core,rdma_cm");


MODULE_INFO(srcversion, "20F88B6060445383B2027E0");
