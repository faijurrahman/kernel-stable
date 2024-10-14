/* SPDX-License-Identifier: GPL-2.0 */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM cros_file

#if !defined(_TRACE_CROS_FILE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_CROS_FILE_H

#include <linux/dcache.h>
#include <linux/tracepoint.h>
#include <linux/minmax.h>
/* In kernels<6.6 fentry, fexit and LSM hooks for eBPF do not work for ARM platforms.
 * As a workaround the following tracepoints have been added to provide hooks for
 * XDR file event eBPF hooks for ARM platforms.
 *
 */
TRACE_EVENT_CONDITION(cros_filp_close_exit,
	TP_PROTO(struct file *filp, fl_owner_t id, int ret),
	TP_ARGS(filp, id, ret),
	TP_CONDITION(filp && filp->f_path.dentry),
	TP_STRUCT__entry(
		__array(char, name, 128)
	),
	TP_fast_assign(
		unsigned int name_len = 0;
		struct qstr *dname = &(filp->f_path.dentry->d_name);
		static const unsigned int max_name_size = sizeof(__entry->name) - 1;

		name_len = min(max_name_size, dname->len);
		memmove(__entry->name, dname->name, name_len);
		__entry->name[name_len] = '\0';
	),
	TP_printk("do_not_depend:%s", __entry->name)
	);

TRACE_EVENT_CONDITION(cros_security_inode_rename_exit,
	TP_PROTO(struct inode *old_dir, struct dentry *old_dentry,
		struct inode *new_dir, struct dentry *new_dentry,
		unsigned int flags, int ret),
	TP_ARGS(old_dir, old_dentry, new_dir, new_dentry, flags, ret),
	TP_CONDITION(old_dentry && new_dentry),
	TP_STRUCT__entry(
		__array(char, old_name, 128)
		__array(char, new_name, 128)
	),
	TP_fast_assign(
		unsigned int name_len = 0;
		struct qstr *old_dname = &(old_dentry->d_name);
		struct qstr *new_dname = &(new_dentry->d_name);
		/*  Max size without null terminator. */
		static const unsigned int max_old_name_size = sizeof(__entry->old_name)-1;
		static const unsigned int max_new_name_size = sizeof(__entry->new_name)-1;

		__entry->old_name[0] = '\0';
		__entry->new_name[0] = '\0';

		name_len = min(old_dname->len, max_old_name_size);
		memmove(__entry->old_name, old_dname->name, name_len);
		__entry->old_name[name_len] = '\0';

		name_len = min(new_dname->len, max_new_name_size);
		memmove(__entry->new_name, new_dname->name, name_len);
		__entry->new_name[name_len] = '\0';
	),
	TP_printk("do_not_depend: from:%s to:%s", __entry->old_name, __entry->new_name)
	);


TRACE_EVENT_CONDITION(cros_security_inode_link_exit,
	TP_PROTO(struct dentry *old_dentry, struct inode *dir,
		struct dentry *new_dentry, int ret),
	TP_ARGS(old_dentry, dir, new_dentry, ret),
	TP_CONDITION(old_dentry && new_dentry),
	TP_STRUCT__entry(
		__array(char, old_name, 128)
		__array(char, new_name, 128)
	),
	TP_fast_assign(
		unsigned int name_len = 0;
		struct qstr *old_dname = &(old_dentry->d_name);
		struct qstr *new_dname = &(new_dentry->d_name);
		/*  Max size without null terminator. */
		static const unsigned int max_old_name_size = sizeof(__entry->old_name)-1;
		static const unsigned int max_new_name_size = sizeof(__entry->new_name)-1;

		__entry->old_name[0] = '\0';
		__entry->new_name[0] = '\0';

		name_len = min(old_dname->len, max_old_name_size);
		memmove(__entry->old_name, old_dname->name, name_len);
		__entry->old_name[name_len] = '\0';

		name_len = min(new_dname->len, max_new_name_size);
		memmove(__entry->new_name, new_dname->name, name_len);
		__entry->new_name[name_len] = '\0';
	),
	TP_printk("do_not_depend: from:%s to:%s", __entry->old_name, __entry->new_name)
	);

TRACE_EVENT_CONDITION(cros_security_inode_unlink_exit,
	TP_PROTO(struct inode *dir,
		struct dentry *old_dentry, int ret),
	TP_ARGS(dir, old_dentry, ret),
	TP_CONDITION(old_dentry && dir),
	TP_STRUCT__entry(
		__array(char, old_dentry, 128)
	),
	TP_fast_assign(
		unsigned int name_len = 0;
		struct qstr *old_dname = &(old_dentry->d_name);
		/* Max size of string without null terminator. */
		static const unsigned int max_old_dname_size = sizeof(__entry->old_dentry)-1;

		__entry->old_dentry[0] = '\0';
		name_len = min(max_old_dname_size, old_dname->len);
		memmove(__entry->old_dentry, old_dname->name, name_len);
		__entry->old_dentry[name_len] = '\0';
	),
	TP_printk("do_not_depend: unlinked %s", __entry->old_dentry)
	);

TRACE_EVENT_CONDITION(cros_path_mount_exit,
	TP_PROTO(const char *dev_name, const struct path *path,
		const char *type_page, unsigned long flags, void *data_page, int ret),
	TP_ARGS(dev_name, path, type_page, flags, data_page, ret),
	TP_CONDITION(dev_name && path && path->dentry && type_page),
	TP_STRUCT__entry(
		__array(char, dev_name, 128)
		__array(char, target_name, 128)
	),
	TP_fast_assign(
		unsigned int name_len = 0;
		struct qstr *target_dname = &(path->dentry->d_name);
		// string length without null terminator.
		static const unsigned int max_dev_name_size = sizeof(__entry->dev_name) - 1;
		static const unsigned int max_target_name_size = sizeof(__entry->target_name)-1;

		__entry->dev_name[0] = 0;
		__entry->target_name[0] = '\0';
		strncpy(__entry->dev_name, dev_name, max_dev_name_size);
		__entry->dev_name[max_dev_name_size] = 0;
		name_len = min(target_dname->len, max_target_name_size);
		memmove(__entry->target_name, target_dname->name, name_len);
		__entry->target_name[name_len] = '\0';
	),
	TP_printk("do_not_depend: dev_name:%s target:%s", __entry->dev_name, __entry->target_name)
	);

TRACE_EVENT_CONDITION(cros_path_umount_entry,
	TP_PROTO(struct path *path, int flags),
	TP_ARGS(path, flags),
	TP_CONDITION(path && path->dentry),
	TP_STRUCT__entry(
		__array(char, target_name, 128)
	),
	TP_fast_assign(
		unsigned int name_len = 0;
		struct qstr *target_dname = &(path->dentry->d_name);
		/* Max size of string without null terminator. */
		static const unsigned int max_target_name_size = sizeof(__entry->target_name)-1;

		__entry->target_name[0] = '\0';
		name_len = min(target_dname->len, max_target_name_size);
		memmove(__entry->target_name, target_dname->name, name_len);
		__entry->target_name[name_len] = '\0';
	),
	TP_printk("do_not_depend: unmounted:%s ", __entry->target_name)
	);

TRACE_EVENT_CONDITION(cros_path_umount_exit,
	TP_PROTO(struct path *path, int flags, int ret),
	TP_ARGS(path, flags, ret),
	TP_CONDITION(path && path->dentry),
	TP_STRUCT__entry(
		__array(char, target_name, 128)
	),
	TP_fast_assign(
		unsigned int name_len = 0;
		struct qstr *target_dname = &(path->dentry->d_name);
		/* Max size of string without null terminator. */
		static const unsigned int max_target_name_size = sizeof(__entry->target_name)-1;

		__entry->target_name[0] = '\0';
		name_len = min(target_dname->len, max_target_name_size);
		memmove(__entry->target_name, target_dname->name, name_len);
		__entry->target_name[name_len] = '\0';
	),
	TP_printk("do_not_depend: unmounted:%s ", __entry->target_name)
	);

TRACE_EVENT_CONDITION(cros_chmod_common_enter,
	TP_PROTO(const struct path *path, umode_t mode),
	TP_ARGS(path, mode),
	TP_CONDITION(path && path->dentry && path->dentry->d_inode),
	TP_STRUCT__entry(
		__array(char, name, 128)
		__array(char, root, 128)
		__array(char, id, 32)
		__field(umode_t, mode)
	),
	TP_fast_assign(
		unsigned int name_len = 0;
		struct qstr *dname = &(path->dentry->d_name);
		static const unsigned int max_name_size = sizeof(__entry->name) - 1;
		static const unsigned int max_root_size = sizeof(__entry->root) - 1;
		static const unsigned int max_id_size = sizeof(__entry->id) - 1;

		__entry->name[0] = '\0';
		__entry->root[0] = '\0';
		__entry->id[0] = '\0';
		__entry->mode = mode;

		name_len = min(max_name_size, dname->len);
		memmove(__entry->name, dname->name, name_len);
		__entry->name[name_len] = '\0';

		if (path->dentry->d_sb && path->dentry->d_sb->s_root) {
			struct qstr *root_name = &(path->dentry->d_sb->s_root->d_name);

			name_len = min(dname->len, max_root_size);
			memmove(__entry->root, root_name->name, name_len);
			__entry->root[name_len] = '\0';
			name_len = min(max_id_size, sizeof(path->dentry->d_sb->s_id));
			memmove(__entry->id, path->dentry->d_sb->s_id, name_len);
			__entry->id[name_len] = '\0';
		}
	),
	TP_printk("do_not_depend:%s root:%s id:%s mode:0%o", __entry->name,
		  __entry->root, __entry->id, __entry->mode)
	);

TRACE_EVENT_CONDITION(cros_chmod_common_exit,
	TP_PROTO(const struct path *path, umode_t mode, int ret),
	TP_ARGS(path, mode, ret),
	TP_CONDITION(path && path->dentry && path->dentry->d_inode),
	TP_STRUCT__entry(
		__array(char, name, 128)
		__array(char, root, 128)
		__array(char, id, 32)
		__field(umode_t, mode)
	),
	TP_fast_assign(
		unsigned int name_len = 0;
		struct qstr *dname = &(path->dentry->d_name);
		static const unsigned int max_name_size = sizeof(__entry->name) - 1;
		static const unsigned int max_root_size = sizeof(__entry->root) - 1;
		static const unsigned int max_id_size = sizeof(__entry->id) - 1;

		__entry->name[0] = '\0'; __entry->root[0] = '\0';
		__entry->id[0] = '\0'; __entry->mode = mode;

		name_len = min(max_name_size, dname->len);
		memmove(__entry->name, dname->name, name_len);
		__entry->name[name_len] = '\0';

		if (path->dentry->d_sb && path->dentry->d_sb->s_root) {
			struct qstr *root_name = &(path->dentry->d_sb->s_root->d_name);

			name_len = min(dname->len, max_root_size);
			memmove(__entry->root, root_name->name, name_len);
			__entry->root[name_len] = '\0';
			name_len = min(max_id_size, sizeof(path->dentry->d_sb->s_id));
			memmove(__entry->id, path->dentry->d_sb->s_id, name_len);
			__entry->id[name_len] = '\0';
		}
	),
	TP_printk("do_not_depend:%s root:%s id:%s mode:0%o", __entry->name,
		  __entry->root, __entry->id, __entry->mode)
	);

TRACE_EVENT_CONDITION(cros_chown_common_enter,
	TP_PROTO(const struct path *path, uid_t user, gid_t group),
	TP_ARGS(path, user, group),
	TP_CONDITION(path && path->dentry && path->dentry->d_inode),
	TP_STRUCT__entry(
		__array(char, name, 128)
		__array(char, root, 128)
		__array(char, id, 32)
		__field(uid_t, user)
		__field(gid_t, group)
	),
	TP_fast_assign(
		unsigned int name_len = 0;
		struct qstr *dname = &(path->dentry->d_name);
		static const unsigned int max_name_size = sizeof(__entry->name) - 1;
		static const unsigned int max_root_size = sizeof(__entry->root) - 1;
		static const unsigned int max_id_size = sizeof(__entry->id) - 1;

		__entry->name[0] = '\0'; __entry->root[0] = '\0';
		__entry->id[0] = '\0'; __entry->user = user;
		__entry->group = group;

		name_len = min(max_name_size, dname->len);
		memmove(__entry->name, dname->name, name_len);
		__entry->name[name_len] = '\0';

		if (path->dentry->d_sb && path->dentry->d_sb->s_root) {
			struct qstr *root_name = &(path->dentry->d_sb->s_root->d_name);

			name_len = min(dname->len, max_root_size);
			memmove(__entry->root, root_name->name, name_len);
			__entry->root[name_len] = '\0';
			name_len = min(max_id_size, sizeof(path->dentry->d_sb->s_id));
			memmove(__entry->id, path->dentry->d_sb->s_id, name_len);
			__entry->id[name_len] = '\0';
		}
	),
	TP_printk("do_not_depend:%s root:%s id:%s user:%u group:%u",
		  __entry->name, __entry->root, __entry->id, __entry->user,
		  __entry->group)
	);

TRACE_EVENT_CONDITION(cros_chown_common_exit,
	TP_PROTO(const struct path *path, uid_t user, gid_t group, int ret),
	TP_ARGS(path, user, group, ret),
	TP_CONDITION(path && path->dentry && path->dentry->d_inode),
	TP_STRUCT__entry(
		__array(char, name, 128)
		__array(char, root, 128)
		__array(char, id, 32)
		__field(uid_t, user)
		__field(gid_t, group)
	),
	TP_fast_assign(
		unsigned int name_len = 0;
		struct qstr *dname = &(path->dentry->d_name);
		static const unsigned int max_name_size = sizeof(__entry->name) - 1;
		static const unsigned int max_root_size = sizeof(__entry->root) - 1;
		static const unsigned int max_id_size = sizeof(__entry->id) - 1;

		__entry->name[0] = '\0'; __entry->root[0] = '\0';
		__entry->id[0] = '\0'; __entry->user = user;
		__entry->group = group;

		name_len = min(max_name_size, dname->len);
		memmove(__entry->name, dname->name, name_len);
		__entry->name[name_len] = '\0';

		if (path->dentry->d_sb && path->dentry->d_sb->s_root) {
			struct qstr *root_name = &(path->dentry->d_sb->s_root->d_name);

			name_len = min(dname->len, max_root_size);
			memmove(__entry->root, root_name->name, name_len);
			__entry->root[name_len] = '\0';
			name_len = min(max_id_size, sizeof(path->dentry->d_sb->s_id));
			memmove(__entry->id, path->dentry->d_sb->s_id, name_len);
			__entry->id[name_len] = '\0';
		}
	),
	TP_printk("do_not_depend:%s root:%s id:%s user:%u group:%u",
		  __entry->name, __entry->root, __entry->id, __entry->user,
		  __entry->group)
	);

TRACE_EVENT_CONDITION(cros_vfs_utimes_enter,
	TP_PROTO(const struct path *path, struct timespec64 *times),
	TP_ARGS(path, times),
	TP_CONDITION(path && path->dentry && path->dentry->d_inode && times),
	TP_STRUCT__entry(
		__array(char, name, 128)
		__array(char, root, 128)
		__array(char, id, 32)
		__field(long, atime_sec)
		__field(long, atime_nsec)
		__field(long, mtime_sec)
		__field(long, mtime_nsec)
	),
	TP_fast_assign(
		unsigned int name_len = 0;
		struct qstr *dname = &(path->dentry->d_name);
		static const unsigned int max_name_size = sizeof(__entry->name) - 1;
		static const unsigned int max_root_size = sizeof(__entry->root) - 1;
		static const unsigned int max_id_size = sizeof(__entry->id) - 1;

		__entry->name[0] = '\0'; __entry->root[0] = '\0';
		__entry->id[0] = '\0';
		__entry->atime_sec = times[0].tv_sec;
		__entry->atime_nsec = times[0].tv_nsec;
		__entry->mtime_sec = times[1].tv_sec;
		__entry->mtime_nsec = times[1].tv_nsec;

		name_len = min(max_name_size, dname->len);
		memmove(__entry->name, dname->name, name_len);
		__entry->name[name_len] = '\0';

		if (path->dentry->d_sb && path->dentry->d_sb->s_root) {
			struct qstr *root_name = &(path->dentry->d_sb->s_root->d_name);

			name_len = min(dname->len, max_root_size);
			memmove(__entry->root, root_name->name, name_len);
			__entry->root[name_len] = '\0';
			name_len = min(max_id_size, sizeof(path->dentry->d_sb->s_id));
			memmove(__entry->id, path->dentry->d_sb->s_id, name_len);
			__entry->id[name_len] = '\0';
		}
	),
	TP_printk(
		"do_not_depend:%s root:%s id:%s atime:%ld.%09ld mtime:%ld.%09ld",
		__entry->name, __entry->root, __entry->id, __entry->atime_sec,
		__entry->atime_nsec, __entry->mtime_sec, __entry->mtime_nsec)
	);

TRACE_EVENT_CONDITION(cros_vfs_utimes_exit,
	TP_PROTO(const struct path *path, struct timespec64 *times, int ret),
	TP_ARGS(path, times, ret),
	TP_CONDITION(path && path->dentry && path->dentry->d_inode && times),
	TP_STRUCT__entry(
		__array(char, name, 128)
		__array(char, root, 128)
		__array(char, id, 32)
		__field(long, atime_sec)
		__field(long, atime_nsec)
		__field(long, mtime_sec)
		__field(long, mtime_nsec)),
	TP_fast_assign(
		unsigned int name_len = 0;
		struct qstr *dname = &(path->dentry->d_name);
		static const unsigned int max_name_size = sizeof(__entry->name) - 1;
		static const unsigned int max_root_size = sizeof(__entry->root) - 1;
		static const unsigned int max_id_size = sizeof(__entry->id) - 1;

		__entry->name[0] = '\0'; __entry->root[0] = '\0';
		__entry->id[0] = '\0';
		__entry->atime_sec = times[0].tv_sec;
		__entry->atime_nsec = times[0].tv_nsec;
		__entry->mtime_sec = times[1].tv_sec;
		__entry->mtime_nsec = times[1].tv_nsec;

		name_len = min(max_name_size, dname->len);
		memmove(__entry->name, dname->name, name_len);
		__entry->name[name_len] = '\0';

		if (path->dentry->d_sb && path->dentry->d_sb->s_root) {
			struct qstr *root_name = &(path->dentry->d_sb->s_root->d_name);

			name_len = min(dname->len, max_root_size);
			memmove(__entry->root, root_name->name, name_len);
			__entry->root[name_len] = '\0';
			name_len = min(max_id_size, sizeof(path->dentry->d_sb->s_id));
			memmove(__entry->id, path->dentry->d_sb->s_id, name_len);
			__entry->id[name_len] = '\0';
		}
	),
	TP_printk(
		"do_not_depend:%s root:%s id:%s atime:%ld.%09ld mtime:%ld.%09ld",
		__entry->name, __entry->root, __entry->id, __entry->atime_sec,
		__entry->atime_nsec, __entry->mtime_sec, __entry->mtime_nsec)
	);

#endif // _TRACE_CROS_NET_H
/* This part must be outside protection */
#include <trace/define_trace.h>
