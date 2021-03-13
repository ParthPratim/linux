#include <linux/mm.h>
#include <linux/mmzone.h>
#include <linux/mman.h>
#include <linux/ratelimit.h>
#include <linux/proc_fs.h>
#include <linux/nsproxy.h>
#include <linux/reboot.h>
#include <linux/fs.h>
#include <net/net_namespace.h>
#include <asm/dce-types.h>
#include <asm/dce_assert.h>

static int namecmp(const char *name1, int len1, const char *name2, int len2)
{
	int minlen;
	int cmp;

	minlen = len1;
	if (minlen > len2)
		minlen = len2;

	cmp = memcmp(name1, name2, minlen);
	if (cmp == 0)
		cmp = len1 - len2;
	return cmp;
}

static DEFINE_SPINLOCK(sysctl_lock);

static struct ctl_table root_table[] = {
	{
		.procname = "",
		.mode = S_IFDIR|S_IRUGO|S_IXUGO,
	},
	{ }
};

static struct ctl_table_root sysctl_table_root = {
	.default_set.dir.header = {
		{{.count = 1,
		  .nreg = 1,
		  .ctl_table = root_table }},
		.ctl_table_arg = root_table,
		.root = &sysctl_table_root,
		.set = &sysctl_table_root.default_set,
	},
};

static struct ctl_table *ctl_table_find_entry(struct ctl_table_header **phead,
	struct ctl_dir *dir, const char *name, int namelen)
{
	struct ctl_table_header *head;
	struct ctl_table *entry;
	struct rb_node *node = dir->root.rb_node;

	while (node)
	{
		struct ctl_node *ctl_node;
		const char *procname;
		int cmp;

		ctl_node = rb_entry(node, struct ctl_node, node);
		head = ctl_node->header;
		entry = &head->ctl_table[ctl_node - head->node];
		procname = entry->procname;

		cmp = namecmp(name, namelen, procname, strlen(procname));
		if (cmp < 0)
			node = node->rb_left;
		else if (cmp > 0)
			node = node->rb_right;
		else {
			*phead = head;
			return entry;
		}
	}
	return NULL;
}

static int use_table(struct ctl_table_header *p)
{
	if (unlikely(p->unregistering))
		return 0;
	p->used++;
	return 1;
}


static struct ctl_node *first_usable_entry(struct rb_node *node)
{
	struct ctl_node *ctl_node;

	for (;node; node = rb_next(node)) {
		ctl_node = rb_entry(node, struct ctl_node, node);
		if (use_table(ctl_node->header))
			return ctl_node;
	}
	return NULL;
}

static void unuse_table(struct ctl_table_header *p)
{
	if (!--p->used)
		if (unlikely(p->unregistering))
			complete(p->unregistering);
}

static struct ctl_dir *find_subdir(struct ctl_dir *dir,
				   const char *name, int namelen)
{
	struct ctl_table_header *head;
	struct ctl_table *entry;

	entry = ctl_table_find_entry(&head, dir, name, namelen);
	if (!entry)
		return ERR_PTR(-ENOENT);
	if (!S_ISDIR(entry->mode))
		return ERR_PTR(-ENOTDIR);
	return container_of(head, struct ctl_dir, header);
}

static void ctl_table_first_entry(struct ctl_dir *dir,
	struct ctl_table_header **phead, struct ctl_table **pentry)
{
	struct ctl_table_header *head = NULL;
	struct ctl_table *entry = NULL;
	struct ctl_node *ctl_node;

	spin_lock(&sysctl_lock);
	ctl_node = first_usable_entry(rb_first(&dir->root));
	spin_unlock(&sysctl_lock);
	if (ctl_node) {
		head = ctl_node->header;
		entry = &head->ctl_table[ctl_node - head->node];
	}
	*phead = head;
	*pentry = entry;
}

static void ctl_table_next_entry(struct ctl_table_header **phead, struct ctl_table **pentry)
{
	struct ctl_table_header *head = *phead;
	struct ctl_table *entry = *pentry;
	struct ctl_node *ctl_node = &head->node[entry - head->ctl_table];

	spin_lock(&sysctl_lock);
	unuse_table(head);

	ctl_node = first_usable_entry(rb_next(&ctl_node->node));
	spin_unlock(&sysctl_lock);
	head = NULL;
	if (ctl_node) {
		head = ctl_node->header;
		entry = &head->ctl_table[ctl_node - head->node];
	}
	*phead = head;
	*pentry = entry;
}

static struct ctl_dir *ctl_table_xlate_dir(struct ctl_table_set *set, struct ctl_dir *dir)
{
	struct ctl_dir *parent;
	const char *procname;
	if (!dir->header.parent)
		return &set->dir;
	parent = ctl_table_xlate_dir(set, dir->header.parent);
	if (IS_ERR(parent))
		return parent;
	procname = dir->header.ctl_table[0].procname;
	return find_subdir(parent, procname, strlen(procname));
}

static void iterate_table_recursive(const struct SimSysIterator *iter,
				    struct ctl_table_header *head)
{
	struct ctl_table *entry;

	for (entry = head->ctl_table; entry->procname; entry++) {
		bool may_read = (head->ctl_table->mode & MAY_READ);
		bool may_write = (head->ctl_table->mode & MAY_WRITE);
		int flags = 0;

		flags |= may_read ? SIM_SYS_FILE_READ : 0;
		flags |= may_write ? SIM_SYS_FILE_WRITE : 0;
		iter->report_file(iter, entry->procname, flags,
				  (struct SimSysFile *)entry);
	}
}

static void iterate_recursive(const struct SimSysIterator *iter,
			      struct ctl_table_header *head)
{
	struct ctl_table_header *h = NULL;
	struct ctl_table *entry;
	struct ctl_dir *ctl_dir;

	ctl_dir = container_of(head, struct ctl_dir, header);
	for (ctl_table_first_entry(ctl_dir, &h, &entry); h;
	     ctl_table_next_entry(&h, &entry)) {
		struct ctl_dir *dir;
		int ret;
		const char *procname;

		/* copy from sysctl_follow_link () */
		if (S_ISLNK(entry->mode)) {
			dir = ctl_table_xlate_dir(&init_net.sysctls, h->parent);
			if (IS_ERR(dir)) {
				ret = PTR_ERR(dir);
				lib_assert(false);
			} else {
				procname = entry->procname;
				h = NULL;
				entry =
					ctl_table_find_entry(&h, dir, procname,
							     strlen(procname));
				ret = -ENOENT;
			}
		}

		if (S_ISDIR(entry->mode)) {
			iter->report_start_dir(iter, entry->procname);
			iterate_recursive(iter, h);
			iter->report_end_dir(iter);
		} else
			iterate_table_recursive(iter, h);
	}

}


void dce_sys_iterate_files(const struct SimSysIterator *iter)
{
	struct ctl_table_header *root =
		&sysctl_table_root.default_set.dir.header;

	iterate_recursive(iter, root);
}

int dce_sys_file_read(const struct SimSysFile *file, char *buffer, int size,
		      int offset)
{
	struct ctl_table *table = (struct ctl_table *)file;
	loff_t ppos = offset;
	size_t result = size;
	int error;

	error = table->proc_handler(table, 0, buffer, &result, &ppos);
	return result;
}

int dce_sys_file_write(const struct SimSysFile *file, const char *buffer,
		       int size, int offset)
{
	struct ctl_table *table = (struct ctl_table *)file;
	loff_t ppos = offset;
	size_t result = size;
	int error;

	error = table->proc_handler(table, 1, (char *)buffer, &result, &ppos);
	return result;
}
