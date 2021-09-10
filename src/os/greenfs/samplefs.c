#include <linux/module.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/time.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/blkdev.h>
#include <linux/parser.h>
//#include <linux/smp_lock.h>
#include <linux/hardirq.h>
#include <linux/buffer_head.h>
#include <linux/exportfs.h>
#include <linux/vfs.h>
#include <linux/random.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/quotaops.h>
#include <linux/seq_file.h>
#include <asm/uaccess.h>

//mount -t zxfs /root/t1/ /root/t1/
MODULE_LICENSE("GPL");
MODULE_AUTHOR("zx");
#define zxfs_MAGIC 0x20210903


static struct inode *zxfs_make_inode(struct super_block *sb, int mode)
{
        struct inode *ret = new_inode(sb);
        if (ret) {
                ret->i_mode = mode;
                ret->i_uid.val = ret->i_gid.val = 0;
                ret->i_blocks = 0;
                ret->i_atime = ret->i_mtime = ret->i_ctime = CURRENT_TIME;
        }
        return ret;
}
static int zxfs_open(struct inode *inode, struct file *filp)
{
        filp->private_data = inode->i_private;
        return 0;
}
#define TMPSIZE 20
static ssize_t zxfs_read_file(struct file *filp, char *buf,
                size_t count, loff_t *offset)
{
        atomic_t *counter = (atomic_t *) filp->private_data;
        int v, len;
        char tmp[TMPSIZE];
        v = atomic_read(counter);
        if (*offset > 0)
                v -= 1;  
        else
                atomic_inc(counter);
        len = snprintf(tmp, TMPSIZE, "%d\n", v);
        if (*offset > len)
                return 0;
        if (count > len - *offset)
                count = len - *offset;
        if (copy_to_user(buf, tmp + *offset, count))
                return -EFAULT;
        *offset += count;
        return count;
}
static ssize_t zxfs_write_file(struct file *filp, const char *buf,
                size_t count, loff_t *offset)
{
        atomic_t *counter = (atomic_t *) filp->private_data;
        char tmp[TMPSIZE];

        if (*offset != 0)
                return -EINVAL;

        if (count >= TMPSIZE)
                return -EINVAL;
        memset(tmp, 0, TMPSIZE);
        if (copy_from_user(tmp, buf, count))
                return -EFAULT;

        atomic_set(counter, simple_strtol(tmp, NULL, 10));
        return count;
}
static struct file_operations zxfs_file_ops = {
        .open        = zxfs_open,
        .read         = zxfs_read_file,
        .write  = zxfs_write_file,
};

static struct dentry *zxfs_create_file (struct super_block *sb,
                struct dentry *dir, const char *name,
                atomic_t *counter)
{
        struct dentry *dentry;
        struct inode *inode;
        struct qstr qname;

        qname.name = name;
        qname.len = strlen (name);
        qname.hash = full_name_hash(name, qname.len);

        dentry = d_alloc(dir, &qname);
        if (! dentry)
                goto out;
        inode = zxfs_make_inode(sb, S_IFREG | 0644);
        if (! inode)
                goto out_dput;
        inode->i_fop = &zxfs_file_ops;
        inode->i_private = counter;
        d_add(dentry, inode);
        return dentry;
  out_dput:
        dput(dentry);
  out:
        return 0;
}
static struct dentry *zxfs_create_dir (struct super_block *sb,
                struct dentry *parent, const char *name)
{
        struct dentry *dentry;
        struct inode *inode;
        struct qstr qname;
        qname.name = name;
        qname.len = strlen (name);
        qname.hash = full_name_hash(name, qname.len);
        //dentry的主要作用是建立文件名和inode之间的关联。
		/*所以该结构体包括两个最主要的字段，d_inode和d_name。
		其中，d_name为文件名。qstr是内核对字符串的封装（可以理解为带有散列值的char*）。
		d_inode是与该文件名对应的inode。*/
        dentry = d_alloc(parent, &qname);
        if (! dentry)
                goto out;
        inode = zxfs_make_inode(sb, S_IFDIR | 0644);
        if (! inode)
                goto out_dput;
        inode->i_op = &simple_dir_inode_operations;
        inode->i_fop = &simple_dir_operations;
        d_add(dentry, inode);
        return dentry;
  out_dput:
        dput(dentry);
  out:
        return 0;
}
static atomic_t counter, subcounter;
static void zxfs_create_files (struct super_block *sb, struct dentry *root)
{
        struct dentry *subdir;

        atomic_set(&counter, 0);
        zxfs_create_file(sb, root, "counter", &counter);

        atomic_set(&subcounter, 0);
        subdir = zxfs_create_dir(sb, root, "subdir");
        if (subdir)
                zxfs_create_file(sb, subdir, "subcounter", &subcounter);
}
static struct super_operations zxfs_s_ops = {
        .statfs                = simple_statfs,
        .drop_inode        = generic_delete_inode,
};
static int zxfs_fill_super (struct super_block *sb, void *data, int silent)
{
        struct inode *root;
        struct dentry *root_dentry;
		
        sb->s_blocksize = PAGE_CACHE_SIZE;
        sb->s_blocksize_bits = PAGE_CACHE_SHIFT;
        sb->s_magic = zxfs_MAGIC;
        sb->s_op = &zxfs_s_ops;

	printk(KERN_INFO "zxfs: zxfs_fill_super is here\n");
        root = zxfs_make_inode (sb, S_IFDIR | 0755);
        if (! root)
                goto out;
        root->i_op = &simple_dir_inode_operations;
        root->i_fop = &simple_dir_operations;

        root_dentry = d_make_root(root);
        if (! root_dentry)
                goto out_iput;
        sb->s_root = root_dentry;

        zxfs_create_files (sb, root_dentry);
        return 0;
        
  out_iput:
        iput(root);
  out:
        return -ENOMEM;
}

// void simple_set_mnt(struct vfsmount *mnt, struct super_block *sb)
// {
// 	mnt->mnt_sb = sb;
// 	mnt->mnt_root = dget(sb->s_root);
// }
/* 
int set_anon_super(struct super_block *s, void *data)
{
	int error = get_anon_bdev(&s->s_dev);
	if (!error)
		s->s_bdi = &noop_backing_dev_info;
	return error;
}
*/

/* 
int get_sb_single(struct file_system_type *fs_type,
	int flags, void *data,
	int (*fill_super)(struct super_block *, void *, int),
	struct vfsmount *mnt)
{
	struct super_block *s=NULL;
	int error;

	s = sget(fs_type, compare_single, set_anon_super, flags,NULL);
	if (IS_ERR(s))
		return PTR_ERR(s);
	if (!s->s_root) {
		s->s_flags = flags;
		error = fill_super(s, data, flags & MS_SILENT ? 1 : 0);
		if (error) {
			deactivate_locked_super(s);
			return error;
		}
		s->s_flags |= MS_ACTIVE;
	} else {
		do_remount_sb(s, flags, data, 0);
	}
	simple_set_mnt(mnt, s);
	return 0;
}
*/


static int zxfs_get_super(struct file_system_type *fst,int flags, const char *devname, void *data,struct vfsmount *mount)
{
	printk(KERN_INFO "mount from user\n");
    return mount_single(fst, flags, data, zxfs_fill_super);
}

static struct file_system_type zxfs_type = {
        .owner                 = THIS_MODULE,
        .name                = "zxfs",
        .mount                = zxfs_get_super,
        .kill_sb        = kill_litter_super,
};

static int __init zxfs_init(void)
{
	struct file_system_type * tmp;  
	printk("zxfs: zxfs_init ok\n");
    return register_filesystem(&zxfs_type);
}
static void __exit zxfs_exit(void)
{
    unregister_filesystem(&zxfs_type);
	printk("zxfs: zxfs_exit ok\n");
}
module_init(zxfs_init);
module_exit(zxfs_exit);

// Makefile
// ifneq ($(KERNELRELEASE),)
// 	obj-m := zx.o 
// else        
// 	KERNELDIR ?= /lib/modules/$(shell uname -r)/build
//         PWD := $(shell pwd) 
// default:
// 	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
// endif

// clean:
// 	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions *.order *.symvers *.unsigned