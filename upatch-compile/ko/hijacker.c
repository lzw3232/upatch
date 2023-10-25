#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/file.h>
#include <linux/binfmts.h>
#include <linux/kprobes.h>
#include <linux/miscdevice.h>

#include "upatch-entry.h"
#include "upatch-ioctl.h"

#include "entry.h"

/* code from fs/namei.c */
#define EMBEDDED_NAME_MAX	(PATH_MAX - offsetof(struct filename, iname))

inline int copy_para_from_user(unsigned long addr, char *buf, size_t buf_len)
{
    size_t len;

    if (!buf || addr == 0)
        return -EINVAL;

    len = strnlen_user((void __user *)addr, MAX_ARG_STRLEN);
    if (len < 0 || len > buf_len)
        return -EOVERFLOW;

    if (copy_from_user(buf, (void __user *)addr, len))
        return -ENOMEM;

    return 0;
}

static inline int __register_entry(unsigned long entry_ino, const char *entry_name,
    const char *jumper_name, bool if_hijacker)
{
    struct upatch_entry_des value;

    memset(&value, 0, sizeof(value));
    value.ref = 1;
    value.if_hijacker = if_hijacker;
    value.self_ino = entry_ino;
    strcpy((char *)&value.jumper_path, jumper_name);
    return entry_get(entry_name, &value);
}

static inline int __unregister_entry(const char *entry_name)
{
    return entry_put(entry_name);
}

static int register_entry(unsigned long prey_ino, const char *prey_name,
    unsigned long hijacker_ino, const char *hijacker_name)
{
    int ret;

    ret = __register_entry(prey_ino, prey_name, hijacker_name, 0);
    if (ret)
        goto out;

    ret = __register_entry(hijacker_ino, hijacker_name, prey_name, 1);
    if (ret)
        goto out_clean;

    goto out;
out_clean:
    __unregister_entry(prey_name);
out:
    return ret;
}

static int unregister_entry(const char *prey_name, const char *hijacker_name)
{
    __unregister_entry(prey_name);
    __unregister_entry(hijacker_name);
    return 0;
}

static int hijacker_handler(unsigned int cmd, unsigned long arg)
{
    int ret;
    char prey_name[UPATCH_ENTRY_MAX_LEN];
    char hijacker_name[UPATCH_ENTRY_MAX_LEN];
    struct upatch_hijack_msg msg;

    ret = -ENOMEM;
    if (copy_from_user(&msg, (const void __user *)arg, sizeof(struct upatch_hijack_msg)))
        goto out;

    ret = copy_para_from_user((unsigned long)msg.prey_name,
        (char *)&prey_name, UPATCH_ENTRY_MAX_LEN);
    if (ret)
        goto out;

    ret = copy_para_from_user((unsigned long)msg.hijacker_name,
        (char *)&hijacker_name, UPATCH_ENTRY_MAX_LEN);
    if (ret)
        goto out;

    if (cmd == UPATCH_HIJACKER_REGISTER)
        ret = register_entry(msg.prey_ino, (char *)&prey_name,
            msg.hijacker_ino, (char *)&hijacker_name);
    else
        ret = unregister_entry((char *)&prey_name, (char *)&hijacker_name);
out:
    if (ret)
        pr_err("hijack entry failed - %d \n", ret);
    return ret;
}

static long hijacker_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    if (_IOC_TYPE(cmd) != UPATCH_HIJACKER_MAGIC)
        return -EINVAL;

    switch (cmd) {
    case UPATCH_HIJACKER_REGISTER:
    case UPATCH_HIJACKER_UNREGISTER:
        return hijacker_handler(cmd, arg);
    default:
        return -ENOTTY;
    }
    return 0;
}

static int __kprobes hijack_execve_pre(struct kprobe *p, struct pt_regs *ctx)
{
    struct upatch_entry_des value;
    unsigned long caller_ino;
    struct filename *filename = NULL;

    if (!entries_enabled())
        goto out;

    caller_ino = current->mm->exe_file->f_inode->i_ino;
    filename = (void *)regs_get_kernel_argument(ctx, 1);
    if (strlen(filename->name) + 1 > UPATCH_ENTRY_MAX_LEN)
        goto out;

    if (entries_lookup(filename->name, &value))
        goto out;

    if ((value.if_hijacker && value.self_ino == caller_ino) ||
        (!value.if_hijacker && value.self_ino != caller_ino))
        memcpy((char *)filename->name, (char *)&value.jumper_path, UPATCH_ENTRY_MAX_LEN);
out:
    return 0;
}

static struct kprobe hijacker_kprobe = {
    .pre_handler = hijack_execve_pre,
    .post_handler = NULL,
};

static const struct file_operations hijacker_ops = {
    .owner		    = THIS_MODULE,
    .unlocked_ioctl = hijacker_ioctl,
};

static struct miscdevice upatch_hijacker = {
    .minor = MISC_DYNAMIC_MINOR,
    .mode  = 0660,
    .name  = UPATCH_HIJACKER_DEV_NAME,
    .fops  = &hijacker_ops,
};

static int __init upatch_hijacker_init(void)
{
    int ret;

    ret = -EINVAL;
    if (UPATCH_ENTRY_MAX_LEN >= EMBEDDED_NAME_MAX) {
        pr_err("overflowed name for upatch-hijacker \n");
        goto out;
    }

    ret = misc_register(&upatch_hijacker);
    if (ret) {
        pr_err("register misc device for %s failed \n", UPATCH_HIJACKER_DEV_NAME);
        goto out;
    }

    hijacker_kprobe.symbol_name = "do_execveat_common.isra.0";
    ret = register_kprobe(&hijacker_kprobe);
    if (ret == -ENOENT) {
        /* If not found, try another name */
        hijacker_kprobe.symbol_name = "do_execveat_common";
        ret = register_kprobe(&hijacker_kprobe);
    }

    if (ret < 0) {
        pr_err("register kprobe for execve failed - %d \n", ret);
        goto out_clean;
    }

    goto out;
out_clean:
    misc_deregister(&upatch_hijacker);
out:
    return ret;
}

static void __exit upatch_hijacker_exit(void)
{
    misc_deregister(&upatch_hijacker);
    unregister_kprobe(&hijacker_kprobe);
}

module_init(upatch_hijacker_init);
module_exit(upatch_hijacker_exit);
MODULE_AUTHOR("Longjun Luo (luolongjuna@gmail.com)");
MODULE_DESCRIPTION("kernel module for upatch-hijacker (live-patch in userspace)");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");  
