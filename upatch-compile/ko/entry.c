#include <linux/spinlock.h>

#include "upatch-entry.h"

struct entry_ht {
    struct upatch_entry key;
    struct upatch_entry_des value;
};

static DEFINE_SPINLOCK(entries_lock);
static struct entry_ht entries[UPATCH_MAX_HIJACK_ENTRY];
static volatile unsigned int entries_total_ref = 0;

inline int entries_enabled(void)
{
    return !!entries_total_ref;
}

static struct entry_ht *__entries_lookup(const char *search)
{
    int i;
    for (i = 0; i < UPATCH_MAX_HIJACK_ENTRY; i ++) {
        if (strcmp((char *)&entries[i].key.name, search) == 0)
            return &entries[i];
    }
    return NULL;
}

int entries_lookup(const char *search, struct upatch_entry_des *value)
{
    int ret = -ENOENT;
    struct entry_ht *ht = NULL;

    if (!value)
        return -EINVAL;

    spin_lock(&entries_lock);
    ht = __entries_lookup(search);
    if (ht) {
        memcpy(value, &ht->value, sizeof(*value));
        ret = 0;
    }
    spin_unlock(&entries_lock);
    return ret;
}

static int __entry_create(const char *search, struct upatch_entry_des *value)
{
    int ret;
    struct entry_ht *ht = NULL;

    if (!value)
        return -EINVAL;

    ht = __entries_lookup(search);
    if (ht) {
        ret = -EPERM;
        goto out;
    }
        
    ht = __entries_lookup("");
    if (!ht) {
        ret = -EOVERFLOW;
        goto out;
    }

    strcpy((char *)&ht->key.name, search);
    memcpy(&ht->value, value, sizeof(*value));
    entries_total_ref ++;
    ret = 0;
out:
    return ret;
}

int __entry_sync(struct entry_ht *ht, struct upatch_entry_des *value)
{
    if (strcmp((char *)&ht->value.jumper_path, (char *)&value->jumper_path) != 0
        || ht->value.if_hijacker != value->if_hijacker)
        return -EINVAL;
    ht->value.ref ++;
    entries_total_ref ++;
    return 0;
}

int entry_get(const char *search, struct upatch_entry_des *value)
{
    int ret = 0;
    struct entry_ht *ht = NULL;
    spin_lock(&entries_lock);
    ht = __entries_lookup(search);
    if (ht)
        ret = __entry_sync(ht, value);
    else
        ret = __entry_create(search, value);
    spin_unlock(&entries_lock);
    return ret;
}

int entry_put(const char *search)
{
    int ret = -EPERM;
    struct entry_ht *ht = NULL;
    spin_lock(&entries_lock);
    if (entries_total_ref == 0)
        goto out;
    
    ret = -ENOENT;
    ht = __entries_lookup(search);
    if (!ht)
        goto out;

    ht->value.ref --;
    if (ht->value.ref == 0)
        memset(ht, 0, sizeof(*ht));
    entries_total_ref --;
out:
    spin_unlock(&entries_lock);
    return ret;
}