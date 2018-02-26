/*
 * Cray kfabric CXI event queue.
 * Copyright 2019-2021 Hewlett Packard Enterprise Development LP. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0
 */
#include <linux/slab.h>

#include "kcxi_prov.h"

static const struct kfi_eq_attr kcxi_eq_attr = {
	.size = KCXI_EQ_DEF_SZ,
	.flags = KFI_WRITE,
	.wait_obj = KFI_WAIT_NONE,
	.signaling_vector = 0,
	.wait_set = NULL
};

static int kcxi_eq_close(struct kfid *fid)
{
	/*
	 * Don't need to check of fid is not NULL since it would have been
	 * dereferenced by kfi_close.
	 */
	struct kcxi_eq *kcxi_eq;

	kcxi_eq = container_of(fid, struct kcxi_eq, eq.fid);

	if (atomic_read(&kcxi_eq->ref_cnt))
		return -EBUSY;

	/* Dec the fabric ref count */
	atomic_dec(&kcxi_eq->fab->ref_cnt);

	kvfree(kcxi_eq->entries);
	kfree(kcxi_eq);
	return 0;
}

static ssize_t kcxi_eq_read(struct kfid_eq *eq, uint32_t *event, void *buf,
			    size_t len, uint64_t flags)
{
	int rc;
	struct kcxi_eq *kcxi_eq;
	struct kcxi_eq_entry *entry;

	/*
	 * Don't need to check EQ for NULL since it is dereferenced by
	 * kfi_eq_read.
	 */
	if (!event || !buf)
		return -EINVAL;

	kcxi_eq = container_of(eq, struct kcxi_eq, eq);

	if (atomic_read(&kcxi_eq->error_cnt) > 0)
		return -KFI_EAVAIL;

	spin_lock(&kcxi_eq->entry_list_lock);

	if (list_empty(&kcxi_eq->event_list)) {
		if (!atomic_read(&kcxi_eq->overrun))
			kcxi_eq->armed = true;

		spin_unlock(&kcxi_eq->entry_list_lock);
		if (atomic_read(&kcxi_eq->overrun))
			return -KFI_EOVERRUN;
		else
			return -EAGAIN;
	}

	entry = list_first_entry(&kcxi_eq->event_list, struct kcxi_eq_entry,
				 entry);
	if (entry->len > len) {
		spin_unlock(&kcxi_eq->entry_list_lock);
		return -KFI_ETOOSMALL;
	}

	*event = entry->type;
	memcpy(buf, &entry->event, entry->len);
	rc = entry->len;

	if (!(flags & KFI_PEEK))
		list_del(&entry->entry);

	spin_unlock(&kcxi_eq->entry_list_lock);

	if (!(flags & KFI_PEEK)) {
		/* Should entry be zeroed ? */
		spin_lock(&kcxi_eq->entry_free_list_lock);
		list_add_tail(&entry->entry, &kcxi_eq->free_list);
		spin_unlock(&kcxi_eq->entry_free_list_lock);
	}

	return rc;
}

static ssize_t kcxi_eq_readerr(struct kfid_eq *eq, struct kfi_eq_err_entry *buf,
			       uint64_t flags)
{
	int rc;
	struct kcxi_eq *kcxi_eq;
	struct kcxi_eq_entry *entry;

	/*
	 * Don't need to check EQ for NULL since it is dereferenced by
	 * kfi_eq_readerr.
	 */
	if (!buf)
		return -EINVAL;

	kcxi_eq = container_of(eq, struct kcxi_eq, eq);

	spin_lock(&kcxi_eq->entry_list_lock);

	if (list_empty(&kcxi_eq->error_list)) {
		spin_unlock(&kcxi_eq->entry_list_lock);
		if (atomic_read(&kcxi_eq->overrun))
			return -KFI_EOVERRUN;
		else
			return -EAGAIN;
	}

	/* TODO: Should error data be provided to the user ? */
	entry = list_first_entry(&kcxi_eq->error_list, struct kcxi_eq_entry,
				 entry);

	*buf = entry->error;
	rc = entry->len;

	if (!(flags & KFI_PEEK)) {
		list_del(&entry->entry);
		atomic_dec(&kcxi_eq->error_cnt);
	}

	spin_unlock(&kcxi_eq->entry_list_lock);

	if (!(flags & KFI_PEEK)) {
		/* Should entry be zeroed ? */
		spin_lock(&kcxi_eq->entry_free_list_lock);
		list_add_tail(&entry->entry, &kcxi_eq->free_list);
		spin_unlock(&kcxi_eq->entry_free_list_lock);
	}

	return rc;
}

static const char *kcxi_eq_strerror(struct kfid_eq *eq, int prov_errno,
				   const void *err_data, char *buf, size_t len)
{
	/* TODO: Should EQ string error be defined? */
	return NULL;
}


static int cxi_verify_eq_attr(const struct kfi_eq_attr *attr)
{
	if (!attr)
		return -EINVAL;

	if (attr->size > kcxi_eq_attr.size)
		goto bad_attr;

	if (attr->flags & ~kcxi_eq_attr.flags)
		goto bad_attr;

	switch (attr->wait_obj) {
	case KFI_WAIT_NONE:
		break;
	case KFI_WAIT_UNSPEC:
	case KFI_WAIT_SET:
	case KFI_WAIT_QUEUE:
	default:
		goto bad_attr;
	}

	if (attr->wait_set)
		goto bad_attr;

	return 0;

bad_attr:
	return -ENOSYS;
}

int kcxi_eq_report_event(struct kcxi_eq *kcxi_eq, uint32_t type,
			 const struct kfi_eq_entry *event)
{
	struct kcxi_eq_entry *entry;

	if (!kcxi_eq || !event)
		return -EINVAL;

	if (atomic_read(&kcxi_eq->overrun))
		return -KFI_EOVERRUN;

	spin_lock(&kcxi_eq->entry_free_list_lock);
	if (list_empty(&kcxi_eq->free_list)) {
		spin_unlock(&kcxi_eq->entry_free_list_lock);
		atomic_inc(&kcxi_eq->overrun);
		return -KFI_EOVERRUN;
	}

	entry = list_first_entry(&kcxi_eq->free_list, struct kcxi_eq_entry,
				 entry);
	list_del(&entry->entry);
	spin_unlock(&kcxi_eq->entry_free_list_lock);

	entry->len = sizeof(*event);
	entry->type = type;
	entry->event = *event;

	spin_lock(&kcxi_eq->entry_list_lock);
	list_add_tail(&entry->entry, &kcxi_eq->event_list);
	spin_unlock(&kcxi_eq->entry_list_lock);

	return 0;
}

int kcxi_eq_report_error(struct kcxi_eq *kcxi_eq,
			 const struct kfi_eq_err_entry *error)
{
	struct kcxi_eq_entry *entry;

	if (!kcxi_eq || !error)
		return -EINVAL;

	if (atomic_read(&kcxi_eq->overrun))
		return -KFI_EOVERRUN;

	spin_lock(&kcxi_eq->entry_free_list_lock);
	if (list_empty(&kcxi_eq->free_list)) {
		spin_unlock(&kcxi_eq->entry_free_list_lock);
		atomic_inc(&kcxi_eq->overrun);
		return -KFI_EOVERRUN;
	}

	entry = list_first_entry(&kcxi_eq->free_list, struct kcxi_eq_entry,
				 entry);
	list_del(&entry->entry);
	spin_unlock(&kcxi_eq->entry_free_list_lock);

	entry->len = sizeof(*error);
	entry->error = *error;

	spin_lock(&kcxi_eq->entry_list_lock);
	list_add_tail(&entry->entry, &kcxi_eq->error_list);
	atomic_inc(&kcxi_eq->error_cnt);
	spin_unlock(&kcxi_eq->entry_list_lock);

	return 0;
}

/**
 * kcxi_eq_raise_handler() - Call the kfabric EQ handler/callback.
 * @eq: The event queue
 *
 * The kfabric EQ handler/callback is only raised if the EQ has been completely
 * drained (-EAGAIN is returned when reading events/errors). The motivation for
 * this is to not notify the kfabric user every time events are written.
 */
void kcxi_eq_raise_handler(struct kcxi_eq *eq)
{
	if (!eq->eq.event_handler)
		return;

	/* Serialize access to armed using entry list lock. */
	spin_lock(&eq->entry_list_lock);
	if (!eq->armed) {
		spin_unlock(&eq->entry_list_lock);
		return;
	}

	eq->armed = false;
	spin_unlock(&eq->entry_list_lock);

	eq->eq.event_handler(&eq->eq, eq->eq.fid.context);
}

static struct kfi_ops kcxi_eq_fid_ops = {
	.close = kcxi_eq_close,
	.bind = kfi_no_bind,
	.control = kfi_no_control,
	.ops_open = kfi_no_ops_open
};

static struct kfi_ops_eq kcxi_eq_ops = {
	.read = kcxi_eq_read,
	.readerr = kcxi_eq_readerr,
	.write = kfi_no_eq_write,
	.sread = kfi_no_eq_sread,
	.strerror = kcxi_eq_strerror
};

int kcxi_eq_open(struct kfid_fabric *fabric, struct kfi_eq_attr *attr,
		 struct kfid_eq **eq, kfi_event_handler event_handler,
		 void *context)
{
	/*
	 * Don't need to check fabric for NULL since it is dereferenced by
	 * kfi_eq_open.
	 */
	int rc;
	int i;
	struct kcxi_eq *kcxi_eq;
	struct kcxi_eq_entry *entry;

	if (attr) {
		rc = cxi_verify_eq_attr(attr);
		if (rc)
			return rc;
	}

	kcxi_eq = kmalloc(sizeof(*kcxi_eq), GFP_KERNEL);
	if (!kcxi_eq)
		return -ENOMEM;

	kcxi_eq->fab = container_of(fabric, struct kcxi_fabric, fab_fid);
	kcxi_eq->eq.fid.fclass = KFI_CLASS_EQ;
	kcxi_eq->eq.fid.context = context;
	kcxi_eq->eq.fid.ops = &kcxi_eq_fid_ops;
	kcxi_eq->eq.ops = &kcxi_eq_ops;
	kcxi_eq->eq.event_handler = event_handler;
	kcxi_eq->report_event = kcxi_eq_report_event;
	kcxi_eq->report_error = kcxi_eq_report_error;
	kcxi_eq->raise_handler = kcxi_eq_raise_handler;

	if (attr)
		kcxi_eq->attr = *attr;
	else
		kcxi_eq->attr = kcxi_eq_attr;

	INIT_LIST_HEAD(&kcxi_eq->event_list);
	INIT_LIST_HEAD(&kcxi_eq->error_list);
	INIT_LIST_HEAD(&kcxi_eq->free_list);
	spin_lock_init(&kcxi_eq->entry_list_lock);
	spin_lock_init(&kcxi_eq->entry_free_list_lock);
	atomic_set(&kcxi_eq->error_cnt, 0);
	atomic_set(&kcxi_eq->overrun, 0);
	atomic_set(&kcxi_eq->ref_cnt, 0);

	/* Allocate all memory now to avoid allocation in interrupt context */
	kcxi_eq->entries = kvcalloc(kcxi_eq->attr.size,
				    sizeof(*kcxi_eq->entries), GFP_KERNEL);
	if (!kcxi_eq->entries) {
		rc = -ENOMEM;
		goto err_gen_entries;
	}

	for (i = 0; i < kcxi_eq->attr.size; i++) {
		entry = kcxi_eq->entries + i;
		list_add(&entry->entry, &kcxi_eq->free_list);
	}

	kcxi_eq->armed = true;

	/* Inc the fabric ref count */
	atomic_inc(&kcxi_eq->fab->ref_cnt);

	*eq = &kcxi_eq->eq;
	return 0;

err_gen_entries:
	kfree(kcxi_eq);
	return rc;
}
