/*
 * Cray kfabric CXI provider address vector.
 * Copyright 2019 Hewlett Packard Enterprise Development LP. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0
 */
#include <linux/slab.h>

#include "kcxi_prov.h"

static void kcxi_update_av_table(struct kcxi_av *_av)
{
	/* Assume that av was checked by calling function */
	_av->table = (void *)_av->table_hdr + sizeof(struct kcxi_av_table_hdr);
}

/* This check may be unnecessary but better safe than sorry. */
static int kcxi_verify_table_count(uint64_t count, uint64_t rx_ctx_mask)
{
	/*
	 * Since the index is a signed value, check to see if the new count may
	 * have wrapped to a negative index.
	 */
	if ((int)count < 0)
		return -EINVAL;

	/*
	 * If RX bits were specified, verify that the new count does not allow
	 * for indices to be in the RX bit space.
	 */
	if (count & ~rx_ctx_mask)
		return -EINVAL;

	return 0;
}

static int kcxi_resize_av_table(struct kcxi_av *av)
	__must_hold(&av->table_lock)
{
	/* Assume that av was checked by calling function */
	void *new_addr;
	uint64_t new_count;
	uint64_t table_sz;
	int rc;

	new_count = av->table_hdr->size * 2;
	table_sz = KCXI_AV_TABLE_SZ(new_count);

	rc = kcxi_verify_table_count(new_count, av->mask);
	if (rc)
		return rc;

	new_addr = krealloc(av->table_hdr, table_sz, GFP_ATOMIC);
	if (!new_addr)
		return -ENOMEM;

	av->table_hdr = new_addr;
	av->table_hdr->size = new_count;
	kcxi_update_av_table(av);

	return 0;
}

static void kcxi_av_mark_index_allocated(struct kcxi_av *av, int index)
	__must_hold(&av->table_lock)
{
	struct kcxi_addr *addr;

	addr = av->table + index;
	KCXI_ADDR_AV_ENTRY_SET_ALLOCATED(addr);
}

static int kcxi_av_get_next_index(struct kcxi_av *av)
	__must_hold(&av->table_lock)
{
	/* Assume that av was checked by calling function */
	int i;
	struct kcxi_addr *addr;

	for (i = 0; i < av->table_hdr->size; i++) {
		addr = av->table + i;
		if (!KCXI_ADDR_AV_ENTRY_ALLOCATED(addr))
			return i;
	}

	return -1;
}

static int kcxi_av_get_index(struct kcxi_av *av)
	__must_hold(&av->table_lock)
{
	int rc;
	int index;

	if (!av)
		return -EINVAL;

	/*
	 * If the AV stored value is equal to the size value, all
	 * entries in the AV may be used.
	 */
	if (av->table_hdr->stored == av->table_hdr->size) {

		/*
		 * It is possible that one of the previous addresses in
		 * the AV was removed meaning that there may be a free
		 * index.
		 */
		index = kcxi_av_get_next_index(av);
		if (index < 0) {

			/*
			 * If the index is not greater than zero, there
			 * was no free index in the table. Next step is
			 * to try and grow the table.
			 */
			rc = kcxi_resize_av_table(av);
			if (rc)
				return rc;

			index = av->table_hdr->stored++;
		}
	} else {
		index = av->table_hdr->stored++;
	}

	kcxi_av_mark_index_allocated(av, index);

	return index;
}

static void kcxi_av_write_addr(struct kcxi_av *av, const struct kcxi_addr *addr,
			       unsigned int index)
{
	struct kcxi_addr *av_addr;

	av_addr = av->table + index;
	av_addr->nic = addr->nic;
	av_addr->pid = addr->pid;

	KCXI_ADDR_AV_ENTRY_SET_VALID(av_addr);
}

static void kcxi_av_clear_index(struct kcxi_av *av, unsigned int index)
{
	struct kcxi_addr *av_addr;

	av_addr = av->table + index;

	KCXI_ADDR_AV_ENTRY_CLR_VALID(av_addr);
	KCXI_ADDR_AV_ENTRY_CLR_ALLOCATED(av_addr);
}

static int kcxi_av_free_kfi_addrs(struct kcxi_av *av, kfi_addr_t *fi_addr,
				  size_t count)
{
	int i;
	int index;

	write_lock(&av->table_lock);

	for (i = 0; i < count; i++) {
		if (fi_addr[i] == KFI_ADDR_NOTAVAIL)
			continue;

		index = (fi_addr[i] & av->mask);
		if (index >= (int)av->table_hdr->size || index < 0) {
			write_unlock(&av->table_lock);
			return -EINVAL;
		}

		kcxi_av_clear_index(av, index);
	}

	write_unlock(&av->table_lock);

	return 0;
}

static void kcxi_av_report_error(struct kcxi_av *av, int index, int rc,
				 void *context)
{
	struct kfi_eq_err_entry error = {};

	if (!av->eq)
		return;

	error.fid = &av->av_fid.fid;
	error.context = context;
	error.data = index;
	error.err = ETIMEDOUT;
	error.prov_errno = rc;

	kcxi_eq_report_error(av->eq, &error);
}

static void kcxi_av_report_event(struct kcxi_av *av, int resolved_count,
				 void *context)
{
	struct kfi_eq_entry event = {};

	if (!av->eq)
		return;

	event.fid = &av->av_fid.fid;
	event.context = context;
	event.data = resolved_count;

	kcxi_eq_report_event(av->eq, KFI_AV_COMPLETE, &event);
}

/* AV async resolution context structure. */
struct kcxi_av_async_res {
	struct kcxi_av *av;
	int *av_index;
	int count;
	void *context;
};

static struct kcxi_av_async_res *kcxi_av_async_res_alloc(int count)
{
	struct kcxi_av_async_res *entry;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		goto error;

	entry->av_index = kcalloc(count, sizeof(*entry->av_index), GFP_KERNEL);
	if (!entry->av_index)
		goto error_free_entry;

	entry->count = count;

	return entry;

error_free_entry:
	kfree(entry);
error:
	return NULL;
}

static void kcxi_av_async_res_free(struct kcxi_av_async_res *entry)
{
	kfree(entry->av_index);
	kfree(entry);
}

/**
 * kcxi_av_addr_res_cb() - AV asynchronous resolution callback.
 * @nic: Resolved NIC address.
 * @pid: Resolved PID.
 * @rc: Return code from the asynchronous resolution. If zero, NIC address and
 * PID are valid.
 * @context: User provided context.
 *
 * This function will fill in the AV table with the results of the asynchronous
 * resolution. Note that the AV indices are already allocated and stored within
 * the AV index array field within AV async resolution context structure.
 */
static void kcxi_av_addr_res_cb(uint32_t nic, uint16_t pid, int rc,
				void *context)
{
	struct kcxi_av_async_res *entry;
	struct kcxi_addr addr = {};
	int i;
	int index;
	int resolved_count = 0;

	entry = context;

	addr.nic = nic;
	addr.pid = pid;

	if (rc)
		LOG_ERR("Async resolution failed: rc=%d", rc);
	else
		LOG_DEBUG("Async resolved NIC address (%d) PID (%d)", nic, pid);

	for (i = 0; i < entry->count; i++, addr.nic++) {
		index = entry->av_index[i];

		/* Indices less than zero are errors. */
		if (index < 0) {
			kcxi_av_report_error(entry->av, i, index,
					     entry->context);
			continue;
		}

		/* Cannot write AV address if resolution failed. */
		if (rc) {
			kcxi_av_report_error(entry->av, i, rc, entry->context);
			continue;
		}

		kcxi_av_write_addr(entry->av, &addr, index);

		resolved_count++;
	}

	kcxi_av_report_event(entry->av, resolved_count, entry->context);

	/* Trigger the EQ event handler. */
	if (entry->av->eq)
		kcxi_eq_raise_handler(entry->av->eq);

	kcxi_av_async_res_free(entry);
}

/**
 * kcxi_check_table_in_async() - Insert address into the AV asynchronously.
 * @av: Address vector.
 * @node: Node string.
 * @service: Service string.
 * @fi_addr: User KFI address array.
 * @count: Size of KFI address array.
 * @flags: Operation flags.
 * @context: Operation context.
 *
 * This function will allocate KFI addresses (AV table indices from the array
 * and return these KFI addresses to the user. Note that these addresses are NOT
 * valid until an AV complete event occurs on the EQ bound to the AV.
 *
 * Once the KFI addresses are allocated, an asynchronous request structure is
 * built and the node and service strings are submitted for resolution. Async
 * processing will be completed in kcxi_av_addr_res_cb().
 *
 * Return: On success, number of addresses submitted for resolution. On error,
 * negative kfabric errno.
 */
static int kcxi_check_table_in_async(struct kcxi_av *av, const char *node,
				     const char *service, kfi_addr_t *fi_addr,
				     int count, uint64_t flags, void *context)
{
	struct kcxi_av_async_res *entry;
	int index;
	int rc;
	int i;

	if ((av->attr.flags & KFI_EVENT) && !av->eq)
		return -KFI_ENOEQ;

	/* Build up the AV async resolution entry. */
	entry = kcxi_av_async_res_alloc(count);
	if (!entry)
		return -ENOMEM;

	entry->av = av;
	entry->context = context;

	/* Allocate a block of AV indexes. */
	write_lock(&av->table_lock);

	for (i = 0; i < count; i++) {

		/* Allocate an unused AV index. */
		rc = kcxi_av_get_index(av);
		if (rc < 0) {
			if (fi_addr)
				fi_addr[i] = KFI_ADDR_NOTAVAIL;

			entry->av_index[i] = rc;
			continue;
		}

		index = rc;

		if (fi_addr)
			fi_addr[i] = (kfi_addr_t)index;

		entry->av_index[i] = index;
	}

	write_unlock(&av->table_lock);

	/* Issue the asynchronous resolution request. */
	rc = kcxi_addr_res_dest_info_async(node, service, kcxi_av_addr_res_cb,
					   entry);
	if (rc)
		goto error_free_index_array;

	return count;

error_free_index_array:
	kcxi_av_free_kfi_addrs(av, fi_addr, count);
	kcxi_av_async_res_free(entry);

	return rc;
}

/**
 * kcxi_check_table_in_sync() - Insert address into the AV synchronously.
 * @av: Address vector.
 * @addr: Resolved kCXI address.
 * @fi_addr: User KFI address array.
 * @count: Size of KFI address array.
 * @flags: Operation flags.
 * @context: Operation context.
 *
 * This function will allocate KFI addresses (AV table indices from the array
 * and return these KFI addresses to the user. Each of these addresses will be
 * back by a kCXI address.
 *
 * Return: On success, number of addresses submitted for resolution. On error,
 * negative kfabric errno.
 */
static int kcxi_check_table_in_sync(struct kcxi_av *av, struct kcxi_addr *addr,
				    kfi_addr_t *fi_addr, int count,
				    uint64_t flags, void *context)
{
	int i;
	int rc;
	int resolved_count = 0;
	int index;

	if (!av || !addr)
		return 0;

	if ((av->attr.flags & KFI_EVENT) && !av->eq)
		return -KFI_ENOEQ;

	write_lock(&av->table_lock);

	for (i = 0; i < count; i++, addr->nic++) {
		/* Allocate an unused AV index. */
		rc = kcxi_av_get_index(av);
		if (rc < 0) {
			if (fi_addr)
				fi_addr[i] = KFI_ADDR_NOTAVAIL;

			kcxi_av_report_error(av, i, rc, context);
			continue;
		}

		index = rc;

		kcxi_av_write_addr(av, addr, index);

		/* Return the index to the user as a kfi_addr_t. */
		if (fi_addr)
			fi_addr[i] = (kfi_addr_t)index;

		resolved_count++;
	}

	write_unlock(&av->table_lock);

	kcxi_av_report_event(av, resolved_count, context);

	/* Trigger the EQ event handler. */
	if (av->eq)
		kcxi_eq_raise_handler(av->eq);

	return resolved_count;
}

/**
 * kcxi_av_reverse_lookup() - Lookup the KFI address by NIC and PID.
 * @av: Address vector the lookup will occur on.
 * @nic: NIC address to lookup.
 * @pid: PID value to lookup.
 *
 * Return: If found, a valid KFI address is returned. If not found,
 * KFI_ADDR_NOTAVAIL is returned.
 */
kfi_addr_t kcxi_av_reverse_lookup(struct kcxi_av *av, uint32_t nic,
				  uint16_t pid)
{
	kfi_addr_t src_addr = KFI_ADDR_NOTAVAIL;
	int i;
	struct kcxi_addr *addr;

	if (!av)
		return src_addr;

	read_lock(&av->table_lock);

	for (i = 0; i < av->table_hdr->size; i++) {
		addr = av->table + i;

		if (addr->nic == nic && addr->pid == pid) {
			src_addr = i;
			break;
		}
	}

	read_unlock(&av->table_lock);

	return src_addr;
}

static int kcxi_av_lookup(struct kfid_av *av, kfi_addr_t fi_addr, void *addr,
			  size_t *addrlen)
{
	int index;
	struct kcxi_av *_av;
	struct kcxi_addr *av_addr;

	/*
	 *  AV does not need to be checked since kfabric would have
	 *  dereferenced.
	 */
	if (!addr || !addrlen)
		return -EINVAL;

	_av = container_of(av, struct kcxi_av, av_fid);

	read_lock(&_av->table_lock);

	index = (fi_addr & _av->mask);
	if (index >= (int)_av->table_hdr->size || index < 0)
		goto err;

	av_addr = _av->table + index;
	if (!KCXI_ADDR_AV_ENTRY_VALID(av_addr))
		goto err;

	memcpy(addr, av_addr, min(*addrlen, sizeof(*av_addr)));

	read_unlock(&_av->table_lock);

	*addrlen = sizeof(*av_addr);
	return 0;

err:
	read_unlock(&_av->table_lock);
	return -EINVAL;
}

static int kcxi_av_insertsvc(struct kfid_av *av, const char *node,
			     const char *service, kfi_addr_t *fi_addr,
			     uint64_t flags, void *context)
{
	/*
	 *  AV does not need to be checked since kfabric would have
	 *  dereferenced. Leave all the other checking of pointers to the other
	 *  functions.
	 */
	int rc;
	struct kcxi_av *_av;
	struct kcxi_addr addr = {};

	_av = container_of(av, struct kcxi_av, av_fid);

	/* If AV is opened with KFI_EVENT flag, perform asynchronous address
	 * resolution.
	 */
	if (_av->attr.flags & KFI_EVENT) {
		rc = kcxi_check_table_in_async(_av, node, service, fi_addr, 1,
					       flags, context);
	} else {
		rc = kcxi_addr_res_dest_info(node, service, &addr);
		if (rc)
			return rc;

		rc = kcxi_check_table_in_sync(_av, &addr, fi_addr, 1, flags,
					      context);
	}

	return rc;
}

static int kcxi_av_remove(struct kfid_av *av, kfi_addr_t *fi_addr, size_t count,
			  uint64_t flags)
{
	struct kcxi_av *_av;

	/*
	 * AV does not need to be checked since kfabric would have
	 * dereferenced.
	 */
	if (!fi_addr)
		return -EINVAL;

	_av = container_of(av, struct kcxi_av, av_fid);

	return kcxi_av_free_kfi_addrs(_av, fi_addr, count);
}

static const char *kcxi_av_straddr(struct kfid_av *av, const void *addr,
				   char *buf, size_t *len)
{
	size_t size;
	uint64_t kcxi_addr;

	/*
	 * AV does not need to be checked since kfabric would have
	 * dereferenced.
	 */
	if (!addr || !len)
		return NULL;

	kcxi_addr = ((struct kcxi_addr *)addr)->qw;

	size = snprintf(buf, *len, "kfi_addr_kcxi://0x%llx", kcxi_addr);

	/* Make sure that possibly truncated messages have a null terminator. */
	if (buf && *len)
		buf[*len - 1] = '\0';
	*len = size + 1;

	return buf;
}

static int kcxi_av_bind(struct kfid *fid, struct kfid *bfid, uint64_t flags)
{
	struct kcxi_av *av;
	struct kcxi_eq *eq;

	/*
	 * Fid does not need to be checked since kfabric would have
	 * dereferenced.
	 */
	if (!bfid || bfid->fclass != KFI_CLASS_EQ)
		return -EINVAL;

	av = container_of(fid, struct kcxi_av, av_fid.fid);
	eq = container_of(bfid, struct kcxi_eq, eq.fid);

	if (av->eq)
		return -EINVAL;

	atomic_inc(&eq->ref_cnt);
	av->eq = eq;

	return 0;
}

static int kcxi_av_close(struct kfid *fid)
{
	/*
	 * Fid does not need to be checked since kfabric would have
	 * dereferenced.
	 */
	struct kcxi_av *av;

	av = container_of(fid, struct kcxi_av, av_fid.fid);
	if (atomic_read(&av->ref_cnt))
		return -EBUSY;

	if (av->eq)
		atomic_dec(&av->eq->ref_cnt);

	atomic_dec(&av->domain->ref_cnt);

	kfree(av->table_hdr);
	kfree(av);

	return 0;
}

static struct kfi_ops kcxi_av_kfi_ops = {
	.close = kcxi_av_close,
	.bind = kcxi_av_bind,
	.control = kfi_no_control,
	.ops_open = kfi_no_ops_open
};

static struct kfi_ops_av kcxi_av_ops = {
	.insert = kfi_no_av_insert,
	.insertsvc = kcxi_av_insertsvc,
	.remove = kcxi_av_remove,
	.lookup = kcxi_av_lookup,
	.straddr = kcxi_av_straddr
};

static int kcxi_verify_av_attr(const struct kfi_av_attr *attr)
{
	if (!attr)
		return -EINVAL;

	switch (attr->type) {
	case KFI_AV_TABLE:
	case KFI_AV_MAP:
	case KFI_AV_UNSPEC:
		break;
	default:
		return -EINVAL;
	};

	/*
	 * TODO: Does it make sense for KFI_READ to be a flag for AV attrs?
	 * KFI_READ and named AV instances are used for processes sharing an
	 * AV (shared memory). Since the kernel is a "single process", all
	 * memory is shared. But, it does not make sense to share AVs across
	 * kernel services. For example, why would iSCSI over kfabric want to
	 * use the AV kfilnd allocated? If kfilnd were to close the AV and the
	 * domain the AV was allocated against, iSCSI would be using an
	 * orphaned AV.
	 *
	 * For now, don't support read and named instances.
	 */

	if (attr->name)
		return -EINVAL;

	if (attr->flags & (KFI_READ | KFI_SYMMETRIC))
		return -EINVAL;

	if (attr->rx_ctx_bits > KCXI_EP_MAX_CTX_BITS)
		return -EINVAL;

	return 0;
}

int kcxi_av_open(struct kfid_domain *domain, struct kfi_av_attr *attr,
		 struct kfid_av **av, void *context)
{
	int rc;
	struct kcxi_domain *dom;
	struct kcxi_av *_av;
	size_t table_sz;

	/*
	 * Domain does not need to be checked since kfabric would have
	 * dereferenced.
	 */
	if (!attr || !av)
		return -EINVAL;

	rc = kcxi_verify_av_attr(attr);
	if (rc)
		return rc;

	dom = container_of(domain, struct kcxi_domain, dom_fid);
	if (dom->attr.av_type != KFI_AV_UNSPEC &&
	    dom->attr.av_type != attr->type)
		return -EINVAL;

	_av = kzalloc(sizeof(*_av), GFP_KERNEL);
	if (!_av)
		return -ENOMEM;

	_av->attr = *attr;

	/*
	 * The table type really doesn't matter since this implementation
	 * accounts for both KFI_AV_TABLE and KFI_AV_MAP.
	 */
	if (_av->attr.type == KFI_AV_UNSPEC)
		_av->attr.type = KFI_AV_MAP;

	if (!_av->attr.count)
		_av->attr.count = KCXI_AV_DEF_SZ;

	_av->av_fid.fid.fclass = KFI_CLASS_AV;
	_av->av_fid.fid.context = context;
	_av->av_fid.fid.ops = &kcxi_av_kfi_ops;
	_av->av_fid.ops = &kcxi_av_ops;
	_av->domain = dom;
	rwlock_init(&_av->table_lock);
	atomic_set(&_av->ref_cnt, 0);

	/*
	 * The AV mask is used to identify RX CTX bits. Table indices must NOT
	 * intrude into this space.
	 */
	_av->mask = attr->rx_ctx_bits ?
		((uint64_t)1 << (64 - attr->rx_ctx_bits)) - 1 : ~0;

	/*
	 * Verify that the table count (number of items) does not intrude the
	 * space reserved for RX CTXs.
	 */
	rc = kcxi_verify_table_count(_av->attr.count, _av->mask);
	if (rc)
		goto err;

	/* The table count checks out so allocate the table. */
	table_sz = KCXI_AV_TABLE_SZ(_av->attr.count);
	_av->table_hdr = kzalloc(table_sz, GFP_KERNEL);
	if (!_av->table_hdr) {
		rc = -ENOMEM;
		goto err;
	}
	kcxi_update_av_table(_av);
	_av->table_hdr->size = _av->attr.count;

	atomic_inc(&_av->domain->ref_cnt);

	*av = &_av->av_fid;
	return 0;

err:
	kfree(_av);
	return rc;
}
