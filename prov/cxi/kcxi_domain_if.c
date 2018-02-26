//SPDX-License-Identifier: GPL-2.0
/*
 * Cray kfabric CXI provider domain interface.
 * Copyright 2019,2021-2022 Hewlett Packard Enterprise Development LP. All rights reserved.
 */
#include <linux/slab.h>

#include "kcxi_prov.h"

/**
 * kcxi_domain_if_index_reserve() - Reserve PID index
 * @dom_if: Domain interface
 * @index: PID index
 *
 * Note: Reserving a PID index protects against allocating the same PltTE.
 *
 * Return: 0 on success. Else, negative errno.
 */
int kcxi_domain_if_index_reserve(struct kcxi_domain_if *dom_if,
				 unsigned int index)
{
	if (index > dom_if->max_index)
		return -EINVAL;

	mutex_lock(&dom_if->lock);
	if (test_bit(index, dom_if->index_bitmap)) {
		mutex_unlock(&dom_if->lock);
		return -EADDRINUSE;
	}

	bitmap_set(dom_if->index_bitmap, index, 1);

	atomic_inc(&dom_if->ref_cnt);

	mutex_unlock(&dom_if->lock);

	return 0;
}

/**
 * kcxi_domain_if_index_release() - Release PID index
 * @dom_if: Domain interface
 * @index: PID index
 */
void kcxi_domain_if_index_release(struct kcxi_domain_if *dom_if,
				  unsigned int index)
{
	if (index > dom_if->max_index)
		return;

	mutex_lock(&dom_if->lock);

	if (test_bit(index, dom_if->index_bitmap)) {
		bitmap_clear(dom_if->index_bitmap, index, 1);

		atomic_dec(&dom_if->ref_cnt);
	}

	mutex_unlock(&dom_if->lock);
}

/**
 * kcxi_domain_if_alloc() - Allocate a domain interface
 * @kcxi_if: kCXI interface
 * @auth_key: Authorization key (VNI) of interface
 * @pid: PID of interface
 *
 * Note: Conceptually, a domain interface is a portal table. The size of the
 * portal table is equal to the CXI device PID granule. Each index, sometimes
 * called PID index or offset, is where a PtlTE can be allocated.
 *
 * Return: Valid pointer on success. Else, errno pointer.
 */
struct kcxi_domain_if *kcxi_domain_if_alloc(struct kcxi_if *kcxi_if,
					    unsigned int auth_key,
					    unsigned int pid)
{
	struct kcxi_domain_if *kcxi_dom_if;
	size_t bitmap_size;
	int rc;
	char domain_if_debugfs_dir_name[32];

	kcxi_dom_if = kzalloc(sizeof(*kcxi_dom_if), GFP_KERNEL);
	if (!kcxi_dom_if) {
		rc = -ENOMEM;
		goto err;
	}

	kcxi_dom_if->dom = cxi_domain_alloc(kcxi_if->lni, auth_key, pid);
	if (IS_ERR(kcxi_dom_if->dom)) {
		rc = PTR_ERR(kcxi_dom_if->dom);
		goto err_free_dom_if;
	}

	kcxi_dom_if->max_index = kcxi_if->dev->pid_granule / 2 - 1;
	bitmap_size = BITS_TO_LONGS(kcxi_dom_if->max_index) * sizeof(long);
	kcxi_dom_if->index_bitmap = kzalloc(bitmap_size, GFP_KERNEL);
	if (!kcxi_dom_if->index_bitmap) {
		rc = -ENOMEM;
		goto err_free_dom;
	}

	rc = snprintf(domain_if_debugfs_dir_name,
		      sizeof(domain_if_debugfs_dir_name), "dom_if%u_%u",
		      pid, auth_key);
	if (rc >= sizeof(domain_if_debugfs_dir_name)) {
		rc = -ENOMEM;
		goto err_free_dom_bitmap;
	} else if (rc < 0) {
		goto err_free_dom_bitmap;
	}

	kcxi_dom_if->dom_if_debugfs_dir =
		debugfs_create_dir(domain_if_debugfs_dir_name,
				   kcxi_if->if_debugfs_dir);

	kcxi_dom_if->kcxi_if = kcxi_if;
	kcxi_dom_if->pid = kcxi_dom_if->dom->pid;
	kcxi_dom_if->auth_key = auth_key;

	atomic_set(&kcxi_dom_if->ref_cnt, 0);

	atomic_inc(&kcxi_if->ref_cnt);

	KCXI_DOM_IF_DEBUG(kcxi_dom_if, "Domain interface allocated");

	return kcxi_dom_if;

err_free_dom_bitmap:
	kfree(kcxi_dom_if->index_bitmap);
err_free_dom:
	cxi_domain_free(kcxi_dom_if->dom);
err_free_dom_if:
	kfree(kcxi_dom_if);
err:
	return ERR_PTR(rc);
}

/**
 * kcxi_domain_if_free() - Free a domain interface
 * @kcxi_dom_if: kCXI domain interface to be freed
 *
 * Note: -EBUSY is returned if domain interface is still in use.
 *
 * Return: 0 on success. Else, negative errno.
 */
int kcxi_domain_if_free(struct kcxi_domain_if *kcxi_dom_if)
{
	if (atomic_read(&kcxi_dom_if->ref_cnt))
		return -EBUSY;

	KCXI_DOM_IF_DEBUG(kcxi_dom_if, "Domain interface freed");

	debugfs_remove_recursive(kcxi_dom_if->dom_if_debugfs_dir);

	atomic_dec(&kcxi_dom_if->kcxi_if->ref_cnt);

	kfree(kcxi_dom_if->index_bitmap);

	cxi_domain_free(kcxi_dom_if->dom);

	kfree(kcxi_dom_if);

	return 0;
}
