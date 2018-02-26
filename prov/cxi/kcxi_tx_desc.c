//SPDX-License-Identifier: GPL-2.0
/*
 * Cray kfabric CXI provider transmit descriptor.
 * Copyright 2019,2021,2023 Hewlett Packard Enterprise Development LP. All rights reserved.
 */
#include <linux/slab.h>

#include "kcxi_prov.h"

static struct kmem_cache *tx_desc_cache;

/**
 * kcxi_tx_desc_init_cache() - Initialize the transmit descriptor cache.
 * Return: 0 on success. Else, negative errno.
 */
int kcxi_tx_desc_init_cache(void)
{
	tx_desc_cache = kmem_cache_create("kcxi_tx_desc",
					  sizeof(struct kcxi_tx_desc), 0,
					  SLAB_HWCACHE_ALIGN,
					  NULL);
	if (!tx_desc_cache)
		return -ENOMEM;

	return 0;
}

/**
 * kcxi_tx_desc_destroy_cache() - Destroy the transmit descriptor cache.
 */
void kcxi_tx_desc_destroy_cache(void)
{
	kmem_cache_destroy(tx_desc_cache);
}

/**
 * kcxi_tx_desc_free() - Free a TX descriptor.
 * @tx_desc: TX descriptor to be freed.
 *
 * Freeing will decrement counters associated with this TX descriptor. These
 * counters are the TX context posted counter and the TX context CQ active
 * operation counter.
 */
void kcxi_tx_desc_free(struct kcxi_tx_desc *tx_desc)
{
	if (!tx_desc)
		return;

	atomic_dec(&tx_desc->tx_ctx->posted_tx_cnt);
	kmem_cache_free(tx_desc_cache, tx_desc);
}

/**
 * kcxi_tx_desc_alloc() - Allocate a TX descriptor.
 * @tx_ctx: TX context associated with the TX descriptor.
 *
 * Allocation will increment counters associated with this TX descriptor. These
 * counters are the TX context posted counter and the TX context CQ active
 * operation counter.
 *
 * Only TX descriptor field set during allocation is the tx_ctx. Users should
 * set the remaining fields accordingly.
 *
 * Return: On success, valid pointer. Else, negative errno pointer.
 */
struct kcxi_tx_desc *kcxi_tx_desc_alloc(struct kcxi_tx_ctx *tx_ctx)
{
	struct kcxi_tx_desc *tx_desc;
	int rc;

	if (!tx_ctx) {
		rc = -EINVAL;
		goto err;
	}

	tx_desc = kmem_cache_zalloc(tx_desc_cache, GFP_NOWAIT);
	if (!tx_desc) {
		rc = -ENOMEM;
		goto err;
	}

	tx_desc->tx_ctx = tx_ctx;

	atomic_inc(&tx_ctx->posted_tx_cnt);

	return tx_desc;

err:
	return ERR_PTR(rc);
}
