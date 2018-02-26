//SPDX-License-Identifier: GPL-2.0
/*
 * Cray kfabric CXI provider receive descriptor.
 * Copyright 2019,2021,2023 Hewlett Packard Enterprise Development LP. All rights reserved.
 */
#include <linux/slab.h>

#include "kcxi_prov.h"

static struct kmem_cache *rx_desc_cache;

/**
 * kcxi_rx_desc_init_cache() - Initialize the receive descriptor cache.
 * Return: 0 on success. Else, negative errno.
 */
int kcxi_rx_desc_init_cache(void)
{
	rx_desc_cache = kmem_cache_create("kcxi_rx_desc",
					  sizeof(struct kcxi_rx_desc), 0,
					  SLAB_HWCACHE_ALIGN,
					  NULL);
	if (!rx_desc_cache)
		return -ENOMEM;

	return 0;
}

/**
 * kcxi_rx_desc_destroy_cache() - Destroy the receive descriptor cache.
 */
void kcxi_rx_desc_destroy_cache(void)
{
	kmem_cache_destroy(rx_desc_cache);
}

/**
 * kcxi_rx_desc_free() - Free a RX descriptor.
 * @rx_desc: RX descriptor to be freed.
 *
 * Freeing will decrement counters associated with this RX descriptor. These
 * counters are the RX context posted counter and the RX context CQ active
 * operation counter.
 *
 * In addition, the buffer ID associated with this RX descriptor will be
 * returned to the RX context CQ.
 */
void kcxi_rx_desc_free(struct kcxi_rx_desc *rx_desc)
{
	if (!rx_desc)
		return;

	atomic_dec(&rx_desc->rx_ctx->posted_rx_cnt);
	kcxi_cq_buffer_id_unmap(rx_desc->rx_ctx->recv_cq, rx_desc->buffer_id);
	kmem_cache_free(rx_desc_cache, rx_desc);
}

/**
 * kcxi_rx_desc_alloc() - Allocate a RX descriptor.
 * @Rx_ctx: RX context associated with the RX descriptor.
 *
 * Allocation will increment counters associated with this RX descriptor. These
 * counters are the RX context posted counter and the RX context CQ active
 * operation counter.
 *
 * In addition, a buffer ID will be allocated from the RX context CQ.
 *
 * The RX descriptor fields set during allocation are the rx_ctx and buffer ID.
 * Users should set the remaining fields accordingly.
 *
 * Return: On success, valid pointer. Else, negative errno pointer.
 */
struct kcxi_rx_desc *kcxi_rx_desc_alloc(struct kcxi_rx_ctx *rx_ctx)
{
	struct kcxi_rx_desc *rx_desc;
	int rc;

	if (!rx_ctx) {
		rc = -EINVAL;
		goto err;
	}

	rx_desc = kmem_cache_zalloc(rx_desc_cache, GFP_NOWAIT);
	if (!rx_desc) {
		rc = -ENOMEM;
		goto err;
	}

	rc = kcxi_cq_buffer_id_map(rx_ctx->recv_cq, &rx_desc->req);
	if (rc < 0)
		goto err_free_rx_desc;

	rx_desc->buffer_id = rc;
	rx_desc->rx_ctx = rx_ctx;

	atomic_inc(&rx_ctx->posted_rx_cnt);

	return rx_desc;

err_free_rx_desc:
	kmem_cache_free(rx_desc_cache, rx_desc);
err:
	return ERR_PTR(rc);
}
