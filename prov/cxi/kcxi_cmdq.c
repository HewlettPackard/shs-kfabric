//SPDX-License-Identifier: GPL-2.0
/*
 * Cray kfabric CXI provider command queue implementation.
 * Copyright 2019-2021 Hewlett Packard Enterprise Development LP. All rights reserved.
 */
#include <linux/slab.h>

#include "kcxi_prov.h"

/**
 * kcxi_cmdq_free() - Free a kCXI command queue.
 * @kcxi_cmdq: The command queue to be freed
 */
void kcxi_cmdq_free(struct kcxi_cmdq *kcxi_cmdq)
{
	if (IS_ERR_OR_NULL(kcxi_cmdq))
		return;

	if (kcxi_cmdq->cp)
		kcxi_cp_free(kcxi_cmdq->cp);

	atomic_dec(&kcxi_cmdq->kcxi_if->ref_cnt);

	cxi_cq_free(kcxi_cmdq->cmdq);

	kfree(kcxi_cmdq);
}

static struct kcxi_cmdq *kcxi_cmdq_alloc(struct kcxi_if *kcxi_if,
					 unsigned int count,
					 unsigned int auth_key,
					 enum cxi_traffic_class tc,
					 bool is_transmit,
					 int numa_node)
{
	int rc;
	struct kcxi_cmdq *kcxi_cmdq;
	struct cxi_cq_alloc_opts opts = {
		.count = count,
		.flags = is_transmit ? CXI_CQ_IS_TX : 0,
	};

	if (!kcxi_if) {
		rc = -EINVAL;
		goto err;
	}

	kcxi_cmdq = kzalloc_node(sizeof(*kcxi_cmdq), GFP_KERNEL, numa_node);
	if (!kcxi_cmdq) {
		rc = -ENOMEM;
		goto err;
	}

	if (is_transmit) {
		kcxi_cmdq->cp = kcxi_cp_alloc(kcxi_if, auth_key, tc);
		if (IS_ERR(kcxi_cmdq->cp)) {
			rc = PTR_ERR(kcxi_cmdq->cp);
			goto err_free_cmdq;
		}

		opts.lcid = kcxi_cmdq->cp->cp->lcid;
		opts.count *= KCXI_TX_ALLOC_INCREASE_FACTOR;
	}

	kcxi_cmdq->cmdq = cxi_cq_alloc(kcxi_if->lni, NULL, &opts, numa_node);
	if (IS_ERR(kcxi_cmdq->cmdq)) {
		rc = PTR_ERR(kcxi_cmdq->cmdq);
		goto err_free_cp;
	}

	spin_lock_init(&kcxi_cmdq->lock);

	kcxi_cmdq->kcxi_if = kcxi_if;

	atomic_inc(&kcxi_if->ref_cnt);

	return kcxi_cmdq;

err_free_cp:
	if (is_transmit)
		kcxi_cp_free(kcxi_cmdq->cp);
err_free_cmdq:
	kfree(kcxi_cmdq);
err:
	return ERR_PTR(rc);
}

/**
 * kcxi_cmdq_transmit_alloc() - Allocate a kCXI transmit command queue
 * @kcxi_if: kCXI interface command queue will be allocated against
 * @count: The count (size)
 * @numa_node: NUMA node CQ memory should be allocated on
 */
struct kcxi_cmdq *kcxi_cmdq_transmit_alloc(struct kcxi_if *kcxi_if,
					   unsigned int count,
					   unsigned int auth_key,
					   enum cxi_traffic_class tc,
					   int numa_node)

{
	return kcxi_cmdq_alloc(kcxi_if, count, auth_key, tc, true,
			       numa_node);
}

/**
 * kcxi_cmdq_target_alloc() - Allocate a kCXI target command queue
 * @kcxi_if: CXI interface command queue will be allocated against
 * @count: The count (size)
 * @numa_node: NUMA node CQ memory should be allocated on
 */
struct kcxi_cmdq *kcxi_cmdq_target_alloc(struct kcxi_if *kcxi_if,
					 unsigned int count,
					 int numa_node)
{
	return kcxi_cmdq_alloc(kcxi_if, count, 0, 0, false, numa_node);
}

/**
 * kcxi_cmdq_emit_target() - Emit a target command
 * @target: Target command queue
 * @cmd: Target command
 *
 * This function is a thread safe implementation of cxi_cq_emit_target().
 *
 * Return: 0 on success. Else, negative errno.
 */
int kcxi_cmdq_emit_target(struct kcxi_cmdq *target, const void *cmd)
{
	int rc;

	spin_lock(&target->lock);
	rc = cxi_cq_emit_target(target->cmdq, cmd);
	spin_unlock(&target->lock);

	return rc;
}

/**
 * kcxi_cmdq_emit_dma() - Emit a transmit DMA command
 * @transmit: Transmit command queue
 * @cmd: DMA command
 *
 * This function is a thread safe implementation of cxi_cq_emit_dma().
 *
 * Return: 0 on success. Else, negative errno.
 */
int kcxi_cmdq_emit_dma(struct kcxi_cmdq *transmit, struct c_full_dma_cmd *cmd)
{
	int rc;

	spin_lock(&transmit->lock);
	rc = cxi_cq_emit_dma(transmit->cmdq, cmd);
	spin_unlock(&transmit->lock);

	return rc;
}

/**
 * kcxi_cmdq_ring() - Ring the CQ doorbell.
 */
void kcxi_cmdq_ring(struct kcxi_cmdq *cq)
{
	spin_lock(&cq->lock);
	cxi_cq_ring(cq->cmdq);
	spin_unlock(&cq->lock);
}
