//SPDX-License-Identifier: GPL-2.0
/*
 * Cray kfabric CXI provider command queue implementation.
 * Copyright 2019-2021 Hewlett Packard Enterprise Development LP. All rights reserved.
 */
#include <linux/slab.h>
#include <linux/topology.h>

#include "kcxi_prov.h"

/**
 * kcxi_get_node_cpu() - Get NUMA node and CPU for a queue
 * @dev: Device structure
 * @queue_id: Queue ID
 * @queue_node: Output pointer for NUMA node
 * @queue_cpu: Output pointer for CPU
 *
 * This function spreads queues across non-empty NUMA nodes (nodes that
 * contain CPUs) to avoid overloading a single node. It handles systems
 * with empty NUMA nodes by counting only nodes with CPUs.
 */
void kcxi_get_node_cpu(struct device *dev, unsigned int queue_id,
		       unsigned int *queue_node, unsigned int *queue_cpu)
{
	int node;
	int cpu;
	int cpu_offset;
	const struct cpumask *cpus;
	int cpu_count;
	int num_cpu_nodes = 0;
	int dev_node = NUMA_NO_NODE;
	int i;

	/* Get device's NUMA node if device is provided */
	if (dev)
		dev_node = dev_to_node(dev);

	/* If device node is invalid, use node 0 as default */
	if (dev_node == NUMA_NO_NODE || dev_node < 0)
		dev_node = 0;

	/* Figure out how many numa nodes are online and contain
	 * CPUs. Apparently linux will reorder the nodes so that the
	 * empty ones are at the end of the list. If it's not the
	 * case, then further changes will be needed.
	 */
	for_each_online_node(node) {
		cpus = cpumask_of_node(node);
		if (!cpumask_empty(cpus))
			num_cpu_nodes++;
	}

	/* If no nodes with CPUs found, default to node 0 */
	if (num_cpu_nodes == 0) {
		*queue_node = 0;
		*queue_cpu = 0;
		return;
	}

	/* Round robin queues across all the nodes in the system instead of
	 * overloading 1 node with multiple queues. Favor the local node to
	 * start with.
	 */
	node = (dev_node + queue_id) % num_cpu_nodes;
	if (!node_online(node)) {
		/* For sanity, but that shouldn't be possible. */
		if (dev)
			dev_warn(dev, "Node %u not online. Defaulting to %u\n",
				 node, dev_node);
		node = dev_node;
	}

	/* If the queue ID exceeds the number of nodes, multiple queues will be
	 * mapped to the same node. For this case, round robin queues within the
	 * node.
	 */
	cpus = cpumask_of_node(node);
	if (cpumask_empty(cpus)) {
		/* For sanity, but that shouldn't be possible. */
		if (dev)
			dev_warn(dev, "Node %u is empty. Defaulting to all cpus.\n",
				 node);
		cpus = cpu_all_mask;
	}

	cpu_count = 0;
	for_each_cpu(cpu, cpus) {
		if (cpu_is_offline(cpu))
			continue;
		/* We only care about CPUs which belong to the NUMA node. */
		if (cpumask_test_cpu(cpu, cpus))
			cpu_count++;
	}

	if (cpu_count == 0) {
		/* Fallback if no online CPUs in node */
		*queue_node = 0;
		*queue_cpu = 0;
		return;
	}

	cpu_offset = (queue_id / num_cpu_nodes) % cpu_count;
	i = 0;
	for_each_cpu(cpu, cpus) {
		if (cpu_is_offline(cpu))
			continue;
		if (cpumask_test_cpu(cpu, cpus)) {
			if (i == cpu_offset)
				break;
			i++;
		}
	}

	*queue_node = cpu_to_node(cpu);
	*queue_cpu = cpu;
}
EXPORT_SYMBOL(kcxi_get_node_cpu);

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
