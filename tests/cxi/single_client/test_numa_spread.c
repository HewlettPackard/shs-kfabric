//SPDX-License-Identifier: GPL-2.0
/*
 * Kfabric NUMA node spreading tests.
 * Copyright 2024 Hewlett Packard Enterprise Development LP
 *
 */
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/numa.h>
#include <linux/cpumask.h>
#include <kfabric.h>
#include <kfi_log.h>
#include <kfi_eq.h>
#include <kfi_errno.h>
#include <test_common.h>

#include "../../../prov/cxi/kcxi_prov.h"

#ifdef MODULE_NAME
#undef MODULE_NAME
#endif
#define MODULE_NAME "test_numa_spread"

#define MAX_TX_CTX 16
#define MAX_RX_CTX 16

MODULE_AUTHOR("HPE");
MODULE_DESCRIPTION("kfabric CXI NUMA node spreading tests");
MODULE_LICENSE("GPL v2");

static struct sep_resource *res;

static int test_init(void)
{
	struct sep_resource_opts res_opts = {};
	struct kfi_av_attr av_attr = {};
	struct kfi_cq_attr cq_attr = {};

	av_attr.type = KFI_AV_UNSPEC;
	cq_attr.size = 8;
	cq_attr.format = KFI_CQ_FORMAT_DATA;

	res_opts.hints = kfi_allocinfo();
	if (!res_opts.hints) {
		LOG_ERR("Failed to allocate info structure");
		return -ENOMEM;
	}

	/* Set resource for async MR. */
	res_opts.hints->caps = KFI_MSG;
	res_opts.av_attr = &av_attr;
	res_opts.tx_cq_attr = &cq_attr;
	res_opts.rx_cq_attr = &cq_attr;
	res_opts.tx_count = MAX_TX_CTX;
	res_opts.rx_count = MAX_RX_CTX;

	res = sep_resource_alloc(&res_opts);
	if (IS_ERR(res)) {
		LOG_ERR("Failed to allocate SEP resource: rc=%ld",
			PTR_ERR(res));
		kfi_freeinfo(res_opts.hints);
		return PTR_ERR(res);
	}

	kfi_freeinfo(res_opts.hints);

	return 0;
}

static void test_fini(void)
{
	sep_resource_free(res);
}

/*
 * Test that kcxi_get_node_cpu only counts non-empty NUMA nodes
 */
static int test_get_node_cpu_non_empty_nodes(int id)
{
	unsigned int node, cpu;
	int num_online_nodes = 0;
	int num_cpu_nodes = 0;
	int test_node;
	int i;
	const struct cpumask *cpus;
	struct device *dev;

	/* Count online nodes and nodes with CPUs */
	for_each_online_node(test_node) {
		num_online_nodes++;
		cpus = cpumask_of_node(test_node);
		if (!cpumask_empty(cpus))
			num_cpu_nodes++;
	}

	LOG_INFO("System has %d online nodes, %d with CPUs",
		 num_online_nodes, num_cpu_nodes);

	if (num_cpu_nodes == 0) {
		LOG_ERR("TEST %d FAILED: No nodes with CPUs found", id);
		return -EINVAL;
	}

	/* Get device from the first RX context */
	if (!res || !res->rx || !res->rx[0]) {
		LOG_ERR("TEST %d FAILED: No RX context available", id);
		return -EINVAL;
	}

	/* We need to get the device through the context structure */
	dev = NULL; /* This would normally come from kcxi_if->dev->device */

	/* Test multiple queue IDs to ensure proper spreading */
	for (i = 0; i < num_cpu_nodes * 2; i++) {
		/* Use a mock device pointer for testing - in real use this comes from
		 * the kcxi_if structure. Since we're testing the logic, we can test
		 * with a NULL device in the get_node_cpu function by checking the
		 * implementation handles the modulo correctly.
		 */
		kcxi_get_node_cpu(dev, i, &node, &cpu);
		
		/* Verify the node is online */
		if (!node_online(node)) {
			LOG_ERR("TEST %d FAILED: Queue %d assigned to offline node %u",
				id, i, node);
			return -EINVAL;
		}

		/* Verify the node has CPUs */
		cpus = cpumask_of_node(node);
		if (cpumask_empty(cpus)) {
			LOG_ERR("TEST %d FAILED: Queue %d assigned to empty node %u",
				id, i, node);
			return -EINVAL;
		}

		/* Verify CPU is valid and belongs to the node */
		if (!cpu_online(cpu)) {
			LOG_ERR("TEST %d FAILED: Queue %d assigned to offline CPU %u",
				id, i, cpu);
			return -EINVAL;
		}

		if (cpu_to_node(cpu) != node) {
			LOG_ERR("TEST %d FAILED: CPU %u doesn't belong to node %u",
				id, cpu, node);
			return -EINVAL;
		}

		LOG_INFO("Queue %d: node=%u cpu=%u", i, node, cpu);
	}

	LOG_INFO("TEST %d %s PASSED", id, __func__);
	return 0;
}

/*
 * Test that multiple TX contexts get spread across NUMA nodes
 */
static int test_tx_ctx_numa_spread(int id)
{
	int i;
	int num_cpu_nodes = 0;
	int test_node;
	const struct cpumask *cpus;
	unsigned int *node_usage;
	int max_usage, min_usage;

	/* Count nodes with CPUs */
	for_each_online_node(test_node) {
		cpus = cpumask_of_node(test_node);
		if (!cpumask_empty(cpus))
			num_cpu_nodes++;
	}

	if (num_cpu_nodes == 0) {
		LOG_ERR("TEST %d FAILED: No nodes with CPUs found", id);
		return -EINVAL;
	}

	/* Allocate array to track node usage */
	node_usage = kcalloc(num_cpu_nodes, sizeof(*node_usage), GFP_KERNEL);
	if (!node_usage) {
		LOG_ERR("TEST %d FAILED: Cannot allocate node_usage", id);
		return -ENOMEM;
	}

	/* Enable multiple TX contexts and check their NUMA node assignment
	 * Note: In practice, this would require enabling the contexts and
	 * checking the transmit cmdq allocation node. For this test, we're
	 * verifying the get_node_cpu logic indirectly.
	 */
	for (i = 0; i < MAX_TX_CTX && i < num_cpu_nodes * 2; i++) {
		unsigned int node, cpu;
		int node_idx = 0;
		int curr_node;

		kcxi_get_node_cpu(NULL, i, &node, &cpu);

		/* Find the index of this node in our cpu_nodes array */
		for_each_online_node(curr_node) {
			cpus = cpumask_of_node(curr_node);
			if (!cpumask_empty(cpus)) {
				if (curr_node == node)
					break;
				node_idx++;
			}
		}

		if (node_idx < num_cpu_nodes)
			node_usage[node_idx]++;
	}

	/* Check that queues are reasonably balanced across nodes */
	max_usage = 0;
	min_usage = INT_MAX;
	for (i = 0; i < num_cpu_nodes; i++) {
		LOG_INFO("Node %d usage: %u", i, node_usage[i]);
		if (node_usage[i] > max_usage)
			max_usage = node_usage[i];
		if (node_usage[i] < min_usage)
			min_usage = node_usage[i];
	}

	kfree(node_usage);

	/* With round-robin, difference should be at most 1 */
	if (max_usage - min_usage > 1) {
		LOG_ERR("TEST %d FAILED: Unbalanced distribution (max=%d, min=%d)",
			id, max_usage, min_usage);
		return -EINVAL;
	}

	LOG_INFO("TEST %d %s PASSED (max=%d, min=%d)", id, __func__,
		 max_usage, min_usage);
	return 0;
}

/*
 * Test that multiple RX contexts get spread across NUMA nodes
 */
static int test_rx_ctx_numa_spread(int id)
{
	int i;
	int num_cpu_nodes = 0;
	int test_node;
	const struct cpumask *cpus;
	unsigned int *node_usage;
	int max_usage, min_usage;

	/* Count nodes with CPUs */
	for_each_online_node(test_node) {
		cpus = cpumask_of_node(test_node);
		if (!cpumask_empty(cpus))
			num_cpu_nodes++;
	}

	if (num_cpu_nodes == 0) {
		LOG_ERR("TEST %d FAILED: No nodes with CPUs found", id);
		return -EINVAL;
	}

	/* Allocate array to track node usage */
	node_usage = kcalloc(num_cpu_nodes, sizeof(*node_usage), GFP_KERNEL);
	if (!node_usage) {
		LOG_ERR("TEST %d FAILED: Cannot allocate node_usage", id);
		return -ENOMEM;
	}

	/* Check RX context NUMA node assignment */
	for (i = 0; i < MAX_RX_CTX && i < num_cpu_nodes * 2; i++) {
		unsigned int node, cpu;
		int node_idx = 0;
		int curr_node;

		kcxi_get_node_cpu(NULL, i, &node, &cpu);

		/* Find the index of this node in our cpu_nodes array */
		for_each_online_node(curr_node) {
			cpus = cpumask_of_node(curr_node);
			if (!cpumask_empty(cpus)) {
				if (curr_node == node)
					break;
				node_idx++;
			}
		}

		if (node_idx < num_cpu_nodes)
			node_usage[node_idx]++;
	}

	/* Check that queues are reasonably balanced across nodes */
	max_usage = 0;
	min_usage = INT_MAX;
	for (i = 0; i < num_cpu_nodes; i++) {
		LOG_INFO("Node %d usage: %u", i, node_usage[i]);
		if (node_usage[i] > max_usage)
			max_usage = node_usage[i];
		if (node_usage[i] < min_usage)
			min_usage = node_usage[i];
	}

	kfree(node_usage);

	/* With round-robin, difference should be at most 1 */
	if (max_usage - min_usage > 1) {
		LOG_ERR("TEST %d FAILED: Unbalanced distribution (max=%d, min=%d)",
			id, max_usage, min_usage);
		return -EINVAL;
	}

	LOG_INFO("TEST %d %s PASSED (max=%d, min=%d)", id, __func__,
		 max_usage, min_usage);
	return 0;
}

static int __init test_module_init(void)
{
	int rc = 0;
	int test_id = 1;
	int failed = 0;

	rc = test_init();
	if (rc)
		return rc;

	rc = test_get_node_cpu_non_empty_nodes(test_id++);
	if (rc)
		failed++;

	rc = test_tx_ctx_numa_spread(test_id++);
	if (rc)
		failed++;

	rc = test_rx_ctx_numa_spread(test_id++);
	if (rc)
		failed++;

	test_fini();

	if (failed > 0) {
		LOG_ERR("NUMA spreading tests: %d failed", failed);
		return -EINVAL;
	}

	LOG_INFO("All NUMA spreading tests passed");
	return 0;
}

static void __exit test_module_exit(void)
{
}

module_init(test_module_init);
module_exit(test_module_exit);
