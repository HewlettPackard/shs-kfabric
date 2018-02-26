// SPDX-License-Identifier: GPL-2.0
/*
 * Kfabric fabric tests.
 * Copyright 2018 Cray Inc. All Rights Reserved.
 */
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <kfabric.h>
#include <kfi_log.h>
#include <kfi_eq.h>
#include <kfi_domain.h>
#include <linux/slab.h>

#include "../../../prov/cxi/kcxi_prov.h"

#ifdef MODULE_NAME
#undef MODULE_NAME
#endif
#define MODULE_NAME "test_sep_multi_sep"

MODULE_AUTHOR("Ian Ziemba");
MODULE_DESCRIPTION("kfabric CXI SEP Multi SEP tests");
MODULE_LICENSE("GPL v2");

struct kfi_resource_group {
	struct kfi_info *info;
	struct kfid_fabric *fabric;
	struct kfid_domain *domain;
	struct kfid_av *av;
	struct kfid_ep *sep;
};

static void free_resources(struct kfi_resource_group *group)
{
	if (!group)
		return;

	if (group->sep)
		kfi_close(&group->sep->fid);

	if (group->av)
		kfi_close(&group->av->fid);

	if (group->domain)
		kfi_close(&group->domain->fid);

	if (group->fabric)
		kfi_close(&group->fabric->fid);

	if (group->info)
		kfi_freeinfo(group->info);

	kfree(group);
}

static struct kfi_resource_group *alloc_resources(struct kfi_info *hints,
						  const char *node,
						  const char *service)
{
	struct kfi_av_attr av_attr = {};
	struct kfi_resource_group *group;
	int rc;

	group = kzalloc(sizeof(*group), GFP_KERNEL);
	if (!group)
		return NULL;

	rc = kfi_getinfo(0, node, service, KFI_SOURCE, hints, &group->info);
	if (rc) {
		LOG_ERR("Failed to allocate info");
		goto err;
	}

	rc = kfi_fabric(group->info->fabric_attr, &group->fabric, NULL);
	if (rc) {
		LOG_ERR("Failed to create fabric object");
		goto err;
	}

	rc = kfi_domain(group->fabric, group->info, &group->domain, NULL);
	if (rc) {
		LOG_ERR("Failed to create domain object");
		goto err;
	}

	av_attr.type = KFI_AV_UNSPEC;
	rc = kfi_av_open(group->domain, &av_attr, &group->av, NULL);
	if (rc) {
		LOG_ERR("Failed to create address vector");
		goto err;
	}

	rc = kfi_scalable_ep(group->domain, group->info, &group->sep, NULL);
	if (rc) {
		LOG_ERR("Unable to open SEP");
		goto err;
	}

	return group;

err:
	free_resources(group);
	return NULL;
}

static int run_test(void)
{
	struct kfi_info *hints = NULL;
	struct kfi_resource_group *group_a = NULL;
	struct kfi_resource_group *group_b = NULL;
	int rc;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("Failed to allocate info structure");
		return -ENOMEM;
	}
	hints->caps = (KFI_MSG | KFI_RMA | KFI_SEND | KFI_RECV | KFI_READ |
		       KFI_WRITE | KFI_REMOTE_READ | KFI_REMOTE_WRITE |
		       KFI_MULTI_RECV | KFI_RMA_EVENT | KFI_REMOTE_COMM);
	hints->ep_attr->tx_ctx_cnt = 12;
	hints->ep_attr->rx_ctx_cnt = 12;

	group_a = alloc_resources(hints, "0x0", "5");
	if (!group_a) {
		rc = -ENOMEM;
		goto err;
	}

	rc = kfi_scalable_ep_bind(group_a->sep, &group_a->av->fid, 0);
	if (rc) {
		LOG_ERR("Unable to bind AV to SEP");
		goto err;
	}

	rc  = kfi_enable(group_a->sep);
	if (rc) {
		LOG_ERR("Unable to enable SEP");
		goto err;
	}

	LOG_INFO("Resource group A allocated and SEP enabled");

	group_b = alloc_resources(hints, "0x0", "34");
	if (!group_b) {
		rc = -ENOMEM;
		goto err;
	}

	rc = kfi_scalable_ep_bind(group_b->sep, &group_b->av->fid, 0);
	if (rc) {
		LOG_ERR("Unable to bind AV to SEP");
		goto err;
	}

	rc  = kfi_enable(group_b->sep);
	if (rc) {
		LOG_ERR("Unable to enable SEP");
		goto err;
	}

	LOG_INFO("Resource group B allocated and SEP enabled");

err:
	free_resources(group_b);
	free_resources(group_a);
	kfi_freeinfo(hints);

	return rc;
}

static int __init test_module_init(void)
{
	int rc;

	rc = run_test();

	return rc;
}

static void __exit test_module_exit(void)
{
}


module_init(test_module_init);
module_exit(test_module_exit);
