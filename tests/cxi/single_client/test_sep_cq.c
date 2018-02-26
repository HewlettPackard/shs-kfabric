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
#define MODULE_NAME "test_sep_cq"

MODULE_AUTHOR("Ian Ziemba");
MODULE_DESCRIPTION("kfabric KCXI SEP CQ tests");
MODULE_LICENSE("GPL v2");

static struct kfi_info *info;
static struct kfi_info *hints;
static struct kfid_fabric *fabric;
static struct kfid_domain *domain;
static struct kfid_cq *cq;

static int verify_info_attrs(struct kfi_info *info)
{
	if (info->tx_attr->caps & ~info->caps)
		return -EINVAL;
	if (info->rx_attr->caps & ~info->caps)
		return -EINVAL;
	if (info->domain_attr->caps & ~info->caps)
		return -EINVAL;
	return 0;
}

static int kfi_getinfo_success(uint32_t version, const char *node,
			       const char *service, uint64_t flags,
			       struct kfi_info *hints, struct kfi_info **info)
{
	int rc;

	rc = kfi_getinfo(version, node, service, flags, hints, info);
	if (rc) {
		LOG_ERR("kfi_getinfo() did not return 0");
		return -EINVAL;
	}

	if (!*info) {
		LOG_ERR("kfi_getinfo() returned NULL");
		return -EINVAL;
	}

	rc = verify_info_attrs(*info);
	if (rc) {
		LOG_ERR("kfi_getinfo() returned bad info");
		return -EINVAL;
	}

	return 0;
}

static int test_init(void)
{
	int rc = 0;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("Failed to allocate info structure");
		rc = -ENOMEM;
		goto out;
	}
	hints->caps = (KFI_MSG | KFI_RMA | KFI_SEND | KFI_RECV | KFI_READ |
		       KFI_WRITE | KFI_REMOTE_READ | KFI_REMOTE_WRITE |
		       KFI_MULTI_RECV | KFI_RMA_EVENT | KFI_REMOTE_COMM);

	rc = kfi_getinfo_success(0, NULL, NULL, KFI_SOURCE,  hints, &info);
	if (rc) {
		LOG_ERR("Failed to check fabric info");
		goto out;
	}

	rc = kfi_fabric(info->fabric_attr, &fabric, NULL);
	if (rc) {
		LOG_ERR("Failed to create fabric object");
		goto out;
	}

	rc = kfi_domain(fabric, info, &domain, NULL);
	if (rc) {
		LOG_ERR("Failed to create domain object");
		goto close_fabric;
	}

	rc = kfi_cq_open(domain, NULL, &cq, NULL, NULL);
	if (rc) {
		LOG_ERR("Failed to create completion queue");
		goto close_domain;
	}

	return 0;

close_domain:
	kfi_close(&domain->fid);
close_fabric:
	kfi_close(&fabric->fid);
out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;

}

static void test_fini(void)
{
	kfi_close(&cq->fid);
	kfi_close(&domain->fid);
	kfi_close(&fabric->fid);
	kfi_freeinfo(hints);
	kfi_freeinfo(info);
}

static int test_create_sep(int id)
{
	int rc;
	struct kfid_ep *sep;

	rc = kfi_scalable_ep(domain, info, &sep, NULL);
	if (rc) {
		LOG_ERR("Test %d %s FAILED: Unable to open SEP", id, __func__);
		return rc;
	}

	rc = kfi_close(&sep->fid);
	if (rc) {
		LOG_ERR("Test %d %s FAILED: Unable to close SEP", id, __func__);
		return rc;
	}

	LOG_INFO("Test %d %s PASSED", id, __func__);

	return 0;
}

static int test_sep_bind_cq(int id)
{
	int rc;
	int exit_rc = 0;
	struct kfid_ep *sep;

	rc = kfi_scalable_ep(domain, info, &sep, NULL);
	if (rc) {
		LOG_ERR("Test %d %s FAILED: Unable to open SEP", id, __func__);
		return rc;
	}

	rc = kfi_scalable_ep_bind(sep, &cq->fid, 0);
	if (!rc) {
		LOG_ERR("Test %d %s FAILED: CQ cannot be count to SEP", id,
			__func__);
		exit_rc = -EINVAL;
		goto out;
	}

out:
	rc = kfi_close(&sep->fid);
	if (rc) {
		LOG_ERR("Test %d %s FAILED: Unable to close SEP", id, __func__);
		return rc;
	}

	if (!exit_rc)
		LOG_INFO("Test %d %s PASSED", id, __func__);

	return exit_rc;
}

static int __init test_module_init(void)
{
	int rc = 0;
	int exit_rc = 0;
	int test_id = 1;

	rc = test_init();
	if (rc)
		return rc;

	rc = test_create_sep(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_sep_bind_cq(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	test_fini();

	if (!exit_rc)
		LOG_INFO("ALL TESTS PASSED");

	return exit_rc;
}

static void __exit test_module_exit(void)
{
}


module_init(test_module_init);
module_exit(test_module_exit);
