/*
 * Kfabric fabric tests.
 * Copyright 2018,2023 Hewlett Packard Enterprise Development LP
 *
 * SPDX-License-Identifier: GPL-2.0
 */
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <kfabric.h>
#include <kfi_log.h>
#include <kfi_eq.h>

#include "../../../prov/cxi/kcxi_prov.h"

#ifdef MODULE_NAME
#undef MODULE_NAME
#endif
#define MODULE_NAME "test_domain"

MODULE_AUTHOR("Ian Ziemba");
MODULE_DESCRIPTION("kfabric CXI domain tests");
MODULE_LICENSE("GPL v2");

static struct kfi_info *info;
static struct kfi_info *hints;
static struct kfid_fabric *fabric;
static struct kfid_eq *eq;

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

	if (!info) {
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

	rc = kfi_eq_open(fabric, NULL, &eq, NULL, NULL);
	if (rc) {
		LOG_ERR("Failed to create EQ object");
		goto close_fabric;
	}

	return 0;

close_fabric:
	kfi_close(&fabric->fid);
out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;

}

static int test_open_close_domain(int id)
{
	struct kfid_domain *domain;
	int rc;

	rc = kfi_domain(fabric, info, &domain, NULL);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unabled to open domain", id,
			__func__);
		return rc;
	}

	rc = kfi_close(&domain->fid);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unabled to open domain", id,
			__func__);
		return rc;
	}

	LOG_INFO("TEST %d %s PASSED", id, __func__);
	return 0;
}

static int test_premature_fabric_close(int id)
{
	struct kfid_domain *domain;
	int rc;
	int exit_rc = 0;

	rc = kfi_domain(fabric, info, &domain, NULL);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unabled to open domain", id,
			__func__);
		return rc;
	}

	rc = kfi_close(&fabric->fid);
	if (rc != -EBUSY) {
		LOG_ERR("TEST %d %s FAILED: Fabric close should return EBUSY",
			id, __func__);
		exit_rc = -EINVAL;
	}

	rc = kfi_close(&domain->fid);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unabled to open domain", id,
			__func__);
		return rc;
	}

	if (!exit_rc)
		LOG_INFO("TEST %d %s PASSED", id, __func__);

	return exit_rc;
}

static int test_eq_domain_bind(int id)
{
	struct kfid_domain *domain;
	int rc;
	int exit_rc = 0;

	rc = kfi_domain(fabric, info, &domain, NULL);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unabled to open domain", id,
			__func__);
		return rc;
	}

	rc = kfi_domain_bind(domain, &eq->fid, KFI_REG_MR);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unabled to bind EQ to domain", id,
			__func__);
		exit_rc = rc;
		goto out;
	}

	rc = kfi_domain_bind(domain, &eq->fid, KFI_REG_MR);
	if (!rc) {
		LOG_ERR("TEST %d %s FAILED: Cannot bind multiple EQ to domain",
			id, __func__);
		exit_rc = rc;
		goto out;
	}

	rc = kfi_close(&eq->fid);
	if (rc != -EBUSY) {
		LOG_ERR("TEST %d %s FAILED: EQ close should return EBUSY", id,
			__func__);
		exit_rc = -EINVAL;
	}

out:
	rc = kfi_close(&domain->fid);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unabled to open domain", id,
			__func__);
		return rc;
	}

	if (!exit_rc)
		LOG_INFO("TEST %d %s PASSED", id, __func__);

	return exit_rc;
}

static int test_domain_ops(int id)
{
	struct kfid_domain *domain;
	struct kfi_cxi_domain_ops *dom_ops = NULL;
	struct device *dev = NULL;
	int rc;
	int exit_rc = 0;

	rc = kfi_domain(fabric, info, &domain, NULL);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unable to open domain", id,
			__func__);
		return rc;
	}

	/* test short string */
	rc = kfi_open_ops(&domain->fid, "cxi_dom_ops_v", 0, (void**)&dom_ops, NULL);
	if (!rc) {
		LOG_ERR("TEST %d %s FAILED: Open domain ops did not fail as expected",
			id, __func__);
		exit_rc = -EINVAL;
		goto out;
	}

	/* test unsupported string */
	rc = kfi_open_ops(&domain->fid, "cxi_dom_ops_v2", 0, (void**)&dom_ops, NULL);
	if (!rc) {
		LOG_ERR("TEST %d %s FAILED: Open domain ops did not fail as expected",
			id, __func__);
		exit_rc = -EINVAL;
		goto out;
	}

	/* test long string */
	rc = kfi_open_ops(&domain->fid, "cxi_dom_ops_v11", 0, (void**)&dom_ops, NULL);
	if (!rc) {
		LOG_ERR("TEST %d %s FAILED: Open domain ops did not fail as expected",
			id, __func__);
		exit_rc = -EINVAL;
		goto out;
	}

	/* test supported string */
	rc = kfi_open_ops(&domain->fid, KFI_CXI_DOM_OPS_1, 0, (void**)&dom_ops, NULL);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unable to open domain ops",
			id, __func__);
		exit_rc = rc;
		goto out;
	}

	rc = dom_ops->get_device(&domain->fid, &dev);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: get_device failed",
			id, __func__);
		exit_rc = rc;
		goto out;
	}

	if (dev == NULL) {
		LOG_ERR("TEST %d %s FAILED: dev invalid",
			id, __func__);
		exit_rc = -EINVAL;
		goto out;
	}

out:
	rc = kfi_close(&domain->fid);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unable to close domain", id,
			__func__);
		return rc;
	}

	if (!exit_rc)
		LOG_INFO("TEST %d %s PASSED", id, __func__);

	return exit_rc;
}

static void test_fini(void)
{
	kfi_close(&eq->fid);
	kfi_close(&fabric->fid);
	kfi_freeinfo(hints);
	kfi_freeinfo(info);
}

static int __init test_module_init(void)
{
	int rc = 0;
	int exit_rc = 0;
	int test_id = 1;

	rc = test_init();
	if (rc)
		return rc;

	rc = test_open_close_domain(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_premature_fabric_close(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_eq_domain_bind(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_domain_ops(test_id);
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
