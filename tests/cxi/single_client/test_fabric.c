/*
 * Kfabric fabric tests.
 * Copyright 2018,2022 Hewlett Packard Enterprise Development LP
 *
 * SPDX-License-Identifier: GPL-2.0
 */
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <kfabric.h>
#include <kfi_cxi_ext.h>
#include <kfi_log.h>

#ifdef MODULE_NAME
#undef MODULE_NAME
#endif
#define MODULE_NAME "test_fabric"

MODULE_AUTHOR("Ian Ziemba");
MODULE_DESCRIPTION("kfabric CXI kfi_fabric() tests");
MODULE_LICENSE("GPL v2");

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

static int test_basic_fabric_kfilnd_hints(int id)
{
	int rc = 0;
	struct kfi_info *info = NULL;
	struct kfi_info *hints = NULL;
	struct kfid_fabric *fabric = NULL;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		LOG_ERR("Failed to allocate info structure");
		rc = -ENOMEM;
		goto out;
	}
	hints->caps = (KFI_MSG | KFI_RMA | KFI_SEND | KFI_RECV | KFI_READ |
		       KFI_WRITE | KFI_REMOTE_READ | KFI_REMOTE_WRITE |
		       KFI_MULTI_RECV | KFI_RMA_EVENT | KFI_REMOTE_COMM);

	rc = kfi_getinfo_success(0, NULL, NULL, KFI_SOURCE,  hints, &info);
	if (rc) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		LOG_ERR("Failed to check fabric info");
		goto out;
	}

	rc = kfi_fabric(info->fabric_attr, &fabric, NULL);
	if (rc) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		LOG_ERR("Failed to create fabric object");
		goto out;
	}

	rc = kfi_close(&fabric->fid);
	if (rc) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		LOG_ERR("Failed to close fabric object");
		goto out;
	}

	LOG_INFO("TEST %d PASSED: %s", id, __func__);
	return 0;

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;

}

static int test_fabric_ops(int id)
{
	int rc = 0;
	struct kfi_info *info = NULL;
	struct kfi_info *hints = NULL;
	struct kfid_fabric *fabric = NULL;
	struct kfi_cxi_fabric_ops *fab_ops = NULL;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		LOG_ERR("Failed to allocate info structure");
		rc = -ENOMEM;
		goto out;
	}
	hints->caps = (KFI_MSG | KFI_RMA | KFI_SEND | KFI_RECV | KFI_READ |
		       KFI_WRITE | KFI_REMOTE_READ | KFI_REMOTE_WRITE |
		       KFI_MULTI_RECV | KFI_RMA_EVENT | KFI_REMOTE_COMM);

	rc = kfi_getinfo_success(0, NULL, NULL, KFI_SOURCE,  hints, &info);
	if (rc) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		LOG_ERR("Failed to check fabric info");
		goto out;
	}

	rc = kfi_fabric(info->fabric_attr, &fabric, NULL);
	if (rc) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		LOG_ERR("Failed to create fabric object");
		goto out;
	}

	rc = kfi_open_ops(&fabric->fid, "foo", 0, (void**)&fab_ops, NULL);
	if (!rc) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		LOG_ERR("Open fabric ops did not fail as expected");
		goto out;
	}

	rc = kfi_open_ops(&fabric->fid, KFI_CXI_FAB_OPS_1, 0, (void**)&fab_ops, NULL);
	if (rc) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		LOG_ERR("Failed to open fabric ops");
		goto out;
	}

	rc = fab_ops->enable_dynamic_rsrc_alloc(&fabric->fid, true);
	if (rc) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		LOG_ERR("Failed to enable dynamic resource allocation");
		goto out;
	}

	rc = kfi_close(&fabric->fid);
	if (rc) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		LOG_ERR("Failed to close fabric object");
		goto out;
	}

	LOG_INFO("TEST %d PASSED: %s", id, __func__);
	return 0;

out:
	if (fabric)
		kfi_close(&fabric->fid);
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;

}
static int __init test_module_init(void)
{
	int rc = 0;
	int exit_rc = 0;
	int test_id = 1;

	rc = test_basic_fabric_kfilnd_hints(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_fabric_ops(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	if (!exit_rc)
		LOG_INFO("ALL TESTS PASSED");

	return exit_rc;
}

static void __exit test_module_exit(void)
{
}


module_init(test_module_init);
module_exit(test_module_exit);
