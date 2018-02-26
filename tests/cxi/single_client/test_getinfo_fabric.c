//SPDX-License-Identifier: GPL-2.0
/*
 * Verify that already allocated fabric pointers are returned if matching
 * requested hints.
 *
 * Copyright 2019 Cray Inc. All Rights Reserved.
 */
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <kfabric.h>
#include <kfi_log.h>

#ifdef MODULE_NAME
#undef MODULE_NAME
#endif
#define MODULE_NAME "test_getinfo_fabric"

static struct kfid_fabric *fabric1;
static struct kfid_fabric *fabric2;

static char *node = "0x0";
static char *service = "0";
static char *fabric_prov_name = "kcxi";
static char *fabric_name = "cxi/1";

static int test_init(void)
{
	int rc;
	struct kfi_info *hints;
	struct kfi_info *info;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("Failed to allocate fabric hints");
		rc = -ENOMEM;
		goto err;
	}

	hints->fabric_attr->prov_name = kstrdup(fabric_prov_name, GFP_KERNEL);
	if (!hints->fabric_attr->prov_name) {
		LOG_ERR("Failed to allocate fabric provider name string");
		rc = -ENOMEM;
		goto err_free_hints;
	}

	hints->fabric_attr->name = kstrdup(fabric_name, GFP_KERNEL);
	if (!hints->fabric_attr->name) {
		LOG_ERR("Failed to allocate fabric name string");
		rc = -ENOMEM;
		goto err_free_hints;
	}

	rc = kfi_getinfo(0, node, service, KFI_SOURCE, hints, &info);
	if (rc) {
		LOG_ERR("Failed to get fabric info");
		goto err_free_hints;
	}

	/* Verify fabric attribute fields. */
	if (info->fabric_attr->fabric != NULL) {
		LOG_ERR("Fabric pointer should be NULL");
		rc = -EINVAL;
		goto err_free_info;
	}

	if (strcmp(info->fabric_attr->prov_name, fabric_prov_name)) {
		LOG_ERR("Fabric provider name should be %s instead of %s",
			fabric_prov_name, info->fabric_attr->prov_name);
		rc = -EINVAL;
		goto err_free_info;
	}

	if (strcmp(info->fabric_attr->name, fabric_name)) {
		LOG_ERR("Fabric name should be %s instead of %s", fabric_name,
			info->fabric_attr->name);
		rc = -EINVAL;
		goto err_free_info;
	}

	rc = kfi_fabric(info->fabric_attr, &fabric1, NULL);
	if (rc) {
		LOG_ERR("Failed to create fabric object");
		goto err_free_info;
	}

	rc = kfi_fabric(info->fabric_attr, &fabric2, NULL);
	if (rc) {
		LOG_ERR("Failed to create fabric object");
		goto err_free_fabric1;
	}


	kfi_freeinfo(info);
	kfi_freeinfo(hints);

	return 0;

err_free_fabric1:
	kfi_close(&fabric1->fid);
err_free_info:
	kfi_freeinfo(info);
err_free_hints:
	kfi_freeinfo(hints);
err:
	return rc;
}

static void test_fini(void)
{
	kfi_close(&fabric2->fid);
	kfi_close(&fabric1->fid);
}

/* The first fabric (fabric1) should be set in the output info. */
static int test_valid_output_fabric_fid(void)
{
	int rc;
	struct kfi_info *hints;
	struct kfi_info *info;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("Failed to allocate fabric hints");
		rc = -ENOMEM;
		goto err;
	}

	hints->fabric_attr->prov_name = kstrdup(fabric_prov_name, GFP_KERNEL);
	if (!hints->fabric_attr->prov_name) {
		LOG_ERR("Failed to allocate fabric provider name string");
		rc = -ENOMEM;
		goto err_free_hints;
	}

	hints->fabric_attr->name = kstrdup(fabric_name, GFP_KERNEL);
	if (!hints->fabric_attr->name) {
		LOG_ERR("Failed to allocate fabric name string");
		rc = -ENOMEM;
		goto err_free_hints;
	}

	rc = kfi_getinfo(0, node, service, KFI_SOURCE, hints, &info);
	if (rc) {
		LOG_ERR("Failed to get fabric info");
		goto err_free_hints;
	}

	if (info->fabric_attr->fabric != fabric1) {
		LOG_ERR("Bad fabric pointer in returned kfi_info");
		rc = -EINVAL;
		goto err_free_info;
	}

	kfi_freeinfo(info);
	kfi_freeinfo(hints);

	LOG_INFO("%s: PASSED", __func__);

	return 0;

err_free_info:
	kfi_freeinfo(info);
err_free_hints:
	kfi_freeinfo(hints);
err:
	return rc;
}

/* Set the hints fabric pointer to restrict results to a specific fabric. */
static int test_valid_input_fabric_fid(void)
{
	int rc;
	struct kfi_info *hints;
	struct kfi_info *info;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("Failed to allocate fabric hints");
		rc = -ENOMEM;
		goto err;
	}

	hints->fabric_attr->prov_name = kstrdup(fabric_prov_name, GFP_KERNEL);
	if (!hints->fabric_attr->prov_name) {
		LOG_ERR("Failed to allocate fabric provider name string");
		rc = -ENOMEM;
		goto err_free_hints;
	}

	hints->fabric_attr->name = kstrdup(fabric_name, GFP_KERNEL);
	if (!hints->fabric_attr->name) {
		LOG_ERR("failed to allocate fabric name string");
		rc = -ENOMEM;
		goto err_free_hints;
	}

	hints->fabric_attr->fabric = fabric2;

	rc = kfi_getinfo(0, node, service, KFI_SOURCE, hints, &info);
	if (rc) {
		LOG_ERR("Failed to get fabric info");
		goto err_free_hints;
	}

	if (info->fabric_attr->fabric != fabric2) {
		LOG_ERR("Bad fabric pointer in returned kfi_info");
		rc = -EINVAL;
		goto err_free_info;
	}

	kfi_freeinfo(info);
	kfi_freeinfo(hints);

	LOG_INFO("%s: PASSED", __func__);

	return 0;

err_free_info:
	kfi_freeinfo(info);
err_free_hints:
	kfi_freeinfo(hints);
err:
	return rc;
}

/* Verify a bad fabric input doesn't return a kfi_info. */
static int test_invalid_input_fabric_fid(void)
{
	int rc;
	struct kfi_info *hints;
	struct kfi_info *info;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("failed to allocate fabric hints");
		rc = -ENOMEM;
		goto err;
	}

	hints->fabric_attr->prov_name = kstrdup(fabric_prov_name, GFP_KERNEL);
	if (!hints->fabric_attr->prov_name) {
		LOG_ERR("Failed to allocate fabric provider name string");
		rc = -ENOMEM;
		goto err_free_hints;
	}

	hints->fabric_attr->name = kstrdup(fabric_name, GFP_KERNEL);
	if (!hints->fabric_attr->name) {
		LOG_ERR("Failed to allocate fabric name string");
		rc = -ENOMEM;
		goto err_free_hints;
	}

	hints->fabric_attr->fabric = (void *)0x1234;

	rc = kfi_getinfo(0, node, service, KFI_SOURCE, hints, &info);
	if (rc != -ENODATA) {
		LOG_ERR("Info should not have been allocated");
		goto err_free_info;
	}

	kfi_freeinfo(hints);

	LOG_INFO("%s: PASSED", __func__);

	return 0;

err_free_info:
	kfi_freeinfo(info);
err_free_hints:
	kfi_freeinfo(hints);
err:
	return rc;
}

static int test_zero_fabric_provider_version(void)
{
	int rc;
	struct kfi_info *hints;
	struct kfi_info *info;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("failed to allocate fabric hints");
		rc = -ENOMEM;
		goto err;
	}

	rc = kfi_getinfo(0, node, service, KFI_SOURCE, hints, &info);
	if (rc) {
		LOG_ERR("Info should have been allocated");
		goto err_free_hints;
	}

	if (info->fabric_attr->prov_version == 0) {
		LOG_ERR("No provider version returned");
		rc = -EINVAL;
		goto err_free_info;
	}

	kfi_freeinfo(info);
	kfi_freeinfo(hints);

	LOG_INFO("%s: PASSED", __func__);

	return 0;

err_free_info:
	kfi_freeinfo(info);
err_free_hints:
	kfi_freeinfo(hints);
err:
	return rc;
}

static int test_invalid_fabric_provider_version(void)
{
	int rc;
	struct kfi_info *hints;
	struct kfi_info *info;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("failed to allocate fabric hints");
		rc = -ENOMEM;
		goto err;
	}

	hints->fabric_attr->prov_version = KFI_VERSION(0x1000U, 0x2U);

	rc = kfi_getinfo(0, node, service, KFI_SOURCE, hints, &info);

	kfi_freeinfo(hints);

	if (rc != -ENODATA) {
		if (rc == 0)
			kfi_freeinfo(info);
		LOG_ERR("Info should not have been allocated");
		rc = -EINVAL;
		goto err;
	}

	LOG_INFO("%s: PASSED", __func__);

	return 0;

err:
	return rc;
}

static int test_valid_fabric_provider_version(void)
{
	int rc;
	struct kfi_info *hints;
	struct kfi_info *info;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("failed to allocate fabric hints");
		rc = -ENOMEM;
		goto err;
	}

	hints->fabric_attr->prov_version = KFI_VERSION(1U, 0U);

	rc = kfi_getinfo(0, node, service, KFI_SOURCE, hints, &info);
	if (rc) {
		LOG_ERR("Info should have been allocated");
		goto err_free_hints;
	}

	if (info->fabric_attr->prov_version == 0) {
		LOG_ERR("No provider version returned");
		rc = -EINVAL;
		goto err_free_info;
	}

	kfi_freeinfo(info);
	kfi_freeinfo(hints);

	LOG_INFO("%s: PASSED", __func__);

	return 0;

err_free_info:
	kfi_freeinfo(info);
err_free_hints:
	kfi_freeinfo(hints);
err:
	return rc;
}

static int __init test_module_init(void)
{
	int rc;

	rc = test_init();
	if (rc)
		goto err;

	rc = test_valid_output_fabric_fid();
	if (rc)
		goto err_cleanup;

	rc = test_valid_input_fabric_fid();
	if (rc)
		goto err_cleanup;

	rc = test_invalid_input_fabric_fid();
	if (rc)
		goto err_cleanup;

	rc = test_zero_fabric_provider_version();
	if (rc)
		goto err_cleanup;

	rc = test_invalid_fabric_provider_version();
	if (rc)
		goto err_cleanup;

	rc = test_valid_fabric_provider_version();
	if (rc)
		goto err_cleanup;

	return 0;

err_cleanup:
	test_fini();
err:
	return rc;
}

static void __exit test_module_exit(void)
{
	test_fini();
}

module_init(test_module_init);
module_exit(test_module_exit);
MODULE_LICENSE("GPL v2");
