//SPDX-License-Identifier: GPL-2.0
/*
 * Verify that already allocated domain pointers are returned if matching
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
#include <kfi_domain.h>

#ifdef MODULE_NAME
#undef MODULE_NAME
#endif
#define MODULE_NAME "test_getinfo_domain"

static struct kfid_fabric *fabric1;
static struct kfid_fabric *fabric2;
static struct kfid_domain *domain1;
static struct kfid_domain *domain2;

static char *node = "0x0";
static char *service = "0";
static char *domain_name = "cxi0";

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

	rc = kfi_getinfo(0, node, service, KFI_SOURCE, hints, &info);
	if (rc) {
		LOG_ERR("Failed to get fabric info");
		goto err_free_hints;
	}

	/* Verify domain attribute fields. */
	if (info->domain_attr->domain != NULL) {
		LOG_ERR("Domain pointer should be NULL");
		rc = -EINVAL;
		goto err_free_info;
	}

	if (strcmp(info->domain_attr->name, domain_name)) {
		LOG_ERR("Domain name should be %s instead of %s", domain_name,
			info->domain_attr->name);
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

	rc = kfi_domain(fabric1, info, &domain1, NULL);
	if (rc) {
		LOG_ERR("Failed to create domain object");
		goto err_free_fabric2;
	}

	rc = kfi_domain(fabric2, info, &domain2, NULL);
	if (rc) {
		LOG_ERR("Failed to create domain object");
		goto err_free_domain1;
	}

	kfi_freeinfo(info);
	kfi_freeinfo(hints);

	return 0;

err_free_domain1:
	kfi_close(&domain1->fid);
err_free_fabric2:
	kfi_close(&fabric2->fid);
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
	kfi_close(&domain2->fid);
	kfi_close(&domain1->fid);
	kfi_close(&fabric2->fid);
	kfi_close(&fabric1->fid);
}

/* The first fabric and domain (fabric1 and domain1) should be set in the output
 * info.
 */
static int test_valid_output_domain_fid(void)
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

	hints->domain_attr->name = kstrdup(domain_name, GFP_KERNEL);
	if (!hints->domain_attr->name) {
		LOG_ERR("Failed to allocate domain name string");
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

	if (info->domain_attr->domain != domain1) {
		LOG_ERR("Bad domain pointer in returned kfi_info");
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

/* Set the fabric fid to fabric2. This should cause domain2 to be returned. */
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

	hints->fabric_attr->fabric = fabric2;
	hints->domain_attr->name = kstrdup(domain_name, GFP_KERNEL);
	if (!hints->domain_attr->name) {
		LOG_ERR("Failed to allocate domain name string");
		rc = -ENOMEM;
		goto err_free_hints;
	}

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

	if (info->domain_attr->domain != domain2) {
		LOG_ERR("Bad domain pointer in returned kfi_info");
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

/* Set the fabric fid to fabric2 and domain fid to domain2. */
static int test_valid_input_domain_fid(void)
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

	hints->fabric_attr->fabric = fabric2;
	hints->domain_attr->name = kstrdup(domain_name, GFP_KERNEL);
	hints->domain_attr->domain = domain2;
	if (!hints->domain_attr->name) {
		LOG_ERR("Failed to allocate domain name string");
		rc = -ENOMEM;
		goto err_free_hints;
	}

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

	if (info->domain_attr->domain != domain2) {
		LOG_ERR("Bad domain pointer in returned kfi_info");
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

/* Set the fabric fid to fabric2 and domain fid to domain2 but use and invalid
 * node for a domain2 fid.
 */
static int test_valid_input_domain_fid_invalid_node(void)
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

	hints->fabric_attr->fabric = fabric2;
	hints->domain_attr->name = kstrdup(domain_name, GFP_KERNEL);
	hints->domain_attr->domain = domain2;
	if (!hints->domain_attr->name) {
		LOG_ERR("Failed to allocate domain name string");
		rc = -ENOMEM;
		goto err_free_hints;
	}

	rc = kfi_getinfo(0, "cxi1", service, KFI_SOURCE, hints, &info);
	if (rc == 0) {
		LOG_ERR("Incorrectly allocated fabric info");
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

/* Set the domain fid to invalid value. */
static int test_invalid_input_domain_fid(void)
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

	hints->domain_attr->name = kstrdup(domain_name, GFP_KERNEL);
	hints->domain_attr->domain = (void *)0x12345;
	if (!hints->domain_attr->name) {
		LOG_ERR("Failed to allocate domain name string");
		rc = -ENOMEM;
		goto err_free_hints;
	}

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

static int __init test_module_init(void)
{
	int rc;

	rc = test_init();
	if (rc)
		goto err;

	rc = test_valid_output_domain_fid();
	if (rc)
		goto err_cleanup;

	rc = test_valid_input_fabric_fid();
	if (rc)
		goto err_cleanup;

	rc = test_valid_input_domain_fid();
	if (rc)
		goto err_cleanup;

	rc = test_invalid_input_domain_fid();
	if (rc)
		goto err_cleanup;

	rc = test_valid_input_domain_fid_invalid_node();
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
