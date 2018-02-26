//SPDX-License-Identifier: GPL-2.0
/*
 * Kfabric fabric tests.
 * Copyright 2022 Hewlett Packard Enterprise Development LP
 *
 */
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <kfabric.h>
#include <kfi_log.h>
#include <kfi_eq.h>
#include <kfi_errno.h>
#include <test_common.h>

#include "../../../prov/cxi/kcxi_prov.h"

#ifdef MODULE_NAME
#undef MODULE_NAME
#endif
#define MODULE_NAME "test_rx_tx_ctx_limits"

MODULE_AUTHOR("Ron Gredvig");
MODULE_DESCRIPTION("kfabric CXI RX TX context limit tests");
MODULE_LICENSE("GPL v2");

static struct sep_resource *res;

static int test_good_defaults(int id)
{
	struct sep_resource_opts res_opts = {};
	struct kfi_av_attr av_attr = {};
	struct kfi_cq_attr cq_attr = {};

	av_attr.type = KFI_AV_UNSPEC;
	cq_attr.size = 8;
	cq_attr.format = KFI_CQ_FORMAT_DATA;

	res_opts.hints = kfi_allocinfo();
	if (!res_opts.hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		return -ENOMEM;
	}

	/* Set resource */
	res_opts.hints->caps = KFI_MSG;
	res_opts.av_attr = &av_attr;
	res_opts.tx_cq_attr = &cq_attr;
	res_opts.rx_cq_attr = &cq_attr;
	res_opts.rx_count = KCXI_DOM_RX_CTX_RES;
	res_opts.tx_count = KCXI_DOM_TX_CTX_RES;

	res = sep_resource_alloc(&res_opts);
	if (IS_ERR(res)) {
		LOG_ERR("Failed to allocate SEP resource: rc=%ld", PTR_ERR(res));
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		kfi_freeinfo(res_opts.hints);
		return PTR_ERR(res);
	}

	kfi_freeinfo(res_opts.hints);
	sep_resource_free(res);
	LOG_INFO("TEST %d %s PASSED", id, __func__);
	return 0;
}

static int test_good_limits(int id)
{
	struct sep_resource_opts res_opts = {};
	struct kfi_av_attr av_attr = {};
	struct kfi_cq_attr cq_attr = {};

	av_attr.type = KFI_AV_UNSPEC;
	cq_attr.size = 8;
	cq_attr.format = KFI_CQ_FORMAT_DATA;

	res_opts.hints = kfi_allocinfo();
	if (!res_opts.hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		return -ENOMEM;
	}

	/* Set resource */
	res_opts.hints->caps = KFI_MSG;
	res_opts.av_attr = &av_attr;
	res_opts.tx_cq_attr = &cq_attr;
	res_opts.rx_cq_attr = &cq_attr;
	res_opts.rx_count = KCXI_DOM_RX_CTX_MAX;
	res_opts.tx_count = KCXI_DOM_TX_CTX_MAX;

	res = sep_resource_alloc(&res_opts);
	if (IS_ERR(res)) {
		LOG_ERR("Failed to allocate SEP resource: rc=%ld", PTR_ERR(res));
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		kfi_freeinfo(res_opts.hints);
		return PTR_ERR(res);
	}

	kfi_freeinfo(res_opts.hints);
	sep_resource_free(res);
	LOG_INFO("TEST %d %s PASSED", id, __func__);
	return 0;
}

static int test_bad_limits(int id)
{
	struct sep_resource_opts res_opts = {};
	struct kfi_av_attr av_attr = {};
	struct kfi_cq_attr cq_attr = {};

	av_attr.type = KFI_AV_UNSPEC;
	cq_attr.size = 8;
	cq_attr.format = KFI_CQ_FORMAT_DATA;

	res_opts.hints = kfi_allocinfo();
	if (!res_opts.hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		return -ENOMEM;
	}

	/* Set resource */
	res_opts.hints->caps = KFI_MSG;
	res_opts.av_attr = &av_attr;
	res_opts.tx_cq_attr = &cq_attr;
	res_opts.rx_cq_attr = &cq_attr;
	res_opts.rx_count = KCXI_DOM_RX_CTX_MAX + 1;
	res_opts.tx_count = KCXI_DOM_TX_CTX_MAX + 1;

	res = sep_resource_alloc(&res_opts);
	if (IS_ERR(res)) {
		LOG_INFO("sep_resource_alloc failed as expected: rc=%ld", PTR_ERR(res));
		LOG_INFO("TEST %d %s PASSED", id, __func__);
		kfi_freeinfo(res_opts.hints);
		return 0;
	}

	kfi_freeinfo(res_opts.hints);
	sep_resource_free(res);
	LOG_ERR("sep_resource_alloc() did not fail");
	LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	return -EINVAL;
}

static int test_good_low_dynamic_limits(int id)
{
	struct sep_resource_opts res_opts = {};
	struct kfi_av_attr av_attr = {};
	struct kfi_cq_attr cq_attr = {};
	int num_ctx = 16;
	int rx_size = 512;

	av_attr.type = KFI_AV_UNSPEC;
	cq_attr.size = 8;
	cq_attr.format = KFI_CQ_FORMAT_DATA;

	res_opts.hints = kfi_allocinfo();
	if (!res_opts.hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		return -ENOMEM;
	}

	/* Set resource */
	res_opts.hints->caps = KFI_MSG;
	res_opts.hints->domain_attr->cq_cnt = num_ctx * 2;
	res_opts.hints->domain_attr->tx_ctx_cnt = num_ctx;
	res_opts.hints->domain_attr->rx_ctx_cnt = num_ctx;
	res_opts.hints->rx_attr->size = rx_size;
	res_opts.av_attr = &av_attr;
	res_opts.tx_cq_attr = &cq_attr;
	res_opts.rx_cq_attr = &cq_attr;
	res_opts.rx_count = num_ctx;
	res_opts.tx_count = num_ctx;
	res_opts.dynamic_rsrc_alloc = true;

	res = sep_resource_alloc(&res_opts);
	if (IS_ERR(res)) {
		LOG_ERR("Failed to allocate SEP resource: rc=%ld", PTR_ERR(res));
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		kfi_freeinfo(res_opts.hints);
		return PTR_ERR(res);
	}

	kfi_freeinfo(res_opts.hints);
	sep_resource_free(res);
	LOG_INFO("TEST %d %s PASSED", id, __func__);
	return 0;
}

static int test_good_high_dynamic_limits(int id)
{
	struct sep_resource_opts res_opts = {};
	struct kfi_av_attr av_attr = {};
	struct kfi_cq_attr cq_attr = {};
	int num_ctx = KCXI_DOM_RX_CTX_MAX;
	int rx_size = 480;

	av_attr.type = KFI_AV_UNSPEC;
	cq_attr.size = 8;
	cq_attr.format = KFI_CQ_FORMAT_DATA;

	res_opts.hints = kfi_allocinfo();
	if (!res_opts.hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		return -ENOMEM;
	}

	/* Set resource */
	res_opts.hints->caps = KFI_MSG;
	res_opts.hints->domain_attr->cq_cnt = num_ctx * 2;
	res_opts.hints->domain_attr->tx_ctx_cnt = num_ctx;
	res_opts.hints->domain_attr->rx_ctx_cnt = num_ctx;
	res_opts.hints->rx_attr->size = rx_size;
	res_opts.av_attr = &av_attr;
	res_opts.tx_cq_attr = &cq_attr;
	res_opts.rx_cq_attr = &cq_attr;
	res_opts.rx_count = num_ctx;
	res_opts.tx_count = num_ctx;
	res_opts.dynamic_rsrc_alloc = true;

	res = sep_resource_alloc(&res_opts);
	if (IS_ERR(res)) {
		LOG_ERR("Failed to allocate SEP resource: rc=%ld", PTR_ERR(res));
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		kfi_freeinfo(res_opts.hints);
		return PTR_ERR(res);
	}

	kfi_freeinfo(res_opts.hints);
	sep_resource_free(res);
	LOG_INFO("TEST %d %s PASSED", id, __func__);
	return 0;
}

static int test_bad_dynamic_limits(int id)
{
	struct sep_resource_opts res_opts = {};
	struct kfi_av_attr av_attr = {};
	struct kfi_cq_attr cq_attr = {};
	int num_ctx = KCXI_DOM_RX_CTX_MAX;
	int rx_size = 512;

	av_attr.type = KFI_AV_UNSPEC;
	cq_attr.size = 8;
	cq_attr.format = KFI_CQ_FORMAT_DATA;

	res_opts.hints = kfi_allocinfo();
	if (!res_opts.hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		return -ENOMEM;
	}

	/* Set resource */
	res_opts.hints->caps = KFI_MSG;
	res_opts.hints->domain_attr->cq_cnt = num_ctx * 2;
	res_opts.hints->domain_attr->tx_ctx_cnt = num_ctx;
	res_opts.hints->domain_attr->rx_ctx_cnt = num_ctx;
	res_opts.hints->rx_attr->size = rx_size;
	res_opts.av_attr = &av_attr;
	res_opts.tx_cq_attr = &cq_attr;
	res_opts.rx_cq_attr = &cq_attr;
	res_opts.rx_count = num_ctx;
	res_opts.tx_count = num_ctx;
	res_opts.dynamic_rsrc_alloc = true;

	res = sep_resource_alloc(&res_opts);
	if (IS_ERR(res)) {
		LOG_INFO("sep_resource_alloc failed as expected: rc=%ld", PTR_ERR(res));
		LOG_INFO("TEST %d %s PASSED", id, __func__);
		kfi_freeinfo(res_opts.hints);
		return 0;
	}

	kfi_freeinfo(res_opts.hints);
	sep_resource_free(res);
	LOG_ERR("sep_resource_alloc() did not fail");
	LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	return -EINVAL;
}

static int __init test_module_init(void)
{
	int rc = 0;
	int exit_rc = 0;
	int test_id = 1;

	rc = test_good_defaults(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_good_limits(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bad_limits(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_good_low_dynamic_limits(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_good_high_dynamic_limits(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bad_dynamic_limits(test_id);
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
