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
#define MODULE_NAME "test_sep_alloc_tx"

#define MAX_TX_CNT 10
#define MAX_RX_CNT 10

MODULE_AUTHOR("Ian Ziemba");
MODULE_DESCRIPTION("kfabric KCXI SEP Alloc TX CTX tests");
MODULE_LICENSE("GPL v2");

static struct kfi_info *info;
static struct kfi_info *hints;
static struct kfid_fabric *fabric;
static struct kfid_domain *domain;
static struct kfid_av *av;
static struct kfid_ep *sep;

static const struct kfi_tx_attr kcxi_rdm_tx_attr = {
	.caps = KCXI_TX_CAPS,
	.mode = KCXI_TX_MODE,
	.op_flags = KCXI_TX_OP_FLAGS,
	.msg_order = KCXI_TX_MSG_ORDER,
	.comp_order = KCXI_TX_COMP_ORDER,
	.inject_size = KCXI_TX_INJECT_SIZE,
	.size = KCXI_TX_SIZE,
	.iov_limit = KCXI_TX_IOV_LIMIT,
	.rma_iov_limit = KCXI_TX_RMA_IOV_LIMIT,
};

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
	struct kfi_av_attr av_attr = {};

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("Failed to allocate info structure");
		rc = -ENOMEM;
		goto err;
	}
	hints->caps = KCXI_EP_RDM_CAP;
	hints->ep_attr->tx_ctx_cnt = MAX_TX_CNT;
	hints->ep_attr->rx_ctx_cnt = MAX_RX_CNT;
	*hints->tx_attr = kcxi_rdm_tx_attr;

	rc = kfi_getinfo_success(0, NULL, NULL, KFI_SOURCE,  hints, &info);
	if (rc) {
		LOG_ERR("Failed to check fabric info");
		goto err_free_hints;
	}

	rc = kfi_fabric(info->fabric_attr, &fabric, NULL);
	if (rc) {
		LOG_ERR("Failed to create fabric object");
		goto err_free_info;
	}

	rc = kfi_domain(fabric, info, &domain, NULL);
	if (rc) {
		LOG_ERR("Failed to create domain object");
		goto err_free_fabric;
	}

	av_attr.type = KFI_AV_UNSPEC;
	rc = kfi_av_open(domain, &av_attr, &av, NULL);
	if (rc) {
		LOG_ERR("Failed to create address vector");
		goto err_free_domain;
	}

	rc = kfi_scalable_ep(domain, info, &sep, NULL);
	if (rc) {
		LOG_ERR("Failed to allocate SEP");
		goto err_free_av;
	}

	rc = kfi_scalable_ep_bind(sep, &av->fid, 0);
	if (rc) {
		LOG_ERR("Failed to bind AV to SEP");
		goto err_free_sep;
	}

	rc  = kfi_enable(sep);
	if (rc) {
		LOG_ERR("Failed to enable SEP");
		goto err_free_sep;
	}

	return 0;

err_free_sep:
	kfi_close(&sep->fid);

err_free_av:
	kfi_close(&av->fid);

err_free_domain:
	kfi_close(&domain->fid);

err_free_fabric:
	kfi_close(&fabric->fid);

err_free_info:
	kfi_freeinfo(info);

err_free_hints:
	kfi_freeinfo(hints);

err:
	return rc;
}

static void test_fini(void)
{
	kfi_close(&sep->fid);
	kfi_close(&av->fid);
	kfi_close(&domain->fid);
	kfi_close(&fabric->fid);
	kfi_freeinfo(hints);
	kfi_freeinfo(info);
}

static int verify_tx_attributes(const struct kfi_tx_attr *input,
				const struct kfi_tx_attr *comp)
{
	if (input->caps != comp->caps) {
		LOG_ERR("Bad TX Attr Caps: Got %llu, Expected %llu",
			input->caps, comp->caps);
		goto err;
	}

	if (input->mode != comp->mode) {
		LOG_ERR("Bad TX Attr Mode: Got %llu, Expected %llu",
			input->mode, comp->mode);
		goto err;
	}

	if (input->op_flags != comp->op_flags) {
		LOG_ERR("Bad TX Attr Op Flags: Got %llu, Expected %llu",
			input->op_flags, comp->op_flags);
		goto err;
	}

	if (input->msg_order != comp->msg_order) {
		LOG_ERR("Bad TX Attr Msg Order: Got %llu, Expected %llu",
			input->msg_order, comp->msg_order);
		goto err;
	}

	if (input->comp_order != comp->comp_order) {
		LOG_ERR("Bad TX Attr Comp Order: Got %llu, Expected %llu",
			input->comp_order, comp->comp_order);
		goto err;
	}

	if (input->inject_size != comp->inject_size) {
		LOG_ERR("Bad TX Attr Inject Size: Got %lu, Expected %lu",
			input->inject_size, comp->inject_size);
		goto err;
	}

	if (input->size != comp->size) {
		LOG_ERR("Bad TX Attr Size: Got %lu, Expected %lu",
			input->size, comp->size);
		goto err;
	}

	if (input->iov_limit != comp->iov_limit) {
		LOG_ERR("Bad TX Attr IOV Limit: Got %lu, Expected %lu",
			input->iov_limit, comp->iov_limit);
		goto err;
	}

	if (input->rma_iov_limit != comp->rma_iov_limit) {
		LOG_ERR("Bad TX Attr RMA IOV Limit: Got %lu, Expected %lu",
			input->rma_iov_limit, comp->rma_iov_limit);
		goto err;
	}

	return 0;

err:
	return -EINVAL;
}

static int test_alloc_tx_ctx_null_attr(int id)
{
	struct kfi_tx_attr expected_attr = kcxi_rdm_tx_attr;
	struct kfid_ep *tx_ep[MAX_TX_CNT];
	struct kfid_ep *tx_bad_ep;
	struct kcxi_tx_ctx *tx_ctx;
	int exit_rc = 0;
	int rc;
	int i;

	for (i = 0; i < MAX_TX_CNT; i++)
		tx_ep[i] = NULL;

	for (i = 0; i < MAX_TX_CNT; i++) {
		rc = kfi_tx_context(sep, i, NULL, &tx_ep[i], NULL);
		if (rc) {
			LOG_ERR("TEST %d %s FAILED", id, __func__);
			LOG_ERR("Failed to alloc TX CTX");
			exit_rc = rc;
			goto err;
		}
		tx_ctx = container_of(tx_ep[i], struct kcxi_tx_ctx, ctx);

		rc = verify_tx_attributes(&tx_ctx->attr, &expected_attr);
		if (rc) {
			LOG_ERR("TEST %d %s FAILED", id, __func__);
			LOG_ERR("Bad TX context attributes");
			exit_rc = rc;
			goto err;
		}
	}

	rc = kfi_tx_context(sep, i + 1, NULL, &tx_bad_ep, NULL);
	if (!rc) {
		LOG_ERR("TEST %d %s FAILED", id, __func__);
		LOG_ERR("Should not have opened TX context");
		exit_rc = -EINVAL;
		kfi_close(&tx_bad_ep->fid);
		goto err;
	}

	if (!exit_rc)
		LOG_ERR("TEST %d %s PASSED", id, __func__);

err:
	for (i = 0; i < MAX_TX_CNT; i++) {
		if (tx_ep[i])
			kfi_close(&tx_ep[i]->fid);
	}

	return exit_rc;
}

static int test_alloc_tx_ctx_good_attr(int id)
{
	struct kfi_tx_attr expected_attr = kcxi_rdm_tx_attr;
	struct kfid_ep *tx_ep[MAX_TX_CNT];
	struct kfid_ep *tx_bad_ep;
	struct kcxi_tx_ctx *tx_ctx;
	int exit_rc = 0;
	int rc;
	int i;

	expected_attr.size = 1;

	for (i = 0; i < MAX_TX_CNT; i++)
		tx_ep[i] = NULL;

	for (i = 0; i < MAX_TX_CNT; i++) {
		rc = kfi_tx_context(sep, i, &expected_attr, &tx_ep[i], NULL);
		if (rc) {
			LOG_ERR("TEST %d %s FAILED", id, __func__);
			LOG_ERR("Failed to alloc TX CTX");
			exit_rc = rc;
			goto err;
		}
		tx_ctx = container_of(tx_ep[i], struct kcxi_tx_ctx, ctx);

		rc = verify_tx_attributes(&tx_ctx->attr, &expected_attr);
		if (rc) {
			LOG_ERR("TEST %d %s FAILED", id, __func__);
			LOG_ERR("Bad TX context attributes");
			exit_rc = rc;
			goto err;
		}
	}

	rc = kfi_tx_context(sep, i + 1, NULL, &tx_bad_ep, NULL);
	if (!rc) {
		LOG_ERR("TEST %d %s FAILED", id, __func__);
		LOG_ERR("Should not have opened TX context");
		exit_rc = -EINVAL;
		kfi_close(&tx_bad_ep->fid);
		goto err;
	}

	if (!exit_rc)
		LOG_ERR("TEST %d %s PASSED", id, __func__);

err:
	for (i = 0; i < MAX_TX_CNT; i++) {
		if (tx_ep[i])
			kfi_close(&tx_ep[i]->fid);
	}

	return exit_rc;
}

static int test_alloc_tx_ctx_bad_attr(int id)
{
	struct kfi_tx_attr attr = {};
	struct kfid_ep *tx_ep;
	int exit_rc = 0;
	int rc;

	attr.size = 9999999;

	rc = kfi_tx_context(sep, 0, &attr, &tx_ep, NULL);
	if (!rc) {
		LOG_ERR("TEST %d %s FAILED", id, __func__);
		LOG_ERR("Should not have allocated TX CTX");
		exit_rc = -EINVAL;
		kfi_close(&tx_ep->fid);
	}

	if (!exit_rc)
		LOG_ERR("TEST %d %s PASSED", id, __func__);

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

	rc = test_alloc_tx_ctx_null_attr(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_alloc_tx_ctx_good_attr(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_alloc_tx_ctx_bad_attr(test_id);
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
