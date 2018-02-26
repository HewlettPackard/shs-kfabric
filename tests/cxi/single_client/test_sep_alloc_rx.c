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
#define MODULE_NAME "test_sep_alloc_rx"

#define MAX_RX_CNT 10
#define MAX_RX_CNT 10

MODULE_AUTHOR("Ian Ziemba");
MODULE_DESCRIPTION("kfabric KCXI SEP Alloc RX CTX tests");
MODULE_LICENSE("GPL v2");

static struct kfi_info *info;
static struct kfi_info *hints;
static struct kfid_fabric *fabric;
static struct kfid_domain *domain;
static struct kfid_av *av;
static struct kfid_ep *sep;

static const struct kfi_rx_attr kcxi_rdm_rx_attr = {
	.caps = KCXI_RX_CAPS,
	.mode = KCXI_RX_MODE,
	.op_flags = KCXI_RX_OP_FLAGS,
	.msg_order = KCXI_RX_MSG_ORDER,
	.comp_order = KCXI_RX_COMP_ORDER,
	.total_buffered_recv = KCXI_RX_TOTAL_BUFFERED_RECV,
	.size = KCXI_RX_SIZE,
	.iov_limit = KCXI_RX_IOV_LIMIT,
};

static int verify_info_attrs(struct kfi_info *info)
{
	if (info->rx_attr->caps & ~info->caps)
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
	hints->ep_attr->rx_ctx_cnt = MAX_RX_CNT;
	hints->ep_attr->rx_ctx_cnt = MAX_RX_CNT;
	*hints->rx_attr = kcxi_rdm_rx_attr;

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

static int verify_rx_attributes(const struct kfi_rx_attr *input,
				const struct kfi_rx_attr *comp)
{
	if (input->caps != comp->caps) {
		LOG_ERR("Bad RX Attr Caps: Got %llu, Expected %llu",
			input->caps, comp->caps);
		goto err;
	}

	if (input->mode != comp->mode) {
		LOG_ERR("Bad RX Attr Mode: Got %llu, Expected %llu",
			input->mode, comp->mode);
		goto err;
	}

	if (input->op_flags != comp->op_flags) {
		LOG_ERR("Bad RX Attr Op Flags: Got %llu, Expected %llu",
			input->op_flags, comp->op_flags);
		goto err;
	}

	if (input->msg_order != comp->msg_order) {
		LOG_ERR("Bad RX Attr Msg Order: Got %llu, Expected %llu",
			input->msg_order, comp->msg_order);
		goto err;
	}

	if (input->comp_order != comp->comp_order) {
		LOG_ERR("Bad RX Attr Comp Order: Got %llu, Expected %llu",
			input->comp_order, comp->comp_order);
		goto err;
	}

	if (input->total_buffered_recv != comp->total_buffered_recv) {
		LOG_ERR("Bad RX Attr Total Buf Recv: Got %lu, Expected %lu",
			input->total_buffered_recv, comp->total_buffered_recv);
		goto err;
	}

	if (input->size != comp->size) {
		LOG_ERR("Bad RX Attr Size: Got %lu, Expected %lu",
			input->size, comp->size);
		goto err;
	}

	if (input->iov_limit != comp->iov_limit) {
		LOG_ERR("Bad RX Attr IOV Limit: Got %lu, Expected %lu",
			input->iov_limit, comp->iov_limit);
		goto err;
	}

	return 0;

err:
	return -EINVAL;
}

static int test_alloc_rx_ctx_null_attr(int id)
{
	struct kfi_rx_attr expected_attr = kcxi_rdm_rx_attr;
	struct kfid_ep *rx_ep[MAX_RX_CNT];
	struct kfid_ep *rx_bad_ep;
	struct kcxi_rx_ctx *rx_ctx;
	int exit_rc = 0;
	int rc;
	int i;

	for (i = 0; i < MAX_RX_CNT; i++)
		rx_ep[i] = NULL;

	for (i = 0; i < MAX_RX_CNT; i++) {
		rc = kfi_rx_context(sep, i, NULL, &rx_ep[i], NULL);
		if (rc) {
			LOG_ERR("TEST %d %s FAILED", id, __func__);
			LOG_ERR("Failed to alloc RX CTX");
			exit_rc = rc;
			goto err;
		}
		rx_ctx = container_of(rx_ep[i], struct kcxi_rx_ctx, ctx);

		rc = verify_rx_attributes(&rx_ctx->attr, &expected_attr);
		if (rc) {
			LOG_ERR("TEST %d %s FAILED", id, __func__);
			LOG_ERR("Bad RX context attributes");
			exit_rc = rc;
			goto err;
		}
	}

	rc = kfi_rx_context(sep, i + 1, NULL, &rx_bad_ep, NULL);
	if (!rc) {
		LOG_ERR("TEST %d %s FAILED", id, __func__);
		LOG_ERR("Should not have opened RX context");
		exit_rc = -EINVAL;
		kfi_close(&rx_bad_ep->fid);
		goto err;
	}

	if (!exit_rc)
		LOG_ERR("TEST %d %s PASSED", id, __func__);

err:
	for (i = 0; i < MAX_RX_CNT; i++) {
		if (rx_ep[i])
			kfi_close(&rx_ep[i]->fid);
	}

	return exit_rc;
}

static int test_alloc_rx_ctx_good_attr(int id)
{
	struct kfi_rx_attr expected_attr = kcxi_rdm_rx_attr;
	struct kfid_ep *rx_ep[MAX_RX_CNT];
	struct kfid_ep *rx_bad_ep;
	struct kcxi_rx_ctx *rx_ctx;
	int exit_rc = 0;
	int rc;
	int i;

	expected_attr.size = 1;

	for (i = 0; i < MAX_RX_CNT; i++)
		rx_ep[i] = NULL;

	for (i = 0; i < MAX_RX_CNT; i++) {
		rc = kfi_rx_context(sep, i, &expected_attr, &rx_ep[i], NULL);
		if (rc) {
			LOG_ERR("TEST %d %s FAILED", id, __func__);
			LOG_ERR("Failed to alloc RX CTX");
			exit_rc = rc;
			goto err;
		}
		rx_ctx = container_of(rx_ep[i], struct kcxi_rx_ctx, ctx);

		rc = verify_rx_attributes(&rx_ctx->attr, &expected_attr);
		if (rc) {
			LOG_ERR("TEST %d %s FAILED", id, __func__);
			LOG_ERR("Bad RX context attributes");
			exit_rc = rc;
			goto err;
		}
	}

	rc = kfi_rx_context(sep, i + 1, NULL, &rx_bad_ep, NULL);
	if (!rc) {
		LOG_ERR("TEST %d %s FAILED", id, __func__);
		LOG_ERR("Should not have opened RX context");
		exit_rc = -EINVAL;
		kfi_close(&rx_bad_ep->fid);
		goto err;
	}

	if (!exit_rc)
		LOG_ERR("TEST %d %s PASSED", id, __func__);

err:
	for (i = 0; i < MAX_RX_CNT; i++) {
		if (rx_ep[i])
			kfi_close(&rx_ep[i]->fid);
	}

	return exit_rc;
}

static int test_alloc_rx_ctx_bad_attr(int id)
{
	struct kfi_rx_attr attr = {};
	struct kfid_ep *rx_ep;
	int exit_rc = 0;
	int rc;

	attr.size = 9999999;

	rc = kfi_rx_context(sep, 0, &attr, &rx_ep, NULL);
	if (!rc) {
		LOG_ERR("TEST %d %s FAILED", id, __func__);
		LOG_ERR("Should not have allocated RX CTX");
		exit_rc = -EINVAL;
		kfi_close(&rx_ep->fid);
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

	rc = test_alloc_rx_ctx_null_attr(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_alloc_rx_ctx_good_attr(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_alloc_rx_ctx_bad_attr(test_id);
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
