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
#define MODULE_NAME "test_sep_cq_tx"

#define MAX_TX_CNT 10
#define MAX_RX_CNT 10

MODULE_AUTHOR("Ian Ziemba");
MODULE_DESCRIPTION("kfabric KCXI SEP CQ TX CTX tests");
MODULE_LICENSE("GPL v2");

static struct kfi_info *info;
static struct kfi_info *hints;
static struct kfid_fabric *fabric;
static struct kfid_domain *domain;
static struct kfid_av *av;
static struct kfid_cq *cq;
static struct kfid_ep *sep;

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
		goto out;
	}
	hints->caps = KCXI_EP_RDM_CAP;
	hints->ep_attr->tx_ctx_cnt = MAX_TX_CNT;
	hints->ep_attr->rx_ctx_cnt = MAX_RX_CNT;

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

	av_attr.type = KFI_AV_UNSPEC;
	rc = kfi_av_open(domain, &av_attr, &av, NULL);
	if (rc) {
		LOG_ERR("Failed to create address vector");
		goto close_domain;
	}

	rc = kfi_cq_open(domain, NULL, &cq, NULL, NULL);
	if (rc) {
		LOG_ERR("Failed to allocate CQ");
		goto close_av;
	}

	rc = kfi_scalable_ep(domain, info, &sep, NULL);
	if (rc) {
		LOG_ERR("Failed to allocate SEP");
		goto close_cq;
	}

	rc = kfi_scalable_ep_bind(sep, &av->fid, 0);
	if (rc) {
		LOG_ERR("Failed to bind AV to SEP");
		goto close_sep;
	}

	rc  = kfi_enable(sep);
	if (rc) {
		LOG_ERR("Failed to enable SEP");
		goto close_sep;
	}

	return 0;

close_sep:
	kfi_close(&sep->fid);
close_cq:
	kfi_close(&cq->fid);
close_av:
	kfi_close(&av->fid);
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
	kfi_close(&sep->fid);
	kfi_close(&cq->fid);
	kfi_close(&av->fid);
	kfi_close(&domain->fid);
	kfi_close(&fabric->fid);
	kfi_freeinfo(hints);
	kfi_freeinfo(info);
}

static int test_tx_ctx_single_bind_cq(int id)
{
	struct kfid_ep *tx_ep;
	struct kcxi_tx_ctx *tx_ctx;
	struct kcxi_cq *kcxi_cq = NULL;
	int exit_rc = 0;
	int rc;

	rc = kfi_tx_context(sep, 0, NULL, &tx_ep, NULL);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED", id, __func__);
		LOG_ERR("Failed to open TX CTX");
		return rc;
	}
	tx_ctx = container_of(tx_ep, struct kcxi_tx_ctx, ctx);

	rc = kfi_ep_bind(tx_ep, &cq->fid, 0);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED", id, __func__);
		LOG_ERR("Failed to bind CQ");
		exit_rc = rc;
		goto out;
	}

	if (tx_ctx->suppress_events) {
		LOG_ERR("TEST %d %s FAILED", id, __func__);
		LOG_ERR("TX contexts selective comp set");
		exit_rc = -EINVAL;
		goto out;
	}

	if (!tx_ctx->send_cq) {
		LOG_ERR("TEST %d %s FAILED", id, __func__);
		LOG_ERR("Failed to bind CQ");
		exit_rc = -EINVAL;
		goto out;
	}
	kcxi_cq = tx_ctx->send_cq;

	if (atomic_read(&kcxi_cq->ref_cnt) != 1) {
		LOG_ERR("TEST %d %s FAILED", id, __func__);
		LOG_ERR("CQ ref count not correct");
		exit_rc = -EINVAL;
		goto out;
	}

out:
	kfi_close(&tx_ep->fid);

	if (kcxi_cq) {
		if (atomic_read(&kcxi_cq->ref_cnt) != 0) {
			LOG_ERR("TEST %d %s FAILED", id, __func__);
			LOG_ERR("CQ ref count not zero");
			exit_rc = -EINVAL;
		}
	}

	if (!exit_rc)
		LOG_ERR("TEST %d %s PASSED", id, __func__);

	return exit_rc;
}

static int test_tx_ctx_single_bind_cq_selective_comp(int id)
{
	struct kfid_ep *tx_ep;
	struct kcxi_tx_ctx *tx_ctx;
	int exit_rc = 0;
	int rc;

	rc = kfi_tx_context(sep, 0, NULL, &tx_ep, NULL);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED", id, __func__);
		LOG_ERR("Failed to open TX CRX");
		return rc;
	}
	tx_ctx = container_of(tx_ep, struct kcxi_tx_ctx, ctx);

	rc = kfi_ep_bind(tx_ep, &cq->fid, KFI_SELECTIVE_COMPLETION);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED", id, __func__);
		LOG_ERR("Failed to bind CQ");
		exit_rc = rc;
		goto out;
	}

	if (!tx_ctx->suppress_events) {
		LOG_ERR("TEST %d %s FAILED", id, __func__);
		LOG_ERR("TX contexts selective comp not set");
		exit_rc = -EINVAL;
		goto out;
	}

out:
	kfi_close(&tx_ep->fid);

	if (!exit_rc)
		LOG_ERR("TEST %d %s PASSED", id, __func__);

	return exit_rc;
}

static int test_tx_ctx_double_bind_cq(int id)
{
	struct kfid_ep *tx_ep;
	int exit_rc = 0;
	int rc;

	rc = kfi_tx_context(sep, 0, NULL, &tx_ep, NULL);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED", id, __func__);
		LOG_ERR("Failed to open TX CTX");
		return rc;
	}

	rc = kfi_ep_bind(tx_ep, &cq->fid, 0);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED", id, __func__);
		LOG_ERR("Failed to bind CQ");
		exit_rc = rc;
		goto out;
	}

	rc = kfi_ep_bind(tx_ep, &cq->fid, 0);
	if (!rc) {
		LOG_ERR("TEST %d %s FAILED", id, __func__);
		LOG_ERR("Double bound CQ");
		exit_rc = -EINVAL;
		goto out;
	}

out:
	kfi_close(&tx_ep->fid);

	if (!exit_rc)
		LOG_ERR("TEST %d %s PASSED", id, __func__);

	return exit_rc;
}

static int test_tx_ctx_premature_cq_close(int id)
{
	struct kfid_ep *tx_ep;
	int exit_rc = 0;
	int rc;

	rc = kfi_tx_context(sep, 0, NULL, &tx_ep, NULL);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED", id, __func__);
		LOG_ERR("Failed to open TX CTX");
		return rc;
	}

	rc = kfi_ep_bind(tx_ep, &cq->fid, 0);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED", id, __func__);
		LOG_ERR("Failed to bind CQ");
		exit_rc = rc;
		goto out;
	}

	rc = kfi_close(&cq->fid);
	if (rc != -EBUSY) {
		LOG_ERR("TEST %d %s FAILED", id, __func__);
		LOG_ERR("Premature CQ close");
		exit_rc = -EINVAL;
		goto out;
	}

out:
	kfi_close(&tx_ep->fid);

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

	rc = test_tx_ctx_single_bind_cq(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_tx_ctx_single_bind_cq_selective_comp(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_tx_ctx_double_bind_cq(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_tx_ctx_premature_cq_close(test_id);
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
