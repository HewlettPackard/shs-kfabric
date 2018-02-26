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
#define MODULE_NAME "test_sep_enable_tx"

#define MAX_TX_CNT 10
#define MAX_RX_CNT 10

MODULE_AUTHOR("Ian Ziemba");
MODULE_DESCRIPTION("kfabric KCXI SEP Enable TX CTX tests");
MODULE_LICENSE("GPL v2");

static struct kfi_info *info;
static struct kfi_info *hints;
static struct kfid_fabric *fabric;
static struct kfid_domain *domain;
static struct kfid_av *av;
static struct kfid_cq *cq;
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
	.rma_iov_limit = KCXI_TX_RMA_IOV_LIMIT
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

	rc = kfi_cq_open(domain, NULL, &cq, NULL, NULL);
	if (rc) {
		LOG_ERR("Failed to allocate CQ");
		goto err_free_av;
	}

	return 0;
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
	kfi_close(&cq->fid);
	kfi_close(&av->fid);
	kfi_close(&domain->fid);
	kfi_close(&fabric->fid);
	kfi_freeinfo(hints);
	kfi_freeinfo(info);
}

static int test_alloc_sep(size_t max_msg_size)
{
	int rc;

	info->ep_attr->max_msg_size = max_msg_size;

	rc = kfi_scalable_ep(domain, info, &sep, NULL);
	if (rc) {
		LOG_ERR("Failed to allocate SEP");
		goto err;
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

err:
	return rc;
}

static void test_close_sep(void)
{
	kfi_close(&sep->fid);
}

static int test_enable_tx_ctx_no_cq(int id)
{
	struct kfid_ep *tx_ep;
	int rc;

	/* Use the default max message size. */
	rc = test_alloc_sep(0);
	if (rc) {
		LOG_ERR("Failed to open SEP");
		goto err;
	}

	rc = kfi_tx_context(sep, 0, NULL, &tx_ep, NULL);
	if (rc) {
		LOG_ERR("Failed to open TX CTX");
		goto err_close_sep;
	}

	rc = kfi_enable(tx_ep);
	if (rc != -KFI_ENOCQ) {
		LOG_ERR("Should not have been able to enable TX CTX");
		rc = -EINVAL;
		goto err_close_tx;
	}

	kfi_close(&tx_ep->fid);

	test_close_sep();

	LOG_ERR("TEST %d %s PASSED", id, __func__);

	return 0;

err_close_tx:
	kfi_close(&tx_ep->fid);

err_close_sep:
	test_close_sep();

err:
	LOG_ERR("TEST %d %s FAILED", id, __func__);
	return rc;
}

static int test_enable_tx_ctx(int id)
{
	struct kcxi_tx_ctx *kcxi_tx;
	struct kfid_ep *tx_ep;
	int rc;

	/* Use the default max message size. */
	rc = test_alloc_sep(0);
	if (rc) {
		LOG_ERR("Failed to open SEP");
		goto err;
	}

	rc = kfi_tx_context(sep, 5, NULL, &tx_ep, NULL);
	if (rc) {
		LOG_ERR("Failed to allocate TX context");
		goto err_close_sep;
	}

	kcxi_tx = container_of(tx_ep, struct kcxi_tx_ctx, ctx);

	rc = kfi_ep_bind(tx_ep, &cq->fid, 0);
	if (rc) {
		LOG_ERR("Failed to bind CQ");
		goto err_close_tx;
	}

	rc = kfi_enable(tx_ep);
	if (rc) {
		LOG_ERR("Failed enable TX CTX");
		goto err_close_tx;
	}

	/* Verify pte_cmdq-> are allocated. */
	if (!kcxi_tx->transmit) {
		LOG_ERR("Transmit CMDQ not allocated");
		rc = -EINVAL;
		goto err_close_tx;
	}

	if (atomic_read(&kcxi_tx->send_cq->ref_cnt) != 1) {
		LOG_ERR("CQ refcount incorrect");
		rc = -EINVAL;
		goto err_close_tx;
	}

	if (atomic_read(&kcxi_tx->ep_attr->num_tx_ctx) != 1) {
		LOG_ERR("SEP TX count incorrect");
		rc = -EINVAL;
		goto err_close_tx;
	}

	kfi_close(&tx_ep->fid);

	test_close_sep();

	LOG_ERR("TEST %d %s PASSED", id, __func__);

	return 0;

err_close_tx:
	kfi_close(&tx_ep->fid);

err_close_sep:
	test_close_sep();

err:
	LOG_ERR("TEST %d %s FAILED", id, __func__);
	return rc;
}

static int test_enable_tx_ctx_no_rendezvous(int id)
{
	struct kcxi_tx_ctx *kcxi_tx;
	struct kfid_ep *tx_ep;
	int rc;

	/* Use the default max message size. */
	rc = test_alloc_sep(256);
	if (rc) {
		LOG_ERR("Failed to open SEP");
		goto err;
	}

	rc = kfi_tx_context(sep, 5, NULL, &tx_ep, NULL);
	if (rc) {
		LOG_ERR("Failed to open TX CTX");
		goto err_close_sep;
	}

	kcxi_tx = container_of(tx_ep, struct kcxi_tx_ctx, ctx);

	rc = kfi_ep_bind(tx_ep, &cq->fid, 0);
	if (rc) {
		LOG_ERR("Failed to bind CQ");
		goto err_close_tx;
	}

	rc = kfi_enable(tx_ep);
	if (rc) {
		LOG_ERR("Failed enable TX CTX");
		goto err_close_tx;
	}

	if (!kcxi_tx->transmit) {
		LOG_ERR("Transmit CMDQ not allocated");
		rc = -EINVAL;
		goto err_close_tx;
	}

	if (atomic_read(&kcxi_tx->send_cq->ref_cnt) != 1) {
		LOG_ERR("CQ refcount incorrect");
		rc = -EINVAL;
		goto err_close_tx;
	}

	if (atomic_read(&kcxi_tx->ep_attr->num_tx_ctx) != 1) {
		LOG_ERR("SEP TX count incorrect");
		rc = -EINVAL;
		goto err_close_tx;
	}

	kfi_close(&tx_ep->fid);

	test_close_sep();

	LOG_ERR("TEST %d %s PASSED", id, __func__);

	return 0;

err_close_tx:
	kfi_close(&tx_ep->fid);

err_close_sep:
	test_close_sep();

err:
	LOG_ERR("TEST %d %s FAILED", id, __func__);
	return rc;
}

/*
 * Test an RMA command when the TX context is not enabled. -KFI_EOPBADSTATE
 * should be returned.
 */
static int test_rma_operation_no_enable(int id)
{
	struct kfid_ep *tx_ep;
	int rc;

	/* Use the default max message size. */
	rc = test_alloc_sep(256);
	if (rc) {
		LOG_ERR("Failed to open SEP");
		goto err;
	}

	rc = kfi_tx_context(sep, 5, NULL, &tx_ep, NULL);
	if (rc) {
		LOG_ERR("Failed to open TX CTX");
		goto err_close_sep;
	}

	rc = kfi_read(tx_ep, NULL, 0, NULL, 0, 0, 0, 0);
	if (rc != -KFI_EOPBADSTATE) {
		LOG_ERR("-KFI_EOPBADSTATE should have been returned");
		goto err_close_tx;
	}

	kfi_close(&tx_ep->fid);
	test_close_sep();

	LOG_ERR("TEST %d %s PASSED", id, __func__);

	return 0;

err_close_tx:
	kfi_close(&tx_ep->fid);

err_close_sep:
	test_close_sep();

err:
	LOG_ERR("TEST %d %s FAILED", id, __func__);
	return rc;
}

/*
 * Test a send command when the TX context is not enabled. -KFI_EOPBADSTATE
 * should be returned.
 */
static int test_send_operation_no_enable(int id)
{
	struct kfid_ep *tx_ep;
	int rc;

	/* Use the default max message size. */
	rc = test_alloc_sep(256);
	if (rc) {
		LOG_ERR("Failed to open SEP");
		goto err;
	}

	rc = kfi_tx_context(sep, 5, NULL, &tx_ep, NULL);
	if (rc) {
		LOG_ERR("Failed to open TX CTX");
		goto err_close_sep;
	}

	rc = kfi_send(tx_ep, NULL, 0, NULL, 0, NULL);
	if (rc != -KFI_EOPBADSTATE) {
		LOG_ERR("-KFI_EOPBADSTATE should have been returned");
		goto err_close_tx;
	}

	kfi_close(&tx_ep->fid);
	test_close_sep();

	LOG_ERR("TEST %d %s PASSED", id, __func__);

	return 0;

err_close_tx:
	kfi_close(&tx_ep->fid);

err_close_sep:
	test_close_sep();

err:
	LOG_ERR("TEST %d %s FAILED", id, __func__);
	return rc;
}

static int __init test_module_init(void)
{
	int rc = 0;
	int exit_rc = 0;
	int test_id = 1;

	rc = test_init();
	if (rc)
		return rc;

	rc = test_enable_tx_ctx_no_cq(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_enable_tx_ctx(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_enable_tx_ctx_no_rendezvous(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_rma_operation_no_enable(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_send_operation_no_enable(test_id);
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
