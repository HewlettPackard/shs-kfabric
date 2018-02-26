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
#define MODULE_NAME "test_sep_attr"

MODULE_AUTHOR("Ian Ziemba");
MODULE_DESCRIPTION("kfabric KCXI SEP attribute tests");
MODULE_LICENSE("GPL v2");

static struct kfi_info *info;
static struct kfid_fabric *fabric;
static struct kfid_domain *domain;

static const struct kfi_ep_attr kcxi_rdm_ep_attr = {
	.type = KCXI_EP_TYPE,
	.protocol = KCXI_EP_PROTOCOL,
	.protocol_version = KCXI_EP_PROTOCOL_VERSION,
	.max_msg_size = KCXI_EP_MAX_MSG_SIZE,
	.msg_prefix_size = KCXI_EP_MSG_PREFIX_SIZE,
	.max_order_raw_size = KCXI_EP_MAX_ORDER_RAW_SIZE,
	.max_order_war_size = KCXI_EP_MAX_ORDER_WAR_SIZE,
	.max_order_waw_size = KCXI_EP_MAX_ORDER_WAW_SIZE,
	.mem_tag_format = KCXI_EP_MAX_ORDER_WAW_SIZE,
	.tx_ctx_cnt = KCXI_EP_TX_CTX_CNT,
	.rx_ctx_cnt = KCXI_EP_RX_CTX_CNT,
};

static const struct kfi_tx_attr kcxi_rdm_tx_attr = {
	.caps = KCXI_TX_CAPS,
	.mode = KCXI_TX_MODE,
	.op_flags = KCXI_TX_OP_FLAGS & ~KFI_MORE,
	.msg_order = KCXI_TX_MSG_ORDER,
	.comp_order = KCXI_TX_COMP_ORDER,
	.inject_size = KCXI_TX_INJECT_SIZE,
	.size = KCXI_TX_SIZE,
	.iov_limit = KCXI_TX_IOV_LIMIT,
	.rma_iov_limit = KCXI_TX_RMA_IOV_LIMIT,
};

static const struct kfi_rx_attr kcxi_rdm_rx_attr = {
	.caps = KCXI_RX_CAPS,
	.mode = KCXI_RX_MODE,
	.op_flags = KCXI_RX_OP_FLAGS & ~(KFI_MORE | KFI_MULTI_RECV),
	.msg_order = KCXI_RX_MSG_ORDER,
	.comp_order = KCXI_RX_COMP_ORDER,
	.total_buffered_recv = KCXI_RX_TOTAL_BUFFERED_RECV,
	.size = KCXI_RX_SIZE,
	.iov_limit = KCXI_RX_IOV_LIMIT,
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

static int test_init(struct kfi_info *hints)
{
	int rc = 0;

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

	return 0;

close_fabric:
	kfi_close(&fabric->fid);
out:
	if (info)
		kfi_freeinfo(info);

	return rc;

}

static void test_fini(void)
{
	kfi_close(&domain->fid);
	kfi_close(&fabric->fid);
	kfi_freeinfo(info);
}

static int test_verify_sep_tx_attr(const struct kfi_tx_attr *input,
				   const struct kfi_tx_attr *expected)
{
	if (input->caps != expected->caps) {
		LOG_ERR("Bad TX Caps: got %llu, expected %llu", input->caps,
			expected->caps);
		goto err;
	}

	if (input->mode != expected->mode) {
		LOG_ERR("Bad TX mode: got %llu, expected %llu", input->mode,
			expected->mode);
		goto err;
	}

	if (input->op_flags != expected->op_flags) {
		LOG_ERR("Bad TX OP Flags: got %llu, expected %llu",
			input->op_flags, expected->op_flags);
		goto err;
	}

	if (input->msg_order != expected->msg_order) {
		LOG_ERR("Bad TX MSG Order: got %llu, expected %llu",
			input->msg_order, expected->msg_order);
		goto err;
	}

	if (input->comp_order != expected->comp_order) {
		LOG_ERR("Bad TX Comp Order: got %llu, expected %llu",
			input->comp_order, expected->comp_order);
		goto err;
	}

	if (input->inject_size != expected->inject_size) {
		LOG_ERR("Bad TX Inject Size: got %lu, expected %lu",
			input->inject_size, expected->inject_size);
		goto err;
	}

	if (input->size != expected->size) {
		LOG_ERR("Bad TX Size: got %lu, expected %lu",
			input->size, expected->size);
		goto err;
	}

	if (input->iov_limit != expected->iov_limit) {
		LOG_ERR("Bad TX IOV Limit: got %lu, expected %lu",
			input->iov_limit, expected->iov_limit);
		goto err;
	}

	if (input->rma_iov_limit != expected->rma_iov_limit) {
		LOG_ERR("Bad TX RMA IOV Limit: got %lu, expected %lu",
			input->rma_iov_limit, expected->rma_iov_limit);
		goto err;
	}

	return 0;
err:
	return -EINVAL;
}

static int test_verify_sep_rx_attr(const struct kfi_rx_attr *input,
				   const struct kfi_rx_attr *expected)
{
	if (input->caps != expected->caps) {
		LOG_ERR("Bad RX Caps: got %llu, expected %llu", input->caps,
			expected->caps);
		goto err;
	}

	if (input->mode != expected->mode) {
		LOG_ERR("Bad RX mode: got %llu, expected %llu", input->mode,
			expected->mode);
		goto err;
	}

	if (input->op_flags != expected->op_flags) {
		LOG_ERR("Bad RX OP Flags: got %llu, expected %llu",
			input->op_flags, expected->op_flags);
		goto err;
	}

	if (input->msg_order != expected->msg_order) {
		LOG_ERR("Bad RX MSG Order: got %llu, expected %llu",
			input->msg_order, expected->msg_order);
		goto err;
	}

	if (input->comp_order != expected->comp_order) {
		LOG_ERR("Bad RX Comp Order: got %llu, expected %llu",
			input->comp_order, expected->comp_order);
		goto err;
	}

	if (input->total_buffered_recv != expected->total_buffered_recv) {
		LOG_ERR("Bad RX Total Buffered Recv: got %lu, expected %lu",
			input->total_buffered_recv,
			expected->total_buffered_recv);
		goto err;
	}

	if (input->size != expected->size) {
		LOG_ERR("Bad RX Size: got %lu, expected %lu",
			input->size, expected->size);
		goto err;
	}

	if (input->iov_limit != expected->iov_limit) {
		LOG_ERR("Bad RX IOV Limit: got %lu, expected %lu",
			input->iov_limit, expected->iov_limit);
		goto err;
	}

	return 0;
err:
	return -EINVAL;
}

static int test_verify_sep_ep_attr(const struct kfi_ep_attr *input,
				   const struct kfi_ep_attr *expected)
{
	if (input->type != expected->type) {
		LOG_ERR("Bad EP Type: got %d, expected %d", input->type,
			expected->type);
		goto err;
	}

	if (input->protocol != expected->protocol) {
		LOG_ERR("Bad EP Proto: got %u, expected %u",
			input->protocol, expected->protocol);
		goto err;
	}

	if (input->protocol_version != expected->protocol_version) {
		LOG_ERR("Bad EP Proto Version: got %u, expected %u",
			input->protocol_version, expected->protocol_version);
		goto err;
	}

	if (input->max_msg_size != expected->max_msg_size) {
		LOG_ERR("Bad EP Max MSG Size: got %lu, expected %lu",
			input->max_msg_size, expected->max_msg_size);
		goto err;
	}

	if (input->msg_prefix_size != expected->msg_prefix_size) {
		LOG_ERR("Bad EP MSG Prefix Size: got %lu, expected %lu",
			input->msg_prefix_size, expected->msg_prefix_size);
		goto err;
	}

	if (input->max_order_raw_size != expected->max_order_raw_size) {
		LOG_ERR("Bad EP RAW Size: got %lu, expected %lu",
			input->max_order_raw_size,
			expected->max_order_raw_size);
		goto err;
	}

	if (input->max_order_war_size != expected->max_order_war_size) {
		LOG_ERR("Bad EP WAR Size: got %lu, expected %lu",
			input->max_order_war_size,
			expected->max_order_war_size);
		goto err;
	}

	if (input->max_order_waw_size != expected->max_order_waw_size) {
		LOG_ERR("Bad EP WAW Size: got %lu, expected %lu",
			input->max_order_waw_size,
			expected->max_order_waw_size);
		goto err;
	}

	if (input->mem_tag_format != expected->mem_tag_format) {
		LOG_ERR("Bad EP Mem Tag FMT: got %llu, expected %llu",
			input->mem_tag_format,
			expected->mem_tag_format);
		goto err;
	}

	if (input->tx_ctx_cnt != expected->tx_ctx_cnt) {
		LOG_ERR("Bad EP TX CTX CNT: got %lu, expected %lu",
			input->tx_ctx_cnt, expected->tx_ctx_cnt);
		goto err;
	}

	if (input->rx_ctx_cnt != expected->rx_ctx_cnt) {
		LOG_ERR("Bad EP RX CTX CNT: got %lu, expected %lu",
			input->rx_ctx_cnt, expected->rx_ctx_cnt);
		goto err;
	}

	return 0;
err:
	return -EINVAL;
}

static int test_create_verify_sep(struct kfi_info *ep_info,
				  struct kfi_ep_attr *ep_attr,
				  struct kfi_tx_attr *tx_attr,
				  struct kfi_rx_attr *rx_attr)
{
	int rc;
	int exit_rc = 0;
	struct kfid_ep *sep;
	struct kcxi_ep *kcxi_ep;

	rc = kfi_scalable_ep(domain, ep_info, &sep, NULL);
	if (rc) {
		LOG_ERR("Unable to open SEP");
		return rc;
	}
	kcxi_ep = container_of(sep, struct kcxi_ep, ep);

	rc = test_verify_sep_ep_attr(&kcxi_ep->ep_attr.attr, ep_attr);
	if (rc) {
		LOG_ERR("SEP EP attributes not matching");
		exit_rc = rc;
		goto err_close_sep;
	}

	rc = test_verify_sep_tx_attr(&kcxi_ep->tx_attr, tx_attr);
	if (rc) {
		LOG_ERR("SEP TX attributes not matching");
		exit_rc = rc;
		goto err_close_sep;
	}

	rc = test_verify_sep_rx_attr(&kcxi_ep->rx_attr, rx_attr);
	if (rc) {
		LOG_ERR("SEP RX attributes not matching");
		exit_rc = rc;
	}

err_close_sep:
	kfi_close(&sep->fid);

	return exit_rc;
}

static int test_sep_create_null_hints(int id)
{
	int rc;
	int exit_rc = 0;
	struct kfi_info *hints;
	struct kfi_ep_attr ep_attr = kcxi_rdm_ep_attr;
	struct kfi_tx_attr tx_attr = kcxi_rdm_tx_attr;
	struct kfi_rx_attr rx_attr = kcxi_rdm_rx_attr;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("Test %d %s FAILED: Unable to allocate kfi_info", id,
			__func__);
		return -ENOMEM;
	}
	hints->caps = KCXI_EP_RDM_CAP;

	rc = test_init(hints);
	if (rc) {
		LOG_ERR("Test %d %s FAILED: Failed to initialize test", id,
			__func__);
		exit_rc = rc;
		goto err;
	}

	rc = test_create_verify_sep(NULL, &ep_attr, &tx_attr, &rx_attr);
	if (rc) {
		LOG_ERR("Test %d %s FAILED: SEP creation/verification errors",
			id, __func__);
		exit_rc = rc;
	}

	if (!exit_rc)
		LOG_INFO("Test %d %s PASSED", id, __func__);

	test_fini();

err:
	if (hints)
		kfi_freeinfo(hints);

	return exit_rc;
}

static int test_sep_create_valid_ep_attr(int id)
{
	int rc;
	int exit_rc = 0;
	struct kfi_info *hints;
	struct kfi_ep_attr ep_attr = kcxi_rdm_ep_attr;
	struct kfi_tx_attr tx_attr = kcxi_rdm_tx_attr;
	struct kfi_rx_attr rx_attr = kcxi_rdm_rx_attr;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("Test %d %s FAILED: Unable to allocate kfi_info", id,
			__func__);
		return -ENOMEM;
	}
	hints->caps = KCXI_EP_RDM_CAP;
	hints->ep_attr->tx_ctx_cnt = 5;
	hints->ep_attr->rx_ctx_cnt = 10;
	ep_attr.tx_ctx_cnt = 5;
	ep_attr.rx_ctx_cnt = 10;

	rc = test_init(hints);
	if (rc) {
		LOG_ERR("Test %d %s FAILED: Failed to initialize test", id,
			__func__);
		exit_rc = rc;
		goto err;
	}

	rc = test_create_verify_sep(info, &ep_attr, &tx_attr, &rx_attr);
	if (rc) {
		LOG_ERR("Test %d %s FAILED: SEP creation/verification errors",
			id, __func__);
		exit_rc = rc;
	}

	if (!exit_rc)
		LOG_INFO("Test %d %s PASSED", id, __func__);

	test_fini();

err:
	if (hints)
		kfi_freeinfo(hints);

	return exit_rc;
}

static int test_sep_create_bad_ep_attr(int id)
{
	int rc;
	int exit_rc = 0;
	struct kfi_info *hints;
	struct kfi_ep_attr ep_attr = kcxi_rdm_ep_attr;
	struct kfi_tx_attr tx_attr = kcxi_rdm_tx_attr;
	struct kfi_rx_attr rx_attr = kcxi_rdm_rx_attr;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("Test %d %s FAILED: Unable to allocate kfi_info", id,
			__func__);
		return -ENOMEM;
	}
	hints->caps = KCXI_EP_RDM_CAP;
	ep_attr.tx_ctx_cnt = 123456879;
	ep_attr.rx_ctx_cnt = 123456789;

	rc = test_init(hints);
	if (rc) {
		LOG_ERR("Test %d %s FAILED: Failed to initialize test", id,
			__func__);
		exit_rc = rc;
		goto err;
	}

	info->ep_attr->tx_ctx_cnt = 123456879;
	info->ep_attr->rx_ctx_cnt = 123456879;

	rc = test_create_verify_sep(info, &ep_attr, &tx_attr, &rx_attr);
	if (!rc) {
		LOG_ERR("Test %d %s FAILED: SEP should have error",
			id, __func__);
		exit_rc = -EINVAL;
	}

	if (!exit_rc)
		LOG_INFO("Test %d %s PASSED", id, __func__);

	test_fini();

err:
	if (hints)
		kfi_freeinfo(hints);

	return exit_rc;
}

static int test_sep_create_valid_tx_attr(int id)
{
	int rc;
	int exit_rc = 0;
	struct kfi_info *hints;
	struct kfi_ep_attr ep_attr = kcxi_rdm_ep_attr;
	struct kfi_tx_attr tx_attr = kcxi_rdm_tx_attr;
	struct kfi_rx_attr rx_attr = kcxi_rdm_rx_attr;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("Test %d %s FAILED: Unable to allocate kfi_info", id,
			__func__);
		return -ENOMEM;
	}
	hints->caps = KCXI_EP_RDM_CAP;
	hints->tx_attr->caps = (KFI_SEND | KFI_WRITE);
	hints->tx_attr->size = 2;
	hints->tx_attr->iov_limit = 1;
	hints->tx_attr->rma_iov_limit = 1;
	tx_attr.caps = (KFI_SEND | KFI_WRITE);
	tx_attr.size = 2;
	tx_attr.iov_limit = 1;
	tx_attr.rma_iov_limit = 1;

	rc = test_init(hints);
	if (rc) {
		LOG_ERR("Test %d %s FAILED: Failed to initialize test", id,
			__func__);
		exit_rc = rc;
		goto err;
	}

	rc = test_create_verify_sep(info, &ep_attr, &tx_attr, &rx_attr);
	if (rc) {
		LOG_ERR("Test %d %s FAILED: SEP creation/verification errors",
			id, __func__);
		exit_rc = rc;
	}

	if (!exit_rc)
		LOG_INFO("Test %d %s PASSED", id, __func__);

	test_fini();

err:
	if (hints)
		kfi_freeinfo(hints);

	return exit_rc;
}

static int test_sep_create_bad_tx_attr(int id)
{
	int rc;
	int exit_rc = 0;
	struct kfi_info *hints;
	struct kfi_ep_attr ep_attr = kcxi_rdm_ep_attr;
	struct kfi_tx_attr tx_attr = kcxi_rdm_tx_attr;
	struct kfi_rx_attr rx_attr = kcxi_rdm_rx_attr;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("Test %d %s FAILED: Unable to allocate kfi_info", id,
			__func__);
		return -ENOMEM;
	}
	hints->caps = KCXI_EP_RDM_CAP;

	rc = test_init(hints);
	if (rc) {
		LOG_ERR("Test %d %s FAILED: Failed to initialize test", id,
			__func__);
		exit_rc = rc;
		goto err;
	}

	info->tx_attr->caps = KFI_RECV;

	rc = test_create_verify_sep(info, &ep_attr, &tx_attr, &rx_attr);
	if (!rc) {
		LOG_ERR("Test %d %s FAILED: SEP should have error",
			id, __func__);
		exit_rc = -EINVAL;
	}

	if (!exit_rc)
		LOG_INFO("Test %d %s PASSED", id, __func__);

	test_fini();

err:
	if (hints)
		kfi_freeinfo(hints);

	return exit_rc;
}

static int test_sep_create_valid_rx_attr(int id)
{
	int rc;
	int exit_rc = 0;
	struct kfi_info *hints;
	struct kfi_ep_attr ep_attr = kcxi_rdm_ep_attr;
	struct kfi_tx_attr tx_attr = kcxi_rdm_tx_attr;
	struct kfi_rx_attr rx_attr = kcxi_rdm_rx_attr;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("Test %d %s FAILED: Unable to allocate kfi_info", id,
			__func__);
		return -ENOMEM;
	}
	hints->caps = KCXI_EP_RDM_CAP;
	hints->rx_attr->caps = (KFI_RECV | KFI_MULTI_RECV);
	hints->rx_attr->size = 2;
	hints->rx_attr->iov_limit = 1;
	rx_attr.caps = (KFI_RECV | KFI_MULTI_RECV);
	rx_attr.size = 2;
	rx_attr.iov_limit = 1;

	rc = test_init(hints);
	if (rc) {
		LOG_ERR("Test %d %s FAILED: Failed to initialize test", id,
			__func__);
		exit_rc = rc;
		goto err;
	}

	rc = test_create_verify_sep(info, &ep_attr, &tx_attr, &rx_attr);
	if (rc) {
		LOG_ERR("Test %d %s FAILED: SEP creation/verification errors",
			id, __func__);
		exit_rc = rc;
	}

	if (!exit_rc)
		LOG_INFO("Test %d %s PASSED", id, __func__);

	test_fini();

err:
	if (hints)
		kfi_freeinfo(hints);

	return exit_rc;
}

static int test_sep_create_bad_rx_attr(int id)
{
	int rc;
	int exit_rc = 0;
	struct kfi_info *hints;
	struct kfi_ep_attr ep_attr = kcxi_rdm_ep_attr;
	struct kfi_tx_attr tx_attr = kcxi_rdm_tx_attr;
	struct kfi_rx_attr rx_attr = kcxi_rdm_rx_attr;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("Test %d %s FAILED: Unable to allocate kfi_info", id,
			__func__);
		return -ENOMEM;
	}
	hints->caps = KCXI_EP_RDM_CAP;

	rc = test_init(hints);
	if (rc) {
		LOG_ERR("Test %d %s FAILED: Failed to initialize test", id,
			__func__);
		exit_rc = rc;
		goto err;
	}

	info->rx_attr->caps = KFI_SEND;

	rc = test_create_verify_sep(info, &ep_attr, &tx_attr, &rx_attr);
	if (!rc) {
		LOG_ERR("Test %d %s FAILED: SEP should have error",
			id, __func__);
		exit_rc = -EINVAL;
	}

	if (!exit_rc)
		LOG_INFO("Test %d %s PASSED", id, __func__);

	test_fini();

err:
	if (hints)
		kfi_freeinfo(hints);

	return exit_rc;
}

static int __init test_module_init(void)
{
	int rc = 0;
	int exit_rc = 0;
	int test_id = 1;

	rc = test_sep_create_null_hints(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_sep_create_valid_ep_attr(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_sep_create_bad_ep_attr(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_sep_create_valid_tx_attr(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_sep_create_bad_tx_attr(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_sep_create_valid_rx_attr(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_sep_create_bad_rx_attr(test_id);
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
