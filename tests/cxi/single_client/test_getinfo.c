/*
 * Kfabric getinfo tests.
 * Copyright 2018-2025 Hewlett Packard Enterprise Development LP
 *
 * SPDX-License-Identifier: GPL-2.0
 */
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <kfabric.h>
#include <kfi_log.h>
#include <linux/slab.h>

#include "../../../prov/cxi/kcxi_prov.h"

#ifdef MODULE_NAME
#undef MODULE_NAME
#endif
#define MODULE_NAME "test_getinfo"

static char *valid_node = "0";
static char *valid_service = "5";
static char *valid_ipv4 = "192.168.1.1";
static char *valid_offset_node = "cxi0";

MODULE_AUTHOR("Ian Ziemba");
MODULE_DESCRIPTION("kfabric CXI kfi_getinfo() tests");
MODULE_LICENSE("GPL v2");

static void display_info(struct kfi_info *info)
{
	LOG_INFO("Fabric Provider: %s", info->fabric_attr->prov_name);
	LOG_INFO("Fabric Name: %s", info->fabric_attr->name);
	LOG_INFO("Domain Name: %s", info->domain_attr->name);
}

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

static int kfi_getinfo_failure(uint32_t version, const char *node,
			       const char *service, uint64_t flags,
			       struct kfi_info *hints, struct kfi_info **info)
{
	int rc;

	rc = kfi_getinfo(version, node, service, flags, hints, info);
	if (!rc) {
		LOG_ERR("kfi_getinfo() did not fail");
		return -EINVAL;
	}

	if (!info) {
		LOG_ERR("kfi_getinfo() did not return NULL");
		return -EINVAL;
	}

	return 0;
}

/* The following tests verify kfi_getinfo() enforces bounds */
static int test_bad_rx_iov_limit(int id)
{
	int rc = 0;
	struct kfi_info *hints = NULL;
	struct kfi_info *info = NULL;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		rc = -ENOMEM;
		goto out;
	}
	hints->rx_attr->iov_limit = 1234567;

	rc = kfi_getinfo_failure(0, valid_node, valid_service, KFI_SOURCE,
				 hints, &info);
	if (rc)
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	else
		LOG_INFO("TEST %d PASSED: %s", id, __func__);

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;
}

static int test_bad_rx_size(int id)
{
	int rc = 0;
	struct kfi_info *hints = NULL;
	struct kfi_info *info = NULL;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		rc = -ENOMEM;
		goto out;
	}
	hints->rx_attr->size = 1234567;

	rc = kfi_getinfo_failure(0, valid_node, valid_service, KFI_SOURCE,
				 hints, &info);
	if (rc)
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	else
		LOG_INFO("TEST %d PASSED: %s", id, __func__);

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;
}

static int test_bad_rx_total_buffer_recv(int id)
{
	int rc = 0;
	struct kfi_info *hints = NULL;
	struct kfi_info *info = NULL;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		rc = -ENOMEM;
		goto out;
	}
	hints->rx_attr->total_buffered_recv = 12345678999;

	rc = kfi_getinfo_failure(0, valid_node, valid_service, KFI_SOURCE,
				 hints, &info);
	if (rc)
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	else
		LOG_INFO("TEST %d PASSED: %s", id, __func__);

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;
}

static int test_bad_rx_comp_order(int id)
{
	int rc = 0;
	struct kfi_info *hints = NULL;
	struct kfi_info *info = NULL;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		rc = -ENOMEM;
		goto out;
	}
	hints->rx_attr->comp_order = KFI_ORDER_SAS;

	rc = kfi_getinfo_failure(0, valid_node, valid_service, KFI_SOURCE,
				 hints, &info);
	if (rc)
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	else
		LOG_INFO("TEST %d PASSED: %s", id, __func__);

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;
}

static int test_bad_rx_ops_mode(int id)
{
	int rc = 0;
	struct kfi_info *hints = NULL;
	struct kfi_info *info = NULL;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		rc = -ENOMEM;
		goto out;
	}
	hints->rx_attr->op_flags = KFI_INJECT;

	rc = kfi_getinfo_failure(0, valid_node, valid_service, KFI_SOURCE,
				 hints, &info);
	if (rc)
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	else
		LOG_INFO("TEST %d PASSED: %s", id, __func__);

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;
}

static int test_bad_rx_mode(int id)
{
	int rc = 0;
	struct kfi_info *hints = NULL;
	struct kfi_info *info = NULL;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		rc = -ENOMEM;
		goto out;
	}
	hints->rx_attr->mode = KFI_MSG_PREFIX;

	rc = kfi_getinfo_failure(0, valid_node, valid_service, KFI_SOURCE,
				 hints, &info);
	if (rc)
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	else
		LOG_INFO("TEST %d PASSED: %s", id, __func__);

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;
}

static int test_bad_rx_caps(int id)
{
	int rc = 0;
	struct kfi_info *hints = NULL;
	struct kfi_info *info = NULL;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		rc = -ENOMEM;
		goto out;
	}
	hints->rx_attr->caps = KFI_SEND;

	rc = kfi_getinfo_failure(0, valid_node, valid_service, KFI_SOURCE,
				 hints, &info);
	if (rc)
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	else
		LOG_INFO("TEST %d PASSED: %s", id, __func__);

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;
}

static int test_bad_tx_rma_iov_limit(int id)
{
	int rc = 0;
	struct kfi_info *hints = NULL;
	struct kfi_info *info = NULL;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		rc = -ENOMEM;
		goto out;
	}
	hints->tx_attr->rma_iov_limit = 1234567;

	rc = kfi_getinfo_failure(0, valid_node, valid_service, KFI_SOURCE,
				 hints, &info);
	if (rc)
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	else
		LOG_INFO("TEST %d PASSED: %s", id, __func__);

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;
}

static int test_bad_tx_iov_limit(int id)
{
	int rc = 0;
	struct kfi_info *hints = NULL;
	struct kfi_info *info = NULL;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		rc = -ENOMEM;
		goto out;
	}
	hints->tx_attr->iov_limit = 1234567;

	rc = kfi_getinfo_failure(0, valid_node, valid_service, KFI_SOURCE,
				 hints, &info);
	if (rc)
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	else
		LOG_INFO("TEST %d PASSED: %s", id, __func__);

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;
}

static int test_bad_tx_size(int id)
{
	int rc = 0;
	struct kfi_info *hints = NULL;
	struct kfi_info *info = NULL;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		rc = -ENOMEM;
		goto out;
	}
	hints->tx_attr->size = 1234567;

	rc = kfi_getinfo_failure(0, valid_node, valid_service, KFI_SOURCE,
				 hints, &info);
	if (rc)
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	else
		LOG_INFO("TEST %d PASSED: %s", id, __func__);

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;
}

static int test_bad_tx_inject_size(int id)
{
	int rc = 0;
	struct kfi_info *hints = NULL;
	struct kfi_info *info = NULL;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		rc = -ENOMEM;
		goto out;
	}
	hints->tx_attr->inject_size = 1234567;

	rc = kfi_getinfo_failure(0, valid_node, valid_service, KFI_SOURCE,
				 hints, &info);
	if (rc)
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	else
		LOG_INFO("TEST %d PASSED: %s", id, __func__);

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;
}

static int test_bad_tx_comp_order(int id)
{
	int rc = 0;
	struct kfi_info *hints = NULL;
	struct kfi_info *info = NULL;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		rc = -ENOMEM;
		goto out;
	}
	hints->tx_attr->comp_order = KFI_ORDER_SAS;

	rc = kfi_getinfo_failure(0, valid_node, valid_service, KFI_SOURCE,
				 hints, &info);
	if (rc)
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	else
		LOG_INFO("TEST %d PASSED: %s", id, __func__);

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;
}

static int test_bad_tx_ops_mode(int id)
{
	int rc = 0;
	struct kfi_info *hints = NULL;
	struct kfi_info *info = NULL;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		rc = -ENOMEM;
		goto out;
	}
	hints->tx_attr->op_flags = KFI_INJECT;

	rc = kfi_getinfo_failure(0, valid_node, valid_service, KFI_SOURCE,
				 hints, &info);
	if (rc)
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	else
		LOG_INFO("TEST %d PASSED: %s", id, __func__);

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;
}

static int test_bad_tx_mode(int id)
{
	int rc = 0;
	struct kfi_info *hints = NULL;
	struct kfi_info *info = NULL;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		rc = -ENOMEM;
		goto out;
	}
	hints->tx_attr->mode = KFI_MSG_PREFIX;

	rc = kfi_getinfo_failure(0, valid_node, valid_service, KFI_SOURCE,
				 hints, &info);
	if (rc)
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	else
		LOG_INFO("TEST %d PASSED: %s", id, __func__);

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;
}

static int test_bad_tx_caps(int id)
{
	int rc = 0;
	struct kfi_info *hints = NULL;
	struct kfi_info *info = NULL;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		rc = -ENOMEM;
		goto out;
	}
	hints->tx_attr->caps = KFI_RECV;

	rc = kfi_getinfo_failure(0, valid_node, valid_service, KFI_SOURCE,
				 hints, &info);
	if (rc)
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	else
		LOG_INFO("TEST %d PASSED: %s", id, __func__);

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;
}

static int test_bad_ep_missing_auth_key_size(int id)
{
	int rc = 0;
	struct kfi_info *hints = NULL;
	struct kfi_info *info = NULL;
	uint32_t auth_key = 255;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		rc = -ENOMEM;
		goto out;
	}

	hints->ep_attr->auth_key = kzalloc(sizeof(auth_key), GFP_KERNEL);
	if (!hints->ep_attr->auth_key) {
		rc = -ENOMEM;
		LOG_ERR("TEST %d FAILED: rc=%d", id, rc);
		goto out;
	}
	*hints->ep_attr->auth_key = auth_key;

	rc = kfi_getinfo_failure(0, valid_node, valid_service, KFI_SOURCE,
				 hints, &info);
	if (rc)
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	else
		LOG_INFO("TEST %d PASSED: %s", id, __func__);

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;
}

static int test_bad_ep_auth_key_size(int id)
{
	int rc = 0;
	struct kfi_info *hints = NULL;
	struct kfi_info *info = NULL;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		rc = -ENOMEM;
		goto out;
	}
	hints->ep_attr->auth_key_size = 1234567;

	rc = kfi_getinfo_failure(0, valid_node, valid_service, KFI_SOURCE,
				 hints, &info);
	if (rc)
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	else
		LOG_INFO("TEST %d PASSED: %s", id, __func__);

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;
}

static int test_valid_ep_max_rx_cnt(int id)
{
	int rc = 0;
	struct kfi_info *hints = NULL;
	struct kfi_info *info = NULL;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		rc = -ENOMEM;
		goto out;
	}
	hints->ep_attr->rx_ctx_cnt = KCXI_EP_RX_CTX_CNT / 2;

	rc = kfi_getinfo_success(0, valid_node, valid_service, KFI_SOURCE,
				 hints, &info);
	if (rc) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	} else if (hints->ep_attr->rx_ctx_cnt != info->ep_attr->rx_ctx_cnt) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	} else {
		LOG_INFO("TEST %d PASSED: %s", id, __func__);
	}

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;
}

static int test_bad_ep_max_rx_cnt(int id)
{
	int rc = 0;
	struct kfi_info *hints = NULL;
	struct kfi_info *info = NULL;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		rc = -ENOMEM;
		goto out;
	}
	hints->ep_attr->rx_ctx_cnt = KCXI_EP_RX_CTX_CNT + 1;

	rc = kfi_getinfo_failure(0, valid_node, valid_service, KFI_SOURCE,
				 hints, &info);
	if (rc)
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	else
		LOG_INFO("TEST %d PASSED: %s", id, __func__);

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;
}

static int test_valid_ep_max_tx_cnt(int id)
{
	int rc = 0;
	struct kfi_info *hints = NULL;
	struct kfi_info *info = NULL;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		rc = -ENOMEM;
		goto out;
	}
	hints->ep_attr->tx_ctx_cnt = KCXI_EP_TX_CTX_CNT / 2;

	rc = kfi_getinfo_success(0, valid_node, valid_service, KFI_SOURCE,
				 hints, &info);
	if (rc) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	} else if (hints->ep_attr->tx_ctx_cnt != info->ep_attr->tx_ctx_cnt) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	} else {
		LOG_INFO("TEST %d PASSED: %s", id, __func__);
	}

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;
}

static int test_bad_ep_max_tx_cnt(int id)
{
	int rc = 0;
	struct kfi_info *hints = NULL;
	struct kfi_info *info = NULL;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		rc = -ENOMEM;
		goto out;
	}
	hints->ep_attr->tx_ctx_cnt = KCXI_EP_TX_CTX_CNT + 1;

	rc = kfi_getinfo_failure(0, valid_node, valid_service, KFI_SOURCE,
				 hints, &info);
	if (rc)
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	else
		LOG_INFO("TEST %d PASSED: %s", id, __func__);

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;
}

static int test_bad_ep_mem_format(int id)
{
	int rc = 0;
	struct kfi_info *hints = NULL;
	struct kfi_info *info = NULL;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		rc = -ENOMEM;
		goto out;
	}
	hints->ep_attr->mem_tag_format = 0xFFFFFFFFFFFFFFFFULL;

	rc = kfi_getinfo_failure(0, valid_node, valid_service, KFI_SOURCE,
				 hints, &info);
	if (rc)
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	else
		LOG_INFO("TEST %d PASSED: %s", id, __func__);

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;
}

static int test_bad_ep_max_order_waw_size(int id)
{
	int rc = 0;
	struct kfi_info *hints = NULL;
	struct kfi_info *info = NULL;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		rc = -ENOMEM;
		goto out;
	}
	hints->ep_attr->max_order_waw_size = (1 << 31);

	rc = kfi_getinfo_failure(0, valid_node, valid_service, KFI_SOURCE,
				 hints, &info);
	if (rc)
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	else
		LOG_INFO("TEST %d PASSED: %s", id, __func__);

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;
}

static int test_bad_ep_max_order_war_size(int id)
{
	int rc = 0;
	struct kfi_info *hints = NULL;
	struct kfi_info *info = NULL;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		rc = -ENOMEM;
		goto out;
	}
	hints->ep_attr->max_order_war_size = (1 << 31);

	rc = kfi_getinfo_failure(0, valid_node, valid_service, KFI_SOURCE,
				 hints, &info);
	if (rc)
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	else
		LOG_INFO("TEST %d PASSED: %s", id, __func__);

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;
}

static int test_bad_ep_max_order_raw_size(int id)
{
	int rc = 0;
	struct kfi_info *hints = NULL;
	struct kfi_info *info = NULL;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		rc = -ENOMEM;
		goto out;
	}
	hints->ep_attr->max_order_raw_size = (1 << 31);

	rc = kfi_getinfo_failure(0, valid_node, valid_service, KFI_SOURCE,
				 hints, &info);
	if (rc)
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	else
		LOG_INFO("TEST %d PASSED: %s", id, __func__);

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;
}

static int test_bad_ep_msg_prefex_size(int id)
{
	int rc = 0;
	struct kfi_info *hints = NULL;
	struct kfi_info *info = NULL;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		rc = -ENOMEM;
		goto out;
	}
	hints->ep_attr->msg_prefix_size = (1 << 31);

	rc = kfi_getinfo_failure(0, valid_node, valid_service, KFI_SOURCE,
				 hints, &info);
	if (rc)
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	else
		LOG_INFO("TEST %d PASSED: %s", id, __func__);

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;
}

static int test_bad_ep_protocol_version(int id)
{
	int rc = 0;
	struct kfi_info *hints = NULL;
	struct kfi_info *info = NULL;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		rc = -ENOMEM;
		goto out;
	}
	hints->ep_attr->protocol_version = 123;

	rc = kfi_getinfo_failure(0, valid_node, valid_service, KFI_SOURCE,
				 hints, &info);
	if (rc)
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	else
		LOG_INFO("TEST %d PASSED: %s", id, __func__);

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;
}

static int test_bad_ep_protocol(int id)
{
	int rc = 0;
	struct kfi_info *hints = NULL;
	struct kfi_info *info = NULL;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		rc = -ENOMEM;
		goto out;
	}
	hints->ep_attr->protocol = KFI_PROTO_GNI;

	rc = kfi_getinfo_failure(0, valid_node, valid_service, KFI_SOURCE,
				 hints, &info);
	if (rc)
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	else
		LOG_INFO("TEST %d PASSED: %s", id, __func__);

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;
}

static int test_bad_ep_type(int id)
{
	int rc = 0;
	struct kfi_info *hints = NULL;
	struct kfi_info *info = NULL;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		rc = -ENOMEM;
		goto out;
	}
	hints->ep_attr->type = KFI_EP_SOCK_DGRAM;

	rc = kfi_getinfo_failure(0, valid_node, valid_service, KFI_SOURCE,
				 hints, &info);
	if (rc)
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	else
		LOG_INFO("TEST %d PASSED: %s", id, __func__);

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;
}

static int test_bad_domain_missing_auth_key_size(int id)
{
	int rc = 0;
	struct kfi_info *hints = NULL;
	struct kfi_info *info = NULL;
	uint32_t auth_key = 255;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		rc = -ENOMEM;
		goto out;
	}

	hints->ep_attr->auth_key = kzalloc(sizeof(auth_key), GFP_KERNEL);
	if (!hints->ep_attr->auth_key) {
		rc = -ENOMEM;
		LOG_ERR("TEST %d FAILED: rc=%d", id, rc);
		goto out;
	}
	*hints->ep_attr->auth_key = auth_key;

	rc = kfi_getinfo_failure(0, valid_node, valid_service, KFI_SOURCE,
				 hints, &info);
	if (rc)
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	else
		LOG_INFO("TEST %d PASSED: %s", id, __func__);

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;
}

static int test_bad_domain_auth_key_size(int id)
{
	int rc = 0;
	struct kfi_info *hints = NULL;
	struct kfi_info *info = NULL;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		rc = -ENOMEM;
		goto out;
	}
	hints->domain_attr->auth_key_size = 1234567;

	rc = kfi_getinfo_failure(0, valid_node, valid_service, KFI_SOURCE,
				 hints, &info);
	if (rc)
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	else
		LOG_INFO("TEST %d PASSED: %s", id, __func__);

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;
}

static int test_bad_domain_max_mr_count(int id)
{
	int rc = 0;
	struct kfi_info *hints = NULL;
	struct kfi_info *info = NULL;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		rc = -ENOMEM;
		goto out;
	}
	hints->domain_attr->mr_cnt = 1234567;

	rc = kfi_getinfo_failure(0, valid_node, valid_service, KFI_SOURCE,
				 hints, &info);
	if (rc)
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	else
		LOG_INFO("TEST %d PASSED: %s", id, __func__);

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;
}

static int test_bad_domain_max_err_data(int id)
{
	int rc = 0;
	struct kfi_info *hints = NULL;
	struct kfi_info *info = NULL;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		rc = -ENOMEM;
		goto out;
	}
	hints->domain_attr->max_err_data = 1234567;

	rc = kfi_getinfo_failure(0, valid_node, valid_service, KFI_SOURCE,
				 hints, &info);
	if (rc)
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	else
		LOG_INFO("TEST %d PASSED: %s", id, __func__);

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;
}

static int test_bad_domain_mr_iov_limit(int id)
{
	int rc = 0;
	struct kfi_info *hints = NULL;
	struct kfi_info *info = NULL;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		rc = -ENOMEM;
		goto out;
	}
	hints->domain_attr->mr_iov_limit = 1234567;

	rc = kfi_getinfo_failure(0, valid_node, valid_service, KFI_SOURCE,
				 hints, &info);
	if (rc)
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	else
		LOG_INFO("TEST %d PASSED: %s", id, __func__);

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;
}

static int test_bad_domain_cntr_count(int id)
{
	int rc = 0;
	struct kfi_info *hints = NULL;
	struct kfi_info *info = NULL;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		rc = -ENOMEM;
		goto out;
	}
	hints->domain_attr->cntr_cnt = 1234567;

	rc = kfi_getinfo_failure(0, valid_node, valid_service, KFI_SOURCE,
				 hints, &info);
	if (rc)
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	else
		LOG_INFO("TEST %d PASSED: %s", id, __func__);

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;
}

static int test_bad_domain_max_ep_srx_ctx_count(int id)
{
	int rc = 0;
	struct kfi_info *hints = NULL;
	struct kfi_info *info = NULL;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		rc = -ENOMEM;
		goto out;
	}
	hints->domain_attr->max_ep_srx_ctx = 1234567;

	rc = kfi_getinfo_failure(0, valid_node, valid_service, KFI_SOURCE,
				 hints, &info);
	if (rc)
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	else
		LOG_INFO("TEST %d PASSED: %s", id, __func__);

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;
}

static int test_bad_domain_max_ep_stx_ctx_count(int id)
{
	int rc = 0;
	struct kfi_info *hints = NULL;
	struct kfi_info *info = NULL;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		rc = -ENOMEM;
		goto out;
	}
	hints->domain_attr->max_ep_stx_ctx = 1234567;

	rc = kfi_getinfo_failure(0, valid_node, valid_service, KFI_SOURCE,
				 hints, &info);
	if (rc)
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	else
		LOG_INFO("TEST %d PASSED: %s", id, __func__);

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;
}

static int test_valid_domain_max_ep_rx_ctx_count(int id)
{
	int rc = 0;
	struct kfi_info *hints = NULL;
	struct kfi_info *info = NULL;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		rc = -ENOMEM;
		goto out;
	}
	hints->domain_attr->max_ep_rx_ctx = KCXI_DOM_MAX_EP_RX_CTX / 2;

	rc = kfi_getinfo_success(0, valid_node, valid_service, KFI_SOURCE,
				 hints, &info);
	if (rc) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	} else if (hints->domain_attr->max_ep_rx_ctx != info->domain_attr->max_ep_rx_ctx) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	} else {
		LOG_INFO("TEST %d PASSED: %s", id, __func__);
	}

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;
}

static int test_bad_domain_max_ep_rx_ctx_count(int id)
{
	int rc = 0;
	struct kfi_info *hints = NULL;
	struct kfi_info *info = NULL;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		rc = -ENOMEM;
		goto out;
	}
	hints->domain_attr->max_ep_rx_ctx = KCXI_DOM_MAX_EP_RX_CTX + 1;

	rc = kfi_getinfo_failure(0, valid_node, valid_service, KFI_SOURCE,
				 hints, &info);
	if (rc)
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	else
		LOG_INFO("TEST %d PASSED: %s", id, __func__);

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;
}

static int test_valid_domain_max_ep_tx_ctx_count(int id)
{
	int rc = 0;
	struct kfi_info *hints = NULL;
	struct kfi_info *info = NULL;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		rc = -ENOMEM;
		goto out;
	}
	hints->domain_attr->max_ep_tx_ctx = KCXI_DOM_MAX_EP_TX_CTX / 2;

	rc = kfi_getinfo_success(0, valid_node, valid_service, KFI_SOURCE,
				 hints, &info);
	if (rc) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	} else if (hints->domain_attr->max_ep_tx_ctx != info->domain_attr->max_ep_tx_ctx) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	} else {
		LOG_INFO("TEST %d PASSED: %s", id, __func__);
	}

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;
}

static int test_bad_domain_max_ep_tx_ctx_count(int id)
{
	int rc = 0;
	struct kfi_info *hints = NULL;
	struct kfi_info *info = NULL;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		rc = -ENOMEM;
		goto out;
	}
	hints->domain_attr->max_ep_tx_ctx = KCXI_DOM_MAX_EP_TX_CTX + 1;

	rc = kfi_getinfo_failure(0, valid_node, valid_service, KFI_SOURCE,
				 hints, &info);
	if (rc)
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	else
		LOG_INFO("TEST %d PASSED: %s", id, __func__);

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;
}

static int test_valid_domain_rx_count(int id)
{
	int rc = 0;
	struct kfi_info *hints = NULL;
	struct kfi_info *info = NULL;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		rc = -ENOMEM;
		goto out;
	}
	hints->domain_attr->rx_ctx_cnt = KCXI_DOM_RX_CTX_MAX / 2;

	rc = kfi_getinfo_success(0, valid_node, valid_service, KFI_SOURCE,
				 hints, &info);
	if (rc) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	} else if (hints->domain_attr->rx_ctx_cnt != info->domain_attr->rx_ctx_cnt) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	} else {
		LOG_INFO("TEST %d PASSED: %s", id, __func__);
	}

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;
}

static int test_bad_domain_rx_count(int id)
{
	int rc = 0;
	struct kfi_info *hints = NULL;
	struct kfi_info *info = NULL;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		rc = -ENOMEM;
		goto out;
	}
	hints->domain_attr->rx_ctx_cnt = KCXI_DOM_RX_CTX_MAX + 1;

	rc = kfi_getinfo_failure(0, valid_node, valid_service, KFI_SOURCE,
				 hints, &info);
	if (rc)
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	else
		LOG_INFO("TEST %d PASSED: %s", id, __func__);

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;
}

static int test_valid_domain_tx_count(int id)
{
	int rc = 0;
	struct kfi_info *hints = NULL;
	struct kfi_info *info = NULL;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		rc = -ENOMEM;
		goto out;
	}
	hints->domain_attr->tx_ctx_cnt = KCXI_DOM_TX_CTX_MAX / 2;

	rc = kfi_getinfo_success(0, valid_node, valid_service, KFI_SOURCE,
				 hints, &info);
	if (rc) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	} else if (hints->domain_attr->tx_ctx_cnt != info->domain_attr->tx_ctx_cnt) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	} else {
		LOG_INFO("TEST %d PASSED: %s", id, __func__);
	}

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;
}

static int test_bad_domain_tx_count(int id)
{
	int rc = 0;
	struct kfi_info *hints = NULL;
	struct kfi_info *info = NULL;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		rc = -ENOMEM;
		goto out;
	}
	hints->domain_attr->tx_ctx_cnt = KCXI_DOM_TX_CTX_MAX + 1;

	rc = kfi_getinfo_failure(0, valid_node, valid_service, KFI_SOURCE,
				 hints, &info);
	if (rc)
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	else
		LOG_INFO("TEST %d PASSED: %s", id, __func__);

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;
}

static int test_valid_domain_ep_count(int id)
{
	int rc = 0;
	struct kfi_info *hints = NULL;
	struct kfi_info *info = NULL;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		rc = -ENOMEM;
		goto out;
	}
	hints->domain_attr->ep_cnt = KCXI_DOM_EP_CNT / 2;

	rc = kfi_getinfo_success(0, valid_node, valid_service, KFI_SOURCE,
				 hints, &info);
	if (rc) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	} else if (hints->domain_attr->ep_cnt != info->domain_attr->ep_cnt) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	} else {
		LOG_INFO("TEST %d PASSED: %s", id, __func__);
	}

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;
}

static int test_bad_domain_ep_count(int id)
{
	int rc = 0;
	struct kfi_info *hints = NULL;
	struct kfi_info *info = NULL;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		rc = -ENOMEM;
		goto out;
	}
	hints->domain_attr->ep_cnt = KCXI_DOM_EP_CNT + 1;

	rc = kfi_getinfo_failure(0, valid_node, valid_service, KFI_SOURCE,
				 hints, &info);
	if (rc)
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	else
		LOG_INFO("TEST %d PASSED: %s", id, __func__);

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;
}

static int test_valid_domain_cq_count(int id)
{
	int rc = 0;
	struct kfi_info *hints = NULL;
	struct kfi_info *info = NULL;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		rc = -ENOMEM;
		goto out;
	}
	hints->domain_attr->cq_cnt = KCXI_DOM_CQ_CNT / 2;

	rc = kfi_getinfo_success(0, valid_node, valid_service, KFI_SOURCE,
				 hints, &info);
	if (rc) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	} else if (hints->domain_attr->cq_cnt != info->domain_attr->cq_cnt) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	} else {
		LOG_INFO("TEST %d PASSED: %s", id, __func__);
	}

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;
}

static int test_bad_domain_cq_count(int id)
{
	int rc = 0;
	struct kfi_info *hints = NULL;
	struct kfi_info *info = NULL;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		rc = -ENOMEM;
		goto out;
	}
	hints->domain_attr->cq_cnt = KCXI_DOM_CQ_CNT + 1;

	rc = kfi_getinfo_failure(0, valid_node, valid_service, KFI_SOURCE,
				 hints, &info);
	if (rc)
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	else
		LOG_INFO("TEST %d PASSED: %s", id, __func__);

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;
}

static int test_bad_domain_cq_data_size(int id)
{
	int rc = 0;
	struct kfi_info *hints = NULL;
	struct kfi_info *info = NULL;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		rc = -ENOMEM;
		goto out;
	}
	hints->domain_attr->cq_data_size = 1234567;

	rc = kfi_getinfo_failure(0, valid_node, valid_service, KFI_SOURCE,
				 hints, &info);

	if (rc)
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	else
		LOG_INFO("TEST %d PASSED: %s", id, __func__);

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;
}

static int test_bad_domain_mr_key_size(int id)
{
	int rc = 0;
	struct kfi_info *hints = NULL;
	struct kfi_info *info = NULL;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		rc = -ENOMEM;
		goto out;
	}
	hints->domain_attr->mr_key_size = 9;

	rc = kfi_getinfo_failure(0, valid_node, valid_service, KFI_SOURCE,
				 hints, &info);

	if (rc)
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	else
		LOG_INFO("TEST %d PASSED: %s", id, __func__);

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;
}

static int test_bad_domain_mr_mode(int id)
{
	int rc = 0;
	struct kfi_info *hints = NULL;
	struct kfi_info *info = NULL;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		rc = -ENOMEM;
		goto out;
	}
	hints->domain_attr->mr_mode = (KFI_MR_RAW | KFI_MR_RMA_EVENT);

	rc = kfi_getinfo_failure(0, valid_node, valid_service, KFI_SOURCE,
				 hints, &info);

	if (rc)
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	else
		LOG_INFO("TEST %d PASSED: %s", id, __func__);

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;
}

static int test_bad_domain_av_type(int id)
{
	int rc = 0;
	struct kfi_info *hints = NULL;
	struct kfi_info *info = NULL;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		rc = -ENOMEM;
		goto out;
	}
	hints->domain_attr->av_type = KFI_AV_TABLE;

	rc = kfi_getinfo_failure(0, valid_node, valid_service, KFI_SOURCE,
				 hints, &info);

	if (rc)
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	else
		LOG_INFO("TEST %d PASSED: %s", id, __func__);

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;
}

static int test_bad_domain_resource_mgmt(int id)
{
	int rc = 0;
	struct kfi_info *hints = NULL;
	struct kfi_info *info = NULL;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		rc = -ENOMEM;
		goto out;
	}
	hints->domain_attr->resource_mgmt = KFI_RM_ENABLED;

	rc = kfi_getinfo_failure(0, valid_node, valid_service, KFI_SOURCE,
				 hints, &info);

	if (rc)
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	else
		LOG_INFO("TEST %d PASSED: %s", id, __func__);

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;
}

static int test_bad_domain_control_progress(int id)
{
	int rc = 0;
	struct kfi_info *hints = NULL;
	struct kfi_info *info = NULL;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		rc = -ENOMEM;
		goto out;
	}
	hints->domain_attr->control_progress = KFI_PROGRESS_MANUAL;

	rc = kfi_getinfo_failure(0, valid_node, valid_service, KFI_SOURCE,
				 hints, &info);

	if (rc)
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	else
		LOG_INFO("TEST %d PASSED: %s", id, __func__);

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;
}


static int test_bad_domain_threading_mode(int id)
{
	int rc = 0;
	struct kfi_info *hints = NULL;
	struct kfi_info *info = NULL;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		rc = -ENOMEM;
		goto out;
	}
	hints->domain_attr->threading = KFI_THREAD_COMPLETION;

	rc = kfi_getinfo_failure(0, valid_node, valid_service, KFI_SOURCE,
				 hints, &info);

	if (rc)
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	else
		LOG_INFO("TEST %d PASSED: %s", id, __func__);

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;
}

static int test_bad_domain_ptr(int id)
{
	int rc = 0;
	struct kfi_info *hints = NULL;
	struct kfi_info *info = NULL;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		rc = -ENOMEM;
		goto out;
	}

	/* Grab a random ptr */
	hints->domain_attr->domain = (struct kfid_domain *)&rc;

	rc = kfi_getinfo_failure(0, valid_node, valid_service, KFI_SOURCE,
				 hints, &info);

	if (rc)
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	else
		LOG_INFO("TEST %d PASSED: %s", id, __func__);

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;
}

static int test_bad_domain_name(int id)
{
	int rc = 0;
	struct kfi_info *hints = NULL;
	struct kfi_info *info = NULL;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		rc = -ENOMEM;
		goto out;
	}
	hints->domain_attr->name = kstrdup("blah", GFP_KERNEL);

	rc = kfi_getinfo_failure(0, valid_node, valid_service, KFI_SOURCE,
				 hints, &info);

	if (rc)
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	else
		LOG_INFO("TEST %d PASSED: %s", id, __func__);

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;
}

static int test_bad_fabric_prov(int id)
{
	int rc = 0;
	struct kfi_info *hints = NULL;
	struct kfi_info *info = NULL;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		rc = -ENOMEM;
		goto out;
	}
	hints->fabric_attr->prov_name = kstrdup("carrier_pigeons", GFP_KERNEL);

	rc = kfi_getinfo_failure(0, valid_node, valid_service, KFI_SOURCE,
				 hints, &info);

	if (rc)
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	else
		LOG_INFO("TEST %d PASSED: %s", id, __func__);

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;
}

/* These are the caps kfilnd will most likely need */
static int test_kfilnd_required_caps(int id)
{
	int rc = 0;
	struct kfi_info *info = NULL;
	struct kfi_info *hints = NULL;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		rc = -ENOMEM;
		goto out;
	}
	hints->caps = (KFI_MSG | KFI_RMA | KFI_SEND | KFI_RECV | KFI_READ |
		       KFI_WRITE | KFI_REMOTE_READ | KFI_REMOTE_WRITE |
		       KFI_MULTI_RECV | KFI_RMA_EVENT | KFI_REMOTE_COMM);

	rc = kfi_getinfo_success(0, valid_node, valid_service, KFI_SOURCE,
				 hints, &info);
	if (rc)
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	else
		LOG_INFO("TEST %d PASSED: %s", id, __func__);

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;
}

/*
 * Ask for specific capabilities which should succeed. In addition, the
 * domain, tx, and rx attributes should be set to a subset of values of the
 * specific capabilities.
 */
static int test_specific_caps(int id)
{
	int rc = 0;
	struct kfi_info *info = NULL;
	struct kfi_info *hints = NULL;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		rc = -ENOMEM;
		goto out;
	}
	hints->caps = (KFI_RMA | KFI_MSG | KFI_MULTI_RECV);

	rc = kfi_getinfo_success(0, valid_node, valid_service, KFI_SOURCE,
				 hints, &info);
	if (rc)
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	else
		LOG_INFO("TEST %d PASSED: %s", id, __func__);

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;
}

/*
 * This test should not return a valid info structure NIC addr 123 is not
 * defined.
 */
static int test_bad_node(int id)
{
	int rc = 0;
	struct kfi_info *info = NULL;

	rc = kfi_getinfo_failure(0, "123", valid_service, KFI_SOURCE, NULL,
				 &info);
	if (rc)
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	else
		LOG_INFO("TEST %d PASSED: %s", id, __func__);

	if (info)
		kfi_freeinfo(info);

	return rc;
}

/*
 * This test should returned a value info structure by only defining a node
 * and service with KFI_SOURCE. This test assumes that there is a NIC address
 * that is each to zero as defined in the node argument.
 */
static int test_basic_getinfo1(int id)
{
	int rc = 0;
	struct kfi_info *info = NULL;

	rc = kfi_getinfo_success(0, valid_node, "123", KFI_SOURCE,
				 NULL, &info);
	if (rc) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	} else {
		LOG_INFO("TEST %d PASSED: %s", id, __func__);
		display_info(info);
	}

	if (info)
		kfi_freeinfo(info);
	return rc;
}

/*
 * This test should returned a value info structure by only defining a node
 * and service with KFI_SOURCE. This test assumes that there is a NIC address
 * that is each to zero as defined in the node argument.
 */
static int test_basic_getinfo2(int id)
{
	int rc = 0;
	struct kfi_info *info = NULL;

	rc = kfi_getinfo_success(0, valid_node, valid_service, KFI_SOURCE,
				 NULL, &info);
	if (rc) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	} else {
		LOG_INFO("TEST %d PASSED: %s", id, __func__);
		display_info(info);
	}

	if (info)
		kfi_freeinfo(info);
	return rc;
}

/*
 * This test should return a value info structure by a NULL node
 * and valid service with KFI_SOURCE.
 */
static int test_basic_getinfo3(int id)
{
	int rc = 0;
	struct kfi_info *info = NULL;

	rc = kfi_getinfo_success(0, NULL, valid_service, KFI_SOURCE,
				 NULL, &info);
	if (rc) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	} else {
		LOG_INFO("TEST %d PASSED: %s", id, __func__);
		display_info(info);
	}

	if (info)
		kfi_freeinfo(info);
	return rc;
}

/*
 * This test should returned a value info structure by a NULL node
 * and NULL service.
 */
static int test_basic_getinfo4(int id)
{
	int rc = 0;
	struct kfi_info *info = NULL;

	rc = kfi_getinfo_success(0, NULL, NULL, 0, NULL, &info);
	if (rc) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	} else {
		LOG_INFO("TEST %d PASSED: %s", id, __func__);
		display_info(info);
	}

	if (info)
		kfi_freeinfo(info);
	return rc;
}

/*
 * This test should return a valid info structure by a NULL
 * KFI version, a NULL node and NULL service.
 */
static int test_version_null(int id)
{
	int rc = 0;
	struct kfi_info *info = NULL;
	uint32_t version = KFI_VERSION(KFI_MAJOR_VERSION, KFI_MINOR_VERSION);

	rc = kfi_getinfo_success(0, NULL, NULL, 0, NULL, &info);
	if (rc) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		goto fail;
	}

	if (info->fabric_attr->api_version != version) {
		rc = -EINVAL;
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		goto fail;
	}

	LOG_INFO("TEST %d PASSED: %s", id, __func__);
	LOG_INFO("API Version: %x", info->fabric_attr->api_version);

fail:
	if (info)
		kfi_freeinfo(info);
	return rc;
}

/*
 * This test should return a valid info structure by the current
 * KFI version, a NULL node and NULL service.
 */
static int test_version_current(int id)
{
	int rc = 0;
	struct kfi_info *info = NULL;
	uint32_t version = KFI_VERSION(KFI_MAJOR_VERSION, KFI_MINOR_VERSION);

	rc = kfi_getinfo_success(version, NULL, NULL, 0, NULL, &info);
	if (rc) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		goto fail;
	}

	if (info->fabric_attr->api_version != version) {
		rc = -EINVAL;
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		goto fail;
	}

	LOG_INFO("TEST %d PASSED: %s", id, __func__);
	LOG_INFO("API Version: %x", info->fabric_attr->api_version);

fail:
	if (info)
		kfi_freeinfo(info);
	return rc;
}

/*
 * This test should return a valid info structure by a recent
 * KFI version, a NULL node and NULL service.
 */
static int test_version_previous(int id)
{
	int rc = 0;
	struct kfi_info *info = NULL;
	uint32_t version = KFI_VERSION(KFI_MAJOR_VERSION, KFI_MINOR_VERSION - 1);
	uint32_t output_version = KFI_VERSION(KFI_MAJOR_VERSION, KFI_MINOR_VERSION);

	rc = kfi_getinfo_success(version, NULL, NULL, 0, NULL, &info);
	if (rc) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		goto fail;
	}

	if (info->fabric_attr->api_version != output_version) {
		rc = -EINVAL;
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
		goto fail;
	}

	LOG_INFO("TEST %d PASSED: %s", id, __func__);
	LOG_INFO("API Version: %x", info->fabric_attr->api_version);

fail:
	if (info)
		kfi_freeinfo(info);
	return rc;
}

/*
 * This test should return an error with a newer KFI version.
 */
static int test_version_newer(int id)
{
	int rc = 0;
	struct kfi_info *info = NULL;

	rc = kfi_getinfo_failure(KFI_VERSION(KFI_MAJOR_VERSION, KFI_MINOR_VERSION + 1),
			NULL, NULL, 0, NULL, &info);
	if (rc) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	} else {
		LOG_INFO("TEST %d PASSED: %s", id, __func__);
	}

	if (info)
		kfi_freeinfo(info);
	return rc;
}

/*
 * Valid source IPv4 address.
 */
static int test_valid_ipv4_source(int id)
{
	int rc = 0;
	struct kfi_info *info = NULL;

	rc = kfi_getinfo_success(0, valid_ipv4, NULL, KFI_SOURCE, NULL, &info);
	if (rc) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	} else {
		LOG_INFO("TEST %d PASSED: %s", id, __func__);
		display_info(info);
	}

	if (info)
		kfi_freeinfo(info);

	return rc;
}

/*
 * Invalid source IPv4 address.
 */
static int test_invalid_ipv4_source(int id)
{
	int rc = 0;
	struct kfi_info *info = NULL;

	rc = kfi_getinfo_failure(0, "10.0.0.54", NULL, KFI_SOURCE, NULL, &info);
	if (rc)
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	else
		LOG_INFO("TEST %d PASSED: %s", id, __func__);

	if (info)
		kfi_freeinfo(info);

	return rc;
}

/*
 * Valid destination IPv4 address (loopback).
 */
static int test_valid_ipv4_destination(int id)
{
	int rc = 0;
	struct kfi_info *info = NULL;

	rc = kfi_getinfo_success(0, valid_ipv4, NULL, 0, NULL, &info);
	if (rc) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	} else {
		LOG_INFO("TEST %d PASSED: %s", id, __func__);
		display_info(info);
	}

	if (info)
		kfi_freeinfo(info);

	return rc;
}

/*
 * Invalid destination IPv4 address.
 */
static int test_invalid_ipv4_destination(int id)
{
	int rc = 0;
	struct kfi_info *info = NULL;

	rc = kfi_getinfo_failure(0, "10.0.0.54", NULL, 0, NULL, &info);
	if (rc)
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	else
		LOG_INFO("TEST %d PASSED: %s", id, __func__);

	if (info)
		kfi_freeinfo(info);

	return rc;
}

/*
 * Invalid destination IPv4 address.
 */
static int test_invalid_ipv4_destination_same_lan(int id)
{
	int rc = 0;
	struct kfi_info *info = NULL;

	rc = kfi_getinfo_failure(0, "192.168.1.32", NULL, 0, NULL, &info);
	if (rc)
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	else
		LOG_INFO("TEST %d PASSED: %s", id, __func__);

	if (info)
		kfi_freeinfo(info);

	return rc;
}

static int getinfo_traffic_class(unsigned int domain_tclass,
				 unsigned int tx_tclass)
{
	int rc = 0;
	struct kfi_info *info = NULL;
	struct kfi_info *hints = NULL;

	hints = kfi_allocinfo();
	if (!hints)
		return -ENOMEM;

	hints->caps = (KFI_MSG | KFI_RMA | KFI_SEND | KFI_RECV | KFI_READ |
		       KFI_WRITE | KFI_REMOTE_READ | KFI_REMOTE_WRITE |
		       KFI_MULTI_RECV | KFI_RMA_EVENT | KFI_REMOTE_COMM);
	hints->domain_attr->tclass = domain_tclass;
	hints->tx_attr->tclass = tx_tclass;

	rc = kfi_getinfo_success(0, valid_node, valid_service, KFI_SOURCE,
				 hints, &info);

	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;
}

static int test_valid_traffic_classes(int id)
{
	unsigned int valid_tcs[] = {
		KFI_TC_BEST_EFFORT,
		KFI_TC_LOW_LATENCY,
		KFI_TC_DEDICATED_ACCESS,
		KFI_TC_BULK_DATA,
	};
	int i;
	int rc;

	/* Verify valid traffic classes work with domain attr. */
	for (i = 0; i < ARRAY_SIZE(valid_tcs); i++) {
		rc = getinfo_traffic_class(valid_tcs[i], KFI_TC_UNSPEC);
		if (rc)
			goto fail;
	}

	/* Verify valid traffic classes work with tx attr. */
	for (i = 0; i < ARRAY_SIZE(valid_tcs); i++) {
		rc = getinfo_traffic_class(KFI_TC_UNSPEC, valid_tcs[i]);
		if (rc)
			goto fail;
	}

	LOG_INFO("TEST %d PASSED", id);
	return 0;

fail:
	LOG_ERR("TEST %d FAILED", id);
	return rc;
}

static int test_invalid_traffic_classes(int id)
{
	int rc;

	rc = getinfo_traffic_class(KFI_TC_SCAVENGER, KFI_TC_UNSPEC);
	if (!rc)
		goto fail;

	rc = getinfo_traffic_class(KFI_TC_UNSPEC, KFI_TC_SCAVENGER);
	if (!rc)
		goto fail;

	LOG_INFO("TEST %d PASSED", id);
	return 0;

fail:
	LOG_ERR("TEST %d FAILED", id);
	return -EINVAL;
}

/*
 * Valid valid local node offset source address.
 */
static int test_valid_offset_node_source(int id)
{
	int rc = 0;
	struct kfi_info *info = NULL;

	rc = kfi_getinfo_success(0, valid_offset_node, NULL, KFI_SOURCE, NULL,
				 &info);
	if (rc) {
		LOG_ERR("TEST %d FAILED: %s %d", id, __func__, __LINE__);
	} else {
		LOG_INFO("TEST %d PASSED: %s", id, __func__);
		display_info(info);
	}

	if (info)
		kfi_freeinfo(info);

	return rc;
}

static int __init test_module_init(void)
{
	int rc = 0;
	int exit_rc = 0;
	int test_id = 1;

	rc = test_basic_getinfo1(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_basic_getinfo2(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_basic_getinfo3(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_basic_getinfo4(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_version_null(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_version_current(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_version_previous(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_version_newer(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bad_node(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_specific_caps(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_kfilnd_required_caps(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bad_fabric_prov(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bad_domain_name(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bad_domain_ptr(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bad_domain_threading_mode(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bad_domain_control_progress(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bad_domain_resource_mgmt(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bad_domain_av_type(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bad_domain_mr_mode(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bad_domain_mr_key_size(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bad_domain_cq_data_size(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_valid_domain_cq_count(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bad_domain_cq_count(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_valid_domain_ep_count(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bad_domain_ep_count(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_valid_domain_tx_count(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bad_domain_tx_count(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_valid_domain_rx_count(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bad_domain_rx_count(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_valid_domain_max_ep_tx_ctx_count(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bad_domain_max_ep_tx_ctx_count(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_valid_domain_max_ep_rx_ctx_count(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bad_domain_max_ep_rx_ctx_count(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bad_domain_max_ep_stx_ctx_count(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bad_domain_max_ep_srx_ctx_count(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bad_domain_cntr_count(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bad_domain_mr_iov_limit(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bad_domain_max_err_data(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bad_domain_max_mr_count(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bad_domain_auth_key_size(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bad_domain_missing_auth_key_size(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bad_ep_type(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bad_ep_protocol(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bad_ep_protocol_version(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bad_ep_msg_prefex_size(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bad_ep_max_order_raw_size(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bad_ep_max_order_war_size(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bad_ep_max_order_waw_size(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bad_ep_mem_format(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_valid_ep_max_tx_cnt(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bad_ep_max_tx_cnt(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_valid_ep_max_rx_cnt(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bad_ep_max_rx_cnt(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bad_ep_auth_key_size(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bad_ep_missing_auth_key_size(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bad_tx_caps(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bad_tx_mode(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bad_tx_ops_mode(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bad_tx_comp_order(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bad_tx_inject_size(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bad_tx_size(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bad_tx_iov_limit(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bad_tx_rma_iov_limit(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bad_rx_caps(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bad_rx_mode(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bad_rx_ops_mode(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bad_rx_comp_order(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bad_rx_total_buffer_recv(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bad_rx_size(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bad_rx_iov_limit(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_valid_ipv4_source(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_invalid_ipv4_source(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_valid_ipv4_destination(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_invalid_ipv4_destination(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_invalid_ipv4_destination_same_lan(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_valid_traffic_classes(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_invalid_traffic_classes(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_valid_offset_node_source(test_id);
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
