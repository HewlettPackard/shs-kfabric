// SPDX-License-Identifier: GPL-2.0
/* Copyright 2021 Hewlett Packard Enterprise Development LP */
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <kfabric.h>
#include <kfi_log.h>
#include <kfi_eq.h>
#include <kfi_domain.h>
#include <kfi_endpoint.h>
#include <kfi_errno.h>
#include <kfi_tagged.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/random.h>
#include <linux/mm.h>
#include <linux/atomic.h>
#include <linux/module.h>

#include "../../../prov/cxi/kcxi_prov.h"

#ifdef MODULE_NAME
#undef MODULE_NAME
#endif
#define MODULE_NAME "test_msg_rnr"

#define TIMEOUT_SEC 5U
#define BUF_SIZE 1024U

static struct kfi_info *hints;
static struct kfi_info *info;
static struct kfid_fabric *fabric;
static struct kfid_domain *domain;
static struct kfid_av *av;
static struct kfid_cq *cq;
static struct kfid_ep *sep;
static struct kfid_ep *rx;
static struct kfid_ep *tx;
static void *rx_buffer;
static void *tx_buffer;
static char *node = "0x0";
static char *service = "0";
static kfi_addr_t loopback_addr;
static DECLARE_WAIT_QUEUE_HEAD(wait_queue);
static atomic_t event_count = ATOMIC_INIT(0);

MODULE_AUTHOR("Hewlett Packard Enterprise Development LP");
MODULE_DESCRIPTION("kfabric CXI receive not ready tests");
MODULE_LICENSE("GPL v2");

static void test_cq_cb(struct kfid_cq *cq, void *context)
{
	atomic_inc(&event_count);
	wake_up(&wait_queue);
}

static int test_init(void)
{
	struct kfi_av_attr av_attr = {};
	struct kfi_cq_attr cq_attr = {};
	struct kfi_tx_attr tx_attr = {};
	struct kfi_rx_attr rx_attr = {};
	int rc;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("Failed to allocate fabric hints");
		rc = -ENOMEM;
		goto err;
	}
	hints->caps = (KFI_MSG | KFI_RMA | KFI_SEND | KFI_RECV | KFI_READ |
		       KFI_WRITE | KFI_REMOTE_READ | KFI_REMOTE_WRITE |
		       KFI_RMA_EVENT | KFI_REMOTE_COMM |
		       KFI_NAMED_RX_CTX);

	rc = kfi_getinfo(0, node, service, KFI_SOURCE, hints, &info);
	if (rc) {
		LOG_ERR("Failed to get fabric info");
		goto err_free_hints;
	}

	rc = kfi_fabric(info->fabric_attr, &fabric, NULL);
	if (rc) {
		LOG_ERR("Failed to create fabric object");
		goto err_free_info_info;
	}

	rc = kfi_domain(fabric, info, &domain, NULL);
	if (rc) {
		LOG_ERR("Failed to create domain object");
		goto err_free_fabric;
	}

	av_attr.type = KFI_AV_UNSPEC;
	av_attr.rx_ctx_bits = 4;
	rc = kfi_av_open(domain, &av_attr, &av, NULL);
	if (rc) {
		LOG_ERR("Failed to create address vector");
		goto err_free_domain;
	}

	cq_attr.format = KFI_CQ_FORMAT_DATA;
	rc = kfi_cq_open(domain, &cq_attr, &cq, test_cq_cb, NULL);
	if (rc) {
		LOG_ERR("Failed to allocate CQ");
		goto err_free_av;
	}

	rc = kfi_scalable_ep(domain, info, &sep, NULL);
	if (rc) {
		LOG_ERR("Failed to allocate SEP");
		goto err_free_cq;
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

	rc = kfi_rx_context(sep, 0, &rx_attr, &rx, NULL);
	if (rc) {
		LOG_ERR("Failed to allocate RX context");
		goto err_free_sep;
	}

	rc = kfi_ep_bind(rx, &cq->fid, 0);
	if (rc) {
		LOG_ERR("Failed to bind CQ to RX context");
		goto err_free_rx;
	}

	rc = kfi_enable(rx);
	if (rc) {
		LOG_ERR("Failed enable RX CTX");
		goto err_free_rx;
	}

	tx_attr.caps = KFI_NAMED_RX_CTX | KFI_MSG;
	rc = kfi_tx_context(sep, 0, &tx_attr, &tx, NULL);
	if (rc) {
		LOG_ERR("Failed to allocate TX context");
		goto err_free_rx;
	}

	rc = kfi_ep_bind(tx, &cq->fid, 0);
	if (rc) {
		LOG_ERR("Failed to bind CQ to TX context");
		goto err_free_tx;
	}

	rc = kfi_enable(tx);
	if (rc) {
		LOG_ERR("Failed enable TX CTX");
		goto err_free_tx;
	}

	rx_buffer = kmalloc(BUF_SIZE, GFP_KERNEL);
	if (!rx_buffer) {
		rc = -ENOMEM;
		goto err_free_tx;
	}

	tx_buffer = kmalloc(BUF_SIZE, GFP_KERNEL);
	if (!tx_buffer) {
		rc = -ENOMEM;
		goto err_free_rx_buffer;
	}

	rc = kfi_av_insertsvc(av, node, service, &loopback_addr, 0, NULL);
	if (rc < 0)
		goto err_free_tx_buffer;

	/* Named RX context is enabled. Adjust loopback address to target RX
	 * context 0.
	 */
	loopback_addr = kfi_rx_addr(loopback_addr, 0, av_attr.rx_ctx_bits);

	/* sleep a second to allow link to become ready */
	msleep(1000);

	return 0;

err_free_tx_buffer:
	kfree(tx_buffer);
err_free_rx_buffer:
	kfree(rx_buffer);
err_free_tx:
	kfi_close(&tx->fid);
err_free_rx:
	kfi_close(&rx->fid);
err_free_sep:
	kfi_close(&sep->fid);
err_free_cq:
	kfi_close(&cq->fid);
err_free_av:
	kfi_close(&av->fid);
err_free_domain:
	kfi_close(&domain->fid);
err_free_fabric:
	kfi_close(&fabric->fid);
err_free_info_info:
	kfi_freeinfo(info);
err_free_hints:
	kfi_freeinfo(hints);
err:
	return rc;
}

static void test_fini(void)
{
	kfi_close(&tx->fid);
	kfi_close(&rx->fid);
	kfi_close(&sep->fid);
	kfi_close(&cq->fid);
	kfi_close(&av->fid);
	kfi_close(&domain->fid);
	kfi_close(&fabric->fid);
	kfi_freeinfo(info);
	kfi_freeinfo(hints);

	kfree(tx_buffer);
	kfree(rx_buffer);
}

/* Issue a send operation without posting a matching receive buffer. This should
 * eventually cause the operation to timeout.
 */
static int test_rnr_timeout(int id, bool rma)
{
	struct kfi_cq_data_entry event;
	struct kfi_cq_err_entry error;
	uint64_t tag = 0x1010101;
	int rc;

	LOG_INFO("TEST %d STARTED: %s %s", id, __func__, rma ? "rma":"msg");

	atomic_set(&event_count, 0);

	if (!rma)
		rc = kfi_send(tx, tx_buffer, BUF_SIZE, NULL, loopback_addr, tx);
	else
		rc = kfi_write(tx, tx_buffer, BUF_SIZE, NULL, loopback_addr, 0, tag, tx);
	if (rc) {
		LOG_ERR("%s failed: rc=%d", rma ? "kfi_write":"kfi_send", rc);
		return rc;
	}

	/* Wait for callback to be triggered to unblock this thread. */
	rc = wait_event_timeout(wait_queue, atomic_read(&event_count),
				TIMEOUT_SEC * HZ);
	if (!rc) {
		LOG_ERR("Timeout waiting for CQ event: rc=%d", rc);
		rc = -ETIMEDOUT;
		goto err;
	}

	LOG_INFO("%s wait_event_timeout rc=%d", __func__, rc);

	/* An error event should be returned. */
	rc = kfi_cq_read(cq, &event, 1);
	if (rc != -KFI_EAVAIL) {
		LOG_ERR("CQ error not returned: rc=%d", rc);
		rc = -EINVAL;
		goto err;
	}

	rc = kfi_cq_readerr(cq, &error, 0);
	if (rc < 0) {
		LOG_ERR("No CQ error present: rc=%d", rc);
		rc = -EINVAL;
		goto err;
	}

	/* Error should be on tx context*/
	if (error.op_context != tx) {
		LOG_ERR("Bad CQ error event, op context");
		rc = -EINVAL;
		goto err;
	}

	/* For messaging, treat C_RC_ENTRY_NOT_FOUND as receiver not ready. */
	if (error.prov_errno != C_RC_ENTRY_NOT_FOUND) {
		LOG_ERR("Bad CQ error event, provider error %d", error.prov_errno);
		rc = -EINVAL;
		goto err;
	}

	/* When prov_errno is C_RC_ENTRY_NOT_FOUND, err is EREMOTEIO. */
	if (error.err != EREMOTEIO) {
		LOG_ERR("Bad CQ error event, error %d", error.err);
		rc = -EINVAL;
		goto err;
	}

	rc = kfi_cq_read(cq, &event, 1);
	if (rc != -EAGAIN) {
		LOG_ERR("CQ did not return EAGAIN: rc=%d", rc);
		rc = -EINVAL;
		goto err;
	}

	LOG_INFO("TEST %d PASSED: %s %s", id, __func__, rma ? "rma":"msg");
	return 0;

err:
	LOG_INFO("TEST %d FAILED: %s %s", id, __func__, rma ? "rma":"msg");
	return rc;
}

/* Post a receive late. The provider should internally retry the operation and
 * eventually it should match.
 */
static int test_late_recv(int id, bool rma)
{
	struct kfi_cq_data_entry event[2];
	uint64_t tag = 0x1010101;
	struct kvec iov = {
		.iov_base = tx_buffer,
		.iov_len = BUF_SIZE,
	};
	struct kfi_rma_iov rma_iov = {
		.len = BUF_SIZE,
		.key = tag,
	};
	struct kfi_msg_rma rma_msg = {
		.type = KFI_KVEC,
		.msg_iov = &iov,
		.iov_count = 1,
		.addr = loopback_addr,
		.rma_iov = &rma_iov,
		.rma_iov_count = 1,
	};
	int rc;

	LOG_INFO("TEST %d STARTED: %s %s", id, __func__, rma ? "rma":"msg");

	atomic_set(&event_count, 0);

	if (!rma)
		rc = kfi_send(tx, tx_buffer, BUF_SIZE, NULL, loopback_addr, tx);
	else
		rc = kfi_writemsg(tx, &rma_msg, KFI_TAGGED | KFI_COMPLETION);
	if (rc) {
		LOG_ERR("%s failed: rc=%d", rma ? "kfi_writemsg":"kfi_send", rc);
		goto err;
	}

	if (!rma)
		rc = kfi_recv(rx, rx_buffer, BUF_SIZE, NULL, KFI_ADDR_UNSPEC, rx);
	else
		rc = kfi_trecv(rx, rx_buffer, BUF_SIZE, NULL, KFI_ADDR_UNSPEC, tag, 0, rx);
	if (rc) {
		LOG_ERR("%s failed: rc=%d", rma ? "kfi_trecv":"kfi_recv", rc);
		goto err;
	}

	/* Wait for callback to be triggered to unblock this thread. */
	rc = wait_event_timeout(wait_queue, atomic_read(&event_count),
				TIMEOUT_SEC * HZ);
	if (!rc) {
		LOG_ERR("Timeout waiting for CQ event: rc=%d", rc);
		rc = -ETIMEDOUT;
		goto err;
	}

	LOG_INFO("%s wait_event_timeout rc=%d", __func__, rc);

	/* Two events should be returned, one tx and one rx */
	rc = kfi_cq_read(cq, &event, 2);
	if (rc != 2) {
		LOG_ERR("CQ event not returned: rc=%d", rc);
		rc = -EINVAL;
		goto err;
	}

	rc = kfi_cq_read(cq, &event, 1);
	if (rc != -EAGAIN) {
		LOG_ERR("CQ did not return EAGAIN: rc=%d", rc);
		rc = -EINVAL;
		goto err;
	}

	LOG_INFO("TEST %d PASSED: %s %s", id, __func__, rma ? "rma":"msg");
	return 0;

err:
	LOG_INFO("TEST %d FAILED: %s %s", id, __func__, rma ? "rma":"msg");
	return rc;
}

/* Post a tagged receive late. The provider should internally retry the
 * operation and eventually it should match. Tagged send with data is used.
 */
static int test_late_trecv(int id)
{
	struct kfi_cq_data_entry event[2];
	int rc;
	uint64_t tag = 0x1010101;
	uint64_t data = 0x10101;
	int i;
	int cq_count = 0;

	LOG_INFO("TEST %d STARTED: %s", id, __func__);

	atomic_set(&event_count, 0);

	rc = kfi_tsenddata(tx, NULL, 0, NULL, data, loopback_addr, tag, tx);
	if (rc) {
		LOG_ERR("kfi_trsenddata failed: rc=%d", rc);
		goto err;
	}

	rc = kfi_trecv(rx, NULL, 0, NULL, KFI_ADDR_UNSPEC, tag, 0, rx);
	if (rc) {
		LOG_ERR("kfi_trecv failed: rc=%d", rc);
		goto err;
	}

	/* Wait for callback to be triggered to unblock this thread. */
	rc = wait_event_timeout(wait_queue, atomic_read(&event_count),
				TIMEOUT_SEC * HZ);
	if (!rc) {
		LOG_ERR("Timeout waiting for CQ event: rc=%d", rc);
		rc = -ETIMEDOUT;
		goto err;
	}

	LOG_INFO("%s wait_event_timeout rc=%d", __func__, rc);

	/* Two events should be returned, one tx and one rx */
	rc = kfi_cq_read(cq, &event, 2);
	if (rc != 2) {
		LOG_ERR("CQ event not returned: rc=%d", rc);
		rc = -EINVAL;
		goto err;
	}

	for (i = 0; i < ARRAY_SIZE(event); i++) {
		if (event[i].flags & (KFI_RECV | KFI_REMOTE_CQ_DATA)) {
			if (event[i].data != data) {
				LOG_ERR("CQ event data bad");
				rc = -EINVAL;
				goto err;
			}

			cq_count++;
		} else if (event[i].flags & KFI_SEND) {
			cq_count++;
		}
	}

	if (cq_count != ARRAY_SIZE(event)) {
		LOG_ERR("Missing CQ events");
		rc = -EINVAL;
		goto err;
	}

	rc = kfi_cq_read(cq, &event, 1);
	if (rc != -EAGAIN) {
		LOG_ERR("CQ did not return EAGAIN: rc=%d", rc);
		rc = -EINVAL;
		goto err;
	}

	LOG_INFO("TEST %d PASSED: %s", id, __func__);
	return 0;

err:
	LOG_INFO("TEST %d FAILED: %s", id, __func__);
	return rc;
}

static int __init test_module_init(void)
{
	int test_id = 0;
	int rc;

	rc = test_init();
	if (rc)
		goto error;

	rc = test_rnr_timeout(test_id, false);
	if (rc)
		goto error_fini;

	test_id++;
	rc= test_late_recv(test_id, false);
	if (rc)
		goto error_fini;

	test_id++;
	rc= test_late_recv(test_id, true);
	if (rc)
		goto error_fini;

	test_id++;
	rc= test_late_trecv(test_id);
	if (rc)
		goto error_fini;

	test_id++;
	rc = test_rnr_timeout(test_id, true);
	if (rc)
		goto error_fini;

	test_fini();

	return 0;

error_fini:
	test_fini();
error:
	return rc;
}

static void __exit test_module_exit(void)
{
}

module_init(test_module_init);
module_exit(test_module_exit);
