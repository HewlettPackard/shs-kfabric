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
#include <kfi_rma.h>
#include <kfi_tagged.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/random.h>
#include <linux/mm.h>
#include <linux/atomic.h>
#include <linux/module.h>
#include <linux/uio.h>

#include "../../../prov/cxi/kcxi_prov.h"

#ifdef MODULE_NAME
#undef MODULE_NAME
#endif
#define MODULE_NAME "test_tagged_rma"

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
static char *rx_buffer;
static char *tx_buffer;
static char *node = "0x0";
static char *service = "0";
static kfi_addr_t loopback_addr;
static DECLARE_WAIT_QUEUE_HEAD(wait_queue);
static atomic_t event_count = ATOMIC_INIT(0);
static unsigned int tag = 0x123456;

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
		       KFI_NAMED_RX_CTX | KFI_TAGGED_RMA | KFI_DIRECTED_RECV);

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

static int test_tagged_rma_rnr_timeout(bool write)
{
	struct kfi_cq_data_entry event;
	struct kfi_cq_err_entry error;
	int rc;
	struct kvec iov = {
		.iov_base = tx_buffer,
		.iov_len = BUF_SIZE,
	};
	struct kfi_rma_iov rma_iov = {
		.len = BUF_SIZE,
		.key = tag,
	};
	struct kfi_msg_rma rma = {
		.type = KFI_KVEC,
		.msg_iov = &iov,
		.iov_count = 1,
		.addr = loopback_addr,
		.rma_iov = &rma_iov,
		.rma_iov_count = 1,
	};
	uint64_t flags = KFI_TAGGED | KFI_RMA | KFI_SEND;

	atomic_set(&event_count, 0);

	if (write) {
		flags |= KFI_WRITE;
		rc = kfi_writemsg(tx, &rma, KFI_TAGGED | KFI_COMPLETION);
	} else {
		flags |= KFI_READ;
		rc = kfi_readmsg(tx, &rma, KFI_TAGGED | KFI_COMPLETION);
	}
	if (rc) {
		LOG_ERR("kfi_%s failed: rc=%d", write ? "writemsg":"readmsg", rc);
		return rc;
	}

	/* Wait for callback to be triggered to unblock this thread. */
	rc = wait_event_timeout(wait_queue, atomic_read(&event_count),
				TIMEOUT_SEC * HZ);
	if (!rc) {
		LOG_ERR("Timeout waiting for CQ event: rc=%d", rc);
		return -ETIMEDOUT;
	}

	LOG_INFO("%s wait_event_timeout rc=%d", __func__, rc);

	/* An error event should be returned. */
	rc = kfi_cq_read(cq, &event, 1);
	if (rc != -KFI_EAVAIL) {
		LOG_ERR("CQ error not returned: rc=%d", rc);
		return -EINVAL;
	}

	rc = kfi_cq_readerr(cq, &error, 0);
	if (rc < 0) {
		LOG_ERR("No CQ error present: rc=%d", rc);
		return -EINVAL;
	}

	/* For messaging, treat C_RC_ENTRY_NOT_FOUND as receiver not ready. */
	if (error.op_context != tx && error.prov_errno != C_RC_ENTRY_NOT_FOUND) {
		LOG_ERR("Bad CQ error event");
		return -EINVAL;
	}

	if (error.flags != flags) {
		LOG_ERR("Bad CQ error event flags");
		return -EINVAL;
	}

	rc = kfi_cq_read(cq, &event, 1);
	if (rc != -EAGAIN) {
		LOG_ERR("CQ did not return EAGAIN: rc=%d", rc);
		return -EINVAL;
	}

	LOG_INFO("TEST PASSED: %s %s", __func__, write ? "write" : "read");
	return 0;
}

static int test_tagged_rma(bool write, bool overflow)
{
	struct kfi_cq_data_entry event;
	struct kfi_cq_err_entry error;
	int rc;
	struct kvec iov = {
		.iov_base = tx_buffer,
		.iov_len = BUF_SIZE,
	};
	struct kfi_rma_iov rma_iov = {
		.len = BUF_SIZE,
		.key = tag,
	};
	struct kfi_msg_rma rma = {
		.type = KFI_KVEC,
		.msg_iov = &iov,
		.iov_count = 1,
		.addr = loopback_addr,
		.rma_iov = &rma_iov,
		.rma_iov_count = 1,
	};
	uint64_t flags = KFI_TAGGED | KFI_RMA;
	unsigned int cq_event_count = 2;
	unsigned int i;

	atomic_set(&event_count, 0);

	if (overflow)
		rc = kfi_trecv(rx, rx_buffer, BUF_SIZE - 1, NULL,
			       loopback_addr, tag, 0, NULL);
	else
		rc = kfi_trecv(rx, rx_buffer, BUF_SIZE, NULL, loopback_addr,
			       tag, 0, NULL);
	if (rc) {
		LOG_ERR("kfi_trecv failed: rc=%d overflow=%d", rc, overflow);
		return rc;
	}

	if (write) {
		flags |= KFI_WRITE;
		rc = kfi_writemsg(tx, &rma, KFI_TAGGED | KFI_COMPLETION);
	} else {
		flags |= KFI_READ;
		rc = kfi_readmsg(tx, &rma, KFI_TAGGED | KFI_COMPLETION);
	}
	if (rc) {
		LOG_ERR("kfi_%s failed: rc=%d", write ? "writemsg":"readmsg", rc);
		return rc;
	}

	/* Wait for callback to be triggered to unblock this thread. */
	rc = wait_event_timeout(wait_queue, atomic_read(&event_count),
				TIMEOUT_SEC * HZ);
	if (!rc) {
		LOG_ERR("Timeout waiting for CQ event: rc=%d", rc);
		return -ETIMEDOUT;
	}

	/* Verify two events are returned. */
	for(i = 0; i < cq_event_count; i++) {
		rc = kfi_cq_read(cq, &event, 1);
		if (overflow) {
			if (rc != -KFI_EAVAIL) {
				LOG_ERR("CQ error not returned: rc=%d", rc);
				return -EINVAL;
			}

			rc = kfi_cq_readerr(cq, &error, 0);
			if (rc < 0) {
				LOG_ERR("No CQ error present: rc=%d", rc);
				return -EINVAL;
			}

			if ((error.flags & flags) != flags) {
				LOG_ERR("Bad CQ error event flags");
				return -EINVAL;
			}
		} else {
			if (rc < 0) {
				LOG_ERR("CQ error returned: rc=%d", rc);
				return -EINVAL;
			}

			if ((event.flags & flags) != flags) {
				LOG_ERR("Bad CQ error event flags");
				return -EINVAL;
			}
		}

		msleep(20);
	}

	if (!overflow) {
		for (i = 0; i < BUF_SIZE; i++) {
			if (tx_buffer[i] != rx_buffer[i]) {
				LOG_ERR("Data corrupt at byte %u", i);
				return -EIO;
			}
		}
	}

	rc = kfi_cq_read(cq, &event, 1);
	if (rc != -EAGAIN) {
		LOG_ERR("CQ did not return EAGAIN: rc=%d", rc);
		return -EINVAL;
	}

	LOG_INFO("TEST PASSED: %s %s overflow=%d", __func__, write ? "write" : "read", overflow);
	return 0;
}

/* Issue a RMA operation without posting a matching tagged buffer. This should
 * eventually cause the operation to timeout.
 */
static int test_1_tagged_rma_write_rnr_timeout(void)
{
	return test_tagged_rma_rnr_timeout(true);
}

static int test_2_tagged_rma_read_rnr_timeout(void)
{
	return test_tagged_rma_rnr_timeout(false);
}

/* Issue a RMA operation with posting a late matching tagged buffer. Operation
 * should succeed.
 */
static int test_3_tagged_rma_write(void)
{
	return test_tagged_rma(true, false);
}

static int test_4_tagged_rma_read(void)
{
	return test_tagged_rma(false, false);
}

/* Issue a RMA operation which results in an overflow. Operation should fail at
 * both the initiator and target.
 */
static int test_5_tagged_rma_write_oflow(void)
{
	return test_tagged_rma(true, true);
}

static int test_6_tagged_rma_read_oflow(void)
{
	return test_tagged_rma(false, true);
}

static int __init test_module_init(void)
{
	int rc;

	rc = test_init();
	if (rc)
		goto error;

	rc = test_1_tagged_rma_write_rnr_timeout();
	if (rc) {
		LOG_ERR("test_1_tagged_rma_write_rnr_timeout failed: rc=%d", rc);
		goto error_fini;
	}

	rc = test_2_tagged_rma_read_rnr_timeout();
	if (rc) {
		LOG_ERR("test_2_tagged_rma_read_rnr_timeout failed: rc=%d", rc);
		goto error_fini;
	}

	rc = test_3_tagged_rma_write();
	if (rc) {
		LOG_ERR("test_3_tagged_rma_write failed: rc=%d", rc);
		goto error_fini;
	}

	rc = test_4_tagged_rma_read();
	if (rc) {
		LOG_ERR("test_4_tagged_rma_read failed: rc=%d", rc);
		goto error_fini;
	}

	rc = test_5_tagged_rma_write_oflow();
	if (rc) {
		LOG_ERR("test_5_tagged_rma_write_oflow failed: rc=%d", rc);
		goto error_fini;
	}

	rc = test_6_tagged_rma_read_oflow();
	if (rc) {
		LOG_ERR("test_6_tagged_rma_read_oflow failed: rc=%d", rc);
		goto error_fini;
	}

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
