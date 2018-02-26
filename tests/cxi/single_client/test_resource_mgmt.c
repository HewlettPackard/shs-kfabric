//SPDX-License-Identifier: GPL-2.0
/*
 * Resource management test. with resource management enable, data transfer
 * operations will return -EAGAIN as either underlying hardware resources are
 * consumed or the completion queue is running out-of-space. This test issues
 * many data transfer operations until -EAGAIN is returned. The expected number
 * of operations before -EAGAIN is returns is equal to the size of the
 * completion queue.
 *
 * Copyright 2019 Cray Inc. All Rights Reserved.
 */
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <kfabric.h>
#include <kfi_log.h>
#include <kfi_eq.h>
#include <kfi_domain.h>
#include <kfi_endpoint.h>
#include <kfi_rma.h>
#include <kfi_errno.h>
#include <linux/kthread.h>
#include <linux/random.h>
#include <linux/mm.h>
#include <linux/atomic.h>
#include <linux/module.h>
#include <linux/delay.h>
#include <linux/vmalloc.h>

#ifdef MODULE_NAME
#undef MODULE_NAME
#endif
#define MODULE_NAME "test_resource_mgmt"

static struct kfi_info *hints;
static struct kfi_info *info;
static struct kfid_fabric *fabric;
static struct kfid_domain *domain;
static struct kfid_av *av;
static struct kfid_cq *cq;
static struct kfid_ep *sep;
static struct kfid_ep *rx;
static struct kfid_ep *tx;
static struct kfid_mr *mr;

#define CQ_SIZE 64
#define NUM_TXS (CQ_SIZE * 2)
#define TX_BUF_SIZE 1
#define MIN_MULTI_RECV 2
#define RX_BUF_SIZE ((NUM_TXS + MIN_MULTI_RECV) * TX_BUF_SIZE)
#define MR_BUF_SIZE RX_BUF_SIZE
#define MR_KEY 0x123456

static void *rx_buffer;
static void *tx_buffer;
static void *mr_buffer;

static char *node = "0x0";
static char *service = "0";
static kfi_addr_t loopback_addr;

#define TIMEOUT_SEC 5

MODULE_AUTHOR("Ian Ziemba");
MODULE_DESCRIPTION("kfabric CXI resource management test");
MODULE_LICENSE("GPL v2");


static void drain_cq(unsigned int event_count)
{
	int rc = 0;
	struct kfi_cq_data_entry event;
	struct kfi_cq_err_entry error;

	while (event_count) {
		rc = kfi_cq_read(cq, &event, 1);
		if (rc == -KFI_EAVAIL) {
			kfi_cq_readerr(cq, &error, 0);
			event_count--;
		} else if (rc == 1) {
			event_count--;
		} else {
			schedule();
		}
	}

	kfi_cq_read(cq, &event, 1);
}

static int test_init(void)
{
	struct kfi_av_attr av_attr = {
		.type = KFI_AV_UNSPEC,
	};
	struct kfi_cq_attr cq_attr = {
		.size = CQ_SIZE,
		.format = KFI_CQ_FORMAT_DATA,
	};
	struct kfi_rx_attr rx_attr = {
		.op_flags = KFI_MULTI_RECV,
	};
	int rc;
	size_t min_multi_recv = MIN_MULTI_RECV;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("Failed to allocate fabric hints");
		rc = -ENOMEM;
		goto err;
	}
	hints->caps = (KFI_MSG | KFI_RMA | KFI_SEND | KFI_RECV | KFI_READ |
		       KFI_WRITE | KFI_REMOTE_READ | KFI_REMOTE_WRITE |
		       KFI_MULTI_RECV | KFI_REMOTE_COMM);

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

	rc = kfi_av_open(domain, &av_attr, &av, NULL);
	if (rc) {
		LOG_ERR("Failed to create address vector");
		goto err_free_domain;
	}

	rc = kfi_cq_open(domain, &cq_attr, &cq, NULL, NULL);
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

	rc = kfi_tx_context(sep, 0, NULL, &tx, NULL);
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

	rx_buffer = vmalloc(RX_BUF_SIZE);
	if (!rx_buffer) {
		rc = -ENOMEM;
		goto err_free_tx;
	}

	tx_buffer = vmalloc(TX_BUF_SIZE);
	if (!tx_buffer) {
		rc = -ENOMEM;
		goto err_free_rx_buffer;
	}

	mr_buffer = vmalloc(MR_BUF_SIZE);
	if (!mr_buffer) {
		rc = -ENOMEM;
		goto err_free_tx_buffer;
	}

	rc = kfi_av_insertsvc(av, node, service, &loopback_addr, 0, NULL);
	if (rc < 0)
		goto err_free_mr_buffer;

	rc = kfi_setopt(&rx->fid, KFI_OPT_ENDPOINT, KFI_OPT_MIN_MULTI_RECV,
			&min_multi_recv, sizeof(min_multi_recv));
	if (rc) {
		LOG_ERR("Failed to set min_recv");
		goto err_free_mr_buffer;
	}

	rc = kfi_mr_reg(domain, mr_buffer, MR_BUF_SIZE,
			(KFI_REMOTE_READ | KFI_REMOTE_WRITE), 0, MR_KEY, 0, &mr,
			NULL);
	if (rc) {
		LOG_ERR("Failed to allocate MR");
		goto err_free_mr_buffer;
	}

	rc = kfi_mr_bind(mr, &rx->fid, 0);
	if (rc) {
		LOG_ERR("Failed to bind MR");
		goto err_free_mr;
	}

	rc = kfi_mr_enable(mr);
	if (rc) {
		LOG_ERR("Failed to enabled MR");
		goto err_free_mr;
	}

	/* sleep a second to allow link to become ready */
	msleep(1000);

	return 0;

err_free_mr:
	kfi_close(&mr->fid);
err_free_mr_buffer:
	vfree(mr_buffer);
err_free_tx_buffer:
	vfree(tx_buffer);
err_free_rx_buffer:
	vfree(rx_buffer);
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
	kfi_close(&mr->fid);
	kfi_close(&tx->fid);
	kfi_close(&rx->fid);
	kfi_close(&sep->fid);
	kfi_close(&cq->fid);
	kfi_close(&av->fid);
	kfi_close(&domain->fid);
	kfi_close(&fabric->fid);
	kfi_freeinfo(info);
	kfi_freeinfo(hints);

	vfree(mr_buffer);
	vfree(tx_buffer);
	vfree(rx_buffer);
}

/* Overrunning a CQ should cause an error. */
static int test_rma_resource_mgmt(int test_id)
{
	int rc;
	int tx_posted_count = 0;

	rc = test_init();
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Failed to initialize test",
			test_id, __func__);
		return rc;
	}

	/* Post RMA buffers until an error is returned. CQ is saturated. */
	while (tx_posted_count < NUM_TXS) {
		rc = kfi_read(tx, tx_buffer + tx_posted_count, TX_BUF_SIZE,
			      NULL, loopback_addr, tx_posted_count, MR_KEY, tx);
		if (rc) {
			LOG_INFO("TEST %d %s: RMA read error %d at count %d", test_id, __func__, rc, tx_posted_count);
			break;
		}
		tx_posted_count++;
		msleep(20);
	}

	if (!rc) {
		LOG_ERR("TEST %d %s FAILED: RMA read did not return an error",
			test_id, __func__);
		goto err;
	}

	/* Post a muti-receive buffer. It should succeed even though CQ is saturated. */
	rc = kfi_recv(rx, rx_buffer, RX_BUF_SIZE, NULL, 0, rx);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Failed to emit recv command",
			test_id, __func__);
		goto err;
	}

	rc = kfi_cancel(&rx->fid, rx);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Failed to cancel recv operation",
			test_id, __func__);
		goto err;
	}	

	drain_cq(tx_posted_count);

	test_fini();

	LOG_INFO("TEST %d %s: PASSED", test_id, __func__);

	return 0;

err:
	test_fini();

	return -EINVAL;
}

/* Targeting an invalid MR should cause an error and disable the TX context. */
static int test_invalid_mr_resource_mgmt(int test_id)
{
	int rc;
	struct kfi_cq_err_entry error;
	struct kfi_cq_data_entry event;
	unsigned int poll_count = 0;

	rc = test_init();
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Failed to initialize test",
			test_id, __func__);
		return rc;
	}

	rc = kfi_read(tx, tx_buffer, TX_BUF_SIZE, NULL, loopback_addr, 0,
		      MR_KEY + 1, tx);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Failed to emit RMA read", test_id,
			__func__);
		goto err;
	}

	/* Poll CQ waiting for an error. */
	while (poll_count < 5 || (rc = kfi_cq_readerr(cq, &error, 0)) != 1) {
		msleep(20);
		poll_count++;
	}

	if (rc != 1) {
		LOG_ERR("TEST %d %s FAILED: CQ error event did not occur",
			test_id, __func__);
		goto err;
	}

	/* TX context should still accept commands. */
	rc = kfi_read(tx, tx_buffer, TX_BUF_SIZE, NULL, loopback_addr, 0,
		      MR_KEY, tx);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Failed to emit RMA read command",
			test_id, __func__);
		goto err;
	}

	/* Poll CQ waiting for a success event. */
	poll_count = 0;
	while (poll_count < 5 || (rc = kfi_cq_read(cq, &event, 1)) != 1) {
		msleep(20);
		poll_count++;
	}

	if (rc != 1) {
		LOG_ERR("TEST %d %s FAILED: CQ completion event did not occur",
			test_id, __func__);
		goto err;
	}

	test_fini();

	LOG_INFO("TEST %d %s: PASSED", test_id, __func__);

	return 0;
err:
	test_fini();

	return -EINVAL;
}

/* Perform a send to a RX context without a buffer posted. */
static int test_send_resource_mgmt(int test_id)
{
	int rc;
	struct kfi_cq_err_entry error;
	unsigned int poll_count = 0;

	rc = test_init();
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Failed to initialize test",
			test_id, __func__);
		return rc;
	}

	rc = kfi_send(tx, tx_buffer, TX_BUF_SIZE, NULL, loopback_addr, tx);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Failed to emit send", test_id,
			__func__);
		goto err;
	}

	/* Poll CQ waiting for an error. */
	while (poll_count < 20 || (rc = kfi_cq_readerr(cq, &error, 0)) != 1) {
		msleep(20);
		poll_count++;
	}

	if (rc != 1) {
		LOG_ERR("TEST %d %s FAILED: CQ error event did not occur",
			test_id, __func__);
		goto err;
	}

	/* Post RX buffer. */
	rc = kfi_recv(rx, rx_buffer, RX_BUF_SIZE, NULL, 0, rx);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Failed to emit recv command",
			test_id, __func__);
		goto err;

	}

	/* Send should now land. */
	rc = kfi_send(tx, tx_buffer, TX_BUF_SIZE, NULL, loopback_addr, tx);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Failed to emit send command",
			test_id, __func__);
		goto err;
	}

	drain_cq(1);

	test_fini();

	LOG_INFO("TEST %d %s: PASSED", test_id, __func__);

	return 0;
err:
	test_fini();

	return -EINVAL;
}

static int __init test_module_init(void)
{
	int rc;
	int test_id = 0;
	int exit_rc = 0;

	rc = test_rma_resource_mgmt(test_id);
	if (rc) {
		exit_rc = rc;
		goto error;
	}
	test_id++;

	rc = test_invalid_mr_resource_mgmt(test_id);
	if (rc) {
		exit_rc = rc;
		goto error;
	}
	test_id++;

	rc = test_send_resource_mgmt(test_id);
	if (rc) {
		exit_rc = rc;
		goto error;
	}
	test_id++;

error:
	return exit_rc;
}

static void __exit test_module_exit(void)
{}

module_init(test_module_init);
module_exit(test_module_exit);
