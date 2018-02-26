/*
 * Kfabric fabric tests.
 * Copyright 2018 Cray Inc. All Rights Reserved.
 *
 * SPDX-License-Identifier: GPL-2.0
 */
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <kfabric.h>
#include <kfi_log.h>
#include <kfi_eq.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/random.h>
#include <linux/mm.h>

#include "../../../prov/cxi/kcxi_prov.h"

#ifdef MODULE_NAME
#undef MODULE_NAME
#endif
#define MODULE_NAME "test_rx_cancel"

static struct kfi_info *hints;
static struct kfi_info *info;
static struct kfid_fabric *fabric;
static struct kfid_domain *domain;
static struct kfid_av *av;
static struct kfid_cq *cq;
static struct kfid_ep *sep;
static struct kfid_ep *rx;

static DECLARE_WAIT_QUEUE_HEAD(wait_queue);
static atomic_t event_count = ATOMIC_INIT(0);

static void test_cq_cb(struct kfid_cq *cq, void *context)
{
	atomic_inc(&event_count);
	wake_up(&wait_queue);
}

/* Initialize kfabric resources for test. */
static int test_init(void)
{
	struct kfi_av_attr av_attr = {};
	struct kfi_cq_attr cq_attr = {};
	int rc;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("Failed to allocate fabric hints");
		rc = -ENOMEM;
		goto err;
	}
	hints->caps = (KFI_MSG | KFI_RMA | KFI_SEND | KFI_RECV | KFI_READ |
		       KFI_WRITE | KFI_REMOTE_READ | KFI_REMOTE_WRITE |
		       KFI_MULTI_RECV | KFI_RMA_EVENT | KFI_REMOTE_COMM);

	rc = kfi_getinfo(0, "0x0", "0", KFI_SOURCE, hints, &info);
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

	rc = kfi_rx_context(sep, 0, NULL, &rx, NULL);
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

	return 0;

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

/* Close all kfabric test objects. */
static void test_fini(void)
{
	kfi_close(&rx->fid);
	kfi_close(&sep->fid);
	kfi_close(&cq->fid);
	kfi_close(&av->fid);
	kfi_close(&domain->fid);
	kfi_close(&fabric->fid);
	kfi_freeinfo(info);
	kfi_freeinfo(hints);
}

/* Post a receive buffer and then cancel the operation. */
static int test_rx_cancel(void)
{
	void *recv_buf;
	size_t recv_buf_size = 1234;
	void *op_context = (void *)0xFFFAAAFFFAAA;
	struct kfi_cq_err_entry error;
	struct kfi_cq_data_entry comp_event;
	int rc;

	atomic_set(&event_count, 0);

	recv_buf = vzalloc(recv_buf_size);
	if (!recv_buf) {
		LOG_ERR("Failed to allocate recv buffer");
		return -ENOMEM;
	}

	/* Nothing to cancel. */
	rc = kfi_cancel(&rx->fid, op_context);
	if (rc != -ENOENT) {
		LOG_ERR("Cancel did not return -ENOENT");
		goto out;
	}

	rc = kfi_recv(rx, recv_buf, recv_buf_size, NULL, 0, op_context);
	if (rc) {
		LOG_ERR("Failed to post recv buffer");
		goto out;
	}

	rc = kfi_cancel(&rx->fid, op_context);
	if (rc) {
		LOG_ERR("Failed to submit cancel for recv operation");
		goto out;
	}

	rc = wait_event_timeout(wait_queue, atomic_read(&event_count) == 1,
				5 * HZ);
	if (rc == 0) {
		LOG_ERR("Timed out waiting for ECANCELED event");
		rc = -EIO;
		goto out;
	}

	rc = kfi_cq_readerr(cq, &error, 0);
	if (rc != 1) {
		LOG_ERR("Error not present on CQ");
		rc = -EIO;
		goto out;
	}

	if (error.op_context != op_context) {
		LOG_ERR("CQ error op context not correct");
		rc = -EIO;
		goto out;
	}

	if (error.flags != (KFI_MSG | KFI_RECV)) {
		LOG_ERR("CQ error flags not set to KFI MSG and KFI_RECV");
		rc = -EIO;
		goto out;
	}

	if (error.err != ECANCELED) {
		LOG_ERR("CQ error RC not set to ECANCELED");
		rc = -EIO;
		goto out;
	}

	/* Nothing to cancel. */
	rc = kfi_cancel(&rx->fid, op_context);
	if (rc != -ENOENT) {
		LOG_ERR("Cancel did not return -ENOENT");
		goto out;
	}

	/* Read the CQ again to verify it is drained which will rearm the CQ
	 * completion handler.
	 */
	rc = kfi_cq_read(cq, &comp_event, 1);
	if (rc != -EAGAIN) {
		LOG_ERR("%s: CQ not drained", __func__);
		goto out;
	}

	/* Success. */
	rc = 0;
out:
	vfree(recv_buf);
	return rc;
}

/* Post a tagged receive buffer and then cancel the operation. */
static int test_tagged_rx_cancel(void)
{
	void *recv_buf;
	size_t recv_buf_size = 1234;
	void *op_context = (void *)0xFFFAAAFFFAAA;
	struct kfi_cq_err_entry error;
	struct kfi_cq_data_entry comp_event;
	int rc;

	atomic_set(&event_count, 0);

	recv_buf = vzalloc(recv_buf_size);
	if (!recv_buf) {
		LOG_ERR("Failed to allocate recv buffer");
		return -ENOMEM;
	}

	/* Nothing to cancel. */
	rc = kfi_cancel(&rx->fid, op_context);
	if (rc != -ENOENT) {
		LOG_ERR("Cancel did not return -ENOENT");
		goto out;
	}

	rc = kfi_trecv(rx, recv_buf, recv_buf_size, NULL, 0, 0, 0, op_context);
	if (rc) {
		LOG_ERR("Failed to post recv buffer");
		goto out;
	}

	rc = kfi_cancel(&rx->fid, op_context);
	if (rc) {
		LOG_ERR("Failed to submit cancel for recv operation");
		goto out;
	}

	rc = wait_event_timeout(wait_queue, atomic_read(&event_count) == 1,
				5 * HZ);
	if (rc == 0) {
		LOG_ERR("Timed out waiting for ECANCELED event");
		rc = -EIO;
		goto out;
	}

	rc = kfi_cq_readerr(cq, &error, 0);
	if (rc != 1) {
		LOG_ERR("Error not present on CQ");
		rc = -EIO;
		goto out;
	}

	if (error.op_context != op_context) {
		LOG_ERR("CQ error op context not correct");
		rc = -EIO;
		goto out;
	}

	if (error.flags != (KFI_TAGGED | KFI_RECV)) {
		LOG_ERR("CQ error flags not set to KFI_TAGGED and KFI_RECV");
		rc = -EIO;
		goto out;
	}

	if (error.err != ECANCELED) {
		LOG_ERR("CQ error RC not set to ECANCELED");
		rc = -EIO;
		goto out;
	}

	/* Nothing to cancel. */
	rc = kfi_cancel(&rx->fid, op_context);
	if (rc != -ENOENT) {
		LOG_ERR("Cancel did not return -ENOENT");
		goto out;
	}

	/* Read the CQ again to verify it is drained which will rearm the CQ
	 * completion handler.
	 */
	rc = kfi_cq_read(cq, &comp_event, 1);
	if (rc != -EAGAIN) {
		LOG_ERR("%s: CQ not drained", __func__);
		goto out;
	}

	/* Success. */
	rc = 0;
out:
	vfree(recv_buf);
	return rc;
}

/* Allocate and start test threads. */
static int __init test_module_init(void)
{
	int rc;

	rc = test_init();
	if (rc)
		goto out;

	rc = test_rx_cancel();
	if (rc)
		goto out;

	rc = test_tagged_rx_cancel();

out:
	return rc;
}

/* Stop all test threads. */
static void __exit test_module_exit(void)
{
	test_fini();
}

module_init(test_module_init);
module_exit(test_module_exit);
MODULE_LICENSE("GPL v2");
