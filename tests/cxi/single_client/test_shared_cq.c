//SPDX-License-Identifier: GPL-2.0
/*
 * Share CQ test. A single CQ will be shared between two TX contexts and two RX
 * contexts. A message operation will occur between all these contexts. All
 * events should be funneled to the same CQ without errors.
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
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/random.h>
#include <linux/mm.h>
#include <linux/atomic.h>
#include <linux/vmalloc.h>

static struct kfi_info *hints;
static struct kfi_info *info;
static struct kfid_fabric *fabric;
static struct kfid_domain *domain;
static struct kfid_av *av;
static struct kfid_cq *cq;
static struct kfid_ep *sep;
static struct kfid_ep *rx1;
static struct kfid_ep *rx2;
static struct kfid_ep *tx1;
static struct kfid_ep *tx2;

#define BUF_SIZE 16384
static void *rx1_buffer;
static void *rx2_buffer;
static void *tx1_buffer;
static void *tx2_buffer;

static char *node = "0x0";
static char *service = "0";
static kfi_addr_t loopback_addr;

#define TIMEOUT_SEC 5

static DECLARE_WAIT_QUEUE_HEAD(wait_queue);
static atomic_t event_count = ATOMIC_INIT(0);

static void test_cq_cb(struct kfid_cq *cq, void *context)
{
	atomic_inc(&event_count);
	wake_up(&wait_queue);
}

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
	rc = kfi_av_open(domain, &av_attr, &av, NULL);
	if (rc) {
		LOG_ERR("Failed to create address vector");
		goto err_free_domain;
	}

	cq_attr.format = KFI_CQ_FORMAT_CONTEXT;
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

	rc = kfi_rx_context(sep, 0, NULL, &rx1, NULL);
	if (rc) {
		LOG_ERR("Failed to allocate RX1 context");
		goto err_free_sep;
	}

	rc = kfi_ep_bind(rx1, &cq->fid, 0);
	if (rc) {
		LOG_ERR("Failed to bind CQ to RX1 context");
		goto err_free_rx1;
	}

	rc = kfi_enable(rx1);
	if (rc) {
		LOG_ERR("Failed enable RX1 CTX");
		goto err_free_rx1;
	}

	rc = kfi_rx_context(sep, 1, NULL, &rx2, NULL);
	if (rc) {
		LOG_ERR("Failed to allocate RX2 context");
		goto err_free_rx1;
	}

	rc = kfi_ep_bind(rx2, &cq->fid, 0);
	if (rc) {
		LOG_ERR("Failed to bind CQ to RX2 context");
		goto err_free_rx2;
	}

	rc = kfi_enable(rx2);
	if (rc) {
		LOG_ERR("Failed enable RX2 CTX");
		goto err_free_rx2;
	}

	rc = kfi_tx_context(sep, 0, NULL, &tx1, NULL);
	if (rc) {
		LOG_ERR("Failed to allocate TX1 context");
		goto err_free_rx2;
	}

	rc = kfi_ep_bind(tx1, &cq->fid, 0);
	if (rc) {
		LOG_ERR("Failed to bind CQ to TX1 context");
		goto err_free_tx1;
	}

	rc = kfi_enable(tx1);
	if (rc) {
		LOG_ERR("Failed enable TX1 CTX");
		goto err_free_tx1;
	}

	rc = kfi_tx_context(sep, 1, NULL, &tx2, NULL);
	if (rc) {
		LOG_ERR("Failed to allocate TX2 context");
		goto err_free_tx1;
	}

	rc = kfi_ep_bind(tx2, &cq->fid, 0);
	if (rc) {
		LOG_ERR("Failed to bind CQ to TX2 context");
		goto err_free_tx2;
	}

	rc = kfi_enable(tx2);
	if (rc) {
		LOG_ERR("Failed enable TX2 CTX");
		goto err_free_tx2;
	}

	rx1_buffer = vmalloc(BUF_SIZE);
	if (!rx1_buffer) {
		rc = -ENOMEM;
		goto err_free_tx2;
	}

	rx2_buffer = vmalloc(BUF_SIZE);
	if (!rx2_buffer) {
		rc = -ENOMEM;
		goto err_free_rx1_buffer;
	}

	tx1_buffer = vmalloc(BUF_SIZE);
	if (!tx1_buffer) {
		rc = -ENOMEM;
		goto err_free_rx2_buffer;
	}

	tx2_buffer = vmalloc(BUF_SIZE);
	if (!tx2_buffer) {
		rc = -ENOMEM;
		goto err_free_tx1_buffer;
	}

	rc = kfi_av_insertsvc(av, node, service, &loopback_addr, 0, NULL);
	if (rc < 0)
		goto err_free_tx2_buffer;

	return 0;

err_free_tx2_buffer:
	vfree(tx2_buffer);
err_free_tx1_buffer:
	vfree(tx1_buffer);
err_free_rx2_buffer:
	vfree(rx2_buffer);
err_free_rx1_buffer:
	vfree(rx1_buffer);
err_free_tx2:
	kfi_close(&tx2->fid);
err_free_tx1:
	kfi_close(&tx1->fid);
err_free_rx2:
	kfi_close(&rx2->fid);
err_free_rx1:
	kfi_close(&rx1->fid);
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
	kfi_close(&tx2->fid);
	kfi_close(&tx1->fid);
	kfi_close(&rx2->fid);
	kfi_close(&rx1->fid);
	kfi_close(&sep->fid);
	kfi_close(&cq->fid);
	kfi_close(&av->fid);
	kfi_close(&domain->fid);
	kfi_close(&fabric->fid);
	kfi_freeinfo(info);
	kfi_freeinfo(hints);

	vfree(tx2_buffer);
	vfree(tx1_buffer);
	vfree(rx2_buffer);
	vfree(rx1_buffer);
}

static int post_rx_buffers(void)
{
	int rc;

	rc = kfi_recv(rx1, rx1_buffer, BUF_SIZE, NULL, 0, rx1);
	if (rc)
		return rc;

	rc = kfi_recv(rx2, rx2_buffer, BUF_SIZE, NULL, 0, rx2);

	return rc;
}

static int post_tx_buffers(void)
{
	int rc;

	/* Named RX contexts are not enabled. This means that the TX context
	 * index is used to identify the RX context index.
	 */
	rc = kfi_send(tx1, tx1_buffer, BUF_SIZE, NULL, loopback_addr, tx1);
	if (rc)
		return rc;

	rc = kfi_send(tx2, tx2_buffer, BUF_SIZE, NULL, loopback_addr, tx2);

	return rc;
}

static int process_cq(void)
{
	int rc;
	int cq_events = 0;
	struct kfi_cq_entry event;
	int i;

again:
	/* Wait for callback to be triggered to unblock this thread. */
	rc = wait_event_timeout(wait_queue, atomic_read(&event_count),
				TIMEOUT_SEC * HZ);
	if (!rc) {
		LOG_ERR("Timeout waiting for CQ event");
		return -ETIMEDOUT;
	}

	/* Ack the current event count. */
	for (i = 0; i < atomic_read(&event_count); i++)
		atomic_dec(&event_count);

	/* Should expect four success events: two send and two receive. */
	while (true) {
		rc = kfi_cq_read(cq, &event, 1);
		if (rc == 1) {
			if (event.op_context != rx1 &&
			    event.op_context != rx2 &&
			    event.op_context != tx1 &&
			    event.op_context != tx2) {
				LOG_ERR("Bad CQ event data");
				return -EIO;
			}

			cq_events++;
			continue;
		} else if (rc == -EAGAIN) {
			break;
		}

		LOG_ERR("Unexpected CQ rc=%d", rc);
		return rc;
	}

	if (cq_events < 4)
		goto again;

	return 0;
}

static int __init test_module_init(void)
{
	int rc;

	rc = test_init();
	if (rc)
		goto error;

	rc = post_rx_buffers();
	if (rc)
		goto error_cleanup;

	rc = post_tx_buffers();
	if (rc)
		goto error_cleanup;

	rc = process_cq();
	if (rc)
		goto error_cleanup;

	return 0;

error_cleanup:
	test_fini();
error:
	return rc;
}

static void __exit test_module_exit(void)
{
	test_fini();
}

module_init(test_module_init);
module_exit(test_module_exit);
MODULE_LICENSE("GPL v2");
