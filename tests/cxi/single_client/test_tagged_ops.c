/*
 * Kfabric fabric tests.
 * Copyright 2019-2024 Hewlett Packard Enterprise Development LP
 *
 * SPDX-License-Identifier: GPL-2.0
 */
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/random.h>
#include <linux/mm.h>
#include <kfi_errno.h>
#include <kfabric.h>
#include <kfi_log.h>
#include <kfi_domain.h>
#include <kfi_endpoint.h>
#include <kfi_tagged.h>
#include <linux/uio.h>
#include <linux/bvec.h>
#include <linux/scatterlist.h>
#include <linux/dma-mapping.h>

#include "../../../prov/cxi/kcxi_prov.h"

#ifdef MODULE_NAME
#undef MODULE_NAME
#endif
#define MODULE_NAME "test_tagged_ops"

static struct kfi_info *hints;
static struct kfi_info *info;
static struct kfid_fabric *fabric;
static struct kfid_domain *domain;
static struct kfid_av *av;
static struct kfid_cq *cq;
static struct kfid_ep *sep;
static struct kfid_ep *rx;
static struct kfid_ep *tx;
static struct device *device;

#define TX_BUF_SIZE (PAGE_SIZE * 4)
#define RX_BUF_SIZE TX_BUF_SIZE
static void *rx_buffer;
static void *tx_buffer;
static struct bio_vec rx_bvec[RX_BUF_SIZE / PAGE_SIZE];
static struct bio_vec tx_bvec[TX_BUF_SIZE / PAGE_SIZE];
static struct sg_table rx_sgt;
static struct sg_table tx_sgt;

static char *node = "0x0";
static char *service = "0";
static kfi_addr_t loopback_addr;

static char *src_addr_service = "3";
static kfi_addr_t src_addr;

#define TIMEOUT_SEC 5
#define SENDDATA 0xBEEFFULL

static DECLARE_WAIT_QUEUE_HEAD(wait_queue);
static atomic_t event_count = ATOMIC_INIT(0);

MODULE_AUTHOR("Cray Inc.");
MODULE_DESCRIPTION("kfabric CXI tagged operation test");
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
	struct kfi_cxi_domain_ops *dom_ops;
	struct scatterlist *sg;
	int rc;
	int i;

	atomic_set(&event_count, 0);

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("Failed to allocate fabric hints");
		rc = -ENOMEM;
		goto err;
	}
	hints->caps = KFI_SEND | KFI_RECV | KFI_READ | KFI_REMOTE_COMM |
		KFI_TAGGED | KFI_DIRECTED_RECV;

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

	device = NULL;
	rc = kfi_open_ops(&domain->fid, KFI_CXI_DOM_OPS_1, 0,
				(void **)&dom_ops, NULL);
	if (!rc) {
		rc = dom_ops->get_device(&domain->fid, &device);
		if (rc) {
			LOG_ERR("Failed to get device");
			goto err_free_domain;
		}
	}

	av_attr.type = KFI_AV_UNSPEC;
	av_attr.rx_ctx_bits = 4;
	rc = kfi_av_open(domain, &av_attr, &av, NULL);
	if (rc) {
		LOG_ERR("Failed to create address vector");
		goto err_free_domain;
	}

	cq_attr.format = KFI_CQ_FORMAT_TAGGED;
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

	rx_attr.op_flags = KFI_COMPLETION;
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

	tx_attr.caps = KFI_SEND | KFI_TAGGED;
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

	rx_buffer = kmalloc(RX_BUF_SIZE, GFP_KERNEL);
	if (!rx_buffer) {
		rc = -ENOMEM;
		goto err_free_tx;
	}

	tx_buffer = kmalloc(TX_BUF_SIZE, GFP_KERNEL);
	if (!tx_buffer) {
		rc = -ENOMEM;
		goto err_free_rx_buffer;
	}

	for (i = 0; i < ARRAY_SIZE(rx_bvec); i++) {
		rx_bvec[i].bv_page = alloc_page(GFP_KERNEL);
		if (!rx_bvec[i].bv_page) {
			rc = -ENOMEM;
			goto err_free_rx_bvec;
		}
		rx_bvec[i].bv_len = PAGE_SIZE;
	}

	for (i = 0; i < ARRAY_SIZE(tx_bvec); i++) {
		tx_bvec[i].bv_page = alloc_page(GFP_KERNEL);
		if (!tx_bvec[i].bv_page) {
			rc = -ENOMEM;
			goto err_free_tx_bvec;
		}
		tx_bvec[i].bv_len = PAGE_SIZE;
	}

	rc = sg_alloc_table(&rx_sgt, ARRAY_SIZE(rx_bvec), GFP_KERNEL);
	if (rc)
		goto err_free_tx_bvec;

	sg = rx_sgt.sgl;
	for (i = 0; i < ARRAY_SIZE(rx_bvec); i++) {
		sg_set_page(sg, rx_bvec[i].bv_page,
			rx_bvec[i].bv_len,
			rx_bvec[i].bv_offset);
		sg = sg_next(sg);
	}

	rc = dma_map_sgtable(device, &rx_sgt, DMA_BIDIRECTIONAL, 0);
	if (rc) {
		goto err_free_rx_sgt;
	}

	rc = sg_alloc_table(&tx_sgt, ARRAY_SIZE(tx_bvec), GFP_KERNEL);
	if (rc)
		goto err_unmap_rx_sgt;

	sg = tx_sgt.sgl;
	for (i = 0; i < ARRAY_SIZE(tx_bvec); i++) {
		sg_set_page(sg, tx_bvec[i].bv_page,
			tx_bvec[i].bv_len,
			tx_bvec[i].bv_offset);
		sg = sg_next(sg);
	}

	rc = dma_map_sgtable(device, &tx_sgt, DMA_BIDIRECTIONAL, 0);
	if (rc) {
		goto err_free_tx_sgt;
	}

	rc = kfi_av_insertsvc(av, node, service, &loopback_addr, 0, NULL);
	if (rc < 0)
		goto err_unmap_tx_sgt;

	rc = kfi_av_insertsvc(av, node, src_addr_service, &src_addr, 0, NULL);
	if (rc < 0)
		goto err_unmap_tx_sgt;

	return 0;

err_unmap_tx_sgt:
	dma_unmap_sgtable(device, &tx_sgt, DMA_BIDIRECTIONAL, 0);
err_free_tx_sgt:
	sg_free_table(&tx_sgt);
err_unmap_rx_sgt:
	dma_unmap_sgtable(device, &rx_sgt, DMA_BIDIRECTIONAL, 0);
err_free_rx_sgt:
	sg_free_table(&rx_sgt);
err_free_tx_bvec:
	for (i = 0; i < ARRAY_SIZE(tx_bvec); i++) {
		if (tx_bvec[i].bv_page) {
			__free_page(tx_bvec[i].bv_page);
			tx_bvec[i].bv_page = NULL;
		}
	}
err_free_rx_bvec:
	for (i = 0; i < ARRAY_SIZE(rx_bvec); i++) {
		if (rx_bvec[i].bv_page) {
			__free_page(rx_bvec[i].bv_page);
			rx_bvec[i].bv_page = NULL;
		}
	}
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
	int i;

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

	dma_unmap_sgtable(device, &tx_sgt, DMA_BIDIRECTIONAL, 0);
	sg_free_table(&tx_sgt);
	dma_unmap_sgtable(device, &rx_sgt, DMA_BIDIRECTIONAL, 0);
	sg_free_table(&rx_sgt);

	for (i = 0; i < ARRAY_SIZE(tx_bvec); i++) {
		__free_page(tx_bvec[i].bv_page);
		tx_bvec[i].bv_page = NULL;
	}

	for (i = 0; i < ARRAY_SIZE(rx_bvec); i++) {
		__free_page(rx_bvec[i].bv_page);
		rx_bvec[i].bv_page = NULL;
	}
}

static int verify_init_error(void)
{
	int rc;
	struct kfi_cq_tagged_entry event;
	struct kfi_cq_err_entry error;

	rc = wait_event_timeout(wait_queue, atomic_read(&event_count),
				TIMEOUT_SEC * HZ);
	if (!rc) {
		LOG_ERR("Timeout waiting for CQ event");
		return -ETIMEDOUT;
	}

	rc = kfi_cq_read(cq, &event, 1);
	if (rc != -KFI_EAVAIL) {
		LOG_ERR("No error event reported");
		return -EIO;
	}

	rc = kfi_cq_readerr(cq, &error, 0);
	if (rc < 0) {
		LOG_ERR("No CQ error present: rc=%d", rc);
		return -EINVAL;
	}

	if (error.flags != (KFI_SEND | KFI_TAGGED)) {
		LOG_ERR("Bad error flags");
		return -EIO;
	}

	if (error.op_context != tx) {
		LOG_ERR("Bad tagged send event operation context");
		return -EIO;
	}

	return 0;
}

static int _verify_events(uint64_t tag, bool cq_data)
{
	int rc;
	struct kfi_cq_tagged_entry event;
	int i;
	uint64_t rx_flags = KFI_RECV | KFI_TAGGED;
	uint64_t rx_data = 0;

	if (cq_data) {
		rx_flags |= KFI_REMOTE_CQ_DATA;
		rx_data = SENDDATA;
	}

	rc = wait_event_timeout(wait_queue, atomic_read(&event_count),
				TIMEOUT_SEC * HZ);
	if (!rc) {
		LOG_ERR("Timeout waiting for CQ event");
		return -ETIMEDOUT;
	}

	for (i = 0; i < 2; i++) {
		rc = kfi_cq_read(cq, &event, 1);
		if (rc != 1) {
			LOG_ERR("Failed to read CQ event");
			return -EIO;
		}

		if (event.flags == (KFI_SEND | KFI_TAGGED)) {
			if (event.op_context != tx) {
				LOG_ERR("Bad tagged send event operation context");
				return -EIO;
			}

			if (event.len != 0) {
				LOG_ERR("Bad tagged send length");
				return -EIO;
			}

			if (event.buf != NULL) {
				LOG_ERR("Bad tagged send buffer");
				return -EIO;
			}

			if (event.data != 0) {
				LOG_ERR("Bad tagged send data");
				return -EIO;
			}

			if (event.tag != 0) {
				LOG_ERR("Bad tagged send tag");
				return -EIO;
			}

		} else if (event.flags == rx_flags) {
			if (event.op_context != rx) {
				LOG_ERR("Bad tagged recv event operation context");
				return -EIO;
			}

			if (event.len != RX_BUF_SIZE) {
				LOG_ERR("Bad tagged recv length");
				return -EIO;
			}

			if (event.buf != NULL) {
				LOG_ERR("Bad tagged recv buffer");
				return -EIO;
			}

			if (event.data != rx_data) {
				LOG_ERR("Bad tagged recv data");
				return -EIO;
			}

			if (event.tag != tag) {
				LOG_ERR("Bad tagged recv tag");
				return -EIO;
			}

		} else {
			LOG_ERR("Unknown CQ event: flags=0x%llx", event.flags);
			return -EIO;
		}
	}

	return 0;
}

static int verify_events(uint64_t tag)
{
	return _verify_events(tag, false);
}

static int verify_events_cq_data(uint64_t tag)
{
	return _verify_events(tag, true);
}

/* Verify that tagged send without ignore bits work. */
static int test_tsend_no_ignore(int id)
{
	uint64_t tag = 0x1234567;
	int rc;

	rc = test_init();
	if (rc) {
		LOG_ERR("Failed to initialize test: rc=%d", rc);
		goto err;
	}

	rc = kfi_trecv(rx, rx_buffer, RX_BUF_SIZE, NULL, KFI_ADDR_UNSPEC, tag,
		       0, rx);
	if (rc) {
		LOG_ERR("Failed to post tagged receive buffer: rc=%d", rc);
		goto err_cleanup;
	}

	rc = kfi_tsend(tx, tx_buffer, TX_BUF_SIZE, NULL, loopback_addr, tag,
		       tx);
	if (rc) {
		LOG_ERR("Failed to post tagged send buffer: rc=%d", rc);
		goto err_cleanup;
	}


	rc = verify_events(tag);
	if (rc) {
		LOG_ERR("Failed to verify events: rc=%d", rc);
		goto err_cleanup;
	}

	test_fini();

	LOG_INFO("TEST %d PASSED: %s", id, __func__);

	return 0;

err_cleanup:
	test_fini();
err:
	LOG_ERR("TEST %d FAILED: %s", id, __func__);

	return rc;
}

/* Verify that tagged send kvec without ignore bits work. */
static int test_tsendv_no_ignore(int id)
{
	uint64_t tag = 0x9875b;
	int rc;
	struct kvec send_iov = {};
	struct kvec recv_iov = {};

	rc = test_init();
	if (rc) {
		LOG_ERR("Failed to initialize test: rc=%d", rc);
		goto err;
	}

	send_iov.iov_base = tx_buffer;
	send_iov.iov_len = TX_BUF_SIZE;
	recv_iov.iov_base = rx_buffer;
	recv_iov.iov_len = RX_BUF_SIZE;

	rc = kfi_trecvv(rx, &recv_iov, NULL, 1, KFI_ADDR_UNSPEC, tag, 0, rx);
	if (rc) {
		LOG_ERR("Failed to post tagged receive buffer: rc=%d", rc);
		goto err_cleanup;
	}

	rc = kfi_tsendv(tx, &send_iov, NULL, 1, loopback_addr, tag, tx);
	if (rc) {
		LOG_ERR("Failed to post tagged send buffer: rc=%d", rc);
		goto err_cleanup;
	}

	rc = verify_events(tag);
	if (rc) {
		LOG_ERR("Failed to verify events: rc=%d", rc);
		goto err_cleanup;
	}

	test_fini();

	LOG_INFO("TEST %d PASSED: %s", id, __func__);

	return 0;

err_cleanup:
	test_fini();
err:
	LOG_ERR("TEST %d FAILED: %s", id, __func__);

	return rc;
}

/* Verify that tagged send bvec without ignore bits work. */
static int test_tsendbv_no_ignore(int id)
{
	uint64_t tag = 0x9875b;
	int rc;

	rc = test_init();
	if (rc) {
		LOG_ERR("Failed to initialize test: rc=%d", rc);
		goto err;
	}

	rc = kfi_trecvbv(rx, rx_bvec, NULL, ARRAY_SIZE(rx_bvec),
			 KFI_ADDR_UNSPEC, tag, 0, rx);
	if (rc) {
		LOG_ERR("Failed to post tagged receive buffer: rc=%d", rc);
		goto err_cleanup;
	}

	rc = kfi_tsendbv(tx, tx_bvec, NULL, ARRAY_SIZE(tx_bvec), loopback_addr,
			 tag, tx);
	if (rc) {
		LOG_ERR("Failed to post tagged send buffer: rc=%d", rc);
		goto err_cleanup;
	}

	rc = verify_events(tag);
	if (rc) {
		LOG_ERR("Failed to verify events: rc=%d", rc);
		goto err_cleanup;
	}

	test_fini();

	LOG_INFO("TEST %d PASSED: %s", id, __func__);

	return 0;

err_cleanup:
	test_fini();
err:
	LOG_ERR("TEST %d FAILED: %s", id, __func__);

	return rc;
}

/* Verify that tagged send sgl without ignore bits work. */
static int test_tsendsgl_no_ignore(int id)
{
	uint64_t tag = 0x9875b;
	int rc;

	rc = test_init();
	if (rc) {
		LOG_ERR("Failed to initialize test: rc=%d", rc);
		goto err;
	}

	rc = kfi_trecvsgl(rx, rx_sgt.sgl, NULL, rx_sgt.nents,
			 KFI_ADDR_UNSPEC, tag, 0, rx);
	if (rc) {
		LOG_ERR("Failed to post tagged receive buffer: rc=%d", rc);
		goto err_cleanup;
	}

	rc = kfi_tsendsgl(tx, tx_sgt.sgl, NULL, tx_sgt.nents, loopback_addr,
			 tag, tx);
	if (rc) {
		LOG_ERR("Failed to post tagged send buffer: rc=%d", rc);
		goto err_cleanup;
	}

	rc = verify_events(tag);
	if (rc) {
		LOG_ERR("Failed to verify events: rc=%d", rc);
		goto err_cleanup;
	}

	test_fini();

	LOG_INFO("TEST %d PASSED: %s", id, __func__);

	return 0;

err_cleanup:
	test_fini();
err:
	LOG_ERR("TEST %d FAILED: %s", id, __func__);

	return rc;
}

/* Verify that tagged send message without ignore bits work. */
static int test_tsendmsg_no_ignore(int id)
{
	uint64_t tag = 0x1234567;
	struct kfi_msg_tagged rx_msg = {};
	struct kfi_msg_tagged tx_msg = {};
	struct kvec send_iov = {};
	struct kvec recv_iov = {};
	int rc;

	rc = test_init();
	if (rc) {
		LOG_ERR("Failed to initialize test: rc=%d", rc);
		goto err;
	}

	send_iov.iov_base = tx_buffer;
	send_iov.iov_len = TX_BUF_SIZE;

	recv_iov.iov_base = rx_buffer;
	recv_iov.iov_len = RX_BUF_SIZE;

	rx_msg.type = KFI_KVEC;
	rx_msg.msg_iov = &recv_iov;
	rx_msg.iov_count = 1;
	rx_msg.addr = KFI_ADDR_UNSPEC;
	rx_msg.tag = tag;
	rx_msg.context = rx;

	tx_msg.type = KFI_KVEC;
	tx_msg.msg_iov = &send_iov;
	tx_msg.iov_count = 1;
	tx_msg.addr = loopback_addr;
	tx_msg.tag = tag;
	tx_msg.context = tx;

	rc = kfi_trecvmsg(rx, &rx_msg, KFI_COMPLETION);
	if (rc) {
		LOG_ERR("Failed to post tagged receive buffer: rc=%d", rc);
		goto err_cleanup;
	}

	rc = kfi_tsendmsg(tx, &tx_msg, KFI_COMPLETION);
	if (rc) {
		LOG_ERR("Failed to post tagged send buffer: rc=%d", rc);
		goto err_cleanup;
	}


	rc = verify_events(tag);
	if (rc) {
		LOG_ERR("Failed to verify events: rc=%d", rc);
		goto err_cleanup;
	}

	test_fini();

	LOG_INFO("TEST %d PASSED: %s", id, __func__);

	return 0;

err_cleanup:
	test_fini();
err:
	LOG_ERR("TEST %d FAILED: %s", id, __func__);

	return rc;
}

/* Verify that tagged send with ignore bits work. */
static int test_tsend_ignore(int id)
{
	uint64_t ignore = 0xFFFF;
	uint64_t recv_tag = 0x10000;
	uint64_t tag = ignore | recv_tag;
	int rc;

	rc = test_init();
	if (rc) {
		LOG_ERR("Failed to initialize test: rc=%d", rc);
		goto err;
	}

	rc = kfi_trecv(rx, rx_buffer, RX_BUF_SIZE, NULL, KFI_ADDR_UNSPEC,
		       recv_tag, ignore, rx);
	if (rc) {
		LOG_ERR("Failed to post tagged receive buffer: rc=%d", rc);
		goto err_cleanup;
	}

	rc = kfi_tsend(tx, tx_buffer, TX_BUF_SIZE, NULL, loopback_addr, tag,
		       tx);
	if (rc) {
		LOG_ERR("Failed to post tagged send buffer: rc=%d", rc);
		goto err_cleanup;
	}


	rc = verify_events(tag);
	if (rc) {
		LOG_ERR("Failed to verify events: rc=%d", rc);
		goto err_cleanup;
	}

	test_fini();

	LOG_INFO("TEST %d PASSED: %s", id, __func__);

	return 0;

err_cleanup:
	test_fini();
err:
	LOG_ERR("TEST %d FAILED: %s", id, __func__);

	return rc;
}

/* Verify that tagged send kvec with ignore bits work. */
static int test_tsendv_ignore(int id)
{
	uint64_t ignore = 0xFFFF;
	uint64_t recv_tag = 0x10000;
	uint64_t tag = ignore | recv_tag;
	int rc;
	struct kvec send_iov = {};
	struct kvec recv_iov = {};

	rc = test_init();
	if (rc) {
		LOG_ERR("Failed to initialize test: rc=%d", rc);
		goto err;
	}

	send_iov.iov_base = tx_buffer;
	send_iov.iov_len = TX_BUF_SIZE;
	recv_iov.iov_base = rx_buffer;
	recv_iov.iov_len = RX_BUF_SIZE;

	rc = kfi_trecvv(rx, &recv_iov, NULL, 1, KFI_ADDR_UNSPEC, recv_tag,
			ignore, rx);
	if (rc) {
		LOG_ERR("Failed to post tagged receive buffer: rc=%d", rc);
		goto err_cleanup;
	}

	rc = kfi_tsendv(tx, &send_iov, NULL, 1, loopback_addr, tag, tx);
	if (rc) {
		LOG_ERR("Failed to post tagged send buffer: rc=%d", rc);
		goto err_cleanup;
	}

	rc = verify_events(tag);
	if (rc) {
		LOG_ERR("Failed to verify events: rc=%d", rc);
		goto err_cleanup;
	}

	test_fini();

	LOG_INFO("TEST %d PASSED: %s", id, __func__);

	return 0;

err_cleanup:
	test_fini();
err:
	LOG_ERR("TEST %d FAILED: %s", id, __func__);

	return rc;
}

/* Verify that tagged send bvec with ignore bits work. */
static int test_tsendbv_ignore(int id)
{
	uint64_t ignore = 0xFFFF;
	uint64_t recv_tag = 0x10000;
	uint64_t tag = ignore | recv_tag;
	int rc;

	rc = test_init();
	if (rc) {
		LOG_ERR("Failed to initialize test: rc=%d", rc);
		goto err;
	}

	rc = kfi_trecvbv(rx, rx_bvec, NULL, ARRAY_SIZE(rx_bvec),
			 KFI_ADDR_UNSPEC, recv_tag, ignore, rx);
	if (rc) {
		LOG_ERR("Failed to post tagged receive buffer: rc=%d", rc);
		goto err_cleanup;
	}

	rc = kfi_tsendbv(tx, tx_bvec, NULL, ARRAY_SIZE(tx_bvec), loopback_addr,
			 tag, tx);
	if (rc) {
		LOG_ERR("Failed to post tagged send buffer: rc=%d", rc);
		goto err_cleanup;
	}

	rc = verify_events(tag);
	if (rc) {
		LOG_ERR("Failed to verify events: rc=%d", rc);
		goto err_cleanup;
	}

	test_fini();

	LOG_INFO("TEST %d PASSED: %s", id, __func__);

	return 0;

err_cleanup:
	test_fini();
err:
	LOG_ERR("TEST %d FAILED: %s", id, __func__);

	return rc;
}

/* Verify that tagged send sgl with ignore bits work. */
static int test_tsendsgl_ignore(int id)
{
	uint64_t ignore = 0xFFFF;
	uint64_t recv_tag = 0x10000;
	uint64_t tag = ignore | recv_tag;
	int rc;

	rc = test_init();
	if (rc) {
		LOG_ERR("Failed to initialize test: rc=%d", rc);
		goto err;
	}

	rc = kfi_trecvsgl(rx, rx_sgt.sgl, NULL, rx_sgt.nents,
			 KFI_ADDR_UNSPEC, recv_tag, ignore, rx);
	if (rc) {
		LOG_ERR("Failed to post tagged receive buffer: rc=%d", rc);
		goto err_cleanup;
	}

	rc = kfi_tsendsgl(tx, tx_sgt.sgl, NULL, tx_sgt.nents, loopback_addr,
			 tag, tx);
	if (rc) {
		LOG_ERR("Failed to post tagged send buffer: rc=%d", rc);
		goto err_cleanup;
	}

	rc = verify_events(tag);
	if (rc) {
		LOG_ERR("Failed to verify events: rc=%d", rc);
		goto err_cleanup;
	}

	test_fini();

	LOG_INFO("TEST %d PASSED: %s", id, __func__);

	return 0;

err_cleanup:
	test_fini();
err:
	LOG_ERR("TEST %d FAILED: %s", id, __func__);

	return rc;
}

/* Verify that tagged send message with ignore bits work. */
static int test_tsendmsg_ignore(int id)
{
	uint64_t ignore = 0xFFFF;
	uint64_t recv_tag = 0x10000;
	uint64_t tag = ignore | recv_tag;
	struct kfi_msg_tagged rx_msg = {};
	struct kfi_msg_tagged tx_msg = {};
	struct kvec send_iov = {};
	struct kvec recv_iov = {};
	int rc;

	rc = test_init();
	if (rc) {
		LOG_ERR("Failed to initialize test: rc=%d", rc);
		goto err;
	}

	send_iov.iov_base = tx_buffer;
	send_iov.iov_len = TX_BUF_SIZE;

	recv_iov.iov_base = rx_buffer;
	recv_iov.iov_len = RX_BUF_SIZE;

	rx_msg.type = KFI_KVEC;
	rx_msg.msg_iov = &recv_iov;
	rx_msg.iov_count = 1;
	rx_msg.addr = KFI_ADDR_UNSPEC;
	rx_msg.tag = recv_tag;
	rx_msg.ignore = ignore;
	rx_msg.context = rx;

	tx_msg.type = KFI_KVEC;
	tx_msg.msg_iov = &send_iov;
	tx_msg.iov_count = 1;
	tx_msg.addr = loopback_addr;
	tx_msg.tag = tag;
	tx_msg.context = tx;

	rc = kfi_trecvmsg(rx, &rx_msg, KFI_COMPLETION);
	if (rc) {
		LOG_ERR("Failed to post tagged receive buffer: rc=%d", rc);
		goto err_cleanup;
	}

	rc = kfi_tsendmsg(tx, &tx_msg, KFI_COMPLETION);
	if (rc) {
		LOG_ERR("Failed to post tagged send buffer: rc=%d", rc);
		goto err_cleanup;
	}

	rc = verify_events(tag);
	if (rc) {
		LOG_ERR("Failed to verify events: rc=%d", rc);
		goto err_cleanup;
	}

	test_fini();

	LOG_INFO("TEST %d PASSED: %s", id, __func__);

	return 0;

err_cleanup:
	test_fini();
err:
	LOG_ERR("TEST %d FAILED: %s", id, __func__);

	return rc;
}

/* Verify that tagged send with invalid tag bits is rejected. CXI provider does
 * not support all 64 bits.
 */
static int test_tsend_invalid_tag(int id)
{
	uint64_t tag = -1;
	int rc;

	rc = test_init();
	if (rc) {
		LOG_ERR("Failed to initialize test: rc=%d", rc);
		goto err;
	}

	rc = kfi_tsend(tx, tx_buffer, TX_BUF_SIZE, NULL, loopback_addr, tag,
		       tx);
	if (!rc) {
		LOG_ERR("Tagged send buffer should not have been posted");
		rc = -EIO;
		goto err_cleanup;
	}

	if (rc != -EINVAL) {
		LOG_ERR("Invalid RC: expected=%d got=%d", -EINVAL, rc);
		goto err_cleanup;
	}

	test_fini();

	LOG_INFO("TEST %d PASSED: %s", id, __func__);

	return 0;

err_cleanup:
	test_fini();
err:
	LOG_ERR("TEST %d FAILED: %s", id, __func__);

	return rc;
}

/* Verify that tagged kvec send with invalid tag bits is rejected. CXI provider
 * does not support all 64 bits.
 */
static int test_tsendv_invalid_tag(int id)
{
	uint64_t tag = -1;
	int rc;
	struct kvec send_iov = {};

	rc = test_init();
	if (rc) {
		LOG_ERR("Failed to initialize test: rc=%d", rc);
		goto err;
	}

	send_iov.iov_base = tx_buffer;
	send_iov.iov_len = TX_BUF_SIZE;

	rc = kfi_tsendv(tx, &send_iov, NULL, 1, loopback_addr, tag, tx);
	if (!rc) {
		LOG_ERR("Tagged send buffer should not have been posted");
		rc = -EIO;
		goto err_cleanup;
	}

	if (rc != -EINVAL) {
		LOG_ERR("Invalid RC: expected=%d got=%d", -EINVAL, rc);
		goto err_cleanup;
	}

	test_fini();

	LOG_INFO("TEST %d PASSED: %s", id, __func__);

	return 0;

err_cleanup:
	test_fini();
err:
	LOG_ERR("TEST %d FAILED: %s", id, __func__);

	return rc;
}

/* Verify that tagged bvec send with invalid tag bits is rejected. CXI provider
 * does not support all 64 bits.
 */
static int test_tsendbv_invalid_tag(int id)
{
	uint64_t tag = -1;
	int rc;

	rc = test_init();
	if (rc) {
		LOG_ERR("Failed to initialize test: rc=%d", rc);
		goto err;
	}

	rc = kfi_tsendbv(tx, tx_bvec, NULL, ARRAY_SIZE(tx_bvec), loopback_addr,
			 tag, tx);
	if (!rc) {
		LOG_ERR("Tagged send buffer should not have been posted");
		rc = -EIO;
		goto err_cleanup;
	}

	if (rc != -EINVAL) {
		LOG_ERR("Invalid RC: expected=%d got=%d", -EINVAL, rc);
		goto err_cleanup;
	}

	test_fini();

	LOG_INFO("TEST %d PASSED: %s", id, __func__);

	return 0;

err_cleanup:
	test_fini();
err:
	LOG_ERR("TEST %d FAILED: %s", id, __func__);

	return rc;
}

/* Verify that tagged sgl send with invalid tag bits is rejected. CXI provider
 * does not support all 64 bits.
 */
static int test_tsendsgl_invalid_tag(int id)
{
	uint64_t tag = -1;
	int rc;

	rc = test_init();
	if (rc) {
		LOG_ERR("Failed to initialize test: rc=%d", rc);
		goto err;
	}

	rc = kfi_tsendsgl(tx, tx_sgt.sgl, NULL, tx_sgt.nents, loopback_addr,
			 tag, tx);
	if (!rc) {
		LOG_ERR("Tagged send buffer should not have been posted");
		rc = -EIO;
		goto err_cleanup;
	}

	if (rc != -EINVAL) {
		LOG_ERR("Invalid RC: expected=%d got=%d", -EINVAL, rc);
		goto err_cleanup;
	}

	test_fini();

	LOG_INFO("TEST %d PASSED: %s", id, __func__);

	return 0;

err_cleanup:
	test_fini();
err:
	LOG_ERR("TEST %d FAILED: %s", id, __func__);

	return rc;
}

/* Verify that tagged msg send with invalid tag bits is rejected. CXI provider
 * does not support all 64 bits.
 */
static int test_tsendmsg_invalid_tag(int id)
{
	uint64_t tag = -1;
	int rc;
	struct kfi_msg_tagged tx_msg = {};
	struct kvec send_iov = {};

	rc = test_init();
	if (rc) {
		LOG_ERR("Failed to initialize test: rc=%d", rc);
		goto err;
	}

	send_iov.iov_base = tx_buffer;
	send_iov.iov_len = TX_BUF_SIZE;

	tx_msg.type = KFI_KVEC;
	tx_msg.msg_iov = &send_iov;
	tx_msg.iov_count = 1;
	tx_msg.addr = loopback_addr;
	tx_msg.tag = tag;
	tx_msg.context = tx;

	rc = kfi_tsendmsg(tx, &tx_msg, KFI_COMPLETION);
	if (!rc) {
		LOG_ERR("Tagged send buffer should not have been posted");
		rc = -EIO;
		goto err_cleanup;
	}

	if (rc != -EINVAL) {
		LOG_ERR("Invalid RC: expected=%d got=%d", -EINVAL, rc);
		goto err_cleanup;
	}

	test_fini();

	LOG_INFO("TEST %d PASSED: %s", id, __func__);

	return 0;

err_cleanup:
	test_fini();
err:
	LOG_ERR("TEST %d FAILED: %s", id, __func__);

	return rc;
}

/* Verify that tagged recv with invalid tag bits is rejected. CXI provider
 * does not support all 64 bits.
 */
static int test_trecv_invalid_tag(int id)
{
	uint64_t tag = -1;
	int rc;

	rc = test_init();
	if (rc) {
		LOG_ERR("Failed to initialize test: rc=%d", rc);
		goto err;
	}

	rc = kfi_trecv(rx, rx_buffer, RX_BUF_SIZE, NULL, KFI_ADDR_UNSPEC, tag,
		       0, rx);
	if (!rc) {
		LOG_ERR("Tagged recv buffer should not have been posted");
		rc = -EIO;
		goto err_cleanup;
	}

	if (rc != -EINVAL) {
		LOG_ERR("Invalid RC: expected=%d got=%d", -EINVAL, rc);
		goto err_cleanup;
	}

	test_fini();

	LOG_INFO("TEST %d PASSED: %s", id, __func__);

	return 0;

err_cleanup:
	test_fini();
err:
	LOG_ERR("TEST %d FAILED: %s", id, __func__);

	return rc;
}

/* Verify that tagged recv with invalid ignore bits is rejected. CXI provider
 * does not support all 64 bits.
 */
static int test_trecv_invalid_ignore(int id)
{
	uint64_t ignore = -1;
	int rc;

	rc = test_init();
	if (rc) {
		LOG_ERR("Failed to initialize test: rc=%d", rc);
		goto err;
	}

	rc = kfi_trecv(rx, rx_buffer, RX_BUF_SIZE, NULL, 0, KFI_ADDR_UNSPEC,
		       ignore, rx);
	if (!rc) {
		LOG_ERR("Tagged recv buffer should not have been posted");
		rc = -EIO;
		goto err_cleanup;
	}

	if (rc != -EINVAL) {
		LOG_ERR("Invalid RC: expected=%d got=%d", -EINVAL, rc);
		goto err_cleanup;
	}

	test_fini();

	LOG_INFO("TEST %d PASSED: %s", id, __func__);

	return 0;

err_cleanup:
	test_fini();
err:
	LOG_ERR("TEST %d FAILED: %s", id, __func__);

	return rc;
}

/* Verify that tagged kvec recv with invalid tag bits is rejected. CXI
 * provider does not support all 64 bits.
 */
static int test_trecvv_invalid_tag(int id)
{
	uint64_t tag = -1;
	int rc;
	struct kvec recv_iov = {};

	rc = test_init();
	if (rc) {
		LOG_ERR("Failed to initialize test: rc=%d", rc);
		goto err;
	}

	recv_iov.iov_base = rx_buffer;
	recv_iov.iov_len = RX_BUF_SIZE;

	rc = kfi_trecvv(rx, &recv_iov, NULL, 1, KFI_ADDR_UNSPEC, tag, 0, rx);
	if (!rc) {
		LOG_ERR("Tagged recv buffer should not have been posted");
		rc = -EIO;
		goto err_cleanup;
	}

	if (rc != -EINVAL) {
		LOG_ERR("Invalid RC: expected=%d got=%d", -EINVAL, rc);
		goto err_cleanup;
	}

	test_fini();

	LOG_INFO("TEST %d PASSED: %s", id, __func__);

	return 0;

err_cleanup:
	test_fini();
err:
	LOG_ERR("TEST %d FAILED: %s", id, __func__);

	return rc;
}

/* Verify that tagged kvec recv with invalid ignore bits is rejected. CXI
 * provider does not support all 64 bits.
 */
static int test_trecvv_invalid_ignore(int id)
{
	uint64_t ignore = -1;
	int rc;
	struct kvec recv_iov = {};

	rc = test_init();
	if (rc) {
		LOG_ERR("Failed to initialize test: rc=%d", rc);
		goto err;
	}

	recv_iov.iov_base = rx_buffer;
	recv_iov.iov_len = RX_BUF_SIZE;

	rc = kfi_trecvv(rx, &recv_iov, NULL, 1, KFI_ADDR_UNSPEC, 0, ignore, rx);
	if (!rc) {
		LOG_ERR("Tagged recv buffer should not have been posted");
		rc = -EIO;
		goto err_cleanup;
	}

	if (rc != -EINVAL) {
		LOG_ERR("Invalid RC: expected=%d got=%d", -EINVAL, rc);
		goto err_cleanup;
	}

	test_fini();

	LOG_INFO("TEST %d PASSED: %s", id, __func__);

	return 0;

err_cleanup:
	test_fini();
err:
	LOG_ERR("TEST %d FAILED: %s", id, __func__);

	return rc;
}

/* Verify that tagged bvec recv with invalid tag bits is rejected. CXI
 * provider does not support all 64 bits.
 */
static int test_trecvbv_invalid_tag(int id)
{
	uint64_t tag = -1;
	int rc;

	rc = test_init();
	if (rc) {
		LOG_ERR("Failed to initialize test: rc=%d", rc);
		goto err;
	}

	rc = kfi_trecvbv(rx, rx_bvec, NULL, ARRAY_SIZE(rx_bvec),
			 KFI_ADDR_UNSPEC, tag, 0, rx);
	if (!rc) {
		LOG_ERR("Tagged recv buffer should not have been posted");
		rc = -EIO;
		goto err_cleanup;
	}

	if (rc != -EINVAL) {
		LOG_ERR("Invalid RC: expected=%d got=%d", -EINVAL, rc);
		goto err_cleanup;
	}

	test_fini();

	LOG_INFO("TEST %d PASSED: %s", id, __func__);

	return 0;

err_cleanup:
	test_fini();
err:
	LOG_ERR("TEST %d FAILED: %s", id, __func__);

	return rc;
}

/* Verify that tagged bvec recv with invalid ignore bits is rejected. CXI
 * provider does not support all 64 bits.
 */
static int test_trecvbv_invalid_ignore(int id)
{
	uint64_t ignore = -1;
	int rc;

	rc = test_init();
	if (rc) {
		LOG_ERR("Failed to initialize test: rc=%d", rc);
		goto err;
	}

	rc = kfi_trecvbv(rx, rx_bvec, NULL, ARRAY_SIZE(rx_bvec),
			 KFI_ADDR_UNSPEC, 0, ignore, rx);
	if (!rc) {
		LOG_ERR("Tagged recv buffer should not have been posted");
		rc = -EIO;
		goto err_cleanup;
	}

	if (rc != -EINVAL) {
		LOG_ERR("Invalid RC: expected=%d got=%d", -EINVAL, rc);
		goto err_cleanup;
	}

	test_fini();

	LOG_INFO("TEST %d PASSED: %s", id, __func__);

	return 0;

err_cleanup:
	test_fini();
err:
	LOG_ERR("TEST %d FAILED: %s", id, __func__);

	return rc;
}

/* Verify that tagged sgl recv with invalid tag bits is rejected. CXI
 * provider does not support all 64 bits.
 */
static int test_trecvsgl_invalid_tag(int id)
{
	uint64_t tag = -1;
	int rc;

	rc = test_init();
	if (rc) {
		LOG_ERR("Failed to initialize test: rc=%d", rc);
		goto err;
	}

	rc = kfi_trecvsgl(rx, rx_sgt.sgl, NULL, rx_sgt.nents,
			 KFI_ADDR_UNSPEC, tag, 0, rx);
	if (!rc) {
		LOG_ERR("Tagged recv buffer should not have been posted");
		rc = -EIO;
		goto err_cleanup;
	}

	if (rc != -EINVAL) {
		LOG_ERR("Invalid RC: expected=%d got=%d", -EINVAL, rc);
		goto err_cleanup;
	}

	test_fini();

	LOG_INFO("TEST %d PASSED: %s", id, __func__);

	return 0;

err_cleanup:
	test_fini();
err:
	LOG_ERR("TEST %d FAILED: %s", id, __func__);

	return rc;
}

/* Verify that tagged sgl recv with invalid ignore bits is rejected. CXI
 * provider does not support all 64 bits.
 */
static int test_trecvsgl_invalid_ignore(int id)
{
	uint64_t ignore = -1;
	int rc;

	rc = test_init();
	if (rc) {
		LOG_ERR("Failed to initialize test: rc=%d", rc);
		goto err;
	}

	rc = kfi_trecvsgl(rx, rx_sgt.sgl, NULL, rx_sgt.nents,
			 KFI_ADDR_UNSPEC, 0, ignore, rx);
	if (!rc) {
		LOG_ERR("Tagged recv buffer should not have been posted");
		rc = -EIO;
		goto err_cleanup;
	}

	if (rc != -EINVAL) {
		LOG_ERR("Invalid RC: expected=%d got=%d", -EINVAL, rc);
		goto err_cleanup;
	}

	test_fini();

	LOG_INFO("TEST %d PASSED: %s", id, __func__);

	return 0;

err_cleanup:
	test_fini();
err:
	LOG_ERR("TEST %d FAILED: %s", id, __func__);

	return rc;
}

/* Verify that tagged msg recv with invalid tag bits is rejected. CXI
 * provider does not support all 64 bits.
 */
static int test_trecvmsg_invalid_tag(int id)
{
	uint64_t tag = -1;
	struct kfi_msg_tagged rx_msg = {};
	struct kvec recv_iov = {};
	int rc;

	rc = test_init();
	if (rc) {
		LOG_ERR("Failed to initialize test: rc=%d", rc);
		goto err;
	}

	recv_iov.iov_base = rx_buffer;
	recv_iov.iov_len = RX_BUF_SIZE;

	rx_msg.type = KFI_KVEC;
	rx_msg.msg_iov = &recv_iov;
	rx_msg.iov_count = 1;
	rx_msg.addr = KFI_ADDR_UNSPEC;
	rx_msg.tag = tag;
	rx_msg.context = rx;

	rc = kfi_trecvmsg(rx, &rx_msg, KFI_COMPLETION);
	if (!rc) {
		LOG_ERR("Tagged recv buffer should not have been posted");
		rc = -EIO;
		goto err_cleanup;
	}

	if (rc != -EINVAL) {
		LOG_ERR("Invalid RC: expected=%d got=%d", -EINVAL, rc);
		goto err_cleanup;
	}

	test_fini();

	LOG_INFO("TEST %d PASSED: %s", id, __func__);

	return 0;

err_cleanup:
	test_fini();
err:
	LOG_ERR("TEST %d FAILED: %s", id, __func__);

	return rc;
}

/* Verify that tagged msg recv with invalid ignore bits is rejected. CXI
 * provider does not support all 64 bits.
 */
static int test_trecvmsg_invalid_ignore(int id)
{
	uint64_t ignore = -1;
	struct kfi_msg_tagged rx_msg = {};
	struct kvec recv_iov = {};
	int rc;

	rc = test_init();
	if (rc) {
		LOG_ERR("Failed to initialize test: rc=%d", rc);
		goto err;
	}

	recv_iov.iov_base = rx_buffer;
	recv_iov.iov_len = RX_BUF_SIZE;

	rx_msg.type = KFI_KVEC;
	rx_msg.msg_iov = &recv_iov;
	rx_msg.iov_count = 1;
	rx_msg.ignore = ignore;
	rx_msg.addr = KFI_ADDR_UNSPEC;
	rx_msg.context = rx;

	rc = kfi_trecvmsg(rx, &rx_msg, KFI_COMPLETION);
	if (!rc) {
		LOG_ERR("Tagged recv buffer should not have been posted");
		rc = -EIO;
		goto err_cleanup;
	}

	if (rc != -EINVAL) {
		LOG_ERR("Invalid RC: expected=%d got=%d", -EINVAL, rc);
		goto err_cleanup;
	}

	test_fini();

	LOG_INFO("TEST %d PASSED: %s", id, __func__);

	return 0;

err_cleanup:
	test_fini();
err:
	LOG_ERR("TEST %d FAILED: %s", id, __func__);

	return rc;
}

/* Verify that tagged senddata without ignore bits work. */
static int test_tsenddata_no_ignore(int id)
{
	uint64_t tag = 0x1234567;
	int rc;

	rc = test_init();
	if (rc) {
		LOG_ERR("Failed to initialize test: rc=%d", rc);
		goto err;
	}

	rc = kfi_trecv(rx, rx_buffer, RX_BUF_SIZE, NULL, KFI_ADDR_UNSPEC, tag,
		       0, rx);
	if (rc) {
		LOG_ERR("Failed to post tagged receive buffer: rc=%d", rc);
		goto err_cleanup;
	}

	rc = kfi_tsenddata(tx, tx_buffer, TX_BUF_SIZE, NULL, SENDDATA,
			   loopback_addr, tag, tx);
	if (rc) {
		LOG_ERR("Failed to post tagged send buffer: rc=%d", rc);
		goto err_cleanup;
	}

	rc = verify_events_cq_data(tag);
	if (rc) {
		LOG_ERR("Failed to verify events: rc=%d", rc);
		goto err_cleanup;
	}

	test_fini();

	LOG_INFO("TEST %d PASSED: %s", id, __func__);

	return 0;

err_cleanup:
	test_fini();
err:
	LOG_ERR("TEST %d FAILED: %s", id, __func__);

	return rc;
}

/* Verify that tagged senddata without ignore bits work. */
static int test_tsenddata_no_ignore_src_addr(int id)
{
	uint64_t tag = 0x1234567;
	int rc;

	rc = test_init();
	if (rc) {
		LOG_ERR("Failed to initialize test: rc=%d", rc);
		goto err;
	}

	rc = kfi_trecv(rx, rx_buffer, RX_BUF_SIZE, NULL, loopback_addr, tag, 0,
		       rx);
	if (rc) {
		LOG_ERR("Failed to post tagged receive buffer: rc=%d", rc);
		goto err_cleanup;
	}

	rc = kfi_tsenddata(tx, tx_buffer, TX_BUF_SIZE, NULL, SENDDATA,
			   loopback_addr, tag, tx);
	if (rc) {
		LOG_ERR("Failed to post tagged send buffer: rc=%d", rc);
		goto err_cleanup;
	}

	rc = verify_events_cq_data(tag);
	if (rc) {
		LOG_ERR("Failed to verify events: rc=%d", rc);
		goto err_cleanup;
	}

	test_fini();

	LOG_INFO("TEST %d PASSED: %s", id, __func__);

	return 0;

err_cleanup:
	test_fini();
err:
	LOG_ERR("TEST %d FAILED: %s", id, __func__);

	return rc;
}

static int test_src_addr_no_matching_init(int id)
{
	uint64_t ignore = 0xFFFF;
	uint64_t recv_tag = 0x10000;
	uint64_t tag = ignore | recv_tag;
	int rc;

	rc = test_init();
	if (rc) {
		LOG_ERR("Failed to initialize test: rc=%d", rc);
		goto err;
	}

	rc = kfi_trecvbv(rx, rx_bvec, NULL, ARRAY_SIZE(rx_bvec), src_addr,
			 recv_tag, ignore, rx);
	if (rc) {
		LOG_ERR("Failed to post tagged receive buffer: rc=%d", rc);
		goto err_cleanup;
	}

	rc = kfi_tsendbv(tx, tx_bvec, NULL, ARRAY_SIZE(tx_bvec), loopback_addr,
			 tag, tx);
	if (rc) {
		LOG_ERR("Failed to post tagged send buffer: rc=%d", rc);
		goto err_cleanup;
	}

	/* Verify that this send fails since it does not match the receive
	 * buffer source address.
	 */
	rc = verify_init_error();
	if (rc) {
		LOG_ERR("Failed to verify init error event: rc=%d", rc);
		goto err_cleanup;
	}

	test_fini();

	LOG_INFO("TEST %d PASSED: %s", id, __func__);

	return 0;

err_cleanup:
	test_fini();
err:
	LOG_ERR("TEST %d FAILED: %s", id, __func__);

	return rc;
}


/* Verify that tagged send message using sgl works. */
static int test_tsendmsg_sgl(int id)
{
	uint64_t tag = 0x1234567;
	struct kfi_msg_tagged rx_msg = {};
	struct kfi_msg_tagged tx_msg = {};
	int rc;

	rc = test_init();
	if (rc) {
		LOG_ERR("Failed to initialize test: rc=%d", rc);
		goto err;
	}

	rx_msg.type = KFI_SGL;
	rx_msg.msg_sgl = rx_sgt.sgl;
	rx_msg.iov_count = rx_sgt.nents;
	rx_msg.addr = KFI_ADDR_UNSPEC;
	rx_msg.tag = tag;
	rx_msg.context = rx;

	tx_msg.type = KFI_SGL;
	tx_msg.msg_sgl = tx_sgt.sgl;
	tx_msg.iov_count = tx_sgt.nents;
	tx_msg.addr = loopback_addr;
	tx_msg.tag = tag;
	tx_msg.context = tx;

	rc = kfi_trecvmsg(rx, &rx_msg, KFI_COMPLETION);
	if (rc) {
		LOG_ERR("Failed to post tagged receive buffer: rc=%d", rc);
		goto err_cleanup;
	}

	rc = kfi_tsendmsg(tx, &tx_msg, KFI_COMPLETION);
	if (rc) {
		LOG_ERR("Failed to post tagged send buffer: rc=%d", rc);
		goto err_cleanup;
	}


	rc = verify_events(tag);
	if (rc) {
		LOG_ERR("Failed to verify events: rc=%d", rc);
		goto err_cleanup;
	}

	test_fini();

	LOG_INFO("TEST %d PASSED: %s", id, __func__);

	return 0;

err_cleanup:
	test_fini();
err:
	LOG_ERR("TEST %d FAILED: %s", id, __func__);

	return rc;
}

static int __init test_module_init(void)
{
	int exit_rc = 0;
	int test_id = 1;
	int rc;

	rc = test_tsend_no_ignore(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_tsendv_no_ignore(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_tsendbv_no_ignore(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_tsendsgl_no_ignore(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_tsendmsg_no_ignore(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_tsend_ignore(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_tsendv_ignore(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_tsendbv_ignore(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_tsendsgl_ignore(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_tsendmsg_ignore(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_tsend_invalid_tag(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_tsendv_invalid_tag(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_tsendbv_invalid_tag(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_tsendsgl_invalid_tag(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_tsendmsg_invalid_tag(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_trecv_invalid_tag(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_trecv_invalid_ignore(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_trecvv_invalid_tag(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_trecvv_invalid_ignore(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_trecvbv_invalid_tag(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_trecvbv_invalid_ignore(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_trecvsgl_invalid_tag(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_trecvsgl_invalid_ignore(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_trecvmsg_invalid_tag(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_trecvmsg_invalid_ignore(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_tsenddata_no_ignore(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_tsenddata_no_ignore_src_addr(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_src_addr_no_matching_init(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_tsendmsg_sgl(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	if (!exit_rc)
		LOG_INFO("ALL TESTS PASSED");

	return exit_rc;
}

/* Stop all test threads. */
static void __exit test_module_exit(void)
{}

module_init(test_module_init);
module_exit(test_module_exit);
