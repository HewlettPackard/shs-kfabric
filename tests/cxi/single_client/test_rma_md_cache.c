// SPDX-License-Identifier: GPL-2.0
/* Copyright 2024 Hewlett Packard Enterprise Development LP */
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
#include <linux/bvec.h>
#include <linux/pci.h>

#include "../../../prov/cxi/kcxi_prov.h"

#ifdef MODULE_NAME
#undef MODULE_NAME
#endif
#define MODULE_NAME "test_rma_md_cache"

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

/* Make the buffers twice as big as the md cache buffer size */
#define TX_BUF_SIZE (MAX_MD_CACHE_BUFSIZE * 2)
#define TX_VEC_CNT (TX_BUF_SIZE / PAGE_SIZE)
#define RX_BUF_SIZE TX_BUF_SIZE
#define RX_VEC_CNT TX_VEC_CNT
static struct bio_vec rx_bvec[RX_VEC_CNT];
static struct bio_vec tx_bvec[TX_VEC_CNT];
static struct kvec rx_kvec[RX_VEC_CNT];
static struct kvec tx_kvec[TX_VEC_CNT];
static struct sg_table rx_sgt[RX_VEC_CNT];
static struct sg_table tx_sgt[TX_VEC_CNT];

/* A buffer with this many bvec elements fits in a cached md */
#define CACHED_BVEC_CNT (MAX_MD_CACHE_BUFSIZE / PAGE_SIZE)

/* Limit the size of the cq, and thus the size of the md cache,
 * to a reasonable size for testing.
 * The md cache is half this value by default
 */
#define CQ_SIZE 32

static char *node = "0x0";
static char *service = "0";
static kfi_addr_t loopback_addr;

#define TIMEOUT_SEC 5U

static DECLARE_WAIT_QUEUE_HEAD(wait_queue);
static atomic_t event_count = ATOMIC_INIT(0);

MODULE_AUTHOR("Hewlett Packard Enterprise Development LP");
MODULE_DESCRIPTION("kfabric CXI rma md cache tests");
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
	int rc;
	int i;

	LOG_INFO("TEST INITIALIZATION STARTING: %s", __func__);

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
	cq_attr.size = CQ_SIZE;
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

	for (i = 0; i < ARRAY_SIZE(rx_kvec); i++) {
		rx_kvec[i].iov_base = kzalloc(PAGE_SIZE, GFP_KERNEL);
		if (!rx_kvec[i].iov_base) {
			rc = -ENOMEM;
			goto err_free_rx_kvec;
		}
		rx_kvec[i].iov_len = PAGE_SIZE;
	}

	for (i = 0; i < ARRAY_SIZE(tx_kvec); i++) {
		tx_kvec[i].iov_base = kzalloc(PAGE_SIZE, GFP_KERNEL);
		if (!tx_kvec[i].iov_base) {
			rc = -ENOMEM;
			goto err_free_tx_kvec;
		}
		tx_kvec[i].iov_len = PAGE_SIZE;
	}

	rc = kfi_av_insertsvc(av, node, service, &loopback_addr, 0, NULL);
	if (rc < 0)
		goto err_free_tx_bvec;

	/* sleep a second to allow link to become ready */
	msleep(1000);

	LOG_INFO("TEST INITIALIZATION COMPLETED: %s", __func__);

	return 0;

err_free_tx_kvec:
	for (i = 0; i < ARRAY_SIZE(tx_kvec); i++) {
		kfree(tx_kvec[i].iov_base);
		tx_kvec[i].iov_base = NULL;
	}
err_free_rx_kvec:
	for (i = 0; i < ARRAY_SIZE(rx_kvec); i++) {
		kfree(rx_kvec[i].iov_base);
		rx_kvec[i].iov_base = NULL;
	}
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

	LOG_INFO("TEST FINALIZATION STARTED: %s", __func__);

	kfi_close(&tx->fid);
	kfi_close(&rx->fid);
	kfi_close(&sep->fid);
	kfi_close(&cq->fid);
	kfi_close(&av->fid);
	kfi_close(&domain->fid);
	kfi_close(&fabric->fid);
	kfi_freeinfo(info);
	kfi_freeinfo(hints);

	for (i = 0; i < ARRAY_SIZE(tx_kvec); i++) {
		kfree(tx_kvec[i].iov_base);
		tx_kvec[i].iov_base = NULL;
	}

	for (i = 0; i < ARRAY_SIZE(rx_kvec); i++) {
		kfree(rx_kvec[i].iov_base);
		rx_kvec[i].iov_base = NULL;
	}

	for (i = 0; i < ARRAY_SIZE(tx_bvec); i++) {
		__free_page(tx_bvec[i].bv_page);
		tx_bvec[i].bv_page = NULL;
	}

	for (i = 0; i < ARRAY_SIZE(rx_bvec); i++) {
		__free_page(rx_bvec[i].bv_page);
		rx_bvec[i].bv_page = NULL;
	}

	LOG_INFO("TEST FINALIZATION COMPLETED: %s", __func__);
}

static int verify_events(uint64_t tag, size_t length)
{
	int rc;
	struct kfi_cq_tagged_entry event;
	int i;

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
				LOG_ERR("Bad tagged send tag 0x%llx", event.tag);
				return -EIO;
			}

		} else if (event.flags == (KFI_RECV | KFI_TAGGED)) {
			if (event.op_context != rx) {
				LOG_ERR("Bad tagged recv event operation context");
				return -EIO;
			}

			if (event.len != length) {
				LOG_ERR("Bad tagged recv length");
				return -EIO;
			}

			if (event.buf != NULL) {
				LOG_ERR("Bad tagged recv buffer");
				return -EIO;
			}

			if (event.data != 0) {
				LOG_ERR("Bad tagged recv data");
				return -EIO;
			}

			if (event.tag != tag) {
				LOG_ERR("Bad tagged recv tag 0x%llx", event.tag);
				return -EIO;
			}

		} else {
			LOG_ERR("Unknown CQ event: flags=0x%llx", event.flags);
			return -EIO;
		}
	}

	rc = kfi_cq_read(cq, &event, 1);
	if (rc != -EAGAIN) {
		LOG_ERR("CQ did not return EAGAIN: rc=%d", rc);
		return -EINVAL;
	}

	return 0;
}

static void reset_vecs(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(tx_kvec); i++) {
		tx_kvec[i].iov_len = PAGE_SIZE;
	}

	for (i = 0; i < ARRAY_SIZE(rx_kvec); i++) {
		rx_kvec[i].iov_len = PAGE_SIZE;
	}

	for (i = 0; i < ARRAY_SIZE(tx_bvec); i++) {
		tx_bvec[i].bv_len = PAGE_SIZE;
		tx_bvec[i].bv_offset = 0;
	}

	for (i = 0; i < ARRAY_SIZE(rx_bvec); i++) {
		rx_bvec[i].bv_len = PAGE_SIZE;
		rx_bvec[i].bv_offset = 0;
	}
}

/* Verify that tagged send works */
static int test_send_recv_vec(int id, int type, int buf_cnt, int buf_len, int offset, bool map, bool gaps)
{
	uint64_t tag = 0x123450;
	int page_cnt_kvec = DIV_ROUND_UP(buf_len, PAGE_SIZE);
	int page_cnt_bvec = DIV_ROUND_UP(buf_len + offset, PAGE_SIZE);
	int page_cnt = (type == KFI_KVEC) ? page_cnt_kvec : page_cnt_bvec;
	struct scatterlist *sg;
	int i, j, page;
	int rc;

	if (gaps && (type == KFI_BVEC || type == KFI_SGL)) {
		int nob = buf_len;
		page_cnt = 0;
		do {
			nob -= PAGE_SIZE - offset;
			page_cnt++;
		} while (nob > 0);
	}

	LOG_INFO("TEST %d SUBTEST STARTED: %s type %d bufs %d len %d off %d pages %d map %d gaps %d",
		id, __func__, type, buf_cnt, buf_len, offset, page_cnt, map, gaps);

	if (type != KFI_KVEC && type != KFI_BVEC && type != KFI_SGL) {
		LOG_ERR("Invalid iov type %d", type);
		rc = -EINVAL;
		goto err;
	}

	if (offset >= PAGE_SIZE) {
		LOG_ERR("Offset %d >= PAGE_SIZE (%ld)", offset, PAGE_SIZE);
		rc = -EINVAL;
		goto err;
	}

	if ((buf_cnt * page_cnt) > TX_VEC_CNT) {
		LOG_ERR("Requested buffers exceed allocated buffers");
		rc = -EINVAL;
		goto err;
	}

	atomic_set(&event_count, 0);

	page = 0;
	for (i = 0; i < buf_cnt; i++) {
		int len;
		int off = (type == KFI_KVEC) ? 0 : offset;
		int nob = buf_len;
		j = 0;
		do {
			if (nob < PAGE_SIZE)
				len = nob;
			else
				len = PAGE_SIZE - off;

			if (type == KFI_KVEC) {
				rx_kvec[page + j].iov_len = len;
				tx_kvec[page + j].iov_len = len;
			} else {
				rx_bvec[page + j].bv_len = len;
				rx_bvec[page + j].bv_offset = off;
				tx_bvec[page + j].bv_len = len;
				tx_bvec[page + j].bv_offset = off;
			}
			nob -= len;
			if (!gaps)
				off = 0;
			j++;
		} while (j < page_cnt);

		page += page_cnt;
	}

	page = 0;
	for (i = 0; i < buf_cnt; i++) {
		if (type == KFI_KVEC) {
			rc = kfi_trecvv(rx, &rx_kvec[page], NULL, page_cnt,
					KFI_ADDR_UNSPEC, tag + i, 0, rx);
		} else if (type == KFI_BVEC) {
			rc = kfi_trecvbv(rx, &rx_bvec[page], NULL, page_cnt,
					KFI_ADDR_UNSPEC, tag + i, 0, rx);
		} else {
			rc = sg_alloc_table(&rx_sgt[i], page_cnt, GFP_KERNEL);
			if (rc)
				goto err_unmap_rx;

			sg = rx_sgt[i].sgl;
			for (j = 0; j < page_cnt; j++) {
				sg_set_page(sg, rx_bvec[page + j].bv_page,
					rx_bvec[page + j].bv_len,
					rx_bvec[page + j].bv_offset);
				sg = sg_next(sg);
			}

			if (map) {
				rc = dma_map_sgtable(device, &rx_sgt[i], DMA_BIDIRECTIONAL, 0);
				if (rc) {
					LOG_ERR("Failed to map tagged receive buffer: rc=%d", rc);
					goto err_unmap_rx;
				}
			}
			rc = kfi_trecvsgl(rx, rx_sgt[i].sgl, NULL, rx_sgt[i].nents,
					KFI_ADDR_UNSPEC, tag + i, 0, rx);
		}
		if (rc) {
			LOG_ERR("Failed to post tagged receive buffer: rc=%d", rc);
			goto err_unmap_rx;
		}

		page += page_cnt;
	}

	page = 0;
	for (i = 0; i < buf_cnt; i++) {
		if (type == KFI_KVEC) {
			rc = kfi_tsendv(tx, &tx_kvec[page], NULL, page_cnt, loopback_addr,
					tag + i, tx);
		} else if (type == KFI_BVEC) {
			rc = kfi_tsendbv(tx, &tx_bvec[page], NULL, page_cnt, loopback_addr,
					tag + i, tx);
		} else {
			rc = sg_alloc_table(&tx_sgt[i], page_cnt, GFP_KERNEL);
			if (rc)
				goto err_unmap_tx;

			sg = tx_sgt[i].sgl;
			for (j = 0; j < page_cnt; j++) {
				sg_set_page(sg, tx_bvec[page + j].bv_page,
					tx_bvec[page + j].bv_len,
					tx_bvec[page + j].bv_offset);
				sg = sg_next(sg);
			}

			if (map) {
				rc = dma_map_sgtable(device, &tx_sgt[i], DMA_BIDIRECTIONAL, 0);
				if (rc) {
					LOG_ERR("Failed to map tagged send buffer: rc=%d", rc);
					goto err_unmap_tx;
				}
			}
			rc = kfi_tsendsgl(tx, tx_sgt[i].sgl, NULL, tx_sgt[i].nents, loopback_addr,
					tag + i, tx);
		}
		if (rc) {
			LOG_ERR("Failed to post tagged send buffer: rc=%d", rc);
			goto err_unmap_tx;
		}

		rc = verify_events(tag + i, buf_len);
		if (rc) {
			LOG_ERR("Failed to verify events: rc=%d", rc);
			goto err_unmap_tx;
		}

		page += page_cnt;
		atomic_set(&event_count, 0);
	}

	if (type == KFI_SGL) {
		for (i = 0; i < buf_cnt; i++) {
			dma_unmap_sgtable(device, &tx_sgt[i], DMA_BIDIRECTIONAL, 0);
			sg_free_table(&tx_sgt[i]);
			dma_unmap_sgtable(device, &rx_sgt[i], DMA_BIDIRECTIONAL, 0);
			sg_free_table(&rx_sgt[i]);
		}
	}

	reset_vecs();

	LOG_INFO("TEST %d SUBTEST PASSED: %s type %d bufs %d len %d off %d pages %d map %d gaps %d",
		id, __func__, type, buf_cnt, buf_len, offset, page_cnt, map, gaps);

	return 0;

err_unmap_tx:
	if (type == KFI_SGL) {
		for (i = 0; i < buf_cnt; i++) {
			dma_unmap_sgtable(device, &tx_sgt[i], DMA_BIDIRECTIONAL, 0);
			sg_free_table(&tx_sgt[i]);
		}
	}
err_unmap_rx:
	if (type == KFI_SGL) {
		for (i = 0; i < buf_cnt; i++) {
			dma_unmap_sgtable(device, &rx_sgt[i], DMA_BIDIRECTIONAL, 0);
			sg_free_table(&rx_sgt[i]);
		}
	}
err:
	reset_vecs();

	LOG_INFO("TEST %d SUBTEST FAILED: %s type %d bufs %d len %d off %d pages %d map %d gaps %d",
		id, __func__, type, buf_cnt, buf_len, offset, page_cnt, map, gaps);

	return rc;
}

/* Issue a RMA send operation to matching tagged buffer.
 * Uses an invalid buffer.
 */
static int test_send_one_vec_invalid(int id, int type)
{
	int buf_len;
	int offset = 0;
	int rc = -EINVAL;

	LOG_INFO("TEST %d STARTED: %s", id, __func__);

	/* unampped vec, only applies to SGL */
	if (type == KFI_SGL) {
		buf_len = PAGE_SIZE;
		offset = 0;
		rc = -EINVAL;
		rc = test_send_recv_vec(id, type, 1, buf_len, offset, false, false);
		if (!rc) {
			rc = -EINVAL;
			goto err;
		}
	}

	/* a small vec with gaps, cached */
	buf_len = PAGE_SIZE;
	offset = PAGE_SIZE / 2;
	rc = -EINVAL;
	rc = test_send_recv_vec(id, type, 1, buf_len, offset, true, true);
	if (!rc) {
		rc = -EINVAL;
		goto err;
	}

	/* a large vec with gaps, uncached */
	buf_len = ((CACHED_BVEC_CNT + 1) * PAGE_SIZE);
	offset = PAGE_SIZE / 4;
	rc = -EINVAL;
	rc = test_send_recv_vec(id, type, 1, buf_len, offset, true, true);
	if (!rc) {
		rc = -EINVAL;
		goto err;
	}

	rc = 0;

	LOG_INFO("TEST %d PASSED: %s", id, __func__);

	return rc;

err:
	LOG_INFO("TEST %d FAILED: %s", id, __func__);
	return rc;
}

/* Issue a RMA send operation to matching tagged buffer.
 * Uses a non-cached md.
 */
static int test_send_one_vec_uncached(int id, int type)
{
	int buf_len;
	int offset;
	int rc = 0;

	LOG_INFO("TEST %d STARTED: %s", id, __func__);

	/* a vec of a single page or less isn't cached */

	/* a vec of a partial page */
	buf_len = PAGE_SIZE/2;
	offset = 0;
	rc = test_send_recv_vec(id, type, 1, buf_len, offset, true, false);
	if (rc) {
		goto err;
	}

	/* a vec of a partial page with offset, use BVEC */
	if (type == KFI_BVEC) {
		buf_len = PAGE_SIZE/2;
		offset = PAGE_SIZE/4;
		rc = test_send_recv_vec(id, type, 1, buf_len, offset, true, false);
		if (rc) {
			goto err;
		}
	}

	/* a vec of a full page */
	buf_len = PAGE_SIZE;
	offset = 0;
	rc = test_send_recv_vec(id, type, 1, buf_len, offset, true, false);
	if (rc) {
		goto err;
	}

	LOG_INFO("TEST %d PASSED: %s", id, __func__);

	return rc;

err:
	LOG_INFO("TEST %d FAILED: %s", id, __func__);
	return rc;
}

/* Issue a RMA send operation to matching tagged buffer.
 * Uses a cached md.
 */
static int test_send_one_vec_cached(int id, int type)
{
	int buf_len;
	int offset;
	int rc = 0;

	LOG_INFO("TEST %d STARTED: %s", id, __func__);

	/* a vec of more than a page is cached */

	/* test one and a half pages */
	buf_len = 3 * PAGE_SIZE / 2;
	offset = 0;
	rc = test_send_recv_vec(id, type, 1, buf_len, offset, true, false);
	if (rc) {
		goto err;
	}

	/* test full two pages */
	buf_len = 2 * PAGE_SIZE;
	offset = 0;
	rc = test_send_recv_vec(id, type, 1, buf_len, offset, true, false);
	if (rc) {
		goto err;
	}

	/* test two half pages */
	buf_len = PAGE_SIZE;
	offset = PAGE_SIZE / 2;
	rc = test_send_recv_vec(id, type, 1, buf_len, offset, true, false);

	/* test one and a half pages with offset */
	buf_len = 3 * PAGE_SIZE / 2;
	offset = PAGE_SIZE / 2;
	rc = test_send_recv_vec(id, type, 1, buf_len, offset, true, false);

	/* test three pages with offset */
	buf_len = 2 * PAGE_SIZE;
	offset = PAGE_SIZE - (PAGE_SIZE / 4);
	rc = test_send_recv_vec(id, type, 1, buf_len, offset, true, false);

	LOG_INFO("TEST %d PASSED: %s", id, __func__);

	return rc;

err:
	LOG_INFO("TEST %d FAILED: %s", id, __func__);
	return rc;
}

/* Issue serveral RMA send operations to matching tagged buffers.
 * Uses several cached md.
 */
static int test_send_several_vec(int id, int type)
{
	int buf_len;
	int offset;
	int rc = 0;

	LOG_INFO("TEST %d STARTED: %s", id, __func__);


	/* test four buffers of two full pages each */
	buf_len = 2 * PAGE_SIZE;
	offset = 0;
	rc = test_send_recv_vec(id, type, 4, buf_len, offset, true, false);

	if (rc) {
		goto err;
	}

	LOG_INFO("TEST %d PASSED: %s", id, __func__);

	return rc;

err:
	LOG_INFO("TEST %d FAILED: %s", id, __func__);
	return rc;
}

/* Issue serveral RMA send operations to matching tagged buffers.
 * Use several sizes.
 */
static int test_send_several_vec_sizes(int id, int type)
{
	int buf_len;
	int offset;
	int i;
	int rc = 0;

	LOG_INFO("TEST %d STARTED: %s", id, __func__);

	/* test the cached buffer sizes (first isn't cached since it is page size) */
	for(i = 1; i <= CACHED_BVEC_CNT; i++) {
		buf_len = i * PAGE_SIZE;
		offset = 0;
		rc = test_send_recv_vec(id, type, 1, buf_len, offset, true, false);
		if (rc)
			goto err;
	}

	/* test an uncached buffer size, length larger than cached */
	buf_len = ((CACHED_BVEC_CNT + 1) * PAGE_SIZE);
	offset = 0;
	rc = test_send_recv_vec(id, type, 1, buf_len, offset, true, false);
	if (rc)
		goto err;

	/* test an uncached buffer size, length + offset larger than cached */
	buf_len = CACHED_BVEC_CNT * PAGE_SIZE;
	offset = PAGE_SIZE / 2;
	rc = test_send_recv_vec(id, type, 1, buf_len, offset, true, false);
	if (rc)
		goto err;

	/* test the largest buffer size configured (it won't be cached) */
	buf_len = RX_BUF_SIZE;
	offset = 0;
	rc = test_send_recv_vec(id, type, 1, buf_len, offset, true, false);
	if (rc)
		goto err;

	/* test more buffers than the cache can handle */
	buf_len = 2 * PAGE_SIZE;
	offset = 0;
	rc = test_send_recv_vec(id, type, CQ_SIZE, buf_len, offset, true, false);
	if (rc)
		goto err;

	LOG_INFO("TEST %d PASSED: %s", id, __func__);

	return rc;

err:
	LOG_INFO("TEST %d FAILED: %s", id, __func__);
	return rc;
}

static int __init test_module_init(void)
{
	int test_id = 1;
	int rc;

	rc = test_init();
	if (rc) {
		goto error;
	}

	rc = test_send_one_vec_invalid(test_id, KFI_BVEC);
	if (rc) {
		goto error_fini;
	}
	test_id++;

	rc = test_send_one_vec_invalid(test_id, KFI_SGL);
	if (rc) {
		goto error_fini;
	}
	test_id++;


	rc = test_send_one_vec_uncached(test_id, KFI_KVEC);
	if (rc) {
		goto error_fini;
	}
	test_id++;

	rc = test_send_one_vec_uncached(test_id, KFI_BVEC);
	if (rc) {
		goto error_fini;
	}
	test_id++;

	rc = test_send_one_vec_uncached(test_id, KFI_SGL);
	if (rc) {
		goto error_fini;
	}
	test_id++;


	rc = test_send_one_vec_cached(test_id, KFI_KVEC);
	if (rc) {
		goto error_fini;
	}
	test_id++;


	rc = test_send_one_vec_cached(test_id, KFI_BVEC);
	if (rc) {
		goto error_fini;
	}
	test_id++;

	rc = test_send_one_vec_cached(test_id, KFI_SGL);
	if (rc) {
		goto error_fini;
	}
	test_id++;


	rc = test_send_several_vec(test_id, KFI_KVEC);
	if (rc) {
		goto error_fini;
	}
	test_id++;

	rc = test_send_several_vec(test_id, KFI_BVEC);
	if (rc) {
		goto error_fini;
	}
	test_id++;

	rc = test_send_several_vec(test_id, KFI_SGL);
	if (rc) {
		goto error_fini;
	}
	test_id++;


	rc = test_send_several_vec_sizes(test_id, KFI_KVEC);
	if (rc) {
		goto error_fini;
	}
	test_id++;

	rc = test_send_several_vec_sizes(test_id, KFI_BVEC);
	if (rc) {
		goto error_fini;
	}
	test_id++;

	rc = test_send_several_vec_sizes(test_id, KFI_SGL);
	if (rc) {
		goto error_fini;
	}
	test_id++;

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
