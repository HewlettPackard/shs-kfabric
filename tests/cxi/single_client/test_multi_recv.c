//SPDX-License-Identifier: GPL-2.0
/*
 * Multi-receive test. Allocate a single RX context with a large multi-receive
 * buffer. Allocate two TX contexts. The first TX context will perform a large
 * write operation. The second TX context will perform a very small operation.
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
#include <kfi_tagged.h>
#include <kfi_errno.h>
#include <test_common.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/random.h>
#include <linux/mm.h>
#include <linux/atomic.h>
#include <linux/vmalloc.h>

#ifdef MODULE_NAME
#undef MODULE_NAME
#endif
#define MODULE_NAME "test_multi_recv"

static struct kfi_info *hints;
static struct kfi_info *info;
static struct kfid_fabric *fabric;
static struct kfid_domain *domain;
static struct kfid_av *av;
static struct kfid_cq *cq;
static struct kfid_ep *sep;
static struct kfid_ep *rx;
static struct kfid_ep *tx1;
static struct kfid_ep *tx2;
static uint64_t tag = 0x1234567;
static uint64_t tag_bad = 0x1234;

#define TX1_BUF_SIZE 2097152
#define TX2_BUF_SIZE 1
#define MIN_MULTI_RECV TX2_BUF_SIZE
#define RX_BUF_SIZE (TX1_BUF_SIZE + TX2_BUF_SIZE + MIN_MULTI_RECV - 1)
static void *rx_buffer;
static void *tx1_buffer;
static void *tx2_buffer;

static char *node = "0x0";
static char *service = "0";
static kfi_addr_t loopback_addr;

#define TIMEOUT_SEC 5
#define SENDDATA 0xCEEFFULL

static DECLARE_WAIT_QUEUE_HEAD(wait_queue);
static atomic_t event_count = ATOMIC_INIT(0);

static bool kmalloc_buf;
module_param(kmalloc_buf, bool, 0);
MODULE_PARM_DESC(kmalloc_buf, "Use kmalloc for buffer allocation");

static bool mode_tagged;
module_param(mode_tagged, bool, 0);
MODULE_PARM_DESC(mode_tagged, "If 0 UNTAGGED or else TAGGED");

MODULE_AUTHOR("Ian Ziemba");
MODULE_DESCRIPTION("kfabric CXI multi-recv test");
MODULE_LICENSE("GPL v2");

/* Since RX events may not occur in order, these TX pointers are set in the
 * order the RX context receive transmits.
 */
static void *rx1_buf;
static size_t rx1_len;
static void *rx2_buf;
static size_t rx2_len;

static void test_cq_cb(struct kfid_cq *cq, void *context)
{
	atomic_inc(&event_count);
	wake_up(&wait_queue);
}

static void *alloc_buffer(size_t size)
{
	if (kmalloc_buf)
		return kmalloc(size, GFP_KERNEL);
	else
		return vmalloc(size);
}

static void free_buffer(void *buffer)
{
	kvfree(buffer);
}

static int test_init(void)
{
	struct kfi_av_attr av_attr = {};
	struct kfi_cq_attr cq_attr = {};
	struct kfi_tx_attr tx_attr = {};
	struct kfi_rx_attr rx_attr = {};
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
		       KFI_MULTI_RECV | KFI_RMA_EVENT | KFI_REMOTE_COMM |
		       KFI_NAMED_RX_CTX);

	if (mode_tagged)
		hints->caps |= KFI_TAGGED | KFI_TAGGED_MULTI_RECV;

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

	if (mode_tagged)
		cq_attr.format = KFI_CQ_FORMAT_TAGGED;
	else
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

	rx_attr.op_flags = KFI_MULTI_RECV | KFI_COMPLETION;
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
	if (mode_tagged)
		tx_attr.caps |=  KFI_TAGGED;

	rc = kfi_tx_context(sep, 0, &tx_attr, &tx1, NULL);
	if (rc) {
		LOG_ERR("Failed to allocate TX1 context");
		goto err_free_rx;
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

	rc = kfi_tx_context(sep, 1, &tx_attr, &tx2, NULL);
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

	rx_buffer = alloc_buffer(RX_BUF_SIZE);
	if (!rx_buffer) {
		rc = -ENOMEM;
		goto err_free_tx2;
	}

	tx1_buffer = alloc_buffer(TX1_BUF_SIZE);
	if (!tx1_buffer) {
		rc = -ENOMEM;
		goto err_free_rx_buffer;
	}

	tx2_buffer = alloc_buffer(TX2_BUF_SIZE);
	if (!tx2_buffer) {
		rc = -ENOMEM;
		goto err_free_tx1_buffer;
	}

	rc = kfi_av_insertsvc(av, node, service, &loopback_addr, 0, NULL);
	if (rc < 0)
		goto err_free_tx2_buffer;

	rc = kfi_setopt(&rx->fid, KFI_OPT_ENDPOINT, KFI_OPT_MIN_MULTI_RECV,
			&min_multi_recv, sizeof(min_multi_recv));
	if (rc) {
		LOG_ERR("Failed to set min_recv");
		goto err_free_tx2_buffer;
	}

	/* Named RX context is enabled. Adjust loopback address to target RX
	 * context 0.
	 */
	loopback_addr = kfi_rx_addr(loopback_addr, 0, av_attr.rx_ctx_bits);

	return 0;

err_free_tx2_buffer:
	free_buffer(tx2_buffer);
err_free_tx1_buffer:
	free_buffer(tx1_buffer);
err_free_rx_buffer:
	free_buffer(rx_buffer);
err_free_tx2:
	kfi_close(&tx2->fid);
err_free_tx1:
	kfi_close(&tx1->fid);
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
	kfi_close(&tx2->fid);
	kfi_close(&tx1->fid);
	kfi_close(&rx->fid);
	kfi_close(&sep->fid);
	kfi_close(&cq->fid);
	kfi_close(&av->fid);
	kfi_close(&domain->fid);
	kfi_close(&fabric->fid);
	kfi_freeinfo(info);
	kfi_freeinfo(hints);

	free_buffer(tx2_buffer);
	free_buffer(tx1_buffer);
	free_buffer(rx_buffer);
}

static int post_rx_buffers(void)
{
	int rc;

	rc = kfi_recv(rx, rx_buffer, RX_BUF_SIZE, NULL, 0, rx);
	if (rc)
		LOG_ERR("Failed to post receive buffer: rc=%d", rc);

	return rc;
}

static int post_tx_buffers(void)
{
	int rc;

	/* Named RX contexts are not enabled. This means that the TX context
	 * index is used to identify the RX context index.
	 */
	rc = kfi_send(tx1, tx1_buffer, TX1_BUF_SIZE, NULL, loopback_addr, tx1);
	if (rc)
		LOG_ERR("Failed to post send buffer: rc=%d", rc);

	rc = kfi_send(tx2, tx2_buffer, TX2_BUF_SIZE, NULL, loopback_addr, tx2);
	if (rc)
		LOG_ERR("Failed to post send buffer: rc=%d", rc);

	return rc;
}

static int post_tagged_rx_buffers(void)
{
	int rc;

	rc = kfi_trecv(rx, rx_buffer, RX_BUF_SIZE, NULL, KFI_ADDR_UNSPEC, tag,
                       0, rx);
	if (rc)
		LOG_ERR("Failed to post tagged receive buffer: rc=%d", rc);

	return rc;
}

static int post_tagged_tx_buffers(void)
{
	int rc;

	/* Named RX contexts are not enabled. This means that the TX context
	 * index is used to identify the RX context index.
	 */
	rc = kfi_tsend(tx1, tx1_buffer, TX1_BUF_SIZE, NULL, loopback_addr, tag,
                       tx1);
	if (rc)
                LOG_ERR("Failed to post tagged send buffer: rc=%d", rc);

	rc = kfi_tsend(tx2, tx2_buffer, TX2_BUF_SIZE, NULL, loopback_addr, tag,
                       tx2);
        if (rc)
                LOG_ERR("Failed to post tagged send buffer: rc=%d", rc);

	return rc;
}

static int post_one_good_one_bad_tagged_tx_buffers(void)
{
	int rc;

	/* Named RX contexts are not enabled. This means that the TX context
	 * index is used to identify the RX context index.
	 */
	rc = kfi_tsend(tx1, tx1_buffer, TX1_BUF_SIZE, NULL, loopback_addr, tag_bad,
                       tx1);
	if (rc)
                LOG_ERR("Failed to post tagged send buffer with bad tag: rc=%d", rc);

	rc = kfi_tsend(tx2, tx2_buffer, TX2_BUF_SIZE, NULL, loopback_addr, tag,
                       tx2);
        if (rc)
                LOG_ERR("Failed to post tagged send buffer with good tag: rc=%d", rc);

	return rc;
}

/* 
 * This function handles the completion queue processing for the
 * test where we send one good tagged message and one bad tagged
 * message. The test will PASS if we receive one good tagged message
 * only. The bad tagged message will not be received. So here we are
 * expecting to catch two send events and one receive. One send event
 * will be caught in the error check when rc == -KFI_EAVAIL. So here 
 * we are expecting cq_events count to be 3. No need for mode_tagged
 * check here since this function is called only when mode_tagged = 1.
 */ 
static int process_one_good_one_bad_tagged_cq(void)
{
	int rc;
	int cq_events = 0;
	int rx_cq_events = 0;
	struct kfi_cq_tagged_entry event;
	struct kfi_cq_err_entry error;
	int i;
	int bad_tag_count = 0;

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

	while (true) {
		rc = kfi_cq_read(cq, &event, 1);
		if (rc == 1) {
			if (event.op_context != rx &&
			    event.op_context != tx1 &&
			    event.op_context != tx2) {
				LOG_ERR("Bad CQ event data");
				return -EIO;
			}

			if ((event.flags & ~KFI_MULTI_RECV) ==
			    (KFI_RECV | KFI_TAGGED)) {
				/* Target events are not in order. */
				if (rx_buffer != event.buf &&
				    (rx_buffer + TX1_BUF_SIZE) != event.buf &&
				    (rx_buffer + TX2_BUF_SIZE) != event.buf) {
					LOG_ERR("Bad multi-recv buf pointer");
					return -EIO;
				}

				rx_cq_events++;

				if (rx_cq_events == 1) {
					rx1_buf = event.buf;
					rx1_len = event.len;
				} else {
					rx2_buf = event.buf;
					rx2_len = event.len;
				}
			}
			if ((event.flags & ~KFI_MULTI_RECV) ==
			    (KFI_MSG | KFI_RECV)) {
				/* Target events are not in order. */
				if (rx_buffer != event.buf &&
				    (rx_buffer + TX1_BUF_SIZE) != event.buf &&
				    (rx_buffer + TX2_BUF_SIZE) != event.buf) {
					LOG_ERR("Bad multi-recv buf pointer");
					return -EIO;
				}

				rx_cq_events++;

				if (rx_cq_events == 1) {
					rx1_buf = event.buf;
					rx1_len = event.len;
				} else {
					rx2_buf = event.buf;
					rx2_len = event.len;
				}
			}

			if ((event.flags & KFI_MULTI_RECV) &&
			    rx_cq_events != 1) {
				LOG_ERR("Multi-receive prematurely returned %d", rx_cq_events);
				return -EIO;
			}

			cq_events++;
			continue;
		} else if (rc == -EAGAIN) {
			break;
		} else if (rc == -KFI_EAVAIL) {
		        rc = kfi_cq_readerr(cq, &error, 0);
		        if (rc < 0) {
                		LOG_ERR("No CQ error present: rc=%d", rc);
                		return -EINVAL;
        		}

        		if (error.flags != (KFI_SEND | KFI_TAGGED)) {
                		LOG_ERR("Bad error flags");
                		return -EIO;
        		}

        		if (error.op_context != tx1) {
                		LOG_ERR("Bad tagged send event operation context");
                		return -EIO;
        		}

			cq_events++;
			bad_tag_count++;
		}

		if (rx_cq_events != 1 && bad_tag_count != 1) {
			LOG_ERR("Unexpected CQ rc=%d", rc);
			return -EIO;
		}
	}

	if (cq_events < 3)
		goto again;

	return 0;
}

/* 
 * This function handles the completion queue processing for both the
 * tests - untagged multi recv and tagged multi recv. For the tagged test
 * we send two good tagged messages. For both the tests, we expect to receive
 * four events - two send and two receive, so cq_events should be 4. Here
 * we are using mode_tagged check because this handles for both tagged
 * and untagged tests.
 */ 
static int process_cq(void)
{
	int rc;
	int cq_events = 0;
	int rx_cq_events = 0;
	struct kfi_cq_tagged_entry event;
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
			if (event.op_context != rx &&
			    event.op_context != tx1 &&
			    event.op_context != tx2) {
				LOG_ERR("Bad CQ event data");
				return -EIO;
			}

			if ((mode_tagged &&
			     (event.flags & ~KFI_MULTI_RECV) ==
					(KFI_RECV | KFI_TAGGED)) ||
			    (!mode_tagged &&
			     ((event.flags & ~KFI_MULTI_RECV) ==
					(KFI_MSG | KFI_RECV)))) {
				/* Target events are not in order. */
				if (rx_buffer != event.buf &&
			    		(rx_buffer + TX1_BUF_SIZE) != event.buf &&
			    		(rx_buffer + TX2_BUF_SIZE) != event.buf) {
						LOG_ERR("Bad multi-recv buf pointer");
						return -EIO;
					}

				rx_cq_events++;

				if (rx_cq_events == 1) {
					rx1_buf = event.buf;
					rx1_len = event.len;
				} else {
					rx2_buf = event.buf;
					rx2_len = event.len;
				}
			}

			if ((event.flags & KFI_MULTI_RECV) &&
			    rx_cq_events != 2) {
				LOG_ERR("Multi-receive prematurely returned %d", rx_cq_events);
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

static int verify_one_good_one_bad_tagged_buffers(void)
{
	int rc;

	if (rx1_len == TX1_BUF_SIZE) {
		rc = memcmp(rx1_buf, tx1_buffer, TX1_BUF_SIZE);
	} else if (rx1_len == TX2_BUF_SIZE) {
		rc = memcmp(rx1_buf, tx2_buffer, TX2_BUF_SIZE);
	} else {
		LOG_ERR("Bad receive length: rx1_len=%lu", rx1_len);
		return -EIO;
	}

	if (rc) {
		LOG_ERR("Data miscompare");
		return -EIO;
	}

	return 0;
}

static int verify_buffers(void)
{
	int rc;

	if (rx1_len == TX1_BUF_SIZE) {
		rc = memcmp(rx1_buf, tx1_buffer, TX1_BUF_SIZE);
	} else if (rx1_len == TX2_BUF_SIZE) {
		rc = memcmp(rx1_buf, tx2_buffer, TX2_BUF_SIZE);
	} else {
		LOG_ERR("Bad receive length: rx1_len=%lu", rx1_len);
		return -EIO;
	}

	if (rc) {
		LOG_ERR("Data miscompare");
		return -EIO;
	}

	if (rx2_len == TX1_BUF_SIZE) {
		rc = memcmp(rx2_buf, tx1_buffer, TX1_BUF_SIZE);
	} else if (rx2_len == TX2_BUF_SIZE) {
		rc = memcmp(rx2_buf, tx2_buffer, TX2_BUF_SIZE);
	} else {
		LOG_ERR("Bad receive length: rx2_len=%lu", rx2_len);
		return -EIO;
	}

	if (rc) {
		LOG_ERR("Data miscompare");
		return -EIO;
	}

	return 0;
}

static int __init test_module_init(void)
{
	int rc;

	LOG_INFO("Using kmalloc=%d", kmalloc_buf);

	rc = test_init();
	if (rc)
		goto error;

	if (mode_tagged) {
		rc = post_tagged_rx_buffers();
		if (rc)
			goto error_cleanup;

		rc = post_tagged_tx_buffers();
		if (rc)
			goto error_cleanup;

		rc = process_cq();
		if (rc)
			goto error_cleanup;

		rc = verify_buffers();
		if (rc)
			goto error_cleanup;

		rc = post_tagged_rx_buffers();
		if (rc)
			goto error_cleanup;

		rc = post_one_good_one_bad_tagged_tx_buffers();
		if (rc)
			goto error_cleanup;

		rc = process_one_good_one_bad_tagged_cq();
		if (rc)
			goto error_cleanup;

		rc = verify_one_good_one_bad_tagged_buffers();
		if (rc)
			goto error_cleanup;
	} else {
		rc = post_rx_buffers();
		if (rc)
			goto error_cleanup;

		rc = post_tx_buffers();
		if (rc)
			goto error_cleanup;

		rc = process_cq();
		if (rc)
			goto error_cleanup;

		rc = verify_buffers();
		if (rc)
			goto error_cleanup;
	}

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
