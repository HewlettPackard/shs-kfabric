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
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/random.h>
#include <linux/mm.h>
#include <linux/atomic.h>
#include <linux/module.h>
#include <linux/uio.h>

#ifdef MODULE_NAME
#undef MODULE_NAME
#endif
#define MODULE_NAME "test_more"

#define TIMEOUT_SEC 15U
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
static struct kfid_mr *mr;
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
		       KFI_REMOTE_COMM | KFI_NAMED_RX_CTX);

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
	cq_attr.size = 4096;
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

	rx_attr.size = 8;
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
	tx_attr.size = 8;
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

	rc = kfi_mr_reg(domain, rx_buffer, BUF_SIZE, KFI_REMOTE_READ | KFI_READ,
			0, 0, 0, &mr, NULL);
	if (rc)
		goto err_free_tx_buffer;

	rc = kfi_mr_bind(mr, &rx->fid, 0);
	if (rc)
		goto err_free_mr;

	rc = kfi_mr_enable(mr);
	if (rc)
		goto err_free_mr;

	rc = kfi_av_insertsvc(av, node, service, &loopback_addr, 0, NULL);
	if (rc < 0)
		goto err_free_mr;

	/* Named RX context is enabled. Adjust loopback address to target RX
	 * context 0.
	 */
	loopback_addr = kfi_rx_addr(loopback_addr, 0, av_attr.rx_ctx_bits);

	return 0;

err_free_mr:
	kfi_close(&mr->fid);
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

	kfree(tx_buffer);
	kfree(rx_buffer);
}

/* Test KFI_MORE with RMA operations. */
static int test_1_rma_more(void)
{
	struct kvec iov = {
		.iov_base = tx_buffer,
		.iov_len = BUF_SIZE,
	};
	struct kfi_rma_iov rma_iov = {
		.len = BUF_SIZE,
	};
	struct kfi_msg_rma msg_rma = {
		.type = KFI_KVEC,
		.msg_iov = &iov,
		.iov_count = 1,
		.addr = loopback_addr,
		.rma_iov = &rma_iov,
		.rma_iov_count = 1,
	};
	struct kfi_cq_data_entry event;
	unsigned int events = 0;
	int rc;

	/* Queue read commands until EAGAIN is returned due to initiator credit
	 * exhaustion. EAGAIN will cause the doorbell to be rung.
	 */
	do {
		rc = kfi_readmsg(tx, &msg_rma, KFI_MORE | KFI_COMPLETION);
		if (rc == 0) {
			events++;

			if (atomic_read(&event_count)) {
				LOG_ERR("Unexpected events occurred");
				return -EINVAL;
			}
		} else if (rc != -EAGAIN) {
			LOG_ERR("kfi_readmsg() failure: rc=%d", rc);
			return rc;
		}
	} while (rc != -EAGAIN);

	/* Process events. */
	rc = -EAGAIN;
	while (events) {
		/* Wait for callback to be triggered to unblock this thread. */
		if (rc == -EAGAIN) {
			rc = wait_event_timeout(wait_queue,
						atomic_read(&event_count),
						TIMEOUT_SEC * HZ);
			if (!rc) {
				LOG_ERR("Timeout waiting for CQ event");
				return -ETIMEDOUT;
			}

			atomic_set(&event_count, 0);
		}

		/* An event should be returned. */
		rc = kfi_cq_read(cq, &event, 1);
		if (rc == 1) {
			events--;
		} else if (rc != -EAGAIN) {
			LOG_ERR("Unexpected CQ rc: %d", rc);
			return -EINVAL;
		}
	}

	rc = kfi_cq_read(cq, &event, 1);
	if (rc != -EAGAIN) {
		LOG_ERR("CQ did not return EAGAIN: rc=%d", rc);
		return -EINVAL;
	}

	return 0;
}

static int test_2_recv_more(void)
{
	struct kfi_cq_data_entry event;
	struct kvec iov = {
		.iov_base = tx_buffer,
		.iov_len = BUF_SIZE,
	};
	struct kfi_msg msg = {
		.type = KFI_KVEC,
		.msg_iov = &iov,
		.iov_count = 1,
	};
	unsigned int events;
	unsigned int posted_recvs = 0;
	int rc;
	int i;

	/* Queue message commands until EAGAIN is returned due to initiator
	 * credit exhaustion. EAGAIN will cause the doorbell to be rung.
	 */
	do {
		rc = kfi_recvmsg(rx, &msg, KFI_MORE | KFI_COMPLETION);
		if (rc == 0) {
			posted_recvs++;
		} else if (rc != -EAGAIN) {
			LOG_ERR("kfi_recvmsg() failure: rc=%d", rc);
			return rc;
		}
	} while (rc != -EAGAIN);

	msleep(2000);

	/* Issue one send to verify receive buffers have been posted. */
	msg.addr = loopback_addr;
	for (i = 0; i < posted_recvs; i++) {
		rc = kfi_sendmsg(tx, &msg, KFI_COMPLETION);
		if (rc) {
			LOG_ERR("kfi_sendmsg() failure: rc=%d", rc);
			return rc;
		}

		events = 2;
		rc = -EAGAIN;
		while (events) {
			/* Wait for callback to be triggered to unblock this
			 * thread.
			 */
			if (rc == -EAGAIN) {
				rc = wait_event_timeout(wait_queue,
							atomic_read(&event_count),
							TIMEOUT_SEC * HZ);
				if (!rc) {
					LOG_ERR("Timeout waiting for CQ event");
					return -ETIMEDOUT;
				}

				atomic_set(&event_count, 0);
			}

			/* An event should be returned. */
			rc = kfi_cq_read(cq, &event, 1);
			if (rc == 1) {
				events--;
			} else if (rc != -EAGAIN) {
				LOG_ERR("Unexpected CQ rc: %d", rc);
				return -EINVAL;
			}
		}

		rc = kfi_cq_read(cq, &event, 1);
		if (rc != -EAGAIN) {
			LOG_ERR("CQ did not return EAGAIN: rc=%d", rc);
			return -EINVAL;
		}
	}

	return 0;
}

/* Test KFI_MORE with send operations. */
static int test_3_send_more(void)
{
	struct kvec iov = {
		.iov_base = tx_buffer,
		.iov_len = BUF_SIZE,
	};
	struct kfi_msg msg = {
		.type = KFI_KVEC,
		.msg_iov = &iov,
		.iov_count = 1,
		.addr = loopback_addr,
	};
	struct kfi_cq_err_entry error;
	struct kfi_cq_data_entry event;
	unsigned int events = 0;
	int rc;

	/* Queue message commands until EAGAIN is returned due to initiator
	 * credit exhaustion. EAGAIN will cause the doorbell to be rung.
	 */
	do {
		rc = kfi_sendmsg(tx, &msg, KFI_MORE | KFI_COMPLETION);
		if (rc == 0) {
			events++;
		} else if (rc != -EAGAIN) {
			LOG_ERR("kfi_sendmsg() failure: rc=%d", rc);
			return rc;
		}
	} while (rc != -EAGAIN);

	/* Wait for RNR timeout events. */
	rc = -EAGAIN;
	while (events) {
		/* Wait for callback to be triggered to unblock this thread. */
		if (rc == -EAGAIN) {
			rc = wait_event_timeout(wait_queue,
						atomic_read(&event_count),
						TIMEOUT_SEC * HZ);
			if (!rc) {
				LOG_ERR("Timeout waiting for CQ event");
				return -ETIMEDOUT;
			}

			atomic_set(&event_count, 0);
		}

		/* An event should be returned. */
		rc = kfi_cq_readerr(cq, &error, 0);
		if (rc == 1) {
			events--;
			continue;
		} else if (rc != -EAGAIN) {
			LOG_ERR("Unexpected CQ rc: %d", rc);
			return -EINVAL;
		}

		/* Use this to reset the CQ callback. */
		kfi_cq_read(cq, &event, 1);
	}

	rc = kfi_cq_read(cq, &event, 1);
	if (rc != -EAGAIN) {
		LOG_ERR("CQ did not return EAGAIN: rc=%d", rc);
		return -EINVAL;
	}

	return 0;
}

static int __init test_module_init(void)
{
	int rc;

	rc = test_init();
	if (rc)
		goto error;

	rc = test_1_rma_more();
	if (rc) {
		LOG_ERR("test_1_rma_more() failed: %d", rc);
		goto error_fini;
	}

	rc = test_2_recv_more();
	if (rc) {
		LOG_ERR("test_2_recv_more() failed: %d", rc);
		goto error_fini;
	}

	rc = test_3_send_more();
	if (rc) {
		LOG_ERR("test_3_send_more() failed: %d", rc);
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
