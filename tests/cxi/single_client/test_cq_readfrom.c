//SPDX-License-Identifier: GPL-2.0
/*
 * Verify that CQ readfrom API.
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

#define ENDPOINT_COUNT 5
#define EVENT_COUNT ENDPOINT_COUNT
#define BUFFER_SIZE 1234

struct test_endpoint {
	struct kfid_cq *cq;
	struct kfid_ep *sep;
	struct kfid_ep *rx;
	struct kfid_ep *tx;
	void *tx_buffer;
	void *rx_buffer;
	kfi_addr_t addr;
	int id;
};

static struct kfid_fabric *fabric;
static struct kfid_domain *domain;
static struct kfid_av *av;
static struct kfid_cq *cq;

static struct test_endpoint endpoints[ENDPOINT_COUNT];
static char *node = "0x0";

#define NEXT_KFI_ADDR(cur) \
	(endpoints[(cur) + 1 >= ENDPOINT_COUNT ? 0 : (cur) + 1].addr)
#define PREV_KFI_ADDR(cur) \
	(endpoints[((int)(cur)) - 1 < 0 ? ENDPOINT_COUNT - 1 : (cur) - 1].addr)

#define TIMEOUT_SEC 5

static DECLARE_WAIT_QUEUE_HEAD(wait_queue);
static atomic_t event_count = ATOMIC_INIT(0);

static void cq_cb(struct kfid_cq *cq, void *context)
{
	atomic_inc(&event_count);
	wake_up(&wait_queue);
}

static int test_init(void)
{
	struct kfi_av_attr av_attr = {
		.type = KFI_AV_UNSPEC,
	};
	struct kfi_cq_attr cq_attr = {
		.format = KFI_CQ_FORMAT_DATA,
	};
	int rc;
	int i;
	unsigned int endpoint_count = 0;
	struct kfi_info *hints = NULL;
	struct kfi_info *info = NULL;
	char *service = NULL;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("Failed to allocate fabric hints");
		rc = -ENOMEM;
		goto err;
	}
	hints->caps = (KFI_MSG | KFI_RMA | KFI_SEND | KFI_RECV | KFI_READ |
		       KFI_WRITE | KFI_REMOTE_READ | KFI_REMOTE_WRITE |
		       KFI_MULTI_RECV | KFI_RMA_EVENT | KFI_REMOTE_COMM |
		       KFI_SOURCE);
	hints->tx_attr->op_flags = KFI_TRANSMIT_COMPLETE;

	rc = kfi_getinfo(0, node, NULL, KFI_SOURCE, hints, &info);
	if (rc) {
		LOG_ERR("Failed to get fabric info");
		goto err_free_hints;
	}

	rc = kfi_fabric(info->fabric_attr, &fabric, NULL);
	if (rc) {
		LOG_ERR("Failed to create fabric object");
		goto err_free_info;
	}

	rc = kfi_domain(fabric, info, &domain, NULL);
	if (rc) {
		LOG_ERR("Failed to create domain object: rc=%d", rc);
		goto err_free_fabric;
	}

	rc = kfi_av_open(domain, &av_attr, &av, NULL);
	if (rc) {
		LOG_ERR("Failed to create address vector: rc=%d", rc);
		goto err_free_domain;
	}

	rc = kfi_cq_open(domain, &cq_attr, &cq, cq_cb, NULL);
	if (rc) {
		LOG_ERR("Failed to allocate CQ: rc=%d", rc);
		goto err_free_av;
	}

	for (i = 0; i < ENDPOINT_COUNT; i++) {
		endpoint_count++;

		endpoints[i].id = i;

		/* Clear info since it will be reused. */
		kfi_freeinfo(info);
		info = NULL;

		service = kasprintf(GFP_KERNEL, "%d", i);
		if (!service) {
			LOG_ERR("Failed to allocate service string");
			rc = -ENOMEM;
			goto err_cleanup;
		}

		rc = kfi_getinfo(0, node, service, KFI_SOURCE, hints, &info);
		if (rc) {
			LOG_ERR("Failed to get fabric info: rc=%d", rc);
			goto err_cleanup;
		}

		rc = kfi_scalable_ep(domain, info, &endpoints[i].sep, NULL);
		if (rc) {
			LOG_ERR("Failed to allocate SEP %d: rc=%d", i, rc);
			goto err_cleanup;
		}

		rc = kfi_scalable_ep_bind(endpoints[i].sep, &av->fid, 0);
		if (rc) {
			LOG_ERR("Failed to bind AV to SEP %d: rc=%d", i, rc);
			goto err_cleanup;
		}

		rc  = kfi_enable(endpoints[i].sep);
		if (rc) {
			LOG_ERR("Failed to enable SEP %i: rc=%d", i, rc);
			goto err_cleanup;
		}

		rc = kfi_rx_context(endpoints[i].sep, 0, NULL, &endpoints[i].rx,
				    NULL);
		if (rc) {
			LOG_ERR("Failed to allocate RX context %d: rc=%d", i,
				rc);
			goto err_cleanup;
		}

		rc = kfi_ep_bind(endpoints[i].rx, &cq->fid, 0);
		if (rc) {
			LOG_ERR("Failed to bind CQ to RX context %d: rc=%d", i,
				rc);
			goto err_cleanup;
		}

		rc = kfi_enable(endpoints[i].rx);
		if (rc) {
			LOG_ERR("Failed enable RX context %d: rc=%d", i, rc);
			goto err_cleanup;
		}

		rc = kfi_tx_context(endpoints[i].sep, 0, NULL, &endpoints[i].tx,
				    NULL);
		if (rc) {
			LOG_ERR("Failed to allocate TX context %d: rc=%d", i,
				rc);
			goto err_cleanup;
		}

		/* Disable TX events. */
		rc = kfi_ep_bind(endpoints[i].tx, &cq->fid,
				 KFI_SELECTIVE_COMPLETION);
		if (rc) {
			LOG_ERR("Failed to bind CQ to TX context %d: rc=%d", i,
				rc);
			goto err_cleanup;
		}

		rc = kfi_enable(endpoints[i].tx);
		if (rc) {
			LOG_ERR("Failed enable TX context %d: rc=%d", i, rc);
			goto err_cleanup;
		}

		rc = kfi_av_insertsvc(av, node, service, &endpoints[i].addr, 0,
				      NULL);
		if (rc < 0) {
			LOG_ERR("Failed to insert address: rc=%d", rc);
			goto err_cleanup;
		}

		endpoints[i].tx_buffer = vmalloc(BUFFER_SIZE);
		if (!endpoints[i].tx_buffer) {
			rc = -ENOMEM;
			goto err_cleanup;
		}

		endpoints[i].rx_buffer = vmalloc(BUFFER_SIZE);
		if (!endpoints[i].rx_buffer) {
			rc = -ENOMEM;
			goto err_cleanup;
		}


		kfree(service);
		kfi_freeinfo(info);

		service = NULL;
		info = NULL;
	}

	return 0;

err_cleanup:
	kfree(service);

	for (i = 0; i < endpoint_count; i++) {
		if (endpoints[i].tx)
			kfi_close(&endpoints[i].tx->fid);
		if (endpoints[i].rx)
			kfi_close(&endpoints[i].rx->fid);
		if (endpoints[i].sep)
			kfi_close(&endpoints[i].sep->fid);

		vfree(endpoints[i].rx_buffer);
		vfree(endpoints[i].tx_buffer);
	}

	kfi_close(&cq->fid);

err_free_av:
	kfi_close(&av->fid);
err_free_domain:
	kfi_close(&domain->fid);
err_free_fabric:
	kfi_close(&fabric->fid);
err_free_info:
	if (info)
		kfi_freeinfo(info);
err_free_hints:
	if (hints)
		kfi_freeinfo(hints);
err:
	return rc;
}

static void test_fini(void)
{
	int i;

	for (i = 0; i < ENDPOINT_COUNT; i++) {
		kfi_close(&endpoints[i].tx->fid);
		kfi_close(&endpoints[i].rx->fid);
		kfi_close(&endpoints[i].sep->fid);

		vfree(endpoints[i].rx_buffer);
		vfree(endpoints[i].tx_buffer);
	}

	kfi_close(&cq->fid);
	kfi_close(&av->fid);
	kfi_close(&domain->fid);
	kfi_close(&fabric->fid);
}

static int post_rx_buffers(void)
{
	int rc;
	int i;

	for (i = 0; i < ENDPOINT_COUNT; i++) {
		rc = kfi_recv(endpoints[i].rx, endpoints[i].rx_buffer,
			      BUFFER_SIZE, NULL, 0, &endpoints[i]);
		if (rc)
			break;
	}

	return rc;
}

static int post_tx_buffers(void)
{
	int rc;
	int i;

	/* Perform a send operation to the right (+1) endpoint. */
	for (i = 0; i < ENDPOINT_COUNT; i++) {
		rc = kfi_send(endpoints[i].tx, endpoints[i].tx_buffer,
			      BUFFER_SIZE, NULL, NEXT_KFI_ADDR(endpoints[i].id),
			      NULL);
		if (rc)
			break;
	}

	return rc;
}

static int process_cq(void)
{
	int rc;
	int cq_events = 0;
	struct kfi_cq_data_entry event;
	kfi_addr_t src_addr;
	struct test_endpoint *ep;
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
		rc = kfi_cq_readfrom(cq, &event, 1, &src_addr);
		if (rc == 1) {
			ep = event.op_context;

			if (!ep) {
				LOG_ERR("Event context NULL");
				return -EINVAL;
			}

			/* Verify source operation was from the left (-1)
			 * endpoint.
			 */
			if (PREV_KFI_ADDR(ep->id) != src_addr) {
				LOG_ERR("Bad source address");
				return -EINVAL;
			}

			cq_events++;
			continue;
		} else if (rc == -EAGAIN) {
			break;
		}

		LOG_ERR("Unexpected CQ rc=%d", rc);
		return rc;
	}

	if (cq_events < EVENT_COUNT)
		goto again;

	return 0;
}

static int __init test_module_init(void)
{
	int rc;

	rc = test_init();
	if (rc)
		goto err;

	rc = post_rx_buffers();
	if (rc)
		goto err_fini;

	rc = post_tx_buffers();
	if (rc)
		goto err_fini;

	rc = process_cq();
	if (rc)
		goto err_fini;

	return 0;

err_fini:
	test_fini();
err:
	return rc;
}

static void __exit test_module_exit(void)
{
	test_fini();
}

module_init(test_module_init);
module_exit(test_module_exit);
MODULE_LICENSE("GPL v2");
