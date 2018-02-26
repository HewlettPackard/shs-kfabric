//SPDX-License-Identifier: GPL-2.0
/*
 * Allocate a SEP with all 256 keys. Verify communication across authorization
 * keys cannot occur.
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

#define AUTH_KEY_COUNT 255
#define AUTH_KEYS_PER_DOMAIN 16
#define DOMAIN_COUNT 14

struct test_domain {
	struct kfid_domain *domain;
	struct kfid_av *av;
	struct kfid_cq *cq;
	struct kfid_ep *sep[AUTH_KEYS_PER_DOMAIN];
	unsigned int sep_count;
	struct kfid_ep *rx[AUTH_KEYS_PER_DOMAIN];
	unsigned int rx_count;
	struct kfid_ep *tx[AUTH_KEYS_PER_DOMAIN];
	unsigned int tx_count;
	kfi_addr_t addr[AUTH_KEYS_PER_DOMAIN];
};

static struct kfid_fabric *fabric;
static struct test_domain domains[DOMAIN_COUNT];

#define BUF_SIZE 64
static void *rx_buffer;
static void *tx_buffer;

static char *node = "0x0";

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
		.format = KFI_CQ_FORMAT_CONTEXT,
	};
	int rc;
	int i;
	int j;
	uint32_t auth_key;
	unsigned int domain_count = 0;
	struct kfi_info *hints = NULL;
	struct kfi_info *fabric_info = NULL;
	struct kfi_info *info = NULL;
	char *service = NULL;
	struct kfi_tx_attr tx_attr = {
		.size = 1,
	};

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("Failed to allocate fabric hints");
		rc = -ENOMEM;
		goto err;
	}
	hints->caps = (KFI_MSG | KFI_RMA | KFI_SEND | KFI_RECV | KFI_READ |
		       KFI_WRITE | KFI_REMOTE_READ | KFI_REMOTE_WRITE |
		       KFI_MULTI_RECV | KFI_RMA_EVENT | KFI_REMOTE_COMM);

	hints->ep_attr->auth_key = kzalloc(sizeof(auth_key), GFP_KERNEL);
	if (!hints->ep_attr->auth_key) {
		LOG_ERR("Failed to allocate auth key attr");
		rc = -ENOMEM;
		goto err_free_hints;
	}
	hints->ep_attr->auth_key_size = sizeof(auth_key);

	rc = kfi_getinfo(0, node, NULL, KFI_SOURCE, hints, &fabric_info);
	if (rc) {
		LOG_ERR("Failed to get fabric info");
		goto err_free_hints;
	}

	rc = kfi_fabric(fabric_info->fabric_attr, &fabric, NULL);
	if (rc) {
		LOG_ERR("Failed to create fabric object");
		goto err_free_info;
	}

	for (i = 0; i < DOMAIN_COUNT; i++) {
		rc = kfi_domain(fabric, fabric_info, &domains[i].domain, NULL);
		if (rc) {
			LOG_ERR("Failed to create domain %d object: rc=%d", i,
				rc);
			goto err_cleanup;
		}
		domain_count++;

		rc = kfi_av_open(domains[i].domain, &av_attr, &domains[i].av,
				 NULL);
		if (rc) {
			LOG_ERR("Failed to create address vector");
			goto err_cleanup;
		}

		rc = kfi_cq_open(domains[i].domain, &cq_attr, &domains[i].cq,
				 cq_cb, NULL);
		if (rc) {
			LOG_ERR("Failed to allocate CQ %d: rc=%d", i, rc);
			goto err_cleanup;
		}

		/* Clear info since it will be reused. */
		kfi_freeinfo(info);
		info = NULL;

		for (j = 0; j < AUTH_KEYS_PER_DOMAIN; j++) {
			service = kasprintf(GFP_KERNEL, "%d", i);
			if (!service) {
				LOG_ERR("Failed to allocate service string");
				rc = -ENOMEM;
				goto err_cleanup;
			}

			/* auth_key 0 is invalid, start at 1 */
			*hints->ep_attr->auth_key =
				i * AUTH_KEYS_PER_DOMAIN + j + 1;

			rc = kfi_getinfo(0, node, service, KFI_SOURCE, hints,
					 &info);
			if (rc) {
				LOG_ERR("Failed to get fabric info: rc=%d", rc);
				goto err_cleanup;
			}

			rc = kfi_scalable_ep(domains[i].domain, info,
					     &domains[i].sep[j], NULL);
			if (rc) {
				LOG_ERR("Failed to allocate SEP %d: rc=%d",
					i * DOMAIN_COUNT + j, rc);
				goto err_cleanup;
			}
			domains[i].sep_count++;

			rc = kfi_scalable_ep_bind(domains[i].sep[j],
						  &domains[i].av->fid, 0);
			if (rc) {
				LOG_ERR("Failed to bind AV to SEP %d: rc=%d",
					i * DOMAIN_COUNT + j, rc);
				goto err_cleanup;
			}

			rc  = kfi_enable(domains[i].sep[j]);
			if (rc) {
				LOG_ERR("Failed to enable SEP %i: rc=%d", i,
					rc);
				goto err_cleanup;
			}

			rc = kfi_rx_context(domains[i].sep[j], 0, NULL,
					    &domains[i].rx[j], NULL);
			if (rc) {
				LOG_ERR("Failed to allocate RX context %d: rc=%d",
					i * DOMAIN_COUNT + j, rc);
				goto err_cleanup;
			}
			domains[i].rx_count++;

			rc = kfi_ep_bind(domains[i].rx[j],
					 &domains[i].cq->fid, 0);
			if (rc) {
				LOG_ERR("Failed to bind CQ to RX context %d: rc=%d",
					i * DOMAIN_COUNT + j, rc);
				goto err_cleanup;
			}

			rc = kfi_enable(domains[i].rx[j]);
			if (rc) {
				LOG_ERR("Failed enable RX context %d: rc=%d",
					i * DOMAIN_COUNT + j, rc);
				goto err_cleanup;
			}

			rc = kfi_tx_context(domains[i].sep[j], 0, &tx_attr,
					    &domains[i].tx[j], NULL);
			if (rc) {
				LOG_ERR("Failed to allocate TX context %d: rc=%d",
					i * DOMAIN_COUNT + j, rc);
			goto err_cleanup;
			}
			domains[i].tx_count++;

			rc = kfi_ep_bind(domains[i].tx[j],
					 &domains[i].cq->fid, 0);
			if (rc) {
				LOG_ERR("Failed to bind CQ to TX context %d: rc=%d",
					i * DOMAIN_COUNT + j, rc);
				goto err_cleanup;
			}

			rc = kfi_enable(domains[i].tx[j]);
			if (rc) {
				LOG_ERR("Failed enable TX context %d: rc=%d",
					i * DOMAIN_COUNT + j, rc);
				goto err_cleanup;
			}

			rc = kfi_av_insertsvc(domains[i].av, node,
					      service,
					      &domains[i].addr[j], 0,
					      NULL);
			if (rc < 0) {
				LOG_ERR("Failed to insert address: rc=%d", rc);
				goto err_cleanup;
			}

			kfree(service);
			kfi_freeinfo(info);

			service = NULL;
			info = NULL;
		}
	}

	tx_buffer = vmalloc(BUF_SIZE);
	if (!tx_buffer) {
		rc = -ENOMEM;
		goto err_cleanup;
	}

	rx_buffer = vmalloc(BUF_SIZE);
	if (!rx_buffer) {
		rc = -ENOMEM;
		goto err_free_tx_buffer;
	}

	return 0;

err_free_tx_buffer:
	vfree(tx_buffer);
err_cleanup:
	kfree(service);

	for (i = 0; i < domain_count; i++) {
		for (j = 0; j < domains[i].tx_count; j++)
			kfi_close(&domains[i].tx[j]->fid);
		for (j = 0; j < domains[i].rx_count; j++)
			kfi_close(&domains[i].rx[j]->fid);
		for (j = 0; j < domains[i].sep_count; j++)
			kfi_close(&domains[i].sep[j]->fid);

		if (domains[i].cq)
			kfi_close(&domains[i].cq->fid);
		if (domains[i].av)
			kfi_close(&domains[i].av->fid);
		if (domains[i].domain)
			kfi_close(&domains[i].domain->fid);
	}

	kfi_close(&fabric->fid);

	if (info)
		kfi_freeinfo(info);
err_free_info:
	if (fabric_info)
		kfi_freeinfo(fabric_info);
err_free_hints:
	if (hints)
		kfi_freeinfo(hints);
err:
	return rc;
}

static void test_fini(void)
{
	int i;
	int j;

	for (i = 0; i < DOMAIN_COUNT; i++) {
		for (j = 0; j < AUTH_KEYS_PER_DOMAIN; j++)
			kfi_close(&domains[i].tx[j]->fid);
		for (j = 0; j < AUTH_KEYS_PER_DOMAIN; j++)
			kfi_close(&domains[i].rx[j]->fid);
		for (j = 0; j < AUTH_KEYS_PER_DOMAIN; j++)
			kfi_close(&domains[i].sep[j]->fid);

		kfi_close(&domains[i].cq->fid);
		kfi_close(&domains[i].av->fid);
		kfi_close(&domains[i].domain->fid);
	}

	kfi_close(&fabric->fid);

	vfree(tx_buffer);
	vfree(rx_buffer);
}

static int __init test_module_init(void)
{
	int rc;

	rc = test_init();
	if (rc)
		goto err;

	/* TODO: Verify authorization key enforcement. */

	return 0;

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
