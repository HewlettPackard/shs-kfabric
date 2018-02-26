/*
 * Cray kfabric CXI provider.
 * Copyright 2018-2024 Hewlett Packard Enterprise Development LP
 *
 * SPDX-License-Identifier: GPL-2.0
 */
#include <linux/module.h>
#include <linux/moduleparam.h>

#include "kcxi_prov.h"

MODULE_AUTHOR("Ian Ziemba");
MODULE_DESCRIPTION("Open Fabric Interface kCXI Provider");
MODULE_LICENSE("GPL v2");

unsigned int eager_threshold = KCXI_DEF_EAGER_THRESHOLD;
module_param(eager_threshold, uint, 0444);
MODULE_PARM_DESC(eager_threshold, "Threshold between eager and rendezvous ops");

unsigned int address_contexts = KCXI_DOM_AC_RES;
module_param(address_contexts, uint, 0444);
MODULE_PARM_DESC(address_contexts, "Reserved number of address contexts per kfabric domain allocation");

unsigned int completion_queues = KCXI_DOM_CQ_RES;
module_param(completion_queues, uint, 0444);
MODULE_PARM_DESC(completion_queues, "Reserved number of completion queues per kfabric domain allocation");

unsigned int transmit_contexts = KCXI_DOM_TX_CTX_RES;
module_param(transmit_contexts, uint, 0444);
MODULE_PARM_DESC(transmit_contexts, "Reserved number of transmit contexts per kfabric domain allocation");

unsigned int receive_contexts = KCXI_DOM_RX_CTX_RES;
module_param(receive_contexts, uint, 0444);
MODULE_PARM_DESC(receive_contexts, "Reserved number of receive contexts per kfabric domain allocation");

unsigned int message_buffers = KCXI_DOM_BUF_RES;
module_param(message_buffers, uint, 0444);
MODULE_PARM_DESC(message_buffers, "Reserved number of message buffers per kfabric domain allocation");

struct workqueue_struct *kcxi_wq;
struct dentry *kcxi_debugfs_dir;

static struct kfi_provider cxi_prov = {
	.name = KCXI_PROV_NAME,
	.version = KCXI_PROV_VERSION,
	.kfi_version = KFI_VERSION(KFI_MAJOR_VERSION, KFI_MINOR_VERSION),
	.kgetinfo = kcxi_getinfo,
	.kfabric = kcxi_fabric,
};

static struct cxi_client client = {
	.add = kcxi_dev_add,
	.remove = kcxi_dev_remove,
	.async_event = kcxi_async_event,
};

#define AUTH_KEY_MAX (BIT(16) - 1)

static int __init kfi_cxi_init(void)
{
	int rc = 0;

	if (eager_threshold > KCXI_EP_MAX_MSG_SIZE) {
		LOG_ERR("Param Error: Eager threshold exceeded max msg size %u",
			KCXI_EP_MAX_MSG_SIZE);
		rc = -EINVAL;
	}

	if (default_auth_key > AUTH_KEY_MAX) {
		LOG_ERR("Param Error: Default auth key exceeded max %lu",
			AUTH_KEY_MAX);
		rc = -EINVAL;
	}

	if (address_contexts > KCXI_DOM_AC_MAX) {
		LOG_ERR("Param Error: Default address contexts reserved per domain exceeded max value %u",
			KCXI_DOM_AC_MAX);
		rc = -EINVAL;
	}

	if (completion_queues > KCXI_DOM_CQ_MAX) {
		LOG_ERR("Param Error: Default completion queues reserved per domain exceeded max value %u",
			KCXI_DOM_CQ_MAX);
		rc = -EINVAL;
	}

	if (transmit_contexts > KCXI_DOM_TX_CTX_MAX) {
		LOG_ERR("Param Error: Default transmit contexts reserved per domain exceeded max value %u",
			KCXI_DOM_TX_CTX_MAX);
		rc = -EINVAL;
	}

	if (receive_contexts > KCXI_DOM_RX_CTX_MAX) {
		LOG_ERR("Param Error: Default receive contexts reserved per domain exceeded max value %u",
			KCXI_DOM_RX_CTX_MAX);
		rc = -EINVAL;
	}

	if (message_buffers > KCXI_DOM_BUF_MAX) {
		LOG_ERR("Param Error: Default message buffers reserved per domain exceeded max value %u",
			KCXI_DOM_BUF_MAX);
		rc = -EINVAL;
	}

	if (cq_fill_percent < 10 || cq_fill_percent > 90) {
		LOG_ERR("Param Error: Fill percent must be between 10 and 90");
		rc = -EINVAL;
	}

	if (md_cache_bufsize > MAX_MD_CACHE_BUFSIZE)
		md_cache_bufsize = MAX_MD_CACHE_BUFSIZE;

	if (md_cache_bufsize < MIN_MD_CACHE_BUFSIZE)
		md_cache_bufsize = MIN_MD_CACHE_BUFSIZE;

	if (rc) {
		return rc;
	}

	rc = kfi_provider_register(&cxi_prov);
	if (rc) {
		LOG_ERR("Failed to register kCXI provider");
		return rc;
	}

	rc = kcxi_cq_init_cache();
	if (rc) {
		LOG_ERR("Failed to initialize CQ cache");
		goto err_prov_dereg;
	}

	rc = kcxi_md_init_cache();
	if (rc) {
		LOG_ERR("Failed to initialize MD cache");
		goto err_cq_destroy_cache;
	}

	rc = kcxi_tx_desc_init_cache();
	if (rc) {
		LOG_ERR("Failed to initialize TX desc cache");
		goto err_md_destroy_cache;
	}

	rc = kcxi_rx_desc_init_cache();
	if (rc) {
		LOG_ERR("Failed to initialize RX desc cache");
		goto err_tx_desc_destroy_cache;
	}

	kcxi_wq = alloc_workqueue("kcxi_wq",
				  WQ_MEM_RECLAIM | WQ_HIGHPRI | WQ_SYSFS,
				  WQ_MAX_ACTIVE);
	if (!kcxi_wq) {
		rc = -ENOMEM;
		LOG_ERR("Failed to allocate kCXI workqueue");
		goto err_rx_desc_destroy_cache;
	}

	rc = kcxi_arp_res_init();
	if (rc) {
		LOG_ERR("Failed to initial address resolution");
		goto err_free_wq;
	}

	kcxi_debugfs_dir = debugfs_create_dir("kfi_cxi", NULL);

	rc = cxi_register_client(&client);
	if (rc) {
		LOG_ERR("Failed to register with CXI core");
		goto err_arp_fini;
	}

	return 0;

err_arp_fini:
	kcxi_arp_res_fini();
err_free_wq:
	destroy_workqueue(kcxi_wq);
err_rx_desc_destroy_cache:
	kcxi_rx_desc_destroy_cache();
err_tx_desc_destroy_cache:
	kcxi_tx_desc_destroy_cache();
err_md_destroy_cache:
	kcxi_md_destroy_cache();
err_cq_destroy_cache:
	kcxi_cq_destroy_cache();
err_prov_dereg:
	kfi_provider_deregister(&cxi_prov);

	return rc;
}

static void __exit kfi_cxi_exit(void)
{
	flush_workqueue(kcxi_wq);

	cxi_unregister_client(&client);
	kcxi_arp_res_fini();
	destroy_workqueue(kcxi_wq);
	kcxi_rx_desc_destroy_cache();
	kcxi_tx_desc_destroy_cache();
	kcxi_md_destroy_cache();
	kcxi_cq_destroy_cache();

	debugfs_remove_recursive(kcxi_debugfs_dir);

	kfi_provider_deregister(&cxi_prov);
}

module_init(kfi_cxi_init);
module_exit(kfi_cxi_exit);
