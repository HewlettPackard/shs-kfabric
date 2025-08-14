//SPDX-License-Identifier: GPL-2.0
/*
 * Cray kfabric CXI provider interface.
 * Copyright 2019-2025 Hewlett Packard Enterprise Development LP
 */
#include <linux/slab.h>
#include <linux/module.h>

#include "kcxi_prov.h"

static bool restricted_members = true;
module_param(restricted_members, bool, 0444);
MODULE_PARM_DESC(restricted_members,
		 "Enable UID/GID checking in cxi_service");
static bool restricted_vnis;
module_param(restricted_vnis, bool, 0444);
MODULE_PARM_DESC(restricted_vnis,
		 "Enable VNI Checking in cxi_service");
static bool restricted_tcs;
module_param(restricted_tcs, bool, 0444);
MODULE_PARM_DESC(restricted_tcs,
		 "Enable TC checking in cxi_service");
static bool resource_limits = true;
module_param(resource_limits, bool, 0444);
MODULE_PARM_DESC(resource_limits,
		 "Enable resource limits in cxi_service");

static void kcxi_if_reset_counters(struct kcxi_if *kcxi_if)
{
	atomic_set(&kcxi_if->md_max_count, 0);
}

static int kcxi_if_counters_file_show(struct seq_file *s, void *unused)
{
	struct kcxi_if *kcxi_if = s->private;

	seq_printf(s, "md_cur_count: %d\n", atomic_read(&kcxi_if->md_cur_count));
	seq_printf(s, "md_max_count: %d\n", atomic_read(&kcxi_if->md_max_count));
	seq_printf(s, "md_cached_count: %d\n", atomic_read(&kcxi_if->md_cached_count));

	return 0;
}

static int kcxi_if_counters_file_open(struct inode *inode, struct file *file)
{
	return single_open(file, kcxi_if_counters_file_show, inode->i_private);
}

static const struct file_operations kcxi_if_counters_file_ops = {
	.owner = THIS_MODULE,
	.open = kcxi_if_counters_file_open,
	.read = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release,
};

static int kcxi_if_reset_counters_set(void *data, u64 value)
{
	struct kcxi_if *kcxi_if = data;

	kcxi_if_reset_counters(kcxi_if);

	return 0;
}

static int kcxi_if_reset_counters_get(void *data, u64 *value)
{
	/* Read is a noop. */
	*value = 0;

	return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(kcxi_if_reset_counters_ops, kcxi_if_reset_counters_get,
			kcxi_if_reset_counters_set, "%llu\n");

/**
 * kcxi_if_alloc() - Allocate a kCXI interface.
 * @dev: Local NIC address the kCXI interface should be allocated against.
 *
 * Return: On success, valid pointer. On error, negative, errno pointer.
 */
struct kcxi_if *kcxi_if_alloc(unsigned int nic, const struct kfid_fabric *fabric, const struct kfi_info *info)
{
	int rc;
	int lock_idx;
	int i;
	bool dynamic_alloc = false;
	struct kcxi_fabric *kcxi_fab;
	struct kcxi_if *kcxi_if;
	struct kcxi_dev *kdev;
	struct cxi_dev *cdev;
	char if_debugfs_dir_name[16];
	struct cxi_rsrc_limits limits = {
		.acs = {
			.max = KCXI_DOM_AC_MAX,
			.res = address_contexts,
		},
		.eqs = {
			.max = KCXI_DOM_CQ_MAX,
			.res = completion_queues,
		},
		.cts = {
			.max = 0,
			.res = 0,
		},
		.ptes = {
			.max = KCXI_DOM_RX_CTX_MAX,
			.res = receive_contexts,
		},
		.txqs = {
			.max = KCXI_DOM_TX_CTX_MAX,
			.res = transmit_contexts,
		},
		.tgqs = {
			.max = KCXI_DOM_RX_CTX_MAX,
			.res = receive_contexts,
		},
		.tles = {
			.max = 0,
			.res = 0,
		},
		/* Will actually have res/4 value for les */
		.les = {
			.max = KCXI_DOM_BUF_MAX / 4,
			.res = (message_buffers + 3) / 4,
		},
	};
	struct cxi_svc_desc svc_desc = {
		 .resource_limits = resource_limits,
		 .restricted_members = restricted_members,
		 .members[0] = {
			 .type = CXI_SVC_MEMBER_UID,
			 .svc_member.uid = (current_euid()).val,
		 },
		 .restricted_vnis = restricted_vnis,
		 .restricted_tcs = restricted_tcs,
		 .limits = limits,
		 .is_system_svc = true,
	};
	struct cxi_svc_fail_info fail_info = {};
	uint16_t auth_key = *(info->domain_attr->auth_key);

	/* Override default resource limit parameters */
	if (fabric) {
		kcxi_fab = container_of(fabric, struct kcxi_fabric, fab_fid);
		if (kcxi_fab->dynamic_rsrc_alloc && info->rx_attr && info->domain_attr) {
			dynamic_alloc = true;
			svc_desc.limits.eqs.res = info->domain_attr->cq_cnt;
			svc_desc.limits.ptes.res = info->domain_attr->rx_ctx_cnt;
			svc_desc.limits.txqs.res = info->domain_attr->tx_ctx_cnt;
			svc_desc.limits.tgqs.res = info->domain_attr->rx_ctx_cnt;
			svc_desc.limits.les.res = ((info->rx_attr->size * info->domain_attr->rx_ctx_cnt) + 3) / 4;
		}
	}

	kdev = kcxi_dev_get(nic);
	if (IS_ERR(kdev)) {
		rc = PTR_ERR(kdev);
		goto err;
	}

	kcxi_if = kzalloc(sizeof(*kcxi_if), GFP_KERNEL);
	if (!kcxi_if) {
		rc = -ENOMEM;
		goto err_dev_put;
	}

	kcxi_if->dev = kdev;

	atomic_set(&kcxi_if->md_cur_count, 0);
	atomic_set(&kcxi_if->md_cached_count, 0);

	INIT_LIST_HEAD(&kcxi_if->ptlte_list);
	spin_lock_init(&kcxi_if->ptlte_list_lock);

	atomic_set(&kcxi_if->ref_cnt, 0);

	INIT_LIST_HEAD(&kcxi_if->tx_profile_list);
	INIT_LIST_HEAD(&kcxi_if->rx_profile_list);
	INIT_LIST_HEAD(&kcxi_if->cp_list);
	mutex_init(&kcxi_if->cp_lock);
	mutex_init(&kcxi_if->rxp_lock);
	mutex_init(&kcxi_if->txp_lock);
	atomic_set(&kcxi_if->cp_cnt, 0);

	lock_idx = srcu_read_lock(&kdev->dev_lock);
	cdev = srcu_dereference(kdev->dev, &kdev->dev_lock);
	if (!cdev) {
		rc = -ENODEV;
		goto err_unlock;
	}

	/* Allocate a CXI Service */
	LOG_INFO("%s CXI resource reservations",
		dynamic_alloc ? "Dynamic" : "Parameter based");
	LOG_INFO("  ACs: %d  EQs: %d  PTEs: %d  TGQs: %d  TXQs: %d  LEs: %d",
		svc_desc.limits.acs.res, svc_desc.limits.eqs.res, svc_desc.limits.ptes.res,
		svc_desc.limits.tgqs.res, svc_desc.limits.txqs.res, svc_desc.limits.les.res);

	rc = cxi_svc_alloc(cdev, &svc_desc, &fail_info);
	if (rc < 0) {
		LOG_INFO("Unable to reserve requested resources");
		for (i = 0; i < CXI_RSRC_TYPE_MAX; i++) {
			if (svc_desc.limits.type[i].res > fail_info.rsrc_avail[i]) {
				LOG_INFO("  %s requested: %d  %s available: %d",
					cxi_rsrc_type_to_str(i), svc_desc.limits.type[i].res, cxi_rsrc_type_to_str(i), fail_info.rsrc_avail[i]);
			}
		}
		goto err_unlock;
	}
	kcxi_if->svc_id = rc;

	rc = kcxi_get_rx_profile(kcxi_if, auth_key);
	if (rc && rc != -EEXIST) {
		LOG_INFO("Unable to allocate RX profile auth_key:%d rc:%d",
			 auth_key, rc);
		goto err_free_svc;
	}

	rc = kcxi_get_tx_profile(kcxi_if, auth_key);
	if (rc && rc != -EEXIST) {
		LOG_INFO("Unable to allocate TX profile auth_key:%d rc:%d",
			 auth_key, rc);
		goto err_free_rx_profile;
	}

	LOG_INFO("");
	kcxi_if->lni = cxi_lni_alloc(cdev, kcxi_if->svc_id);
	if (IS_ERR(kcxi_if->lni)) {
		rc = PTR_ERR(kcxi_if->lni);
		goto err_free_tx_profile;
	}

	rc = cxi_phys_lac_alloc(kcxi_if->lni);
	if (rc < 0)
		goto err_free_lni;

	kcxi_if->phys_lac = rc;
	kcxi_if->nic_addr = cdev->prop.nic_addr;

	rc = snprintf(if_debugfs_dir_name, sizeof(if_debugfs_dir_name),
		      "if%u", kcxi_if->lni->id);
	if (rc >= sizeof(if_debugfs_dir_name)) {
		rc = -ENOMEM;
		goto err_free_lni;
	} else if (rc < 0) {
		goto err_free_lni;
	}

	kcxi_if_reset_counters(kcxi_if);

	kcxi_if->if_debugfs_dir = debugfs_create_dir(if_debugfs_dir_name,
						     kdev->dev_debugfs_dir);
	debugfs_create_file("counters", 0444, kcxi_if->if_debugfs_dir, kcxi_if,
			    &kcxi_if_counters_file_ops);
	debugfs_create_file("reset_counters", 0200, kcxi_if->if_debugfs_dir,
			    kcxi_if, &kcxi_if_reset_counters_ops);

	srcu_read_unlock(&kdev->dev_lock, lock_idx);

	KCXI_IF_INFO(kcxi_if, "Interface allocated");

	return kcxi_if;

err_free_lni:
	cxi_lni_free(kcxi_if->lni);
err_free_tx_profile:
	kcxi_put_tx_profile(kcxi_if, auth_key);
err_free_rx_profile:
	kcxi_put_rx_profile(kcxi_if, auth_key);
err_free_svc:
	cxi_svc_destroy(cdev, kcxi_if->svc_id);
err_unlock:
	srcu_read_unlock(&kdev->dev_lock, lock_idx);
	kfree(kcxi_if);
err_dev_put:
	kcxi_dev_put(kdev);
err:
	return ERR_PTR(rc);
}

/**
 * kcxi_if_free() - Free a kCXI interface.
 * @kcxi_if: kCXI interface to be freed.
 *
 * Return: On success, zero. On error, negative errno value.
 */
int kcxi_if_free(struct kcxi_if *kcxi_if)
{
	struct kcxi_dev *kdev;
	struct cxi_dev *cdev;

	if (!kcxi_if)
		return -EINVAL;

	if (atomic_read(&kcxi_if->ref_cnt))
		return -EBUSY;

	KCXI_IF_INFO(kcxi_if, "Interface freed");

	flush_workqueue(kcxi_wq);

	debugfs_remove_recursive(kcxi_if->if_debugfs_dir);

	kdev = kcxi_if->dev;

	cxi_lni_free(kcxi_if->lni);

	cdev = srcu_dereference(kdev->dev, &kdev->dev_lock);

	kcxi_tx_profiles_cleanup(kcxi_if);
	kcxi_rx_profiles_cleanup(kcxi_if);
	cxi_svc_destroy(cdev, kcxi_if->svc_id);

	kfree(kcxi_if);

	kcxi_dev_put(kdev);

	return 0;
}
