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

int kcxi_alloc_rgroup_rsrcs(struct cxi_dev *cdev, struct kcxi_if *kcxi_if,
		       const struct kfid_fabric *fabric,
		       const struct kfi_info *info)
{
	int i;
	int rc;
	bool dynamic_alloc = false;
	unsigned int ac_entry_id;
	struct cxi_rgroup *rgroup;
	struct kcxi_fabric *kcxi_fab;
	struct cxi_resource_limits limits[CXI_RESOURCE_MAX];
	const union cxi_ac_data ac_data = {
		.uid = __kuid_val(current_euid()),
	};

	limits[CXI_RESOURCE_AC].max = KCXI_DOM_AC_MAX;
	limits[CXI_RESOURCE_AC].reserved = address_contexts;
	limits[CXI_RESOURCE_EQ].max = KCXI_DOM_CQ_MAX;
	limits[CXI_RESOURCE_EQ].reserved = completion_queues;
	limits[CXI_RESOURCE_CT].max = 0;
	limits[CXI_RESOURCE_CT].reserved = 0;
	limits[CXI_RESOURCE_PTLTE].max = KCXI_DOM_RX_CTX_MAX;
	limits[CXI_RESOURCE_PTLTE].reserved = receive_contexts;
	limits[CXI_RESOURCE_TXQ].max = KCXI_DOM_TX_CTX_MAX;
	limits[CXI_RESOURCE_TXQ].reserved = transmit_contexts;
	limits[CXI_RESOURCE_TGQ].max = KCXI_DOM_RX_CTX_MAX;
	limits[CXI_RESOURCE_TGQ].reserved = receive_contexts;
	limits[CXI_RESOURCE_TLE].max = 0;
	limits[CXI_RESOURCE_TLE].reserved = 0;
	limits[CXI_RESOURCE_PE0_LE].max = KCXI_LE_MAX;
	limits[CXI_RESOURCE_PE0_LE].reserved = KCXI_LE_RES(message_buffers);
	limits[CXI_RESOURCE_PE1_LE].max = KCXI_LE_MAX;
	limits[CXI_RESOURCE_PE1_LE].reserved = KCXI_LE_RES(message_buffers);
	limits[CXI_RESOURCE_PE2_LE].max = KCXI_LE_MAX;
	limits[CXI_RESOURCE_PE2_LE].reserved = KCXI_LE_RES(message_buffers);
	limits[CXI_RESOURCE_PE3_LE].max = KCXI_LE_MAX;
	limits[CXI_RESOURCE_PE3_LE].reserved = KCXI_LE_RES(message_buffers);

	/* Override default resource limit parameters */
	if (fabric) {
		kcxi_fab = container_of(fabric, struct kcxi_fabric, fab_fid);
		if (kcxi_fab->dynamic_rsrc_alloc && info->rx_attr && info->domain_attr) {
			dynamic_alloc = true;
			limits[CXI_RESOURCE_EQ].reserved = info->domain_attr->cq_cnt;
			limits[CXI_RESOURCE_PTLTE].reserved = info->domain_attr->rx_ctx_cnt;
			limits[CXI_RESOURCE_TXQ].reserved = info->domain_attr->tx_ctx_cnt;
			limits[CXI_RESOURCE_TGQ].reserved = info->domain_attr->rx_ctx_cnt;
			limits[CXI_RESOURCE_PE0_LE].reserved = KCXI_LE_RES(info->rx_attr->size * info->domain_attr->rx_ctx_cnt);
			limits[CXI_RESOURCE_PE1_LE].reserved = KCXI_LE_RES(info->rx_attr->size * info->domain_attr->rx_ctx_cnt);
			limits[CXI_RESOURCE_PE2_LE].reserved = KCXI_LE_RES(info->rx_attr->size * info->domain_attr->rx_ctx_cnt);
			limits[CXI_RESOURCE_PE3_LE].reserved = KCXI_LE_RES(info->rx_attr->size * info->domain_attr->rx_ctx_cnt);
		}
	}

	LOG_INFO("%s CXI resource reservations",
		 dynamic_alloc ? "Dynamic" : "Parameter based");
	LOG_INFO("  ACs: %ld  EQs: %ld  PTEs: %ld  TGQs: %ld  TXQs: %ld  LEs: %ld",
		 limits[CXI_RESOURCE_AC].reserved,
		 limits[CXI_RESOURCE_EQ].reserved,
		 limits[CXI_RESOURCE_PTLTE].reserved,
		 limits[CXI_RESOURCE_TGQ].reserved,
		 limits[CXI_RESOURCE_TXQ].reserved,
		 limits[CXI_RESOURCE_PE0_LE].reserved);

	rgroup = cxi_dev_alloc_rgroup(cdev, NULL);
	if (IS_ERR(rgroup)) {
		rc = PTR_ERR(rgroup);
		pr_debug("Failed to allocate rgroup:%d\n", rc);
		return rc;
	}

	cxi_rgroup_set_system_service(rgroup, true);
	cxi_rgroup_set_name(rgroup, "kfabric-rgroup");

	LOG_INFO("Allocated %s id:%d", cxi_rgroup_name(rgroup),
	         cxi_rgroup_id(rgroup));

	for (i = CXI_RESOURCE_PTLTE; i < CXI_RESOURCE_MAX; i++) {
		if (!limits[i].reserved && !limits[i].max)
			continue;

		rc = cxi_rgroup_add_resource(rgroup, i, &limits[i]);
		if (rc)
			goto err;
	}

	rc = cxi_rgroup_add_ac_entry(rgroup, CXI_AC_UID, &ac_data,
				     &ac_entry_id);
	if (rc)
		goto err;

	cxi_rgroup_enable(rgroup);

	kcxi_if->rgroup = rgroup;

	return 0;

err:
	cxi_rgroup_dec_refcount(rgroup);

	return rc;
}


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
	struct kcxi_if *kcxi_if;
	struct kcxi_dev *kdev;
	struct cxi_dev *cdev;
	char if_debugfs_dir_name[16];
	uint16_t auth_key = *(info->domain_attr->auth_key);

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

	rc = kcxi_alloc_rgroup_rsrcs(cdev, kcxi_if, fabric, info);
	if (rc < 0) {
		LOG_INFO("Unable to reserve requested resources");
		goto err_unlock;
	}

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

	kcxi_if->lni = cxi_lni_alloc(cdev, cxi_rgroup_id(kcxi_if->rgroup));
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
	cxi_rgroup_dec_refcount(kcxi_if->rgroup);
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

	if (!kcxi_if)
		return -EINVAL;

	if (atomic_read(&kcxi_if->ref_cnt))
		return -EBUSY;

	KCXI_IF_INFO(kcxi_if, "Interface freed");

	flush_workqueue(kcxi_wq);

	debugfs_remove_recursive(kcxi_if->if_debugfs_dir);

	kdev = kcxi_if->dev;

	cxi_lni_free(kcxi_if->lni);

	kcxi_tx_profiles_cleanup(kcxi_if);
	kcxi_rx_profiles_cleanup(kcxi_if);
	cxi_rgroup_dec_refcount(kcxi_if->rgroup);

	kfree(kcxi_if);

	kcxi_dev_put(kdev);

	return 0;
}
