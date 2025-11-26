//SPDX-License-Identifier: GPL-2.0
/*
 * Cray kfabric CXI provider device.
 * Copyright 2019-2022 Hewlett Packard Enterprise Development LP. All rights reserved.
 */
#include <linux/slab.h>
#include <linux/module.h>

#include "kcxi_prov.h"
#include "linux/etherdevice.h"

static LIST_HEAD(dev_list);
static DEFINE_MUTEX(dev_list_lock);

static bool skip_device_ready_checks;
module_param(skip_device_ready_checks, bool, 0444);
MODULE_PARM_DESC(skip_device_ready_checks,
		 "Skip device readiness checks when returning devices to kfabric clients");

/**
 * kcxi_dev_get_nic_addr() - Get kCXI device NIC address.
 * @kdev: kCXI device.
 *
 * Return: The NIC address if this has been configured. Else, ENODEV.
 */
static int kcxi_dev_get_nic_addr(struct kcxi_dev *kdev)
{
	struct cxi_dev *cdev;
	int lock_idx;
	int rc;

	lock_idx = srcu_read_lock(&kdev->dev_lock);

	cdev = srcu_dereference(kdev->dev, &kdev->dev_lock);
	if (cdev && cdev->prop.nid != CXI_INVALID_NID)
		rc = cdev->prop.nid;
	else
		rc = -ENODEV;

	srcu_read_unlock(&kdev->dev_lock, lock_idx);

	return rc;
}

/**
 * kcxi_dev_ready() - Check if device is ready to be used.
 * @kdev: kCXI device.
 *
 * Return: True if device is ready. Else, false.
 */
bool kcxi_dev_ready(struct kcxi_dev *kdev)
{
	struct cxi_dev *cdev;
	int lock_idx;
	bool rh_running;

	if (skip_device_ready_checks)
		return true;

	lock_idx = srcu_read_lock(&kdev->dev_lock);

	cdev = srcu_dereference(kdev->dev, &kdev->dev_lock);
	if (!cdev) {
		srcu_read_unlock(&kdev->dev_lock, lock_idx);
		KCXI_DEV_ERR(kdev, "Failed to dereference CXI device");
		return false;
	}

	rh_running = cxi_retry_handler_running(cdev);

	srcu_read_unlock(&kdev->dev_lock, lock_idx);

	if (!rh_running) {
		KCXI_DEV_ERR(kdev, "Retry handler not running");
		return false;
	}

	return true;
}

/**
 * kcxi_dev_nic_array() - Build an array of NIC addresses.
 * @nic_array: Array to be allocated.
 *
 * Return: On success, number of elements in array. Else negative errno. If the
 * number of elements in greater than zero, users are responsible for freeing
 * the NIC array.
 */
ssize_t kcxi_dev_nic_array(unsigned int **nic_array)
{
	struct kcxi_dev *kdev;
	int count = 0;
	int rc;

	mutex_lock(&dev_list_lock);
	list_for_each_entry(kdev, &dev_list, entry)
		count++;

	if (!count)
		goto out_unlock;

	*nic_array = kcalloc(count, sizeof(**nic_array), GFP_KERNEL);
	if (!*nic_array) {
		rc = -ENOMEM;
		goto err_unlock;
	}

	count = 0;
	list_for_each_entry(kdev, &dev_list, entry) {
		rc = kcxi_dev_get_nic_addr(kdev);
		if (rc < 0)
			goto err_free_nic_array;

		(*nic_array)[count] = rc;
		count++;
	}

	rc = count;

out_unlock:
	mutex_unlock(&dev_list_lock);

	return count;

err_free_nic_array:
	kfree(*nic_array);
err_unlock:
	mutex_unlock(&dev_list_lock);

	return rc;
}

/**
 * kcxi_dev_first_nic() - Get the first NIC regardless of fabric.
 * @nic: User pointer to be set on success.
 *
 * Return: On success, positive value representing the NIC address  Else,
 * negative errno.
 */
int kcxi_dev_first_nic(void)
{
	struct kcxi_dev *kdev;
	int rc;

	mutex_lock(&dev_list_lock);
	kdev = list_first_entry_or_null(&dev_list, struct kcxi_dev, entry);
	if (!kdev)
		rc = -ENODEV;
	else
		rc = kcxi_dev_get_nic_addr(kdev);
	mutex_unlock(&dev_list_lock);

	return rc;
}

/**
 * kcxi_dev_fabric() - Get the fabric for a given NIC.
 * @nic: NIC address.
 *
 * Return: NIC fabric on success. Else, negative errno.
 */
int kcxi_dev_fabric(unsigned int nic)
{
	struct kcxi_dev *kdev;
	int rc = -ENODEV;
	int nic_addr;

	mutex_lock(&dev_list_lock);
	list_for_each_entry(kdev, &dev_list, entry) {
		nic_addr = kcxi_dev_get_nic_addr(kdev);
		if (nic_addr < 0)
			continue;

		if (nic_addr == nic) {
			rc = kdev->fabric;
			break;
		}
	}
	mutex_unlock(&dev_list_lock);

	return rc;
}

/**
 * kcxi_dev_index_to_addr() - Return a local NIC address based on an offset.
 *
 * Return: On success, positive value representing the NIC address  Else,
 * negative errno.
 */
int kcxi_dev_index_to_addr(unsigned int index)
{
	struct kcxi_dev *kdev;
	int rc = -ENODEV;
	int nic_addr;

	mutex_lock(&dev_list_lock);
	list_for_each_entry(kdev, &dev_list, entry) {
		if (kdev->index != index)
			continue;

		nic_addr = kcxi_dev_get_nic_addr(kdev);
		if (nic_addr < 0)
			continue;

		rc = nic_addr;
		break;
	}
	mutex_unlock(&dev_list_lock);

	return rc;
}

/**
 * kcxi_dev_index() - Get the index for a given NIC.
 * @nic: NIC address.
 *
 * Return: NIC index on success. Else, negative errno.
 */
int kcxi_dev_index(unsigned int nic)
{
	struct kcxi_dev *kdev;
	int rc = -ENODEV;
	int nic_addr;

	mutex_lock(&dev_list_lock);
	list_for_each_entry(kdev, &dev_list, entry) {
		nic_addr = kcxi_dev_get_nic_addr(kdev);
		if (nic_addr < 0)
			continue;

		if (nic_addr == nic) {
			rc = kdev->index;
			break;
		}
	}
	mutex_unlock(&dev_list_lock);

	return rc;
}

/**
 * kcxi_dev_nic_exists() - Check if a NIC exists.
 * @nic: NIC address.
 *
 * Return: True if NIC exists. Else, false.
 */
bool kcxi_dev_nic_exists(unsigned int nic)
{
	struct kcxi_dev *kdev;
	bool exists = false;
	int nic_addr;

	mutex_lock(&dev_list_lock);
	list_for_each_entry(kdev, &dev_list, entry) {
		nic_addr = kcxi_dev_get_nic_addr(kdev);
		if (nic_addr < 0)
			continue;

		if (nic_addr == nic) {
			exists = true;
			break;
		}
	}
	mutex_unlock(&dev_list_lock);

	return exists;
}

/**
 * kcxi_dev_fabric_exists() - Check if a fabric exists.
 * @fabric: Fabric ID.
 *
 * Return: True if fabric exists. Else, false.
 */
bool kcxi_dev_fabric_exists(unsigned int fabric)
{
	struct kcxi_dev *kdev;
	bool exists = false;

	mutex_lock(&dev_list_lock);
	list_for_each_entry(kdev, &dev_list, entry) {
		if (kdev->fabric == fabric) {
			exists = true;
			break;
		}
	}
	mutex_unlock(&dev_list_lock);

	return exists;
}

/**
 * kcxi_dev_index_exists() - Check if a index exists.
 * @index: NIC index.
 *
 * Return: True if index exists. Else, false.
 */
bool kcxi_dev_index_exists(unsigned int index)
{
	struct kcxi_dev *kdev;
	bool exists = false;

	mutex_lock(&dev_list_lock);
	list_for_each_entry(kdev, &dev_list, entry) {
		if (kdev->index == index) {
			exists = true;
			break;
		}
	}
	mutex_unlock(&dev_list_lock);

	return exists;
}

/**
 * kcxi_dev_add() - Add a kCXI device.
 * @cdev: CXI device.
 *
 * TODO: Handle different fabric slices. Defaults to 1.
 *
 * Return: 0 success. Else, negative errno.
 */
int kcxi_dev_add(struct cxi_dev *cdev)
{
	struct kcxi_dev *kdev;
	unsigned int multi_recv_bits;
	char dev_debugfs_dir_name[16];
	int rc;

	if (!cdev)
		return -EINVAL;

	kdev = kzalloc(sizeof(*kdev), GFP_KERNEL);
	if (!kdev)
		return -ENOMEM;

	rcu_assign_pointer(kdev->dev, cdev);
	init_srcu_struct(&kdev->dev_lock);
	kdev->index = cdev->cxi_num;
	kdev->fabric = 1;
	kdev->pid_granule = cdev->prop.pid_granule;
	kdev->pid_bits = cdev->prop.pid_bits;

	kdev->multi_recv_shift = cdev->prop.min_free_shift;
	multi_recv_bits = KCXI_MULTI_RECV_BITS + cdev->prop.min_free_shift;
	kdev->multi_recv_limit = (1 << multi_recv_bits) - 1;

	kdev->device = &cdev->pdev->dev;

	atomic_set(&kdev->ref_cnt, 0);

	rc = snprintf(dev_debugfs_dir_name, sizeof(dev_debugfs_dir_name),
		      "cxi%u", kdev->index);
	if (rc >= sizeof(dev_debugfs_dir_name)) {
		rc = -ENOMEM;
		goto err_free_dev;
	} else if (rc < 0) {
		goto err_free_dev;
	}

	kdev->dev_debugfs_dir = debugfs_create_dir(dev_debugfs_dir_name,
						   kcxi_debugfs_dir);

	mutex_lock(&dev_list_lock);
	list_add_tail(&kdev->entry, &dev_list);
	mutex_unlock(&dev_list_lock);

	KCXI_DEV_INFO(kdev, "Device added");

	return 0;

err_free_dev:
	kfree(kdev);

	return rc;
}

static void kcxi_dev_free(struct kcxi_dev *kdev)
{
	KCXI_DEV_INFO(kdev, "Device freed");

	debugfs_remove_recursive(kdev->dev_debugfs_dir);
	cleanup_srcu_struct(&kdev->dev_lock);
	kfree(kdev);
}

/**
 * kcxi_dev_remove() - Remove a kCXI device.
 * @cdev: CXI device to be removed.
 *
 * Note: kCXI device is removed from the global list but is not freed until
 * zero ref counts.
 */
void kcxi_dev_remove(struct cxi_dev *cdev)
{
	struct kcxi_dev *kdev;
	bool free_dev = false;

	if (!cdev)
		return;

	mutex_lock(&dev_list_lock);
	list_for_each_entry(kdev, &dev_list, entry) {
		if (kdev->dev == cdev) {
			rcu_assign_pointer(kdev->dev, NULL);
			synchronize_srcu(&kdev->dev_lock);

			list_del(&kdev->entry);
			if (!atomic_read(&kdev->ref_cnt))
				free_dev = true;

			break;
		}
	}
	mutex_unlock(&dev_list_lock);

	KCXI_DEV_INFO(kdev, "Device removed");

	if (free_dev)
		kcxi_dev_free(kdev);
}

/**
 * kcxi_dev_get() - Get a kCXI device.
 * @nic: NIC address for the kCXI device.
 *
 * Return: Valid pointer on success. Else, errno pointer.
 */
struct kcxi_dev *kcxi_dev_get(unsigned int nic)
{
	struct kcxi_dev *kdev;
	bool found = false;
	int nic_addr;

	mutex_lock(&dev_list_lock);
	list_for_each_entry(kdev, &dev_list, entry) {
		nic_addr = kcxi_dev_get_nic_addr(kdev);
		if (nic_addr < 0)
			continue;

		if (nic_addr == nic) {
			atomic_inc(&kdev->ref_cnt);
			found = true;
			break;
		}
	}
	mutex_unlock(&dev_list_lock);

	if (!found)
		return ERR_PTR(-ENODEV);

	return kdev;
}

/**
 * kcxi_dev_put() - Put a kCXI device.
 * @kdev: kCXI device to put.
 */
void kcxi_dev_put(struct kcxi_dev *kdev)
{
	bool free_dev = false;
	struct cxi_dev *cdev;
	int lock_idx;

	if (!kdev)
		return;

	mutex_lock(&dev_list_lock);
	if (atomic_dec_and_test(&kdev->ref_cnt)) {
		/* Device can no longer be used if the CXI device pointer is
		 * NULL. Note that if NULL, the kCXI device has already be
		 * removed from the global list.
		 */
		lock_idx = srcu_read_lock(&kdev->dev_lock);
		cdev = srcu_dereference(kdev->dev, &kdev->dev_lock);
		if (!cdev)
			free_dev = true;
		srcu_read_unlock(&kdev->dev_lock, lock_idx);
	}
	mutex_unlock(&dev_list_lock);

	if (free_dev)
		kcxi_dev_free(kdev);
}

/**
 * kcxi_async_event() - Asynchronous CXI event handler.
 * @cdev: kCXI device.
 * @event: the event
 */
void kcxi_async_event(struct cxi_dev *cdev, enum cxi_async_event event)
{
	struct kcxi_dev *kdev;
	bool found = false;

	mutex_lock(&dev_list_lock);
	list_for_each_entry(kdev, &dev_list, entry) {
		if (kdev->dev == cdev) {
			found = true;
			break;
		}
	}
	mutex_unlock(&dev_list_lock);

	if (!found)
		return;

	KCXI_DEV_INFO(kdev, "Got CXI async event %d", event);

	switch (event) {
	case CXI_EVENT_NID_CHANGED:
		// TODO
		break;

	default:
		break;
	}
}
