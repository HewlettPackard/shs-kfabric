//SPDX-License-Identifier: GPL-2.0
/*
 * Cray kfabric CXI provider communication profile.
 * Copyright 2025 Hewlett Packard Enterprise Development LP
 */
#include <linux/slab.h>

#include "kcxi_prov.h"

/**
 * kcxi_get_tx_profile() - Find or allocate a new TX profile.
 *
 * @kcxi_if: kCXI interface used to allocate communication profile.
 * @vni: VNI for TX profile.
 *
 * Return: Valid pointer on success. Else, negative errno value.
 */
int kcxi_get_tx_profile(struct kcxi_if *kcxi_if, unsigned int vni)
{
	int rc;
	struct kcxi_tx_profile *tx_prof;

	tx_prof = kzalloc(sizeof(*tx_prof), GFP_KERNEL);
	if (!tx_prof)
		return -ENOMEM;

	mutex_lock(&kcxi_if->txp_lock);

	tx_prof->tx_profile = cxi_dev_get_tx_profile(kcxi_if->dev->dev, vni);
	if (IS_ERR(tx_prof->tx_profile)) {
		rc = PTR_ERR(tx_prof->tx_profile);
		LOG_ERR("Unable to get TX profile for vni:%d rc:%d", vni, rc);
		goto err_free;
	}

	list_add(&tx_prof->entry, &kcxi_if->tx_profile_list);

	mutex_unlock(&kcxi_if->txp_lock);

	return 0;

err_free:
	mutex_unlock(&kcxi_if->txp_lock);
	kfree(tx_prof);
	return rc;
}

/**
 * kcxi_put_tx_profile() - Remove a TX profile
 *
 * @kcxi_if - kCXI interface used to allocate communication profile.
 * @vni: VNI of TX profile to remove.
 */
void kcxi_put_tx_profile(struct kcxi_if *kcxi_if, unsigned int vni)
{
	struct kcxi_tx_profile *tx_prof;
	struct kcxi_tx_profile *temp;

	mutex_lock(&kcxi_if->txp_lock);

	list_for_each_entry_safe(tx_prof, temp,
				 &kcxi_if->tx_profile_list, entry) {
		if (tx_prof->tx_profile->profile_common.vni_attr.match == vni) {
			cxi_tx_profile_dec_refcount(kcxi_if->dev->dev,
						    tx_prof->tx_profile,
						    true);
			list_del(&tx_prof->entry);
			break;
		}
	}

	mutex_unlock(&kcxi_if->txp_lock);
}

/**
 * kcxi_tx_profiles_cleanup() - Remove all TX profiles
 *
 * @kcxi_if - kCXI interface used to allocate communication profile.
 */
void kcxi_tx_profiles_cleanup(struct kcxi_if *kcxi_if)
{
	struct kcxi_tx_profile *tx_prof;
	struct kcxi_tx_profile *temp;

	mutex_lock(&kcxi_if->txp_lock);

	list_for_each_entry_safe(tx_prof, temp,
				 &kcxi_if->tx_profile_list, entry) {
		cxi_tx_profile_dec_refcount(kcxi_if->dev->dev,
					    tx_prof->tx_profile,
					    true);
		list_del(&tx_prof->entry);
	}

	mutex_unlock(&kcxi_if->txp_lock);
}

/**
 * kcxi_get_rx_profile() - Find or allocate a new RX profile.
 *
 * @kcxi_if - kCXI interface used to allocate communication profile.
 * @vni: VNI for RX profile.
 *
 * Return: Valid pointer on success. Else, negative errno value.
 */
int kcxi_get_rx_profile(struct kcxi_if *kcxi_if, unsigned int vni)
{
	int rc;
	struct kcxi_rx_profile *rx_prof;

	rx_prof = kzalloc(sizeof(*rx_prof), GFP_KERNEL);
	if (!rx_prof)
		return -ENOMEM;

	rx_prof->rx_profile = cxi_dev_get_rx_profile(kcxi_if->dev->dev, vni);
	if (IS_ERR(rx_prof->rx_profile)) {
		LOG_ERR("Unable to get RX profile for vni:%d", vni);
		rc = PTR_ERR(rx_prof->rx_profile);
		goto err_free;
	}

	list_add(&rx_prof->entry, &kcxi_if->rx_profile_list);

	mutex_unlock(&kcxi_if->rxp_lock);

	return 0;

err_free:
	mutex_unlock(&kcxi_if->rxp_lock);
	kfree(rx_prof);
	return rc;
}

/**
 * kcxi_put_rx_profile() - Remove an RX profile
 *
 * @kcxi_if - kCXI interface used to allocate communication profile.
 * @vni: VNI of RX profile to remove.
 */
void kcxi_put_rx_profile(struct kcxi_if *kcxi_if, unsigned int vni)
{
	struct kcxi_rx_profile *rx_prof;
	struct kcxi_rx_profile *temp;

	mutex_lock(&kcxi_if->rxp_lock);

	list_for_each_entry_safe(rx_prof, temp,
				 &kcxi_if->rx_profile_list, entry) {
		if (rx_prof->rx_profile->profile_common.vni_attr.match == vni) {
			cxi_rx_profile_dec_refcount(kcxi_if->dev->dev,
						    rx_prof->rx_profile);
			list_del(&rx_prof->entry);
			break;
		}
	}

	mutex_unlock(&kcxi_if->rxp_lock);
}

/**
 * kcxi_rx_profiles_cleanup() - Remove all RX profiles
 *
 * @kcxi_if - kCXI interface used to allocate communication profile.
 */
void kcxi_rx_profiles_cleanup(struct kcxi_if *kcxi_if)
{
	struct kcxi_rx_profile *rx_prof;
	struct kcxi_rx_profile *temp;

	mutex_lock(&kcxi_if->rxp_lock);

	list_for_each_entry_safe(rx_prof, temp,
				 &kcxi_if->rx_profile_list, entry) {
		cxi_rx_profile_dec_refcount(kcxi_if->dev->dev,
					    rx_prof->rx_profile);
		list_del(&rx_prof->entry);
	}

	mutex_unlock(&kcxi_if->rxp_lock);
}
