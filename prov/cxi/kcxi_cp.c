//SPDX-License-Identifier: GPL-2.0
/*
 * Cray kfabric CXI provider communication profile.
 * Copyright 2019-2022 Hewlett Packard Enterprise Development LP. All rights reserved.
 */
#include <linux/slab.h>

#include "kcxi_prov.h"

/**
 * kcxi_cp_new() - Allocate a new communication profile.
 * @kcxi_if - kCXI interface used to allocate communication profile.
 * @auth_key: Authorization key for communication profile.
 * @tc: Traffic class for communication profile.
 *
 * Return: Valid pointer on success. Else, negative errno value.
 */
static struct kcxi_cp *kcxi_cp_new(struct kcxi_if *kcxi_if,
				   unsigned int auth_key,
				   enum cxi_traffic_class tc)
{
	struct kcxi_cp *cp;
	int rc;

	cp = kzalloc(sizeof(*cp), GFP_KERNEL);
	if (!cp) {
		rc = -ENOMEM;
		goto err;
	}

	cp->cp = cxi_cp_alloc(kcxi_if->lni, auth_key, tc, CXI_TC_TYPE_DEFAULT);
	if (IS_ERR(cp->cp)) {
		rc = PTR_ERR(cp->cp);
		goto err_free_cp;
	}

	cp->kcxi_if = kcxi_if;

	atomic_set(&cp->ref_cnt, 0);

	list_add(&cp->entry, &kcxi_if->cp_list);

	atomic_inc(&kcxi_if->ref_cnt);
	atomic_inc(&kcxi_if->cp_cnt);

	return cp;

err_free_cp:
	kfree(cp);
err:
	KCXI_IF_DEBUG(kcxi_if,
		      "New communication profile allocation failed: rc=%d", rc);

	return ERR_PTR(rc);
}

/**
 * kcxi_cp_reuse() - Reuse a communication profile.
 * @kcxi_if - kCXI interface used to reuse a communication profile.
 * @auth_key: Authorization key for communication profile.
 * @tc: Traffic class for communication profile.
 *
 * Return: Valid pointer on success. Else, negative errno value.
 */
static struct kcxi_cp *kcxi_cp_reuse(struct kcxi_if *kcxi_if,
				     unsigned int auth_key,
				     enum cxi_traffic_class tc)
{
	struct kcxi_cp *cp;

	/* Prefer LRU entries. */
	list_for_each_entry_reverse(cp, &kcxi_if->cp_list, entry) {
		if (cp->cp->vni == auth_key && cp->cp->tc == tc) {
			list_del(&cp->entry);
			list_add(&cp->entry, &kcxi_if->cp_list);
			return cp;
		}
	}

	return ERR_PTR(-ENOSPC);
}

/**
 * kcxi_cp_alloc() - Allocate a communication profile.
 * @kcxi_if - kCXI interface used to allocate communication profile.
 * @auth_key: Authorization key for communication profile.
 * @tc: Traffic class for communication profile.
 *
 * Return: Valid pointer on success. Else, negative errno value.
 */
struct kcxi_cp *kcxi_cp_alloc(struct kcxi_if *kcxi_if, unsigned int auth_key,
			      enum cxi_traffic_class tc)
{
	struct kcxi_cp *cp;
	int rc;

	if (!kcxi_if) {
		rc = -EINVAL;
		goto err;
	}

	/* Prefer reusing a communication profile before allocating a new one.
	 */
	mutex_lock(&kcxi_if->cp_lock);

	cp = kcxi_cp_reuse(kcxi_if, auth_key, tc);
	if (IS_ERR(cp)) {
		cp = kcxi_cp_new(kcxi_if, auth_key, tc);
		if (IS_ERR(cp))
			goto err_unlock;
	}

	atomic_inc(&cp->ref_cnt);

	mutex_unlock(&kcxi_if->cp_lock);

	KCXI_IF_DEBUG(kcxi_if,
		      "Communication profile allocated: auth_key=%u tc=%d",
		      auth_key, tc);

	return cp;

err_unlock:
	mutex_unlock(&kcxi_if->cp_lock);
err:
	KCXI_IF_ERR(kcxi_if, "Failed to allocate communication profile: rc=%d",
		    rc);

	return ERR_PTR(rc);
}

/**
 * kcxi_cp_free() - Free a communication profile.
 * @cp: Communication profile to be freed.
 */
void kcxi_cp_free(struct kcxi_cp *cp)
{
	struct kcxi_if *kcxi_if;
	if (!cp)
		return;

	kcxi_if = cp->kcxi_if;

	KCXI_IF_DEBUG(kcxi_if,
		      "Communication profile freed: auth_key=%u tc=%d",
		      cp->cp->vni, cp->cp->tc);

	mutex_lock(&kcxi_if->cp_lock);
	if (atomic_dec_and_test(&cp->ref_cnt)) {
		atomic_dec(&cp->kcxi_if->cp_cnt);
		atomic_dec(&cp->kcxi_if->ref_cnt);

		list_del(&cp->entry);

		cxi_cp_free(cp->cp);

		kfree(cp);
	}
	mutex_unlock(&kcxi_if->cp_lock);
}
