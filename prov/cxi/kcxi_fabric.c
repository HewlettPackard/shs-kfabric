/*
 * Cray kfabric CXI provider fabric.
 * Copyright 2018-2024 Hewlett Packard Enterprise Development LP. All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0
 */
#include <linux/slab.h>
#include <linux/rwlock.h>
#include <linux/if_ether.h>
#include <linux/module.h>

#include "kcxi_prov.h"

static const char *kcxi_fabric_fmt = "cxi/%d";
static const char *kcxi_domain_fmt = "cxi%u";

static const struct kfi_fabric_attr kcxi_fabric_attr = {
	.prov_name = KCXI_PROV_NAME,
	.prov_version = KCXI_PROV_VERSION,
};

static LIST_HEAD(kcxi_fab_list);
static DEFINE_MUTEX(kcxi_fab_list_lock);

static char *kcxi_get_fabric_name(const struct kcxi_addr *src_addr)
{
	int fabric;

	if (!src_addr)
		return NULL;

	fabric = kcxi_dev_fabric(src_addr->nic);
	if (fabric < 0)
		return NULL;

	return kasprintf(GFP_KERNEL, kcxi_fabric_fmt, fabric);
}

static int kcxi_validate_fabric_name(const char *name)
{
	uint32_t fabric;
	int rc;

	if (!name)
		return -EINVAL;

	rc = sscanf(name, kcxi_fabric_fmt, &fabric);
	if (rc != 1)
		return -EINVAL;

	if (!kcxi_dev_fabric_exists(fabric))
		return -EINVAL;

	return 0;
}

/**
 * kcxi_get_domain_name() - Get the domain name from source address
 * @src_addr: The source address
 *
 * Return: Valid pointer on success. NULL on error.
 */
char *kcxi_get_domain_name(const struct kcxi_addr *src_addr)
{
	int idx;

	if (!src_addr)
		return NULL;

	idx = kcxi_dev_index(src_addr->nic);
	if (idx < 0)
		return NULL;

	return kasprintf(GFP_KERNEL, kcxi_domain_fmt, idx);
}

int kcxi_validate_domain_name(const char *name)
{
	uint32_t idx;
	int rc;

	if (!name)
		return -EINVAL;

	rc = sscanf(name, kcxi_domain_fmt, &idx);
	if (rc != 1)
		return -EINVAL;

	if (!kcxi_dev_index_exists(idx))
		return -EINVAL;

	return 0;
}


static bool kcxi_fab_check_list(const struct kcxi_fabric *fabric)
{
	struct kcxi_fabric *fab_entry;

	if (!fabric)
		return false;

	mutex_lock(&kcxi_fab_list_lock);
	list_for_each_entry(fab_entry, &kcxi_fab_list, entry) {
		if (fab_entry == fabric) {
			mutex_unlock(&kcxi_fab_list_lock);
			return true;
		}
	}
	mutex_unlock(&kcxi_fab_list_lock);

	return false;
}

static int kcxi_set_fabric_attr(const struct kcxi_addr *src_addr,
				struct kfi_fabric_attr *attr)
{
	struct kcxi_fabric *fab_entry;

	if (!src_addr) {
		LOG_ERR("kCXI source address must be defined");
		return -EINVAL;
	}

	if (!attr) {
		LOG_ERR("Fabric attributes cannot be NULL");
		return -EINVAL;
	}

	if (!attr->prov_version)
		attr->prov_version = KCXI_PROV_VERSION;

	if (!attr->fabric) {
		mutex_lock(&kcxi_fab_list_lock);
		if (list_empty(&kcxi_fab_list)) {
			attr->fabric = NULL;
		} else {
			fab_entry = list_first_entry(&kcxi_fab_list,
						     struct kcxi_fabric,
						     entry);
			attr->fabric = &fab_entry->fab_fid;
		}
		mutex_unlock(&kcxi_fab_list_lock);
	}

	/* Reset the name */
	if (attr->name)
		kfree(attr->name);

	attr->name = kcxi_get_fabric_name(src_addr);
	if (!attr->name) {
		LOG_ERR("Failed to allocate kCXI fabric name");
		return -ENOMEM;
	}

	return 0;
}

static int kcxi_verify_fabric_attr(const struct kfi_fabric_attr *attr)
{
	if (!attr) {
		LOG_ERR("Bad Fabric Attr: Cannot verify NULL attr");
		return -EINVAL;
	}

	if (attr->name) {
		if (kcxi_validate_fabric_name(attr->name)) {
			LOG_ERR("Bad Fabric Attr: Invalid fabric name %s",
				attr->name);
			goto nomatch;
		}
	}

	if (attr->prov_version &&
	    (KFI_MAJOR(attr->prov_version) >
	     KFI_MAJOR(kcxi_fabric_attr.prov_version))) {
		LOG_ERR("Bad Fabric Attr: Invalid provider version %u",
			attr->prov_version);
		goto nomatch;
	}

	if (attr->prov_name &&
	    (strcmp(attr->prov_name, kcxi_fabric_attr.prov_name) != 0)) {
		LOG_ERR("Bad Fabric Attr: Invalid provider name %s",
			attr->prov_name);
		goto nomatch;
	}

	return 0;

nomatch:
	return -ENODATA;
}

int kcxi_verify_info(const struct kfi_info *hints,
		     const struct kcxi_addr *src_addr)
{
	uint64_t caps;
	int rc;
	enum kfi_ep_type ep_type;
	struct kcxi_fabric *fabric;
	struct kfid_fabric *fab_fid = NULL;
	struct kcxi_dev *kdev;
	bool kdev_ready;

	/* Verify source kCXI drive is ready. */
	kdev = kcxi_dev_get(src_addr->nic);
	if (IS_ERR(kdev))
		goto nomatch;

	kdev_ready = kcxi_dev_ready(kdev);

	kcxi_dev_put(kdev);

	if (!kdev_ready)
		goto nomatch;

	/* NULL hints is valid input */
	if (!hints)
		return 0;

	ep_type = hints->ep_attr ? hints->ep_attr->type : KFI_EP_UNSPEC;
	switch (ep_type) {
	case KFI_EP_UNSPEC:
	case KFI_EP_RDM:
		caps = KCXI_EP_RDM_CAP;
		rc = kcxi_rdm_verify_ep_attr(hints->ep_attr, hints->tx_attr,
					     hints->rx_attr, hints->caps);
		if (rc)
			goto nomatch;
		break;
	default:
		goto nomatch;
	}

	if (hints->caps & ~caps) {
		LOG_ERR("Bad Info: Unsupported capabilities %llx", hints->caps);
		goto nomatch;
	}

	switch (hints->addr_format) {
	case KFI_FORMAT_UNSPEC:
	case KFI_ADDR_CXI:
		break;
	default:
		goto nomatch;
	}

	if (hints->fabric_attr && hints->fabric_attr->fabric) {
		fabric = container_of(hints->fabric_attr->fabric,
				      struct kcxi_fabric, fab_fid);
		if (!kcxi_fab_check_list(fabric)) {
			LOG_ERR("Bad Fabric Attr: Invalid fabric object");
			goto nomatch;
		}

		fab_fid = hints->fabric_attr->fabric;
	}

	rc = kcxi_verify_fabric_attr(hints->fabric_attr);
	if (rc)
		goto nomatch;

	rc = kcxi_verify_domain_attr(fab_fid, src_addr, hints->domain_attr,
				     hints->caps);
	if (rc)
		goto nomatch;

	return 0;

nomatch:
	return -ENODATA;
}


int kcxi_get_src_addr(struct kcxi_addr *dest_addr, struct kcxi_addr *src_addr)
{
	bool loopback = false;
	int rc;

	if (!dest_addr || !src_addr)
		return -ENODATA;

	if (kcxi_dev_nic_exists(dest_addr->nic))
		loopback = true;

	if (loopback) {
		memcpy(src_addr, dest_addr, sizeof(*src_addr));
		return 0;
	}

	/* TODO: How to select an address of matching network */

	/* Just say the first IF matches */
	rc = kcxi_dev_first_nic();
	if (rc < 0)
		return rc;

	src_addr->nic = rc;

	return 0;
}

static int kcxi_kfi_checkinfo(const struct kfi_info *info,
			      const struct kfi_info *hints)
{
	int rc;

	if (!hints || !info || !hints->domain_attr ||
	    !hints->domain_attr->name || !hints->fabric_attr ||
	    !hints->fabric_attr->name)
		return 0;

	rc = strcmp(info->domain_attr->name, hints->domain_attr->name);
	if (rc)
		return -ENODATA;

	rc = strcmp(info->fabric_attr->name, hints->fabric_attr->name);
	if (rc)
		return -ENODATA;

	return 0;
}

static int kcxi_ep_getinfo(const char *node, const char *service,
			   uint64_t flags, const struct kfi_info *hints,
			   enum kfi_ep_type ep_type, struct kfi_info **info)
{
	struct kcxi_addr addr = {};
	struct kcxi_addr *src_addr = NULL;
	struct kcxi_addr *dest_addr = NULL;
	int rc;

	if (flags & KFI_SOURCE) {
		if (!node && !service)
			goto nomatch;

		src_addr = &addr;
		rc = kcxi_addr_res_src_info(node, service, src_addr);
		if (rc)
			goto nomatch;

		if (hints && hints->dest_addr)
			dest_addr = hints->dest_addr;
	} else {
		if (node || service) {
			dest_addr = &addr;

			rc = kcxi_addr_res_dest_info(node, service, dest_addr);
			if (rc)
				goto nomatch;
		} else if (hints) {
			dest_addr = hints->src_addr;
		}

		if (hints && hints->src_addr)
			src_addr = hints->src_addr;
	}

	if (dest_addr && !src_addr) {
		src_addr = &addr;
		rc = kcxi_get_src_addr(dest_addr, src_addr);
		if (rc)
			goto nomatch;
	}

	/* Validated hints against the local source address. */
	rc = kcxi_verify_info(hints, src_addr);
	if (rc)
		goto nomatch;

	switch (ep_type) {
	case KFI_EP_RDM:
		rc = kcxi_rdm_kfi_info(src_addr, dest_addr, hints, info);
		if (rc)
			goto nomatch;
		break;
	default:
		goto nomatch;
	}

	return rc;

nomatch:
	*info = NULL;
	return -ENODATA;
}

static int kcxi_node_getinfo(const char *node, const char *service,
			     uint64_t flags, const struct kfi_info *hints,
			     struct kfi_info **info, struct kfi_info **tail)
{
	enum kfi_ep_type ep_type;
	struct kfi_info *cur;
	int rc;

	if (hints && hints->ep_attr) {
		switch (hints->ep_attr->type) {
		case KFI_EP_RDM:
		case KFI_EP_DGRAM:
		case KFI_EP_MSG:
			rc = kcxi_ep_getinfo(node, service, flags, hints,
					     hints->ep_attr->type, &cur);
			if (rc) {
				if (rc == -ENODATA)
					return rc;
				goto err;
			}

			if (!*info)
				*info = cur;
			else
				(*tail)->next = cur;
			*tail = cur;

			return 0;
		default:
			break;
		}
	}

	for (ep_type = KFI_EP_MSG; ep_type <= KFI_EP_RDM; ep_type++) {
		rc = kcxi_ep_getinfo(node, service, flags, hints, ep_type,
				     &cur);

		if (rc) {
			if (rc == -ENODATA)
				continue;
			goto err;
		}

		if (!*info)
			*info = cur;
		else
			(*tail)->next = cur;
		*tail = cur;
	}

	if (!*info) {
		rc = -ENODATA;
		goto err_no_free;
	}
	return 0;

err:
	kfi_freeinfo(*info);
	*info = NULL;

err_no_free:
	return rc;
}

static int kcxi_node_matches_interface(const char *node)
{
	uint32_t nic;
	int rc;

	rc = kcxi_addr_res_node_src(node);
	if (rc < 0)
		return 0;
	nic = rc;

	return kcxi_dev_nic_exists(nic);
}

/**
 * kcxi_kfi_info() - Allocate base kfi_info structure
 * @hints: User provided hints
 * @src_addr: Source address
 * @dest_addr: Destination address
 *
 * A based kfi_info structure will have everything set and verified except
 * the ep, tx, and rx attributes.
 *
 * Return: Pointer on success. NULL on error.
 */
struct kfi_info *kcxi_kfi_info(const struct kfi_info *hints,
			       const struct kcxi_addr *src_addr,
			       const struct kcxi_addr *dest_addr)
{
	int rc;
	struct kfi_info *info;
	struct kfid_fabric *fab_fid = NULL;

	if (!src_addr)
		return NULL;

	/*
	 * Dupinfo may not allocate fabric, domain, ep, tx, rx attr. It is
	 * dependent on whether the initial hints have these defined.
	 */
	info = kfi_dupinfo(hints);
	if (!info)
		goto err;

	if (info->caps == 0)
		info->caps = KCXI_CAPS;
	if (info->mode == 0)
		info->mode = KCXI_MODE;
	if (info->addr_format == KFI_FORMAT_UNSPEC)
		info->addr_format = KFI_ADDR_CXI;
	if (info->src_addrlen &&
	    (info->src_addrlen != sizeof(struct kcxi_addr)))
		goto err;
	else
		info->src_addrlen = sizeof(struct kcxi_addr);

	if (!info->src_addr) {
		info->src_addr = kmalloc(info->src_addrlen, GFP_KERNEL);
		if (!info->src_addr)
			goto err;
	}
	memcpy(info->src_addr, src_addr, info->src_addrlen);

	if (dest_addr) {
		if (info->dest_addrlen &&
		    (info->dest_addrlen != sizeof(struct kcxi_addr)))
			goto err;
		else
			info->dest_addrlen = sizeof(struct kcxi_addr);

		if (!info->dest_addr) {
			info->dest_addr = kmalloc(info->dest_addrlen,
						  GFP_KERNEL);
			if (!info->dest_addr)
				goto err;
		}
		memcpy(info->dest_addr, dest_addr, info->dest_addrlen);
	}

	/*
	 * Dupinfo may not initialize fabric/domain attr. If it did, any
	 * defined fabric/domain attr in the hints are carried over to the
	 * dup version. So, just fill it the gaps with the set functions.
	 */
	if (info->fabric_attr) {
		rc = kcxi_set_fabric_attr(src_addr, info->fabric_attr);
		if (rc)
			goto err;

		/*
		 * This check may not be needed but does ensure consistency
		 * between the set and verify functions.
		 */
		rc = kcxi_verify_fabric_attr(info->fabric_attr);
		if (rc)
			goto err;

		fab_fid = info->fabric_attr->fabric;
	}

	if (info->domain_attr) {
		rc = kcxi_set_domain_attr(fab_fid, src_addr, info->domain_attr,
					  info->caps);
		if (rc)
			goto err;

		/*
		 * This check may not be needed but does ensure consistency
		 * between the set and verify functions.
		 */
		rc = kcxi_verify_domain_attr(fab_fid, src_addr,
					     info->domain_attr, info->caps);
		if (rc)
			goto err;
	}

	rc = kcxi_kfi_checkinfo(info, hints);
	if (rc)
		goto err;

	return info;

err:
	if (info)
		kfi_freeinfo(info);
	return NULL;
}

/**
 * kcxi_getinfo() kCXI get info implementation
 * @version: kCXI provider version
 * @node: Node string to be interrupted by provider
 * @service: Service string to be interrupted by provider
 * @flags: Flags
 * @hints: User provided hints
 * @kfi_info: Return info structures
 *
 * This function needs to be registered with the OFI framework.
 *
 * Return: 0 for success. Else, errno.
 */
int kcxi_getinfo(uint32_t version, const char *node, const char *service,
		 uint64_t flags, struct kfi_info *hints, struct kfi_info **info)
{
	/* TODO: Expand support for IPv4 port addressing */

	int rc;
	struct kcxi_addr *addr;
	struct kfi_info *tail;
	uint32_t *local_nics;
	ssize_t local_nic_count;
	char *local_node;
	int index;
	unsigned int nic;

	rc = kcxi_dev_first_nic();
	if (rc < 0) {
		LOG_ERR("No kCXI devices found");
		goto nomatch;
	}
	nic = rc;

	if (!(flags & KFI_SOURCE) && hints && hints->src_addr &&
	    (hints->src_addrlen != sizeof(struct kcxi_addr)))
		goto nomatch;

	if (((!node && !service) || (flags & KFI_SOURCE)) &&
	    hints && hints->dest_addr &&
	    (hints->dest_addrlen != sizeof(struct kcxi_addr)))
		goto nomatch;

	rc = 1;
	if ((flags & KFI_SOURCE) && node) {
		rc = kcxi_node_matches_interface(node);
	} else if (hints && hints->src_addr) {
		addr = (struct kcxi_addr *)hints->src_addr;
		rc = kcxi_dev_nic_exists(addr->nic);
	}

	if (!rc) {
		LOG_ERR("Failed to match with local kCXI interface");
		goto nomatch;
	}

	*info = tail = NULL;
	if (node ||
	    (!(flags & KFI_SOURCE) && hints && hints->src_addr) ||
	    (!(flags & KFI_SOURCE) && hints && hints->dest_addr)) {
		rc = kcxi_node_getinfo(node, service, flags, hints, info,
				       &tail);
		if (rc)
			goto nomatch;
	}

	/* Get a list of local NICs. */
	local_nic_count = kcxi_dev_nic_array(&local_nics);
	if (local_nic_count < 0)
		goto nomatch;

	/* Process the array of local nodes */
	flags |= KFI_SOURCE;
	for (index = 0; index < local_nic_count; index++) {
		local_node = kasprintf(GFP_KERNEL, "0x%x", local_nics[index]);
		if (!local_node)
			goto err_free_nic_array;

		rc = kcxi_node_getinfo(local_node, service, flags, hints, info,
				       &tail);

		kfree(local_node);

		if (rc) {
			if (rc == -ENODATA)
				continue;
			goto err_free_nic_array;
		}
	}

	kfree(local_nics);

	return (!*info) ? -ENODATA : 0;

err_free_nic_array:
	kfree(local_nics);
nomatch:
	return -ENODATA;
}

static int kcxi_fabric_close(struct kfid *fid)
{
	/*
	 * Don't need to check if fid is NULL since it is already dereferenced
	 * by kfi_close()
	 */

	struct kcxi_fabric *kcxi_fab;

	kcxi_fab = container_of(fid, struct kcxi_fabric, fab_fid.fid);

	if (atomic_read(&kcxi_fab->ref_cnt))
		return -EBUSY;

	mutex_lock(&kcxi_fab_list_lock);
	list_del(&kcxi_fab->entry);
	mutex_unlock(&kcxi_fab_list_lock);

	kfree(kcxi_fab);

	module_put(THIS_MODULE);

	return 0;
}

static int kcxi_fabric_enable_dynamic_rsrc_alloc(struct kfid *fid, bool enable)
{
	struct kcxi_fabric *kcxi_fab;

	kcxi_fab = container_of(fid, struct kcxi_fabric, fab_fid.fid);

	kcxi_fab->dynamic_rsrc_alloc = enable;

	return 0;
}

static struct kfi_cxi_fabric_ops kcxi_fabric_ops_ext = {
	.enable_dynamic_rsrc_alloc = kcxi_fabric_enable_dynamic_rsrc_alloc
};

static int kcxi_fabric_ops_open(struct kfid *fid, const char *name,
				uint64_t flags, void **ops, void *context)
{
	if (!strcmp(name, KFI_CXI_FAB_OPS_1)) {
		*ops = &kcxi_fabric_ops_ext;
		return 0;
	}

	return -EINVAL;
}

static struct kfi_ops_fabric cxi_fabric_ops = {
	.domain = kcxi_domain,
	.passive_ep = kfi_no_passive_ep,
	.eq_open = kcxi_eq_open,
	.wait_open = kfi_no_wait_open
};

static struct kfi_ops cxi_fabric_fid_ops = {
	.close = kcxi_fabric_close,
	.bind = kfi_no_bind,
	.control = kfi_no_control,
	.ops_open = kcxi_fabric_ops_open
};


/**
 * kcxi_fabric() - Get a fabric object
 * @attr: The attributes
 * @fabric: Fabric to be initialized
 * @context: User context
 *
 * This function needs to be registered with the OFI framework. This function
 * translates to kfi_fabric().
 *
 * Return: 0 for success. Else, errno. Upon success, the fabric double
 * de-reference will point to a single, valid struct kfid_fabric.
 */
int kcxi_fabric(struct kfi_fabric_attr *attr, struct kfid_fabric **fabric,
		void *context)
{
	int rc;
	uint32_t fabric_id;
	struct kcxi_fabric *kcxi_fab;

	if (!attr) {
		rc = -EINVAL;
		goto err;
	}

	rc = kcxi_verify_fabric_attr(attr);
	if (rc)
		goto err;

	rc = sscanf(attr->name, kcxi_fabric_fmt, &fabric_id);
	if (rc != 1) {
		LOG_ERR("%s: bad fabric name attribute: name=%s", __func__,
			attr->name);
		rc = -EINVAL;
		goto err;
	}

	if (!kcxi_dev_fabric_exists(fabric_id)) {
		LOG_ERR("%s: fabric does not exist: fabric_id=%u", __func__,
			fabric_id);
		rc = -ENODEV;
		goto err;
	}

	kcxi_fab = kzalloc(sizeof(*kcxi_fab), GFP_KERNEL);
	if (!kcxi_fab) {
		rc = -ENOMEM;
		goto err;
	}

	INIT_LIST_HEAD(&kcxi_fab->domain_list);
	mutex_init(&kcxi_fab->domain_lock);
	atomic_set(&kcxi_fab->ref_cnt, 0);

	kcxi_fab->fab_fid.fid.fclass = KFI_CLASS_FABRIC;
	kcxi_fab->fab_fid.fid.context = context;
	kcxi_fab->fab_fid.fid.ops = &cxi_fabric_fid_ops;
	kcxi_fab->fab_fid.ops = &cxi_fabric_ops;
	kcxi_fab->fab_fid.api_version = attr->api_version;

	/*
	 * Take a reference against the current module to prevent it from being
	 * pulled out from under us.
	 */
	if (!try_module_get(THIS_MODULE)) {
		LOG_ERR("%s: failed to get reference against kfi_cxi",
			__func__);
		rc = -ENODEV;
		goto err_free_fab;
	}

	mutex_lock(&kcxi_fab_list_lock);
	list_add_tail(&kcxi_fab->entry, &kcxi_fab_list);
	mutex_unlock(&kcxi_fab_list_lock);

	*fabric = &kcxi_fab->fab_fid;
	return 0;

err_free_fab:
	kfree(kcxi_fab);
err:
	*fabric = NULL;
	return rc;
}
