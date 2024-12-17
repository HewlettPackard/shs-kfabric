// SPDX-License-Identifier: GPL-2.0
/*
 * Cray kfabric CXI provider domain.
 * Copyright 2018-2024 Hewlett Packard Enterprise Development LP
 */
#include <linux/slab.h>
#include <linux/module.h>

#include "kcxi_prov.h"

/* Define a default auth key */
unsigned int default_auth_key = 255;
module_param(default_auth_key, uint, 0444);
MODULE_PARM_DESC(default_auth_key,
		 "Default authorization key (VNI) for the domain and endpoint");

static LIST_HEAD(domain_id_list);
static DEFINE_MUTEX(domain_id_lock);

static const struct kfi_domain_attr kcxi_domain_attr = {
	.threading = KCXI_DOM_THREADING,
	.control_progress = KCXI_DOM_CONTROL_PROGRESS,
	.data_progress = KCXI_DOM_DATA_PROGRESS,
	.resource_mgmt = KCXI_DOM_RESOURCE_MGMT,
	.av_type = KCXI_DOM_AV_TYPE,
	.mr_mode = KCXI_DOM_MR_MODE,
	.mr_key_size = KCXI_DOM_MR_KEY_SIZE,
	.cq_data_size = KCXI_DOM_CQ_DATA_SIZE,
	.cq_cnt = KCXI_DOM_CQ_CNT,
	.ep_cnt = KCXI_DOM_EP_CNT,
	.tx_ctx_cnt = KCXI_DOM_TX_CTX_CNT,
	.rx_ctx_cnt = KCXI_DOM_RX_CTX_CNT,
	.max_ep_tx_ctx = KCXI_DOM_MAX_EP_TX_CTX,
	.max_ep_rx_ctx = KCXI_DOM_MAX_EP_RX_CTX,
	.max_ep_stx_ctx = KCXI_DOM_MAX_EP_STX_CTX,
	.max_ep_srx_ctx = KCXI_DOM_MAX_EP_SRX_CTX,
	.cntr_cnt = KCXI_DOM_CNTR_CNT,
	.mr_iov_limit = KCXI_DOM_MR_IOV_LIMIT,
	.caps = KCXI_DOM_CAPS,
	.mode = KCXI_DOM_MODE,
	.auth_key = (void *)&default_auth_key,
	.auth_key_size = KCXI_DOM_AUTH_KEY_SIZE,
	.max_err_data = KCXI_DOM_MAX_ERR_DATA,
	.mr_cnt = KCXI_DOM_MR_CNT,
};

bool kcxi_valid_domain_src_addr(struct kcxi_domain *dom, struct kcxi_addr *addr)
{
	return (dom->kcxi_if->nic_addr == addr->nic);
}

static bool kcxi_matching_domain_attr(const struct kfi_domain_attr *a_attr,
				      const struct kfi_domain_attr *b_attr,
				      unsigned int a_nic, unsigned int b_nic)
{
	if (!a_attr || !b_attr)
		goto nomatch;

	if (a_attr->threading != b_attr->threading)
		goto nomatch;
	if (a_attr->control_progress != b_attr->control_progress)
		goto nomatch;
	if (a_attr->data_progress != b_attr->control_progress)
		goto nomatch;
	if (a_attr->resource_mgmt != b_attr->resource_mgmt)
		goto nomatch;
	if (a_attr->caps != b_attr->caps)
		goto nomatch;
	if (a_nic != b_nic)
		goto nomatch;

	return true;
nomatch:
	return false;
}

/**
 * kcxi_set_domain_attr() - Set the domain attributes,
 * @fabric: Fabric used to set domain fid attribute.
 * @src_addr: The source address to be associated with the domain.
 * @attr: The attributes to be updated.
 * @caps: The capabilities the domain should be restricted to.
 *
 * Return: 0 on success with updated attr. Else errno.
 */
int kcxi_set_domain_attr(const struct kfid_fabric *fabric,
			 const struct kcxi_addr *src_addr,
			 struct kfi_domain_attr *attr, uint64_t caps)
{
	struct kcxi_fabric *kcxi_fab;
	struct kcxi_domain *kcxi_dom;
	int rc;
	bool auth_key_allocated = false;

	if (!src_addr) {
		rc = -EINVAL;
		LOG_ERR("CXI source address must be defined");
		goto err;
	}

	if (!attr) {
		rc = -EINVAL;
		LOG_ERR("Domain attributes cannot be NULL");
		goto err;
	}

	if (attr->threading == KFI_THREAD_UNSPEC)
		attr->threading = kcxi_domain_attr.threading;
	if (attr->control_progress == KFI_PROGRESS_UNSPEC)
		attr->control_progress = kcxi_domain_attr.control_progress;
	if (attr->data_progress == KFI_PROGRESS_UNSPEC)
		attr->data_progress = kcxi_domain_attr.data_progress;
	if (attr->resource_mgmt == KFI_RM_UNSPEC)
		attr->resource_mgmt = kcxi_domain_attr.resource_mgmt;
	if (attr->mr_key_size == 0)
		attr->mr_key_size = kcxi_domain_attr.mr_key_size;
	if (attr->cq_data_size == 0)
		attr->cq_data_size = kcxi_domain_attr.cq_data_size;
	if (attr->cq_cnt == 0)
		attr->cq_cnt = kcxi_domain_attr.cq_cnt;
	if (attr->ep_cnt == 0)
		attr->ep_cnt = kcxi_domain_attr.ep_cnt;
	if (attr->tx_ctx_cnt == 0)
		attr->tx_ctx_cnt = kcxi_domain_attr.tx_ctx_cnt;
	if (attr->rx_ctx_cnt == 0)
		attr->rx_ctx_cnt = kcxi_domain_attr.rx_ctx_cnt;
	if (attr->max_ep_tx_ctx == 0)
		attr->max_ep_tx_ctx = kcxi_domain_attr.max_ep_tx_ctx;
	if (attr->max_ep_rx_ctx == 0)
		attr->max_ep_rx_ctx = kcxi_domain_attr.max_ep_rx_ctx;
	if (attr->max_ep_stx_ctx == 0)
		attr->max_ep_stx_ctx = kcxi_domain_attr.max_ep_stx_ctx;
	if (attr->max_ep_srx_ctx == 0)
		attr->max_ep_srx_ctx = kcxi_domain_attr.max_ep_srx_ctx;
	if (attr->cntr_cnt == 0)
		attr->cntr_cnt = kcxi_domain_attr.cntr_cnt;
	if (attr->mr_iov_limit == 0)
		attr->mr_iov_limit = kcxi_domain_attr.mr_iov_limit;
	if (attr->caps == 0)
		attr->caps = (kcxi_domain_attr.caps & caps);
	if (attr->auth_key_size == 0 && !attr->auth_key) {
		attr->auth_key = kmemdup(kcxi_domain_attr.auth_key,
					 kcxi_domain_attr.auth_key_size,
					 GFP_KERNEL);
		if (!attr->auth_key) {
			rc = -ENOMEM;
			LOG_ERR("Failed to allocated auth_key memory");
			goto err;
		}
		attr->auth_key_size = kcxi_domain_attr.auth_key_size;

		auth_key_allocated = true;
	} else if (attr->auth_key_size == 0) {
		rc = -EINVAL;
		LOG_ERR("Authorization key is zero bytes but pointer is set");
		goto err;
	}
	if (attr->max_err_data == 0)
		attr->max_err_data = kcxi_domain_attr.max_err_data;
	if (attr->mr_cnt == 0)
		attr->mr_cnt = kcxi_domain_attr.mr_cnt;
	if (attr->tclass == KFI_TC_UNSPEC)
		attr->tclass = KFI_TC_BEST_EFFORT;

	/* Reset the name field */
	if (attr->name)
		kfree(attr->name);

	attr->name = kcxi_get_domain_name(src_addr);
	if (!attr->name) {
		rc = -ENOMEM;
		LOG_ERR("Failed to allocate CXI domain name");
		goto err_free_auth_key;
	}

	/* Attempt to set the domain fid attribute. */
	if (fabric && src_addr && !attr->domain) {
		kcxi_fab = container_of(fabric, struct kcxi_fabric, fab_fid);

		mutex_lock(&kcxi_fab->domain_lock);
		list_for_each_entry(kcxi_dom, &kcxi_fab->domain_list, entry) {
			if (kcxi_matching_domain_attr(&kcxi_dom->attr, attr,
						      kcxi_dom->kcxi_if->nic_addr,
						      src_addr->nic)) {
				attr->domain = &kcxi_dom->dom_fid;
				break;
			}
		}
		mutex_unlock(&kcxi_fab->domain_lock);
	}

	return 0;

err_free_auth_key:
	if (auth_key_allocated) {
		kfree(attr->auth_key);
		attr->auth_key = NULL;
		attr->auth_key_size = 0;
	}
err:
	return rc;
}

/**
 * kcxi_verify_domain_attr() - Verify domain attributes
 * @fabric: Fabric used to verify domain fid attribute.
 * @src_addr: Source address associated with the domain attributes
 * @attr: The attributes to be verified
 * @caps: The capabilities the attributes should be limited too
 *
 * Return: 0 on success. Else errno.
 */
int kcxi_verify_domain_attr(const struct kfid_fabric *fabric,
			    const struct kcxi_addr *src_addr,
			    const struct kfi_domain_attr *attr, uint64_t caps)
{
	struct kcxi_fabric *kcxi_fab;
	struct kcxi_domain *kcxi_dom;
	bool found = false;

	if (!attr) {
		LOG_ERR("Bad Domain Attr: Cannot verify NULL attr");
		return -EINVAL;
	}

	if (!src_addr) {
		LOG_ERR("Bad Domain Attr: Cannot verify NULL source address");
		return -EINVAL;
	}

	if (fabric && attr->domain) {
		kcxi_fab = container_of(fabric, struct kcxi_fabric, fab_fid);

		mutex_lock(&kcxi_fab->domain_lock);
		list_for_each_entry(kcxi_dom, &kcxi_fab->domain_list, entry) {
			if (&kcxi_dom->dom_fid == attr->domain &&
			    src_addr->nic == kcxi_dom->kcxi_if->nic_addr) {
				found = true;
				break;
			}
		}
		mutex_unlock(&kcxi_fab->domain_lock);

		if (!found) {
			LOG_DEBUG("Bad Domain Attr: Invalid domain fid pointer");
			goto nomatch;
		}
	} else if (attr->domain) {
		LOG_ERR("Bad Domain Attr: Domain fid set but fabric fid NULL");
		goto nomatch;
	}

	if (attr->name) {
		if (kcxi_validate_domain_name(attr->name)) {
			LOG_ERR("Bad Domain Attr: Invalid domain name %s",
				attr->name);
			goto nomatch;
		}
	}

	switch (attr->threading) {
	case KFI_THREAD_UNSPEC:
	case KFI_THREAD_SAFE:
		break;
	default:
		LOG_ERR("Bad Domain Attr: Unsupported threading type %d",
			attr->threading);
		goto nomatch;
	}

	switch (attr->control_progress) {
	case KFI_PROGRESS_UNSPEC:
	case KFI_PROGRESS_AUTO:
		break;
	default:
		LOG_ERR("Bad Domain Attr: Unsupported control progress %d",
			attr->control_progress);
		goto nomatch;
	}

	switch (attr->data_progress) {
	case KFI_PROGRESS_UNSPEC:
	case KFI_PROGRESS_MANUAL:
	case KFI_PROGRESS_AUTO:
		break;
	default:
		LOG_ERR("Bad Domain Attr: Unsupported data progress %d",
			attr->data_progress);
		goto nomatch;
	}

	switch (attr->resource_mgmt) {
	case KFI_RM_UNSPEC:
	case KFI_RM_DISABLED:
		break;
	default:
		LOG_ERR("Bad Domain Attr: Unsupported resource management %d",
			attr->resource_mgmt);
		goto nomatch;
	}

	switch (attr->av_type) {
	case KFI_AV_UNSPEC:
	case KFI_AV_MAP:
		break;
	default:
		LOG_ERR("Bad Domain Attr: Unsupported address vector %d",
			attr->av_type);
		goto nomatch;
	}

	if (attr->mr_mode & ~kcxi_domain_attr.mr_mode) {
		LOG_ERR("Bad Domain Attr: Unsupported MR mode %d",
			attr->mr_mode);
		goto nomatch;
	}

	if (attr->mr_key_size &&
	    (attr->mr_key_size > kcxi_domain_attr.mr_key_size)) {
		LOG_ERR("Bad Domain Attr: Unsupported MR ker size %lu",
			attr->mr_key_size);
		goto nomatch;
	}

	if (attr->cq_data_size > kcxi_domain_attr.cq_data_size) {
		LOG_ERR("Bad Domain Attr: Unsupported CQ data size %lu",
			attr->cq_data_size);
		goto nomatch;
	}

	if (attr->cq_cnt > kcxi_domain_attr.cq_cnt) {
		LOG_ERR("Bad Domain Attr: Unsupported CQ count %lu",
			attr->cq_cnt);
		goto nomatch;
	}

	if (attr->ep_cnt > kcxi_domain_attr.ep_cnt) {
		LOG_ERR("Bad Domain Attr: Unsupported EP count %lu",
			attr->ep_cnt);
		goto nomatch;
	}

	if (attr->tx_ctx_cnt > KCXI_DOM_TX_CTX_MAX) {
		LOG_ERR("Bad Domain Attr: Unsupported tx count %lu",
			attr->tx_ctx_cnt);
		goto nomatch;
	}

	if (attr->rx_ctx_cnt > KCXI_DOM_RX_CTX_MAX) {
		LOG_ERR("Bad Domain Attr: Unsupported rx count %lu",
			attr->rx_ctx_cnt);
		goto nomatch;
	}

	if (attr->max_ep_tx_ctx > kcxi_domain_attr.max_ep_tx_ctx) {
		LOG_ERR("Bad Domain Attr: Unsupported tx context count %lu",
			attr->max_ep_tx_ctx);
		goto nomatch;
	}

	if (attr->max_ep_rx_ctx > kcxi_domain_attr.max_ep_rx_ctx) {
		LOG_ERR("Bad Domain Attr: Unsupported rx context count %lu",
			attr->max_ep_rx_ctx);
		goto nomatch;
	}

	if (attr->max_ep_stx_ctx > kcxi_domain_attr.max_ep_stx_ctx) {
		LOG_ERR("Bad Domain Attr: Unsupported stx context count %lu",
			attr->max_ep_stx_ctx);
		goto nomatch;
	}

	if (attr->max_ep_srx_ctx > kcxi_domain_attr.max_ep_srx_ctx) {
		LOG_ERR("Bad Domain Attr: Unsupported srx context count %lu",
			attr->max_ep_srx_ctx);
		goto nomatch;
	}

	if (attr->cntr_cnt > kcxi_domain_attr.cntr_cnt) {
		LOG_ERR("Bad Domain Attr: Unsupported counter count %lu",
			attr->cntr_cnt);
		goto nomatch;
	}

	if (attr->mr_iov_limit > kcxi_domain_attr.mr_iov_limit) {
		LOG_ERR("Bad Domain Attr: Unsupported number of MR IOVs %lu",
			attr->mr_iov_limit);
		goto nomatch;
	}

	if (caps && (attr->caps & ~caps)) {
		LOG_ERR("Bad Domain Attr: Unsupported capabilities %llx",
			attr->caps);
		goto nomatch;
	}

	if (attr->caps & ~kcxi_domain_attr.caps) {
		LOG_ERR("Bad Domain Attr: Unsupported capabilities %llx",
			attr->caps);
		goto nomatch;
	}

	if (attr->mode & ~kcxi_domain_attr.mode) {
		LOG_ERR("Bad Domain Attr: Unsupported mode %llx", attr->mode);
		goto nomatch;
	}

	if (attr->auth_key_size &&
	    (attr->auth_key_size != kcxi_domain_attr.auth_key_size)) {
		LOG_ERR("Bad Domain Attr: Unsupported auth key size %lu",
			attr->auth_key_size);
		goto nomatch;
	}

	if (attr->auth_key && !attr->auth_key_size) {
		LOG_ERR("Bad Domain Attr: Size not specified for auth key");
		goto nomatch;
	}

	if (attr->max_err_data > kcxi_domain_attr.max_err_data) {
		LOG_ERR("Bad Domain Attr: Unsupported max error data %lu",
			attr->max_err_data);
		goto nomatch;
	}

	if (attr->mr_cnt > kcxi_domain_attr.mr_cnt) {
		LOG_ERR("Bad Domain Attr: Unsupported MR count %lu",
			attr->mr_cnt);
		goto nomatch;
	}

	switch (attr->tclass) {
		case KFI_TC_UNSPEC:
		case KFI_TC_BEST_EFFORT:
		case KFI_TC_LOW_LATENCY:
		case KFI_TC_DEDICATED_ACCESS:
		case KFI_TC_BULK_DATA:
			break;
		case KFI_TC_SCAVENGER:
		case KFI_TC_NETWORK_CTRL:
		default:
			LOG_ERR("Unsupported traffic class: %u", attr->tclass);
			goto nomatch;
	}

	return 0;

nomatch:
	return -ENODATA;
}

static int kcxi_domain_close(struct kfid *domain)
{
	struct kcxi_domain *kcxi_dom;
	int rc;

	kcxi_dom = container_of(domain, struct kcxi_domain, dom_fid.fid);
	if (atomic_read(&kcxi_dom->ref_cnt))
		return -EBUSY;

	rc = kcxi_if_free(kcxi_dom->kcxi_if);
	if (rc)
		return rc;

	/* If bound to EQ, drop the ref count */
	if (kcxi_dom->eq)
		atomic_dec(&kcxi_dom->eq->ref_cnt);

	/* Remove domain from fabric */
	mutex_lock(&kcxi_dom->fab->domain_lock);
	list_del(&kcxi_dom->entry);
	atomic_dec(&kcxi_dom->fab->ref_cnt);
	mutex_unlock(&kcxi_dom->fab->domain_lock);

	kfree(kcxi_dom);

	return 0;
}

static int kcxi_domain_bind(struct kfid *domain, struct kfid *bfid,
			    uint64_t flags)
{
	struct kcxi_domain *kcxi_dom;
	struct kcxi_eq *kcxi_eq;

	if (!bfid || bfid->fclass != KFI_CLASS_EQ)
		return -EINVAL;

	kcxi_dom = container_of(domain, struct kcxi_domain, dom_fid.fid);
	kcxi_eq = container_of(bfid, struct kcxi_eq, eq.fid);

	if (kcxi_dom->eq)
		return -EINVAL;

	kcxi_dom->eq = kcxi_eq;
	if (flags & KFI_REG_MR)
		kcxi_dom->mr_eq = kcxi_eq;

	atomic_inc(&kcxi_eq->ref_cnt);

	return 0;
}

static int kcxi_domain_get_device(struct kfid *domain, struct device **device)
{
	struct kcxi_domain *kcxi_dom;

	kcxi_dom = container_of(domain, struct kcxi_domain, dom_fid.fid);

	*device = kcxi_dom->kcxi_if->dev->device;

	return 0;
}

static struct kfi_cxi_domain_ops kcxi_domain_ops_ext = {
	.get_device = kcxi_domain_get_device
};

static int kcxi_domain_ops_open(struct kfid *fid, const char *name,
				uint64_t flags, void **ops, void *context)
{
	if (!strcmp(name, KFI_CXI_DOM_OPS_1)) {
		*ops = &kcxi_domain_ops_ext;
		return 0;
	}

	return -EINVAL;
}

static struct kfi_ops kcxi_domain_fid_ops = {
	.close = kcxi_domain_close,
	.bind = kcxi_domain_bind,
	.control = kfi_no_control,
	.ops_open = kcxi_domain_ops_open
};

static struct kfi_ops_mr kcxi_mr_ops = {
	.reg = kcxi_mr_reg,
	.regv = kcxi_mr_regv,
	.regbv = kcxi_mr_regbv,
	.regsgl = kcxi_mr_regsgl,
	.regattr = kfi_no_mr_regattr
};

static struct kfi_ops_domain kcxi_domain_ops = {
	.av_open = kcxi_av_open,
	.cq_open = kcxi_cq_open,
	.endpoint = kfi_no_endpoint,
	.scalable_ep = kcxi_rdm_sep,
	.cntr_open = kfi_no_cntr_open,
	.poll_open = kfi_no_poll_open,
	.stx_ctx = kfi_no_stx_ctx,
	.srx_ctx = kfi_no_srx_ctx,
	.query_atomic = kfi_no_query_atomic
};

int kcxi_domain(struct kfid_fabric *fabric, struct kfi_info *info,
		struct kfid_domain **dom, void *context)
{
	struct kcxi_domain *kcxi_dom;
	uint32_t nic;
	int rc;

	if (!fabric || !info || !dom) {
		rc = -EINVAL;
		goto err;
	}

	rc = kcxi_verify_info(info, info->src_addr);
	if (rc)
		goto err;

	nic = ((struct kcxi_addr *)info->src_addr)->nic;

	kcxi_dom = kzalloc(sizeof(*kcxi_dom), GFP_KERNEL);
	if (!kcxi_dom) {
		rc = -ENOMEM;
		goto err;
	}

	kcxi_dom->kcxi_if = kcxi_if_alloc(nic, fabric, info);
	if (IS_ERR(kcxi_dom->kcxi_if)) {
		rc = PTR_ERR(kcxi_dom->kcxi_if);
		LOG_ERR("Failed to allocate kCXI interface: rc=%d", rc);
		goto err_free_dom;
	}

	if (info->domain_attr) {
		kcxi_dom->attr = *info->domain_attr;
		if (info->domain_attr->auth_key)
			kcxi_dom->def_auth_key = *(uint32_t *)info->domain_attr->auth_key;
		else
			kcxi_dom->def_auth_key = default_auth_key;
	} else {
		kcxi_dom->attr = kcxi_domain_attr;
		kcxi_dom->def_auth_key = default_auth_key;
	}

	atomic_set(&kcxi_dom->ref_cnt, 0);
	kcxi_dom->dom_fid.fid.fclass = KFI_CLASS_DOMAIN;
	kcxi_dom->dom_fid.fid.context = context;
	kcxi_dom->dom_fid.fid.ops = &kcxi_domain_fid_ops;
	kcxi_dom->dom_fid.ops = &kcxi_domain_ops;
	kcxi_dom->dom_fid.mr = &kcxi_mr_ops;
	kcxi_dom->fab = container_of(fabric, struct kcxi_fabric, fab_fid);

	/* Add domain to fabric */
	mutex_lock(&kcxi_dom->fab->domain_lock);
	list_add_tail(&kcxi_dom->entry, &kcxi_dom->fab->domain_list);
	atomic_inc(&kcxi_dom->fab->ref_cnt);
	mutex_unlock(&kcxi_dom->fab->domain_lock);

	*dom = &kcxi_dom->dom_fid;
	return 0;

err_free_dom:
	kfree(kcxi_dom);
err:
	*dom = NULL;
	return rc;
}
