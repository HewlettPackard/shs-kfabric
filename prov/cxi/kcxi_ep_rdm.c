//SPDX-License-Identifier: GPL-2.0
/*
 * Cray kfabric CXI provider RDM implementation.
 * Copyright 2019,2021-2022 Hewlett Packard Enterprise Development LP. All rights reserved.
 */
#include <linux/slab.h>

#include "kcxi_prov.h"

static const struct kfi_ep_attr kcxi_rdm_ep_attr = {
	.type = KCXI_EP_TYPE,
	.protocol = KCXI_EP_PROTOCOL,
	.protocol_version = KCXI_EP_PROTOCOL_VERSION,
	.max_msg_size = KCXI_EP_MAX_MSG_SIZE,
	.msg_prefix_size = KCXI_EP_MSG_PREFIX_SIZE,
	.max_order_raw_size = KCXI_EP_MAX_ORDER_RAW_SIZE,
	.max_order_war_size = KCXI_EP_MAX_ORDER_WAR_SIZE,
	.max_order_waw_size = KCXI_EP_MAX_ORDER_WAW_SIZE,
	.mem_tag_format = KCXI_EP_MAX_ORDER_WAW_SIZE,
	.tx_ctx_cnt = KCXI_EP_TX_CTX_CNT,
	.rx_ctx_cnt = KCXI_EP_RX_CTX_CNT,
};

static const struct kfi_tx_attr kcxi_rdm_tx_attr = {
	.caps = KCXI_TX_CAPS,
	.mode = KCXI_TX_MODE,
	.op_flags = KCXI_TX_OP_FLAGS,
	.msg_order = KCXI_TX_MSG_ORDER,
	.comp_order = KCXI_TX_COMP_ORDER,
	.inject_size = KCXI_TX_INJECT_SIZE,
	.size = KCXI_TX_SIZE,
	.iov_limit = KCXI_TX_IOV_LIMIT,
	.rma_iov_limit = KCXI_TX_RMA_IOV_LIMIT,
};

static const struct kfi_rx_attr kcxi_rdm_rx_attr = {
	.caps = KCXI_RX_CAPS,
	.mode = KCXI_RX_MODE,
	.op_flags = KCXI_RX_OP_FLAGS,
	.msg_order = KCXI_RX_MSG_ORDER,
	.comp_order = KCXI_RX_COMP_ORDER,
	.total_buffered_recv = KCXI_RX_TOTAL_BUFFERED_RECV,
	.size = KCXI_RX_SIZE,
	.iov_limit = KCXI_RX_IOV_LIMIT,
};

static void kcxi_rdm_set_ep_attr(struct kfi_ep_attr *attr)
{
	if (attr->type == KFI_EP_UNSPEC)
		attr->type = kcxi_rdm_ep_attr.type;
	if (attr->protocol == KFI_PROTO_UNSPEC)
		attr->protocol = kcxi_rdm_ep_attr.protocol;
	if (attr->protocol_version == 0)
		attr->protocol_version = kcxi_rdm_ep_attr.protocol_version;
	if (attr->max_msg_size == 0)
		attr->max_msg_size = kcxi_rdm_ep_attr.max_msg_size;
	if (attr->msg_prefix_size == 0)
		attr->msg_prefix_size = kcxi_rdm_ep_attr.msg_prefix_size;
	if (attr->max_order_raw_size == 0)
		attr->max_order_raw_size = kcxi_rdm_ep_attr.max_order_raw_size;
	if (attr->max_order_war_size == 0)
		attr->max_order_war_size = kcxi_rdm_ep_attr.max_order_war_size;
	if (attr->max_order_waw_size == 0)
		attr->max_order_waw_size = kcxi_rdm_ep_attr.max_order_waw_size;
	if (attr->mem_tag_format == 0)
		attr->mem_tag_format = kcxi_rdm_ep_attr.mem_tag_format;
	if (attr->tx_ctx_cnt == 0)
		attr->tx_ctx_cnt = kcxi_rdm_ep_attr.tx_ctx_cnt;
	if (attr->rx_ctx_cnt == 0)
		attr->rx_ctx_cnt = kcxi_rdm_ep_attr.rx_ctx_cnt;
}

void kcxi_rdm_set_tx_attr(struct kfi_tx_attr *attr, uint64_t caps)
{
	if (attr->caps == 0)
		attr->caps = (kcxi_rdm_tx_attr.caps & caps);
	if (attr->mode == 0)
		attr->mode = kcxi_rdm_tx_attr.mode;
	if (attr->op_flags == 0)
		attr->op_flags = kcxi_rdm_tx_attr.op_flags & ~KFI_MORE;
	if (attr->msg_order == KFI_ORDER_NONE)
		attr->msg_order = kcxi_rdm_tx_attr.msg_order;
	if (attr->comp_order == KFI_ORDER_NONE)
		attr->comp_order = kcxi_rdm_tx_attr.comp_order;
	if (attr->inject_size == 0)
		attr->inject_size = kcxi_rdm_tx_attr.inject_size;
	if (attr->size == 0)
		attr->size = kcxi_rdm_tx_attr.size;
	if (attr->iov_limit == 0)
		attr->iov_limit = kcxi_rdm_tx_attr.iov_limit;
	if (attr->rma_iov_limit == 0)
		attr->rma_iov_limit = kcxi_rdm_tx_attr.rma_iov_limit;
}

int kcxi_rdm_verify_tx_attr(const struct kfi_tx_attr *attr, uint64_t caps)
{
	if (!attr) {
		LOG_ERR("Bad TX Attr: Cannot verify NULL attr");
		return -EINVAL;
	}

	if (caps && (attr->caps & ~caps)) {
		LOG_ERR("Bad TX Attr: Unsupported capabilities %llx",
			attr->caps);
		goto nomatch;
	}

	if (attr->caps & ~kcxi_rdm_tx_attr.caps) {
		LOG_ERR("Bad TX Attr: Unsupported capabilities %llx",
			attr->caps);
		goto nomatch;
	}

	if (attr->mode != kcxi_rdm_tx_attr.mode) {
		LOG_ERR("Bad TX Attr: Unsupported mode %llx", attr->mode);
		goto nomatch;
	}

	if (attr->op_flags & ~kcxi_rdm_tx_attr.op_flags) {
		LOG_ERR("Bad TX Attr: Unsupported operation flags %llx",
			attr->op_flags);
		goto nomatch;
	}

	if (attr->msg_order & ~kcxi_rdm_tx_attr.msg_order) {
		LOG_ERR("Bad TX Attr: Unsupported msg order %llx",
			attr->msg_order);
		goto nomatch;
	}

	if (attr->comp_order & ~kcxi_rdm_tx_attr.comp_order) {
		LOG_ERR("Bad TX Attr: Unsupported comp order %llx",
			attr->comp_order);
		goto nomatch;
	}

	if (attr->inject_size > kcxi_rdm_tx_attr.inject_size) {
		LOG_ERR("Bad TX Attr: Unsupported inject size %lu",
			attr->inject_size);
		goto nomatch;
	}

	if (attr->size > kcxi_rdm_tx_attr.size) {
		LOG_ERR("Bad TX Attr: Unsupported tx size %lu", attr->size);
		goto nomatch;
	}

	if (attr->iov_limit > kcxi_rdm_tx_attr.iov_limit) {
		LOG_ERR("Bad TX Attr: Unsupported number of IOVs %lu",
			attr->iov_limit);
		goto nomatch;
	}

	if (attr->rma_iov_limit > kcxi_rdm_tx_attr.rma_iov_limit) {
		LOG_ERR("Bad TX Attr: Unsupported number of RMA IOVs %lu",
			attr->rma_iov_limit);
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

void kcxi_rdm_set_rx_attr(struct kfi_rx_attr *attr, uint64_t caps)
{
	if (attr->caps == 0)
		attr->caps = (kcxi_rdm_rx_attr.caps & caps);
	if (attr->mode == 0)
		attr->mode = kcxi_rdm_rx_attr.mode;
	if (attr->op_flags == 0)
		attr->op_flags = kcxi_rdm_rx_attr.op_flags &
			~(KFI_MORE | KFI_MULTI_RECV);
	if (attr->msg_order == KFI_ORDER_NONE)
		attr->msg_order = kcxi_rdm_rx_attr.msg_order;
	if (attr->comp_order == KFI_ORDER_NONE)
		attr->comp_order = kcxi_rdm_rx_attr.comp_order;
	if (attr->total_buffered_recv == 0)
		attr->total_buffered_recv =
			kcxi_rdm_rx_attr.total_buffered_recv;
	if (attr->size == 0)
		attr->size = kcxi_rdm_rx_attr.size;
	if (attr->iov_limit == 0)
		attr->iov_limit = kcxi_rdm_rx_attr.iov_limit;
}

int kcxi_rdm_verify_rx_attr(const struct kfi_rx_attr *attr, uint64_t caps)
{
	if (!attr) {
		LOG_ERR("Bad RX Attr: Cannot verify NULL attr");
		return -EINVAL;
	}

	if (caps && (attr->caps & ~caps)) {
		LOG_ERR("Bad RX Attr: Unsupported capabilities %llx",
			attr->caps);
		goto nomatch;
	}

	if (attr->caps & ~kcxi_rdm_rx_attr.caps) {
		LOG_ERR("Bad RX Attr: Unsupported capabilities %llx",
			attr->caps);
		goto nomatch;
	}

	if (attr->mode != kcxi_rdm_rx_attr.mode) {
		LOG_ERR("Bad RX Attr: Unsupported mode %llx", attr->mode);
		goto nomatch;
	}

	if (attr->op_flags & ~kcxi_rdm_rx_attr.op_flags) {
		LOG_ERR("Bad RX Attr: Unsupported operation flags %llx",
			attr->op_flags);
		goto nomatch;
	}

	if (attr->msg_order & ~kcxi_rdm_rx_attr.msg_order) {
		LOG_ERR("Bad RX Attr: Unsupported msg order %llx",
			attr->msg_order);
		goto nomatch;
	}

	if (attr->comp_order & ~kcxi_rdm_rx_attr.comp_order) {
		LOG_ERR("Bad RX Attr: Unsupported comp order %llx",
			attr->comp_order);
		goto nomatch;
	}

	if (attr->total_buffered_recv > kcxi_rdm_rx_attr.total_buffered_recv) {
		LOG_ERR("Bad RX Attr: Unsupported total buffered recv %lu",
			attr->total_buffered_recv);
		goto nomatch;
	}

	if (attr->size > kcxi_rdm_rx_attr.size) {
		LOG_ERR("Bad RX Attr: Unsupported rx size %lu", attr->size);
		goto nomatch;
	}

	if (attr->iov_limit > kcxi_rdm_rx_attr.iov_limit) {
		LOG_ERR("Bad RX Attr: Unsupported number of IOVs %lu",
			attr->iov_limit);
		goto nomatch;
	}

	return 0;

nomatch:
	return -ENODATA;
}

/**
 * kcxi_rdm_verify_ep_attr() - Verify EP/TX/RX attributes
 * @ep_attr: EP attributes
 * @tx_attr: TX attributes
 * @rx_attr: RX attributes
 * @caps: Capabilities to be verified against
 *
 * This function will only verify non NULL attributes.
 *
 * Return: 0 on success. Errno on failure.
 */
int kcxi_rdm_verify_ep_attr(const struct kfi_ep_attr *ep_attr,
			    const struct kfi_tx_attr *tx_attr,
			    const struct kfi_rx_attr *rx_attr, uint64_t caps)
{
	int rc;

	if (ep_attr) {
		switch (ep_attr->type) {
		case KFI_EP_UNSPEC:
		case KFI_EP_RDM:
			break;
		default:
			LOG_ERR("Bad EP Attr: Unsupported EP type %d",
				ep_attr->type);
			goto nomatch;
		}

		switch (ep_attr->protocol) {
		case KFI_PROTO_UNSPEC:
		case KFI_PROTO_CXI:
			break;
		default:
			LOG_ERR("Bad EP Attr: Unsupported protocol %d",
				ep_attr->protocol);
			goto nomatch;
		}

		if (ep_attr->protocol_version >
		    kcxi_rdm_ep_attr.protocol_version) {
			LOG_ERR("Bad EP Attr: Unsupported protocol ver %d",
				ep_attr->protocol_version);
			goto nomatch;
		}

		if (ep_attr->max_msg_size > kcxi_rdm_ep_attr.max_msg_size) {
			LOG_ERR("Bad EP Attr: Unsupported max msg size %lu",
				ep_attr->max_msg_size);
			goto nomatch;
		}

		if (ep_attr->msg_prefix_size >
		    kcxi_rdm_ep_attr.msg_prefix_size) {
			LOG_ERR("Bad EP Attr: Unsupported msg prefix size %lu",
				ep_attr->msg_prefix_size);
			goto nomatch;
		}

		if (ep_attr->max_order_raw_size >
		    kcxi_rdm_ep_attr.max_order_raw_size) {
			LOG_ERR("Bad EP Attr: Unsupported max RAW size %lu",
				ep_attr->max_order_raw_size);
			goto nomatch;
		}

		if (ep_attr->max_order_war_size >
		    kcxi_rdm_ep_attr.max_order_war_size) {
			LOG_ERR("Bad EP Attr: Unsupported max WAR size %lu",
				ep_attr->max_order_war_size);
			goto nomatch;
		}

		if (ep_attr->max_order_waw_size >
		    kcxi_rdm_ep_attr.max_order_waw_size) {
			LOG_ERR("Bad EP Attr: Unsupported max WAW size %lu",
				ep_attr->max_order_waw_size);
			goto nomatch;
		}

		if (ep_attr->mem_tag_format !=
		    kcxi_rdm_ep_attr.mem_tag_format) {
			LOG_ERR("Bad EP Attr: Unsupported mem tag format %llx",
				ep_attr->mem_tag_format);
			goto nomatch;
		}

		if (ep_attr->tx_ctx_cnt > kcxi_rdm_ep_attr.tx_ctx_cnt &&
		    ep_attr->tx_ctx_cnt != KFI_SHARED_CONTEXT) {
			LOG_ERR("Bad EP Attr: Unsupported tx count %lu",
				ep_attr->tx_ctx_cnt);
			goto nomatch;
		}

		if (ep_attr->rx_ctx_cnt > kcxi_rdm_ep_attr.rx_ctx_cnt &&
		    ep_attr->rx_ctx_cnt != KFI_SHARED_CONTEXT){
			LOG_ERR("Bad EP Attr: Unsupported rx count %lu",
				ep_attr->rx_ctx_cnt);
			goto nomatch;
		}

		if (ep_attr->auth_key_size &&
		    (ep_attr->auth_key_size != KCXI_DOM_AUTH_KEY_SIZE)) {
			LOG_ERR("Bad EP Attr: Unsupported auth key size %lu",
				ep_attr->auth_key_size);
			goto nomatch;
		}

		if (ep_attr->auth_key && !ep_attr->auth_key_size) {
			LOG_ERR("Bad EP Attr: Size not specified for auth key");
			goto nomatch;
		}
	}

	if (tx_attr) {
		rc = kcxi_rdm_verify_tx_attr(tx_attr, caps);
		if (rc)
			goto nomatch;
	}

	if (rx_attr) {
		rc = kcxi_rdm_verify_rx_attr(rx_attr, caps);
		if (rc)
			goto nomatch;
	}

	return 0;

nomatch:
	return -ENODATA;
}

/**
 * kcxi_rdm_kfi_info() - Allocate a kfi_info structure for RDM EP type
 * @src_addr: Source address
 * @dest_addr: Destination address
 * @hints: User provided hints
 * @info: Pointer to be allocated upon success
 *
 * Return: 0 on success. -ENODATA on error/no match.
 */
int kcxi_rdm_kfi_info(const struct kcxi_addr *src_addr,
		      const struct kcxi_addr *dest_addr,
		      const struct kfi_info *hints, struct kfi_info **info)
{
	int rc;
	struct kfi_info *rdm_info;

	rdm_info = kcxi_kfi_info(hints, src_addr, dest_addr);
	if (!rdm_info) {
		rc = -ENOMEM;
		goto err;
	}

	/*
	 * kcxi_kfi_info may not initialize ep/tx/rx/domain attr. If it did, any
	 * defined ep/tx/rx attr in the hints are carried over to the
	 * dup version. So, just fill in the gaps with the set functions.
	 */

	if (rdm_info->ep_attr)
		kcxi_rdm_set_ep_attr(rdm_info->ep_attr);
	if (rdm_info->tx_attr)
		kcxi_rdm_set_tx_attr(rdm_info->tx_attr, rdm_info->caps);
	if (rdm_info->rx_attr)
		kcxi_rdm_set_rx_attr(rdm_info->rx_attr, rdm_info->caps);

	/*
	 * This check may not be needed but does ensure consistency
	 * between the set and verify functions.
	 */
	rc = kcxi_rdm_verify_ep_attr(rdm_info->ep_attr, rdm_info->tx_attr,
				     rdm_info->rx_attr, rdm_info->caps);
	if (rc)
		goto err;

	*info = rdm_info;
	return 0;

err:
	if (rdm_info)
		kfi_freeinfo(rdm_info);
	*info = NULL;
	return rc;
}

static int kcxi_rdm_endpoint(struct kfid_domain *domain, struct kfi_info *info,
			     struct kcxi_ep **ep, void *context, size_t fclass)
{
	int rc;
	struct kcxi_addr def_addr = {};
	struct kfi_info ep_info = {};
	struct kfi_ep_attr ep_attr = kcxi_rdm_ep_attr;
	struct kfi_tx_attr tx_attr = kcxi_rdm_tx_attr;
	struct kfi_rx_attr rx_attr = kcxi_rdm_rx_attr;
	struct kcxi_domain *kcxi_dom =
		container_of(domain, struct kcxi_domain, dom_fid);

	/*
	 * Domain has already been dereferenced by kfabric. NULL info is fine.
	 * EP cannot be NULL. NULL context is fine.
	 */
	if (!ep)
		return -EINVAL;

	/*
	 * Set the caps to zero. The actual value will get set one of two ways:
	 * 1. If caps are defined in TX/RX attributes (ie. caps values are
	 * greater than zero)
	 * 2. kcxi_rdm_set_tx_attr() and kcxi_rdm_set_rx_attr() will set the
	 * values if they are still zero
	 */
	tx_attr.caps = 0;
	rx_attr.caps = 0;

	/* Do not set KFI_MORE by default. This can just lead to problems. */
	tx_attr.op_flags &= ~KFI_MORE;
	rx_attr.op_flags &= ~(KFI_MORE | KFI_MULTI_RECV);

	if (info) {
		ep_info = *info;

		if (info->ep_attr)
			ep_attr = *info->ep_attr;

		if (info->tx_attr)
			tx_attr = *info->tx_attr;

		if (info->rx_attr)
			rx_attr = *info->rx_attr;
	} else {
		def_addr.nic = kcxi_dom->kcxi_if->nic_addr;
		def_addr.pid = 0;
		ep_info.caps = KCXI_EP_RDM_CAP;
		ep_info.addr_format = KFI_ADDR_CXI;
		ep_info.src_addr = &def_addr;
		ep_info.src_addrlen = sizeof(def_addr);
	}

	/* Fill in any missing attribute information. */
	kcxi_rdm_set_ep_attr(&ep_attr);
	kcxi_rdm_set_tx_attr(&tx_attr, ep_info.caps);
	kcxi_rdm_set_rx_attr(&rx_attr, ep_info.caps);

	rc = kcxi_rdm_verify_ep_attr(&ep_attr, &tx_attr, &rx_attr,
				     ep_info.caps);
	if (rc)
		return rc;

	rc = kcxi_ep_alloc(domain, &ep_info, &ep_attr, &tx_attr, &rx_attr, ep,
			  context, fclass);

	return rc;
}

int kcxi_rdm_sep(struct kfid_domain *domain, struct kfi_info *info,
		 struct kfid_ep **sep, void *context)
{
	int rc;
	struct kcxi_ep *endpoint;

	/*
	 * Domain is dereferenced in kfabric. Info and context can be NULL. SEP
	 * cannot be NULL.
	 */
	if (!sep)
		return -EINVAL;

	rc = kcxi_rdm_endpoint(domain, info, &endpoint, context, KFI_CLASS_SEP);
	if (rc)
		return rc;

	*sep = &endpoint->ep;
	return 0;
}
