//SPDX-License-Identifier: GPL-2.0
/*
 * Cray kfabric CXI provider endpoints.
 * Copyright 2019-2025 Hewlett Packard Enterprise Development LP
 */
#include <linux/slab.h>

#include "kcxi_prov.h"

static int kcxi_ep_close(struct kfid *fid)
{
	/* Fid has already been dereference by kfabric. */
	int rc;
	struct kcxi_ep *kcxi_ep;

	if (fid->fclass != KFI_CLASS_SEP)
		return -EINVAL;

	kcxi_ep = container_of(fid, struct kcxi_ep, ep.fid);

	if (atomic_read(&kcxi_ep->ep_attr.num_rx_ctx) ||
	    atomic_read(&kcxi_ep->ep_attr.num_tx_ctx))
		return -EBUSY;

	rc = kcxi_domain_if_free(kcxi_ep->ep_attr.dom_if);
	if (rc)
		return rc;

	if (kcxi_ep->ep_attr.av)
		atomic_dec(&kcxi_ep->ep_attr.av->ref_cnt);

	atomic_dec(&kcxi_ep->ep_attr.domain->ref_cnt);

	kfree(kcxi_ep->ep_attr.tx_array);
	kfree(kcxi_ep->ep_attr.rx_array);
	kfree(kcxi_ep);

	return 0;
}

static int kcxi_ep_enable(struct kcxi_ep *kcxi_ep)
{

	if (kcxi_ep->ep.fid.fclass != KFI_CLASS_SEP)
		return -EINVAL;

	if (!kcxi_ep->ep_attr.av)
		return -KFI_ENOAV;

	mutex_lock(&kcxi_ep->ep_attr.lock);
	kcxi_ep->ep_attr.is_enabled = true;
	mutex_unlock(&kcxi_ep->ep_attr.lock);

	return 0;
}

static int kcxi_ep_bind(struct kfid *fid, struct kfid *bfid, uint64_t flags)
{
	struct kcxi_ep *ep;
	struct kcxi_av *av;

	/* Fid has already been dereferenced by kfabric. */
	if (!bfid)
		return -EINVAL;

	if (fid->fclass != KFI_CLASS_SEP)
		return -EINVAL;

	if (bfid->fclass != KFI_CLASS_AV)
		return -ENOSYS;

	ep = container_of(fid, struct kcxi_ep, ep.fid);

	mutex_lock(&ep->ep_attr.lock);

	av = container_of(bfid, struct kcxi_av, av_fid.fid);
	if (ep->ep_attr.domain != av->domain) {
		mutex_unlock(&ep->ep_attr.lock);
		return -EINVAL;
	}

	if (ep->ep_attr.av) {
		mutex_unlock(&ep->ep_attr.lock);
		return -EINVAL;
	}

	ep->ep_attr.av = av;

	mutex_unlock(&ep->ep_attr.lock);

	atomic_inc(&av->ref_cnt);

	return 0;
}

static int kcxi_ep_control(struct kfid *fid, int command, void *arg)
{
	/* Fid has already been dereferenced by kfabric. */
	struct kcxi_ep *kcxi_ep;

	if (fid->fclass != KFI_CLASS_SEP)
		return -EINVAL;

	kcxi_ep = container_of(fid, struct kcxi_ep, ep.fid);

	if (command == KFI_ENABLE)
		return kcxi_ep_enable(kcxi_ep);

	return -EINVAL;
}

static int kcxi_ep_tx_ctx(struct kfid_ep *sep, int index,
			  struct kfi_tx_attr *attr, struct kfid_ep **tx_ep,
			  void *context)
{
	struct kcxi_ep *kcxi_ep = container_of(sep, struct kcxi_ep, ep);
	struct kfi_tx_attr *tx_attr = &kcxi_ep->tx_attr;
	struct kcxi_tx_ctx *tx_ctx;
	int rc;

	/*
	 * SEP has already been dereferenced by kfabric. NULL attr is fine. NULL
	 * tx_ep is not fine. NULL context is fine.
	 */
	if (!tx_ep)
		return -EINVAL;

	if  (sep->fid.fclass != KFI_CLASS_SEP)
		return -ENOSYS;

	if (index >= kcxi_ep->ep_attr.attr.tx_ctx_cnt)
		return -EINVAL;

	if (attr) {
		/* Fill in any missing information in TX attributes. */
		kcxi_rdm_set_tx_attr(attr, kcxi_ep->ep_attr.caps);

		rc = kcxi_rdm_verify_tx_attr(attr, kcxi_ep->ep_attr.caps);
		if (rc)
			return rc;

		tx_attr = attr;
	}

	mutex_lock(&kcxi_ep->ep_attr.lock);

	if (kcxi_ep->ep_attr.tx_array[index]) {
		mutex_unlock(&kcxi_ep->ep_attr.lock);
		return -EADDRINUSE;
	}

	tx_ctx = kcxi_tx_ctx_alloc(tx_attr, index, &kcxi_ep->ep_attr, context);
	if (!tx_ctx) {
		mutex_unlock(&kcxi_ep->ep_attr.lock);
		return -ENOMEM;
	}

	kcxi_ep->ep_attr.tx_array[index] = tx_ctx;

	atomic_inc(&kcxi_ep->ep_attr.num_tx_ctx);

	mutex_unlock(&kcxi_ep->ep_attr.lock);

	*tx_ep = &tx_ctx->ctx;

	return 0;
}

static int kcxi_ep_rx_ctx(struct kfid_ep *sep, int index,
			  struct kfi_rx_attr *attr, struct kfid_ep **rx_ep,
			  void *context)
{
	struct kcxi_ep *kcxi_ep = container_of(sep, struct kcxi_ep, ep);
	struct kfi_rx_attr *rx_attr = &kcxi_ep->rx_attr;
	struct kcxi_rx_ctx *rx_ctx;
	int rc;

	/*
	 * SEP has already been dereferenced by kfabric. NULL attr is fine. NULL
	 * rx_ep is not fine. NULL context is fine.
	 */
	if (!rx_ep)
		return -EINVAL;

	if (sep->fid.fclass != KFI_CLASS_SEP)
		return -ENOSYS;

	if (index >= kcxi_ep->ep_attr.attr.rx_ctx_cnt)
		return -EINVAL;

	if (attr) {
		/* Fill in any missing information in the RX attributes. */
		kcxi_rdm_set_rx_attr(attr, kcxi_ep->ep_attr.caps);

		rc = kcxi_rdm_verify_rx_attr(attr, kcxi_ep->ep_attr.caps);
		if (rc)
			return rc;

		rx_attr = attr;
	}

	mutex_lock(&kcxi_ep->ep_attr.lock);

	if (kcxi_ep->ep_attr.rx_array[index]) {
		mutex_unlock(&kcxi_ep->ep_attr.lock);
		return -EADDRINUSE;
	}

	rx_ctx = kcxi_rx_ctx_alloc(rx_attr, index, &kcxi_ep->ep_attr, context);
	if (!rx_ctx) {
		mutex_unlock(&kcxi_ep->ep_attr.lock);
		return -ENOMEM;
	}

	kcxi_ep->ep_attr.rx_array[index] = rx_ctx;

	atomic_inc(&kcxi_ep->ep_attr.num_rx_ctx);

	mutex_unlock(&kcxi_ep->ep_attr.lock);

	*rx_ep = &rx_ctx->ctx;

	return 0;
}

static int kcxi_ep_cm_getname(struct kfid *fid, void *addr, size_t *addrlen)
{
	struct kcxi_ep *kcxi_ep = container_of(fid, struct kcxi_ep, ep.fid);
	struct kcxi_addr *src_addr = (struct kcxi_addr *)addr;

	if (*addrlen < sizeof(struct kcxi_addr))
		return -KFI_ETOOSMALL;

	if (!kcxi_ep->ep_attr.dom_if->dom)
		return -KFI_EOPBADSTATE;

	*addrlen = sizeof(struct kcxi_addr);
	memset(addr, 0, *addrlen);
	src_addr->pid = kcxi_ep->ep_attr.dom_if->dom->pid;
	src_addr->nic = kcxi_ep->ep_attr.dom_if->kcxi_if->nic_addr;

	return KFI_SUCCESS;
}

static struct kfi_ops kcxi_ep_fid_ops = {
	.close = kcxi_ep_close,
	.bind = kcxi_ep_bind,
	.control = kcxi_ep_control,
	.ops_open = kfi_no_ops_open
};

static struct kfi_ops_ep kcxi_ep_ops = {
	.cancel = kfi_no_cancel,
	.getopt = kfi_no_getopt,
	.setopt = kfi_no_setopt,
	.tx_ctx = kcxi_ep_tx_ctx,
	.rx_ctx = kcxi_ep_rx_ctx
};

static struct kfi_ops_cm kcxi_ep_cm_ops = {
	.setname = kfi_no_setname,
	.getname = kcxi_ep_cm_getname,
	.getpeer = kfi_no_getpeer,
	.connect = kfi_no_connect,
	.listen = kfi_no_listen,
	.accept = kfi_no_accept,
	.reject = kfi_no_reject,
	.shutdown = kfi_no_shutdown,
	.join = kfi_no_join
};

static struct kfi_ops_msg kcxi_ep_msg_ops = {
	.recv = kfi_no_msg_recv,
	.recvv = kfi_no_msg_recvv,
	.recvbv = kfi_no_msg_recvbv,
	.recvsgl = kfi_no_msg_recvsgl,
	.recvmsg = kfi_no_msg_recvmsg,
	.send = kfi_no_msg_send,
	.sendv = kfi_no_msg_sendv,
	.sendbv = kfi_no_msg_sendbv,
	.sendsgl = kfi_no_msg_sendsgl,
	.sendmsg = kfi_no_msg_sendmsg,
	.inject = kfi_no_msg_inject,
	.senddata = kfi_no_msg_senddata,
	.injectdata = kfi_no_msg_injectdata
};

static struct kfi_ops_rma kcxi_ep_rma_ops = {
	.read = kfi_no_rma_read,
	.readv = kfi_no_rma_readv,
	.readbv = kfi_no_rma_readbv,
	.readsgl = kfi_no_rma_readsgl,
	.readmsg = kfi_no_rma_readmsg,
	.write = kfi_no_rma_write,
	.writev = kfi_no_rma_writev,
	.writebv = kfi_no_rma_writebv,
	.writesgl = kfi_no_rma_writesgl,
	.writemsg = kfi_no_rma_writemsg,
	.inject = kfi_no_rma_inject,
	.writedata = kfi_no_rma_writedata,
	.injectdata = kfi_no_rma_injectdata
};

static struct kfi_ops_tagged kcxi_ep_tagged_ops = {
	.recv = kfi_no_tagged_recv,
	.recvv = kfi_no_tagged_recvv,
	.recvbv = kfi_no_tagged_recvbv,
	.recvsgl = kfi_no_tagged_recvsgl,
	.recvmsg = kfi_no_tagged_recvmsg,
	.send = kfi_no_tagged_send,
	.sendv = kfi_no_tagged_sendv,
	.sendbv = kfi_no_tagged_sendbv,
	.sendsgl = kfi_no_tagged_sendsgl,
	.sendmsg = kfi_no_tagged_sendmsg,
	.inject = kfi_no_tagged_inject,
	.senddata = kfi_no_tagged_senddata,
	.injectdata = kfi_no_tagged_injectdata
};

static struct kfi_ops_atomic kcxi_ep_atomic_ops = {
	.write = kfi_no_atomic_write,
	.writev = kfi_no_atomic_writev,
	.writemsg = kfi_no_atomic_writemsg,
	.inject = kfi_no_atomic_inject,
	.readwrite = kfi_no_atomic_readwrite,
	.readwritev = kfi_no_atomic_readwritev,
	.readwritemsg = kfi_no_atomic_readwritemsg,
	.compwrite = kfi_no_atomic_compwrite,
	.compwritev = kfi_no_atomic_compwritev,
	.compwritemsg = kfi_no_atomic_compwritemsg,
	.writevalid = kfi_no_atomic_writevalid,
	.readwritevalid = kfi_no_atomic_readwritevalid,
	.compwritevalid = kfi_no_atomic_compwritevalid
};

/**
 * kcxi_ep_release_tx_index() - Release reserved space in the TX array
 * @ep_attr: The kCXI ep attributes
 * @index: Index into the TX array
 *
 * TX contexts are expected to call this function when they are being closed.
 */
void kcxi_ep_release_tx_index(struct kcxi_ep_attr *ep_attr, unsigned int index)
{
	mutex_lock(&ep_attr->lock);
	ep_attr->tx_array[index] = NULL;
	mutex_unlock(&ep_attr->lock);

	atomic_dec(&ep_attr->num_tx_ctx);
}

/**
 * kcxi_ep_release_rx_index() - Release reserved space in the RX array
 * @ep_attr: The kCXI ep attributes
 * @index: Index into the RX array
 *
 * RX contexts are expected to call this function when they are being closed.
 */
void kcxi_ep_release_rx_index(struct kcxi_ep_attr *ep_attr, unsigned int index)
{
	mutex_lock(&ep_attr->lock);
	ep_attr->rx_array[index] = NULL;
	mutex_unlock(&ep_attr->lock);

	atomic_dec(&ep_attr->num_rx_ctx);
}

/**
 * kcxi_ep_alloc() - Allocate an endpoint
 * @domain: Domain the EP should be allocated against
 * @info: Info used for the EP
 * @ep_attr: EP attributes used for the EP
 * @tx_attr: TX attributes used for the EP
 * @rx_attr: RX attributes used for the EP
 * @ep: User's point to be set on success
 * @context: User's context
 * @fclass: The class of EP
 *
 * Note: Currently, the EP only supported is OFI scalable EPs. In addition,
 * alias EPs cannot be used.
 */
int kcxi_ep_alloc(struct kfid_domain *domain, struct kfi_info *info,
		  struct kfi_ep_attr *ep_attr, struct kfi_tx_attr *tx_attr,
		  struct kfi_rx_attr *rx_attr, struct kcxi_ep **ep,
		  void *context, size_t fclass)
{
	int rc;
	struct kcxi_ep *kcxi_ep;
	struct kcxi_domain *kcxi_dom;
	uint32_t auth_key;
	struct kcxi_addr addr;

	if (!domain || !info || !ep_attr || !tx_attr || !rx_attr || !ep)
		return -EINVAL;

	if (fclass != KFI_CLASS_SEP)
		return -EINVAL;

	if (ep_attr->tx_ctx_cnt == KFI_SHARED_CONTEXT) {
		LOG_ERR("%s: Shared TX contexts invalid for SEP", __func__);
		return -EINVAL;
	}

	if (ep_attr->rx_ctx_cnt == KFI_SHARED_CONTEXT) {
		LOG_ERR("%s: Shared RX contexts invalid for SEP", __func__);
		return -EINVAL;
	}

	/* Quick verification of important info fields. */
	if (info->addr_format != KFI_ADDR_CXI)
		return -EINVAL;

	if (info->src_addr && info->src_addrlen != sizeof(addr))
		return -EINVAL;

	if (info->dest_addr && info->dest_addrlen != sizeof(addr))
		return -EINVAL;

	kcxi_dom = container_of(domain, struct kcxi_domain, dom_fid);

	kcxi_ep = kzalloc(sizeof(*kcxi_ep), GFP_KERNEL);
	if (!kcxi_ep)
		return -ENOMEM;

	kcxi_ep->ep.fid.fclass = fclass;
	kcxi_ep->ep.fid.context = context;
	kcxi_ep->ep.fid.ops = &kcxi_ep_fid_ops;
	kcxi_ep->ep.ops = &kcxi_ep_ops;
	kcxi_ep->ep.cm = &kcxi_ep_cm_ops;
	kcxi_ep->ep.msg = &kcxi_ep_msg_ops;
	kcxi_ep->ep.rma = &kcxi_ep_rma_ops;
	kcxi_ep->ep.tagged = &kcxi_ep_tagged_ops;
	kcxi_ep->ep.atomic = &kcxi_ep_atomic_ops;

	kcxi_ep->ep_attr.caps = info->caps;

	kcxi_ep->ep_attr.attr = *ep_attr;
	if (ep_attr->auth_key)
		auth_key = *(uint32_t *)ep_attr->auth_key;
	else
		auth_key = kcxi_dom->def_auth_key;
	kcxi_ep->ep_attr.auth_key = auth_key;

	kcxi_ep->tx_attr = *tx_attr;
	kcxi_ep->rx_attr = *rx_attr;

	if (info->src_addr) {
		addr = *(struct kcxi_addr *)info->src_addr;
	} else {
		rc = kcxi_get_src_addr(info->dest_addr, &addr);
		if (rc)
			goto err;
	}

	/* Verify that EP addressing belongs to domain. */
	if (!kcxi_valid_domain_src_addr(kcxi_dom, &addr)) {
		LOG_ERR("Source address does not belong to domain");
		rc = -EINVAL;
		goto err;
	}

	atomic_set(&kcxi_ep->ep_attr.num_tx_ctx, 0);
	atomic_set(&kcxi_ep->ep_attr.num_rx_ctx, 0);
	mutex_init(&kcxi_ep->ep_attr.lock);

	kcxi_ep->ep_attr.tx_array = kcalloc(kcxi_ep->ep_attr.attr.tx_ctx_cnt,
					    sizeof(struct kcxi_tx_ctx *),
					    GFP_KERNEL);
	if (!kcxi_ep->ep_attr.tx_array) {
		rc = -ENOMEM;
		goto err;
	}

	kcxi_ep->ep_attr.rx_array = kcalloc(kcxi_ep->ep_attr.attr.rx_ctx_cnt,
					    sizeof(struct kcxi_rx_ctx *),
					    GFP_KERNEL);
	if (!kcxi_ep->ep_attr.rx_array) {
		rc = -ENOMEM;
		goto err;
	}

	/* Allocate a domain interface specific to this EP. */
	kcxi_ep->ep_attr.dom_if = kcxi_domain_if_alloc(kcxi_dom->kcxi_if,
						       auth_key, addr.pid);
	if (IS_ERR(kcxi_ep->ep_attr.dom_if)) {
		rc = PTR_ERR(kcxi_ep->ep_attr.dom_if);
		if (rc == -EEXIST)
			rc = -EADDRINUSE;

		goto err;
	}

	kcxi_ep->ep_attr.domain = kcxi_dom;
	atomic_inc(&kcxi_dom->ref_cnt);

	*ep = kcxi_ep;
	return 0;

err:
	kfree(kcxi_ep->ep_attr.rx_array);
	kfree(kcxi_ep->ep_attr.tx_array);
	kfree(kcxi_ep);
	return rc;
}
