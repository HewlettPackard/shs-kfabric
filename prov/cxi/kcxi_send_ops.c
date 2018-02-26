//SPDX-License-Identifier: GPL-2.0
/*
 * Cray kfabric CXI provider send operations.
 * Copyright 2019-2024 Hewlett Packard Enterprise Development LP. All rights reserved.
 */
#include <linux/slab.h>
#include <linux/module.h>

#include "kcxi_prov.h"

unsigned long rnr_timeout = 500000;
module_param(rnr_timeout, ulong, 0444);
MODULE_PARM_DESC(rnr_timeout, "Messaging receiver not ready timeout in nsecs");

/**
 * kcxi_msg_tx_req_cb() - Transmit message operation callback
 * @req: kCXI request state for the RMA operation
 * @event: Hardware event
 *
 * Return: 0 for success and non-user event. 1 for success and user event. Else,
 * negative errno.
 */
static int kcxi_msg_tx_req_cb(struct kcxi_cq *cq, struct kcxi_req_state *req,
			      const union c_event *event)
{
	struct kcxi_tx_desc *tx_desc;
	struct kcxi_tx_ctx *tx_ctx;
	size_t event_olen;
	int rc;
	int error_rc;

	tx_desc = container_of(req, struct kcxi_tx_desc, req);
	tx_ctx = tx_desc->tx_ctx;

	if (event->hdr.event_size != C_EVENT_SIZE_16_BYTE) {
		TXC_ERR(tx_ctx, "Bad event size: expected=%u got=%u",
			C_EVENT_SIZE_16_BYTE, event->hdr.event_size);
		return -EINVAL;
	}

	if (event->hdr.event_type != C_EVENT_ACK) {
		TXC_ERR(tx_ctx, "Bad event: event_type=%d",
			event->hdr.event_type);
		return -EINVAL;
	}

	/* For messaging, treat C_RC_ENTRY_NOT_FOUND as receiver not ready. */
	if (tx_ctx->enabled &&
	    event->init_short.return_code == C_RC_ENTRY_NOT_FOUND) {
		if (tx_desc->timeout > ktime_get()) {
			queue_work(kcxi_wq, &tx_desc->retry);
			return 0;
		}

		TXC_ERR_RL(tx_ctx,
			   "Message timeout to RX context NIC (%#x) PID (%u) Index (%u); nsec=%llu rnr_retries=%llu posted_tx_count=%u",
			   tx_desc->peer.nic, tx_desc->peer.pid, tx_desc->offset,
			   ktime_sub(ktime_get(), tx_desc->timeout - rnr_timeout),
			   atomic64_read(&tx_desc->retries),
			   atomic_read(&tx_ctx->posted_tx_cnt));
	}

	/* Overflow length is a kCXI success, but kfabric CQ error. */
	event_olen = tx_desc->tx_len - event->init_short.mlength;

	TXC_DEBUG(tx_desc->tx_ctx,
		  "TX event: eqn=%u event_type=%u mlength=%u olen=%lu rc=%d",
		  cq->eq->eqn, event->hdr.event_type, event->init_short.mlength,
		  event_olen, event->init_short.return_code);

	if (event->init_short.return_code == C_RC_OK && event_olen == 0) {
		if (tx_desc->suppress_events) {
			rc = 0;
			goto out;
		}

		rc = cq->report_completion(cq, KFI_ADDR_NOTAVAIL, req);
		if (rc != 1)
			TXC_ERR(tx_desc->tx_ctx,
				"Failed to report CQ event: rc=%d", rc);
	} else {
		if (event_olen && event->init_short.return_code == C_RC_OK) {
			error_rc = EMSGSIZE;
		} else if (event->init_short.return_code == C_RC_UNDELIVERABLE) {
			/* C_RC_UNDELIVERABLE means retry handler was unsuccessful.
			 * Report target as unreachable
			 */
			error_rc = EHOSTUNREACH;
		} else if (event->init_short.return_code == C_RC_VNI_NOT_FOUND ) {
			/* C_RC_VNI_NOT_FOUND means no VNI match at target endpoint.
			 * Report target endpoint as unconnected.
			 */
			error_rc = ENOTCONN ;
		} else if (tx_ctx->enabled &&
			   event->init_short.return_code == C_RC_ENTRY_NOT_FOUND) {
			/* C_RC_ENTRY_NOT_FOUND means the message was delivered to
			 * the target endpoint but no resources were available for it.
			 * Report remote io error.
			 */
			error_rc = EREMOTEIO;
		} else {
			/* For all other errors report generic io error. */
			error_rc = EIO;
		}

		rc = cq->report_error(cq, req, 0, error_rc,
				      event->init_short.return_code);
		if (rc != 1)
			TXC_ERR(tx_desc->tx_ctx,
				"Failed to report CQ error: rc=%d", rc);
	}

out:
	kcxi_md_free(tx_desc->md);

	kcxi_tx_desc_free(tx_desc);

	TXC_DEBUG(tx_ctx,
		  "TX complete: posted_tx_count=%u",
		  atomic_read(&tx_ctx->posted_tx_cnt));

	return rc;
}

/**
 * kcxi_queue_msg() - Queue a message transmit descriptor to hardware.
 * @tx_desc: Message transmit descriptor.
 * @flags: Operational flags.
 *
 * Return: 0 on success. -EAGAIN if queueing failed.
 */
static int kcxi_queue_msg(struct kcxi_tx_desc *tx_desc, uint64_t flags)
{
	struct c_full_dma_cmd cmd = {};
	struct kcxi_md *md = tx_desc->md;
	struct kcxi_tx_ctx *tx_ctx = tx_desc->tx_ctx;
	struct kcxi_domain_if *dom_if = tx_ctx->ep_attr->dom_if;
	union c_fab_addr dfa;
	uint8_t index_ext;
	int rc;
	bool more = !!(flags & KFI_MORE);

	cxi_build_dfa(tx_desc->peer.nic, tx_desc->peer.pid,
		      dom_if->kcxi_if->dev->pid_bits, tx_desc->offset, &dfa,
		      &index_ext);

	cmd.command.cmd_type = C_CMD_TYPE_DMA;
	cmd.command.opcode = C_CMD_PUT;
	cmd.index_ext = index_ext;
	cmd.lac = md->lac;
	cmd.event_send_disable = 1;
	cmd.dfa = dfa;
	cmd.local_addr = md->addr;
	cmd.request_len = md->len;
	cmd.eq = tx_ctx->send_cq->eq->eqn;
	cmd.initiator =
		CXI_MATCH_ID(tx_ctx->ep_attr->dom_if->kcxi_if->dev->pid_bits,
			     tx_ctx->ep_attr->dom_if->pid,
			     tx_ctx->ep_attr->dom_if->kcxi_if->nic_addr);
	cmd.match_bits = tx_desc->match_bits;
	cmd.user_ptr = (uintptr_t)&tx_desc->req;
	cmd.header_data = tx_desc->header_data;

	/*
	 * TODO: Handle initiator with PID_ANY, NID_ANY, and RANK_ANY are
	 * defined. Also, is KFI_DIRECT_RECV needed (requires handling of
	 * src_addr).
	 */
	TXC_DEBUG(tx_ctx,
		  "Destination RX context NIC (%#x) PID (%u) Index (%u); operation=send length=%lu tag=0x%llx more=%u",
		  tx_desc->peer.nic, tx_desc->peer.pid, tx_desc->offset,
		  md->len, tx_desc->match_bits, more);

	kcxi_cmdq_lock(tx_ctx->transmit);

	rc = kcxi_cmdq_emit_dma_lockless(tx_ctx->transmit, &cmd);
	if (rc) {
		kcxi_cmdq_unlock(tx_ctx->transmit);
		TXC_DEBUG(tx_ctx, "Failed to emit transmit command: rc=%d", rc);
		atomic64_inc(&tx_ctx->command_queue_full);
		return -EAGAIN;
	}

	if (!more)
		kcxi_cmdq_ring_lockless(tx_ctx->transmit);

	kcxi_cmdq_unlock(tx_ctx->transmit);

	TXC_DEBUG(tx_ctx, "TX posted: posted_tx_count=%u rnr_retries_send=%llu",
		  atomic_read(&tx_ctx->posted_tx_cnt), atomic64_read(&tx_ctx->rnr_retries_send));

	return 0;
}

/**
 * kcxi_wq_retry_msg() - Work queue function to retry a send operation.
 * @work: Transmit descriptor embedded work struct.
 *
 * If queueing fails, the transmit descriptor retry work structure will be
 * queued again until it succeeds.
 */
static void kcxi_wq_retry_msg(struct work_struct *work)
{
	struct kcxi_tx_desc *tx_desc =
		container_of(work, struct kcxi_tx_desc, retry);
	struct kcxi_tx_ctx *tx_ctx = tx_desc->tx_ctx;
	int rc;

	atomic64_inc(&tx_ctx->rnr_retries);
	atomic64_inc(&tx_ctx->rnr_retries_send);
	atomic64_inc(&tx_desc->retries);

	rc = kcxi_queue_msg(tx_desc, 0);
	if (rc) {
		TXC_ERR(tx_ctx, "Failed to queue message transmit: rc=%d", rc);
		queue_work(kcxi_wq, &tx_desc->retry);
	}
}

/**
 * kcxi_sendmsg() - Perform a send tagged or message operation.
 * @ep: Local kfabric endpoint.
 * @msg: Message structure.
 * @tagged: Whether or not the send should be tagged.
 * @flags: Operation flags.
 *
 * Return: 0 on success. Else, kfabric negative errno.
 */
static ssize_t kcxi_sendmsg(struct kfid_ep *ep,
			    const struct kfi_msg_tagged *msg, bool tagged,
			    uint64_t flags)
{
	struct kcxi_tx_ctx *tx_ctx;
	struct kcxi_md *md;
	struct kcxi_tx_desc *tx_desc;
	struct kcxi_domain_if *dom_if;
	struct kcxi_addr peer;
	size_t addr_size = sizeof(peer);
	uint32_t map_flags = CXI_MAP_READ;
	int rc;

	/* Only support KFI_COMPLETION for flags. */
	if (!msg || (flags & ~(KCXI_TX_OP_FLAGS | KFI_REMOTE_CQ_DATA)) ||
	    (tagged && msg->tag > KCXI_MAX_USER_MATCH_VALUE))
		return -EINVAL;

	tx_ctx = container_of(ep, struct kcxi_tx_ctx, ctx);
	dom_if = tx_ctx->ep_attr->dom_if;

	if (!tx_ctx->enabled)
		return -KFI_EOPBADSTATE;

	if (kcxi_cq_saturated(tx_ctx->send_cq)) {
		atomic64_inc(&tx_ctx->completion_queue_saturated);
		return -EAGAIN;
	}

	/* Build the destination fabric address. */
	rc = kfi_av_lookup(&tx_ctx->ep_attr->av->av_fid, msg->addr, &peer,
			   &addr_size);
	if (rc) {
		TXC_ERR(tx_ctx, "Address (%llx) lookup failed: rc=%d",
			msg->addr, rc);
		goto err;
	}

	/* Map the user's buffer. */
	switch (msg->type) {
	case KFI_KVEC:
		md = kcxi_md_iov_alloc(dom_if->kcxi_if, tx_ctx->send_cq, msg->msg_iov,
				       msg->iov_count, 0, map_flags);
		break;
	case KFI_BVEC:
		md = kcxi_md_biov_alloc(dom_if->kcxi_if, tx_ctx->send_cq, msg->msg_biov,
					msg->iov_count, 0, map_flags);
		break;
	default:
		TXC_ERR(tx_ctx, "Invalid buffer type: type=%d", msg->type);
		rc = -EINVAL;
		goto err;
	}

	if (IS_ERR(md)) {
		rc = PTR_ERR(md);
		TXC_ERR(tx_ctx, "Failed to map send buffer: rc=%d", rc);
		goto err;
	}

	tx_desc = kcxi_tx_desc_alloc(tx_ctx);
	if (IS_ERR(tx_desc)) {
		rc = PTR_ERR(tx_desc);
		goto err_free_md;
	}

	INIT_WORK(&tx_desc->retry, kcxi_wq_retry_msg);
	tx_desc->md = md;
	tx_desc->req.context = msg->context;
	tx_desc->timeout = ktime_get() + rnr_timeout;
	tx_desc->req.cb = kcxi_msg_tx_req_cb;
	tx_desc->tx_len = md->len;
	tx_desc->peer = peer;
	tx_desc->req.flags = KFI_SEND;
	tx_desc->header_data = msg->data;

	if (tagged)
		tx_desc->req.flags |= KFI_TAGGED;
	else
		tx_desc->req.flags |= KFI_MSG;

	if (flags & KFI_COMPLETION)
		tx_desc->suppress_events = false;
	else
		tx_desc->suppress_events = tx_ctx->suppress_events;

	if (tagged)
		tx_desc->match_bits = KCXI_TAG_MSG_MATCH_VALUE | msg->tag;
	else
		tx_desc->match_bits = KCXI_MSG_MATCH_VALUE;

	if (flags & KFI_REMOTE_CQ_DATA)
		tx_desc->match_bits |= KCXI_REMOTE_CQ_DATA_MATCH_VALUE;

	tx_desc->match_bits |= KCXI_PROV_VERSION_BITS(KCXI_PROV_MAJOR_VERSION);

	if (tx_ctx->attr.caps & KFI_NAMED_RX_CTX)
		tx_desc->offset = kcxi_rx_ctx_offset(msg->addr,
						     tx_ctx->ep_attr->av);
	else
		tx_desc->offset = tx_ctx->tx_id;

	rc = kcxi_queue_msg(tx_desc, flags);
	if (rc) {
		TXC_DEBUG(tx_ctx, "Failed to queue message transmit: rc=%d",
			  rc);
		goto err_free_desc;
	}

	return 0;

err_free_desc:
	kcxi_tx_desc_free(tx_desc);
err_free_md:
	kcxi_md_free(md);
err:
	/* Flush transmit command queue to help prevent future -EAGAINs. */
	if (rc == -EAGAIN)
		kcxi_cmdq_ring(tx_ctx->transmit);

	return rc;

}

/**
 * kcxi_msg_sendmsg() - Perform a send operation using the msg struct
 * @ep: Local kfabric endpoint
 * @msg: Message structure
 * @flags: Operation flags
 *
 * Return: 0 on success. Else, kfabric negative errno.
 */
ssize_t kcxi_msg_sendmsg(struct kfid_ep *ep, const struct kfi_msg *msg,
			 uint64_t flags)
{
	const struct kfi_msg_tagged tagged_msg = {
		.type = msg->type,
		.msg_iov = msg->msg_iov,
		.desc = msg->desc,
		.iov_count = msg->iov_count,
		.addr = msg->addr,
		.context = msg->context,
		.data = msg->data,
	};

	return kcxi_sendmsg(ep, &tagged_msg, false, flags);
}

/**
 * kcxi_msg_sendbv() - Post send using a bvec buffer
 * @ep: Kfabric endpoint
 * @biov: Bvec buffer
 * @desc: Memory descriptor (unused)
 * @count: Number of bvecs
 * @dest_addr: Destination address
 * @context: User operation context
 *
 * Return: 0 on success. Else, kfabric negative errno.
 */
ssize_t kcxi_msg_sendbv(struct kfid_ep *ep, const struct bio_vec *biov,
			void **desc, size_t count, kfi_addr_t dest_addr,
			void *context)
{
	struct kfi_msg msg = {};
	struct kcxi_tx_ctx *tx_ctx;

	tx_ctx = container_of(ep, struct kcxi_tx_ctx, ctx);

	msg.type = KFI_BVEC;
	msg.msg_biov = biov;
	msg.iov_count = count;
	msg.addr = dest_addr;
	msg.context = context;

	return kcxi_msg_sendmsg(ep, &msg, tx_ctx->attr.op_flags);
}

/**
 * kcxi_msg_sendv() - Post send using a kvec buffer
 * @ep: Kfabric endpoint
 * @iov: Kvec buffer
 * @desc: Memory descriptor (unused)
 * @count: Number of kvecs
 * @dest_addr: Destination address
 * @context: User operation context
 *
 * Return: 0 on success. Else, kfabric negative errno.
 */
ssize_t kcxi_msg_sendv(struct kfid_ep *ep, const struct kvec *iov, void **desc,
		       size_t count, kfi_addr_t dest_addr, void *context)
{
	struct kfi_msg msg = {};
	struct kcxi_tx_ctx *tx_ctx;

	tx_ctx = container_of(ep, struct kcxi_tx_ctx, ctx);

	msg.type = KFI_KVEC;
	msg.msg_iov = iov;
	msg.iov_count = count;
	msg.addr = dest_addr;
	msg.context = context;

	return kcxi_msg_sendmsg(ep, &msg, tx_ctx->attr.op_flags);
}

/**
 * kcxi_msg_send() - Post send
 * @ep: Kfabric endpoint
 * @buf: User buffer
 * @len: Length of buffer
 * @desc: Memory descriptor (unused)
 * @dest_addr: Destination address
 * @context: User operation context
 *
 * Return: 0 on success. Else, kfabric negative errno.
 */
ssize_t kcxi_msg_send(struct kfid_ep *ep, const void *buf, size_t len,
		      void *desc, kfi_addr_t dest_addr, void *context)
{
	struct kvec iov;

	iov.iov_base = (void *)buf;
	iov.iov_len = len;

	return kcxi_msg_sendv(ep, &iov, desc, 1, dest_addr, context);
}

/**
 * kcxi_tagged_sendmsg() - Perform a tagged send operation using the msg struct.
 * @ep: Local kfabric endpoint.
 * @msg: Message structure.
 * @flags: Operation flags.
 *
 * Return: 0 on success. Else, kfabric negative errno.
 */
ssize_t kcxi_tagged_sendmsg(struct kfid_ep *ep,
			    const struct kfi_msg_tagged *msg, uint64_t flags)
{
	return kcxi_sendmsg(ep, msg, true, flags);
}

/**
 * kcxi_tagged_sendbv() - Post tagged send using a bvec buffer.
 * @ep: Kfabric endpoint.
 * @biov: Bvec buffer.
 * @desc: Memory descriptor (unused).
 * @count: Number of bvecs.
 * @dest_addr: Destination address.
 * @tag: Message tag.
 * @context: User operation context.
 *
 * Return: 0 on success. Else, kfabric negative errno.
 */
ssize_t kcxi_tagged_sendbv(struct kfid_ep *ep, const struct bio_vec *biov,
			   void **desc, size_t count, kfi_addr_t dest_addr,
			   uint64_t tag, void *context)
{
	const struct kfi_msg_tagged msg = {
		.type = KFI_BVEC,
		.msg_biov = biov,
		.iov_count = count,
		.addr = dest_addr,
		.tag = tag,
		.context = context,
	};
	struct kcxi_tx_ctx *tx_ctx;

	tx_ctx = container_of(ep, struct kcxi_tx_ctx, ctx);

	return kcxi_tagged_sendmsg(ep, &msg, tx_ctx->attr.op_flags);
}

/**
 * kcxi_tagged_sendv() - Post tagged send using a kvec buffer.
 * @ep: Kfabric endpoint.
 * @iov: Kvec buffer.
 * @desc: Memory descriptor (unused).
 * @count: Number of kvecs.
 * @dest_addr: Destination address.
 * @tag: Message tag.
 * @context: User operation context.
 *
 * Return: 0 on success. Else, kfabric negative errno.
 */
ssize_t kcxi_tagged_sendv(struct kfid_ep *ep, const struct kvec *iov,
			  void **desc, size_t count, kfi_addr_t dest_addr,
			  uint64_t tag, void *context)
{
	const struct kfi_msg_tagged msg = {
		.type = KFI_KVEC,
		.msg_iov = iov,
		.iov_count = count,
		.addr = dest_addr,
		.tag = tag,
		.context = context,
	};
	struct kcxi_tx_ctx *tx_ctx;

	tx_ctx = container_of(ep, struct kcxi_tx_ctx, ctx);

	return kcxi_tagged_sendmsg(ep, &msg, tx_ctx->attr.op_flags);
}

/**
 * kcxi_tagged_send() - Post tagged send.
 * @ep: Kfabric endpoint.
 * @buf: User buffer.
 * @len: Length of buffer.
 * @desc: Memory descriptor (unused).
 * @dest_addr: Destination address.
 * @tag: Message tag.
 * @context: User operation context.
 *
 * Return: 0 on success. Else, kfabric negative errno.
 */
ssize_t kcxi_tagged_send(struct kfid_ep *ep, const void *buf, size_t len,
			 void *desc, kfi_addr_t dest_addr, uint64_t tag,
			 void *context)
{
	const struct kvec iov = {
		.iov_base = (void *)buf,
		.iov_len = len,
	};

	return kcxi_tagged_sendv(ep, &iov, desc, 1, dest_addr, tag, context);
}

ssize_t kcxi_tagged_senddata(struct kfid_ep *ep, const void *buf, size_t len,
			     void *desc, uint64_t data, kfi_addr_t dest_addr,
			     uint64_t tag, void *context)
{
	const struct kvec iov = {
		.iov_base = (void *)buf,
		.iov_len = len,
	};
	const struct kfi_msg_tagged tagged_msg = {
		.type = KFI_KVEC,
		.msg_iov = &iov,
		.desc = &desc,
		.iov_count = 1,
		.addr = dest_addr,
		.tag = tag,
		.context = context,
		.data = data,
	};
	struct kcxi_tx_ctx *tx_ctx;

	tx_ctx = container_of(ep, struct kcxi_tx_ctx, ctx);

	return kcxi_sendmsg(ep, &tagged_msg, true,
			    tx_ctx->attr.op_flags | KFI_REMOTE_CQ_DATA);
}
