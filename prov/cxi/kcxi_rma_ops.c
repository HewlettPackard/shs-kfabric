//SPDX-License-Identifier: GPL-2.0
/*
 * Cray kfabric CXI provider RMA operations.
 * Copyright 2019-2024 Hewlett Packard Enterprise Development LP. All rights reserved.
 */
#include <linux/slab.h>

#include "kcxi_prov.h"

/**
 * kcxi_rma_req_cb() - RMA operation callback for event processing
 * @req: kCXI request state for the RMA operation
 * @event: Hardware event
 *
 * Return: 0 for success and non-user event. 1 for success and user event. Else,
 * negative errno.
 */
static int kcxi_rma_req_cb(struct kcxi_cq *cq, struct kcxi_req_state *req,
			   const union c_event *event)
{
	struct kcxi_tx_desc *tx_desc;
	struct kcxi_tx_ctx *tx_ctx;
	int rc;
	size_t event_olen;
	int error_rc;

	tx_desc = container_of(req, struct kcxi_tx_desc, req);
	tx_ctx = tx_desc->tx_ctx;

	if (event->hdr.event_size != C_EVENT_SIZE_16_BYTE) {
		TXC_ERR(tx_desc->tx_ctx, "Bad event size: expected=%u got=%u",
			C_EVENT_SIZE_16_BYTE, event->hdr.event_size);
		rc = -EINVAL;
		goto out;
	}

	/* Only handle ACK and REPLY events. */
	switch (event->hdr.event_type) {
	case C_EVENT_ACK:
	case C_EVENT_REPLY:
		break;

	default:
		TXC_ERR(tx_desc->tx_ctx, "Bad event: event_type=%d",
			event->hdr.event_type);
		rc = -EINVAL;
		goto out;
	}

	TXC_DEBUG(tx_desc->tx_ctx,
		  "RMA event: eqn=%u event_type=%u mlength=%u rc=%d",
		  cq->eq->eqn, event->hdr.event_type, event->init_short.mlength,
		  event->init_short.return_code);

	/* For RMA, treat C_RC_ENTRY_NOT_FOUND as receiver not ready. */
	if (tx_ctx->enabled &&
	    event->init_short.return_code == C_RC_ENTRY_NOT_FOUND) {
		if (tx_desc->timeout > ktime_get()) {
			queue_work(kcxi_wq, &tx_desc->retry);
			return 0;
		}

		TXC_ERR_RL(tx_ctx,
			   "RMA timeout to RX context NIC (%#x) PID (%u) Index (%u) Key (%#llx); nsec=%llu rnr_retries=%llu posted_tx_count=%u",
			   tx_desc->peer.nic, tx_desc->peer.pid, tx_desc->offset,
			   tx_desc->match_bits & KCXI_MAX_USER_MATCH_VALUE,
			   ktime_sub(ktime_get(), tx_desc->timeout - rnr_timeout),
			   atomic64_read(&tx_desc->retries),
			   atomic_read(&tx_ctx->posted_tx_cnt));
	}

	event_olen = tx_desc->tx_len - event->init_short.mlength;

	if (event->init_short.return_code == C_RC_OK && event_olen == 0) {

		/*
		 * Suppressing the event causes a kfabric CQ event to not be
		 * written in addition to not calling the CQ user's callback.
		 * Whether or not an event is suppressed is dependent on the
		 * bind flags used for a CQ and the RMA operation flags.
		 */
		if (tx_desc->suppress_events) {
			rc = 0;
		} else {
			rc = cq->report_completion(cq, KFI_ADDR_NOTAVAIL, req);
			if (rc != 1)
				TXC_ERR(tx_desc->tx_ctx,
					"Failed to report CQ event: rc=%d", rc);
		}
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
		  "RMA completion: posted_tx_count=%u",
		  atomic_read(&tx_ctx->posted_tx_cnt));

	return rc;
}

/**
 * kcxi_queue_rma() - Queue an RMA transmit descriptor to hardware.
 * @tx_desc: RMA transmit descriptor.
 * @flags: Operational flags.
 *
 * Return: 0 on success. -EAGAIN if queueing failed.
 */
static int kcxi_queue_rma(struct kcxi_tx_desc *tx_desc, uint64_t flags)
{
	struct c_full_dma_cmd cmd = {};
	struct kcxi_md *md = tx_desc->md;
	struct kcxi_tx_ctx *tx_ctx = tx_desc->tx_ctx;
	struct kcxi_domain_if *dom_if = tx_ctx->ep_attr->dom_if;
	union c_fab_addr dfa;
	uint8_t index_ext;
	int rc;
	bool more = !!(flags & KFI_MORE);
	enum c_dma_op opcode;

	cxi_build_dfa(tx_desc->peer.nic, tx_desc->peer.pid,
		      dom_if->kcxi_if->dev->pid_bits, tx_desc->offset, &dfa,
		      &index_ext);

	if (tx_desc->req.flags & KFI_WRITE)
		opcode = C_CMD_PUT;
	else
		opcode = C_CMD_GET;

	/* Build RMA command. */
	cmd.command.cmd_type = C_CMD_TYPE_DMA;
	cmd.command.opcode = opcode;
	cmd.index_ext = index_ext;
	cmd.lac = md->lac;
	cmd.event_send_disable = 1;
	cmd.dfa = dfa;
	cmd.remote_offset = tx_desc->remote_offset;
	cmd.local_addr = md->addr;
	cmd.request_len = md->len;
	cmd.eq = tx_ctx->send_cq->eq->eqn;
	cmd.initiator =
		CXI_MATCH_ID(tx_ctx->ep_attr->dom_if->kcxi_if->dev->pid_bits,
			     tx_ctx->ep_attr->dom_if->pid,
			     tx_ctx->ep_attr->dom_if->kcxi_if->nic_addr);
	cmd.user_ptr = (uintptr_t)&tx_desc->req;
	cmd.match_bits = tx_desc->match_bits;

	TXC_DEBUG(tx_ctx,
		  "Destination MR NIC (%#x) PID (%u) Index (%u) Key (%llx): operation=%s length=%lu offset=%lu more=%u tagged=%u",
		  tx_desc->peer.nic, tx_desc->peer.pid, tx_desc->offset,
		  tx_desc->match_bits & KCXI_MAX_USER_MATCH_VALUE,
		  opcode == C_CMD_PUT ? "write" : "read", md->len,
		  tx_desc->remote_offset, more,
		  tx_desc->req.flags & KFI_TAGGED ? 1 : 0);

	kcxi_cmdq_lock(tx_ctx->transmit);

	rc = kcxi_cmdq_emit_dma_lockless(tx_ctx->transmit, &cmd);
	if (rc) {
		kcxi_cmdq_unlock(tx_ctx->transmit);
		TXC_DEBUG(tx_ctx, "Failed to emit DMA command: rc=%d", rc);
		atomic64_inc(&tx_ctx->command_queue_full);
		return -EAGAIN;
	}

	if (!more)
		kcxi_cmdq_ring_lockless(tx_ctx->transmit);

	kcxi_cmdq_unlock(tx_ctx->transmit);

	TXC_DEBUG(tx_ctx, "RMA posted: posted_tx_count=%u rnr_retries_rma=%llu",
		  atomic_read(&tx_ctx->posted_tx_cnt), atomic64_read(&tx_ctx->rnr_retries_rma));

	return 0;
}

/**
 * kcxi_wq_retry_rma() - Work queue function to retry an RMA operation.
 * @work: Transmit descriptor embedded work struct.
 *
 * If queueing fails, the transmit descriptor retry work structure will be
 * queued again until it succeeds.
 */
static void kcxi_wq_retry_rma(struct work_struct *work)
{
	struct kcxi_tx_desc *tx_desc =
		container_of(work, struct kcxi_tx_desc, retry);
	struct kcxi_tx_ctx *tx_ctx = tx_desc->tx_ctx;
	int rc;

	atomic64_inc(&tx_ctx->rnr_retries);
	atomic64_inc(&tx_ctx->rnr_retries_rma);
	atomic64_inc(&tx_desc->retries);

	rc = kcxi_queue_rma(tx_desc, 0);
	if (rc) {
		TXC_ERR(tx_ctx, "Failed to queue message transmit: rc=%d", rc);
		queue_work(kcxi_wq, &tx_desc->retry);
	}
}

/**
 * kcxi_rma_command() - Issue a RMA command
 * @ep: Kfabric endpoint
 * @msg: RMA message attributes
 * @flags: RMA operation flags
 * @write: Write or read command
 *
 * Return: 0 on success. Else, kfabric negative errno.
 */
static int kcxi_rma_command(struct kfid_ep *ep, const struct kfi_msg_rma *msg,
			    uint64_t flags, bool write)
{
	struct kcxi_tx_ctx *tx_ctx;
	struct kcxi_md *md;
	struct kcxi_tx_desc *tx_desc;
	struct kcxi_domain_if *dom_if;
	struct kcxi_addr peer;
	size_t addr_size = sizeof(peer);
	uint32_t offset;
	uint32_t map_flags = 0;
	int rc;

	if (!msg || msg->rma_iov_count != 1 || !msg->rma_iov ||
	    (flags & ~(KCXI_TX_OP_FLAGS | KFI_TAGGED | KFI_REMOTE_CQ_DATA)))
		return -EINVAL;

	tx_ctx = container_of(ep, struct kcxi_tx_ctx, ctx);
	dom_if = tx_ctx->ep_attr->dom_if;

	if (!tx_ctx->enabled)
		return -KFI_EOPBADSTATE;

	if (msg->rma_iov[0].key > KCXI_MAX_USER_MATCH_VALUE)
		return -KFI_EKEYREJECTED;

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

	if (tx_ctx->attr.caps & KFI_NAMED_RX_CTX)
		offset = kcxi_rx_ctx_offset(msg->addr, tx_ctx->ep_attr->av);
	else
		offset = tx_ctx->tx_id;

	if (write) {
		map_flags |= CXI_MAP_READ;
	} else {
		map_flags |= CXI_MAP_WRITE;
		offset += KCXI_GET_PID_OFFSET;
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
		TXC_ERR(tx_ctx, "Failed to map RMA buffer: rc=%d", rc);
		goto err;
	}

	if (md->len > msg->rma_iov[0].len) {
		rc = -EINVAL;
		TXC_ERR(tx_ctx,
			"Local buffer len %lu exceeds target MR len %lu",
			md->len, msg->rma_iov[0].len);
		goto err_free_md;
	}

	/* Setup the transaction transmit descriptor. */
	tx_desc = kcxi_tx_desc_alloc(tx_ctx);
	if (IS_ERR(tx_desc)) {
		rc = PTR_ERR(tx_desc);
		goto err_free_md;
	}

	INIT_WORK(&tx_desc->retry, kcxi_wq_retry_rma);
	tx_desc->md = md;
	tx_desc->req.context = msg->context;
	tx_desc->timeout = ktime_get() + rnr_timeout;
	tx_desc->req.flags = KFI_RMA;
	tx_desc->req.cb = kcxi_rma_req_cb;
	tx_desc->offset = offset;
	tx_desc->peer = peer;
	tx_desc->tx_len = md->len;
	tx_desc->remote_offset = msg->rma_iov[0].addr;

	if (flags & KFI_COMPLETION)
		tx_desc->suppress_events = false;
	else
		tx_desc->suppress_events = tx_ctx->suppress_events;

	if (write)
		tx_desc->req.flags |= KFI_WRITE;
	else
		tx_desc->req.flags |= KFI_READ;

	if (flags & KFI_TAGGED)
		tx_desc->req.flags |= KFI_TAGGED | KFI_SEND;

	tx_desc->match_bits = msg->rma_iov[0].key |
		KCXI_PROV_VERSION_BITS(KCXI_PROV_MAJOR_VERSION);
	if (tx_desc->req.flags & KFI_TAGGED)
		tx_desc->match_bits |= KCXI_TAG_MSG_MATCH_VALUE |
			KCXI_RMA_TAG_MATCH_VALUE;
	else
		tx_desc->match_bits |= KCXI_MR_MATCH_VALUE;

	if (flags & KFI_REMOTE_CQ_DATA)
		tx_desc->match_bits |= KCXI_REMOTE_CQ_DATA_MATCH_VALUE;

	rc = kcxi_queue_rma(tx_desc, flags);
	if (rc) {
		TXC_DEBUG(tx_ctx, "Failed to queue RMA transmit: rc=%d", rc);
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
 * kcxi_rma_writemsg() - Perform a RMA write operation using the msg struct
 * @ep: Local kfabric endpoint
 * @msg: Message structure
 * @flags: Operation flags
 *
 * Return: 0 on success. Else, negative errno.
 */
ssize_t kcxi_rma_writemsg(struct kfid_ep *ep, const struct kfi_msg_rma *msg,
			  uint64_t flags)
{
	return kcxi_rma_command(ep, msg, flags, true);
}

/**
 * kcxi_rma_readmsg() - Perform a RMA read operation using the msg struct
 * @ep: Local kfabric endpoint
 * @msg: Message structure
 * @flags: Operation flags
 *
 * Return: 0 on success. Else, negative errno.
 */
ssize_t kcxi_rma_readmsg(struct kfid_ep *ep, const struct kfi_msg_rma *msg,
			 uint64_t flags)
{
	return kcxi_rma_command(ep, msg, flags, false);
}

/**
 * kcxi_rma_writebv() - Perform a RMA write operation using a bvec iov
 * @ep: Local kfabric endpoint
 * @biov: Bvec iov
 * @count: Number of iovs
 * @desc: Memory descriptor (unused)
 * @dest_addr: Destination address
 * @addr: Offset into remote memory region
 * @key: Remote protection key
 * @context: User specified pointer associated with this operation
 *
 * Return: 0 on success. Else, negative errno.
 */
ssize_t kcxi_rma_writebv(struct kfid_ep *ep, const struct bio_vec *biov,
			 void **desc, size_t count, kfi_addr_t dest_addr,
			 uint64_t addr, uint64_t key, void *context)
{
	size_t len = 0;
	struct kfi_rma_iov rma_iov;
	struct kfi_msg_rma msg_rma;
	int i;
	struct kcxi_tx_ctx *tx_ctx;

	tx_ctx = container_of(ep, struct kcxi_tx_ctx, ctx);

	for (i = 0; i < count; i++)
		len += biov[i].bv_len;

	rma_iov.addr = addr;
	rma_iov.len = len;
	rma_iov.key = key;

	msg_rma.type = KFI_BVEC;
	msg_rma.msg_biov = biov;
	msg_rma.desc = desc;
	msg_rma.iov_count = count;
	msg_rma.addr = dest_addr;
	msg_rma.rma_iov = &rma_iov;
	msg_rma.rma_iov_count = 1;
	msg_rma.context = context;

	return kcxi_rma_command(ep, &msg_rma, tx_ctx->attr.op_flags, true);
}

/**
 * kcxi_rma_readbv() - Perform a RMA read operation using a bvec iov
 * @ep: Local kfabric endpoint
 * @biov: Bvec iov
 * @count: Number of iovs
 * @desc: Memory descriptor (unused)
 * @src_addr: Source address
 * @addr: Offset into remote memory region
 * @key: Remote protection key
 * @context: User specified pointer associated with this operation
 *
 * Return: 0 on success. Else, negative errno.
 */
ssize_t kcxi_rma_readbv(struct kfid_ep *ep, const struct bio_vec *biov,
			void **desc, size_t count, kfi_addr_t src_addr,
			uint64_t addr, uint64_t key, void *context)
{
	size_t len = 0;
	struct kfi_rma_iov rma_iov;
	struct kfi_msg_rma msg_rma;
	int i;
	struct kcxi_tx_ctx *tx_ctx;

	tx_ctx = container_of(ep, struct kcxi_tx_ctx, ctx);

	for (i = 0; i < count; i++)
		len += biov[i].bv_len;

	rma_iov.addr = addr;
	rma_iov.len = len;
	rma_iov.key = key;

	msg_rma.type = KFI_BVEC;
	msg_rma.msg_biov = biov;
	msg_rma.desc = desc;
	msg_rma.iov_count = count;
	msg_rma.addr = src_addr;
	msg_rma.rma_iov = &rma_iov;
	msg_rma.rma_iov_count = 1;
	msg_rma.context = context;

	return kcxi_rma_command(ep, &msg_rma, tx_ctx->attr.op_flags, false);
}

/**
 * kcxi_rma_writev() - Perform a RMA write operation using a kvec iov
 * @ep: Local kfabric endpoint
 * @iov: Kvec iov
 * @count: Number of iovs
 * @desc: Memory descriptor (unused)
 * @dest_addr: Destination address
 * @addr: Offset into remote memory region
 * @key: Remote protection key
 * @context: User specified pointer associated with this operation
 *
 * Return: 0 on success. Else, negative errno.
 */
ssize_t kcxi_rma_writev(struct kfid_ep *ep, const struct kvec *iov, void **desc,
			size_t count, kfi_addr_t dest_addr, uint64_t addr,
			uint64_t key, void *context)
{
	size_t len = 0;
	struct kfi_rma_iov rma_iov;
	struct kfi_msg_rma msg_rma;
	int i;
	struct kcxi_tx_ctx *tx_ctx;

	tx_ctx = container_of(ep, struct kcxi_tx_ctx, ctx);

	for (i = 0; i < count; i++)
		len += iov[i].iov_len;

	rma_iov.addr = addr;
	rma_iov.len = len;
	rma_iov.key = key;

	msg_rma.type = KFI_KVEC;
	msg_rma.msg_iov = iov;
	msg_rma.desc = desc;
	msg_rma.iov_count = count;
	msg_rma.addr = dest_addr;
	msg_rma.rma_iov = &rma_iov;
	msg_rma.rma_iov_count = 1;
	msg_rma.context = context;

	return kcxi_rma_command(ep, &msg_rma, tx_ctx->attr.op_flags, true);
}

/**
 * kcxi_rma_readv() - Perform a RMA read operation using a kvec iov
 * @ep: Local kfabric endpoint
 * @iov: Kvec iov
 * @count: Number of iovs
 * @desc: Memory descriptor (unused)
 * @src_addr: Source address
 * @addr: Offset into remote memory region
 * @key: Remote protection key
 * @context: User specified pointer associated with this operation
 *
 * Return: 0 on success. Else, negative errno.
 */
ssize_t kcxi_rma_readv(struct kfid_ep *ep, const struct kvec *iov, void **desc,
		       size_t count, kfi_addr_t src_addr, uint64_t addr,
		       uint64_t key, void *context)
{
	size_t len = 0;
	struct kfi_rma_iov rma_iov;
	struct kfi_msg_rma msg_rma;
	int i;
	struct kcxi_tx_ctx *tx_ctx;

	tx_ctx = container_of(ep, struct kcxi_tx_ctx, ctx);

	for (i = 0; i < count; i++)
		len += iov[i].iov_len;

	rma_iov.addr = addr;
	rma_iov.len = len;
	rma_iov.key = key;

	msg_rma.type = KFI_KVEC;
	msg_rma.msg_iov = iov;
	msg_rma.desc = desc;
	msg_rma.iov_count = count;
	msg_rma.addr = src_addr;
	msg_rma.rma_iov = &rma_iov;
	msg_rma.rma_iov_count = 1;
	msg_rma.context = context;

	return kcxi_rma_command(ep, &msg_rma, tx_ctx->attr.op_flags, false);
}

/**
 * kcxi_rma_write() - Perform a RMA write operation
 * @ep: Local kfabric endpoint
 * @buf: Local buffer where data is written from
 * @len: Length of buffer
 * @desc: Memory descriptor (unused)
 * @dest_addr: Destination address
 * @addr: Offset into remote memory region
 * @key: Remote protection key
 * @context: User specified pointer associated with this operation
 *
 * Return: 0 on success. Else, negative errno.
 */
ssize_t kcxi_rma_write(struct kfid_ep *ep, const void *buf, size_t len,
		       void *desc, kfi_addr_t dest_addr, uint64_t addr,
		       uint64_t key, void *context)
{
	struct kvec iov;

	if (len) {
		iov.iov_base = (void *)buf;
		iov.iov_len = len;

		return kcxi_rma_writev(ep, &iov, desc, 1, dest_addr, addr, key,
				       context);
	}

	return kcxi_rma_writev(ep, NULL, desc, 0, dest_addr, addr, key,
			       context);
}

/**
 * kcxi_rma_read() - Perform a RMA read operation
 * @ep: Local kfabric endpoint
 * @buf: Local buffer where data is written to
 * @len: Length of buffer
 * @desc: Memory descriptor (unused)
 * @src_addr: Source address
 * @addr: Offset into remote memory region
 * @key: Remote protection key
 * @context: User specified pointer associated with this operation
 *
 * Return: 0 on success. Else, negative errno.
 */
ssize_t kcxi_rma_read(struct kfid_ep *ep, void *buf, size_t len, void *desc,
		      kfi_addr_t src_addr, uint64_t addr, uint64_t key,
		      void *context)
{
	struct kvec iov;

	if (len) {
		iov.iov_base = buf;
		iov.iov_len = len;

		return kcxi_rma_readv(ep, &iov, desc, 1, src_addr, addr, key,
				      context);
	}

	return kcxi_rma_readv(ep, NULL, desc, 0, src_addr, addr, key, context);
}
