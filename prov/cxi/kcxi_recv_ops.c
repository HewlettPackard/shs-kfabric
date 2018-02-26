//SPDX-License-Identifier: GPL-2.0
/*
 * Cray kfabric CXI provider receive operations.
 * Copyright 2019-2024 Hewlett Packard Enterprise Development LP. All rights reserved.
 */
#include <linux/slab.h>

#include "kcxi_prov.h"

/**
 * kcxi_msg_rx_req_cb() - Recv message operation callback for event processing
 * @req: kCXI request state for the RMA operation
 * @event: Hardware event
 *
 * Return: 0 for success and non-user event. 1 for success and user event. Else,
 * negative errno.
 */
static int kcxi_msg_rx_req_cb(struct kcxi_cq *cq, struct kcxi_req_state *req,
			      const union c_event *event)
{
	int error_rc;
	int event_rc;
	size_t event_olen;
	size_t event_mlength;
	uint64_t event_start;
	uint64_t header_data;
	int rc;
	struct kcxi_rx_desc *rx_desc;
	struct kcxi_rx_ctx *rx_ctx;
	bool auto_unlinked;
	bool free_rx_desc = false;
	bool suppress_event;
	bool success = true;
	uint32_t initiator;
	kfi_addr_t src_addr;
	bool rma = false;

	rx_desc = container_of(req, struct kcxi_rx_desc, req);
	rx_ctx = rx_desc->rx_ctx;

	switch (event->hdr.event_size) {
	case C_EVENT_SIZE_32_BYTE:
		event_olen = 0;
		event_rc = event->tgt_short.return_code;
		event_mlength = event->tgt_short.length;
		auto_unlinked = event->tgt_short.auto_unlinked;
		event_start = rx_desc->md->addr;
		initiator = event->tgt_short.initiator;
		req->tag = event->tgt_short.match_bits;
		header_data = event->tgt_short.header_data;
		break;

	case C_EVENT_SIZE_64_BYTE:
		event_olen = event->tgt_long.rlength - event->tgt_long.mlength;
		event_rc = event->tgt_long.return_code;
		event_mlength = event->tgt_long.mlength;
		auto_unlinked = event->tgt_long.auto_unlinked;
		event_start = event->tgt_long.start;
		initiator = event->tgt_long.initiator.initiator.process;
		req->tag = event->tgt_long.match_bits;
		header_data = event->tgt_long.header_data;
		break;

	/* This should NEVER happen. */
	default:
		RXC_ERR(rx_desc->rx_ctx, "Bad event size: %u",
			event->hdr.event_size);
		RXC_ERR(rx_desc->rx_ctx, "Possible resource leak");
		return -EINVAL;
	}

	/* Bit used to identify if a tagged RMA write/read was issued instead
	 * of a tagged send.
	 */
	if (req->tag & KCXI_RMA_TAG_MATCH_VALUE)
		rma = true;

	if (req->tag & KCXI_REMOTE_CQ_DATA_MATCH_VALUE)
		req->flags |= KFI_REMOTE_CQ_DATA;
	else
		header_data = 0;

	/* Upper bits of the tag are used internally by the provider and need to
	 * be sanitized.
	 */
	req->tag &= KCXI_MAX_USER_MATCH_VALUE;

	RXC_DEBUG(rx_desc->rx_ctx,
		  "RX event: eqn=%u event_type=%u mlength=%lu olen=%lu rc=%d auto_unlink=%d multi-recv=%d tag=0x%llx rma=%u",
		  cq->eq->eqn, event->hdr.event_type, event_mlength, event_olen,
		  event_rc, auto_unlinked, rx_desc->multi_recv, req->tag,
		  rma);

	suppress_event = rx_desc->suppress_events;
	req->data_len = event_mlength;
	req->data = header_data;

	switch (event->hdr.event_type) {
	/* Tagged send and RMA write with KFI_TAGGED operations. */
	case C_EVENT_PUT:
		if (rma) {
			req->flags |= KFI_RMA | KFI_WRITE;
			if (auto_unlinked)
				rx_desc->unlinked = true;
		} else {
			if (auto_unlinked) {
				rx_desc->unlinked = true;

				if (rx_desc->multi_recv)
					rx_desc->unlink_byte_count =
						event_start - rx_desc->md->addr +
						event_mlength;
			}

			/* Multi-receive buffers require byte count to determine if the
			* descriptor should be freed. Normal receive buffers can be
			* freed after a single receive.
			*/
			if (rx_desc->multi_recv) {
				rx_desc->rx_byte_count += event_mlength;

				/* Update the request buffer field with the location of
				* where the data landed.
				*/
				req->buf = kcxi_md_to_va(rx_desc->md, event_start);
				if (!req->buf) {
					RXC_ERR(rx_desc->rx_ctx,
						"Failed to translate MD to VA");
					success = false;
				}

				/* Generate the multi-receive event only if all receives
				* have been processed.
				*/
				if (rx_desc->rx_byte_count ==
				    rx_desc->unlink_byte_count) {
					if (rx_desc->suppress_events) {
						req->data_len = 0;
						req->buf = NULL;
						req->flags = KFI_MULTI_RECV;
					} else {
						req->flags |= KFI_MULTI_RECV;
					}

					/* Multi recv events are never suppressed. */
					suppress_event = false;
				}
			}
		}

		if (event_rc == C_RC_OK && event_olen == 0 && success) {
			if (suppress_event) {
				rc = 0;
			} else {
				src_addr = kcxi_rx_ctx_src_addr(rx_ctx,
								initiator);

				rc = cq->report_completion(cq, src_addr,
							   &rx_desc->req);
				if (rc != 1)
					RXC_ERR(rx_desc->rx_ctx,
						"Failed to report CQ event: rc=%d",
						rc);
			}
		} else {
			if (event_olen && event_rc == C_RC_OK)
				error_rc = EMSGSIZE;
			else
				error_rc = EIO;

			rc = cq->report_error(cq, &rx_desc->req, event_olen,
					      error_rc, event_rc);
			if (rc != 1)
				RXC_ERR(rx_desc->rx_ctx,
					"Failed to report CQ error: rc=%d", rc);
		}
		break;

	/* RMA read with KFI_TAGGED operation. */
	case C_EVENT_GET:
		req->flags |= KFI_RMA | KFI_READ;
		if (auto_unlinked)
			rx_desc->unlinked = true;

		if (event_rc == C_RC_OK && event_olen == 0 && success) {
			if (suppress_event) {
				rc = 0;
			} else {
				src_addr = kcxi_rx_ctx_src_addr(rx_ctx,
								initiator);

				rc = cq->report_completion(cq, src_addr,
							   &rx_desc->req);
				if (rc != 1)
					RXC_ERR(rx_desc->rx_ctx,
						"Failed to report CQ event: rc=%d",
						rc);
			}
		} else {
			if (event_olen && event_rc == C_RC_OK)
				error_rc = EMSGSIZE;
			else
				error_rc = EIO;

			rc = cq->report_error(cq, &rx_desc->req, event_olen,
					      error_rc, event_rc);
			if (rc != 1)
				RXC_ERR(rx_desc->rx_ctx,
					"Failed to report CQ error: rc=%d", rc);
		}
		break;

	/* Auto unlink events are disabled. */
	case C_EVENT_UNLINK:
		/* Should never happen since auto unlink events are disabled. */
		if (auto_unlinked) {
			RXC_ERR(rx_ctx,
				"Unexpected auto-unlink event: event_rc=%u",
				event_rc);
			RXC_ERR(rx_ctx, "Possible resource leak");
			return -EIO;
		}

		rc = cq->report_error(cq, &rx_desc->req, 0, ECANCELED,
					event_rc);
		if (rc != 1)
			RXC_ERR(rx_ctx, "Failed to report CQ error: rc=%d", rc);

		/* TODO: For multi-recv buffers, PtlTE LE invalidation needs to
		 * occur to flush any pending puts. In addition, the EQ needs to
		 * be flushed to ensure no trailing puts match the multi-recv
		 * buffer before freeing it.
		 */
		free_rx_desc = true;
		break;

	case C_EVENT_LINK:
		/* Only resource exhaustion is expected. */
		if (event_rc != C_RC_NO_SPACE) {
			RXC_ERR(rx_ctx, "Unexpected event type %u rc: %u",
				event->hdr.event_type, event_rc);
			RXC_ERR(rx_ctx, "Possible resource leak");
			return -EIO;
		}

		rc = cq->report_error(cq, &rx_desc->req, 0, EAGAIN, event_rc);
		if (rc != 1)
			RXC_ERR(rx_desc->rx_ctx,
				"Failed to report CQ error: rc=%d", rc);

		/* Force buffer cleanup. */
		free_rx_desc = true;
		break;

	default:
		RXC_ERR(rx_desc->rx_ctx, "Bad event type: %u",
			event->hdr.event_type);
		RXC_ERR(rx_desc->rx_ctx, "Possible resource leak");
		return -EINVAL;
	}

	if (free_rx_desc ||
	    (rx_desc->unlinked &&
	     (!rx_desc->multi_recv ||
	      rx_desc->rx_byte_count == rx_desc->unlink_byte_count))) {
		spin_lock(&rx_desc->rx_ctx->post_rx_lock);
		list_del(&rx_desc->entry);
		spin_unlock(&rx_desc->rx_ctx->post_rx_lock);

		kcxi_md_free(rx_desc->md);

		kcxi_rx_desc_free(rx_desc);

		RXC_DEBUG(rx_ctx,
			  "RX complete: posted_rx_count=%u",
			  atomic_read(&rx_ctx->posted_rx_cnt));
	}

	return rc;
}

#define KFI_BASE_ADDR(addr, rx_ctx_bits) \
	((addr) & ((1UL << (64 - (rx_ctx_bits))) - 1))

/**
 * kcxi_recvmsg() - Perform a recv tagged or message operation.
 * @ep: Local kfabric endpoint
 * @msg: Message structure
 * @tagged: Whether or not the recv should be tagged.
 * @flags: Operation flags
 *
 * Return: 0 on success. Else, kfabric negative errno.
 */
ssize_t kcxi_recvmsg(struct kfid_ep *ep, const struct kfi_msg_tagged *msg,
		     bool tagged, uint64_t flags)
{
	struct kcxi_rx_ctx *rx_ctx;
	struct kcxi_md *md;
	struct kcxi_rx_desc *rx_desc;
	struct kcxi_domain_if *dom_if;
	struct c_target_cmd cmd = {};
	uint32_t map_flags = CXI_MAP_WRITE | CXI_MAP_READ;
	uint32_t match_id = CXI_MATCH_ID_ANY;
	struct kcxi_addr match_peer;
	size_t match_peer_size = sizeof(match_peer);
	int rc;
	bool more = !!(flags & KFI_MORE);

	if (!msg || (flags & ~(KCXI_RX_OP_FLAGS | KFI_MULTI_RECV)) ||
	    (tagged && (flags & KFI_MULTI_RECV)) ||
	    (tagged && (msg->tag > KCXI_MAX_USER_MATCH_VALUE ||
			msg->ignore > KCXI_MAX_USER_MATCH_VALUE)))
		return -EINVAL;

	/* Multi recv buffers can ONLY have a single VA. */
	if ((flags & KFI_MULTI_RECV) && msg->iov_count != 1)
		return -ENOSYS;

	rx_ctx = container_of(ep, struct kcxi_rx_ctx, ctx);
	dom_if = rx_ctx->ep_attr->dom_if;

	if (!rx_ctx->enabled)
		return -KFI_EOPBADSTATE;

	/* Don't check cq saturation for multi recv buffers.
	 * Always want to post them so immediate messages can land.
	 */
	if (!(flags & KFI_MULTI_RECV) && kcxi_cq_saturated(rx_ctx->recv_cq)) {
		atomic64_inc(&rx_ctx->completion_queue_saturated);
		rc = -EAGAIN;
		goto err;
	}

	if (rx_ctx->directed_recv && msg->addr != KFI_ADDR_UNSPEC) {
		rc = kfi_av_lookup(&rx_ctx->ep_attr->av->av_fid,
				   KFI_BASE_ADDR(msg->addr, rx_ctx->ep_attr->av->attr.rx_ctx_bits),
				   &match_peer, &match_peer_size);
		if (rc) {
			RXC_ERR(rx_ctx, "Address (%#llx) lookup failed: rc=%d",
				msg->addr, rc);
			return rc;
		}

		match_id = CXI_MATCH_ID(rx_ctx->ep_attr->dom_if->kcxi_if->dev->pid_bits,
					match_peer.pid, match_peer.nic);
	}

	/* Map the user's buffer. */
	switch (msg->type) {
	case KFI_KVEC:
		md = kcxi_md_iov_alloc(dom_if->kcxi_if, rx_ctx->recv_cq, msg->msg_iov,
				       msg->iov_count, 0, map_flags);
		break;
	case KFI_BVEC:
		md = kcxi_md_biov_alloc(dom_if->kcxi_if, rx_ctx->recv_cq, msg->msg_biov,
					msg->iov_count, 0, map_flags);
		break;
	default:
		RXC_ERR(rx_ctx, "Invalid buffer type: type=%d", msg->type);
		rc = -EINVAL;
		goto err;
	}

	if (IS_ERR(md)) {
		rc = PTR_ERR(md);
		RXC_ERR(rx_ctx, "Failed to map receive buffer: rc=%d", rc);
		goto err;
	}

	rx_desc = kcxi_rx_desc_alloc(rx_ctx);
	if (IS_ERR(rx_desc)) {
		rc = PTR_ERR(rx_desc);
		goto err_free_md;
	}

	rx_desc->md = md;
	rx_desc->req.data_len = md->len;
	rx_desc->req.context = msg->context;

	rx_desc->req.flags = KFI_RECV;
	if (tagged)
		rx_desc->req.flags |= KFI_TAGGED;
	else
		rx_desc->req.flags |= KFI_MSG;

	rx_desc->req.cb = kcxi_msg_rx_req_cb;

	if (flags & KFI_COMPLETION)
		rx_desc->suppress_events = false;
	else
		rx_desc->suppress_events = rx_ctx->suppress_events;

	cmd.command.opcode = C_CMD_TGT_APPEND;
	cmd.ptl_list = C_PTL_LIST_PRIORITY;
	cmd.ptlte_index = KCXI_PTLTE_INDEX(rx_ctx->ptlte);
	cmd.op_put = 1;
	cmd.op_get = 1;
	cmd.unrestricted_body_ro = 1;
	cmd.unrestricted_end_ro = 1;
	cmd.buffer_id = rx_desc->buffer_id;
	cmd.lac = md->lac;
	cmd.start = md->addr;
	cmd.length = md->len;
	cmd.match_id = match_id;
	cmd.event_unlink_disable = 1;
	cmd.event_link_disable = 1;

	if (tagged) {
		cmd.match_bits = KCXI_TAG_MSG_MATCH_VALUE | msg->tag;
		cmd.ignore_bits = KCXI_RMA_TAG_MATCH_VALUE | msg->ignore;
	} else {
		cmd.match_bits = KCXI_MSG_MATCH_VALUE;
	}

	cmd.ignore_bits |= KCXI_REMOTE_CQ_DATA_MATCH_VALUE;
	cmd.match_bits |= KCXI_PROV_VERSION_BITS(KCXI_PROV_MAJOR_VERSION);

	if (flags & KFI_MULTI_RECV) {
		rx_desc->multi_recv = true;
		cmd.manage_local = 1;
		cmd.min_free = rx_ctx->min_multi_recv;
	} else {
		cmd.use_once = 1;
	}

	/*
	 * TODO: Handle match_id with PID_ANY, NID_ANY, and RANK_ANY are
	 * defined. Also, is KFI_DIRECT_RECV needed (requires handling of
	 * src_addr).
	 */

	RXC_DEBUG(rx_ctx, "Post receive: operation=%s length=%lu ignore=0x%llx tag=0x%llx more=%u",
		  flags & KFI_MULTI_RECV ? "multi-recv" : "recv", md->len,
		  msg->ignore, msg->tag, more);

	spin_lock(&rx_ctx->post_rx_lock);
	list_add_tail(&rx_desc->entry, &rx_ctx->posted_rx_list);
	spin_unlock(&rx_ctx->post_rx_lock);

	rc = kcxi_cmdq_emit_target(rx_ctx->target, &cmd);
	if (rc) {
		RXC_ERR(rx_ctx, "Failed to emit target command: rc=%d", rc);
		rc = -EAGAIN;
		atomic64_inc(&rx_ctx->command_queue_full);
		goto err_remove_posted_rx;
	}

	if (!more)
		kcxi_cmdq_ring(rx_ctx->target);

	RXC_DEBUG(rx_ctx,
		  "Receive posted: posted_rx_count=%u",
		  atomic_read(&rx_ctx->posted_rx_cnt));

	return 0;

err_remove_posted_rx:
	spin_lock(&rx_ctx->post_rx_lock);
	list_del(&rx_desc->entry);
	spin_unlock(&rx_ctx->post_rx_lock);

	kcxi_rx_desc_free(rx_desc);
err_free_md:
	kcxi_md_free(md);
err:
	/* Flush receive command queue to help prevent future -EAGAINs. */
	if (rc == -EAGAIN)
		kcxi_cmdq_ring(rx_ctx->target);

	return rc;
}

/**
 * kcxi_msg_recvmsg() - Perform a recv operation using the msg struct
 * @ep: Local kfabric endpoint
 * @msg: Message structure
 * @flags: Operation flags
 *
 * Return: 0 on success. Else, kfabric negative errno.
 */
ssize_t kcxi_msg_recvmsg(struct kfid_ep *ep, const struct kfi_msg *msg,
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

	return kcxi_recvmsg(ep, &tagged_msg, false, flags);
}

/**
 * kcxi_msg_recvbv() - Post recv using a bvec buffer
 * @ep: Kfabric endpoint
 * @biov: Bvec buffer
 * @desc: Memory descriptor (unused)
 * @count: Number of bvecs
 * @src_addr: Source address for posted recv buffer (unused currently)
 * @context: User operation context
 *
 * Return: 0 on success. Else, kfabric negative errno.
 */
ssize_t kcxi_msg_recvbv(struct kfid_ep *ep, const struct bio_vec *biov,
			void **desc, size_t count, kfi_addr_t src_addr,
			void *context)
{
	struct kfi_msg msg = {};
	struct kcxi_rx_ctx *rx_ctx;

	rx_ctx = container_of(ep, struct kcxi_rx_ctx, ctx);

	msg.type = KFI_BVEC;
	msg.msg_biov = biov;
	msg.iov_count = count;
	msg.addr = src_addr;
	msg.context = context;

	return kcxi_msg_recvmsg(ep, &msg, rx_ctx->attr.op_flags);
}

/**
 * kcxi_msg_recvv() - Post recv using a kvec buffer
 * @ep: Kfabric endpoint
 * @iov: Kvec buffer
 * @desc: Memory descriptor (unused)
 * @count: Number of kvecs
 * @src_addr: Source address for posted recv buffer (unused currently)
 * @context: User operation context
 *
 * Return: 0 on success. Else, kfabric negative errno.
 */
ssize_t kcxi_msg_recvv(struct kfid_ep *ep, const struct kvec *iov, void **desc,
		       size_t count, kfi_addr_t src_addr, void *context)
{
	struct kfi_msg msg = {};
	struct kcxi_rx_ctx *rx_ctx;

	rx_ctx = container_of(ep, struct kcxi_rx_ctx, ctx);

	msg.type = KFI_KVEC;
	msg.msg_iov = iov;
	msg.iov_count = count;
	msg.addr = src_addr;
	msg.context = context;

	return kcxi_msg_recvmsg(ep, &msg, rx_ctx->attr.op_flags);
}

/**
 * kcxi_msg_recv() - Post recv
 * @ep: Kfabric endpoint
 * @buf: User buffer
 * @len: Length of buffer
 * @desc: Memory descriptor (unused)
 * @src_addr: Source address for posted recv buffer (unused currently)
 * @context: User operation context
 *
 * Return: 0 on success. Else, kfabric negative errno.
 */
ssize_t kcxi_msg_recv(struct kfid_ep *ep, void *buf, size_t len, void *desc,
		      kfi_addr_t src_addr, void *context)
{
	struct kvec iov;

	iov.iov_base = (void *)buf;
	iov.iov_len = len;

	return kcxi_msg_recvv(ep, &iov, desc, 1, src_addr, context);
}

/**
 * kcxi_tagged_recvmsg() - Perform a tagged recv operation using the msg struct.
 * @ep: Local kfabric endpoint.
 * @msg: Message structure.
 * @flags: Operation flags.
 *
 * Return: 0 on success. Else, kfabric negative errno.
 */
ssize_t kcxi_tagged_recvmsg(struct kfid_ep *ep,
			    const struct kfi_msg_tagged *msg, uint64_t flags)
{
	return kcxi_recvmsg(ep, msg, true, flags);
}

/**
 * kcxi_tagged_recvbv() - Post tagged recv using a bvec buffer.
 * @ep: Kfabric endpoint.
 * @biov: Bvec buffer.
 * @desc: Memory descriptor (unused).
 * @count: Number of bvecs.
 * @src_addr: Source address for posted recv buffer (unused currently).
 * @tag: Receive tag bits.
 * @ignore: Receive ignore bits.
 * @context: User operation context.
 *
 * Return: 0 on success. Else, kfabric negative errno.
 */
ssize_t kcxi_tagged_recvbv(struct kfid_ep *ep, const struct bio_vec *biov,
			   void **desc, size_t count, kfi_addr_t src_addr,
			   uint64_t tag, uint64_t ignore, void *context)
{
	const struct kfi_msg_tagged msg = {
		.type = KFI_BVEC,
		.msg_biov = biov,
		.iov_count = count,
		.addr = src_addr,
		.tag = tag,
		.ignore = ignore,
		.context = context,
	};
	struct kcxi_rx_ctx *rx_ctx;

	rx_ctx = container_of(ep, struct kcxi_rx_ctx, ctx);

	return kcxi_recvmsg(ep, &msg, true, rx_ctx->attr.op_flags);
}

/**
 * kcxi_tagged_recvv() - Post tagged recv using a kvec buffer.
 * @ep: Kfabric endpoint.
 * @iov: Kvec buffer.
 * @desc: Memory descriptor (unused).
 * @count: Number of kvecs.
 * @src_addr: Source address for posted recv buffer (unused currently).
 * @tag: Receive tag bits.
 * @ignore: Receive ignore bits.
 * @context: User operation context.
 *
 * Return: 0 on success. Else, kfabric negative errno.
 */
ssize_t kcxi_tagged_recvv(struct kfid_ep *ep, const struct kvec *iov,
			  void **desc, size_t count, kfi_addr_t src_addr,
			  uint64_t tag, uint64_t ignore, void *context)
{
	const struct kfi_msg_tagged msg = {
		.type = KFI_KVEC,
		.msg_iov = iov,
		.iov_count = count,
		.addr = src_addr,
		.tag = tag,
		.ignore = ignore,
		.context = context,
	};
	struct kcxi_rx_ctx *rx_ctx;

	rx_ctx = container_of(ep, struct kcxi_rx_ctx, ctx);

	return kcxi_recvmsg(ep, &msg, true, rx_ctx->attr.op_flags);
}

/**
 * kcxi_tagged_recv() - Post tagged recv.
 * @ep: Kfabric endpoint.
 * @buf: User buffer.
 * @len: Length of buffer.
 * @desc: Memory descriptor (unused).
 * @src_addr: Source address for posted recv buffer (unused currently).
 * @tag: Receive tag bits.
 * @ignore: Receive ignore bits.
 * @context: User operation context.
 *
 * Return: 0 on success. Else, kfabric negative errno.
 */
ssize_t kcxi_tagged_recv(struct kfid_ep *ep, void *buf, size_t len, void *desc,
			 kfi_addr_t src_addr, uint64_t tag, uint64_t ignore,
			 void *context)
{
	const struct kvec iov = {
		.iov_base = (void *)buf,
		.iov_len = len,
	};

	return kcxi_tagged_recvv(ep, &iov, desc, 1, src_addr, tag, ignore,
				 context);
}
