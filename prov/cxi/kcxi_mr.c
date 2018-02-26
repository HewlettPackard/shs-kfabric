//SPDX-License-Identifier: GPL-2.0
/*
 * Cray kfabric CXI provider memory regions.
 * Copyright 2019-2021,2024 Hewlett Packard Enterprise Development LP. All rights reserved.
 */
#include <linux/slab.h>

#include "kcxi_prov.h"

static void kcxi_mr_unlink_event(struct kcxi_req_state *req,
				 const union c_event *event)
{
	struct kcxi_mr *mr;
	enum kcxi_mr_state state = MR_UNLINKED;
	int event_rc;

	mr = container_of(req, struct kcxi_mr, req);

	if (event->hdr.event_type != C_EVENT_UNLINK) {
		MR_ERR(mr, "Bad event type: %d", event->hdr.event_type);
		return;
	}

	switch (event->hdr.event_size) {
	case C_EVENT_SIZE_32_BYTE:
		event_rc = event->tgt_short.return_code;
		break;

	case C_EVENT_SIZE_64_BYTE:
		event_rc = event->tgt_long.return_code;
		break;

	/* This should NEVER happen. */
	default:
		MR_ERR(mr, "Bad event size: %u", event->hdr.event_size);
		MR_ERR(mr, "Possible resource leak");
		return;
	}

	MR_DEBUG(mr, "MR unlink event");

	if (event_rc != C_RC_OK)
		state = MR_ERROR;

	if (mr->state == state) {
		switch (state) {
		case MR_LINKED:
			MR_WARN(mr, "MR state already set to linked");
			break;
		case MR_UNLINKED:
			MR_WARN(mr, "MR state already set to unlinked");
			break;
		case MR_ERROR:
			MR_WARN(mr, "MR state already set to error");
			break;
		default:
			MR_ERR(mr, "Unknown MR state: %d", state);
			return;
		}
	}

	mr->state = state;

	/* Thread(s)s are blocking for MR unlink event. */
	kcxi_mr_domain_wake_up();
}

static struct kcxi_eq *kcxi_mr_link_event(struct kcxi_req_state *req,
					  const union c_event *event)
{
	struct kcxi_mr *mr;
	enum kcxi_mr_state state = MR_LINKED;
	struct kfi_eq_entry eq_event = {};
	struct kfi_eq_err_entry eq_error = {};
	int rc = 0;
	int event_rc;

	mr = container_of(req, struct kcxi_mr, req);

	if (event->hdr.event_type != C_EVENT_LINK) {
		MR_ERR(mr, "Bad event type: %d", event->hdr.event_type);
		return NULL;
	}

	switch (event->hdr.event_size) {
	case C_EVENT_SIZE_32_BYTE:
		event_rc = event->tgt_short.return_code;
		break;

	case C_EVENT_SIZE_64_BYTE:
		event_rc = event->tgt_long.return_code;
		break;

	/* This should NEVER happen. */
	default:
		MR_ERR(mr, "Bad event size: %u", event->hdr.event_size);
		MR_ERR(mr, "Possible resource leak");
		return NULL;
	}

	MR_DEBUG(mr, "MR link event");

	if (event_rc != C_RC_OK)
		state = MR_ERROR;

	if (mr->state == state) {
		switch (state) {
		case MR_LINKED:
			MR_WARN(mr, "MR state already set to linked");
			break;
		case MR_UNLINKED:
			MR_WARN(mr, "MR state already set to unlinked");
			break;
		case MR_ERROR:
			MR_WARN(mr, "MR state already set to error");
			break;
		default:
			MR_ERR(mr, "Unknown MR state: %d", state);
			return NULL;
		}
	}

	mr->state = state;

	/* Non-null pointer means domain is setup for async MR notification. */
	if (mr->eq) {
		if (state == MR_ERROR) {
			/* TODO: Should kCXI provider err info be provided? */
			eq_error.fid = &mr->mr_fid.fid;
			eq_error.context = mr->mr_fid.fid.context;

			rc = kcxi_eq_report_error(mr->eq, &eq_error);
			if (rc)
				MR_ERR(mr, "Failed to write MR err event: %d",
				       rc);
		} else if (state == MR_LINKED) {
			eq_event.fid = &mr->mr_fid.fid;
			eq_event.context = mr->mr_fid.fid.context;

			rc = kcxi_eq_report_event(mr->eq, KFI_MR_COMPLETE,
						 &eq_event);
			if (rc)
				MR_ERR(mr, "Failed to write MR event: %d", rc);
		}
	} else {
		kcxi_mr_domain_wake_up();
	}

	return mr->eq;
}

/**
 * kcxi_mr_req_cb() - Memory region request state callback
 * @cq: kCXI completion queue
 * @req: The request state
 * @event: The event to be processed
 *
 * Return: 0 on success. Else, negative errno.
 */
static int kcxi_mr_req_cb(struct kcxi_cq *cq, struct kcxi_req_state *req,
			  const union c_event *event)
{
	struct kcxi_mr *mr;
	int event_rc;
	int rc;
	size_t event_mlength;
	bool mr_unlinked;
	bool remote_data;
	uint64_t header_data;

	switch (event->hdr.event_size) {
	case C_EVENT_SIZE_32_BYTE:
		event_rc = event->tgt_short.return_code;
		event_mlength = event->tgt_short.length;
		header_data = event->tgt_short.header_data;
		remote_data = !!(event->tgt_short.match_bits &
				 KCXI_REMOTE_CQ_DATA_MATCH_VALUE);
		break;

	case C_EVENT_SIZE_64_BYTE:
		event_rc = event->tgt_long.return_code;
		event_mlength = event->tgt_long.mlength;
		header_data = event->tgt_short.header_data;
		remote_data = !!(event->tgt_short.match_bits &
				 KCXI_REMOTE_CQ_DATA_MATCH_VALUE);
		break;

	default:
		LOG_ERR("Bad MR event size: %u", event->hdr.event_size);
		BUG();
	}

	/* Drop all is MST cancelled events. */
	if (event_rc == C_RC_MST_CANCELLED) {
		LOG_ERR("Dropping MR event: event_type=%d rc=%d",
			event->hdr.event_type, event_rc);
		return 0;
	}

	mr = container_of(req, struct kcxi_mr, req);
	mr_unlinked = mr->state == MR_UNLINKED;

	MR_DEBUG(mr, "MR event: eqn=%u event_type=%u mlength=%lu rc=%d",
		 cq->eq->eqn, event->hdr.event_type, event_mlength, event_rc);

	if (mr->rx_ctx->mr_domain->with_remote_rma_events &&
	    (event->hdr.event_type == C_EVENT_PUT ||
	     event->hdr.event_type == C_EVENT_GET)) {
		if (event->hdr.event_type == C_EVENT_PUT)
			req->flags = (KFI_RMA | KFI_REMOTE_WRITE);
		else
			req->flags = (KFI_RMA | KFI_REMOTE_READ);

		if (remote_data)
			req->flags |= KFI_REMOTE_CQ_DATA;
		else
			header_data = 0;

		req->data = header_data;

		/* TODO: Update kfabric documentation stating MR context is
		 * returned for remote RMA events.
		 */
		req->context = mr->mr_fid.fid.context;

		if (event_rc == C_RC_OK) {
			rc = cq->report_completion(cq, KFI_ADDR_NOTAVAIL, req);
			if (rc != 1)
				MR_ERR(mr, "Failed to report CQ event: rc=%d",
				       rc);
		} else {
			rc = cq->report_error(cq, req, 0, EIO, event_rc);
			if (rc != 1)
				MR_ERR(mr, "Failed to report CQ error: rc=%d",
				       rc);
		}
	} else {
		rc = 0;
	}

	/* MR cannot be reference after incrementing the match and RMA event
	 * counters.
	 */
	switch (event->hdr.event_type) {
	case C_EVENT_PUT:
	case C_EVENT_GET:
		atomic_inc(&mr->rma_event_count);
		MR_DEBUG(mr, "RMA event: count=%u",
			 atomic_read(&mr->rma_event_count));
		break;

	case C_EVENT_MATCH:
		atomic_inc(&mr->match_event_count);
		MR_DEBUG(mr, "Match event: count=%u",
			 atomic_read(&mr->match_event_count));
		break;

	default:
		MR_ERR(mr, "Bad event size: %u", event->hdr.event_size);
		BUG();
	}

	/* If MR is unlinked, needed to wakeup any thread waiting for
	 * match event count to equal RMA event count.
	 */
	if (mr_unlinked)
		kcxi_mr_domain_wake_up();

	return rc;
}

static int kcxi_mr_enable(struct kcxi_mr *mr)
{
	int rc;

	if (!mr->rx_ctx)
		return -EINVAL;

	/* Verify new MR key is unique. */
	rc = kcxi_mr_domain_register(mr->rx_ctx->mr_domain, mr);
	if (rc)
		return rc;

	/* Allocate buffer ID for MR. */
	rc = kcxi_mr_domain_buffer_id_map(mr->rx_ctx->mr_domain, &mr->req);
	if (rc < 0)
		goto err_remove_key;
	mr->buffer_id = rc;

	/* Link the buffer. */
	rc = kcxi_mr_domain_link(mr->rx_ctx->mr_domain, mr);
	if (rc)
		goto err_unmap_buffer_id;

	mr->enabled = true;

	MR_DEBUG(mr, "MR enabled");

	return 0;

err_unmap_buffer_id:
	kcxi_mr_domain_buffer_id_unmap(mr->rx_ctx->mr_domain, mr->buffer_id);
err_remove_key:
	kcxi_mr_domain_deregister(mr->rx_ctx->mr_domain, mr);

	MR_ERR(mr, "Failed to enabled MR: rc=%d", rc);

	return rc;
}

/**
 * kcxi_mr_close() - Closer a MR
 * @mr: MR to be close
 *
 * Note: This function will block until an unlink event occurs.
 *
 * Return: 0 on success. Else, negative errno.
 */
static int kcxi_mr_close(struct kfid *mr)
{
	struct kcxi_mr *kcxi_mr = container_of(mr, struct kcxi_mr, mr_fid.fid);

	if (kcxi_mr->enabled) {
		kcxi_mr_domain_unlink(kcxi_mr->rx_ctx->mr_domain, kcxi_mr);

		kcxi_mr_domain_buffer_id_unmap(kcxi_mr->rx_ctx->mr_domain,
					      kcxi_mr->buffer_id);

		kcxi_mr_domain_deregister(kcxi_mr->rx_ctx->mr_domain, kcxi_mr);
	}

	if (kcxi_mr->rx_ctx)
		kcxi_rx_ctx_unbind_mr(kcxi_mr->rx_ctx, kcxi_mr);

	kcxi_md_free(kcxi_mr->md);

	atomic_dec(&kcxi_mr->dom->ref_cnt);

	LOG_DEBUG("MR freed: key=%llx", kcxi_mr->mr_fid.key);

	kfree(kcxi_mr);

	return 0;
}

/**
 * kcxi_mr_bind() - Bind a MR to a RX context
 * @mr: MR fid
 * @bfid: Bind fid
 * @flags: Bind flags
 *
 * Return: 0 on success. Else, kfabric negative errno.
 */
static int kcxi_mr_bind(struct kfid *mr, struct kfid *bfid, uint64_t flags)
{
	struct kcxi_mr *kcxi_mr = container_of(mr, struct kcxi_mr, mr_fid.fid);
	struct kcxi_rx_ctx *rx_ctx;
	int rc;

	if (!bfid || kcxi_mr->rx_ctx)
		return -EINVAL;

	if (bfid->fclass != KFI_CLASS_RX_CTX)
		return -ENOSYS;

	if (flags)
		return -KFI_EBADFLAGS;

	rx_ctx = container_of(bfid, struct kcxi_rx_ctx, ctx.fid);

	rc = kcxi_rx_ctx_bind_mr(rx_ctx, kcxi_mr);
	if (rc)
		LOG_ERR("Failed to bind MR: key=%llx", kcxi_mr->mr_fid.key);

	MR_DEBUG(kcxi_mr, "MR bound to RX context");

	return 0;
}

/**
 * kcxi_mr_control() - MR control operations
 * @mr: MR fid
 * @command: Control command
 * @arg: Control args
 *
 * Return: 0 on success. Else, negative errno.
 */
static int kcxi_mr_control(struct kfid *mr, int command, void *arg)
{
	struct kcxi_mr *kcxi_mr = container_of(mr, struct kcxi_mr, mr_fid.fid);

	if (command == KFI_ENABLE)
		return kcxi_mr_enable(kcxi_mr);

	return -EINVAL;
}

static struct kfi_ops kcxi_mr_fid_ops = {
	.close = kcxi_mr_close,
	.bind = kcxi_mr_bind,
	.control = kcxi_mr_control,
	.ops_open = kfi_no_ops_open
};

/**
 * kcxi_mr_alloc() - Allocate a memory region
 * @dom: kCXI domain MR should be allocated against
 * @md: Memory descriptor MR should be associated with
 * @access: MR access flags
 * @key: Remote access key
 * @context: User defined context
 *
 * Return: Valid pointer on success. Else, kfabric errno pointer.
 */
static struct kcxi_mr *kcxi_mr_alloc(struct kcxi_domain *dom,
				     struct kcxi_md *md, uint64_t access,
				     uint64_t key, void *context)
{
	struct kcxi_mr *mr;

	if (key > KCXI_MAX_USER_MATCH_VALUE)
		return ERR_PTR(-KFI_EKEYREJECTED);

	mr = kzalloc(sizeof(*mr), GFP_NOWAIT);
	if (!mr)
		return ERR_PTR(-ENOMEM);

	mr->dom = dom;
	mr->md = md;
	mr->access = access;
	mr->state = MR_UNLINKED;
	mr->mr_fid.fid.fclass = KFI_CLASS_MR;
	mr->mr_fid.fid.context = context;
	mr->mr_fid.fid.ops = &kcxi_mr_fid_ops;
	mr->mr_fid.key = key;
	mr->req.context = mr;
	mr->req.cb = kcxi_mr_req_cb;
	mr->req.mr_link_cb = kcxi_mr_link_event;
	mr->req.mr_unlink_cb = kcxi_mr_unlink_event;
	mr->eq = dom->mr_eq;

	atomic_set(&mr->rma_event_count, 0);
	atomic_set(&mr->match_event_count, 0);

	atomic_inc(&dom->ref_cnt);

	return mr;
}

/**
 * kcxi_mr_regbv() - Allocate a kfabric MR using a bvec buffer
 * @fid: Kfabric domain fid
 * @biov: Bvec IOV
 * @count: Number of IOVs
 * @access: Kfabric access flags
 * @offset: Offset of buffer
 * @requested_key: Requested key for peers
 * @flags: MR reg flags
 * @mr: User MR pointer to be set on success
 * @context: User context
 *
 * Return: 0 on success. Else, negative kfabric errno.
 */
int kcxi_mr_regbv(struct kfid *fid, const struct bio_vec *biov, size_t count,
		  uint64_t access, uint64_t offset, uint64_t requested_key,
		  uint64_t flags, struct kfid_mr **mr, void *context)
{
	struct kcxi_domain *kcxi_dom;
	struct kcxi_mr *kcxi_mr;
	struct kcxi_md *md;
	uint32_t map_flags = 0;
	int rc;

	if (!mr) {
		rc = -EINVAL;
		goto err;
	}

	/*
	 * Don't support MR flags. In the future, when a MR can be bound to a
	 * completion queue, the need for KFI_RMA_EVENT may be needed.
	 */
	if (flags) {
		rc = -KFI_EBADFLAGS;
		goto err;
	}

	/*
	 * Since kCXI supports scalable memory registration, memory registration
	 * only needs to occur for remote access. This could be changed in the
	 * future is needed.
	 */
	if (!(access & (KFI_REMOTE_READ | KFI_REMOTE_WRITE))) {
		rc = -EINVAL;
		goto err;
	}

	kcxi_dom = container_of(fid, struct kcxi_domain, dom_fid.fid);

	/* Setup the CXI mapping flags */
	if (access & KFI_REMOTE_READ)
		map_flags |= CXI_MAP_READ;

	if (access & KFI_REMOTE_WRITE)
		map_flags |= CXI_MAP_WRITE;

	md = kcxi_md_biov_alloc(kcxi_dom->kcxi_if, NULL, biov, count, offset,
				map_flags);
	if (IS_ERR(md)) {
		rc = PTR_ERR(md);
		goto err;
	}

	kcxi_mr = kcxi_mr_alloc(kcxi_dom, md, access, requested_key, context);
	if (IS_ERR(kcxi_mr)) {
		rc = PTR_ERR(kcxi_mr);
		goto err_free_md;
	}

	LOG_DEBUG("MR allocated: key=%llx access=%llx length=%lu",
		  requested_key, access, md->len);

	*mr = &kcxi_mr->mr_fid;

	return 0;

err_free_md:
	kcxi_md_free(md);
err:
	*mr = NULL;
	return rc;
}

/**
 * kcxi_mr_regv() - Allocate a kfabric MR using a kvec buffer
 * @fid: Kfabric domain fid
 * @iov: Kvec IOV
 * @count: Number of IOVs
 * @access: Kfabric access flags
 * @offset: Offset of buffer
 * @requested_key: Requested key for peers
 * @flags: MR reg flags
 * @mr: User MR pointer to be set on success
 * @context: User context
 *
 * Return: 0 on success. Else, negative kfabric errno.
 */
int kcxi_mr_regv(struct kfid *fid, const struct kvec *iov, size_t count,
		 uint64_t access, uint64_t offset, uint64_t requested_key,
		 uint64_t flags, struct kfid_mr **mr, void *context)
{
	struct kcxi_domain *kcxi_dom;
	struct kcxi_mr *kcxi_mr;
	struct kcxi_md *md;
	uint32_t map_flags = 0;
	int rc;

	if (!mr) {
		rc = -EINVAL;
		goto err;
	}

	/*
	 * Don't support MR flags. In the future, when a MR can be bound to a
	 * completion queue, the need for KFI_RMA_EVENT may be needed.
	 */
	if (flags) {
		rc = -KFI_EBADFLAGS;
		goto err;
	}

	/*
	 * Since kCXI supports scalable memory registration, memory registration
	 * only needs to occur for remote access. This could be changed in the
	 * future is needed.
	 */
	if (!(access & (KFI_REMOTE_READ | KFI_REMOTE_WRITE))) {
		rc = -EINVAL;
		goto err;
	}

	kcxi_dom = container_of(fid, struct kcxi_domain, dom_fid.fid);

	/* Setup the CXI mapping flags */
	if (access & KFI_REMOTE_READ)
		map_flags |= CXI_MAP_READ;

	if (access & KFI_REMOTE_WRITE)
		map_flags |= CXI_MAP_WRITE;

	md = kcxi_md_iov_alloc(kcxi_dom->kcxi_if, NULL, iov, count, offset,
			       map_flags);
	if (IS_ERR(md)) {
		rc = PTR_ERR(md);
		goto err;
	}

	kcxi_mr = kcxi_mr_alloc(kcxi_dom, md, access, requested_key, context);
	if (IS_ERR(kcxi_mr)) {
		rc = PTR_ERR(kcxi_mr);
		goto err_free_md;
	}

	LOG_DEBUG("MR allocated: key=%llx access=%llx length=%lu",
		  requested_key, access, md->len);

	*mr = &kcxi_mr->mr_fid;

	return 0;

err_free_md:
	kcxi_md_free(md);
err:
	*mr = NULL;
	return rc;
}

/**
 * kcxi_mr_reg() - Allocate a kfabric MR
 * @fid: Kfabric domain fid
 * @buf: User buffer
 * @len: Length of buffer
 * @access: Kfabric access flags
 * @offset: Offset of buffer
 * @requested_key: Requested key for peers
 * @mr: User MR pointer to be set on success
 * @context: User context
 *
 * Return: 0 on success. Else, negative errno.
 */
int kcxi_mr_reg(struct kfid *fid, const void *buf, size_t len, uint64_t access,
		uint64_t offset, uint64_t requested_key, uint64_t flags,
		struct kfid_mr **mr, void *context)
{
	struct kcxi_domain *kcxi_dom;
	struct kcxi_mr *kcxi_mr;
	struct kcxi_md *md;
	uint32_t map_flags = 0;
	int rc;

	if (!mr) {
		rc = -EINVAL;
		goto err;
	}

	/*
	 * Don't support MR flags. In the future, when a MR can be bound to a
	 * completion queue, the need for KFI_RMA_EVENT may be needed.
	 */
	if (flags) {
		rc = -KFI_EBADFLAGS;
		goto err;
	}

	/*
	 * Since kCXI supports scalable memory registration, memory registration
	 * only needs to occur for remote access. This could be changed in the
	 * future is needed.
	 */
	if (!(access & (KFI_REMOTE_READ | KFI_REMOTE_WRITE))) {
		rc = -EINVAL;
		goto err;
	}

	kcxi_dom = container_of(fid, struct kcxi_domain, dom_fid.fid);

	/* Setup the CXI mapping flags */
	if (access & KFI_REMOTE_READ)
		map_flags |= CXI_MAP_READ;

	if (access & KFI_REMOTE_WRITE)
		map_flags |= CXI_MAP_WRITE;

	md = kcxi_md_alloc(kcxi_dom->kcxi_if, NULL, buf, len, offset, map_flags, false);
	if (IS_ERR(md)) {
		rc = PTR_ERR(md);
		goto err;
	}

	kcxi_mr = kcxi_mr_alloc(kcxi_dom, md, access, requested_key, context);
	if (IS_ERR(kcxi_mr)) {
		rc = PTR_ERR(kcxi_mr);
		goto err_free_md;
	}

	LOG_DEBUG("MR allocated: key=%llx access=%llx length=%lu",
		  requested_key, access, md->len);

	*mr = &kcxi_mr->mr_fid;

	return 0;

err_free_md:
	kcxi_md_free(md);
err:
	*mr = NULL;
	return rc;
}
