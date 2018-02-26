//SPDX-License-Identifier: GPL-2.0
/*
 * Cray kfabric CXI provider RX context implementation.
 * Copyright 2019-2024 Hewlett Packard Enterprise Development LP. All rights reserved.
 */
#include <linux/slab.h>
#include <linux/module.h>

#include "kcxi_prov.h"

static bool mr_events;
module_param(mr_events, bool, 0444);
MODULE_PARM_DESC(mr_events, "Enable MR events (Match, Put, and Get)");

static void kcxi_rx_ctx_reset_counters(struct kcxi_rx_ctx *rx_ctx)
{
	atomic64_set(&rx_ctx->command_queue_full, 0);
	atomic64_set(&rx_ctx->completion_queue_saturated, 0);
	if (rx_ctx->recv_cq)
		atomic_set(&rx_ctx->recv_cq->md_cache.md_cached_max, 0);
}

static int kcxi_rx_ctx_counters_file_show(struct seq_file *s, void *unused)
{
	struct kcxi_rx_ctx *rxc = s->private;

	seq_printf(s, "command_queue_full: %llu\n",
		   atomic64_read(&rxc->command_queue_full));
	seq_printf(s, "completion_queue_saturated: %llu\n",
		   atomic64_read(&rxc->completion_queue_saturated));
	if (rxc->recv_cq) {
		seq_printf(s, "md_cached_count: %d\n", atomic_read(&rxc->recv_cq->md_cache.md_cached_count));
		seq_printf(s, "md_cached_avail: %d\n", atomic_read(&rxc->recv_cq->md_cache.md_cached_avail));
		seq_printf(s, "md_cached_used: %d\n", atomic_read(&rxc->recv_cq->md_cache.md_cached_count) -
			atomic_read(&rxc->recv_cq->md_cache.md_cached_avail));
		seq_printf(s, "md_cached_max: %d\n", atomic_read(&rxc->recv_cq->md_cache.md_cached_max));
	}

	return 0;
}

static int kcxi_rx_ctx_counters_file_open(struct inode *inode,
					  struct file *file)
{
	return single_open(file, kcxi_rx_ctx_counters_file_show,
			   inode->i_private);
}

static const struct file_operations kcxi_rx_ctx_counters_file_ops = {
	.owner = THIS_MODULE,
	.open = kcxi_rx_ctx_counters_file_open,
	.read = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release,
};

static int kcxi_rx_ctx_reset_counters_set(void *data, u64 value)
{
	struct kcxi_rx_ctx *rxc = data;

	kcxi_rx_ctx_reset_counters(rxc);

	return 0;
}

static int kcxi_rx_ctx_reset_counters_get(void *data, u64 *value)
{
	/* Read is a noop. */
	*value = 0;

	return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(kcxi_rx_ctx_reset_counters_ops,
			kcxi_rx_ctx_reset_counters_get,
			kcxi_rx_ctx_reset_counters_set, "%llu\n");

/**
 * kcxi_rx_ctx_src_addr() - Derive the KFI source address from initiator bits.
 * @rx_ctx: Receive context.
 * @initiator: Initiator bits.
 *
 * Return: If the receive context was not allocated with KFI_SOURCE capability
 * or the KFI source address does not exist in the receive context address
 * vector, KFI_ADDR_NOTAVAIL is returned. Else, valid KFI source address.
 */
kfi_addr_t kcxi_rx_ctx_src_addr(struct kcxi_rx_ctx *rx_ctx, uint32_t initiator)
{
	uint32_t nic;
	uint16_t pid;
	uint32_t pid_bits;

	if (!rx_ctx || !(rx_ctx->attr.caps & KFI_SOURCE))
		return KFI_ADDR_NOTAVAIL;

	pid_bits = rx_ctx->ep_attr->dom_if->kcxi_if->dev->pid_bits;
	nic = CXI_MATCH_ID_EP(pid_bits, initiator);
	pid = CXI_MATCH_ID_PID(pid_bits, initiator);

	return kcxi_av_reverse_lookup(rx_ctx->ep_attr->av, nic, pid);
}

/**
 * kcxi_rx_ctx_unbind_mr() - Unbind an MR from an RX context
 *
 * Note: The rx_ctx field in the MR will be cleared.
 */
void kcxi_rx_ctx_unbind_mr(struct kcxi_rx_ctx *rx_ctx, struct kcxi_mr *mr)
{
	if (rx_ctx && mr && rx_ctx == mr->rx_ctx) {
		atomic_dec(&rx_ctx->ref_cnt);

		mr->rx_ctx = NULL;
	}
}

/**
 * kcxi_rx_ctx_bind_mr() - Bind an MR to an RX context
 * @rx_ctx: RX context
 * @mr: MR
 *
 * MRs can only be bound to an RX context if the following is true:
 * 1. MR access flags are KFI_REMOTE_READ and the KFI_RMA and KFI_REMOTE_READ
 * bits are set in the RX context's capability flags.
 * 2. MR access flags are KFI_REMOTE_WRITE and the KFI_RMA and KFI_REMOTE_WRITE
 * bits are set in the RX context's capability flags.
 *
 * Return: 0 on success and the rx_ctx field in the MR will be set. Else,
 * negative kfabric errno.
 */
int kcxi_rx_ctx_bind_mr(struct kcxi_rx_ctx *rx_ctx, struct kcxi_mr *mr)
{
	int rc;

	if (!rx_ctx || !mr)
		return -EINVAL;

	/* Taking a reference prevents RX context from being disabled. */
	atomic_inc(&rx_ctx->ref_cnt);

	if (!rx_ctx->enabled) {
		RXC_ERR(rx_ctx, "RX context not enabled");
		rc = -EINVAL;
		goto err;
	}

	if (!(rx_ctx->attr.caps & KFI_RMA)) {
		RXC_ERR(rx_ctx, "KFI_RMA flag not set for RX context");
		rc = -ENOSYS;
		goto err;
	}

	if ((mr->access & KFI_REMOTE_READ) &&
	    !(rx_ctx->attr.caps & KFI_REMOTE_READ)) {
		RXC_ERR(rx_ctx, "KFI_REMOTE_READ flag not set for RX context");
		rc = -ENOSYS;
		goto err;
	}

	if ((mr->access & KFI_REMOTE_WRITE) &&
	    !(rx_ctx->attr.caps & KFI_REMOTE_WRITE)) {
		RXC_ERR(rx_ctx, "KFI_REMOTE_WRITE flag not set for RX context");
		rc = -ENOSYS;
		goto err;
	}

	mr->rx_ctx = rx_ctx;

	return 0;

err:
	atomic_dec(&rx_ctx->ref_cnt);

	return rc;
}

static int kcxi_rx_ctx_close(struct kfid *fid)
{
	struct kcxi_rx_ctx *rx_ctx;
	struct kcxi_cq *cq;
	struct kcxi_rx_desc *cur;
	struct kcxi_rx_desc *next;
	int rc;

	rx_ctx = container_of(fid, struct kcxi_rx_ctx, ctx.fid);
	cq = rx_ctx->recv_cq;

	if (atomic_read(&rx_ctx->ref_cnt)) {
		kcxi_cmdq_ring(rx_ctx->target);
		return -EBUSY;
	}

	if (rx_ctx->enabled) {
		/* Can't close RX context is MRs still allocated. */
		rc = kcxi_mr_domain_free(rx_ctx->mr_domain);
		if (rc) {
			RXC_ERR(rx_ctx, "Failed to close MR domain: rc=%d", rc);
			return rc;
		}

		/* Disable PtlTE to prevent send operations from landing. */
		rc = kcxi_ptlte_disable(rx_ctx->ptlte, rx_ctx->target);
		if (rc)
			RXC_ERR(rx_ctx, "Failed to disable ptlte: rc=%d", rc);

		/* Cleanup resources for any posted RX operations. */
		list_for_each_entry_safe(cur, next, &rx_ctx->posted_rx_list,
					 entry) {
			list_del(&cur->entry);
			kcxi_cq_buffer_id_unmap(cq, cur->buffer_id);
			kcxi_md_free(cur->md);
			kfree(cur);
		}

		/* Leave the unlinking of LEs for freeing of PtlTE. */
		kcxi_ptlte_free(rx_ctx->ptlte);

		kcxi_cmdq_free(rx_ctx->target);
	}

	debugfs_remove_recursive(rx_ctx->rxc_debugfs_dir);

	RXC_DEBUG(rx_ctx, "RX context freed");

	kcxi_ep_release_rx_index(rx_ctx->ep_attr, rx_ctx->rx_id);

	if (rx_ctx->recv_cq)
		atomic_dec(&rx_ctx->recv_cq->ref_cnt);

	kfree(rx_ctx);

	return 0;
}

static int kcxi_rx_ctx_can_enable(struct kcxi_rx_ctx *rx_ctx)
{
	/* Nothing to enable if no MSG or TAGGED. */
	if (!(rx_ctx->attr.caps & (KFI_MSG | KFI_TAGGED | KFI_RMA)))
		return -EINVAL;

	if (!rx_ctx->ep_attr->av)
		return -KFI_ENOAV;

	if (!rx_ctx->recv_cq)
		return -KFI_ENOCQ;

	return 0;
}

static int kcxi_rx_ctx_enable(struct kcxi_rx_ctx *rx_ctx)
{
	struct cxi_pt_alloc_opts pte_opts = {};
	bool with_remote_rma_events = false;
	bool with_mr_events = mr_events;
	size_t mr_table_size = rx_ctx->ep_attr->domain->attr.mr_cnt;
	int rc;
	char rxc_debugfs_dir_name[16];

	mutex_lock(&rx_ctx->lock);

	if (rx_ctx->enabled) {
		mutex_unlock(&rx_ctx->lock);
		return 0;
	}

	rc = kcxi_rx_ctx_can_enable(rx_ctx);
	if (rc) {
		mutex_unlock(&rx_ctx->lock);
		return rc;
	}

	/* TODO: Handle rendezvous. */
	if (rx_ctx->ep_attr->attr.max_msg_size > eager_threshold)
		rx_ctx->rendezvous_enabled = true;

	/* KFI_MSG, KFI_TAGGED, KFI_RMA RX CTX needs target CMDQ and PtlTE. */
	rx_ctx->target =
		kcxi_cmdq_target_alloc(rx_ctx->ep_attr->dom_if->kcxi_if,
				       rx_ctx->attr.size,
				       cpu_to_node(rx_ctx->recv_cq->attr.signaling_vector));
	if (IS_ERR(rx_ctx->target)) {
		mutex_unlock(&rx_ctx->lock);
		return PTR_ERR(rx_ctx->target);
	}

	/* TODO: What should the size of CMDQ to be set to? */
	/* TODO: Verify pte_opts. */
	pte_opts.is_matching = 1;

	/* Remote RMA events utilize match events. */
	if (rx_ctx->attr.caps & KFI_RMA_EVENT) {
		with_remote_rma_events = true;
		with_mr_events = true;
	}

	if (with_mr_events)
		pte_opts.en_event_match = 1;

	rx_ctx->ptlte = kcxi_ptlte_alloc(rx_ctx->ep_attr->dom_if,
					 rx_ctx->recv_cq, rx_ctx->rx_id,
					 &pte_opts);
	if (IS_ERR(rx_ctx->ptlte)) {
		mutex_unlock(&rx_ctx->lock);
		rc = PTR_ERR(rx_ctx->ptlte);
		goto err_free_target;
	}

	rc = kcxi_ptlte_enable(rx_ctx->ptlte, rx_ctx->target);
	if (rc) {
		mutex_unlock(&rx_ctx->lock);
		goto err_free_ptlte;
	}

	/*
	 * Only allocate MR domain if RX context is to be target for RMA
	 * operations and either KFI_REMOTE_READ or KFI_REMOTE_WRITE is set.
	 */
	if ((rx_ctx->attr.caps & (KFI_RMA | KFI_REMOTE_READ)) ||
	     (rx_ctx->attr.caps & (KFI_RMA | KFI_REMOTE_WRITE))) {
		rx_ctx->mr_domain =
			kcxi_mr_domain_alloc(rx_ctx->recv_cq, rx_ctx->target,
					    rx_ctx->ptlte,
					    with_remote_rma_events,
					    with_mr_events, mr_table_size);
		if (IS_ERR(rx_ctx->mr_domain)) {
			mutex_unlock(&rx_ctx->lock);
			rc = PTR_ERR(rx_ctx->mr_domain);
			RXC_ERR(rx_ctx, "Failed to allocated MR domain: rc=%d",
				rc);
			goto err_free_ptlte;
		}
	}

	rc = snprintf(rxc_debugfs_dir_name, sizeof(rxc_debugfs_dir_name),
		      "rxc%u", rx_ctx->rx_id);
	if (rc >= sizeof(rxc_debugfs_dir_name)) {
		rc = -ENOMEM;
		goto err_free_mr_domain;
	} else if (rc < 0) {
		goto err_free_mr_domain;
	}

	rx_ctx->rxc_debugfs_dir =
		debugfs_create_dir(rxc_debugfs_dir_name,
				   rx_ctx->ep_attr->dom_if->dom_if_debugfs_dir);
	debugfs_create_file("counters", 0444, rx_ctx->rxc_debugfs_dir, rx_ctx,
			    &kcxi_rx_ctx_counters_file_ops);
	debugfs_create_file("reset_counters", 0200, rx_ctx->rxc_debugfs_dir,
			    rx_ctx, &kcxi_rx_ctx_reset_counters_ops);

	rx_ctx->enabled = true;

	mutex_unlock(&rx_ctx->lock);

	RXC_DEBUG(rx_ctx, "RX context enabled");

	return 0;

err_free_mr_domain:
	kcxi_mr_domain_free(rx_ctx->mr_domain);
err_free_ptlte:
	kcxi_ptlte_free(rx_ctx->ptlte);
err_free_target:
	kcxi_cmdq_free(rx_ctx->target);

	return rc;
}

static int kcxi_rx_ctx_setopt(struct kfid *fid, int level, int optname,
			      const void *optval, size_t optlen)
{
	struct kcxi_rx_ctx *rx_ctx;
	size_t min_multi_recv;
	size_t multi_recv_limit;
	unsigned int shift;

	if (!optval)
		return -EINVAL;

	if (optname != KFI_OPT_MIN_MULTI_RECV || level != KFI_OPT_ENDPOINT)
		return -ENOPROTOOPT;

	if (optlen < sizeof(size_t))
		return -KFI_ETOOSMALL;

	rx_ctx = container_of(fid, struct kcxi_rx_ctx, ctx.fid);
	multi_recv_limit =
		rx_ctx->ep_attr->dom_if->kcxi_if->dev->multi_recv_limit;
	shift = rx_ctx->ep_attr->dom_if->kcxi_if->dev->multi_recv_shift;

	min_multi_recv = *(size_t *)optval;
	if (min_multi_recv > multi_recv_limit)
		return -E2BIG;

	/* Need to shift min_multi_recv so it can be used with min_free. */
	rx_ctx->min_multi_recv = min_multi_recv >> shift;

	/* True min multi recv value may differ depending of shift. */
	if (min_multi_recv & ((1 << shift) - 1))
		RXC_WARN(rx_ctx, "Min multi-recv set to %lu instead of %lu",
			 rx_ctx->min_multi_recv << shift, min_multi_recv);

	return 0;
}

static int kcxi_rx_ctx_getopt(struct kfid *fid, int level, int optname,
			     void *optval, size_t *optlen)
{
	struct kcxi_rx_ctx *rx_ctx;
	unsigned int shift;

	if (!optval || !optlen)
		return -EINVAL;

	if (optname != KFI_OPT_MIN_MULTI_RECV || level != KFI_OPT_ENDPOINT)
		return -ENOPROTOOPT;

	if (*optlen < sizeof(size_t))
		return -KFI_ETOOSMALL;

	rx_ctx = container_of(fid, struct kcxi_rx_ctx, ctx.fid);
	shift = rx_ctx->ep_attr->dom_if->kcxi_if->dev->multi_recv_shift;

	*(size_t *)optval = rx_ctx->min_multi_recv << shift;
	*optlen = sizeof(size_t);

	return 0;
}

static int kcxi_rx_ctx_get_op_flags(struct kcxi_rx_ctx *rx_ctx, uint64_t *flags)
{
	if (!flags) {
		RXC_ERR(rx_ctx, "NULL flags pointer");
		return -EINVAL;
	}

	if ((*flags & KFI_TRANSMIT) && (*flags & KFI_RECV)) {
		RXC_ERR(rx_ctx, "KFI_TRANSMIT and KFI_RECV flags both set");
		return -EINVAL;
	}

	if (!(*flags & KFI_RECV)) {
		RXC_ERR(rx_ctx, "KFI_RECV flag not set");
		return -EINVAL;
	}

	*flags = rx_ctx->attr.op_flags;

	return 0;
}

static int kcxi_rx_ctx_set_op_flags(struct kcxi_rx_ctx *rx_ctx, uint64_t *flags)
{
	uint64_t new_flags;
	uint64_t invalid_flags;

	if (!flags) {
		RXC_ERR(rx_ctx, "NULL flags pointer");
		return -EINVAL;
	}

	if ((*flags & KFI_TRANSMIT) && (*flags & KFI_RECV)) {
		RXC_ERR(rx_ctx, "KFI_TRANSMIT and KFI_RECV flags both set");
		return -EINVAL;
	}

	if (!(*flags & KFI_RECV)) {
		RXC_ERR(rx_ctx, "KFI_RECV flag not set");
		return -EINVAL;
	}

	new_flags = (*flags & ~KFI_RECV);
	invalid_flags = (new_flags & ~KCXI_RX_OP_FLAGS);
	if (invalid_flags) {
		RXC_ERR(rx_ctx, "Invalid RX op flags: flags=%llx",
			invalid_flags);
		return -EINVAL;
	}

	rx_ctx->attr.op_flags = new_flags;

	RXC_DEBUG(rx_ctx, "Operation flags set: flags=%llx", new_flags);

	return 0;
}

static int kcxi_rx_ctx_control(struct kfid *fid, int command, void *arg)
{
	struct kcxi_rx_ctx *rx_ctx = container_of(fid, struct kcxi_rx_ctx,
						 ctx.fid);

	switch (command) {
	case KFI_ENABLE:
		return kcxi_rx_ctx_enable(rx_ctx);

	case KFI_GETOPSFLAG:
		return kcxi_rx_ctx_get_op_flags(rx_ctx, arg);

	case KFI_SETOPSFLAG:
		return kcxi_rx_ctx_set_op_flags(rx_ctx, arg);

	default:
		RXC_ERR(rx_ctx, "Invalid control command: command=%d", command);
		return -EINVAL;
	}
}

static int kcxi_rx_ctx_bind(struct kfid *fid, struct kfid *bfid, uint64_t flags)
{
	struct kcxi_cq *cq;
	struct kcxi_rx_ctx *rx_ctx;

	if (!bfid)
		return -EINVAL;

	/* Only allow CQs to be bound to RX context. */
	if (bfid->fclass != KFI_CLASS_CQ)
		return -ENOSYS;

	if (flags & ~KCXI_EP_CQ_BIND_FLAGS)
		return -EINVAL;

	rx_ctx = container_of(fid, struct kcxi_rx_ctx, ctx.fid);
	cq = container_of(bfid, struct kcxi_cq, cq_fid.fid);

	if (cq->domain != rx_ctx->ep_attr->domain)
		return -EINVAL;

	/* Serialize access to recv_cq. */
	mutex_lock(&rx_ctx->lock);

	if (rx_ctx->recv_cq) {
		mutex_unlock(&rx_ctx->lock);
		return -EINVAL;
	}

	/*
	 * Bind CQ to RX if:
	 * 1. The KFI_RECV flag is specified
	 * OR
	 * 2. Neither KFI_TRANSMIT and KFI_RECV are specified
	 */
	if ((flags & KFI_RECV) || !(flags & (KFI_TRANSMIT | KFI_RECV))) {
		rx_ctx->recv_cq = cq;
		if (flags & KFI_SELECTIVE_COMPLETION)
			rx_ctx->suppress_events = true;
		atomic_inc(&cq->ref_cnt);
	}

	mutex_unlock(&rx_ctx->lock);

	RXC_DEBUG(rx_ctx, "CQ successfully bound");

	return 0;
}

/**
 * kcxi_rx_ctx_cancel() - Cancel an RX operation
 * @fid: The RX context fid
 * @context: Context for operation to be canceled.
 *
 * Note: The context is used for find the operation to be cancel. If multiple
 * RX operations exist with the same context, the first RX operation will be
 * canceled.
 *
 * Return: 0 if the cancel command was successfully submitted. -ENOENT if no RX
 * operation was found. Else, negative errno.
 */
static ssize_t kcxi_rx_ctx_cancel(struct kfid *fid, void *context)
{
	struct kcxi_rx_ctx *rx_ctx;
	struct kcxi_cq *cq;
	struct kcxi_rx_desc *rx_desc;
	struct kcxi_rx_desc *next;
	bool found = false;
	struct c_target_cmd cmd = {};
	int rc;

	rx_ctx = container_of(fid, struct kcxi_rx_ctx, ctx.fid);
	cq = rx_ctx->recv_cq;

	spin_lock(&rx_ctx->post_rx_lock);
	list_for_each_entry_safe(rx_desc, next, &rx_ctx->posted_rx_list,
				 entry) {
		if (rx_desc->req.context == context && !rx_desc->canceled) {
			found = true;
			break;
		}
	}

	if (!found) {
		spin_unlock(&rx_ctx->post_rx_lock);
		return -ENOENT;
	}

	rx_desc->canceled = true;

	/* RX desc will be cleaned up by the EVENT_UNLINK handler. */
	cmd.command.opcode = C_CMD_TGT_UNLINK;
	cmd.ptl_list = C_PTL_LIST_PRIORITY;
	cmd.ptlte_index = KCXI_PTLTE_INDEX(rx_ctx->ptlte);
	cmd.buffer_id = rx_desc->buffer_id;

	rc = kcxi_cmdq_emit_target(rx_ctx->target, &cmd);
	if (rc)
		rx_desc->canceled = false;

	spin_unlock(&rx_ctx->post_rx_lock);

	kcxi_cmdq_ring(rx_ctx->target);

	if (rc) {
		RXC_DEBUG(rx_ctx, "Unable to emit unlink cmd: rc=%d", rc);
		return -EAGAIN;
	}

	RXC_DEBUG(rx_ctx, "Unlink cmd emitted: context=%pK", context);

	return 0;
}

static struct kfi_ops kcxi_rx_ctx_fid_ops = {
	.close = kcxi_rx_ctx_close,
	.bind = kcxi_rx_ctx_bind,
	.control = kcxi_rx_ctx_control,
	.ops_open = kfi_no_ops_open
};

static struct kfi_ops_ep kcxi_rx_ctx_ep_ops = {
	.cancel = kcxi_rx_ctx_cancel,
	.getopt = kcxi_rx_ctx_getopt,
	.setopt = kcxi_rx_ctx_setopt,
	.tx_ctx = kfi_no_tx_ctx,
	.rx_ctx = kfi_no_rx_ctx
};

static struct kfi_ops_cm kcxi_rx_ctx_cm_ops = {
	.setname = kfi_no_setname,
	.getname = kfi_no_getname,
	.getpeer = kfi_no_getpeer,
	.connect = kfi_no_connect,
	.listen = kfi_no_listen,
	.accept = kfi_no_accept,
	.reject = kfi_no_reject,
	.shutdown = kfi_no_shutdown,
	.join = kfi_no_join
};

static struct kfi_ops_msg kcxi_rx_ctx_msg_ops = {
	.recv = kcxi_msg_recv,
	.recvv = kcxi_msg_recvv,
	.recvbv = kcxi_msg_recvbv,
	.recvmsg = kcxi_msg_recvmsg,
	.send = kfi_no_msg_send,
	.sendv = kfi_no_msg_sendv,
	.sendmsg = kfi_no_msg_sendmsg,
	.inject = kfi_no_msg_inject,
	.senddata = kfi_no_msg_senddata,
	.injectdata = kfi_no_msg_injectdata
};

static struct kfi_ops_rma kcxi_rx_ctx_rma_ops = {
	.read = kfi_no_rma_read,
	.readv = kfi_no_rma_readv,
	.readmsg = kfi_no_rma_readmsg,
	.write = kfi_no_rma_write,
	.writev = kfi_no_rma_writev,
	.writemsg = kfi_no_rma_writemsg,
	.inject = kfi_no_rma_inject,
	.writedata = kfi_no_rma_writedata,
	.injectdata = kfi_no_rma_injectdata
};

static struct kfi_ops_tagged kcxi_rx_ctx_tagged_ops = {
	.recv = kcxi_tagged_recv,
	.recvv = kcxi_tagged_recvv,
	.recvbv = kcxi_tagged_recvbv,
	.recvmsg = kcxi_tagged_recvmsg,
	.send = kfi_no_tagged_send,
	.sendv = kfi_no_tagged_sendv,
	.sendbv = kfi_no_tagged_sendbv,
	.sendmsg = kfi_no_tagged_sendmsg,
	.inject = kfi_no_tagged_inject,
	.senddata = kfi_no_tagged_senddata,
	.injectdata = kfi_no_tagged_injectdata
};

static struct kfi_ops_atomic kcxi_rx_ctx_atomic_ops = {
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
 * kcxi_rx_ctx_alloc() - Allocate a RX context
 * @attr: RX attributes
 * @index: Index the RX context should be associated with in RX array
 * @ep_attr: EP attributes to be associated with RX context
 * @context: User context
 *
 * Return: Valid pointer on success. Else, NULL.
 */
struct kcxi_rx_ctx *kcxi_rx_ctx_alloc(const struct kfi_rx_attr *attr,
				      unsigned int index,
				      struct kcxi_ep_attr *ep_attr,
				      void *context)
{
	struct kcxi_rx_ctx *rx_ctx;

	rx_ctx = kzalloc(sizeof(*rx_ctx), GFP_KERNEL);
	if (!rx_ctx)
		return NULL;

	mutex_init(&rx_ctx->lock);
	INIT_LIST_HEAD(&rx_ctx->posted_rx_list);
	spin_lock_init(&rx_ctx->post_rx_lock);
	atomic_set(&rx_ctx->posted_rx_cnt, 0);
	atomic_set(&rx_ctx->ref_cnt, 0);

	rx_ctx->ctx.fid.fclass = KFI_CLASS_RX_CTX;
	rx_ctx->ctx.fid.context = context;
	rx_ctx->ctx.fid.ops = &kcxi_rx_ctx_fid_ops;
	rx_ctx->ctx.ops = &kcxi_rx_ctx_ep_ops;
	rx_ctx->ctx.cm = &kcxi_rx_ctx_cm_ops;
	rx_ctx->ctx.msg = &kcxi_rx_ctx_msg_ops;
	rx_ctx->ctx.rma = &kcxi_rx_ctx_rma_ops;
	rx_ctx->ctx.tagged = &kcxi_rx_ctx_tagged_ops;
	rx_ctx->ctx.atomic = &kcxi_rx_ctx_atomic_ops;
	rx_ctx->num_left = attr->size;
	rx_ctx->min_multi_recv = KCXI_EP_DEF_MIN_MULTI_RECV;
	rx_ctx->attr = *attr;
	rx_ctx->rx_id = index;
	rx_ctx->ep_attr = ep_attr;
	rx_ctx->directed_recv = !!(attr->caps & KFI_DIRECTED_RECV);

	kcxi_rx_ctx_reset_counters(rx_ctx);

	RXC_DEBUG(rx_ctx, "RX context allocated: auth_key=%u",
		 rx_ctx->ep_attr->dom_if->auth_key);

	return rx_ctx;
}
