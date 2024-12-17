//SPDX-License-Identifier: GPL-2.0
/*
 * Cray kfabric CXI provider TX context implementation.
 * Copyright 2019-2024 Hewlett Packard Enterprise Development LP
 */
#include <linux/slab.h>

#include "kcxi_prov.h"

static void kcxi_tx_ctx_reset_counters(struct kcxi_tx_ctx *tx_ctx)
{
	atomic64_set(&tx_ctx->command_queue_full, 0);
	atomic64_set(&tx_ctx->completion_queue_saturated, 0);
	atomic64_set(&tx_ctx->rnr_retries, 0);
	atomic64_set(&tx_ctx->rnr_retries_send, 0);
	atomic64_set(&tx_ctx->rnr_retries_rma, 0);
	if (tx_ctx->send_cq)
		atomic_set(&tx_ctx->send_cq->md_cache.md_cached_max, 0);
}

static int kcxi_tx_ctx_counters_file_show(struct seq_file *s, void *unused)
{
	struct kcxi_tx_ctx *txc = s->private;

	seq_printf(s, "command_queue_full: %llu\n",
		   atomic64_read(&txc->command_queue_full));
	seq_printf(s, "completion_queue_saturated: %llu\n",
		   atomic64_read(&txc->completion_queue_saturated));
	seq_printf(s, "rnr_retries: %llu\n", atomic64_read(&txc->rnr_retries));
	seq_printf(s, "rnr_retries_send: %llu\n", atomic64_read(&txc->rnr_retries_send));
	seq_printf(s, "rnr_retries_rma: %llu\n", atomic64_read(&txc->rnr_retries_rma));
	if (txc->send_cq) {
		seq_printf(s, "md_cached_count: %d\n", atomic_read(&txc->send_cq->md_cache.md_cached_count));
		seq_printf(s, "md_cached_avail: %d\n", atomic_read(&txc->send_cq->md_cache.md_cached_avail));
		seq_printf(s, "md_cached_used: %d\n", atomic_read(&txc->send_cq->md_cache.md_cached_count) -
			atomic_read(&txc->send_cq->md_cache.md_cached_avail));
		seq_printf(s, "md_cached_max: %d\n", atomic_read(&txc->send_cq->md_cache.md_cached_max));
	}

	return 0;
}

static int kcxi_tx_ctx_counters_file_open(struct inode *inode,
					  struct file *file)
{
	return single_open(file, kcxi_tx_ctx_counters_file_show,
			   inode->i_private);
}

static const struct file_operations kcxi_tx_ctx_counters_file_ops = {
	.owner = THIS_MODULE,
	.open = kcxi_tx_ctx_counters_file_open,
	.read = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release,
};

static int kcxi_tx_ctx_reset_counters_set(void *data, u64 value)
{
	struct kcxi_tx_ctx *txc = data;

	kcxi_tx_ctx_reset_counters(txc);

	return 0;
}

static int kcxi_tx_ctx_reset_counters_get(void *data, u64 *value)
{
	/* Read is a noop. */
	*value = 0;

	return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(kcxi_tx_ctx_reset_counters_ops,
			kcxi_tx_ctx_reset_counters_get,
			kcxi_tx_ctx_reset_counters_set, "%llu\n");


static int kcxi_tx_ctx_close(struct kfid *fid)
{
	struct kcxi_tx_ctx *tx_ctx = container_of(fid, struct kcxi_tx_ctx,
						  ctx.fid);

	/*
	 * Cannot close TX context if there are still posted TX operations. The
	 * HW event for the TX operation MUST be processed in order to not have
	 * resources leaked. It is the responsibility of operation callbacks to
	 * decrement the posted_tx_cnt when a TX desc is freed.
	 */
	if (atomic_read(&tx_ctx->posted_tx_cnt)) {
		kcxi_cmdq_ring(tx_ctx->transmit);
		return -EBUSY;
	}

	kcxi_cmdq_free(tx_ctx->transmit);

	debugfs_remove_recursive(tx_ctx->txc_debugfs_dir);

	TXC_DEBUG(tx_ctx, "TX context freed");

	kcxi_ep_release_tx_index(tx_ctx->ep_attr, tx_ctx->tx_id);

	if (tx_ctx->send_cq)
		atomic_dec(&tx_ctx->send_cq->ref_cnt);

	kfree(tx_ctx);

	return 0;
}

static int kcxi_tx_ctx_can_enable(struct kcxi_tx_ctx *tx_ctx)
{
	/* Nothing to enable if no MSG, TAGGED, or RMA. */
	if (!(tx_ctx->attr.caps & (KFI_MSG | KFI_TAGGED | KFI_RMA)))
		return -EINVAL;

	if (!tx_ctx->ep_attr->av)
		return -KFI_ENOAV;

	if (!tx_ctx->send_cq)
		return -KFI_ENOCQ;

	if (atomic_read(&tx_ctx->posted_tx_cnt))
		return -EBUSY;

	return 0;
}

static enum cxi_traffic_class kfi_tc_to_cxi_tc(uint32_t tclass)
{
	switch (tclass) {
		case KFI_TC_LOW_LATENCY:
			return CXI_TC_LOW_LATENCY;
		case KFI_TC_DEDICATED_ACCESS:
			return CXI_TC_DEDICATED_ACCESS;
		case KFI_TC_BULK_DATA:
			return CXI_TC_BULK_DATA;
		case KFI_TC_SCAVENGER:
		case KFI_TC_NETWORK_CTRL:
			/*
			 * scavenger and network control are not supported by cassini
			 * use best effort instead
			 */
		case KFI_TC_BEST_EFFORT:
		default:
			return CXI_TC_BEST_EFFORT;
	}
}

static int kcxi_tx_ctx_enable(struct kcxi_tx_ctx *tx_ctx)
{
	int rc;
	char txc_debugfs_dir_name[16];

	mutex_lock(&tx_ctx->lock);

	if (tx_ctx->enabled) {
		mutex_unlock(&tx_ctx->lock);
		return 0;
	}

	rc = kcxi_tx_ctx_can_enable(tx_ctx);
	if (rc) {
		mutex_unlock(&tx_ctx->lock);
		return rc;
	}

	if (tx_ctx->attr.caps & (KFI_MSG | KFI_TAGGED) &&
	    tx_ctx->ep_attr->attr.max_msg_size > eager_threshold)
		tx_ctx->rendezvous_enabled = true;

	tx_ctx->transmit =
		kcxi_cmdq_transmit_alloc(tx_ctx->ep_attr->dom_if->kcxi_if,
					 tx_ctx->attr.size,
					 tx_ctx->ep_attr->auth_key,
					 kfi_tc_to_cxi_tc(tx_ctx->attr.tclass),
					 cpu_to_node(tx_ctx->send_cq->attr.signaling_vector));
	if (IS_ERR(tx_ctx->transmit)) {
		mutex_unlock(&tx_ctx->lock);
		return PTR_ERR(tx_ctx->transmit);
	}

	/* TODO: Handle rendezvous. */

	rc = snprintf(txc_debugfs_dir_name, sizeof(txc_debugfs_dir_name),
		      "txc%u", tx_ctx->tx_id);
	if (rc >= sizeof(txc_debugfs_dir_name)) {
		rc = -ENOMEM;
		goto err_free_cmdq;
	} else if (rc < 0) {
		goto err_free_cmdq;
	}

	tx_ctx->txc_debugfs_dir =
		debugfs_create_dir(txc_debugfs_dir_name,
				   tx_ctx->ep_attr->dom_if->dom_if_debugfs_dir);
	debugfs_create_file("counters", 0444, tx_ctx->txc_debugfs_dir, tx_ctx,
			    &kcxi_tx_ctx_counters_file_ops);
	debugfs_create_file("reset_counters", 0200, tx_ctx->txc_debugfs_dir,
			    tx_ctx, &kcxi_tx_ctx_reset_counters_ops);

	tx_ctx->enabled = true;

	mutex_unlock(&tx_ctx->lock);

	TXC_DEBUG(tx_ctx, "TX context enabled");

	return 0;

err_free_cmdq:
	kcxi_cmdq_free(tx_ctx->transmit);

	return rc;
}

static int kcxi_tx_ctx_get_op_flags(struct kcxi_tx_ctx *tx_ctx, uint64_t *flags)
{
	if (!flags) {
		TXC_ERR(tx_ctx, "NULL flags pointer");
		return -EINVAL;
	}

	if ((*flags & KFI_TRANSMIT) && (*flags & KFI_RECV)) {
		TXC_ERR(tx_ctx, "KFI_TRANSMIT and KFI_RECV flags both set");
		return -EINVAL;
	}

	if (!(*flags & KFI_TRANSMIT)) {
		TXC_ERR(tx_ctx, "KFI_TRANSMIT flag not set");
		return -EINVAL;
	}

	*flags = tx_ctx->attr.op_flags;

	return 0;
}

static int kcxi_tx_ctx_set_op_flags(struct kcxi_tx_ctx *tx_ctx, uint64_t *flags)
{
	uint64_t new_flags;
	uint64_t invalid_flags;

	if (!flags) {
		TXC_ERR(tx_ctx, "NULL flags pointer");
		return -EINVAL;
	}

	if ((*flags & KFI_TRANSMIT) && (*flags & KFI_RECV)) {
		TXC_ERR(tx_ctx, "KFI_TRANSMIT and KFI_RECV flags both set");
		return -EINVAL;
	}

	if (!(*flags & KFI_TRANSMIT)) {
		TXC_ERR(tx_ctx, "KFI_TRANSMIT flag not set");
		return -EINVAL;
	}

	new_flags = (*flags & ~KFI_TRANSMIT);
	invalid_flags = (new_flags & ~KCXI_TX_OP_FLAGS);
	if (invalid_flags) {
		TXC_ERR(tx_ctx, "Invalid TX op flags: flags=%llx",
			invalid_flags);
		return -EINVAL;
	}

	tx_ctx->attr.op_flags = new_flags;

	TXC_DEBUG(tx_ctx, "Operation flags set: flags=%llx", new_flags);

	return 0;
}

static int kcxi_tx_ctx_control(struct kfid *fid, int command, void *arg)
{
	struct kcxi_tx_ctx *tx_ctx = container_of(fid, struct kcxi_tx_ctx,
						 ctx.fid);

	switch (command) {
	case KFI_ENABLE:
		return kcxi_tx_ctx_enable(tx_ctx);

	case KFI_GETOPSFLAG:
		return kcxi_tx_ctx_get_op_flags(tx_ctx, arg);

	case KFI_SETOPSFLAG:
		return kcxi_tx_ctx_set_op_flags(tx_ctx, arg);

	default:
		TXC_ERR(tx_ctx, "Invalid control command: command=%d", command);
		return -EINVAL;
	}
}

static int kcxi_tx_ctx_bind(struct kfid *fid, struct kfid *bfid, uint64_t flags)
{
	struct kcxi_cq *cq;
	struct kcxi_tx_ctx *tx_ctx;

	if (!bfid)
		return -EINVAL;

	/* Only allow CQs to be bound to TX context. */
	if (bfid->fclass != KFI_CLASS_CQ)
		return -ENOSYS;

	if (flags & ~KCXI_EP_CQ_BIND_FLAGS)
		return -EINVAL;

	tx_ctx = container_of(fid, struct kcxi_tx_ctx, ctx.fid);
	cq = container_of(bfid, struct kcxi_cq, cq_fid.fid);

	if (cq->domain != tx_ctx->ep_attr->domain)
		return -EINVAL;

	/* Serialize access to send_cq. */
	mutex_lock(&tx_ctx->lock);

	if (tx_ctx->send_cq) {
		mutex_unlock(&tx_ctx->lock);
		return -EINVAL;
	}

	/*
	 * Bind CQ to TX if:
	 * 1. The KFI_TRANSMIT flag is specified
	 * OR
	 * 2. Neither KFI_TRANSMIT and KFI_RECV are specified
	 */
	if ((flags & KFI_TRANSMIT) || !(flags & (KFI_TRANSMIT | KFI_RECV))) {
		tx_ctx->send_cq = cq;
		if (flags & KFI_SELECTIVE_COMPLETION)
			tx_ctx->suppress_events = true;
		atomic_inc(&cq->ref_cnt);
	}

	mutex_unlock(&tx_ctx->lock);

	TXC_DEBUG(tx_ctx, "CQ successfully bound");

	return 0;
}

static struct kfi_ops kcxi_tx_ctx_fid_ops = {
	.close = kcxi_tx_ctx_close,
	.bind = kcxi_tx_ctx_bind,
	.control = kcxi_tx_ctx_control,
	.ops_open = kfi_no_ops_open
};

static struct kfi_ops_ep kcxi_tx_ctx_ep_ops = {
	.cancel = kfi_no_cancel,
	.getopt = kfi_no_getopt,
	.setopt = kfi_no_setopt,
	.tx_ctx = kfi_no_tx_ctx,
	.rx_ctx = kfi_no_rx_ctx
};

static struct kfi_ops_cm kcxi_tx_ctx_cm_ops = {
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

static struct kfi_ops_msg kcxi_tx_ctx_msg_ops = {
	.recv = kfi_no_msg_recv,
	.recvv = kfi_no_msg_recvv,
	.recvbv = kfi_no_msg_recvbv,
	.recvsgl = kfi_no_msg_recvsgl,
	.recvmsg = kfi_no_msg_recvmsg,
	.send = kcxi_msg_send,
	.sendv = kcxi_msg_sendv,
	.sendbv = kcxi_msg_sendbv,
	.sendsgl = kcxi_msg_sendsgl,
	.sendmsg = kcxi_msg_sendmsg,
	.inject = kfi_no_msg_inject,
	.senddata = kfi_no_msg_senddata,
	.injectdata = kfi_no_msg_injectdata
};

static struct kfi_ops_rma kcxi_tx_ctx_rma_ops = {
	.read = kcxi_rma_read,
	.readv = kcxi_rma_readv,
	.readbv = kcxi_rma_readbv,
	.readsgl = kcxi_rma_readsgl,
	.readmsg = kcxi_rma_readmsg,
	.write = kcxi_rma_write,
	.writev = kcxi_rma_writev,
	.writebv = kcxi_rma_writebv,
	.writesgl = kcxi_rma_writesgl,
	.writemsg = kcxi_rma_writemsg,
	.inject = kfi_no_rma_inject,
	.writedata = kfi_no_rma_writedata,
	.injectdata = kfi_no_rma_injectdata
};

static struct kfi_ops_tagged kcxi_tx_ctx_tagged_ops = {
	.recv = kfi_no_tagged_recv,
	.recvv = kfi_no_tagged_recvv,
	.recvbv = kfi_no_tagged_recvbv,
	.recvsgl = kfi_no_tagged_recvsgl,
	.recvmsg = kfi_no_tagged_recvmsg,
	.send = kcxi_tagged_send,
	.sendv = kcxi_tagged_sendv,
	.sendbv = kcxi_tagged_sendbv,
	.sendsgl = kcxi_tagged_sendsgl,
	.sendmsg = kcxi_tagged_sendmsg,
	.inject = kfi_no_tagged_inject,
	.senddata = kcxi_tagged_senddata,
	.injectdata = kfi_no_tagged_injectdata
};

static struct kfi_ops_atomic kcxi_tx_ctx_atomic_ops = {
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
 * kcxi_tx_ctx_alloc() - Allocate a TX context
 * @attr: TX attributes
 * @index: Index the TX context should be associated with in TX array
 * @ep_attr: EP attributes to be associated with TX context
 * @context: User context
 *
 * Return: Valid pointer on success. Else, NULL.
 */
struct kcxi_tx_ctx *kcxi_tx_ctx_alloc(const struct kfi_tx_attr *attr,
				      unsigned int index,
				      struct kcxi_ep_attr *ep_attr,
				      void *context)
{
	struct kcxi_tx_ctx *tx_ctx;

	tx_ctx = kzalloc(sizeof(*tx_ctx), GFP_KERNEL);
	if (!tx_ctx)
		return NULL;

	mutex_init(&tx_ctx->lock);
	atomic_set(&tx_ctx->posted_tx_cnt, 0);

	tx_ctx->ctx.fid.fclass = KFI_CLASS_TX_CTX;
	tx_ctx->ctx.fid.context = context;
	tx_ctx->ctx.fid.ops = &kcxi_tx_ctx_fid_ops;
	tx_ctx->ctx.ops = &kcxi_tx_ctx_ep_ops;
	tx_ctx->ctx.cm = &kcxi_tx_ctx_cm_ops;
	tx_ctx->ctx.msg = &kcxi_tx_ctx_msg_ops;
	tx_ctx->ctx.rma = &kcxi_tx_ctx_rma_ops;
	tx_ctx->ctx.tagged = &kcxi_tx_ctx_tagged_ops;
	tx_ctx->ctx.atomic = &kcxi_tx_ctx_atomic_ops;
	tx_ctx->attr = *attr;
	tx_ctx->attr.op_flags |= KFI_TRANSMIT_COMPLETE;
	tx_ctx->tx_id = index;
	tx_ctx->ep_attr = ep_attr;

	if (tx_ctx->attr.tclass == KFI_TC_UNSPEC)
		tx_ctx->attr.tclass = ep_attr->domain->attr.tclass;

	kcxi_tx_ctx_reset_counters(tx_ctx);

	TXC_DEBUG(tx_ctx, "TX context allocated: auth_key=%u tclass=%d",
		  tx_ctx->ep_attr->dom_if->auth_key, tx_ctx->attr.tclass);

	return tx_ctx;
}
