//SPDX-License-Identifier: GPL-2.0
/*
 * Cray kfabric CXI provider memory region domain.
 * Copyright 2019-2021 Hewlett Packard Enterprise Development LP. All rights reserved.
 */
#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/sched.h>

#include "kcxi_prov.h"

static DECLARE_WAIT_QUEUE_HEAD(mr_wait_queue);

static bool is_invalidation_required(const struct kcxi_mr_domain *mr_domain)
{
	return !mr_domain->with_mr_events;
}

static bool is_mr_unlinked(const struct kcxi_mr_domain *mr_domain,
			   const struct kcxi_mr *mr)
{
	if (is_invalidation_required(mr_domain))
		return mr->state != MR_LINKED;

	return (mr->state != MR_LINKED &&
		(atomic_read(&mr->match_event_count) ==
		 atomic_read(&mr->rma_event_count)));
}

/**
 * kcxi_mr_domain_wake_up() - Wake threads waiting for an MR state change.
 */
void kcxi_mr_domain_wake_up(void)
{
	wake_up(&mr_wait_queue);
}

/**
 * kcxi_mr_domain_unlink() - Unlink an MR from an MR domain.
 * @mr_domain: The MR domain.
 * @mr: The MR.
 *
 * Note: Function may sleep. kcxi_mr_domain_wake_up() should be called when the
 * unlink event occurs.
 *
 * Return: 0 on success. Else, negative errno.
 */
int kcxi_mr_domain_unlink(struct kcxi_mr_domain *mr_domain, struct kcxi_mr *mr)
{
	int rc;
	struct c_target_cmd cmd = {};

	if (mr->state != MR_LINKED) {
		MR_DOM_ERR(mr_domain,
			   "MR state not set to linked: state=%d key=%llx",
			   mr->state, mr->mr_fid.key);
		return -EINVAL;
	}

	cmd.command.opcode = C_CMD_TGT_UNLINK;
	cmd.ptl_list = C_PTL_LIST_PRIORITY;
	cmd.ptlte_index = KCXI_PTLTE_INDEX(mr_domain->ptlte);
	cmd.buffer_id = mr->buffer_id;

	rc = kcxi_cmdq_emit_target(mr_domain->target, &cmd);
	if (rc)
		goto err;

	kcxi_cmdq_ring(mr_domain->target);

	MR_DOM_DEBUG(mr_domain, "MR unlink issued: key=%llx", mr->mr_fid.key);

	/*
	 * Wait for the MR state to change for linked.
	 * TODO: If MR is async, can this not block?
	 */
	wait_event(mr_wait_queue, is_mr_unlinked(mr_domain, mr));
	if (mr->state != MR_UNLINKED) {
		MR_DOM_ERR(mr_domain, "MR unlink failed: key=%llx",
			   mr->mr_fid.key);
		return -EIO;
	}

	/* After successful unlink, check if invalidation is required. */
	if (is_invalidation_required(mr_domain)) {
		MR_DOM_DEBUG(mr_domain, "Invalidating MR: key=%llx",
			     mr->mr_fid.key);

		cxi_pte_le_invalidate(mr_domain->ptlte->pte, mr->buffer_id,
				      C_PTL_LIST_PRIORITY);
	}

	return 0;

err:
	return rc;
}

/**
 * kcxi_mr_domain_link() - Link an MR into an MR domain.
 * @mr_domain: The MR domain.
 * @mr: The MR.
 *
 * Note: Function may sleep. kcxi_mr_domain_wake_up() should be called when the
 * link event occurs unless MR domain is bound to an event queue for async MR
 * notification.
 *
 * Return: 0 on success. Else, negative errno.
 */
int kcxi_mr_domain_link(struct kcxi_mr_domain *mr_domain, struct kcxi_mr *mr)
{
	struct c_target_cmd cmd = {};
	int rc;
	bool async = false;

	if (mr->dom->mr_eq)
		async = true;

	cmd.command.opcode = C_CMD_TGT_APPEND;
	cmd.ptl_list = C_PTL_LIST_PRIORITY;
	cmd.ptlte_index = KCXI_PTLTE_INDEX(mr_domain->ptlte);

	if (mr->access & KFI_REMOTE_WRITE)
		cmd.op_put = 1;

	if (mr->access & KFI_REMOTE_READ)
		cmd.op_get = 1;

	cmd.unrestricted_body_ro = 1;
	cmd.unrestricted_end_ro = 1;
	cmd.no_truncate = 1;
	cmd.buffer_id = mr->buffer_id;
	cmd.lac = mr->md->lac;
	cmd.start = mr->md->dma_addr;
	cmd.length = mr->md->len;
	cmd.match_bits = mr->mr_fid.key | KCXI_MR_MATCH_VALUE |
		KCXI_PROV_VERSION_BITS(KCXI_PROV_MAJOR_VERSION);
	cmd.match_id = CXI_MATCH_ID_ANY;
	cmd.ignore_bits = KCXI_REMOTE_CQ_DATA_MATCH_VALUE;

	if (!mr_domain->with_mr_events)
		cmd.event_comm_disable = 1;

	rc = kcxi_cmdq_emit_target(mr_domain->target, &cmd);
	if (rc)
		goto err;

	kcxi_cmdq_ring(mr_domain->target);

	MR_DOM_DEBUG(mr_domain, "MR link issued: key=%llx", mr->mr_fid.key);

	/* Wait for the MR state to change from unlinked. */
	if (!async) {
		wait_event(mr_wait_queue, mr->state != MR_UNLINKED);
		if (mr->state != MR_LINKED) {
			MR_DOM_ERR(mr_domain, "MR link failed: key");
			return -EIO;
		}
	}

	return 0;

err:
	return rc;
}

static const struct rhashtable_params mr_hash_params = {
	.key_len = sizeof(((struct kcxi_mr *)0)->mr_fid.key),
	.key_offset = offsetof(struct kcxi_mr, mr_fid.key),
	.head_offset = offsetof(struct kcxi_mr, node),
	.automatic_shrinking = true,
};

/**
 * kcxi_mr_domain_register() - Register an MR with an MR domain.
 * @mr_domain: The MR domain.
 * @mr: The MR.
 *
 * Return: 0 on success. Else, -KFI_ENOKEY on key collision.
 */
int kcxi_mr_domain_register(struct kcxi_mr_domain *mr_domain,
			    struct kcxi_mr *mr)
{
	int rc;
	struct kcxi_mr *clash_mr;

	clash_mr = rhashtable_lookup_get_insert_fast(&mr_domain->mr_hash,
						     &mr->node, mr_hash_params);
	if (IS_ERR(clash_mr)) {
		rc = PTR_ERR(clash_mr);
		MR_DOM_ERR(mr_domain, "Failed to register key: key=%llx rc=%d",
			   mr->mr_fid.key, rc);
	} else if (clash_mr) {
		rc = -KFI_ENOKEY;
		MR_DOM_ERR(mr_domain, "MR key rejected: key=%llx",
			   mr->mr_fid.key);
	} else {
		rc = 0;
		MR_DOM_DEBUG(mr_domain, "MR key registered: key=%llx",
			     mr->mr_fid.key);
	}

	return rc;
}

/**
 * kcxi_mr_domain_deregister() - Deregister an MR from an MR domain
 * @mr_domain: The MR space.
 * @mr: The MR.
 *
 * Note: This function will free the used key from the MR space.
 */
void kcxi_mr_domain_deregister(struct kcxi_mr_domain *mr_domain,
			      struct kcxi_mr *mr)
{
	int rc;

	rc = rhashtable_remove_fast(&mr_domain->mr_hash, &mr->node,
				    mr_hash_params);

	if (rc)
		MR_DOM_ERR(mr_domain,
			   "Failed to deregister key: key=%llx rc=%d",
			   mr->mr_fid.key, rc);
	else
		MR_DOM_DEBUG(mr_domain, "MR key deregistered: key=%llx",
			     mr->mr_fid.key);
}

/**
 * kcxi_mr_domain_buffer_id_map() - Map an MR request state into an MR domain.
 * @mr_domain: The MR domain.
 * @req: MR request state.
 *
 * Return: Buffer ID greater than or equal to zero on success. Else, negative
 * errno.
 */
int kcxi_mr_domain_buffer_id_map(struct kcxi_mr_domain *mr_domain,
				 struct kcxi_req_state *req)
{
	return kcxi_cq_buffer_id_map(mr_domain->cq, req);
}

/**
 * kcxi_mr_domain_buffer_id_unmap() - Unmap a buffer ID from an MR domain.
 * @mr_domain: The MR domain.
 * @req: MR request state.
 */
void kcxi_mr_domain_buffer_id_unmap(struct kcxi_mr_domain *mr_domain,
				    unsigned int buffer_id)
{
	kcxi_cq_buffer_id_unmap(mr_domain->cq, buffer_id);
}

/**
 * kcxi_mr_domain_alloc() - Allocate an MR domain.
 * @cq: MR target CQ.
 * @target: MR target command queue.
 * @ptlte: MR matching PtlTE.
 * @with_remote_rma_events: Generate completion queue remote RMA events.
 * @with_mr_events: Generate match, put, and get events.
 * @table_size: Size of the MR table.
 *
 * An MR domain is used to register and deregister MRs with the NIC. An MR
 * domain does not allocate its own NIC resources. Instead, it utilizes the
 * kCXI completion queue, target command queue, and matching PtlTE provided
 * during MR domain allocation. The kCXI completion queue needs to be the same
 * kCXI completion queue used to allocate the PtlTE.
 *
 * MR related events will appear on the CXI event queue associated with the
 * provided PtlTE. Any remote RMA events will be placed on the kCXI completion
 * queue associated with the CXI event queue. From the kfabric user's
 * perspective, remote RMA events will appear on the completion queue bound to a
 * target endpoint/RX context.
 *
 * MRs are identified on the fabric by NIC, PID, PID Index, and MR rkey. The MR
 * rkey is used as the match bits when the MR is registered with the NIC.
 *
 * Return: Valid pointer on success. Else, negative errno pointer.
 */
struct kcxi_mr_domain *kcxi_mr_domain_alloc(struct kcxi_cq *cq,
					    struct kcxi_cmdq *target,
					    struct kcxi_ptlte *ptlte,
					    bool with_remote_rma_events,
					    bool with_mr_events,
					    size_t table_size)
{
	struct kcxi_mr_domain *mr_domain;
	int rc;

	if (!cq || !target || !ptlte)
		return ERR_PTR(-EINVAL);

	if (table_size == 0)
		table_size = KCXI_DOM_MR_CNT;

	/* Put a upper bound on the MR table size. */
	table_size = min_t(size_t, table_size, KCXI_DOM_MR_CNT);

	mr_domain = kzalloc(sizeof(*mr_domain), GFP_KERNEL);
	if (!mr_domain)
		return ERR_PTR(-ENOMEM);

	rc = rhashtable_init(&mr_domain->mr_hash, &mr_hash_params);
	if (rc) {
		kfree(mr_domain);
		return ERR_PTR(rc);
	}

	mr_domain->cq = cq;
	mr_domain->target = target;
	mr_domain->ptlte = ptlte;
	mr_domain->with_remote_rma_events = with_remote_rma_events;
	mr_domain->with_mr_events = with_mr_events;

	MR_DOM_DEBUG(mr_domain,
		     "MR domain allocated: remote_rma_events=%d mmr_events=%d",
		     mr_domain->with_remote_rma_events,
		     mr_domain->with_mr_events);

	return mr_domain;
}

/**
 * kcxi_mr_domain_free() - Free an MR domain.
 *
 * Return: 0 on success. Else, -EBUSY if still be used.
 */
int kcxi_mr_domain_free(struct kcxi_mr_domain *mr_domain)
{
	if (!mr_domain)
		return 0;

	if (atomic_read(&mr_domain->mr_hash.nelems))
		return -EBUSY;

	MR_DOM_DEBUG(mr_domain, "MR domain freed");

	rhashtable_destroy(&mr_domain->mr_hash);
	kfree(mr_domain);

	return 0;
}
