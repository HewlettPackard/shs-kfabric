//SPDX-License-Identifier: GPL-2.0
/*
 * Cray kfabric CXI provider PteTE implementation.
 * Copyright 2019,2021 Hewlett Packard Enterprise Development LP. All rights reserved.
 */
#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/sched.h>

#include "kcxi_prov.h"

static DECLARE_WAIT_QUEUE_HEAD(enable_queue);

/**
 * kcxi_ptlte_set_state() - Change the state of a PtlTE
 * kcxi_if: kCXI interface PtlTE belongs to
 * @ptn: PtlTE entry number to be changed
 * @state: The new state
 */
void kcxi_ptlte_set_state(struct kcxi_if *kcxi_if, unsigned int ptn,
			  enum c_ptlte_state state)
{
	struct kcxi_ptlte *ptlte;

	spin_lock(&kcxi_if->ptlte_list_lock);
	list_for_each_entry(ptlte, &kcxi_if->ptlte_list, entry) {
		if (KCXI_PTLTE_INDEX(ptlte) == ptn) {
			ptlte->state = state;
			break;
		}
	}
	spin_unlock(&kcxi_if->ptlte_list_lock);

	wake_up(&enable_queue);
}

/**
 * kcxi_ptlte_free() - Free a PtlTE
 * @ptlte: The PtlTE to be freed
 */
void kcxi_ptlte_free(struct kcxi_ptlte *ptlte)
{
	if (!ptlte)
		return;

	spin_lock(&ptlte->dom_if->kcxi_if->ptlte_list_lock);
	list_del(&ptlte->entry);
	spin_unlock(&ptlte->dom_if->kcxi_if->ptlte_list_lock);

	kcxi_domain_if_index_release(ptlte->dom_if, ptlte->pid_index);
	cxi_pte_unmap(ptlte->pte, ptlte->dom_if->dom, ptlte->get_pt_index);
	cxi_pte_unmap(ptlte->pte, ptlte->dom_if->dom, ptlte->put_pt_index);
	cxi_pte_free(ptlte->pte);
	kfree(ptlte);
}

/**
 * kcxi_ptlte_alloc() - Allocate a new PtlTE
 * @dom_if: kCXI domain interface PtlTE is allocated against
 * @cq: The completion queue to be associated with the PtlTE
 * @pid_index: Index into PID space the PtlTE should be mapped
 * @opts: PtlTE options
 *
 * Return: On success, valid pointer. Else, errno pointer.
 */
struct kcxi_ptlte *kcxi_ptlte_alloc(struct kcxi_domain_if *dom_if,
				    struct kcxi_cq *cq, unsigned int pid_index,
				    struct cxi_pt_alloc_opts *opts)
{
	struct kcxi_ptlte *ptlte;
	int rc;

	if (!dom_if || !cq || !opts)
		return ERR_PTR(-EINVAL);

	rc = kcxi_domain_if_index_reserve(dom_if, pid_index);
	if (rc)
		return ERR_PTR(rc);

	ptlte = kzalloc(sizeof(*ptlte), GFP_KERNEL);
	if (!ptlte)
		return ERR_PTR(-ENOMEM);

	ptlte->pte = cxi_pte_alloc(dom_if->kcxi_if->lni, cq->eq, opts);
	if (IS_ERR(ptlte->pte)) {
		rc = PTR_ERR(ptlte->pte);
		goto err;
	}

	rc = cxi_pte_map(ptlte->pte, dom_if->dom, pid_index, false,
			 &ptlte->put_pt_index);
	if (rc)
		goto err_free_pte;

	rc = cxi_pte_map(ptlte->pte, dom_if->dom,
			 pid_index + KCXI_GET_PID_OFFSET, false,
			 &ptlte->get_pt_index);
	if (rc)
		goto err_unmap_put_pt_index;

	ptlte->state = C_PTLTE_DISABLED;
	ptlte->dom_if = dom_if;
	ptlte->pid_index = pid_index;

	spin_lock(&dom_if->kcxi_if->ptlte_list_lock);
	list_add_tail(&ptlte->entry, &dom_if->kcxi_if->ptlte_list);
	spin_unlock(&dom_if->kcxi_if->ptlte_list_lock);

	return ptlte;

err_unmap_put_pt_index:
	cxi_pte_unmap(ptlte->pte, ptlte->dom_if->dom, ptlte->put_pt_index);
err_free_pte:
	cxi_pte_free(ptlte->pte);
err:
	kfree(ptlte);

	return ERR_PTR(rc);
}

/**
 * kcxi_ptlte_enable() - Enable a PtlTE
 * @ptlte: PtlTE to be enabled
 * @target: Target command queue to be used for enable command
 *
 * Return: 0 on success. Else, negative errno.
 */
int kcxi_ptlte_enable(struct kcxi_ptlte *ptlte, struct kcxi_cmdq *target)
{
	struct c_set_state_cmd cmd = {};
	int rc;

	if (!ptlte || !target || ptlte->state != C_PTLTE_DISABLED)
		return -EINVAL;

	/* PtlTE should be disabled and drop count is ignored. */
	cmd.command.opcode = C_CMD_TGT_SETSTATE;
	cmd.ptlte_index = KCXI_PTLTE_INDEX(ptlte);
	cmd.ptlte_state  = C_PTLTE_ENABLED;
	cmd.drop_count = 0xFFFFFF;

	rc = kcxi_cmdq_emit_target(target, &cmd);
	if (rc)
		return rc;

	kcxi_cmdq_ring(target);

	/*
	 * Wait until PtlTE state is set to enabled. This will occur when an
	 * EVENT_STATE_CHANGE event occurs on the EQ associated with the PtlTe.
	 */
	wait_event(enable_queue, ptlte->state != C_PTLTE_DISABLED);
	if (ptlte->state != C_PTLTE_ENABLED) {
		LOG_ERR("%s: failed to enabled PtlTE: state=%d", __func__,
			ptlte->state);
		return -EIO;
	}

	return 0;
}

/**
 * kcxi_ptlte_disable() - Disable a PtlTE
 * @ptlte: PtlTE to be disabled
 * @target: Target command queue to be used for enable command
 *
 * Return: 0 on success. Else, negative errno.
 */
int kcxi_ptlte_disable(struct kcxi_ptlte *ptlte, struct kcxi_cmdq *target)
{
	struct c_set_state_cmd cmd = {};
	enum c_ptlte_state cur_state;
	int rc;

	if (!ptlte || !target)
		return -EINVAL;

	if (ptlte->state == C_PTLTE_DISABLED)
		return 0;

	cur_state = ptlte->state;

	cmd.command.opcode = C_CMD_TGT_SETSTATE;
	cmd.ptlte_index = KCXI_PTLTE_INDEX(ptlte);
	cmd.ptlte_state  = C_PTLTE_DISABLED;

	rc = kcxi_cmdq_emit_target(target, &cmd);
	if (rc)
		return rc;

	kcxi_cmdq_ring(target);

	wait_event(enable_queue, ptlte->state != cur_state);
	if (ptlte->state != C_PTLTE_DISABLED) {
		LOG_ERR("%s: failed to disabled PtlTE: state=%d", __func__,
			ptlte->state);
		return -EIO;
	}

	return 0;
}
