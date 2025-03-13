// SPDX-License-Identifier: GPL-2.0
/*
 * Cray kfabric CXI provider completion queue.
 * Copyright 2019-2025 Hewlett Packard Enterprise Development LP
 */
#include <linux/slab.h>
#include <linux/module.h>

#include "kcxi_prov.h"

/* Define a default completion queue fill percentage */
unsigned int cq_fill_percent = 50;
module_param(cq_fill_percent, uint, 0444);
MODULE_PARM_DESC(cq_fill_percent,
		 "Fill percent used to determine when completion queue is saturated");

/* TODO: Find a better way to set batch ack count value. */
#define BATCH_ACK_COUNT 20U

static struct kmem_cache *cq_entry_cache;

/**
 * kcxi_cq_saturated() - Check if the completion queue is saturated.
 * @cq: Completion queue
 *
 * A completion queue is considered saturated if priority count exceeds the
 * request count or the underlying CXI EQ is saturated.
 *
 * Note: A saturated completion queue is not fatal. Overflow completion queue
 * entries can be allocated to continue completion queue progression. But, this
 * should be avoided since it may lead to completion queue overrun.
 *
 * Return: True if the completion queue is saturated. Else, false.
 */
bool kcxi_cq_saturated(struct kcxi_cq *cq)
{
	if (atomic_read(&cq->priority_entry_cnt) >= cq->attr.size ||
		cq->eq_saturated) {
		return true;
	}

	/* Hardware will automatically update the EQ status writeback area,
	 * which includes a timestamp, once the EQ reaches a certain fill
	 * percentage. The EQ status timestamp is compared against cached
	 * versions of the previous EQ status timestamp to determine if new
	 * writebacks have occurred. Each time a new writeback occurs, the EQ
	 * is treated as saturated and no more commands which generate events
	 * should be issued until it is drained.
	 */
	if ((cq->eq->status->timestamp_sec > cq->prev_eq_status.timestamp_sec) ||
	    (cq->eq->status->timestamp_ns > cq->prev_eq_status.timestamp_ns)) {
		cq->eq_saturated = true;
		cq->prev_eq_status = *cq->eq->status;
		CQ_DEBUG(cq, "CQ saturated: free_eq_event_slots=%u",
			 cq->eq->status->event_slots_free);

		return true;
	}

	return false;
}

/**
 * kcxi_cq_init_cache() - Initialize the CQ entry cache
 *
 * The cache is used when a CXI CQ has exhausted its allocated CXI CQ entries.
 *
 * Return: 0 on success. Else, negative errno.
 */
int kcxi_cq_init_cache(void)
{
	cq_entry_cache = kmem_cache_create("kcxi_cq_entries",
					   sizeof(struct kcxi_cq_entry), 0, 0,
					   NULL);
	if (!cq_entry_cache)
		return -ENOMEM;

	return 0;
}

/**
 * kcxi_cq_destroy_cache() - Destroy the CQ entry cache
 *
 * All CXI CQ must have any allocated CXI CQ entries returned back to the cache
 * before this is called. Else, memory leak will occur.
 */
void kcxi_cq_destroy_cache(void)
{
	kmem_cache_destroy(cq_entry_cache);
}

/**
 * kcxi_cq_raise_handler() - Call the kfabric CQ handler/callback.
 * @cq: The completion queue
 *
 * The kfabric CQ handler/callback is only raised if the CQ has been completely
 * drained (-EAGAIN is returned when reading events/errors). The motivation for
 * this is to not notify the kfabric user every time events are written.
 */
static void kcxi_cq_raise_handler(struct kcxi_cq *cq)
{
	if (!cq->cq_fid.comp_handler)
		return;

	/* Serialize access to armed using entry list lock. */
	spin_lock(&cq->entry_list_lock);
	if (!cq->armed) {
		spin_unlock(&cq->entry_list_lock);
		return;
	}

	CQ_DEBUG(cq, "CQ callback disarmed");

	cq->armed = false;
	spin_unlock(&cq->entry_list_lock);

	cq->cq_fid.comp_handler(&cq->cq_fid, cq->cq_fid.fid.context);
}

/**
 * kcxi_cq_pt_state_change() - Process a PtlTE state change event
 * @kcxi_if: kCXI interface the event came in on
 * @event: The state change event
 *
 * State change events do not have a buffer ID associated with them. So, a
 * search of all allocated PtlTEs using this CXI CQ is required. This is what
 * cxi_ptlte_set_state() does.
 */
static void kcxi_cq_pt_state_change(struct kcxi_if *kcxi_if,
				    const union c_event *event)
{
	unsigned int ptn = event->tgt_long.ptlte_index;
	enum c_ptlte_state state =
		event->tgt_long.initiator.state_change.ptlte_state;

	if (event->hdr.event_size != C_EVENT_SIZE_64_BYTE) {
		LOG_ERR("%s: bad event size: expected=%u got=%u", __func__,
			C_EVENT_SIZE_64_BYTE, event->hdr.event_size);
		return;
	}

	if (event->tgt_long.return_code != C_RC_OK) {
		LOG_ERR("%s: bad return code: %d", __func__,
			event->tgt_long.return_code);
		return;
	}

	kcxi_ptlte_set_state(kcxi_if, ptn, state);
}

/**
 * kcxi_cq_work_process_event() - Initial processing of hardware event queue
 * @work: Pointer to kCXI CQ embedded work struct
 *
 * Even though kCXI CQ present a kfabric completion queue to users, the
 * underlying hardware event queue may/will contain many events that do not
 * translate to a kfabric completion queue event. One example is PtlTE state
 * change events.
 */
static void kcxi_cq_work_process_event(struct work_struct *work)
{
	struct kcxi_cq *cq = container_of(work, struct kcxi_cq, work);
	const union c_event *event;
	struct kcxi_req_state *req = NULL;
	unsigned int buffer_id;
	int rc;
	int count = 0;
	bool trigger_user_cb = false;
	struct kcxi_eq *eq = NULL;

	mutex_lock(&cq->processing_eq_lock);

again:
	while ((event = cxi_eq_get_event(cq->eq))) {
		switch (event->hdr.event_type) {
		default:
			BUG();
			continue;

		/* State change events do not use a request state. */
		case C_EVENT_STATE_CHANGE:
			kcxi_cq_pt_state_change(cq->domain->kcxi_if, event);
			continue;

		/* Handle target events. */
		case C_EVENT_UNLINK:
			/* If C_RC_ENTRY_NOT_FOUND is returned, this is a sign
			 * a unlink command did not find the unexpected LE. This
			 * is valid since the unlink command and incoming put
			 * may be racing against the same LE.
			 */
			if (cxi_tgt_event_rc(event) == C_RC_ENTRY_NOT_FOUND)
				continue;

			fallthrough;
		case C_EVENT_LINK:
		case C_EVENT_PUT:
		case C_EVENT_GET:
		case C_EVENT_MATCH:
			if (event->hdr.event_size == C_EVENT_SIZE_64_BYTE) {
				buffer_id = event->tgt_long.buffer_id;
			} else if (event->hdr.event_size == C_EVENT_SIZE_32_BYTE) {
				buffer_id = event->tgt_short.buffer_id;
			} else {
				CQ_ERR(cq, "bad target event_size=%d",
				       event->hdr.event_size);
				BUG();
			}

			if (!buffer_id) {
				/* RC_ENTRY_NOT_FOUND is generated at the target
				 * if an incoming operation does not match a
				 * user posted receive. These are not errors, so
				 * do not log an error message.
				 */
				if (cxi_event_rc(event) != C_RC_ENTRY_NOT_FOUND)
					CQ_ERR(cq,
					       "NULL buffer ID: hw_event_type=%u hw_event_rc=%u",
					       event->hdr.event_type,
					       cxi_event_rc(event));
				continue;
			}

			spin_lock(&cq->table_lock);
			req = idr_find(&cq->buffer_id_table, buffer_id);
			spin_unlock(&cq->table_lock);
			break;

		/* Handle initiator events. */
		case C_EVENT_ACK:
		case C_EVENT_REPLY:
			if (event->hdr.event_size == C_EVENT_SIZE_16_BYTE) {
				req = (void *)event->init_short.user_ptr;
			} else if (event->hdr.event_size == C_EVENT_SIZE_32_BYTE) {
				req = (void *)event->init_long.user_ptr;
			} else {
				CQ_ERR(cq, "bad init event_size=%d",
				       event->hdr.event_size);
				BUG();
			}
			break;
		}

		if (!req) {
			CQ_ERR(cq, "NULL request: event_size=%d event_type=%d",
			       event->hdr.event_size, event->hdr.event_type);
			BUG();
		}

		/*
		 * Hand event off to request state callback for processing. If
		 * this was an LE event and the request state is for an MR, the
		 * MR registration CB will be set and used instead of the
		 * general purpose request state CB.
		 */
		if (event->hdr.event_type == C_EVENT_LINK && req->mr_link_cb) {
			eq = req->mr_link_cb(req, event);
		} else if (event->hdr.event_type == C_EVENT_UNLINK &&
			   req->mr_unlink_cb) {
			req->mr_unlink_cb(req, event);
		} else {
			rc = req->cb(cq, req, event);
			if (rc > 0)
				trigger_user_cb = true;
			else if (rc < 0)
				CQ_ERR(cq, "req cb bad rc: rc=%d", rc);
		}

		count++;
		if (count == BATCH_ACK_COUNT) {
			cxi_eq_int_disable(cq->eq);
			count = 0;

			if (trigger_user_cb) {
				kcxi_cq_raise_handler(cq);
				trigger_user_cb = false;
			}

			if (eq) {
				kcxi_eq_raise_handler(eq);
				eq = NULL;
			}
		}
	}

	cxi_eq_int_enable(cq->eq);

	/* Can only progress beyond this point if event queue is empty. */
	if (!cxi_eq_empty(cq->eq))
		goto again;

	cq->eq_saturated = false;

	/* Dropping an event leads to memory leaking. This is fatal and must be
	 * prevented.
	 */
	if (cxi_eq_get_drops(cq->eq)) {
		CQ_ERR(cq, "EQ overflow detected");
		BUG();
	}

	/* Trigger user's completion queue callback. */
	if (trigger_user_cb)
		kcxi_cq_raise_handler(cq);

	/*
	 * Trigger user's event queue callback due to MR registration events.
	 */
	if (eq)
		kcxi_eq_raise_handler(eq);

	mutex_unlock(&cq->processing_eq_lock);
}

static void kcxi_cq_process_event(void *context)
{
	struct kcxi_cq *cq = context;

	queue_work_on(cq->attr.signaling_vector, kcxi_wq, &cq->work);
}

/**
 * kcxi_cq_entry_alloc() - Allocated a kCXI CQ entry
 * @cq: The kCXI CQ the kCXI CQ entry should belong to
 *
 * Memory allocation can come from two locations: the initial CQ entry array
 * associated with the kCXI CQ or the CQ entry cache. The cache is only used
 * when the initial CQ entries are all used. Entries allocated from the cache
 * are marked as overflow and returned to the cache once processed by the
 * kfabric user.
 *
 * Return: Valid pointer. Else, NULL.
 */
static struct kcxi_cq_entry *kcxi_cq_entry_alloc(struct kcxi_cq *cq)
{
	struct kcxi_cq_entry *entry;

	if (!cq)
		return NULL;

	spin_lock(&cq->entry_free_list_lock);
	entry = list_first_entry_or_null(&cq->entry_free_list,
					 struct kcxi_cq_entry, entry);
	if (entry) {
		list_del(&entry->entry);
		atomic_inc(&cq->priority_entry_cnt);
	}
	spin_unlock(&cq->entry_free_list_lock);

	if (entry) {
		entry->overflow = false;
	} else if (atomic_read(&cq->overflow_entry_cnt) <
		   MAX_CQ_OVERFLOW_ENTRY_CNT) {
		entry = kmem_cache_alloc(cq_entry_cache, GFP_ATOMIC);
		if (entry) {
			entry->overflow = true;
			atomic_inc(&cq->overflow_entry_cnt);
		}
	}

	if (entry) {
		CQ_DEBUG(cq,
			 "Event entry allocated: priority_event_cnt=%u overflow_event_cnt=%u",
			 atomic_read(&cq->priority_entry_cnt),
			 atomic_read(&cq->overflow_entry_cnt));
	} else {
		atomic_inc(&cq->overrun_cnt);

		CQ_ERR(cq, "CQ overrun: overrun_count=%u",
		       atomic_read(&cq->overrun_cnt));
	}

	return entry;
}

/**
 * kcxi_cq_entry_free() - Free a kCXI CQ entry
 * @cq: The kCXI CQ the kCXI CQ entry belongs to
 * @entry: The kCXI CQ entry
 *
 * Initial kCXI CQ entries are returned to the kCXI CQ free list. kCXI CQ
 * entries marked as overflow are returned to the cache.
 */
static void kcxi_cq_entry_free(struct kcxi_cq *cq, struct kcxi_cq_entry *entry)
{
	/* CQ and entry are checked for NULL by calling function. */
	if (entry->overflow) {
		kmem_cache_free(cq_entry_cache, entry);
		atomic_dec(&cq->overflow_entry_cnt);
		return;
	}

	spin_lock(&cq->entry_free_list_lock);
	list_add(&entry->entry, &cq->entry_free_list);
	atomic_dec(&cq->priority_entry_cnt);
	spin_unlock(&cq->entry_free_list_lock);

	CQ_DEBUG(cq,
		 "Event entry freed: priority_event_cnt=%u overflow_event_cnt=%u",
		 atomic_read(&cq->priority_entry_cnt),
		 atomic_read(&cq->overflow_entry_cnt));
}

/**
 * kcxi_cq_entry_size() - Determine the size of a kCXI CQ entry
 * @ cq: The kCXI CQ
 *
 * Return: Size of CQ entry on success. Else, -1.
 */
static ssize_t kcxi_cq_entry_size(const struct kcxi_cq *cq)
{
	/* This function is called by kcxi_cq_open so CQ will not be NULL. */
	ssize_t size;

	switch (cq->attr.format) {
	case KFI_CQ_FORMAT_CONTEXT:
		size = sizeof(struct kfi_cq_entry);
		break;

	case KFI_CQ_FORMAT_MSG:
		size = sizeof(struct kfi_cq_msg_entry);
		break;

	case KFI_CQ_FORMAT_DATA:
		size = sizeof(struct kfi_cq_data_entry);
		break;

	case KFI_CQ_FORMAT_TAGGED:
		size = sizeof(struct kfi_cq_tagged_entry);
		break;

	case KFI_CQ_FORMAT_UNSPEC:
	default:
		size = -1;
		break;
	}

	return size;
}

/**
 * kcxi_cq_insert_event() - Insert a new kCXI CQ entry
 * @cq: The kCXI CQ
 * @entry: The entry
 *
 * Note: Only kCXI CQ entries corresponding to kfabric completion queue events
 * are put on the list. This means that hardware events not corresponding to a
 * kfabric completion queue will not be placed on the list.
 */
static void kcxi_cq_insert_event(struct kcxi_cq *cq,
				 struct kcxi_cq_entry *entry)
{
	/* CQ and entry are already checked for not NULL by calling func. */
	spin_lock(&cq->entry_list_lock);
	list_add_tail(&entry->entry, &cq->event_list);
	spin_unlock(&cq->entry_list_lock);
}

/**
 * kcxi_cq_insert_error() - Insert a new kCXI CQ error
 * @cq: The kCXI CQ
 * @entry: The entry
 *
 * Note: Only kCXI CQ entries corresponding to kfabric completion queue errors
 * are put on the list.
 */
static void kcxi_cq_insert_error(struct kcxi_cq *cq,
				 struct kcxi_cq_entry *entry)
{
	/* CQ and entry are already checked for not NULL by calling func. */
	spin_lock(&cq->entry_list_lock);
	list_add_tail(&entry->entry, &cq->error_list);
	spin_unlock(&cq->entry_list_lock);
}

/**
 * kcxi_cq_report_context() - Report a new context event.
 * @cq: The kCXI CQ.
 * @src_addr: KFI source address for CQ event.
 * @req: The kCXI request state.
 *
 * Return: 1 on success. Else, negative errno.
 */
static ssize_t kcxi_cq_report_context(struct kcxi_cq *cq,
				      kfi_addr_t src_addr,
				      struct kcxi_req_state *req)
{
	struct kcxi_cq_entry *entry;

	if (!cq || !req)
		return -EINVAL;

	entry = kcxi_cq_entry_alloc(cq);
	if (!entry)
		return -ENOMEM;

	entry->event.context.op_context = req->context;
	entry->src_addr = src_addr;

	kcxi_cq_insert_event(cq, entry);

	return 1;
}

/**
 * kcxi_cq_sanitize_flags() - Sanitize flags
 * @flags: Unsanitized flags
 *
 * Return: Sanitized flags.
 */
static uint64_t kcxi_cq_sanitize_flags(uint64_t flags)
{
	return (flags & (KFI_SEND | KFI_RECV | KFI_RMA | KFI_ATOMIC | KFI_MSG |
			 KFI_TAGGED | KFI_READ | KFI_WRITE | KFI_REMOTE_READ |
			 KFI_REMOTE_WRITE | KFI_REMOTE_CQ_DATA |
			 KFI_MULTI_RECV));
}

/**
 * kcxi_cq_report_msg() - Report a new msg event.
 * @cq: The kCXI CQ.
 * @src_addr: KFI source address for CQ event.
 * @req: The kCXI request state.
 *
 * Return: 1 on success. Else, negative errno.
 */
static ssize_t kcxi_cq_report_msg(struct kcxi_cq *cq,
				  kfi_addr_t src_addr,
				  struct kcxi_req_state *req)
{
	struct kcxi_cq_entry *entry;

	if (!cq || !req)
		return -EINVAL;

	entry = kcxi_cq_entry_alloc(cq);
	if (!entry)
		return -ENOMEM;

	entry->event.msg.op_context = req->context;
	entry->event.msg.flags =
		kcxi_cq_sanitize_flags(req->flags) & ~KFI_REMOTE_CQ_DATA;
	entry->event.msg.len = req->data_len;
	entry->src_addr = src_addr;

	kcxi_cq_insert_event(cq, entry);

	return 1;
}

/**
 * kcxi_cq_report_data() - Report a new data event.
 * @cq: The kCXI CQ.
 * @src_addr: KFI source address for CQ event.
 * @req: The kCXI request state,
 *
 * Return: 1 on success. Else, negative errno.
 */
static ssize_t kcxi_cq_report_data(struct kcxi_cq *cq,
				   kfi_addr_t src_addr,
				   struct kcxi_req_state *req)
{
	struct kcxi_cq_entry *entry;

	if (!cq || !req)
		return -EINVAL;

	entry = kcxi_cq_entry_alloc(cq);
	if (!entry)
		return -ENOMEM;

	entry->event.data.op_context = req->context;
	entry->event.data.flags = kcxi_cq_sanitize_flags(req->flags);
	entry->event.data.len = req->data_len;
	entry->event.data.buf = req->buf;
	entry->event.data.data = req->data;
	entry->src_addr = src_addr;

	kcxi_cq_insert_event(cq, entry);

	return 1;
}

/**
 * kcxi_cq_report_tagged() - Report a new tagged event.
 * @cq: The kCXI CQ.
 * @src_addr: KFI source address for CQ event.
 * @req: The kCXI request state.
 *
 * Return: 1 on success. Else, negative errno.
 */
static ssize_t kcxi_cq_report_tagged(struct kcxi_cq *cq,
				     kfi_addr_t src_addr,
				     struct kcxi_req_state *req)
{
	struct kcxi_cq_entry *entry;

	if (!cq || !req)
		return -EINVAL;

	entry = kcxi_cq_entry_alloc(cq);
	if (!entry)
		return -ENOMEM;

	entry->event.tagged.op_context = req->context;
	entry->event.tagged.flags = kcxi_cq_sanitize_flags(req->flags);
	entry->event.tagged.len = req->data_len;
	entry->event.tagged.buf = req->buf;
	entry->event.tagged.data = req->data;
	entry->event.tagged.tag = req->tag;
	entry->src_addr = src_addr;

	kcxi_cq_insert_event(cq, entry);

	return 1;
}

/**
 * kcxi_cq_set_report_fn() - Set the kCXI CQ event reporting function
 * @kcxi_cq: The kCXI CQ
 *
 * The reporting function is based on the kfabric users CQ format type.
 */
static void kcxi_cq_set_report_fn(struct kcxi_cq *cq)
{
	/* kcxi_cq is checked for not NULL by calling function. */
	switch (cq->attr.format) {
	case KFI_CQ_FORMAT_CONTEXT:
		cq->report_completion = kcxi_cq_report_context;
		break;

	case KFI_CQ_FORMAT_MSG:
		cq->report_completion = kcxi_cq_report_msg;
		break;

	case KFI_CQ_FORMAT_DATA:
		cq->report_completion = kcxi_cq_report_data;
		break;

	case KFI_CQ_FORMAT_TAGGED:
		cq->report_completion = kcxi_cq_report_tagged;
		break;

	case KFI_CQ_FORMAT_UNSPEC:
	default:
		LOG_ERR("Invalid CQ format");
		break;
	}
}

/**
 * kcxi_cq_report_error() - Report a new error event.
 * @cq: The kCXI CQ.
 * @req: The kCXI request state.
 * @olen: Overflow length.
 * @err: Positive err value.
 * @prov_errno: Provider error value.
 *
 * Return: Number of elements inserted on success. Else, negative errno.
 */
static ssize_t kcxi_cq_report_error(struct kcxi_cq *cq,
				    struct kcxi_req_state *req, size_t olen,
				    int err, int prov_errno)
{
	struct kcxi_cq_entry *entry;

	if (!cq || !req)
		return -EINVAL;

	entry = kcxi_cq_entry_alloc(cq);
	if (!entry)
		return -ENOMEM;

	entry->event.error.err = err;
	entry->event.error.olen = olen;
	entry->event.error.err_data = NULL;
	entry->event.error.err_data_size = 0;
	entry->event.error.len = req->data_len;
	entry->event.error.prov_errno = prov_errno;
	entry->event.error.flags = req->flags;
	entry->event.error.data = req->data;
	entry->event.error.tag = req->tag;
	entry->event.error.op_context = req->context;

	kcxi_cq_insert_error(cq, entry);

	return 1;
}

/**
 * kcxi_cq_read_event() - Read a kfabric completion event with source address.
 * @cq: Kfabric completion queue
 * @buf: User buffer for event to be copied to
 * @count: Number of events and source addresses the user buffer can hold
 * @src_addr: Optional array of source addresses.
 *
 * Note: Errors will block the reading of events.
 *
 * Return: Number of events and source addresses processed. Else, negative
 * errno.
 */
static ssize_t kcxi_cq_read_event(struct kfid_cq *cq, void *buf, size_t count,
				  kfi_addr_t *src_addr)
{
	struct kcxi_cq *kcxi_cq;
	struct kcxi_cq_entry *entry;
	size_t read_count;

	if (!cq || !buf)
		return -EINVAL;

	kcxi_cq = container_of(cq, struct kcxi_cq, cq_fid);

	for (read_count = 0; read_count < count; read_count++) {
		spin_lock(&kcxi_cq->entry_list_lock);

		if (!list_empty(&kcxi_cq->error_list)) {
			spin_unlock(&kcxi_cq->entry_list_lock);
			if (!read_count)
				return -KFI_EAVAIL;
			return read_count;
		}

		entry = list_first_entry_or_null(&kcxi_cq->event_list,
						 struct kcxi_cq_entry, entry);
		if (!entry) {

			/*
			 * Rearm the comp handler if the event list is empty
			 * (-EAGAIN is returned to user) and the CQ has not been
			 * overrun_cnt.
			 */
			if (!atomic_read(&kcxi_cq->overrun_cnt)) {
				CQ_DEBUG(kcxi_cq, "CQ callback armed");
				kcxi_cq->armed = true;
			}

			spin_unlock(&kcxi_cq->entry_list_lock);
			if (!read_count) {
				if (atomic_read(&kcxi_cq->overrun_cnt))
					return -KFI_EOVERRUN;
				return -EAGAIN;
			}
			return read_count;
		}

		list_del(&entry->entry);
		spin_unlock(&kcxi_cq->entry_list_lock);

		memcpy(buf + (read_count * kcxi_cq->cq_entry_size),
		       &entry->event, kcxi_cq->cq_entry_size);

		if (src_addr)
			*(src_addr + read_count) = entry->src_addr;

		kcxi_cq_entry_free(kcxi_cq, entry);
	}

	return read_count;
}

/**
 * kcxi_cq_readfrom() - Read a kfabric completion event with source address.
 * @cq: Kfabric completion queue
 * @buf: User buffer for event to be copied to
 * @count: Number of events and source addresses the user buffer can hold
 * @src_addr: Array of source addresses.
 *
 * Note: Errors will block the reading of events.
 *
 * Return: Number of events and source addresses processed. Else, negative
 * errno.
 */
static ssize_t kcxi_cq_readfrom(struct kfid_cq *cq, void *buf, size_t count,
				kfi_addr_t *src_addr)
{
	if (!src_addr)
		return -EINVAL;

	return kcxi_cq_read_event(cq, buf, count, src_addr);
}

/**
 * kcxi_cq_read() - Read a kfabric completion event
 * @cq: Kfabric completion queue
 * @buf: User buffer for event to be copied to
 * @count: Number of events the user buffer can hold
 *
 * Note: Errors will block the reading of events.
 *
 * Return: Number of events processed. Else, negative errno.
 */
static ssize_t kcxi_cq_read(struct kfid_cq *cq, void *buf, size_t count)
{
	return kcxi_cq_read_event(cq, buf, count, NULL);
}

/**
 * kcxi_cq_readerr() - Read a kfabric completion error
 * @cq: Kfabric completion queue
 * @buf: User buffer for error to be copied to
 * @flags: Unused
 *
 * Return: Number of errors processed. Else, negative errno.
 */
static ssize_t kcxi_cq_readerr(struct kfid_cq *cq, struct kfi_cq_err_entry *buf,
			      uint64_t flags)
{
	struct kcxi_cq *kcxi_cq;
	struct kcxi_cq_entry *entry;
	void *user_err_data;

	kcxi_cq = container_of(cq, struct kcxi_cq, cq_fid);

	if (!buf)
		return -EINVAL;

	spin_lock(&kcxi_cq->entry_list_lock);
	entry = list_first_entry_or_null(&kcxi_cq->error_list,
					 struct kcxi_cq_entry, entry);
	if (!entry) {
		spin_unlock(&kcxi_cq->entry_list_lock);
		if (atomic_read(&kcxi_cq->overrun_cnt))
			return -KFI_EOVERRUN;
		return -EAGAIN;
	}

	list_del(&entry->entry);
	spin_unlock(&kcxi_cq->entry_list_lock);

	user_err_data = buf->err_data;
	memcpy(buf, &entry->event, sizeof(*buf));
	buf->err_data = user_err_data;

	kcxi_cq_entry_free(kcxi_cq, entry);

	return 1;
}

/* TODO: Implement provider specific error functions */
static const char *kcxi_cq_strerror(struct kfid_cq *cq, int prov_errno,
				   const void *err_data, char *buf, size_t len)
{
	return NULL;
}

/**
 * kcxi_cq_entries_free() - Free all kCXI CQ entries
 * @cq: The kCXI CQ
 *
 * Note: Any unread events/errors will be lost. Any memory allocated from the
 * cache (marked as overflow) is returned.
 */
static void kcxi_cq_entries_free(struct kcxi_cq *cq)
{
	/* CQ is checked for not NULL by calling function. */
	struct kcxi_cq_entry *pos;
	struct kcxi_cq_entry *n;

	list_for_each_entry_safe(pos, n, &cq->event_list, entry) {
		if (pos->overflow) {
			list_del(&pos->entry);
			kmem_cache_free(cq_entry_cache, pos);
		}
	}

	list_for_each_entry_safe(pos, n, &cq->error_list, entry) {
		if (pos->overflow) {
			list_del(&pos->entry);
			kmem_cache_free(cq_entry_cache, pos);
		}
	}

	kvfree(cq->priority_entries);
}

/**
 * kcxi_cq_entries_alloc() - Allocate kCXI CQ entries
 * @cq: The kCXI CQ
 *
 * Setup the initial kCXI CQ entry pool.
 *
 * Return: 0 on success. Else, negative errno.
 */
static int kcxi_cq_entries_alloc(struct kcxi_cq *cq)
{
	/* CQ is checked for not NULL by calling function. */
	struct kcxi_cq_entry *entry;
	size_t i;

	cq->priority_entries =
		kvzalloc_node(cq->attr.size *
			      sizeof(*cq->priority_entries),
			      GFP_KERNEL,
			      cpu_to_node(cq->attr.signaling_vector));
	if (!cq->priority_entries)
		return -ENOMEM;

	for (i = 0; i < cq->attr.size; i++) {
		entry = cq->priority_entries + i;
		list_add(&entry->entry, &cq->entry_free_list);
	}

	return 0;
}

/**
 * kcxi_cq_free() - Free a kCXI CQ
 * @cq: The kCXI CQ
 *
 * Return: 0 on success. Else, negative errno.
 */
static int kcxi_cq_free(struct kcxi_cq *cq)
{
	if (!cq)
		return -EINVAL;

	flush_workqueue(kcxi_wq);

	if (atomic_read(&cq->ref_cnt))
		return -EBUSY;

	CQ_DEBUG(cq, "CQ freed");

	atomic_dec(&cq->domain->ref_cnt);

	cxi_eq_free(cq->eq);

	kcxi_md_cache_flush(cq);

	kcxi_md_free(cq->queue_md);

	kvfree(cq->queue);

	kcxi_cq_entries_free(cq);

	kfree(cq);

	return 0;
}

/**
 * kcxi_cq_close() - Close a kCXI completion queue
 * @fid: kCXI CQ fid
 *
 * Return: 0 on success. Else, negative errno.
 */
static int kcxi_cq_close(struct kfid *fid)
{
	/*
	 * Do not need to check fid for being NULL since kfabric would have
	 * dereferenced it by this point.
	 */
	struct kcxi_cq *cq;

	cq = container_of(fid, struct kcxi_cq, cq_fid.fid);

	return kcxi_cq_free(cq);
}

/**
 * kcxi_cq_verify_attr() - Verify a CQ attributes
 *
 * Return: 0 on success. Else, negative errno.
 */
static int kcxi_cq_verify_attr(struct kfi_cq_attr *attr)
{
	if (!attr)
		return 0;

	if (attr->flags && attr->flags != KFI_AFFINITY)
		return -ENOSYS;

	switch (attr->format) {
	case KFI_CQ_FORMAT_CONTEXT:
	case KFI_CQ_FORMAT_MSG:
	case KFI_CQ_FORMAT_DATA:
	case KFI_CQ_FORMAT_TAGGED:
		break;
	case KFI_CQ_FORMAT_UNSPEC:
		attr->format = KFI_CQ_FORMAT_DATA;
		break;
	default:
		return -ENOSYS;
	};

	switch (attr->wait_obj) {
	case KFI_WAIT_NONE:
		break;
	case KFI_WAIT_UNSPEC:
	case KFI_WAIT_SET:
	case KFI_WAIT_QUEUE:
	default:
		return -ENOSYS;
	};

	switch (attr->wait_cond) {
	case KFI_CQ_COND_NONE:
		break;
	default:
		return -ENOSYS;
	};

	if (attr->wait_set)
		return -ENOSYS;

	return 0;
}

/**
 * kcxi_cq_buffer_id_map() - Map a kCXI request state to a buffer ID
 * @cq: The kCXI CQ the CXI request state should be associated with
 * @req: The kCXI request state
 *
 * For target size events, a buffer ID is needed to map an event to a user
 * context. In this case, the user context is a CXI request state. Buffer IDs
 * MUST be unique for a single kCXI CQ.
 *
 * Callers of this function MUST cache the buffer ID.
 *
 * Return: Value greater or equal to 1 on success. Else, negative errno.
 */
int kcxi_cq_buffer_id_map(struct kcxi_cq *cq, struct kcxi_req_state *req)
{
	int rc;

	if (!cq || !req)
		return -EINVAL;

	idr_preload(GFP_KERNEL);
	spin_lock(&cq->table_lock);
	rc = idr_alloc(&cq->buffer_id_table, req, 1, MAX_BUFFER_ID, GFP_NOWAIT);
	spin_unlock(&cq->table_lock);
	idr_preload_end();

	return rc;
}

/**
 * kcxi_cq_buffer_id_unmap() - Unmap a kCXI request state from a buffer ID
 * @cq: The kCXI CQ
 * @buffer_id: The buffer ID the kCXI request state should be un-mapped from
 */
void kcxi_cq_buffer_id_unmap(struct kcxi_cq *cq, unsigned int buffer_id)
{
	if (!cq || buffer_id >= MAX_BUFFER_ID)
		return;

	spin_lock(&cq->table_lock);
	idr_remove(&cq->buffer_id_table, buffer_id);
	spin_unlock(&cq->table_lock);
}

static const struct kfi_cq_attr kcxi_cq_def_attr = {
	.size = KCXI_CQ_DEF_SZ,
	.flags = 0,
	.format = KFI_CQ_FORMAT_DATA,
	.wait_obj = KFI_WAIT_NONE,
	.signaling_vector = 0,
	.wait_cond = KFI_CQ_COND_NONE,
	.wait_set = NULL,
};

static struct kfi_ops_cq kcxi_cq_ops = {
	.read = kcxi_cq_read,
	.readfrom = kcxi_cq_readfrom,
	.readerr = kcxi_cq_readerr,
	.sread = kfi_no_cq_sread,
	.sreadfrom = kfi_no_cq_sreadfrom,
	.signal = kfi_no_cq_signal,
	.strerror = kcxi_cq_strerror
};

static struct kfi_ops kcxi_cq_fi_ops = {
	.close = kcxi_cq_close,
	.bind = kfi_no_bind,
	.control = kfi_no_control,
	.ops_open = kfi_no_ops_open
};

/**
 * kcxi_cq_alloc() - Allocate and initialize a kCXI CQ
 * @domain: The kCXI domain the kCXI CQ belongs to
 * @attr: The kCXI CQ attributes
 * @comp_handler: The completion handler callback
 * @context: User context
 *
 * Note: This function is intended to be called by kcxi_cq_open() or by another
 * area in the kCXI provider which requires the event processing capabilities of
 * a kCXI CQ. For example, an MR space may want to have a private kCXI CQ to be
 * used for MR allocation. Thus, the same hardware event queue processing can be
 * utilized.
 *
 * Return: Valid pointer on success. Else, negative errno pointer.
 */
static struct kcxi_cq *kcxi_cq_alloc(struct kcxi_domain *kcxi_dom,
				     struct kfi_cq_attr *attr,
				     kfi_comp_handler comp_handler,
				     void *context)
{
	struct cxi_lni *lni;
	struct kcxi_cq *kcxi_cq;
	struct cxi_eq *cxi_eq;
	struct cxi_eq_attr eq_attr = {};
	uint32_t flags = CXI_MAP_WRITE;
	int rc;
	int numa_node;

	if (!kcxi_dom)
		return ERR_PTR(-EINVAL);

	rc = kcxi_cq_verify_attr(attr);
	if (rc)
		return ERR_PTR(rc);

	if (attr)
		numa_node = cpu_to_node(attr->signaling_vector);
	else
		numa_node = cpu_to_node(kcxi_cq_def_attr.signaling_vector);

	kcxi_cq = kzalloc_node(sizeof(*kcxi_cq), GFP_KERNEL, numa_node);
	if (!kcxi_cq)
		return ERR_PTR(-ENOMEM);

	lni = kcxi_dom->kcxi_if->lni;
	kcxi_cq->domain = kcxi_dom;

	kcxi_cq->cq_fid.fid.fclass = KFI_CLASS_CQ;
	kcxi_cq->cq_fid.fid.context = context;
	kcxi_cq->cq_fid.fid.ops = &kcxi_cq_fi_ops;
	kcxi_cq->cq_fid.ops = &kcxi_cq_ops;
	kcxi_cq->cq_fid.comp_handler = comp_handler;

	if (!attr) {
		kcxi_cq->attr = kcxi_cq_def_attr;
	} else {
		kcxi_cq->attr = *attr;
		if (attr->size == 0)
			kcxi_cq->attr.size = kcxi_cq_def_attr.size;
	}

	kcxi_cq->cq_entry_size = kcxi_cq_entry_size(kcxi_cq);
	if (kcxi_cq->cq_entry_size == -1) {
		rc = -EINVAL;
		goto err_free_cq;
	}

	INIT_LIST_HEAD(&kcxi_cq->event_list);
	INIT_LIST_HEAD(&kcxi_cq->error_list);
	INIT_LIST_HEAD(&kcxi_cq->entry_free_list);
	spin_lock_init(&kcxi_cq->entry_list_lock);
	spin_lock_init(&kcxi_cq->entry_free_list_lock);
	atomic_set(&kcxi_cq->overflow_entry_cnt, 0);
	rc = kcxi_cq_entries_alloc(kcxi_cq);
	if (rc)
		goto err_free_cq;

	atomic_set(&kcxi_cq->priority_entry_cnt, 0);
	atomic_set(&kcxi_cq->overflow_entry_cnt, 0);
	atomic_set(&kcxi_cq->overrun_cnt, 0);
	atomic_set(&kcxi_cq->ref_cnt, 0);

	kcxi_cq_set_report_fn(kcxi_cq);
	kcxi_cq->report_error = kcxi_cq_report_error;
	kcxi_cq->buffer_id_map = kcxi_cq_buffer_id_map;
	kcxi_cq->buffer_id_unmap = kcxi_cq_buffer_id_unmap;

	idr_init(&kcxi_cq->buffer_id_table);
	spin_lock_init(&kcxi_cq->table_lock);

	/* Setup buffer for EQ. */
	kcxi_cq->queue_len =
		ALIGN(2 * kcxi_cq->attr.size * C_EE_CFG_ECB_SIZE, PAGE_SIZE);
	kcxi_cq->queue = kvzalloc_node(kcxi_cq->queue_len, GFP_KERNEL,
				       cpu_to_node(kcxi_cq->attr.signaling_vector));
	if (!kcxi_cq->queue) {
		rc = -ENOMEM;
		goto err_free_entries;
	}

	kcxi_cq->queue_md = kcxi_md_alloc(kcxi_dom->kcxi_if, NULL, kcxi_cq->queue,
					  kcxi_cq->queue_len, 0, flags, false);
	if (IS_ERR(kcxi_cq->queue_md)) {
		rc = PTR_ERR(kcxi_cq->queue_md);
		goto err_free_queue;
	}

	eq_attr.queue = kcxi_cq->queue;
	eq_attr.queue_len = kcxi_cq->queue_len;
	eq_attr.ec_delay = 200;

	/* Once the EQ is cq_fill_percent full, a status event is generated. When a status
	 * event occurs, the kCXI CQ is considered saturated until the CXI EQ
	 * is drained.
	 */
	eq_attr.status_thresh_base = cq_fill_percent;
	eq_attr.status_thresh_delta = 0;
	eq_attr.status_thresh_count= 1;

	if (attr)
		eq_attr.cpu_affinity = attr->signaling_vector;
	if (kcxi_md_phys_mapping(kcxi_cq->queue_md))
		eq_attr.flags |= CXI_EQ_PASSTHROUGH;

	cxi_eq = cxi_eq_alloc(lni, kcxi_cq->queue_md->mapped_md, &eq_attr,
			      kcxi_cq_process_event, kcxi_cq,
			      kcxi_cq_process_event, kcxi_cq);
	if (IS_ERR(cxi_eq)) {
		rc = PTR_ERR(cxi_eq);
		goto err_free_queue_md;
	}
	kcxi_cq->eq = cxi_eq;
	kcxi_cq->armed = true;

	atomic_inc(&kcxi_dom->ref_cnt);
	INIT_WORK(&kcxi_cq->work, kcxi_cq_work_process_event);
	mutex_init(&kcxi_cq->processing_eq_lock);

	kcxi_md_cache_populate(kcxi_cq);

	CQ_DEBUG(kcxi_cq, "CQ allocated");

	return kcxi_cq;

err_free_queue_md:
	kcxi_md_free(kcxi_cq->queue_md);
err_free_queue:
	kvfree(kcxi_cq->queue);
err_free_entries:
	kcxi_cq_entries_free(kcxi_cq);
err_free_cq:
	kfree(kcxi_cq);

	return ERR_PTR(rc);
}

/**
 * kcxi_cq_open() - Open up a kfabric completion queue
 * @domain: Kfabric domain
 * @attr: CQ attributes
 * @cq: Kfabric CQ pointer to be set on success
 * @comp_handler: Kfabric user callback for CQ events/errors
 * @context: User context
 *
 * Return: 0 on success. Else, negative errno.
 */
int kcxi_cq_open(struct kfid_domain *domain, struct kfi_cq_attr *attr,
		 struct kfid_cq **cq, kfi_comp_handler comp_handler,
		 void *context)
{
	struct kcxi_domain *kcxi_dom;
	struct kcxi_cq *kcxi_cq;

	/*
	 * Domain does not need to be checked since kfabric dereferences it.
	 * NULL attr, comp_handler, and context is acceptable and handled.
	 */
	if (!cq)
		return -EINVAL;

	kcxi_dom = container_of(domain, struct kcxi_domain, dom_fid);

	kcxi_cq = kcxi_cq_alloc(kcxi_dom, attr, comp_handler, context);
	if (IS_ERR(kcxi_cq))
		return PTR_ERR(kcxi_cq);

	*cq = &kcxi_cq->cq_fid;
	return 0;
}
