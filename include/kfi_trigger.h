/*
 * Copyright (c) 2016 Intel Corporation. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef _KFI_TRIGGER_H_
#define _KFI_TRIGGER_H_

#include <kfabric.h>
#include <kfi_tagged.h>
#include <kfi_rma.h>
#include <kfi_atomic.h>

enum kfi_trigger_event {
	KFI_TRIGGER_THRESHOLD,
};

enum kfi_op_type {
	KFI_OP_RECV,
	KFI_OP_SEND,
	KFI_OP_TRECV,
	KFI_OP_TSEND,
	KFI_OP_READ,
	KFI_OP_WRITE,
	KFI_OP_ATOMIC,
	KFI_OP_FETCH_ATOMIC,
	KFI_OP_COMPARE_ATOMIC,
	KFI_OP_CNTR_SET,
	KFI_OP_CNTR_ADD
};

struct kfi_trigger_threshold {
	struct kfid_cntr	*cntr;
	size_t			threshold;
};

struct kfi_op_msg {
	struct kfid_ep		*ep;
	struct kfi_msg		msg;
	uint64_t		flags;
};

struct kfi_op_tagged {
	struct kfid_ep          *ep;
	struct kfi_msg_tagged	msg;
	uint64_t		flags;
};

struct kfi_op_rma {
	struct kfid_ep          *ep;
	struct kfi_msg_rma	msg;
	uint64_t		flags;
};

struct kfi_op_atomic {
	struct kfid_ep          *ep;
	struct kfi_msg_atomic	msg;
	uint64_t		flags;
};

struct kfi_op_fetch_atomic {
	struct kfid_ep          *ep;
	struct kfi_msg_atomic	msg;
	struct kfi_msg_fetch	fetch;
	uint64_t		flags;
};

struct kfi_op_cntr {
	struct kfid_cntr	*cntr;
	uint64_t		value;
};

#ifndef KFABRIC_DIRECT

/* Size must match struct kfi_context */
struct kfi_triggered_context {
	enum kfi_trigger_event			event_type;
	union {
		struct kfi_trigger_threshold	threshold;
		void				*internal[3];
	} trigger;
};

/* Size must match struct kfi_context2 */
struct kfi_triggered_context2 {
	enum kfi_trigger_event			event_type;
	union {
		struct kfi_trigger_threshold	threshold;
		void				*internal[7];
	} trigger;
};

struct kfi_deferred_work {
	struct kfi_context2			context;
	uint64_t				threshold;
	struct kfid_cntr			*triggering_cntr;
	struct kfid_cntr			*completion_cntr;
	enum kfi_op_type			op_type;
	union {
		struct kfi_op_msg		*msg;
		struct kfi_op_tagged		*tagged;
		struct kfi_op_rma		*rma;
		struct kfi_op_atomic		*atomic;
		struct kfi_op_fetch_atomic	*fetch_atomic;
		struct kfi_op_compare_atomic	*compare_atomic;
		struct kfi_op_cntr		*cntr;
	} op;
};

#else /* KFABRIC_DIRECT */
#include <kfi_direct_trigger.h>
#endif


#endif /* _KFI_TRIGGER_H_ */
