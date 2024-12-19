/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Common CXI test header.
 * Copyright 2018-2024 Hewlett Packard Enterprise Development LP
 */

#ifndef _TEST_COMMON_
#define _TEST_COMMON_

#include <kfabric.h>
#include <kfi_cxi_ext.h>
#include <kfi_log.h>
#include <kfi_domain.h>
#include <kfi_endpoint.h>
#include <linux/uio.h>
#include <linux/bvec.h>
#include <linux/mm.h>

/**
 * struct sep_resource - sep resource group
 * @node: Node for SEP resource
 * @service: Service for SEP resource
 * @info: info used to allocate various objects
 * @fabric: fabric object
 * @eq: event queue object
 * @domain: domain object
 * @av: address vector object
 * @tx_cq: tx completion queue array
 * @rx_cq: rx completion queue array
 * @sep: scalable endpoint object
 * @tx: tx context array
 * @rx: rx context array
 * @tx_cq_count: number of allocated tx completion queues
 * @rx_cq_count: number of allocated rx completion queues
 * @tx_count: number of allocated tx contexts
 * @rx_count: number of allocated rx contexts
 * @rx_ctx_bits: RX context bits
 */
struct sep_resource {
	char *node;
	char *service;
	struct kfi_info *info;
	struct kfid_fabric *fabric;
	struct kfid_eq *eq;
	struct kfid_domain *domain;
	struct kfid_av *av;
	struct kfid_cq **tx_cq;
	struct kfid_cq **rx_cq;
	struct kfid_ep *sep;
	struct kfid_ep **tx;
	struct kfid_ep **rx;
	size_t tx_cq_count;
	size_t rx_cq_count;
	size_t tx_count;
	size_t rx_count;
	int rx_ctx_bits;
	struct device *device;
};

/**
 * struct sep_resource_opts - sep resource options
 * @node: node string passed to kfi_getinfo (can be null)
 * @service: service string passed to kfi_getinfo(can be null)
 * @hints: hints passed to kfi_getinfo (can be null)
 * @eq_attr: event queue attributes (can be null)
 * @av_attr: address vector attributes (can be null)
 * @tx_cq_attr: tx completion queue attributes (can be null)
 * @rx_cq_attr: rx completion queue attributes (can be null)
 * @tx_attr: tx context attributes (can be null)
 * @rx_attr: rx context attributes (can be null)
 * @eq_handler: EQ callback
 * @eq_context: EQ context
 * @tx_cq_handler: tx completion queue callback
 * @rx_cq_handler: rx completion queue callback
 * @tx_cq_context: Array of TX CQ contexts (size is equal to tx_count)
 * @rx_cq_context: Array of RX CQ contexts (size is equal to rx_count)
 * @async_mr_events: async mr events (kfi_reg_mr)
 * @tx_selective_completion: tx selective completion (kfi_selective_completion)
 * @rx_selective_completion: rx selective completion (kfi_selective_completion)
 * @tx_count: number of tx contexts
 * @rx_count: number of rx contexts
 */
struct sep_resource_opts {
	char *node;
	char *service;
	struct kfi_info *hints;
	struct kfi_eq_attr *eq_attr;
	struct kfi_av_attr *av_attr;
	struct kfi_cq_attr *tx_cq_attr;
	struct kfi_cq_attr *rx_cq_attr;
	struct kfi_tx_attr *tx_attr;
	struct kfi_rx_attr *rx_attr;
	kfi_event_handler eq_handler;
	void *eq_context;
	kfi_comp_handler tx_cq_handler;
	kfi_comp_handler rx_cq_handler;
	void **tx_cq_context;
	void **rx_cq_context;
	bool async_mr_events;
	bool tx_selective_completion;
	bool rx_selective_completion;
	size_t tx_count;
	size_t rx_count;
	bool dynamic_rsrc_alloc;
};

/**
 * struct sep_res_loopback - Loopback address for a SEP resource
 * @mr_addr: MR address
 * @rx_addr: Array of RX addresses
 * @rx_count: Size of RX array
 */
struct sep_res_loopback {
	kfi_addr_t mr_addr;
	kfi_addr_t *rx_addr;
	size_t rx_count;
};

struct sep_resource *sep_resource_alloc(const struct sep_resource_opts *opts);
int sep_resource_free(struct sep_resource *sep);
struct sep_res_loopback *sep_res_loopback_alloc(struct sep_resource *res);
void sep_res_loopback_free(struct sep_res_loopback *loopback);
int mr_enable(struct kfid_ep *sep, struct kfid_mr *mr);
int verify_first_cq_entry(struct kfid_cq *cq, void *comp_event,
			  enum kfi_cq_format comp_format);
int verify_first_cq_error(struct kfid_cq *cq, struct kfi_cq_err_entry *cerror);
int verify_data(uint8_t *a, uint8_t *b, size_t byte_count);
int verify_data_iov(uint8_t *a, struct kvec *b, size_t count);
int verify_data_biov(uint8_t *a, struct bio_vec *b, size_t count);
int kfi_getinfo_verify(uint32_t version, const char *node, const char *service,
		       uint64_t flags, struct kfi_info *hints,
		       struct kfi_info **info);
void free_iov(struct kvec *iov, size_t count);
struct kvec *alloc_iov(size_t len, size_t *count);
void free_biov(struct bio_vec *biov, size_t count);
struct bio_vec *alloc_biov(size_t len, size_t *count, bool first_page_offset);

#endif /* _TEST_COMMON_ */
