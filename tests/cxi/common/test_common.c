//SPDX-License-Identifier: GPL-2.0
/*
 * Common CXI test functions.
 * Copyright 2018,2022 Hewlett Packard Enterprise Development LP
 */
#include <linux/slab.h>
#include <test_common.h>

#ifdef MODULE_NAME
#undef MODULE_NAME
#endif
#define MODULE_NAME "test_common"

/**
 * sep_resource_alloc() - Allocate a group of SEP resources
 * @opts: Allocate options
 *
 * Note: NULL pointers will be passed to the underlying kfabric allocation
 * function.
 *
 * Note: TX and RX contexts will have resources bound. Each TX and RX context
 * will have a unique CQ count to them.
 *
 * Note: If TX/RX count options is set to zero, TX and/or RX completion queues
 * and contexts will not be allocated.
 *
 * Return: Valid pointer on success. Else, kfabric errno pointer.
 */
struct sep_resource *sep_resource_alloc(const struct sep_resource_opts *opts)
{
	struct sep_resource *sep;
	void *context;
	uint64_t bind_flags;
	int i;
	int rc;

	sep = kzalloc(sizeof(*sep), GFP_KERNEL);
	if (!sep) {
		rc = -ENOMEM;
		goto err;
	}

	if (opts->node) {
		sep->node = kstrdup(opts->node, GFP_KERNEL);
		if (!sep->node) {
			rc = -ENOMEM;
			goto err_free_sep;
		}
	}

	if (opts->service) {
		sep->service = kstrdup(opts->service, GFP_KERNEL);
		if (!sep->service) {
			rc = -ENOMEM;
			goto err_free_sep;
		}
	}

	if (opts->tx_count) {
		sep->tx_cq = kcalloc(opts->tx_count, sizeof(*sep->tx_cq),
				     GFP_KERNEL);
		if (!sep->tx_cq) {
			rc = -ENOMEM;
			goto err_free_sep;
		}

		sep->tx = kcalloc(opts->tx_count, sizeof(*sep->tx), GFP_KERNEL);
		if (!sep->tx) {
			rc = -ENOMEM;
			goto err_free_sep;
		}
	}

	if (opts->rx_count) {
		sep->rx_cq = kcalloc(opts->rx_count, sizeof(*sep->rx_cq),
				     GFP_KERNEL);
		if (!sep->rx_cq) {
			rc = -ENOMEM;
			goto err_free_sep;
		}

		sep->rx = kcalloc(opts->rx_count, sizeof(*sep->rx), GFP_KERNEL);
		if (!sep->rx) {
			rc = -ENOMEM;
			goto err_free_sep;
		}
	}

	rc = kfi_getinfo_verify(0, opts->node, opts->service, KFI_SOURCE,
				opts->hints, &sep->info);
	if (rc) {
		LOG_ERR("kfi_getinfo_verify failed: rc=%d", rc);
		goto err_free_sep;
	}

	rc = kfi_fabric(sep->info->fabric_attr, &sep->fabric, sep);
	if (rc) {
		LOG_ERR("kfi_fabric failed: rc=%d", rc);
		goto err_free_info;
	}

	if (opts->dynamic_rsrc_alloc) {
		struct kfi_cxi_fabric_ops *fab_ops;

		rc = kfi_open_ops(&sep->fabric->fid, KFI_CXI_FAB_OPS_1, 0, (void**)&fab_ops, NULL);
		if (rc) {
			LOG_ERR("kfi_open_ops failed: rc=%d", rc);
			goto err_free_fabric;
		}

		rc = fab_ops->enable_dynamic_rsrc_alloc(&sep->fabric->fid, true);
		if (rc) {
			LOG_ERR("Enable dynamic resource allocation failed: rc=%d", rc);
			goto err_free_fabric;
		}
	}

	rc = kfi_eq_open(sep->fabric, opts->eq_attr, &sep->eq, opts->eq_handler,
			 opts->eq_context);
	if (rc) {
		LOG_ERR("kfi_eq_open failed: rc=%d", rc);
		goto err_free_fabric;
	}

	rc = kfi_domain(sep->fabric, sep->info, &sep->domain, sep);
	if (rc) {
		LOG_ERR("kfi_domain failed: rc=%d", rc);
		goto err_free_eq;
	}

	if (opts->async_mr_events) {
		rc = kfi_domain_bind(sep->domain, &sep->eq->fid, KFI_REG_MR);
		if (rc) {
			LOG_ERR("kfi_domain_bind failed: rc=%d", rc);
			goto err_free_domain;
		}
	}

	if (opts->av_attr->rx_ctx_bits)
		sep->rx_ctx_bits = opts->av_attr->rx_ctx_bits;

	rc = kfi_av_open(sep->domain, opts->av_attr, &sep->av, sep);
	if (rc) {
		LOG_ERR("kfi_av_open failed: rc=%d", rc);
		goto err_free_domain;
	}

	for (i = 0; i < opts->tx_count; i++) {
		if (opts->tx_cq_context)
			context = opts->tx_cq_context[i];
		else
			context = NULL;

		rc = kfi_cq_open(sep->domain, opts->tx_cq_attr, &sep->tx_cq[i],
				 opts->tx_cq_handler, context);
		if (rc) {
			LOG_ERR("kfi_cq_open failed: rc=%d", rc);
			goto err_free_tx_cq;
		}
		sep->tx_cq_count++;
	}

	for (i = 0; i < opts->rx_count; i++) {
		if (opts->rx_cq_context)
			context = opts->rx_cq_context[i];
		else
			context = NULL;

		rc = kfi_cq_open(sep->domain, opts->rx_cq_attr, &sep->rx_cq[i],
				 opts->rx_cq_handler, context);
		if (rc) {
			LOG_ERR("kfi_cq_open failed: rc=%d", rc);
			goto err_free_rx_cq;
		}
		sep->rx_cq_count++;
	}

	rc = kfi_scalable_ep(sep->domain, sep->info, &sep->sep, sep);
	if (rc) {
		LOG_ERR("kfi_scalable_ep failed: rc=%d", rc);
		goto err_free_av;
	}

	rc = kfi_scalable_ep_bind(sep->sep, &sep->av->fid, 0);
	if (rc) {
		LOG_ERR("kfi_scalable_ep_bind failed: rc=%d", rc);
		goto err_free_sep_ep;
	}

	rc  = kfi_enable(sep->sep);
	if (rc) {
		LOG_ERR("kfi_enable failed: rc=%d", rc);
		goto err_free_sep_ep;
	}

	for (i = 0; i < opts->tx_count; i++) {
		rc = kfi_tx_context(sep->sep, i, opts->tx_attr, &sep->tx[i],
				    sep);
		if (rc) {
			LOG_ERR("kfi_tx_context failed: rc=%d", rc);
			goto err_free_tx;
		}
		sep->tx_count++;

		bind_flags = 0;
		if (opts->tx_selective_completion)
			bind_flags |= KFI_SELECTIVE_COMPLETION;

		rc = kfi_ep_bind(sep->tx[i], &sep->tx_cq[i]->fid, bind_flags);
		if (rc) {
			LOG_ERR("kfi_ep_bind failed: rc=%d", rc);
			goto err_free_tx;
		}

		rc  = kfi_enable(sep->tx[i]);
		if (rc) {
			LOG_ERR("kfi_enable failed: rc=%d", rc);
			goto err_free_tx;
		}
	}

	for (i = 0; i < opts->rx_count; i++) {
		rc = kfi_rx_context(sep->sep, i, opts->rx_attr, &sep->rx[i],
				    sep);
		if (rc) {
			LOG_ERR("kfi_rx_context failed: rc=%d", rc);
			goto err_free_rx;
		}
		sep->rx_count++;

		bind_flags = 0;
		if (opts->rx_selective_completion)
			bind_flags |= KFI_SELECTIVE_COMPLETION;

		rc = kfi_ep_bind(sep->rx[i], &sep->rx_cq[i]->fid, bind_flags);
		if (rc) {
			LOG_ERR("kfi_ep_bind failed: rc=%d", rc);
			goto err_free_tx;
		}

		rc  = kfi_enable(sep->rx[i]);
		if (rc) {
			LOG_ERR("kfi_enable failed: rc=%d", rc);
			goto err_free_tx;
		}
	}

	return sep;

err_free_rx:
	for (i = 0; i < sep->rx_count; i++)
		kfi_close(&sep->rx[i]->fid);
err_free_tx:
	for (i = 0; i < sep->tx_count; i++)
		kfi_close(&sep->tx[i]->fid);
err_free_sep_ep:
	kfi_close(&sep->sep->fid);
err_free_rx_cq:
	for (i = 0; i < sep->rx_cq_count; i++)
		kfi_close(&sep->rx_cq[i]->fid);
err_free_tx_cq:
	for (i = 0; i < sep->tx_cq_count; i++)
		kfi_close(&sep->tx_cq[i]->fid);
err_free_av:
	kfi_close(&sep->av->fid);
err_free_domain:
	kfi_close(&sep->domain->fid);
err_free_eq:
	kfi_close(&sep->eq->fid);
err_free_fabric:
	kfi_close(&sep->fabric->fid);
err_free_info:
	kfi_freeinfo(sep->info);
err_free_sep:
	kfree(sep->rx);
	kfree(sep->tx);
	kfree(sep->rx_cq);
	kfree(sep->tx_cq);
	kfree(sep->service);
	kfree(sep->node);
	kfree(sep);
err:
	return ERR_PTR(rc);
}

/**
 * sep_resource_free() - Free SEP resource
 * @sep: SEP resource
 *
 * Return: 0 on success. Else, kfabric negative errno.
 */
int sep_resource_free(struct sep_resource *sep)
{
	int rc;

	for (; sep->rx_count > 0; sep->rx_count--) {
		rc = kfi_close(&sep->rx[sep->rx_count - 1]->fid);
		if (rc) {
			LOG_ERR("Failed to close RX context: rc=%d", rc);
			return rc;
		}

		sep->rx[sep->rx_count - 1] = NULL;
	}

	for (; sep->tx_count > 0; sep->tx_count--) {
		rc = kfi_close(&sep->tx[sep->tx_count - 1]->fid);
		if (rc) {
			LOG_ERR("Failed to close TX context: rc=%d", rc);
			return rc;
		}

		sep->tx[sep->tx_count - 1] = NULL;
	}

	if (sep->sep) {
		rc = kfi_close(&sep->sep->fid);
		if (rc) {
			LOG_ERR("Failed to close SEP: rc=%d", rc);
			return rc;
		}

		sep->sep = NULL;
	}

	for (; sep->rx_cq_count > 0; sep->rx_cq_count--) {
		rc = kfi_close(&sep->rx_cq[sep->rx_cq_count - 1]->fid);
		if (rc) {
			LOG_ERR("Failed to close RX CQ: rc=%d", rc);
			return rc;
		}

		sep->rx_cq[sep->rx_cq_count - 1] = NULL;
	}

	for (; sep->tx_cq_count > 0; sep->tx_cq_count--) {
		rc = kfi_close(&sep->tx_cq[sep->tx_cq_count - 1]->fid);
		if (rc) {
			LOG_ERR("Failed to close TX CQ: rc=%d", rc);
			return rc;
		}

		sep->tx_cq[sep->tx_cq_count - 1] = NULL;
	}

	if (sep->av) {
		rc = kfi_close(&sep->av->fid);
		if (rc) {
			LOG_ERR("Failed to close AV: rc=%d", rc);
			return rc;
		}

		sep->av = NULL;
	}

	if (sep->domain) {
		rc = kfi_close(&sep->domain->fid);
		if (rc) {
			LOG_ERR("Failed to close domain: rc=%d", rc);
			return rc;
		}

		sep->domain = NULL;
	}

	if (sep->eq) {
		rc = kfi_close(&sep->eq->fid);
		if (rc) {
			LOG_ERR("Failed to close EQ: rc=%d", rc);
			return rc;
		}

		sep->eq = NULL;
	}

	if (sep->fabric) {
		rc = kfi_close(&sep->fabric->fid);
		if (rc) {
			LOG_ERR("Failed to close fabric: rc=%d", rc);
			return rc;
		}

		sep->fabric = NULL;
	}

	if (sep->info) {
		kfi_freeinfo(sep->info);
		sep->info = NULL;
	}

	kfree(sep->rx);
	kfree(sep->tx);
	kfree(sep->rx_cq);
	kfree(sep->tx_cq);
	kfree(sep->service);
	kfree(sep->node);
	kfree(sep);

	return 0;
}

/**
 * struct sep_res_loopback - Allocate loopback resources for SEP resource
 * @res: SEP resource
 *
 * The RX array is symmetric to the RX context array in SEP resource.
 *
 * Return: Valid pointer on success. Else, negative errno pointer.
 */
struct sep_res_loopback *sep_res_loopback_alloc(struct sep_resource *res)
{

	int rc;
	int i;
	struct sep_res_loopback *loopback;
	kfi_addr_t base_addr;

	if (!res) {
		LOG_ERR("SEP resource group NULL");
		rc = -EINVAL;
		goto err;
	}

	if (res->rx_ctx_bits < 0) {
		LOG_ERR("rx_ctx_bits cannot be negative");
		rc = -EINVAL;
		goto err;
	}

	if ((1 << res->rx_ctx_bits) < res->rx_count) {
		LOG_ERR("Not enough RX bits for local RX contexts");
		rc = -EINVAL;
		goto err;
	}

	loopback = kzalloc(sizeof(*loopback), GFP_KERNEL);
	if (!loopback) {
		LOG_ERR("Failed to allocate loopback structure");
		rc = -ENOMEM;
		goto err;
	}

	if (res->rx_count) {
		loopback->rx_addr = kcalloc(res->rx_count,
					    sizeof(*loopback->rx_addr),
					    GFP_KERNEL);
		if (!loopback->rx_addr) {
			LOG_ERR("Failed to allocate loopback RX array");
			rc = -ENOMEM;
			goto err_free_loopback;
		}
	}
	loopback->rx_count = res->rx_count;

	rc = kfi_av_insertsvc(res->av, res->node, res->service, &base_addr, 0,
			      NULL);
	if (rc != 1) {
		LOG_ERR("kfi_av_insertsvc failed: rc=%d", rc);
		goto err_free_rx_array;
	}

	loopback->mr_addr = base_addr;

	for (i = 0; i < loopback->rx_count; i++) {
		loopback->rx_addr[i] = kfi_rx_addr(base_addr, i,
						   res->rx_ctx_bits);
	}

	return loopback;

err_free_rx_array:
	kfree(loopback->rx_addr);
err_free_loopback:
	kfree(loopback);
err:
	return ERR_PTR(rc);
}

/**
 * void sep_res_loopback_free() - Free a loopback structure
 * @loopback: Loopback structure
 */
void sep_res_loopback_free(struct sep_res_loopback *loopback)
{
	if (!loopback)
		return;

	kfree(loopback->rx_addr);
	kfree(loopback);
}

/**
 * mr_enable() - Bind a MR to an endpoint and enable.
 * @sep: SEP
 * @mr: User memory region
 *
 * Note: If domain is setup for async MRs, an event will occur on the EQ if this
 * function is successful.
 *
 * Return: 0 on success. Else, kfabric negative errno.
 */
int mr_enable(struct kfid_ep *sep, struct kfid_mr *mr)
{
	int rc;

	if (!sep || !mr)
		return -EINVAL;

	rc = kfi_mr_bind(mr, &sep->fid, 0);
	if (rc) {
		LOG_ERR("kfi_mr_bind failed: rc=%d", rc);
		return rc;
	}

	/* Verify that SEP cannot be closed once bound to MR. */
	rc = kfi_close(&sep->fid);
	if (!rc) {
		LOG_ERR("SEP should not have been able to be closed");
		return rc;
	}

	rc = kfi_mr_enable(mr);
	if (rc) {
		LOG_ERR("kfi_mr_enable failed: rc=%d", rc);
		return rc;
	}

	return 0;
}

/**
 * verify_first_cq_entry() - Pop the first element of CQ and compare the entry
 * @CQ: Completion queue
 * @comp_event: Pointer to compare event entry
 * @comp_event: Format of compare event entry
 *
 * Note: This function will NOT process errors.
 *
 * Return: 0 if the first element matches the compare event. Else, kfabric
 * negative errno.
 */
int verify_first_cq_entry(struct kfid_cq *cq, void *comp_event,
			  enum kfi_cq_format comp_format)
{
	struct kfi_cq_tagged_entry *cevent = comp_event;
	struct kfi_cq_tagged_entry event;
	int rc;

	if (!comp_event) {
		LOG_ERR("Compare event NULL");
		return -EINVAL;
	}

	/* Only support KFI_CQ_FORMAT_TAGGED for now. */
	if (comp_format != KFI_CQ_FORMAT_TAGGED) {
		LOG_ERR("Unsupported CQ verify format type: comp_event=%u",
			comp_format);
		return -ENOSYS;
	}

	rc = kfi_cq_read(cq, &event, 1);
	if (rc != 1) {
		LOG_ERR("Failed to read event from CQ: rc=%d", rc);
		return rc;
	}

	if (event.op_context != cevent->op_context) {
		LOG_ERR("CQ OP context does not match: expected=%pK got=%pK",
			cevent->op_context, event.op_context);
		return -EINVAL;
	}

	if (event.flags != cevent->flags) {
		LOG_ERR("CQ flags do not match: expected=%llu got=%llu",
			cevent->flags, event.flags);
		return -EINVAL;
	}

	if (event.len != cevent->len) {
		LOG_ERR("CQ length does not match: expected=%lu got=%lu",
			cevent->len, event.len);
		return -EINVAL;
	}

	if (event.buf != cevent->buf) {
		LOG_ERR("CQ buffer does not match: expected=%pK got=%pK",
			cevent->buf, event.buf);
		return -EINVAL;
	}

	if (event.data != cevent->data) {
		LOG_ERR("CQ data does not match: expected=%llu got=%llu",
			cevent->data, event.data);
		return -EINVAL;
	}

	if (event.tag != cevent->tag) {
		LOG_ERR("CQ tag does not match: expected=%llu got=%llu",
			cevent->tag, event.tag);
		return -EINVAL;
	}

	return 0;
}

/**
 * verify_first_cq_error() - Pop the first error of CQ and compare the error
 * @CQ: Completion queue
 * @cerror: Comparison error
 *
 * Note: This function will NOT process events.
 *
 * Return: 0 if the first error matches the compare error. Else, kfabric
 * negative errno.
 */
int verify_first_cq_error(struct kfid_cq *cq, struct kfi_cq_err_entry *cerror)
{
	struct kfi_cq_err_entry error = {};
	int rc;

	rc = kfi_cq_readerr(cq, &error, 0);
	if (rc != 1) {
		LOG_ERR("Failed to read error from CQ: rc=%d", rc);
		return rc;
	}

	if (error.op_context != cerror->op_context) {
		LOG_ERR("CQ OP context does not match: expected=%pK got=%pK",
			cerror->op_context, error.op_context);
		return -EINVAL;
	}

	if (error.flags != cerror->flags) {
		LOG_ERR("CQ flags does not match: expected=%llx got=%llx",
			cerror->flags, error.flags);
		return -EINVAL;
	}

	if (error.len != cerror->len) {
		LOG_ERR("CQ len does not match: expected=%lu got=%lu",
			cerror->len, error.len);
		return -EINVAL;
	}

	if (error.buf != cerror->buf) {
		LOG_ERR("CQ buf does not match: expected=%pK got=%pK",
			cerror->buf, error.buf);
		return -EINVAL;
	}

	if (error.data != cerror->data) {
		LOG_ERR("CQ data does not match: expected=%llx got=%llx",
			cerror->data, error.data);
		return -EINVAL;
	}

	if (error.tag != cerror->tag) {
		LOG_ERR("CQ tag does not match: expected=%llx got=%llx",
			cerror->tag, error.tag);
		return -EINVAL;
	}

	if (error.olen != cerror->olen) {
		LOG_ERR("CQ olen does not match: expected=%lu got=%lu",
			cerror->olen, error.olen);
		return -EINVAL;
	}

	if (error.err != cerror->err) {
		LOG_ERR("CQ err does not match: expected=%d got=%d",
			cerror->err, error.err);
		return -EINVAL;
	}

	if (error.prov_errno != cerror->prov_errno) {
		LOG_ERR("CQ prov_errno does not match: expected=%d got=%d",
			cerror->prov_errno, error.prov_errno);
		return -EINVAL;
	}

	if (error.err_data != cerror->err_data) {
		LOG_ERR("CQ err_data does not match: expected=%pK got=%pK",
			cerror->err_data, error.err_data);
		return -EINVAL;
	}

	if (error.err_data_size != cerror->err_data_size) {
		LOG_ERR("CQ err_data_size does not match: expected=%lu got=%lu",
			cerror->err_data_size, error.err_data_size);
		return -EINVAL;
	}

	return 0;
}

/**
 * verify_data() - Verify data between two buffers
 * @a: Buffer a
 * @b: Buffer b
 * @byte_count: Number of bytes to compare
 *
 * Return: -1 on success. Else, byte where data miscompare occurred.
 */
int verify_data(uint8_t *a, uint8_t *b, size_t byte_count)
{
	int i;

	for (i = 0; i < byte_count; i++) {
		if (a[i] != b[i]) {
			LOG_ERR("Data miscompare: byte=%d", i);
			return i;
		}
	}

	return -1;
}

/**
 * verify_data_iov() - Verify data between two buffers
 * @a: Buffer a
 * @b: Buffer b
 * @count: Number of kvecs
 *
 * Return: -1 on success. Else, byte where data miscompare occurred.
 */
int verify_data_iov(uint8_t *a, struct kvec *b, size_t count)
{
	int i;
	int j;
	size_t cur_byte = 0;
	uint8_t *cmp;

	for (i = 0; i < count; i++) {
		cmp = b[i].iov_base;
		for (j = 0; j < b[i].iov_len; j++, cur_byte++) {
			if (a[cur_byte] != cmp[j]) {
				LOG_ERR("Data miscompare: byte=%lu", cur_byte);
				return cur_byte;
			}
		}
	}

	return -1;
}

/**
 * verify_data_biov() - Verify data between two buffers
 * @a: Buffer a
 * @b: Buffer b
 * @count: Number of bvecs
 *
 * Return: -1 on success. Else, byte where data miscompare occurred.
 */
int verify_data_biov(uint8_t *a, struct bio_vec *b, size_t count)
{
	int i;
	int j;
	size_t cur_byte = 0;
	uint8_t *cmp;

	for (i = 0; i < count; i++) {
		cmp = page_to_virt(b[i].bv_page) + b[i].bv_offset;
		for (j = 0; j < b[i].bv_len; j++, cur_byte++) {
			if (a[cur_byte] != cmp[j]) {
				LOG_ERR("Data miscompare: byte=%lu", cur_byte);
				return cur_byte;
			}
		}
	}

	return -1;
}

static int verify_info_caps(struct kfi_info *info)
{
	if (info->tx_attr->caps & ~info->caps)
		return -EINVAL;
	if (info->rx_attr->caps & ~info->caps)
		return -EINVAL;
	if (info->domain_attr->caps & ~info->caps)
		return -EINVAL;
	return 0;
}

/**
 * kfi_getinfo_verify() - Run kfi_getinfo() with verification checks
 * @version: Version
 * @node: Node
 * @service: Service
 * @flags: Flags
 * @hints: Hints
 * @info: Info
 *
 * Return: 0 and info set on success. Else, kfabric negative errno.
 */
int kfi_getinfo_verify(uint32_t version, const char *node, const char *service,
		       uint64_t flags, struct kfi_info *hints,
		       struct kfi_info **info)
{
	int rc;

	rc = kfi_getinfo(version, node, service, flags, hints, info);
	if (rc) {
		LOG_ERR("kfi_getinfo failed: rc=%d", rc);
		return rc;
	}

	if (!*info) {
		LOG_ERR("kfi_getinfo returned NULL");
		return -EINVAL;
	}

	rc = verify_info_caps(*info);
	if (rc) {
		LOG_ERR("kfi_getinfo returned bad CAPS attributes");
		return -EINVAL;
	}

	return 0;
}

void free_iov(struct kvec *iov, size_t count)
{
	int i;

	for (i = 0; i < count; i++)
		kfree(iov[i].iov_base);
	kfree(iov);
}

/* Allocate a kvec where all IOVs start and end at a page. */
struct kvec *alloc_iov(size_t len, size_t *count)
{
	size_t iov_count = 0;
	size_t iov_size;
	struct kvec *iov;
	size_t nob;
	int i;

	iov_count = max_t(size_t, 1, len / PAGE_SIZE);
	iov_size = PAGE_SIZE;

	iov = kcalloc(iov_count, sizeof(*iov), GFP_KERNEL);
	if (!iov) {
		LOG_ERR("Failed to allocate IOV array");
		return NULL;
	}

	nob = len;
	for (i = 0; i < iov_count; i++) {
		if (i == (iov_count - 1))
			iov[i].iov_len = nob;
		else
			iov[i].iov_len = iov_size;

		iov[i].iov_base = kzalloc(iov[i].iov_len, GFP_KERNEL);
		if (!iov[i].iov_base) {
			LOG_ERR("Failed to allocate IOV");
			goto err_free_iov;
		}

		nob -= iov[i].iov_len;
	}

	for (i = 0; i < iov_count; i++)
		LOG_INFO("kvec %d size=%lu", i, iov[i].iov_len);

	*count = iov_count;
	return iov;

err_free_iov:
	for (i = 0; i < iov_count; i++)
		kfree(iov[i].iov_base);
	kfree(iov);

	return NULL;
}

void free_biov(struct bio_vec *biov, size_t count)
{
	int i;

	for (i = 0; i < count; i++)
		__free_page(biov[i].bv_page);
	kfree(biov);
}

struct bio_vec *alloc_biov(size_t len, size_t *count, bool first_page_offset)
{
	int i;
	size_t iov_count;
	struct bio_vec *biov;
	size_t nob;

	/* Setup the bvec. */
	iov_count = DIV_ROUND_UP(len, PAGE_SIZE);
	biov = kcalloc(iov_count, sizeof(*biov), GFP_KERNEL);
	if (!biov) {
		LOG_ERR("Failed to allocate BIOV array");
		return NULL;
	}

	nob = len;
	if (first_page_offset) {
		for (i = iov_count - 1; i >= 0; i--) {
			biov[i].bv_page = alloc_page(GFP_KERNEL | __GFP_ZERO);
			if (!biov[i].bv_page) {
				LOG_ERR("Failed to allocate BIOV");
				goto err_free_biov;
			}
			biov[i].bv_len = min_t(unsigned int, PAGE_SIZE, nob);
			biov[i].bv_offset = PAGE_SIZE - biov[i].bv_len;
			nob -= biov[i].bv_len;
		}
	} else {
		for (i = 0; i < iov_count; i++) {
			biov[i].bv_page = alloc_page(GFP_KERNEL | __GFP_ZERO);
			if (!biov[i].bv_page) {
				LOG_ERR("Failed to allocate BIOV");
				goto err_free_biov;
			}
			biov[i].bv_offset = 0;
			biov[i].bv_len = min_t(unsigned int, PAGE_SIZE, nob);
			nob -= biov[i].bv_len;
		}
	}

	for (i = 0; i < iov_count; i++)
		LOG_INFO("bvec %d size=%u", i, biov[i].bv_len);

	*count = iov_count;
	return biov;

err_free_biov:
	for (i = 0; i < iov_count; i++) {
		if (biov[i].bv_page)
			__free_page(biov[i].bv_page);
	}
	kfree(biov);

	return NULL;
}
