// SPDX-License-Identifier: GPL-2.0
/*
 * Kfabric fabric tests.
 * Copyright 2018 Cray Inc. All Rights Reserved.
 */
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <kfabric.h>
#include <kfi_log.h>
#include <kfi_eq.h>
#include <kfi_domain.h>
#include <linux/slab.h>

#include "../../../prov/cxi/kcxi_prov.h"

#ifdef MODULE_NAME
#undef MODULE_NAME
#endif
#define MODULE_NAME "test_cq"

MODULE_AUTHOR("Ian Ziemba");
MODULE_DESCRIPTION("kfabric CXI CQ tests");
MODULE_LICENSE("GPL v2");

static struct kfi_info *info;
static struct kfi_info *hints;
static struct kfid_fabric *fabric;
static struct kfid_domain *domain;

static int verify_info_attrs(struct kfi_info *info)
{
	if (info->tx_attr->caps & ~info->caps)
		return -EINVAL;
	if (info->rx_attr->caps & ~info->caps)
		return -EINVAL;
	if (info->domain_attr->caps & ~info->caps)
		return -EINVAL;
	return 0;
}

static int kfi_getinfo_success(uint32_t version, const char *node,
			       const char *service, uint64_t flags,
			       struct kfi_info *hints, struct kfi_info **info)
{
	int rc;

	rc = kfi_getinfo(version, node, service, flags, hints, info);
	if (rc) {
		LOG_ERR("kfi_getinfo() did not return 0");
		return -EINVAL;
	}

	if (!*info) {
		LOG_ERR("kfi_getinfo() returned NULL");
		return -EINVAL;
	}

	rc = verify_info_attrs(*info);
	if (rc) {
		LOG_ERR("kfi_getinfo() returned bad info");
		return -EINVAL;
	}

	return 0;
}

static int test_init(void)
{
	int rc = 0;

	hints = kfi_allocinfo();
	if (!hints) {
		LOG_ERR("Failed to allocate info structure");
		rc = -ENOMEM;
		goto out;
	}
	hints->caps = (KFI_MSG | KFI_RMA | KFI_SEND | KFI_RECV | KFI_READ |
		       KFI_WRITE | KFI_REMOTE_READ | KFI_REMOTE_WRITE |
		       KFI_MULTI_RECV | KFI_RMA_EVENT | KFI_REMOTE_COMM);

	rc = kfi_getinfo_success(0, NULL, NULL, KFI_SOURCE,  hints, &info);
	if (rc) {
		LOG_ERR("Failed to check fabric info");
		goto out;
	}

	rc = kfi_fabric(info->fabric_attr, &fabric, NULL);
	if (rc) {
		LOG_ERR("Failed to create fabric object");
		goto out;
	}

	rc = kfi_domain(fabric, info, &domain, NULL);
	if (rc) {
		LOG_ERR("Failed to create domain object");
		goto close_fabric;
	}

	return 0;

close_fabric:
	kfi_close(&fabric->fid);
out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;

}

static int test_open_close_cq(int id)
{
	struct kfid_cq *cq;
	struct kfi_cq_attr attr = {};
	int rc;

	attr.size = 50;
	attr.format = KFI_CQ_FORMAT_DATA;

	rc = kfi_cq_open(domain, &attr, &cq, NULL, NULL);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unable to open cq", id, __func__);
		return rc;
	}

	rc = kfi_close(&cq->fid);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unable to close cq", id, __func__);
		return rc;
	}

	LOG_INFO("TEST %d %s PASSED", id, __func__);
	return 0;
}

static int test_premature_domain_close(int id)
{
	struct kfid_cq *cq;
	struct kfi_cq_attr attr = {};
	int rc;
	int exit_rc = 0;

	attr.size = 50;
	attr.format = KFI_CQ_FORMAT_DATA;

	rc = kfi_cq_open(domain, &attr, &cq, NULL, NULL);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unable to open cq", id, __func__);
		return rc;
	}

	rc = kfi_close(&domain->fid);
	if (!rc) {
		LOG_ERR("TEST %d %s FAILED: Domain shouldn't close", id,
			__func__);
		exit_rc = -EINVAL;
	}

	rc = kfi_close(&cq->fid);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unable to close cq", id, __func__);
		return rc;
	}

	if (!exit_rc)
		LOG_INFO("TEST %d %s PASSED", id, __func__);

	return exit_rc;
}

static int test_single_event_fmt_context(int id)
{
	struct kfid_cq *cq;
	struct kfi_cq_attr attr = {};
	struct kfi_cq_entry entry;
	struct kcxi_cq *kcxi_cq;
	struct kcxi_req_state kcxi_req;
	uint64_t flags;
	int rc;
	int exit_rc = 0;

	attr.size = 1;
	attr.format = KFI_CQ_FORMAT_CONTEXT;

	rc = kfi_cq_open(domain, &attr, &cq, NULL, NULL);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unable to open cq", id, __func__);
		return rc;
	}

	kcxi_cq = container_of(cq, struct kcxi_cq, cq_fid);

	flags = (KFI_MSG | KFI_SEND);
	kcxi_req.context = &exit_rc;
	kcxi_req.flags = flags;

	rc = kcxi_cq->report_completion(kcxi_cq, KFI_ADDR_NOTAVAIL, &kcxi_req);
	if (rc < 0) {
		LOG_ERR("TEST %d %s FAILED: Unable to write completion", id,
			__func__);
		exit_rc = rc;
		goto out;
	}

	rc = kfi_cq_read(cq, &entry, 1);
	if (rc < 0) {
		LOG_ERR("TEST %d %s FAILED: Unable to read cq", id, __func__);
		exit_rc = rc;
		goto out;
	}

	if (entry.op_context != &exit_rc) {
		LOG_ERR("TEST %d %s FAILED: Bad operation context", id,
			__func__);
		exit_rc = -EINVAL;
		goto out;
	}

out:
	rc = kfi_close(&cq->fid);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unable to close cq", id, __func__);
		return rc;
	}

	if (!exit_rc)
		LOG_INFO("TEST %d %s PASSED", id, __func__);

	return exit_rc;
}

static int test_single_event_fmt_msg(int id)
{
	struct kfid_cq *cq;
	struct kfi_cq_attr attr = {};
	struct kfi_cq_msg_entry msg_entry;
	struct kcxi_cq *kcxi_cq;
	struct kcxi_req_state kcxi_req;
	uint64_t flags;
	int rc;
	int exit_rc = 0;

	attr.size = 1;
	attr.format = KFI_CQ_FORMAT_MSG;

	rc = kfi_cq_open(domain, &attr, &cq, NULL, NULL);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unable to open cq", id, __func__);
		return rc;
	}

	kcxi_cq = container_of(cq, struct kcxi_cq, cq_fid);

	flags = (KFI_MSG | KFI_SEND);
	kcxi_req.context = &exit_rc;
	kcxi_req.flags = flags;

	rc = kcxi_cq->report_completion(kcxi_cq, KFI_ADDR_NOTAVAIL, &kcxi_req);
	if (rc < 0) {
		LOG_ERR("TEST %d %s FAILED: Unable to write completion", id,
			__func__);
		exit_rc = rc;
		goto out;
	}

	rc = kfi_cq_read(cq, &msg_entry, 1);
	if (rc < 0) {
		LOG_ERR("TEST %d %s FAILED: Unable to read cq", id, __func__);
		exit_rc = rc;
		goto out;
	}

	if (msg_entry.op_context != &exit_rc) {
		LOG_ERR("TEST %d %s FAILED: Bad operation context", id,
			__func__);
		exit_rc = -EINVAL;
		goto out;
	}

	if (msg_entry.flags != flags) {
		LOG_ERR("TEST %d %s FAILED: Bad data entry flags", id,
			__func__);
		exit_rc = -EINVAL;
		goto out;
	}

out:
	rc = kfi_close(&cq->fid);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unable to close cq", id, __func__);
		return rc;
	}

	if (!exit_rc)
		LOG_INFO("TEST %d %s PASSED", id, __func__);

	return exit_rc;
}

static int test_single_event_fmt_data(int id)
{
	struct kfid_cq *cq;
	struct kfi_cq_attr attr = {};
	struct kfi_cq_data_entry data_entry;
	struct kcxi_cq *kcxi_cq;
	struct kcxi_req_state kcxi_req;
	uint64_t flags;
	int rc;
	int exit_rc = 0;

	attr.size = 1;
	attr.format = KFI_CQ_FORMAT_DATA;

	rc = kfi_cq_open(domain, &attr, &cq, NULL, NULL);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unable to open cq", id, __func__);
		return rc;
	}

	kcxi_cq = container_of(cq, struct kcxi_cq, cq_fid);

	flags = (KFI_MSG | KFI_SEND);
	kcxi_req.context = &exit_rc;
	kcxi_req.flags = flags;

	rc = kcxi_cq->report_completion(kcxi_cq, KFI_ADDR_NOTAVAIL, &kcxi_req);
	if (rc < 0) {
		LOG_ERR("TEST %d %s FAILED: Unable to write completion", id,
			__func__);
		exit_rc = rc;
		goto out;
	}

	rc = kfi_cq_read(cq, &data_entry, 1);
	if (rc < 0) {
		LOG_ERR("TEST %d %s FAILED: Unable to read cq", id, __func__);
		exit_rc = rc;
		goto out;
	}

	if (data_entry.op_context != &exit_rc) {
		LOG_ERR("TEST %d %s FAILED: Bad operation context", id,
			__func__);
		exit_rc = -EINVAL;
		goto out;
	}

	if (data_entry.flags != flags) {
		LOG_ERR("TEST %d %s FAILED: Bad data entry flags", id,
			__func__);
		exit_rc = -EINVAL;
		goto out;
	}

out:
	rc = kfi_close(&cq->fid);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unable to close cq", id, __func__);
		return rc;
	}

	if (!exit_rc)
		LOG_INFO("TEST %d %s PASSED", id, __func__);

	return exit_rc;
}

static int test_single_event_fmt_tagged(int id)
{
	struct kfid_cq *cq;
	struct kfi_cq_attr attr = {};
	struct kfi_cq_tagged_entry tagged_entry;
	struct kcxi_cq *kcxi_cq;
	struct kcxi_req_state kcxi_req;
	uint64_t flags;
	int rc;
	int exit_rc = 0;

	attr.size = 1;
	attr.format = KFI_CQ_FORMAT_TAGGED;

	rc = kfi_cq_open(domain, &attr, &cq, NULL, NULL);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unable to open cq", id, __func__);
		return rc;
	}

	kcxi_cq = container_of(cq, struct kcxi_cq, cq_fid);

	flags = (KFI_MSG | KFI_SEND);
	kcxi_req.context = &exit_rc;
	kcxi_req.flags = flags;

	rc = kcxi_cq->report_completion(kcxi_cq, KFI_ADDR_NOTAVAIL, &kcxi_req);
	if (rc < 0) {
		LOG_ERR("TEST %d %s FAILED: Unable to write completion", id,
			__func__);
		exit_rc = rc;
		goto out;
	}

	rc = kfi_cq_read(cq, &tagged_entry, 1);
	if (rc < 0) {
		LOG_ERR("TEST %d %s FAILED: Unable to read cq", id, __func__);
		exit_rc = rc;
		goto out;
	}

	if (tagged_entry.op_context != &exit_rc) {
		LOG_ERR("TEST %d %s FAILED: Bad operation context", id,
			__func__);
		exit_rc = -EINVAL;
		goto out;
	}

	if (tagged_entry.flags != flags) {
		LOG_ERR("TEST %d %s FAILED: Bad data entry flags", id,
			__func__);
		exit_rc = -EINVAL;
		goto out;
	}

out:
	rc = kfi_close(&cq->fid);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unable to close cq", id, __func__);
		return rc;
	}

	if (!exit_rc)
		LOG_INFO("TEST %d %s PASSED", id, __func__);

	return exit_rc;
}

static int test_null_attr(int id)
{
	struct kfid_cq *cq;
	int rc;

	rc = kfi_cq_open(domain, NULL, &cq, NULL, NULL);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Failed to open CQ", id, __func__);
		return -EINVAL;
	}

	rc = kfi_close(&cq->fid);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unable to close cq", id, __func__);
		return rc;
	}

	LOG_INFO("TEST %d %s PASSED", id, __func__);

	return 0;
}

static int test_bad_attr_flags(int id)
{
	struct kfid_cq *cq;
	struct kfi_cq_attr attr = {};
	int rc;

	attr.flags = KFI_REMOTE_READ;

	rc = kfi_cq_open(domain, &attr, &cq, NULL, NULL);
	if (!rc) {
		LOG_ERR("TEST %d %s FAILED: Should not have opened CQ", id,
			__func__);
		kfi_close(&cq->fid);
		return -EINVAL;
	}

	LOG_INFO("TEST %d %s PASSED", id, __func__);

	return 0;
}

static int test_bad_attr_wait_obj(int id)
{
	struct kfid_cq *cq;
	struct kfi_cq_attr attr = {};
	int rc;

	attr.wait_obj = KFI_WAIT_UNSPEC;

	rc = kfi_cq_open(domain, &attr, &cq, NULL, NULL);
	if (!rc) {
		LOG_ERR("TEST %d %s FAILED: Should not have opened CQ", id,
			__func__);
		kfi_close(&cq->fid);
		return -EINVAL;
	}

	LOG_INFO("TEST %d %s PASSED", id, __func__);

	return 0;
}

static int test_bad_attr_wait_condition(int id)
{
	struct kfid_cq *cq;
	struct kfi_cq_attr attr = {};
	int rc;

	attr.wait_cond = KFI_CQ_COND_THRESHOLD;

	rc = kfi_cq_open(domain, &attr, &cq, NULL, NULL);
	if (!rc) {
		LOG_ERR("TEST %d %s FAILED: Should not have opened CQ", id,
			__func__);
		kfi_close(&cq->fid);
		return -EINVAL;
	}

	LOG_INFO("TEST %d %s PASSED", id, __func__);

	return 0;
}

static int test_bad_attr_wait_set(int id)
{
	struct kfid_cq *cq;
	struct kfi_cq_attr attr = {};
	int rc;

	/* Set the pointer to garbage since it should expect NULL */
	attr.wait_set = (struct kfid_wait *)&attr;

	rc = kfi_cq_open(domain, &attr, &cq, NULL, NULL);
	if (!rc) {
		LOG_ERR("TEST %d %s FAILED: Should not have opened CQ", id,
			__func__);
		kfi_close(&cq->fid);
		return -EINVAL;
	}

	LOG_INFO("TEST %d %s PASSED", id, __func__);

	return 0;
}

static int test_single_event_error(int id)
{
	struct kfid_cq *cq;
	struct kfi_cq_attr attr = {};
	struct kfi_cq_tagged_entry tagged_entry;
	struct kfi_cq_err_entry error;
	struct kcxi_cq *kcxi_cq;
	struct kcxi_req_state kcxi_req;
	uint64_t flags;
	size_t olen;
	int err;
	int prov_errno;
	int rc;
	int exit_rc = 0;

	attr.size = 1;
	attr.format = KFI_CQ_FORMAT_TAGGED;

	rc = kfi_cq_open(domain, &attr, &cq, NULL, NULL);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unable to open cq", id, __func__);
		return rc;
	}

	kcxi_cq = container_of(cq, struct kcxi_cq, cq_fid);

	flags = (KFI_MSG | KFI_SEND);
	kcxi_req.context = &exit_rc;
	kcxi_req.flags = flags;

	olen = 123;
	err = ENOSPC;
	prov_errno = -999;

	rc = kcxi_cq->report_error(kcxi_cq, &kcxi_req, olen, err, prov_errno);
	if (rc < 0) {
		LOG_ERR("TEST %d %s FAILED: Unable to write completion", id,
			__func__);
		exit_rc = rc;
		goto out;
	}

	rc = kfi_cq_read(cq, &tagged_entry, 1);
	if (rc != -KFI_EAVAIL) {
		LOG_ERR("TEST %d %s FAILED: CQ read should return -KFI_EVAIL",
			id, __func__);
		exit_rc = -EINVAL;
		goto out;
	}

	error.err_data_size = 0;

	rc = kfi_cq_readerr(cq, &error, 0);
	if (rc < 0) {
		LOG_ERR("TEST %d %s FAILED: Could not read error", id,
			__func__);
		exit_rc = -EINVAL;
		goto out;
	}

	if (error.op_context != &exit_rc) {
		LOG_ERR("TEST %d %s FAILED: Bad operation context", id,
			__func__);
		exit_rc = -EINVAL;
		goto out;
	}

	if (error.flags != flags) {
		LOG_ERR("TEST %d %s FAILED: Bad flags", id,
			__func__);
		exit_rc = -EINVAL;
		goto out;
	}

	if (error.olen != olen) {
		LOG_ERR("TEST %d %s FAILED: Bad overflow length", id,
			__func__);
		exit_rc = -EINVAL;
		goto out;
	}

	if (error.err != err) {
		LOG_ERR("TEST %d %s FAILED: Bad err", id,
			__func__);
		exit_rc = -EINVAL;
		goto out;
	}

	if (error.prov_errno != prov_errno) {
		LOG_ERR("TEST %d %s FAILED: Bad prov_errno", id,
			__func__);
		exit_rc = -EINVAL;
		goto out;
	}

	if (error.err_data_size != 0) {
		LOG_ERR("TEST %d %s FAILED: Bad error data size", id,
			__func__);
		exit_rc = -EINVAL;
		goto out;
	}

out:
	rc = kfi_close(&cq->fid);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unable to close cq", id, __func__);
		return rc;
	}

	if (!exit_rc)
		LOG_INFO("TEST %d %s PASSED", id, __func__);

	return exit_rc;
}

static int test_batch_event_read(int id)
{
	struct kfid_cq *cq;
	struct kfi_cq_attr attr = {};
	struct kfi_cq_data_entry data_entry[4];
	struct kcxi_cq *kcxi_cq;
	struct kcxi_req_state kcxi_req;
	uint64_t flags = (KFI_MSG | KFI_SEND);
	int rc;
	int exit_rc = 0;
	int i;
	int j;

	attr.size = 100;
	attr.format = KFI_CQ_FORMAT_DATA;

	rc = kfi_cq_open(domain, &attr, &cq, NULL, NULL);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unable to open cq", id, __func__);
		return rc;
	}

	kcxi_cq = container_of(cq, struct kcxi_cq, cq_fid);

	kcxi_req.flags = flags;
	kcxi_req.context = &exit_rc;

	for (i = 0; i < 10; i++) {
		rc = kcxi_cq->report_completion(kcxi_cq, KFI_ADDR_NOTAVAIL,
						&kcxi_req);
		if (rc < 0) {
			LOG_ERR("TEST %d %s FAILED: Unable to write comp",
				id, __func__);
			exit_rc = rc;
			goto out;
		}
	}

	for (i = 0; i < 2; i++) {
		rc = kfi_cq_read(cq, &data_entry, 4);
		if (rc != 4) {
			LOG_ERR("TEST %d %s FAILED: Unable to read cq", id,
				__func__);
			exit_rc = rc;
			goto out;
		}

		for (j = 0; j < rc; j++) {
			if (data_entry[j].op_context != &exit_rc) {
				LOG_ERR("TEST %d %s FAILED: Bad op context", id,
					__func__);
				exit_rc = -EINVAL;
				goto out;
			}

			if (data_entry[j].flags != flags) {
				LOG_ERR("TEST %d %s FAILED: Bad data flags", id,
					__func__);
				exit_rc = -EINVAL;
				goto out;
			}
		}
	}

	rc = kfi_cq_read(cq, &data_entry, 4);
	if (rc != 2) {
		LOG_ERR("TEST %d %s FAILED: Unable to read cq", id,
			__func__);
		exit_rc = rc;
		goto out;
	}

	for (i = 0; i < rc; i++) {
		if (data_entry[i].op_context != &exit_rc) {
			LOG_ERR("TEST %d %s FAILED: Bad operation context", id,
				__func__);
			exit_rc = -EINVAL;
			goto out;
		}

		if (data_entry[i].flags != flags) {
			LOG_ERR("TEST %d %s FAILED: Bad data entry flags", id,
				__func__);
			exit_rc = -EINVAL;
			goto out;
		}
	}

out:
	rc = kfi_close(&cq->fid);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unable to close cq", id, __func__);
		return rc;
	}

	if (!exit_rc)
		LOG_INFO("TEST %d %s PASSED", id, __func__);

	return exit_rc;
}

static int test_verify_pool_growth(int id)
{
	int rc;
	int exit_rc = 0;
	int i;
	int max_alloc_size = 105;
	int cq_size = 100;
	struct kfid_cq *cq;
	struct kfi_cq_attr attr = {};
	struct kfi_cq_err_entry err_entry;
	struct kfi_cq_data_entry data_entry;
	struct kcxi_cq *kcxi_cq;
	struct kcxi_cq_entry *entry;
	struct kcxi_req_state kcxi_req;

	attr.size = cq_size;
	attr.format = KFI_CQ_FORMAT_DATA;

	kcxi_req.flags = (KFI_MSG | KFI_SEND);
	kcxi_req.context = &exit_rc;

	rc = kfi_cq_open(domain, &attr, &cq, NULL, NULL);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unable to open cq", id, __func__);
		return rc;
	}

	kcxi_cq = container_of(cq, struct kcxi_cq, cq_fid);

	i = 0;
	list_for_each_entry(entry, &kcxi_cq->entry_free_list, entry)
		i++;
	if (i != cq_size) {
		LOG_ERR("TEST %d %s FAILED - Line %d", id, __func__, __LINE__);
		LOG_ERR("Incorrect number of free CXI CQ entries");
		LOG_ERR("Expected %d, got %d", cq_size, i);
		rc = -EINVAL;
		goto out;
	}

	for (i = 0; i < cq_size; i++) {
		rc = kcxi_cq->report_completion(kcxi_cq, KFI_ADDR_NOTAVAIL,
						&kcxi_req);
		if (rc < 0) {
			LOG_ERR("TEST %d %s FAILED: Unable to write comp",
				id, __func__);
			exit_rc = rc;
			goto out;
		}
	}

	i = 0;
	list_for_each_entry(entry, &kcxi_cq->event_list, entry)
		i++;
	if (i != cq_size) {
		LOG_ERR("TEST %d %s FAILED - Line %d", id, __func__, __LINE__);
		LOG_ERR("Incorrect number of used CXI entries for events");
		LOG_ERR("Expected %d, got %d", cq_size, i);
		rc = -EINVAL;
		goto out;
	}

	i = 0;
	list_for_each_entry(entry, &kcxi_cq->entry_free_list, entry)
		i++;
	if (i != 0) {
		LOG_ERR("TEST %d %s FAILED - Line %d", id, __func__, __LINE__);
		LOG_ERR("Incorrect number of free CXI entries");
		rc = -EINVAL;
		LOG_ERR("Expected 0, got %d", i);
		goto out;
	}

	for (i = attr.size; i < attr.size + 5; i++) {
		rc = kcxi_cq->report_error(kcxi_cq, &kcxi_req, 0, 0, 0);
		if (rc < 0) {
			LOG_ERR("TEST %d %s FAILED: Unable to write comp",
				id, __func__);
			exit_rc = rc;
			goto out;
		}
	}

	i = 0;
	list_for_each_entry(entry, &kcxi_cq->event_list, entry)
		i++;
	if (i != cq_size) {
		LOG_ERR("TEST %d %s FAILED - Line %d", id, __func__, __LINE__);
		LOG_ERR("Incorrect number of used event entries");
		LOG_ERR("Expected %d, got %d", cq_size, i);
		rc = -EINVAL;
		goto out;
	}

	i = 0;
	list_for_each_entry(entry, &kcxi_cq->error_list, entry)
		i++;
	if (i != (max_alloc_size - cq_size)) {
		LOG_ERR("TEST %d %s FAILED - Line %d", id, __func__, __LINE__);
		LOG_ERR("Incorrect number of used error entries");
		LOG_ERR("Expected %d, got %d", cq_size, i);
		rc = -EINVAL;
		goto out;
	}

	i = 0;
	list_for_each_entry(entry, &kcxi_cq->entry_free_list, entry)
		i++;
	if (i != 0) {
		LOG_ERR("TEST %d %s FAILED - Line %d", id, __func__, __LINE__);
		LOG_ERR("Incorrect number of free entries");
		rc = -EINVAL;
		LOG_ERR("Expected 0, got %d", i);
		goto out;
	}

	if (atomic_read(&kcxi_cq->overflow_entry_cnt) !=
	    (max_alloc_size - cq_size)) {
		LOG_ERR("TEST %d %s FAILED - Line %d", id, __func__, __LINE__);
		LOG_ERR("Incorrect REQ overflow count");
		rc = -EINVAL;
		goto out;
	}

	for (i = 0; i < (max_alloc_size - cq_size); i++) {
		rc = kfi_cq_readerr(cq, &err_entry, 0);
		if (rc != 1) {
			LOG_ERR("TEST %d %s FAILED: Unable to read cq", id,
				__func__);
			exit_rc = rc;
			goto out;
		}
	}

	i = 0;
	list_for_each_entry(entry, &kcxi_cq->event_list, entry)
		i++;
	if (i != cq_size) {
		LOG_ERR("TEST %d %s FAILED - Line %d", id, __func__, __LINE__);
		LOG_ERR("Incorrect number of used event entries");
		LOG_ERR("Expected %d, got %d", cq_size, i);
		rc = -EINVAL;
		goto out;
	}

	i = 0;
	list_for_each_entry(entry, &kcxi_cq->error_list, entry)
		i++;
	if (i != 0) {
		LOG_ERR("TEST %d %s FAILED - Line %d", id, __func__, __LINE__);
		LOG_ERR("Incorrect number of used error entries");
		LOG_ERR("Expected 0, got %d", i);
		rc = -EINVAL;
		goto out;
	}

	for (i = 0; i < cq_size; i++) {
		rc = kfi_cq_read(cq, &data_entry, 1);
		if (rc != 1) {
			LOG_ERR("TEST %d %s FAILED: Unable to read cq", id,
				__func__);
			exit_rc = rc;
			goto out;
		}
	}

	i = 0;
	list_for_each_entry(entry, &kcxi_cq->event_list, entry)
		i++;
	if (i != 0) {
		LOG_ERR("TEST %d %s FAILED - Line %d", id, __func__, __LINE__);
		LOG_ERR("Incorrect number of used event entries");
		LOG_ERR("Expected 0, got %d", i);
		rc = -EINVAL;
		goto out;
	}

	i = 0;
	list_for_each_entry(entry, &kcxi_cq->error_list, entry)
		i++;
	if (i != 0) {
		LOG_ERR("TEST %d %s FAILED - Line %d", id, __func__, __LINE__);
		LOG_ERR("Incorrect number of used error entries");
		LOG_ERR("Expected 0, got %d", i);
		rc = -EINVAL;
		goto out;
	}

	i = 0;
	list_for_each_entry(entry, &kcxi_cq->entry_free_list, entry)
		i++;
	if (i != cq_size) {
		LOG_ERR("TEST %d %s FAILED - Line %d", id, __func__, __LINE__);
		LOG_ERR("Incorrect number of free CXI entries");
		LOG_ERR("Expected %d, got %d", max_alloc_size, i);
		rc = -EINVAL;
		goto out;
	}

	if (atomic_read(&kcxi_cq->overflow_entry_cnt) != 0) {
		LOG_ERR("TEST %d %s FAILED - Line %d", id, __func__, __LINE__);
		LOG_ERR("Incorrect REQ overflow count");
		rc = -EINVAL;
		goto out;
	}

	rc = 0;
out:
	if (rc)
		exit_rc = rc;

	rc = kfi_close(&cq->fid);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unable to close cq", id, __func__);
		return rc;
	}

	if (!exit_rc)
		LOG_INFO("TEST %d %s PASSED", id, __func__);

	return exit_rc;

}

static int test_verify_metric_counters(int id)
{
	int rc;
	int exit_rc = 0;
	int i;
	struct kfid_cq *cq;
	struct kfi_cq_attr attr = {};
	struct kfi_cq_err_entry err_entry;
	struct kfi_cq_data_entry data_entry;
	struct kcxi_cq *kcxi_cq;
	struct kcxi_req_state req;

	attr.size = 100;
	attr.format = KFI_CQ_FORMAT_DATA;

	rc = kfi_cq_open(domain, &attr, &cq, NULL, NULL);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unable to open cq", id, __func__);
		return rc;
	}

	kcxi_cq = container_of(cq, struct kcxi_cq, cq_fid);

	req.flags = (KFI_MSG | KFI_SEND);
	req.context = &exit_rc;

	for (i = 0; i < 5; i++) {
		rc = kcxi_cq->report_completion(kcxi_cq, KFI_ADDR_NOTAVAIL,
						&req);
		if (rc < 0) {
			LOG_ERR("TEST %d %s FAILED: Unable to write comp",
				id, __func__);
			exit_rc = rc;
			goto out;
		}
	}

	for (i = 0; i < 5; i++) {
		rc = kcxi_cq->report_error(kcxi_cq, &req, 0, 0, 0);
		if (rc < 0) {
			LOG_ERR("TEST %d %s FAILED: Unable to write comp",
				id, __func__);
			exit_rc = rc;
			goto out;
		}
	}

	for (i = 0; i < 5; i++) {
		rc = kfi_cq_readerr(cq, &err_entry, 0);
		if (rc != 1) {
			LOG_ERR("TEST %d %s FAILED: Unable to read cq", id,
				__func__);
			exit_rc = rc;
			goto out;
		}
	}

	for (i = 0; i < 5; i++) {
		rc = kfi_cq_read(cq, &data_entry, 1);
		if (rc != 1) {
			LOG_ERR("TEST %d %s FAILED: Unable to read cq", id,
				__func__);
			exit_rc = rc;
			goto out;
		}
	}

	rc = 0;

out:
	if (rc)
		exit_rc = rc;

	rc = kfi_close(&cq->fid);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unable to close cq", id, __func__);
		return rc;
	}

	if (!exit_rc)
		LOG_INFO("TEST %d %s PASSED", id, __func__);

	return exit_rc;

}

static int test_close_with_outstanding_events(int id)
{
	int rc;
	int exit_rc = 0;
	int i;
	struct kfid_cq *cq;
	struct kfi_cq_attr attr = {};
	struct kcxi_cq *kcxi_cq;
	struct kcxi_req_state req;

	attr.size = 100;
	attr.format = KFI_CQ_FORMAT_DATA;

	rc = kfi_cq_open(domain, &attr, &cq, NULL, NULL);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unable to open cq", id, __func__);
		return rc;
	}

	kcxi_cq = container_of(cq, struct kcxi_cq, cq_fid);

	req.flags = (KFI_MSG | KFI_SEND);
	req.context = &exit_rc;

	for (i = 0; i < 5; i++) {
		rc = kcxi_cq->report_completion(kcxi_cq, KFI_ADDR_NOTAVAIL,
						&req);
		if (rc < 0) {
			LOG_ERR("TEST %d %s FAILED: Unable to write comp",
				id, __func__);
			exit_rc = rc;
			goto out;
		}
	}

	for (i = 0; i < 5; i++) {
		rc = kcxi_cq->report_error(kcxi_cq, &req, 0, 0, 0);
		if (rc < 0) {
			LOG_ERR("TEST %d %s FAILED: Unable to write comp",
				id, __func__);
			exit_rc = rc;
			goto out;
		}
	}

	rc = 0;

out:
	if (rc)
		exit_rc = rc;

	rc = kfi_close(&cq->fid);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unable to close cq", id, __func__);
		return rc;
	}

	if (!exit_rc)
		LOG_INFO("TEST %d %s PASSED", id, __func__);

	return exit_rc;

}

static int test_alloc_buffer_id(int id)
{
	int rc;
	int i;
	struct kfid_cq *cq;
	struct kfi_cq_attr attr = {};
	struct kcxi_cq *kcxi_cq;
	struct kcxi_req_state req;

	attr.size = 100;
	attr.format = KFI_CQ_FORMAT_DATA;

	rc = kfi_cq_open(domain, &attr, &cq, NULL, NULL);
	if (rc) {
		LOG_ERR("Failed to open up completion queue: %d", rc);
		goto err;
	}
	kcxi_cq = container_of(cq, struct kcxi_cq, cq_fid);

	/* Drain all the buffer IDs for the CQ. */
	for (i = 1; i < MAX_BUFFER_ID; i++) {
		rc = kcxi_cq->buffer_id_map(kcxi_cq, &req);
		if (rc < 0) {
			LOG_ERR("Failed to get buffer ID: %d", rc);
			goto err_close_cq;
		}
	}

	/* Any additional allocation should fail. */
	rc = kcxi_cq->buffer_id_map(kcxi_cq, &req);
	if (rc >= 0) {
		LOG_ERR("Should not have allocated buffer ID");
		goto err_close_cq;
	}

	for (i = 1; i < MAX_BUFFER_ID; i++)
		kcxi_cq->buffer_id_unmap(kcxi_cq, i);

	kfi_close(&cq->fid);

	LOG_INFO("TEST %d %s PASSED", id, __func__);

	return 0;

err_close_cq:
	kfi_close(&cq->fid);
err:
	LOG_ERR("Test %d %s FAILED", id, __func__);
	return rc;
}

static void test_fini(void)
{
	kfi_close(&domain->fid);
	kfi_close(&fabric->fid);
	kfi_freeinfo(hints);
	kfi_freeinfo(info);
}

static int __init test_module_init(void)
{
	int rc = 0;
	int exit_rc = 0;
	int test_id = 1;

	rc = test_init();
	if (rc)
		return rc;

	rc = test_open_close_cq(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_premature_domain_close(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_single_event_fmt_context(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_single_event_fmt_msg(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_single_event_fmt_data(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_single_event_fmt_tagged(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_null_attr(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bad_attr_flags(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bad_attr_wait_obj(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bad_attr_wait_condition(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bad_attr_wait_set(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_single_event_error(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_batch_event_read(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_verify_pool_growth(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_verify_metric_counters(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_close_with_outstanding_events(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_alloc_buffer_id(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	test_fini();

	if (!exit_rc)
		LOG_INFO("ALL TESTS PASSED");

	return exit_rc;
}

static void __exit test_module_exit(void)
{
}


module_init(test_module_init);
module_exit(test_module_exit);
