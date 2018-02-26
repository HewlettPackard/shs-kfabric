/*
 * Kfabric fabric tests.
 * Copyright 2018 Cray Inc. All Rights Reserved.
 *
 * SPDX-License-Identifier: GPL-2.0
 */
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <kfabric.h>
#include <kfi_log.h>
#include <kfi_eq.h>

#include "../../../prov/cxi/kcxi_prov.h"

#ifdef MODULE_NAME
#undef MODULE_NAME
#endif
#define MODULE_NAME "test_eq"

MODULE_AUTHOR("Ian Ziemba");
MODULE_DESCRIPTION("kfabric CXI event queue tests");
MODULE_LICENSE("GPL v2");

static struct kfi_info *info;
static struct kfi_info *hints;
static struct kfid_fabric *fabric;
static atomic_t entry_count = ATOMIC_INIT(0);
static atomic_t cb_count = ATOMIC_INIT(0);

static void dummy_event_handler(struct kfid_eq *eq, void *context)
{
	LOG_INFO("Event handler triggered");
}

static void count_event_handler(struct kfid_eq *eq, void *context)
{
	atomic_inc(&cb_count);
}

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

	if (!info) {
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

	return 0;

out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;

}

static int test_create_close_eq_null_attr_handler(int id)
{
	int rc;
	uint8_t context = 0xFF;
	struct kfid_eq *eq;

	rc = kfi_eq_open(fabric, NULL, &eq, NULL, &context);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unable to allocated EQ", id,
			__func__);
		return rc;
	}

	rc = kfi_close(&eq->fid);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unable to close EQ", id, __func__);
		return rc;
	}

	LOG_INFO("TEST %d %s PASSED", id, __func__);
	return 0;
}

static int test_create_close_eq_full_args(int id)
{
	int rc;
	int exit_rc = 0;
	uint8_t context = 0xFF;
	struct kfid_eq *eq;
	struct kfi_eq_attr attr;
	struct kcxi_eq *cxi_eq;

	attr.size = 1;
	attr.flags = 0;
	attr.wait_obj = KFI_WAIT_NONE;
	attr.signaling_vector = 0;
	attr.wait_set = NULL;

	rc = kfi_eq_open(fabric, &attr, &eq, dummy_event_handler, &context);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unable to allocated EQ", id,
			__func__);
		return rc;
	}

	cxi_eq = container_of(eq, struct kcxi_eq, eq);

	if (cxi_eq->attr.size != attr.size) {
		LOG_ERR("TEST %d %s FAILED: Attribute size does not match", id,
			__func__);
		exit_rc = -EINVAL;
	}

	if (cxi_eq->attr.flags != attr.flags) {
		LOG_ERR("TEST %d %s FAILED: Attribute flags do not match", id,
			__func__);
		exit_rc = -EINVAL;
	}

	if (cxi_eq->attr.wait_obj != attr.wait_obj) {
		LOG_ERR("TEST %d %s FAILED: Attribute wait obj does not match",
			id, __func__);
		exit_rc = -EINVAL;
	}

	if (cxi_eq->attr.signaling_vector != attr.signaling_vector) {
		LOG_ERR("TEST %d %s FAILED: Attribute signalvec does not match",
			id, __func__);
		exit_rc = -EINVAL;
	}

	if (cxi_eq->attr.wait_set != attr.wait_set) {
		LOG_ERR("TEST %d %s FAILED: Attribute wait set does not match",
			id, __func__);
		exit_rc = -EINVAL;
	}

	rc = kfi_close(&eq->fid);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unable to close EQ", id, __func__);
		return rc;
	}

	if (!exit_rc)
		LOG_INFO("TEST %d %s PASSED", id, __func__);

	return exit_rc;

}

static int test_premature_fabric_close(int id)
{
	int rc;
	uint8_t context = 0xFF;
	struct kfid_eq *eq;

	rc = kfi_eq_open(fabric, NULL, &eq, NULL, &context);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unable to allocated EQ", id,
			__func__);
		return rc;
	}

	rc = kfi_close(&fabric->fid);
	if (!rc) {
		LOG_ERR("TEST %d %s FAILED: Able to close fabric prematurely",
			id, __func__);

		/* Closing of the EQ may be problabmatic... */
		kfi_close(&eq->fid);
		return rc;

	}

	rc = kfi_close(&eq->fid);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unable to close EQ", id, __func__);
		return rc;
	}

	LOG_INFO("TEST %d %s PASSED", id, __func__);
	return 0;

}

static int test_eq_bad_size(int id)
{
	int rc;
	uint8_t context = 0xFF;
	struct kfid_eq *eq;
	struct kfi_eq_attr attr;

	attr.size = KCXI_EQ_DEF_SZ + 1;

	rc = kfi_eq_open(fabric, &attr, &eq, dummy_event_handler, &context);
	if (rc) {
		LOG_INFO("TEST %d %s PASSED", id, __func__);
		return 0;
	}

	LOG_ERR("TEST %d %s FAILED: EQ open should have failed", id, __func__);
	return -EINVAL;
}

static int test_eq_bad_flags(int id)
{
	int rc;
	uint8_t context = 0xFF;
	struct kfid_eq *eq;
	struct kfi_eq_attr attr;

	attr.flags = KFI_AFFINITY;

	rc = kfi_eq_open(fabric, &attr, &eq, dummy_event_handler, &context);
	if (rc) {
		LOG_INFO("TEST %d %s PASSED", id, __func__);
		return 0;
	}

	LOG_ERR("TEST %d %s FAILED: EQ open should have failed", id, __func__);
	return -EINVAL;
}

static int test_eq_bad_wait_obj(int id)
{
	int rc;
	uint8_t context = 0xFF;
	struct kfid_eq *eq;
	struct kfi_eq_attr attr;

	attr.wait_obj = KFI_WAIT_QUEUE;

	rc = kfi_eq_open(fabric, &attr, &eq, dummy_event_handler, &context);
	if (rc) {
		LOG_INFO("TEST %d %s PASSED", id, __func__);
		return 0;
	}

	LOG_ERR("TEST %d %s FAILED: EQ open should have failed", id, __func__);
	return -EINVAL;
}

static int test_eq_non_null_wait_set(int id)
{
	int rc;
	uint8_t context = 0xFF;
	struct kfid_eq *eq;
	struct kfi_eq_attr attr;

	attr.wait_set = (struct kfid_wait *)&context;

	rc = kfi_eq_open(fabric, &attr, &eq, dummy_event_handler, &context);
	if (rc) {
		LOG_INFO("TEST %d %s PASSED", id, __func__);
		return 0;
	}

	LOG_ERR("TEST %d %s FAILED: EQ open should have failed", id, __func__);
	return -EINVAL;
}

static int test_single_event_no_cb(int id)
{
	int rc, exit_rc;
	uint8_t context = 0xFF;
	uint32_t type, read_type;
	struct kfid_eq *eq;
	struct kfi_eq_attr attr;
	struct kfi_eq_entry event, read_event;
	struct kcxi_eq *cxi_eq;
	ssize_t read_size;

	attr.size = 1;
	attr.flags = 0;
	attr.wait_obj = KFI_WAIT_NONE;
	attr.signaling_vector = 0;
	attr.wait_set = NULL;

	rc = kfi_eq_open(fabric, &attr, &eq, NULL, &context);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unable to allocated EQ", id,
			__func__);
		return rc;
	}

	cxi_eq = container_of(eq, struct kcxi_eq, eq);

	type = KFI_MR_COMPLETE;
	event.fid = &cxi_eq->eq.fid;
	event.context = &context;
	event.data = 1235567;

	/* Write event */
	rc = cxi_eq->report_event(cxi_eq, type, &event);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unabled to write EQ", id, __func__);
		goto out;
	}
	atomic_inc(&entry_count);

	/* Read event */
	read_size = kfi_eq_read(eq, &read_type, &read_event,
				sizeof(read_event), 0);
	atomic_dec(&entry_count);

	if (read_size < 0) {
		LOG_ERR("TEST %d %s FAILED: Failed to read EQ", id,
			__func__);
		rc = -EINVAL;
		goto out;
	}

	if (read_size != sizeof(read_event)) {
		LOG_ERR("TEST %d %s FAILED: Extra read data reported", id,
			__func__);
		rc = -EINVAL;
		goto out;
	}

	if (type != read_type) {
		LOG_ERR("TEST %d %s FAILED: Unexpected type returned", id,
			__func__);
		rc = -EINVAL;
		goto out;
	}

	if (event.fid != read_event.fid ||
	    event.context != read_event.context ||
	    event.data != read_event.data) {
		LOG_ERR("TEST %d %s FAILED: Unmatching event data returned", id,
			__func__);
		rc = -EINVAL;
		goto out;
	}

out:
	exit_rc = rc;

	rc = kfi_close(&eq->fid);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unable to close EQ", id, __func__);
		return rc;
	}

	if (!exit_rc)
		LOG_INFO("TEST %d %s PASSED", id, __func__);

	return exit_rc;

}

static int test_single_event_cb(int id)
{
	int rc, exit_rc;
	uint8_t context = 0xFF;
	uint32_t type, read_type;
	struct kfid_eq *eq;
	struct kfi_eq_attr attr;
	struct kfi_eq_entry event, read_event;
	struct kcxi_eq *cxi_eq;
	ssize_t read_size;

	attr.size = 1;
	attr.flags = 0;
	attr.wait_obj = KFI_WAIT_NONE;
	attr.signaling_vector = 0;
	attr.wait_set = NULL;

	rc = kfi_eq_open(fabric, &attr, &eq, count_event_handler, &context);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unable to allocated EQ", id,
			__func__);
		return rc;
	}

	cxi_eq = container_of(eq, struct kcxi_eq, eq);

	type = KFI_MR_COMPLETE;
	event.fid = &cxi_eq->eq.fid;
	event.context = &context;
	event.data = 1235567;

	/* Write event */
	rc = cxi_eq->report_event(cxi_eq, type, &event);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unabled to write EQ", id, __func__);
		goto out;
	}
	atomic_inc(&entry_count);

	/* Read event */
	read_size = kfi_eq_read(eq, &read_type, &read_event,
				sizeof(read_event), 0);
	atomic_dec(&entry_count);

	/* Need to force CB to be raised. */
	cxi_eq->raise_handler(cxi_eq);

	if (atomic_read(&cb_count) != 1) {
		LOG_ERR("TEST %d %s FAILED: Callback not triggered", id,
			__func__);
		rc = -EINVAL;
		goto out;

	}
	atomic_dec(&cb_count);

	if (read_size < 0) {
		LOG_ERR("TEST %d %s FAILED: Failed to read EQ", id,
			__func__);
		rc = -EINVAL;
		goto out;
	}

	if (read_size != sizeof(read_event)) {
		LOG_ERR("TEST %d %s FAILED: Extra read data reported", id,
			__func__);
		rc = -EINVAL;
		goto out;
	}

	if (type != read_type) {
		LOG_ERR("TEST %d %s FAILED: Unexpected type returned", id,
			__func__);
		rc = -EINVAL;
		goto out;
	}

	if (event.fid != read_event.fid ||
	    event.context != read_event.context ||
	    event.data != read_event.data) {
		LOG_ERR("TEST %d %s FAILED: Unmatching event data returned", id,
			__func__);
		rc = -EINVAL;
		goto out;
	}

out:
	exit_rc = rc;

	rc = kfi_close(&eq->fid);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unable to close EQ", id, __func__);
		return rc;
	}

	if (!exit_rc)
		LOG_INFO("TEST %d %s PASSED", id, __func__);

	return exit_rc;

}

static int test_single_error_no_cb(int id)
{
	int rc, exit_rc;
	uint8_t context = 0xFF;
	uint32_t type;
	struct kfid_eq *eq;
	struct kfi_eq_attr attr;
	struct kfi_eq_err_entry error, read_error;
	struct kfi_eq_entry event;
	struct kcxi_eq *cxi_eq;
	ssize_t read_size;

	attr.size = 1;
	attr.flags = 0;
	attr.wait_obj = KFI_WAIT_NONE;
	attr.signaling_vector = 0;
	attr.wait_set = NULL;

	rc = kfi_eq_open(fabric, &attr, &eq, NULL, &context);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unable to allocated EQ", id,
			__func__);
		return rc;
	}

	cxi_eq = container_of(eq, struct kcxi_eq, eq);

	error.fid = &cxi_eq->eq.fid;
	error.context = &context;
	error.data = 123456;
	error.err = -EINVAL;
	error.prov_errno = -EINVAL;
	error.err_data = NULL;
	error.err_data_size = 0;

	/* Write event */
	rc = cxi_eq->report_error(cxi_eq, &error);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unabled to write EQ", id, __func__);
		goto out;
	}
	atomic_inc(&entry_count);

	/* Read event */
	read_size = kfi_eq_read(eq, &type, &event, sizeof(event), 0);
	if (read_size != -KFI_EAVAIL) {
		LOG_ERR("TEST %d %s FAILED: KFI_AVAIL not returned", id,
			__func__);
		goto out;
	}

	read_size = kfi_eq_readerr(eq, &read_error, 0);
	atomic_dec(&entry_count);

	if (read_size < 0) {
		LOG_ERR("TEST %d %s FAILED: Failed to read EQ", id,
			__func__);
		rc = -EINVAL;
		goto out;
	}

	if (read_size != sizeof(read_error)) {
		LOG_ERR("TEST %d %s FAILED: Extra read data reported", id,
			__func__);
		rc = -EINVAL;
		goto out;
	}

	if (error.fid != read_error.fid ||
	    error.context != read_error.context ||
	    error.data != read_error.data ||
	    error.err != read_error.err ||
	    error.prov_errno != read_error.prov_errno ||
	    error.err_data != read_error.err_data ||
	    error.err_data_size != read_error.err_data_size) {
		LOG_ERR("TEST %d %s FAILED: Unmatching event data returned", id,
			__func__);
		rc = -EINVAL;
		goto out;
	}

out:
	exit_rc = rc;

	rc = kfi_close(&eq->fid);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unable to close EQ", id, __func__);
		return rc;
	}

	if (!exit_rc)
		LOG_INFO("TEST %d %s PASSED", id, __func__);

	return exit_rc;

}

static int test_single_error_cb(int id)
{
	int rc, exit_rc;
	uint8_t context = 0xFF;
	uint32_t type;
	struct kfid_eq *eq;
	struct kfi_eq_attr attr;
	struct kfi_eq_err_entry error, read_error;
	struct kfi_eq_entry event;
	struct kcxi_eq *cxi_eq;
	ssize_t read_size;

	attr.size = 1;
	attr.flags = 0;
	attr.wait_obj = KFI_WAIT_NONE;
	attr.signaling_vector = 0;
	attr.wait_set = NULL;

	rc = kfi_eq_open(fabric, &attr, &eq, count_event_handler, &context);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unable to allocated EQ", id,
			__func__);
		return rc;
	}

	cxi_eq = container_of(eq, struct kcxi_eq, eq);

	error.fid = &cxi_eq->eq.fid;
	error.context = &context;
	error.data = 123456;
	error.err = -EINVAL;
	error.prov_errno = -EINVAL;
	error.err_data = NULL;
	error.err_data_size = 0;

	/* Write event */
	rc = cxi_eq->report_error(cxi_eq, &error);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unabled to write EQ", id, __func__);
		goto out;
	}
	atomic_inc(&entry_count);

	/* Need to force CB to be raised. */
	cxi_eq->raise_handler(cxi_eq);

	if (atomic_read(&cb_count) != 1) {
		LOG_ERR("TEST %d %s FAILED: Callback not triggered", id,
			__func__);
		rc = -EINVAL;
		goto out;

	}
	atomic_dec(&cb_count);

	/* Read event */
	read_size = kfi_eq_read(eq, &type, &event, sizeof(event), 0);
	if (read_size != -KFI_EAVAIL) {
		LOG_ERR("TEST %d %s FAILED: KFI_AVAIL not returned", id,
			__func__);
		goto out;
	}

	read_size = kfi_eq_readerr(eq, &read_error, 0);
	atomic_dec(&entry_count);

	if (read_size < 0) {
		LOG_ERR("TEST %d %s FAILED: Failed to read EQ", id,
			__func__);
		rc = -EINVAL;
		goto out;
	}

	if (read_size != sizeof(read_error)) {
		LOG_ERR("TEST %d %s FAILED: Extra read data reported", id,
			__func__);
		rc = -EINVAL;
		goto out;
	}

	if (error.fid != read_error.fid ||
	    error.context != read_error.context ||
	    error.data != read_error.data ||
	    error.err != read_error.err ||
	    error.prov_errno != read_error.prov_errno ||
	    error.err_data != read_error.err_data ||
	    error.err_data_size != read_error.err_data_size) {
		LOG_ERR("TEST %d %s FAILED: Unmatching event data returned", id,
			__func__);
		rc = -EINVAL;
		goto out;
	}

out:
	exit_rc = rc;

	rc = kfi_close(&eq->fid);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unable to close EQ", id, __func__);
		return rc;
	}

	if (!exit_rc)
		LOG_INFO("TEST %d %s PASSED", id, __func__);

	return exit_rc;

}

static int test_overrun(int id)
{
	int rc, exit_rc;
	uint8_t context = 0xFF;
	uint32_t type, read_type;
	struct kfid_eq *eq;
	struct kfi_eq_attr attr;
	struct kfi_eq_entry event, read_event;
	struct kfi_eq_err_entry error;
	struct kcxi_eq *cxi_eq;
	ssize_t read_size;

	attr.size = 1;
	attr.flags = 0;
	attr.wait_obj = KFI_WAIT_NONE;
	attr.signaling_vector = 0;
	attr.wait_set = NULL;

	rc = kfi_eq_open(fabric, &attr, &eq, NULL, &context);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unable to allocated EQ", id,
			__func__);
		return rc;
	}

	cxi_eq = container_of(eq, struct kcxi_eq, eq);

	type = KFI_MR_COMPLETE;
	event.fid = &cxi_eq->eq.fid;
	event.context = &context;
	event.data = 1235567;

	/* Write 2 events... second event should cause overrun */
	rc = cxi_eq->report_event(cxi_eq, type, &event);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unabled to write EQ", id, __func__);
		goto out;
	}

	rc = cxi_eq->report_event(cxi_eq, type, &event);
	if (rc != -KFI_EOVERRUN) {
		rc = -EINVAL;
		LOG_ERR("TEST %d %s FAILED: Expected EQ to be overrun", id,
			__func__);
		goto out;
	} else {
		rc = 0;
	}

	/* First read should succeed */
	read_size = kfi_eq_read(eq, &read_type, &read_event,
				sizeof(read_event), 0);
	if (read_size < 0) {
		LOG_ERR("TEST %d %s FAILED: Failed to read EQ", id,
			__func__);
		rc = -EINVAL;
		goto out;
	}

	/* Future reads should return errors */
	read_size = kfi_eq_read(eq, &read_type, &read_event,
				sizeof(read_event), 0);
	if (read_size != -KFI_EOVERRUN) {
		rc = -EINVAL;
		LOG_ERR("TEST %d %s FAILED: Expected EQ to be overrun", id,
			__func__);
		goto out;
	}

	read_size = kfi_eq_readerr(eq, &error, 0);
	if (read_size != -KFI_EOVERRUN) {
		rc = -EINVAL;
		LOG_ERR("TEST %d %s FAILED: Expected EQ to be overrun", id,
			__func__);
		goto out;
	}

out:
	exit_rc = rc;

	rc = kfi_close(&eq->fid);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unable to close EQ", id, __func__);
		return rc;
	}

	if (!exit_rc)
		LOG_INFO("TEST %d %s PASSED", id, __func__);

	return exit_rc;

}

static int test_single_event_peek(int id)
{
	int rc, exit_rc;
	uint8_t context = 0xFF;
	uint32_t type, read_type;
	struct kfid_eq *eq;
	struct kfi_eq_attr attr;
	struct kfi_eq_entry event, read_event;
	struct kcxi_eq *cxi_eq;
	ssize_t read_size;

	attr.size = 1;
	attr.flags = 0;
	attr.wait_obj = KFI_WAIT_NONE;
	attr.signaling_vector = 0;
	attr.wait_set = NULL;

	rc = kfi_eq_open(fabric, &attr, &eq, NULL, &context);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unable to allocated EQ", id,
			__func__);
		return rc;
	}

	cxi_eq = container_of(eq, struct kcxi_eq, eq);

	type = KFI_MR_COMPLETE;
	event.fid = &cxi_eq->eq.fid;
	event.context = &context;
	event.data = 1235567;

	/* Write event */
	rc = cxi_eq->report_event(cxi_eq, type, &event);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unabled to write EQ", id, __func__);
		goto out;
	}
	atomic_inc(&entry_count);

	/* Peek at the event event */
	read_size = kfi_eq_read(eq, &read_type, &read_event,
				sizeof(read_event), KFI_PEEK);

	if (read_size < 0) {
		LOG_ERR("TEST %d %s FAILED: Failed to read EQ", id,
			__func__);
		rc = -EINVAL;
		goto out;
	}

	if (read_size != sizeof(read_event)) {
		LOG_ERR("TEST %d %s FAILED: Extra read data reported", id,
			__func__);
		rc = -EINVAL;
		goto out;
	}

	if (type != read_type) {
		LOG_ERR("TEST %d %s FAILED: Unexpected type returned", id,
			__func__);
		rc = -EINVAL;
		goto out;
	}

	if (event.fid != read_event.fid ||
	    event.context != read_event.context ||
	    event.data != read_event.data) {
		LOG_ERR("TEST %d %s FAILED: Unmatching event data returned", id,
			__func__);
		rc = -EINVAL;
		goto out;
	}

	/* Read and consume the event */
	memset(&read_event, 0, sizeof(read_event));
	read_size = kfi_eq_read(eq, &read_type, &read_event,
				sizeof(read_event), 0);
	atomic_dec(&entry_count);

	if (read_size < 0) {
		LOG_ERR("TEST %d %s FAILED: Failed to read EQ", id,
			__func__);
		rc = -EINVAL;
		goto out;
	}

	if (read_size != sizeof(read_event)) {
		LOG_ERR("TEST %d %s FAILED: Extra read data reported", id,
			__func__);
		rc = -EINVAL;
		goto out;
	}

	if (type != read_type) {
		LOG_ERR("TEST %d %s FAILED: Unexpected type returned", id,
			__func__);
		rc = -EINVAL;
		goto out;
	}

	if (event.fid != read_event.fid ||
	    event.context != read_event.context ||
	    event.data != read_event.data) {
		LOG_ERR("TEST %d %s FAILED: Unmatching event data returned", id,
			__func__);
		rc = -EINVAL;
		goto out;
	}

out:
	exit_rc = rc;

	rc = kfi_close(&eq->fid);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unable to close EQ", id, __func__);
		return rc;
	}

	if (!exit_rc)
		LOG_INFO("TEST %d %s PASSED", id, __func__);

	return exit_rc;

}

static int test_single_error_peek(int id)
{
	int rc, exit_rc;
	uint8_t context = 0xFF;
	struct kfid_eq *eq;
	struct kfi_eq_attr attr;
	struct kfi_eq_err_entry error, read_error;
	struct kcxi_eq *cxi_eq;
	ssize_t read_size;

	attr.size = 1;
	attr.flags = 0;
	attr.wait_obj = KFI_WAIT_NONE;
	attr.signaling_vector = 0;
	attr.wait_set = NULL;

	rc = kfi_eq_open(fabric, &attr, &eq, NULL, &context);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unable to allocated EQ", id,
			__func__);
		return rc;
	}

	cxi_eq = container_of(eq, struct kcxi_eq, eq);

	error.fid = &cxi_eq->eq.fid;
	error.context = &context;
	error.data = 123456;
	error.err = -EINVAL;
	error.prov_errno = -EINVAL;
	error.err_data = NULL;
	error.err_data_size = 0;

	/* Write event */
	rc = cxi_eq->report_error(cxi_eq, &error);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unabled to write EQ", id, __func__);
		goto out;
	}
	atomic_inc(&entry_count);

	/* Peek at the error */
	read_size = kfi_eq_readerr(eq, &read_error, KFI_PEEK);

	if (read_size < 0) {
		LOG_ERR("TEST %d %s FAILED: Failed to read EQ", id,
			__func__);
		rc = -EINVAL;
		goto out;
	}

	if (read_size != sizeof(read_error)) {
		LOG_ERR("TEST %d %s FAILED: Extra read data reported", id,
			__func__);
		rc = -EINVAL;
		goto out;
	}

	if (error.fid != read_error.fid ||
	    error.context != read_error.context ||
	    error.data != read_error.data ||
	    error.err != read_error.err ||
	    error.prov_errno != read_error.prov_errno ||
	    error.err_data != read_error.err_data ||
	    error.err_data_size != read_error.err_data_size) {
		LOG_ERR("TEST %d %s FAILED: Unmatching event data returned", id,
			__func__);
		rc = -EINVAL;
		goto out;
	}

	/* Consume the error */
	memset(&read_error, 0, sizeof(read_error));
	read_size = kfi_eq_readerr(eq, &read_error, 0);
	atomic_dec(&entry_count);

	if (read_size < 0) {
		LOG_ERR("TEST %d %s FAILED: Failed to read EQ", id,
			__func__);
		rc = -EINVAL;
		goto out;
	}

	if (read_size != sizeof(read_error)) {
		LOG_ERR("TEST %d %s FAILED: Extra read data reported", id,
			__func__);
		rc = -EINVAL;
		goto out;
	}

	if (error.fid != read_error.fid ||
	    error.context != read_error.context ||
	    error.data != read_error.data ||
	    error.err != read_error.err ||
	    error.prov_errno != read_error.prov_errno ||
	    error.err_data != read_error.err_data ||
	    error.err_data_size != read_error.err_data_size) {
		LOG_ERR("TEST %d %s FAILED: Unmatching event data returned", id,
			__func__);
		rc = -EINVAL;
		goto out;
	}

out:
	exit_rc = rc;

	rc = kfi_close(&eq->fid);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unable to close EQ", id, __func__);
		return rc;
	}

	if (!exit_rc)
		LOG_INFO("TEST %d %s PASSED", id, __func__);

	return exit_rc;

}

static int test_read_empty_queue(int id)
{
	int rc, exit_rc = 0;
	uint8_t context = 0xFF;
	struct kfid_eq *eq;
	uint32_t type;
	struct kfi_eq_entry event;
	struct kfi_eq_err_entry error;
	ssize_t read_size;

	rc = kfi_eq_open(fabric, NULL, &eq, NULL, &context);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unable to allocated EQ", id,
			__func__);
		return rc;
	}

	read_size = kfi_eq_read(eq, &type, &event, sizeof(event), 0);
	if (read_size != -EAGAIN) {
		exit_rc = -EINVAL;
		LOG_ERR("TEST %d %s FAILED: Read event should return -EAGAIN",
			id, __func__);
	}

	read_size = kfi_eq_readerr(eq, &error, 0);
	if (read_size != -EAGAIN) {
		exit_rc = -EINVAL;
		LOG_ERR("TEST %d %s FAILED: Read error should return -EAGAIN",
			id, __func__);
	}

	rc = kfi_close(&eq->fid);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unable to close EQ", id, __func__);
		return rc;
	}

	if (!exit_rc)
		LOG_INFO("TEST %d %s PASSED", id, __func__);

	return exit_rc;
}

static void test_fini(void)
{
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

	rc = test_create_close_eq_null_attr_handler(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_create_close_eq_full_args(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_premature_fabric_close(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_eq_bad_size(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_eq_bad_flags(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_eq_bad_wait_obj(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_eq_non_null_wait_set(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_single_event_no_cb(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_single_event_cb(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_single_error_no_cb(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_single_error_cb(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_overrun(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_single_event_peek(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_single_error_peek(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_read_empty_queue(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	if (!exit_rc)
		LOG_INFO("ALL TESTS PASSED");

	test_fini();

	return exit_rc;
}

static void __exit test_module_exit(void)
{
}


module_init(test_module_init);
module_exit(test_module_exit);
