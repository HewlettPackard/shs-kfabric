/*
 * Kfabric fabric tests.
 * Copyright 2018 Cray Inc. All Rights Reserved.
 *
 * SPDX-License-Identifier: GPL-2.0
 */
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <kfabric.h>
#include <kfi_log.h>
#include <kfi_eq.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <test_common.h>

#include "../../../prov/cxi/kcxi_prov.h"

#ifdef MODULE_NAME
#undef MODULE_NAME
#endif
#define MODULE_NAME "test_mr_alloc_async"

MODULE_AUTHOR("Ian Ziemba");
MODULE_DESCRIPTION("kfabric KCXI MR async allocation tests");
MODULE_LICENSE("GPL v2");

static struct sep_resource *res;
static DECLARE_WAIT_QUEUE_HEAD(wait_queue);
static bool wake_up;

static void test_drain_eq(void)
{
	uint32_t event_type;
	struct kfi_eq_entry event;
	struct kfi_eq_err_entry error;
	int rc;

	/* Drain any potential errors. */
	do {
		rc = kfi_eq_readerr(res->eq, &error, 0);
	} while (rc != -KFI_EAGAIN);

	/* Drain any potential events. */
	do {
		rc = kfi_eq_read(res->eq, &event_type, &event, sizeof(event),
				 0);
	} while (rc != -KFI_EAGAIN);
}

static void test_eq_cb(struct kfid_eq *eq, void *context)
{
	wake_up = true;
	wake_up(&wait_queue);
}

static int test_init(void)
{
	struct sep_resource_opts res_opts = {};
	struct kfi_av_attr av_attr = {};

	av_attr.type = KFI_AV_UNSPEC;

	res_opts.hints = kfi_allocinfo();
	if (!res_opts.hints) {
		LOG_ERR("Failed to allocate info structure");
		return -ENOMEM;
	}

	/* Set resource for async MR. */
	res_opts.hints->caps = (KFI_RMA | KFI_WRITE | KFI_READ |
				KFI_REMOTE_READ | KFI_REMOTE_WRITE);
	res_opts.av_attr = &av_attr;
	res_opts.eq_handler = test_eq_cb;
	res_opts.async_mr_events = true;
	res_opts.rx_count = 1;

	res = sep_resource_alloc(&res_opts);
	if (IS_ERR(res)) {
		LOG_ERR("Failed to allocate SEP resource: rc=%ld",
			PTR_ERR(res));
		kfi_freeinfo(res_opts.hints);
		return PTR_ERR(res);
	}

	kfi_freeinfo(res_opts.hints);

	return 0;
}

static void test_fini(void)
{
	sep_resource_free(res);
}

/*
 * Test allocation of a memory region with remote read/write access and a size
 * of 123 bytes.
 */
static int test_mr_alloc_remote_read_write_123_bytes(int id)
{
	size_t len = 123;
	void *buf;
	struct kfid_mr *mr;
	int rc;
	uint64_t access = (KFI_REMOTE_READ | KFI_REMOTE_WRITE);
	struct kfi_eq_entry event;
	uint32_t event_type;

	wake_up = false;

	buf = kzalloc(len, GFP_KERNEL);
	if (!buf) {
		LOG_ERR("Failed to allocate buffer");
		rc = -ENOMEM;
		goto err;
	}

	rc = kfi_mr_reg(res->domain, buf, len, access, 0, 0, 0, &mr, &access);
	if (rc) {
		LOG_ERR("Failed to register buffer of %lu bytes", len);
		goto err_free_buf;
	}

	rc = mr_enable(res->rx[0], mr);
	if (rc) {
		LOG_ERR("Failed to enabled MR: rc=%d", rc);
		goto err_free_mr;
	}

	rc = wait_event_timeout(wait_queue, wake_up == true, HZ);
	if (!rc) {
		LOG_ERR("Failed to be woken up by event");
		rc = -ETIMEDOUT;
		goto err_free_mr;
	}

	rc = kfi_eq_read(res->eq, &event_type, &event, sizeof(event), 0);
	if (rc != sizeof(event)) {
		LOG_ERR("Failed to read event from the event queue");
		goto err_free_mr;
	}

	if (event_type != KFI_MR_COMPLETE) {
		LOG_ERR("Failed to get KFI_MR_COMPLETE event type");
		rc = -EINVAL;
		goto err_free_mr;
	}

	if (event.fid != &mr->fid) {
		LOG_ERR("Failed to set event fid to MR fid");
		rc = -EINVAL;
		goto err_free_mr;
	}

	if (event.context != &access) {
		LOG_ERR("Failed to set event context to MR context");
		rc = -EINVAL;
		goto err_free_mr;
	}

	kfi_close(&mr->fid);

	kfree(buf);

	/* Draining EQ will arm callback. */
	test_drain_eq();

	LOG_INFO("Test %d %s PASSED", id, __func__);

	return 0;

err_free_mr:
	kfi_close(&mr->fid);
err_free_buf:
	kfree(buf);
err:
	test_drain_eq();
	LOG_ERR("Test %d %s FAILED", id, __func__);
	return rc;
}

/*
 * Test allocation of 30 memory regions with remote read/write access.
 */
static int test_mr_alloc_remote_read_write_30_mrs(int id)
{
	size_t num_mrs = 30;
	size_t len = 535;
	void *buf;
	struct kfid_mr *mr[30];
	int rc;
	uint64_t access = (KFI_REMOTE_READ | KFI_REMOTE_WRITE);
	struct kfi_eq_entry event;
	uint32_t event_type;
	int i;

	buf = kzalloc(len, GFP_KERNEL);
	if (!buf) {
		LOG_ERR("Failed to allocate buffer");
		rc = -ENOMEM;
		goto err;
	}

	for (i = 0; i < num_mrs; i++) {
		wake_up = false;

		rc = kfi_mr_reg(res->domain, buf, len, access, 0, i, 0, &mr[i],
				&access);
		if (rc) {
			LOG_ERR("Failed to register buffer of %lu bytes", len);
			goto err_free_buf;
		}

		rc = mr_enable(res->rx[0], mr[i]);
		if (rc) {
			LOG_ERR("Failed to enabled MR: rc=%d", rc);
			goto err_free_mr;
		}

		rc = wait_event_timeout(wait_queue, wake_up == true, HZ);
		if (!rc) {
			LOG_ERR("Failed to be woken up by event");
			rc = -ETIMEDOUT;
			goto err_free_mr;
		}

		rc = kfi_eq_read(res->eq, &event_type, &event, sizeof(event),
				 0);
		if (rc != sizeof(event)) {
			LOG_ERR("Failed to read event from the event queue");
			goto err_free_mr;
		}

		if (event_type != KFI_MR_COMPLETE) {
			LOG_ERR("Failed to get KFI_MR_COMPLETE event type");
			rc = -EINVAL;
			goto err_free_mr;
		}

		if (event.fid != &mr[i]->fid) {
			LOG_ERR("Failed to set event fid to MR fid");
			rc = -EINVAL;
			goto err_free_mr;
		}

		if (event.context != &access) {
			LOG_ERR("Failed to set event context to MR context");
			rc = -EINVAL;
			goto err_free_mr;
		}

		/* Draining EQ will rearm CB. */
		test_drain_eq();
	}

	for (i = 0; i < num_mrs; i++)
		kfi_close(&mr[i]->fid);

	kfree(buf);

	LOG_INFO("Test %d %s PASSED", id, __func__);

	return 0;

err_free_mr:
	for (i -= 1; i >= 0; i--)
		kfi_close(&mr[i]->fid);
err_free_buf:
	kfree(buf);
err:
	test_drain_eq();
	LOG_ERR("Test %d %s FAILED", id, __func__);
	return rc;
}

/*
 * Test allocation of a memory region where the requested key is redundant. The
 * expected behavior is to have -KFI_ENOKEY returned.
 */
static int test_mr_alloc_remote_read_write_same_key(int id)
{
	size_t len = 4096;
	uint64_t rkey = 0xFFAA;
	void *buf;
	struct kfid_mr *mr;
	struct kfid_mr *bad_mr;
	int rc;
	uint64_t access = (KFI_REMOTE_READ | KFI_REMOTE_WRITE);

	wake_up = false;

	buf = kzalloc(len, GFP_KERNEL);
	if (!buf) {
		LOG_ERR("Failed to allocate buffer");
		rc = -ENOMEM;
		goto err;
	}

	rc = kfi_mr_reg(res->domain, buf, len, access, 0, rkey, 0, &mr, NULL);
	if (rc) {
		LOG_ERR("Failed to register buffer with key %llu", rkey);
		goto err_free_buf;
	}

	rc = mr_enable(res->rx[0], mr);
	if (rc) {
		LOG_ERR("Failed to enabled MR: rc=%d", rc);
		goto err_free_mr;
	}

	rc = kfi_mr_reg(res->domain, buf, len, access, 0, rkey, 0, &bad_mr,
			NULL);
	if (rc) {
		LOG_ERR("Failed to register buffer with key %llu", rkey);
		goto err_free_mr;
	}

	rc = mr_enable(res->rx[0], bad_mr);
	if (rc != -KFI_ENOKEY) {
		LOG_ERR("-KFI_ENOKEY not returned");
		rc = -EINVAL;
		goto err_free_mr2;
	}

	rc = wait_event_timeout(wait_queue, wake_up == true, HZ);
	if (!rc) {
		LOG_ERR("Failed to be woken up by event");
		rc = -ETIMEDOUT;
	}

	kfi_close(&bad_mr->fid);
	kfi_close(&mr->fid);

	kfree(buf);

	LOG_INFO("Test %d %s PASSED", id, __func__);

	return 0;

err_free_mr2:
	kfi_close(&bad_mr->fid);
err_free_mr:
	kfi_close(&mr->fid);
err_free_buf:
	kfree(buf);
err:
	test_drain_eq();
	LOG_ERR("Test %d %s FAILED", id, __func__);
	return rc;
}

static int __init test_module_init(void)
{
	int rc = 0;
	int exit_rc = 0;
	int test_id = 1;

	rc = test_init();
	if (rc)
		return rc;

	rc = test_mr_alloc_remote_read_write_123_bytes(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_mr_alloc_remote_read_write_30_mrs(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_mr_alloc_remote_read_write_same_key(test_id);
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
