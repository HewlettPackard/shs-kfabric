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
#include <test_common.h>

#include "../../../prov/cxi/kcxi_prov.h"

#ifdef MODULE_NAME
#undef MODULE_NAME
#endif
#define MODULE_NAME "test_mr_alloc_sync"

MODULE_AUTHOR("Ian Ziemba");
MODULE_DESCRIPTION("kfabric KCXI MR sync allocation tests");
MODULE_LICENSE("GPL v2");

static struct sep_resource *res;

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
 * Test allocation of a memory region without any access flags. The CXI provider
 * only uses MRs for remote read/write access. So if these access flags are not
 * specified, the MR allocation should fail.
 */
static int test_mr_alloc_no_access(int id)
{
	size_t len = 4096;
	void *buf;
	struct kfid_mr *mr;
	int rc;

	buf = kzalloc(len, GFP_KERNEL);
	if (!buf) {
		LOG_ERR("Failed to allocate buffer");
		rc = -ENOMEM;
		goto err;
	}

	rc = kfi_mr_reg(res->domain, buf, len, 0, 0, 0, 0, &mr, NULL);
	if (!rc) {
		LOG_ERR("Should not have registered buffer");
		LOG_ERR("Memory should only be registered for remote RMA ops");
		rc = -EINVAL;
		kfi_close(&mr->fid);
		goto err_free_buf;
	}

	kfree(buf);

	LOG_INFO("Test %d %s PASSED", id, __func__);

	return 0;

err_free_buf:
	kfree(buf);
err:
	LOG_ERR("Test %d %s FAILED", id, __func__);
	return rc;
}

/*
 * Test allocation of a memory region with flags set. The KCXI provider does not
 * currently support flags during MR allocation. The expected return code is
 * -KFI_EBADFLAGS.
 */
static int test_mr_alloc_flags_set(int id)
{
	size_t len = 4096;
	void *buf;
	struct kfid_mr *mr;
	int rc;
	uint64_t access = (KFI_REMOTE_READ | KFI_REMOTE_WRITE);
	uint64_t flags = 1;

	buf = kzalloc(len, GFP_KERNEL);
	if (!buf) {
		LOG_ERR("Failed to allocate buffer");
		rc = -ENOMEM;
		goto err;
	}

	rc = kfi_mr_reg(res->domain, buf, len, access, 0, 0, flags, &mr, NULL);
	if (rc != -KFI_EBADFLAGS) {
		LOG_ERR("Bad RC: Got %d, Expected %d", rc, -KFI_EBADFLAGS);

		if (!rc) {
			LOG_ERR("Should not have registered buffer");
			kfi_close(&mr->fid);
		}

		rc = -EINVAL;
		goto err_free_buf;
	}

	kfree(buf);

	LOG_INFO("Test %d %s PASSED", id, __func__);

	return 0;

err_free_buf:
	kfree(buf);
err:
	LOG_ERR("Test %d %s FAILED", id, __func__);
	return rc;
}

/*
 * Test allocation of a memory region where the offset of the buffer exceeds the
 * length. Allocation should fail.
 */
static int test_mr_alloc_bad_offset(int id)
{
	size_t len = 4096;
	void *buf;
	struct kfid_mr *mr;
	int rc;
	uint64_t access = (KFI_REMOTE_READ | KFI_REMOTE_WRITE);

	buf = kzalloc(len, GFP_KERNEL);
	if (!buf) {
		LOG_ERR("Failed to allocate buffer");
		rc = -ENOMEM;
		goto err;
	}

	rc = kfi_mr_reg(res->domain, buf, len, access, len + 1, 0, 0, &mr,
			NULL);
	if (!rc) {
		LOG_ERR("Buffer offset cannot exceed the length");
		LOG_ERR("Should not have registered buffer");
		kfi_close(&mr->fid);
		rc = -EINVAL;
		goto err_free_buf;
	}

	kfree(buf);

	LOG_INFO("Test %d %s PASSED", id, __func__);

	return 0;

err_free_buf:
	kfree(buf);
err:
	LOG_ERR("Test %d %s FAILED", id, __func__);
	return rc;
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

	buf = kzalloc(len, GFP_KERNEL);
	if (!buf) {
		LOG_ERR("Failed to allocate buffer");
		rc = -ENOMEM;
		goto err;
	}

	rc = kfi_mr_reg(res->domain, buf, len, access, 0, 0, 0, &mr, NULL);
	if (rc) {
		LOG_ERR("Failed to register buffer of %lu bytes", len);
		goto err_free_buf;
	}

	rc = mr_enable(res->rx[0], mr);
	if (rc) {
		LOG_ERR("Failed to enabled MR: rc=%d", rc);
		goto err_free_mr;
	}

	kfi_close(&mr->fid);

	kfree(buf);

	LOG_INFO("Test %d %s PASSED", id, __func__);

	return 0;

err_free_mr:
	kfi_close(&mr->fid);
err_free_buf:
	kfree(buf);
err:
	LOG_ERR("Test %d %s FAILED", id, __func__);
	return rc;
}

/*
 * Test allocation of a memory region with remote read/write access and a size
 * of 1234 bytes.
 */
static int test_mr_alloc_remote_read_write_1234_bytes(int id)
{
	size_t len = 1234;
	void *buf;
	struct kfid_mr *mr;
	int rc;
	uint64_t access = (KFI_REMOTE_READ | KFI_REMOTE_WRITE);

	buf = kzalloc(len, GFP_KERNEL);
	if (!buf) {
		LOG_ERR("Failed to allocate buffer");
		rc = -ENOMEM;
		goto err;
	}

	rc = kfi_mr_reg(res->domain, buf, len, access, 0, 0, 0, &mr, NULL);
	if (rc) {
		LOG_ERR("Failed to register buffer of %lu bytes", len);
		goto err_free_buf;
	}

	rc = mr_enable(res->rx[0], mr);
	if (rc) {
		LOG_ERR("Failed to enabled MR: rc=%d", rc);
		goto err_free_mr;
	}

	kfi_close(&mr->fid);

	kfree(buf);

	LOG_INFO("Test %d %s PASSED", id, __func__);

	return 0;

err_free_mr:
	kfi_close(&mr->fid);
err_free_buf:
	kfree(buf);
err:
	LOG_ERR("Test %d %s FAILED", id, __func__);
	return rc;
}

/*
 * Test allocation of a memory region with remote read/write access and a size
 * of 1 MiB.
 */
static int test_mr_alloc_remote_read_write_1048576_bytes(int id)
{
	size_t len = (1 << 20);
	void *buf;
	struct kfid_mr *mr;
	int rc;
	uint64_t access = (KFI_REMOTE_READ | KFI_REMOTE_WRITE);

	buf = kzalloc(len, GFP_KERNEL);
	if (!buf) {
		LOG_ERR("Failed to allocate buffer");
		rc = -ENOMEM;
		goto err;
	}

	rc = kfi_mr_reg(res->domain, buf, len, access, 0, 0, 0, &mr, NULL);
	if (rc) {
		LOG_ERR("Failed to register buffer of %lu bytes", len);
		goto err_free_buf;
	}

	rc = mr_enable(res->rx[0], mr);
	if (rc) {
		LOG_ERR("Failed to enabled MR: rc=%d", rc);
		goto err_free_mr;
	}

	kfi_close(&mr->fid);

	kfree(buf);

	LOG_INFO("Test %d %s PASSED", id, __func__);

	return 0;

err_free_mr:
	kfi_close(&mr->fid);
err_free_buf:
	kfree(buf);
err:
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
		LOG_ERR("Expected the following errno: %d, Got %d", -KFI_ENOKEY,
			rc);
		goto err_free_bad_mr;
	}

	kfi_close(&bad_mr->fid);
	kfi_close(&mr->fid);

	kfree(buf);

	LOG_INFO("Test %d %s PASSED", id, __func__);

	return 0;

err_free_bad_mr:
	kfi_close(&bad_mr->fid);
err_free_mr:
	kfi_close(&mr->fid);
err_free_buf:
	kfree(buf);
err:
	LOG_ERR("Test %d %s FAILED", id, __func__);
	return rc;
}

/*
 * Test allocation of a 30 memory regions.
 */
static int test_mr_alloc_30_mrs(int id)
{
	size_t len = 123;
	void *buf;
	struct kfid_mr **mr;
	int i;
	int rc;
	uint64_t access = (KFI_REMOTE_READ | KFI_REMOTE_WRITE);
	size_t num_mrs = 30;

	buf = kzalloc(len, GFP_KERNEL);
	if (!buf) {
		LOG_ERR("Failed to allocate buffer");
		rc = -ENOMEM;
		goto err;
	}

	mr = kcalloc(num_mrs, sizeof(*mr), GFP_KERNEL);
	if (!mr) {
		LOG_ERR("Failed to allocated MR array");
		rc = -ENOMEM;
		goto err_free_buf;
	}

	for (i = 0; i < num_mrs; i++) {
		rc = kfi_mr_reg(res->domain, buf, len, access, 0, i, 0, &mr[i],
				NULL);
		if (rc) {
			LOG_ERR("Failed to register buffer of %lu bytes", len);
			LOG_ERR("Number of MRs registered: %d", i);
			goto err_free_mr;
		}

		rc = mr_enable(res->rx[0], mr[i]);
		if (rc) {
			LOG_ERR("Failed to enabled MR: rc=%d", rc);
			goto err_free_mr;
		}

		LOG_INFO("MR Allocated: %d", i);
	}

	for (i = 0; i < num_mrs; i++)
		kfi_close(&mr[i]->fid);

	kfree(mr);

	kfree(buf);

	LOG_INFO("Test %d %s PASSED", id, __func__);

	return 0;

err_free_mr:
	for (i -= 1; i >= 0; i--)
		kfi_close(&mr[i]->fid);

err_free_buf:
	kfree(buf);
err:
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

	rc = test_mr_alloc_no_access(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_mr_alloc_flags_set(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_mr_alloc_bad_offset(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_mr_alloc_remote_read_write_123_bytes(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_mr_alloc_remote_read_write_1234_bytes(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_mr_alloc_remote_read_write_1048576_bytes(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_mr_alloc_remote_read_write_same_key(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_mr_alloc_30_mrs(test_id);
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
