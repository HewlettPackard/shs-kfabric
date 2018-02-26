//SPDX-License-Identifier: GPL-2.0
/*
 * Kfabric fabric tests.
 * Copyright 2018 Cray Inc. All Rights Reserved.
 *
 */
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <kfabric.h>
#include <kfi_log.h>
#include <kfi_eq.h>
#include <kfi_errno.h>
#include <test_common.h>

#ifdef MODULE_NAME
#undef MODULE_NAME
#endif
#define MODULE_NAME "test_tx_ctx_opts"

#define MAX_TX_CTX 1

MODULE_AUTHOR("Ian Ziemba");
MODULE_DESCRIPTION("kfabric CXI TX context option tests");
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
	res_opts.hints->caps = KFI_MSG;
	res_opts.av_attr = &av_attr;
	res_opts.tx_count = MAX_TX_CTX;

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

/* Read TX op flags with NULL arg. Should return error. */
static int test_get_op_flags_null_arg(int id)
{
	int rc;
	int expect_rc = -EINVAL;

	rc = kfi_control(&res->tx[0]->fid, KFI_GETOPSFLAG, NULL);
	if (rc != expect_rc) {
		LOG_INFO("TEST %d %s FAILED: rc != %d", id, __func__,
			 expect_rc);
		return -EINVAL;
	}

	LOG_INFO("TEST %d %s PASSED", id, __func__);
	return 0;
}

/* Read TX op flags with zero arg flags. Should return error. */
static int test_get_op_flags_zero_arg_flags(int id)
{
	int rc;
	int expect_rc = -EINVAL;
	uint64_t flags = 0;

	rc = kfi_control(&res->tx[0]->fid, KFI_GETOPSFLAG, &flags);
	if (rc != expect_rc) {
		LOG_INFO("TEST %d %s FAILED: rc != %d", id, __func__,
			 expect_rc);
		return -EINVAL;
	}

	LOG_INFO("TEST %d %s PASSED", id, __func__);
	return 0;
}

/* Read TX op flags with TX and TX arg flags. Should return error. */
static int test_get_op_flags_rx_tx_arg_flags(int id)
{
	int rc;
	int expect_rc = -EINVAL;
	uint64_t flags = (KFI_RECV | KFI_TRANSMIT);

	rc = kfi_control(&res->tx[0]->fid, KFI_GETOPSFLAG, &flags);
	if (rc != expect_rc) {
		LOG_INFO("TEST %d %s FAILED: rc != %d", id, __func__,
			 expect_rc);
		return -EINVAL;
	}

	LOG_INFO("TEST %d %s PASSED", id, __func__);
	return 0;
}

/* Read TX op flags with TX arg flags. Should be a success. */
static int test_get_op_flags_tx_arg_flags(int id)
{
	int rc;
	uint64_t flags = KFI_TRANSMIT;

	rc = kfi_control(&res->tx[0]->fid, KFI_GETOPSFLAG, &flags);
	if (rc) {
		LOG_INFO("TEST %d %s FAILED: rc == %d", id, __func__, rc);
		return rc;
	}

	LOG_INFO("TEST %d %s PASSED", id, __func__);
	return 0;
}

/* Write TX op flags with NULL arg. Should return error. */
static int test_set_op_flags_null_arg(int id)
{
	int rc;
	int expect_rc = -EINVAL;

	rc = kfi_control(&res->tx[0]->fid, KFI_SETOPSFLAG, NULL);
	if (rc != expect_rc) {
		LOG_INFO("TEST %d %s FAILED: rc != %d", id, __func__,
			 expect_rc);
		return -EINVAL;
	}

	LOG_INFO("TEST %d %s PASSED", id, __func__);
	return 0;
}

/* Write TX op flags with zero arg flags. Should return error. */
static int test_set_op_flags_zero_arg_flags(int id)
{
	int rc;
	int expect_rc = -EINVAL;
	uint64_t flags = 0;

	rc = kfi_control(&res->tx[0]->fid, KFI_SETOPSFLAG, &flags);
	if (rc != expect_rc) {
		LOG_INFO("TEST %d %s FAILED: rc != %d", id, __func__,
			 expect_rc);
		return -EINVAL;
	}

	LOG_INFO("TEST %d %s PASSED", id, __func__);
	return 0;
}

/* Write TX op flags with TX and TX arg flags. Should return error. */
static int test_set_op_flags_rx_tx_arg_flags(int id)
{
	int rc;
	int expect_rc = -EINVAL;
	uint64_t flags = (KFI_RECV | KFI_TRANSMIT);

	rc = kfi_control(&res->tx[0]->fid, KFI_SETOPSFLAG, &flags);
	if (rc != expect_rc) {
		LOG_INFO("TEST %d %s FAILED: rc != %d", id, __func__,
			 expect_rc);
		return -EINVAL;
	}

	LOG_INFO("TEST %d %s PASSED", id, __func__);
	return 0;
}

/* Write TX op flags with TX invalid op flags. Should return error. */
static int test_set_op_flags_tx_invalid_flags(int id)
{
	int rc;
	int expect_rc = -EINVAL;
	uint64_t flags = (KFI_RECV | KFI_TRANSMIT_COMPLETE);

	rc = kfi_control(&res->tx[0]->fid, KFI_SETOPSFLAG, &flags);
	if (rc != expect_rc) {
		LOG_INFO("TEST %d %s FAILED: rc != %d", id, __func__,
			 expect_rc);
		return -EINVAL;
	}

	LOG_INFO("TEST %d %s PASSED", id, __func__);
	return 0;
}

/* Write TX op flags with TX valid op flags. Should be a success. */
static int test_set_op_flags_tx_flag(int id)
{
	int rc;
	uint64_t flags;
	uint64_t read_flags;

	flags = KFI_TRANSMIT;
	read_flags = 0;
	rc = kfi_control(&res->tx[0]->fid, KFI_SETOPSFLAG, &flags);
	if (rc) {
		LOG_INFO("TEST %d %s FAILED: rc == %d", id, __func__, rc);
		return rc;
	}

	rc = kfi_control(&res->tx[0]->fid, KFI_GETOPSFLAG, &flags);
	if (rc) {
		LOG_INFO("TEST %d %s FAILED: rc == %d", id, __func__, rc);
		return rc;
	}

	if (flags != read_flags) {
		LOG_INFO("TEST %d %s FAILED: bad read flags", id, __func__);
		return -EINVAL;
	}

	flags = (KFI_TRANSMIT | KFI_COMPLETION);
	read_flags = KFI_COMPLETION;
	rc = kfi_control(&res->tx[0]->fid, KFI_SETOPSFLAG, &flags);
	if (rc) {
		LOG_INFO("TEST %d %s FAILED: rc == %d", id, __func__, rc);
		return rc;
	}

	rc = kfi_control(&res->tx[0]->fid, KFI_GETOPSFLAG, &flags);
	if (rc) {
		LOG_INFO("TEST %d %s FAILED: rc == %d", id, __func__, rc);
		return rc;
	}

	if (flags != read_flags) {
		LOG_INFO("TEST %d %s FAILED: bad read flags", id, __func__);
		return -EINVAL;
	}

	LOG_INFO("TEST %d %s PASSED", id, __func__);
	return 0;
}

static int __init test_module_init(void)
{
	int rc = 0;
	int exit_rc = 0;
	int test_id = 1;

	rc = test_init();
	if (rc)
		return rc;

	rc = test_get_op_flags_null_arg(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_get_op_flags_zero_arg_flags(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_get_op_flags_rx_tx_arg_flags(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_get_op_flags_tx_arg_flags(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_set_op_flags_null_arg(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_set_op_flags_zero_arg_flags(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_set_op_flags_rx_tx_arg_flags(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_set_op_flags_tx_invalid_flags(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_set_op_flags_tx_flag(test_id);
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
