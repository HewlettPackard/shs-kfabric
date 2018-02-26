// SPDX-License-Identifier: GPL-2.0
/* Copyright 2021 Hewlett Packard Enterprise Development LP */
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <kfabric.h>
#include <kfi_log.h>
#include <linux/slab.h>

#ifdef MODULE_NAME
#undef MODULE_NAME
#endif
#define MODULE_NAME "test_run_getinfo"

static char *node = "192.168.1.1";
static char *service = "5";
static int expected_rc;

module_param(expected_rc, int, 0000);
MODULE_PARM_DESC(expected_rc, "Expected return code from kfi_getinfo");
/* The node string could be an IP address or a device (e.g.cxi0) */
module_param(node, charp, 0000);
MODULE_PARM_DESC(node, "node string");

MODULE_AUTHOR("Hewlett Packard Enterprise Development LP");
MODULE_DESCRIPTION("kfabric CXI kfi_getinfo() runner");
MODULE_LICENSE("GPL v2");

static int __init test_module_init(void)
{
	int rc;
	struct kfi_info *info = NULL;

	rc = kfi_getinfo(0, node, service, KFI_SOURCE, NULL, &info);
	if (!rc)
		kfi_freeinfo(info);

	LOG_INFO("expected rc %d, actual rc = %d", expected_rc, rc);
	if (rc == expected_rc) {
		LOG_INFO("TEST PASSED");
		rc = 0;
	} else {
		LOG_INFO("TEST FAILED");
		rc = -1;
	}

	return rc;
}

static void __exit test_module_exit(void)
{
}

module_init(test_module_init);
module_exit(test_module_exit);
