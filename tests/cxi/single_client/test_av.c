/*
 * Kfabric fabric tests.
 * Copyright 2018,2025 Hewlett Packard Enterprise Development LP
 *
 * SPDX-License-Identifier: GPL-2.0
 */
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <kfabric.h>
#include <kfi_log.h>
#include <kfi_eq.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/atomic.h>
#include <linux/wait.h>

#include "../../../prov/cxi/kcxi_prov.h"

#ifdef MODULE_NAME
#undef MODULE_NAME
#endif
#define MODULE_NAME "test_av"

MODULE_AUTHOR("Ian Ziemba");
MODULE_DESCRIPTION("kfabric CXI address vector tests");
MODULE_LICENSE("GPL v2");

static struct kfi_info *info;
static struct kfi_info *hints;
static struct kfid_fabric *fabric;
static struct kfid_domain *domain;
static struct kfid_eq *eq;
static char *valid_ipv4 = "192.168.1.1";
static atomic_t cb_count = ATOMIC_INIT(0);
static DECLARE_WAIT_QUEUE_HEAD(queue);

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

static void event_handler(struct kfid_eq *eq, void *context)
{
	atomic_inc(&cb_count);

	wake_up(&queue);
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

	rc = kfi_eq_open(fabric, NULL, &eq, event_handler, NULL);
	if (rc) {
		LOG_ERR("Failed to create EQ object rc=%d", rc);
		goto close_fabric;
	}

	rc = kfi_domain(fabric, info, &domain, NULL);
	if (rc) {
		LOG_ERR("Failed to create domain object");
		goto close_eq;
	}

	return 0;

close_eq:
	kfi_close(&eq->fid);
close_fabric:
	kfi_close(&fabric->fid);
out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;

}

static int test_open_close_av(int id)
{
	struct kfid_av *av;
	struct kfi_av_attr attr = {};
	int rc;

	attr.type = KFI_AV_UNSPEC;

	rc = kfi_av_open(domain, &attr, &av, NULL);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unabled to open av", id, __func__);
		return rc;
	}

	rc = kfi_close(&av->fid);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unabled to close av", id, __func__);
		return rc;
	}

	LOG_INFO("TEST %d %s PASSED", id, __func__);
	return 0;
}

static int test_av_null_attrs(int id)
{
	struct kfid_av *av;
	int rc;

	rc = kfi_av_open(domain, NULL, &av, NULL);
	if (!rc) {
		LOG_ERR("TEST %d %s FAILED: Should not have opened av", id,
			__func__);
		kfi_close(&av->fid);
		return -EINVAL;
	}

	LOG_INFO("TEST %d %s PASSED", id, __func__);
	return 0;
}

static int test_premature_domain_close(int id)
{
	struct kfid_av *av;
	struct kfi_av_attr attr = {};
	int rc;
	int exit_rc = 0;

	attr.type = KFI_AV_UNSPEC;

	rc = kfi_av_open(domain, &attr, &av, NULL);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unabled to open av", id, __func__);
		return rc;
	}

	rc = kfi_close(&domain->fid);
	if (rc != -EBUSY) {
		LOG_ERR("TEST %d %s FAILED: Should not have close domain", id,
			__func__);
		exit_rc = -EINVAL;
	}

	rc = kfi_close(&av->fid);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unabled to close av", id, __func__);
		return rc;
	}

	if (!exit_rc)
		LOG_INFO("TEST %d %s PASSED", id, __func__);

	return exit_rc;
}

static int test_bind_single_eq(int id)
{
	struct kfid_av *av;
	struct kfi_av_attr attr = {};
	int rc;
	int exit_rc = 0;

	attr.type = KFI_AV_UNSPEC;

	rc = kfi_av_open(domain, &attr, &av, NULL);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unabled to open av", id, __func__);
		return rc;
	}

	rc = kfi_av_bind(av, &eq->fid, 0);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Could not bind EQ to AV", id,
			__func__);
		exit_rc = rc;
	}

	rc = kfi_close(&av->fid);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unabled to close av", id, __func__);
		return rc;
	}

	if (!exit_rc)
		LOG_INFO("TEST %d %s PASSED", id, __func__);

	return exit_rc;
}

static int test_bind_double_eq(int id)
{
	struct kfid_av *av;
	struct kfi_av_attr attr = {};
	int rc;
	int exit_rc = 0;

	attr.type = KFI_AV_UNSPEC;

	rc = kfi_av_open(domain, &attr, &av, NULL);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unabled to open av", id, __func__);
		return rc;
	}

	rc = kfi_av_bind(av, &eq->fid, 0);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Could not bind EQ to AV", id,
			__func__);
		exit_rc = rc;
	}

	rc = kfi_av_bind(av, &eq->fid, 0);
	if (!rc) {
		LOG_ERR("TEST %d %s FAILED: Should not have bound EQ to AV", id,
			__func__);
		exit_rc = -EINVAL;
	}

	rc = kfi_close(&av->fid);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unabled to close av", id, __func__);
		return rc;
	}

	if (!exit_rc)
		LOG_INFO("TEST %d %s PASSED", id, __func__);

	return exit_rc;
}

static int test_premature_eq_close(int id)
{
	struct kfid_av *av;
	struct kfi_av_attr attr = {};
	int rc;
	int exit_rc = 0;

	attr.type = KFI_AV_UNSPEC;

	rc = kfi_av_open(domain, &attr, &av, NULL);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unabled to open av", id, __func__);
		return rc;
	}

	rc = kfi_av_bind(av, &eq->fid, 0);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Could not bind EQ to AV", id,
			__func__);
		exit_rc = rc;
		goto out;
	}

	rc = kfi_close(&eq->fid);
	if (rc != -EBUSY) {
		LOG_ERR("TEST %d %s FAILED: Should not have close EQ", id,
			__func__);
		exit_rc = -EINVAL;
	}

out:
	rc = kfi_close(&av->fid);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unabled to close av", id, __func__);
		return rc;
	}

	if (!exit_rc)
		LOG_INFO("TEST %d %s PASSED", id, __func__);

	return exit_rc;
}

static int test_verify_av_attrs(int id)
{
	struct kfid_av *av;
	struct kcxi_av *kcxi_av;
	struct kfi_av_attr attr = {};
	int rc;
	int exit_rc = 0;

	attr.type = KFI_AV_MAP;
	attr.count = 1234;
	attr.rx_ctx_bits = 16;

	rc = kfi_av_open(domain, &attr, &av, NULL);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unabled to open av", id, __func__);
		return rc;
	}

	kcxi_av = container_of(av, struct kcxi_av, av_fid);

	if (kcxi_av->attr.type != attr.type) {
		LOG_ERR("TEST %d %s FAILED: Bad AV type", id, __func__);
		exit_rc = -EINVAL;
		goto out;
	}

	if (kcxi_av->attr.count != attr.count) {
		LOG_ERR("TEST %d %s FAILED: Bad AV count", id, __func__);
		exit_rc = -EINVAL;
		goto out;
	}

	if (kcxi_av->attr.rx_ctx_bits != attr.rx_ctx_bits) {
		LOG_ERR("TEST %d %s FAILED: Bad AV RX CTX bits", id, __func__);
		exit_rc = -EINVAL;
		goto out;
	}

	if ((int)kcxi_av->table_hdr->size != attr.count) {
		LOG_ERR("TEST %d %s FAILED: Bad AV table size", id, __func__);
		exit_rc = -EINVAL;
		goto out;
	}

	if ((int)kcxi_av->table_hdr->stored != 0) {
		LOG_ERR("TEST %d %s FAILED: Bad AV table entries", id,
			__func__);
		exit_rc = -EINVAL;
		goto out;
	}

out:
	rc = kfi_close(&av->fid);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unabled to close av", id, __func__);
		return rc;
	}

	if (!exit_rc)
		LOG_INFO("TEST %d %s PASSED", id, __func__);

	return exit_rc;
}

static int test_bad_av_rx_ctx_bits(int id)
{
	struct kfid_av *av;
	struct kfi_av_attr attr = {};
	int rc;

	attr.rx_ctx_bits = 32;

	rc = kfi_av_open(domain, &attr, &av, NULL);
	if (!rc) {
		LOG_ERR("TEST %d %s FAILED: Should not have opened av", id,
			__func__);
		kfi_close(&av->fid);
		return -EINVAL;
	}

	LOG_INFO("TEST %d %s PASSED", id, __func__);

	return 0;
}

static int test_bad_av_read_flag(int id)
{
	struct kfid_av *av;
	struct kfi_av_attr attr = {};
	int rc;

	attr.flags = KFI_READ;

	rc = kfi_av_open(domain, &attr, &av, NULL);
	if (!rc) {
		LOG_ERR("TEST %d %s FAILED: Should not have opened av", id,
			__func__);
		kfi_close(&av->fid);
		return -EINVAL;
	}

	LOG_INFO("TEST %d %s PASSED", id, __func__);

	return 0;
}

static int test_bad_av_symmetric_flag(int id)
{
	struct kfid_av *av;
	struct kfi_av_attr attr = {};
	int rc;

	attr.flags = KFI_SYMMETRIC;

	rc = kfi_av_open(domain, &attr, &av, NULL);
	if (!rc) {
		LOG_ERR("TEST %d %s FAILED: Should not have opened av", id,
			__func__);
		kfi_close(&av->fid);
		return -EINVAL;
	}

	LOG_INFO("TEST %d %s PASSED", id, __func__);

	return 0;
}

static int test_av_single_add(int id)
{
	struct kfid_av *av;
	struct kcxi_av *kcxi_av;
	struct kfi_av_attr attr = {};
	kfi_addr_t kfi_addr;
	struct kcxi_addr addr = {};
	size_t addr_len = sizeof(addr);
	char *buf;
	size_t len = 50;
	int rc;
	int exit_rc = 0;

	attr.type = KFI_AV_UNSPEC;

	rc = kfi_av_open(domain, &attr, &av, NULL);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unabled to open av", id, __func__);
		return rc;
	}

	kcxi_av = container_of(av, struct kcxi_av, av_fid);

	rc = kfi_av_insertsvc(av, "0x2", "32", &kfi_addr, 0, NULL);
	if (rc < 0) {
		LOG_ERR("TEST %d %s FAILED: Failed to insert address", id,
			__func__);
		exit_rc = rc;
		goto out;
	}

	rc = kfi_av_lookup(av, kfi_addr, &addr, &addr_len);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Failed to lookup address", id,
			__func__);
		exit_rc = rc;
		goto out;
	}

	if (addr.nic != 2) {
		LOG_ERR("TEST %d %s FAILED: Failed to verify NIC", id,
			__func__);
		LOG_ERR("Expected 2, got %d", addr.nic);
		exit_rc = -EINVAL;
		goto out;
	}

	if (addr.pid != 32) {
		LOG_ERR("TEST %d %s FAILED: Failed to verify pid", id,
			__func__);
		LOG_ERR("Expected 32, got %d", addr.pid);
		exit_rc = -EINVAL;
		goto out;
	}

	if (kfi_addr != 0) {
		LOG_ERR("TEST %d %s FAILED: First inserted address should be 0",
			id, __func__);
		exit_rc = -EINVAL;
		goto out;
	}

	if (kcxi_av->table_hdr->stored != 1) {
		LOG_ERR("TEST %d %s FAILED: Table stored count should be 1", id,
			__func__);
		exit_rc = -EINVAL;
		goto out;
	}

	buf = kzalloc(len, GFP_KERNEL);
	if (!buf) {
		LOG_ERR("TEST %d %s FAILED: Failed to allocated memory", id,
			__func__);
		exit_rc = -ENOMEM;
		goto out;
	}

	kfi_av_straddr(av, &addr, buf, &len);
	LOG_INFO("Registered Address: %s\n", buf);

	kfree(buf);

out:
	rc = kfi_close(&av->fid);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unabled to close av", id, __func__);
		return rc;
	}

	if (!exit_rc)
		LOG_INFO("TEST %d %s PASSED", id, __func__);

	return exit_rc;
}

static int test_av_grow(int id)
{
	struct kfid_av *av;
	struct kcxi_av *kcxi_av;
	struct kfi_av_attr attr = {};
	kfi_addr_t kfi_addr;
	struct kcxi_addr addr = {};
	size_t addr_len = sizeof(addr);
	char *buf = NULL;
	size_t len = 50;
	char *service = NULL;
	int i;
	int rc;
	int exit_rc = 0;

	attr.type = KFI_AV_UNSPEC;
	attr.count = 2;

	rc = kfi_av_open(domain, &attr, &av, NULL);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unabled to open av", id, __func__);
		return rc;
	}

	kcxi_av = container_of(av, struct kcxi_av, av_fid);

	if (kcxi_av->table_hdr->size != 2) {
		LOG_ERR("TEST %d %s FAILED: Table size incorrect", id,
			__func__);
		exit_rc = -EINVAL;
		goto out;
	}

	/* Insert more than 2 addresses should cause the AV to grow */
	for (i = 0; i < 20; i++) {

		service = kasprintf(GFP_KERNEL, "%d", i);
		if (!service) {
			LOG_ERR("TEST %d %s FAILED: Failed to allocate memory",
				id, __func__);
			exit_rc = -ENOMEM;
			goto out;
		}

		rc = kfi_av_insertsvc(av, "0x2", service, &kfi_addr, 0, NULL);
		if (rc < 0) {
			LOG_ERR("TEST %d %s FAILED: Failed to insert address",
				id, __func__);
			exit_rc = rc;
			goto out;
		}

		LOG_INFO("kfi_addr=%llu", kfi_addr);

		rc = kfi_av_lookup(av, kfi_addr, &addr, &addr_len);
		if (rc) {
			LOG_ERR("TEST %d %s FAILED: Failed to lookup address",
				id, __func__);
			exit_rc = rc;
			goto out;
		}

		if (addr.nic != 2) {
			LOG_ERR("TEST %d %s FAILED: Failed to verify NIC", id,
				__func__);
			LOG_ERR("Expected 2, got %d", addr.nic);
			exit_rc = -EINVAL;
			goto out;
		}

		if (addr.pid != i) {
			LOG_ERR("TEST %d %s FAILED: Failed to verify domain",
				id, __func__);
			LOG_ERR("Expected %d, got %d", i, addr.pid);
			exit_rc = -EINVAL;
			goto out;
		}

		buf = kzalloc(len, GFP_KERNEL);
		if (!buf) {
			LOG_ERR("TEST %d %s FAILED: Failed to allocated memory",
				id, __func__);
			exit_rc = -ENOMEM;
			goto out;
		}

		kfi_av_straddr(av, &addr, buf, &len);
		LOG_INFO("Registered Address: %s\n", buf);

		kfree(buf);
		kfree(service);
		buf = NULL;
		service = NULL;
	}

	if (kcxi_av->table_hdr->stored != 20) {
		LOG_ERR("TEST %d %s FAILED: Table stored count should be 20 (%lld)",
			id, __func__, kcxi_av->table_hdr->stored);
		exit_rc = -EINVAL;
		goto out;
	}

	if (kcxi_av->table_hdr->size != 32) {
		LOG_ERR("TEST %d %s FAILED: Table did not grow as expected", id,
			__func__);
		exit_rc = -EINVAL;
		goto out;
	}

out:
	kfree(buf);
	kfree(service);

	rc = kfi_close(&av->fid);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unabled to close av", id, __func__);
		return rc;
	}

	if (!exit_rc)
		LOG_INFO("TEST %d %s PASSED", id, __func__);

	return exit_rc;
}

static int test_av_remove(int id)
{
	struct kfid_av *av;
	struct kfi_av_attr attr = {};
	kfi_addr_t kfi_addr;
	struct kcxi_addr addr = {};
	size_t addr_len = sizeof(addr);
	int rc;
	int exit_rc = 0;

	attr.type = KFI_AV_UNSPEC;

	rc = kfi_av_open(domain, &attr, &av, NULL);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unabled to open av", id, __func__);
		return rc;
	}

	rc = kfi_av_insertsvc(av, "0x2", "32", &kfi_addr, 0, NULL);
	if (rc < 0) {
		LOG_ERR("TEST %d %s FAILED: Failed to insert address", id,
			__func__);
		exit_rc = rc;
		goto out;
	}

	rc = kfi_av_remove(av, &kfi_addr, 1, 0);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Failed to remove address", id,
			__func__);
		exit_rc = rc;
		goto out;
	}

	rc = kfi_av_lookup(av, kfi_addr, &addr, &addr_len);
	if (!rc) {
		LOG_ERR("TEST %d %s FAILED: Should not have lookup address", id,
			__func__);
		exit_rc = -EINVAL;
		goto out;
	}

out:
	rc = kfi_close(&av->fid);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unabled to close av", id, __func__);
		return rc;
	}

	if (!exit_rc)
		LOG_INFO("TEST %d %s PASSED", id, __func__);

	return exit_rc;
}

static int test_av_insert_remove(int id)
{
	struct kfid_av *av;
	struct kcxi_av *kcxi_av;
	struct kfi_av_attr attr = {};
	kfi_addr_t kfi_addr;
	struct kcxi_addr addr_in = {};
	struct kcxi_addr addr = {};
	size_t addr_len = sizeof(addr);
	char *buf;
	size_t len = 50;
	int rc;
	int exit_rc = 0;

	attr.type = KFI_AV_UNSPEC;

	rc = kfi_av_open(domain, &attr, &av, NULL);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unabled to open av", id, __func__);
		return rc;
	}

	kcxi_av = container_of(av, struct kcxi_av, av_fid);

	addr_in.nic = 2;
	addr_in.pid = 32;
	rc = kfi_av_insert(av, &addr_in, 1, &kfi_addr, 0, NULL);
	if (rc < 0) {
		LOG_ERR("TEST %d %s FAILED: Failed to insert address", id,
			__func__);
		exit_rc = rc;
		goto out;
	}

	rc = kfi_av_lookup(av, kfi_addr, &addr, &addr_len);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Failed to lookup address", id,
			__func__);
		exit_rc = rc;
		goto out;
	}

	if (addr.nic != 2) {
		LOG_ERR("TEST %d %s FAILED: Failed to verify NIC", id,
			__func__);
		LOG_ERR("Expected 2, got %d", addr.nic);
		exit_rc = -EINVAL;
		goto out;
	}

	if (addr.pid != 32) {
		LOG_ERR("TEST %d %s FAILED: Failed to verify pid", id,
			__func__);
		LOG_ERR("Expected 32, got %d", addr.pid);
		exit_rc = -EINVAL;
		goto out;
	}

	if (kfi_addr != 0) {
		LOG_ERR("TEST %d %s FAILED: First inserted address should be 0",
			id, __func__);
		exit_rc = -EINVAL;
		goto out;
	}

	if (kcxi_av->table_hdr->stored != 1) {
		LOG_ERR("TEST %d %s FAILED: Table stored count should be 1", id,
			__func__);
		exit_rc = -EINVAL;
		goto out;
	}

	buf = kzalloc(len, GFP_KERNEL);
	if (!buf) {
		LOG_ERR("TEST %d %s FAILED: Failed to allocated memory", id,
			__func__);
		exit_rc = -ENOMEM;
		goto out;
	}

	kfi_av_straddr(av, &addr, buf, &len);
	LOG_INFO("Registered Address: %s\n", buf);

	kfree(buf);

	rc = kfi_av_remove(av, &kfi_addr, 1, 0);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Failed to remove address", id,
			__func__);
		exit_rc = rc;
		goto out;
	}

	rc = kfi_av_lookup(av, kfi_addr, &addr, &addr_len);
	if (!rc) {
		LOG_ERR("TEST %d %s FAILED: Should not have lookup address", id,
			__func__);
		exit_rc = -EINVAL;
		goto out;
	}

out:
	rc = kfi_close(&av->fid);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unabled to close av", id, __func__);
		return rc;
	}

	if (!exit_rc)
		LOG_INFO("TEST %d %s PASSED", id, __func__);

	return exit_rc;
}

#define ADDR_COUNT 4

static int test_av_insert_remove_multiple(int id)
{
	struct kfid_av *av;
	struct kcxi_av *kcxi_av;
	struct kfi_av_attr attr = {};
	kfi_addr_t kfi_addr[ADDR_COUNT];
	struct kcxi_addr addr_in[ADDR_COUNT] = {};
	struct kcxi_addr addr = {};
	size_t addr_len = sizeof(addr);
	char *buf = NULL;
	size_t len = 50;
	int i;
	int rc;
	int exit_rc = 0;

	attr.type = KFI_AV_UNSPEC;
	attr.count = 2;

	/* Open the AV with just two available entries */
	rc = kfi_av_open(domain, &attr, &av, NULL);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unabled to open av", id, __func__);
		return rc;
	}

	kcxi_av = container_of(av, struct kcxi_av, av_fid);

	if (kcxi_av->table_hdr->size != 2) {
		LOG_ERR("TEST %d %s FAILED: Table size incorrect", id,
			__func__);
		exit_rc = -EINVAL;
		goto out;
	}

	/* Insert more than 2 addresses should cause the AV to grow */
	for (i = 0; i < ADDR_COUNT; i++) {
		addr_in[i].nic = 2;
		addr_in[i].pid = i;
	}

	rc = kfi_av_insert(av, addr_in, ADDR_COUNT, kfi_addr, 0, NULL);
	if (rc < 0) {
		LOG_ERR("TEST %d %s FAILED: Failed to insert addresses", id,
			__func__);
		exit_rc = rc;
		goto out;
	}

	if (kcxi_av->table_hdr->size != ADDR_COUNT) {
		LOG_ERR("TEST %d %s FAILED: Table did not grow as expected", id,
			__func__);
		exit_rc = -EINVAL;
		goto out;
	}

	for (i = 0; i < ADDR_COUNT; i++) {

		LOG_INFO("kfi_addr[%d]=%llu", i, kfi_addr[i]);

		rc = kfi_av_lookup(av, kfi_addr[i], &addr, &addr_len);
		if (rc) {
			LOG_ERR("TEST %d %s FAILED: Failed to lookup address",
				id, __func__);
			exit_rc = rc;
			goto out;
		}

		if (addr.nic != 2) {
			LOG_ERR("TEST %d %s FAILED: Failed to verify NIC", id,
				__func__);
			LOG_ERR("Expected 2, got %d", addr.nic);
			exit_rc = -EINVAL;
			goto out;
		}

		if (addr.pid != i) {
			LOG_ERR("TEST %d %s FAILED: Failed to verify pid",
				id, __func__);
			LOG_ERR("Expected %d, got %d", i, addr.pid);
			exit_rc = -EINVAL;
			goto out;
		}

		buf = kzalloc(len, GFP_KERNEL);
		if (!buf) {
			LOG_ERR("TEST %d %s FAILED: Failed to allocated memory",
				id, __func__);
			exit_rc = -ENOMEM;
			goto out;
		}

		kfi_av_straddr(av, &addr, buf, &len);
		LOG_INFO("Registered Address: %s\n", buf);

		kfree(buf);
		buf = NULL;
	}

	if (kcxi_av->table_hdr->stored != ADDR_COUNT) {
		LOG_ERR("TEST %d %s FAILED: Table stored count should be %d (%lld)",
			id, __func__, ADDR_COUNT, kcxi_av->table_hdr->stored);
		exit_rc = -EINVAL;
		goto out;
	}

	/* Remove 2 addresses from the middle of the table */
	for (i = 1; i < ADDR_COUNT - 1; i++) {
		rc = kfi_av_remove(av, &kfi_addr[i], 1, 0);
		if (rc) {
			LOG_ERR("TEST %d %s FAILED: Failed to remove address", id,
				__func__);
			exit_rc = rc;
			goto out;
		}

		rc = kfi_av_lookup(av, kfi_addr[i], &addr, &addr_len);
		if (!rc) {
			LOG_ERR("TEST %d %s FAILED: Should not have lookup address", id,
				__func__);
			exit_rc = -EINVAL;
			goto out;
		}
	}

	/* Insert an address, should use one of the newly available table entries */
	rc = kfi_av_insert(av, &addr_in[2], 1, &kfi_addr[2], 0, NULL);
	if (rc < 0) {
		LOG_ERR("TEST %d %s FAILED: Failed to insert address", id,
			__func__);
		exit_rc = rc;
		goto out;
	}

	LOG_INFO("kfi_addr[%d]=%llu", 2, kfi_addr[2]);

	rc = kfi_av_lookup(av, kfi_addr[2], &addr, &addr_len);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Failed to lookup address", id,
			__func__);
		exit_rc = rc;
		goto out;
	}

	if (addr.nic != addr_in[2].nic) {
		LOG_ERR("TEST %d %s FAILED: Failed to verify NIC", id,
			__func__);
		LOG_ERR("Expected 2, got %d", addr.nic);
		exit_rc = -EINVAL;
		goto out;
	}

	if (addr.pid != addr_in[2].pid) {
		LOG_ERR("TEST %d %s FAILED: Failed to verify pid", id,
			__func__);
		LOG_ERR("Expected %d, got %d", addr_in[2].pid, addr.pid);
		exit_rc = -EINVAL;
		goto out;
	}

	buf = kzalloc(len, GFP_KERNEL);
	if (!buf) {
		LOG_ERR("TEST %d %s FAILED: Failed to allocated memory",
			id, __func__);
		exit_rc = -ENOMEM;
		goto out;
	}

	kfi_av_straddr(av, &addr, buf, &len);
	LOG_INFO("Registered Address: %s\n", buf);

	kfree(buf);
	buf = NULL;

out:
	kfree(buf);

	rc = kfi_close(&av->fid);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unabled to close av", id, __func__);
		return rc;
	}

	if (!exit_rc)
		LOG_INFO("TEST %d %s PASSED", id, __func__);

	return exit_rc;
}

static int test_av_async_ipv4_valid(int id)
{
	struct kfid_av *av;
	struct kfi_av_attr attr = {};
	int rc;
	int exit_rc = 0;
	kfi_addr_t kfi_addr;
	struct kfi_eq_entry event;
	uint32_t event_type;

	atomic_set(&cb_count, 0);

	attr.type = KFI_AV_UNSPEC;
	attr.flags = KFI_EVENT;

	rc = kfi_av_open(domain, &attr, &av, NULL);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unabled to open av", id, __func__);
		return rc;
	}

	rc = kfi_av_bind(av, &eq->fid, 0);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Could not bind EQ to AV", id,
			__func__);
		exit_rc = rc;
	}

	rc = kfi_av_insertsvc(av, valid_ipv4, "32", &kfi_addr, 0, av);
	if (rc < 0) {
		LOG_ERR("TEST %d %s FAILED: Failed to insert address", id,
			__func__);
		exit_rc = rc;
		goto out;
	}

	wait_event(queue, atomic_read(&cb_count) == 1);

	rc = kfi_eq_read(eq, &event_type, &event, sizeof(event), 0);
	if (rc < 0) {
		LOG_ERR("TEST %d %s FAILED: Failed to have EQ event", id,
			__func__);
		exit_rc = rc;
		goto out;
	}

	if (event_type != KFI_AV_COMPLETE) {
		LOG_ERR("TEST %d %s FAILED: Bad EQ event type", id, __func__);
		exit_rc = -EINVAL;
		goto out;
	}

	if (event.fid != &av->fid) {
		LOG_ERR("TEST %d %s FAILED: Bad EQ event fid", id, __func__);
		exit_rc = -EINVAL;
		goto out;
	}

	if (event.context != av) {
		LOG_ERR("TEST %d %s FAILED: Bad EQ event context", id,
			__func__);
		exit_rc = -EINVAL;
		goto out;
	}

	if (event.data != 1) {
		LOG_ERR("TEST %d %s FAILED: Bad EQ event data", id, __func__);
		exit_rc = -EINVAL;
		goto out;
	}

	/* Returning -EAGAIN will reset the interrupt. */
	rc = kfi_eq_read(eq, &event_type, &event, sizeof(event), 0);
	if (rc != -EAGAIN) {
		LOG_ERR("TEST %d %s FAILED: unexpected EQ event", id, __func__);
		exit_rc = -EINVAL;
		goto out;
	}
out:
	rc = kfi_close(&av->fid);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unabled to close av", id, __func__);
		return rc;
	}

	if (!exit_rc)
		LOG_INFO("TEST %d %s PASSED", id, __func__);

	return exit_rc;
}

static int test_av_async_ipv4_invalid(int id)
{
	struct kfid_av *av;
	struct kfi_av_attr attr = {};
	int rc;
	int exit_rc = 0;
	kfi_addr_t kfi_addr;
	struct kfi_eq_err_entry error;
	struct kfi_eq_entry event;
	uint32_t event_type;

	atomic_set(&cb_count, 0);

	attr.type = KFI_AV_UNSPEC;
	attr.flags = KFI_EVENT;

	rc = kfi_av_open(domain, &attr, &av, NULL);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unabled to open av", id, __func__);
		return rc;
	}

	rc = kfi_av_bind(av, &eq->fid, 0);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Could not bind EQ to AV", id,
			__func__);
		exit_rc = rc;
	}

	/* Insert an invalid IPv4 address but still on the 192.168.1.0/24
	 * network. This should cause a timeout in resolution.
	 */
	rc = kfi_av_insertsvc(av, "192.168.1.128", "32", &kfi_addr, 0, av);
	if (rc < 0) {
		LOG_ERR("TEST %d %s FAILED: Failed to insert address", id,
			__func__);
		exit_rc = rc;
		goto out;
	}

	wait_event(queue, atomic_read(&cb_count) == 1);

	/* Verify the error event. */
	rc = kfi_eq_readerr(eq, &error, 0);
	if (rc < 0) {
		LOG_ERR("TEST %d %s FAILED: Failed to have EQ event", id,
			__func__);
		exit_rc = rc;
		goto out;
	}

	if (error.fid != &av->fid) {
		LOG_ERR("TEST %d %s FAILED: Bad EQ error fid", id, __func__);
		exit_rc = -EINVAL;
		goto out;
	}

	if (error.context != av) {
		LOG_ERR("TEST %d %s FAILED: Bad EQ error context", id,
			__func__);
		exit_rc = -EINVAL;
		goto out;
	}

	if (error.data != 0) {
		LOG_ERR("TEST %d %s FAILED: Bad EQ error data", id, __func__);
		exit_rc = -EINVAL;
		goto out;
	}

	if (error.err != ETIMEDOUT) {
		LOG_ERR("TEST %d %s FAILED: Bad EQ error err", id, __func__);
		exit_rc = -EINVAL;
		goto out;
	}

	if (error.prov_errno != -ETIMEDOUT) {
		LOG_ERR("TEST %d %s FAILED: Bad EQ error prov_errno", id,
			__func__);
		exit_rc = -EINVAL;
		goto out;
	}

	/* Verify the trailing success event where the data field should be zero
	 * since resolution failed.
	 */
	rc = kfi_eq_read(eq, &event_type, &event, sizeof(event), 0);
	if (rc < 0) {
		LOG_ERR("TEST %d %s FAILED: Failed to have EQ event", id,
			__func__);
		exit_rc = rc;
		goto out;
	}

	if (event_type != KFI_AV_COMPLETE) {
		LOG_ERR("TEST %d %s FAILED: Bad EQ event type", id, __func__);
		exit_rc = -EINVAL;
		goto out;
	}

	if (event.fid != &av->fid) {
		LOG_ERR("TEST %d %s FAILED: Bad EQ event fid", id, __func__);
		exit_rc = -EINVAL;
		goto out;
	}

	if (event.context != av) {
		LOG_ERR("TEST %d %s FAILED: Bad EQ event context", id,
			__func__);
		exit_rc = -EINVAL;
		goto out;
	}

	if (event.data != 0) {
		LOG_ERR("TEST %d %s FAILED: Bad EQ event data", id, __func__);
		exit_rc = -EINVAL;
		goto out;
	}

	/* Returning -EAGAIN will reset the interrupt. */
	rc = kfi_eq_read(eq, &event_type, &event, sizeof(event), 0);
	if (rc != -EAGAIN) {
		LOG_ERR("TEST %d %s FAILED: unexpected EQ event", id, __func__);
		exit_rc = -EINVAL;
		goto out;
	}

out:
	rc = kfi_close(&av->fid);
	if (rc) {
		LOG_ERR("TEST %d %s FAILED: Unabled to close av", id, __func__);
		return rc;
	}

	if (!exit_rc)
		LOG_INFO("TEST %d %s PASSED", id, __func__);

	return exit_rc;
}

static void test_fini(void)
{
	kfi_close(&domain->fid);
	kfi_close(&eq->fid);
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

	rc = test_open_close_av(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_av_null_attrs(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_premature_domain_close(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bind_single_eq(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bind_double_eq(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_premature_eq_close(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_verify_av_attrs(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bad_av_rx_ctx_bits(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bad_av_read_flag(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_bad_av_symmetric_flag(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_av_single_add(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_av_grow(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_av_remove(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_av_insert_remove(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_av_insert_remove_multiple(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_av_async_ipv4_valid(test_id);
	if (rc)
		exit_rc = rc;
	test_id++;

	rc = test_av_async_ipv4_invalid(test_id);
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
