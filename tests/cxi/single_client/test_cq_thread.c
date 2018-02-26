// SPDX-License-Identifier: GPL-2.0
/*
 * Kfabric fabric tests.
 * Copyright 2018 Cray Inc. All Rights Reserved.
 */
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/delay.h>
#include <kfabric.h>
#include <kfi_log.h>
#include <kfi_eq.h>

#include "../../../prov/cxi/kcxi_prov.h"

#ifdef MODULE_NAME
#undef MODULE_NAME
#endif
#define MODULE_NAME "test_cq_thread"

#define NUM_THREADS 4
#define CQ_SIZE 200
#define EVENTS_PER_THREAD (CQ_SIZE / NUM_THREADS)
#define BATCH_EVENT_READS 1
#define ERR_GEN_THRESHOLD 40

MODULE_AUTHOR("Ian Ziemba");
MODULE_DESCRIPTION("kfabric CXI completion queue tests with threads");
MODULE_LICENSE("GPL v2");

struct work_info {
	int count;
	int id;
};

static struct kfi_info *info;
static struct kfi_info *hints;
static struct kfid_fabric *fabric;
static struct kfid_domain *domain;
static struct kfid_cq *cq;
static struct kcxi_cq *kcxi_cq;
static atomic_t entry_count = ATOMIC_INIT(0);
static bool terminate;

static struct work_info winfo[NUM_THREADS];
static struct work_info rinfo[NUM_THREADS];

static struct task_struct *readers[NUM_THREADS];
static struct task_struct *writers[NUM_THREADS];

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
	struct kfi_cq_attr attr = {};

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
		goto clean_fabric;
	}

	attr.size = CQ_SIZE;
	attr.format = KFI_CQ_FORMAT_DATA;

	rc = kfi_cq_open(domain, &attr, &cq, NULL, NULL);
	if (rc) {
		LOG_ERR("Failed to create CQ object");
		goto clean_domain;
	}

	kcxi_cq = container_of(cq, struct kcxi_cq, cq_fid);

	return 0;

clean_domain:
	kfi_close(&domain->fid);
clean_fabric:
	kfi_close(&fabric->fid);
out:
	if (hints)
		kfi_freeinfo(hints);
	if (info)
		kfi_freeinfo(info);

	return rc;

}

static void test_fini(void)
{
	kfi_close(&cq->fid);
	kfi_close(&domain->fid);
	kfi_close(&fabric->fid);
	kfi_freeinfo(hints);
	kfi_freeinfo(info);
}

static int write_events(void *data)
{
	int count;
	int rc;
	int i;
	int id;
	int rand;
	struct kcxi_req_state req_entry;
	uint64_t flags;

	count = ((struct work_info *)data)->count;
	id = ((struct work_info *)data)->id;

	flags = (KFI_MSG | KFI_SEND);
	req_entry.flags = flags;
	req_entry.context = data;

	/* Write event */
	for (i = 0; i < count; i++) {
		/* Should be a value between 0 and 255 */
		rand = 0;
		get_random_bytes(&rand, 1);

		if (rand < ERR_GEN_THRESHOLD) {

			rc = kcxi_cq->report_error(kcxi_cq, &req_entry, 999, 5,
						   -77);
			if (rc < 0) {
				LOG_ERR("Unable to write to CQ error");
				terminate = true;
				goto out;
			}

			LOG_INFO("Write Thread %d: Wrote Error %d", id, i);

		} else {
			rc = kcxi_cq->report_completion(kcxi_cq,
							KFI_ADDR_NOTAVAIL,
							&req_entry);
			if (rc < 0) {
				LOG_ERR("Unable to write to CQ completion");
				terminate = true;
				goto out;
			}

			LOG_INFO("Write Thread %d: Wrote Event %d", id, i);
		}
		atomic_inc(&entry_count);
	}
out:
	LOG_INFO("Write Thread %d: Exiting", id);
	return 0;
}

static int read_events(void *data)
{
	struct kfi_cq_data_entry events[BATCH_EVENT_READS];
	struct kfi_cq_err_entry error;
	int count;
	int id;
	ssize_t read_count;

	count = ((struct work_info *)data)->count;
	id = ((struct work_info *)data)->id;

	while (count > 0 && !terminate) {

		read_count = kfi_cq_read(cq, &events, BATCH_EVENT_READS);
		if (read_count == -EAGAIN) {
			LOG_INFO("Read Thread %d: Going to Sleep", id);

			msleep(20);

			LOG_INFO("Read Thread %d: Waking Up", id);
		} else if (read_count == -KFI_EAVAIL) {

			error.err_data_size = 0;

			/* Process the error instead of event */
			read_count = kfi_cq_readerr(cq, &error, 0);
			if (read_count > 0) {
				LOG_INFO("Read Thread %d: Consumed Error %d",
					 id, count);
				atomic_dec(&entry_count);
				count--;
			} else if (read_count != -EAGAIN) {
				LOG_ERR("Unexpected RC returned");
				terminate = true;
				goto out;
			}
		} else if (read_count < 0) {
			LOG_ERR("Unexpected RC returned");
			terminate = true;
			goto out;
		} else {
			LOG_INFO("Read Thread %d: Consumed Events %d", id,
				 count);
			atomic_dec(&entry_count);
			count -= read_count;
		}
	}

out:
	LOG_INFO("Read Thread %d: Exiting", id);
	return 0;
}

static int spawn_multiple_threads(void)
{
	int i;

	for (i = 0; i < NUM_THREADS; i++) {
		rinfo[i].count = EVENTS_PER_THREAD;
		rinfo[i].id = i;

		readers[i] = kthread_run(read_events, &rinfo[i], "tstr%d", i);
		if (IS_ERR(readers[i])) {
			LOG_ERR("Failed to create reader thread");
			terminate = true;
			return PTR_ERR(readers[i]);
		}
	}

	for (i = 0; i < NUM_THREADS; i++) {
		winfo[i].count = EVENTS_PER_THREAD;
		winfo[i].id = i;

		writers[i] = kthread_run(write_events, &winfo[i], "tstw%d", i);
		if (IS_ERR(writers[i])) {
			LOG_ERR("Failed to create writer thread");
			terminate = true;
			return PTR_ERR(writers[i]);
		}
	}

	return 0;
}

static int __init test_module_init(void)
{
	int rc = 0;

	rc = test_init();
	if (rc)
		return rc;

	rc = spawn_multiple_threads();
	if (rc) {
		test_fini();
		return rc;
	}

	return 0;
}

static void __exit test_module_exit(void)
{
	test_fini();
	if (atomic_read(&entry_count) || terminate)
		LOG_ERR("Test Failed: Not all entries consumed");
	else
		LOG_INFO("Test Passed: All entries consumed");
}


module_init(test_module_init);
module_exit(test_module_exit);
