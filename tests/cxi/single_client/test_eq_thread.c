/*
 * Kfabric fabric tests.
 * Copyright 2018 Cray Inc. All Rights Reserved.
 *
 * SPDX-License-Identifier: GPL-2.0
 */
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <kfabric.h>
#include <kfi_log.h>
#include <kfi_eq.h>

#include "../../../prov/cxi/kcxi_prov.h"

#ifdef MODULE_NAME
#undef MODULE_NAME
#endif
#define MODULE_NAME "test_eq_thread"

/* TODO: Fix test for multiple threads. */
#define NUM_THREADS 1
#define EQ_SIZE 200
#define EVENTS_PER_THREAD (EQ_SIZE / NUM_THREADS)
#define ERR_GEN_THRESHOLD 40

MODULE_AUTHOR("Ian Ziemba");
MODULE_DESCRIPTION("kfabric CXI event queue tests with threads");
MODULE_LICENSE("GPL v2");

struct work_info {
	int count;
	int id;
};

static struct kfi_info *info;
static struct kfi_info *hints;
static struct kfid_fabric *fabric;
static struct kfid_eq *eq;
static struct kcxi_eq *kcxi_eq;
static atomic_t entry_count = ATOMIC_INIT(0);
static atomic_t cb_count = ATOMIC_INIT(0);
static bool terminate;

static DECLARE_WAIT_QUEUE_HEAD(event_wait);
static struct work_info winfo[NUM_THREADS];
static struct work_info rinfo[NUM_THREADS];

static struct task_struct *readers[NUM_THREADS];
static struct task_struct *writers[NUM_THREADS];

void wakeup_event_handler(struct kfid_eq *eq, void *context)
{
	atomic_inc(&cb_count);
	wake_up(&event_wait);
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
	struct kfi_eq_attr attr;

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

	attr.size = EQ_SIZE;
	attr.flags = 0;
	attr.wait_obj = KFI_WAIT_NONE;
	attr.signaling_vector = 0;
	attr.wait_set = NULL;

	rc = kfi_eq_open(fabric, &attr, &eq, wakeup_event_handler, NULL);
	if (rc) {
		LOG_ERR("Failed to allocate memory");
		goto clean_fabric;
	}


	kcxi_eq = container_of(eq, struct kcxi_eq, eq);

	return 0;
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
	kfi_close(&eq->fid);
	kfi_close(&fabric->fid);
	kfi_freeinfo(hints);
	kfi_freeinfo(info);
}

static int write_events(void *data)
{
	uint32_t type;
	struct kfi_eq_entry event;
	struct kfi_eq_err_entry error;
	int count;
	int rc;
	int i;
	int id;
	int rand;

	count = ((struct work_info *)data)->count;
	id = ((struct work_info *)data)->id;

	type = KFI_MR_COMPLETE;
	event.fid = &kcxi_eq->eq.fid;
	event.context = NULL;
	event.data = 0;

	error.fid = &kcxi_eq->eq.fid;
	error.context = NULL;
	error.data = 0;
	error.err = -EINVAL;
	error.prov_errno = -EINVAL;
	error.err_data = NULL;
	error.err_data_size = 0;

	/* Write event */
	for (i = 0; i < count; i++) {
		event.data++;
		error.data++;

		/* Should be a value between 0 and 255 */
		rand = 0;
		get_random_bytes(&rand, 1);

		if (rand < ERR_GEN_THRESHOLD) {
			rc = kcxi_eq->report_error(kcxi_eq, &error);
			if (rc) {
				LOG_ERR("Unable to write to event queue");
				terminate = true;
				wake_up_all(&event_wait);
				goto out;
			}

			LOG_INFO("Write Thread %d: Wrote Error %d", id, i);

		} else {
			rc = kcxi_eq->report_event(kcxi_eq, type, &event);
			if (rc) {
				LOG_ERR("Unable to write to event queue");
				terminate = true;
				wake_up_all(&event_wait);
				goto out;
			}

			LOG_INFO("Write Thread %d: Wrote Event %d", id, i);
		}
		atomic_inc(&entry_count);

		/* Raise handler every 5 events and on last write. */
		if (count % 5 == 0 || i == (count - 1))
			kcxi_eq->raise_handler(kcxi_eq);
	}

out:
	LOG_INFO("Write Thread %d: Exiting", id);
	return 0;
}

static int read_events(void *data)
{
	uint32_t type;
	struct kfi_eq_entry event;
	struct kfi_eq_err_entry error;
	int count;
	int id;
	ssize_t read_size;

	count = ((struct work_info *)data)->count;
	id = ((struct work_info *)data)->id;

	while (count > 0 && !terminate) {

		read_size = kfi_eq_read(eq, &type, &event, sizeof(event), 0);
		if (read_size == -EAGAIN) {
			LOG_INFO("Read Thread %d: Going to Sleep", id);

			wait_event(event_wait, atomic_read(&cb_count) != 0);
			atomic_dec(&cb_count);

			LOG_INFO("Read Thread %d: Waking Up", id);
		} else if (read_size == -KFI_EAVAIL) {

			/* Process the error instead of event */
			read_size = kfi_eq_readerr(eq, &error, 0);
			if (read_size > 0) {
				LOG_INFO("Read Thread %d: Consumed Error %d",
					 id, count);
				atomic_dec(&entry_count);
				count--;
			} else if (read_size != -EAGAIN) {
				LOG_ERR("Unexpected RC returned");
				terminate = true;
				goto out;
			}

		} else if (read_size < 0) {
			LOG_ERR("Unexpected RC returned");
			terminate = true;
			goto out;
		} else {
			LOG_INFO("Read Thread %d: Consumed Event %d", id,
				 count);
			atomic_dec(&entry_count);
			count--;
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
