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
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/random.h>
#include <test_common.h>

#include "../../../prov/cxi/kcxi_prov.h"

#ifdef MODULE_NAME
#undef MODULE_NAME
#endif
#define MODULE_NAME "test_mr_alloc_async_thread"

#define MAX_THREAD_CNT 1
#define MR_BATCH_ALLOC_CNT 10
#define LOOP_CNT 4
#define MR_ALLOC_LIMIT (MR_BATCH_ALLOC_CNT * LOOP_CNT)

MODULE_AUTHOR("Ian Ziemba");
MODULE_DESCRIPTION("kfabric KCXI MR async allocation thread tests");
MODULE_LICENSE("GPL v2");

struct mr_thread_info {
	struct task_struct *thread;
	int id;
	struct sep_resource *res;
	struct kfid_mr **mrs;
	size_t mr_count;
	size_t event_count;
	void *buf;
	size_t len;
	atomic_t wakeup;
};

static DECLARE_WAIT_QUEUE_HEAD(wait_queue);
static bool stop_threads;
static atomic_t error_count = ATOMIC_INIT(0);
static struct mr_thread_info *mr_threads[MAX_THREAD_CNT];

static void test_eq_cb(struct kfid_eq *eq, void *context)
{
	struct mr_thread_info *info = context;

	atomic_inc(&info->wakeup);
	wake_up(&wait_queue);
}

static void test_mr_allocate(struct mr_thread_info *info)
{
	struct kfi_eq_entry event;
	uint32_t event_type;
	uint64_t access = (KFI_REMOTE_READ | KFI_REMOTE_WRITE);
	int rc;
	int i;
	int count = 0;

	while (!stop_threads && count < LOOP_CNT) {

		atomic_set(&info->wakeup, 0);

		/* Batch allocate MRs. */
		for (i = 0; i < MR_BATCH_ALLOC_CNT; i++) {
			rc = kfi_mr_reg(info->res->domain, info->buf, info->len,
					access, 0, info->mr_count, 0,
					&info->mrs[info->mr_count], NULL);
			if (rc) {
				LOG_ERR("Thread %d failed to allocate MR",
					info->id);
				goto err;
			}

			rc = mr_enable(info->res->rx[0],
				       info->mrs[info->mr_count]);
			if (rc) {
				LOG_ERR("Failed to enabled MR: rc=%d", rc);
				goto err;
			}

			info->mr_count++;
			LOG_INFO("Thread %d MR %lu allocated", info->id,
				 info->mr_count);
		}

		/* Process the MR events. */
		for (i = 0; i < MR_BATCH_ALLOC_CNT;) {

			rc = wait_event_timeout(wait_queue,
						atomic_read(&info->wakeup),
						10 * HZ);
			if (!rc) {
				LOG_ERR("event did not occur in time");
				goto err;
			}

			atomic_set(&info->wakeup, 0);

			/* Drain the EQ. */
			while ((rc = kfi_eq_read(info->res->eq, &event_type, &event,
						 sizeof(event), 0)) == sizeof(event)) {
				info->event_count++;
				LOG_INFO("Thread %d event consumed %lu", info->id,
					 info->event_count);
				i++;
				count++;
			}

			if (rc != -EAGAIN) {
				LOG_ERR("Thread %d unable to read eq rc=%d", info->id, rc);
				goto err;
			}
		}
	}

	/* Success. */
	goto free_mr;

err:
	atomic_inc(&error_count);
	stop_threads = true;

free_mr:

	if (info->mr_count) {
		for (i = info->mr_count - 1; i >= 0; i--) {
			kfi_close(&info->mrs[i]->fid);
			LOG_INFO("Thread %d MR %d freed", info->id, i);
		}
	}
}

static int test_run_thread(void *data)
{
	struct mr_thread_info *info = data;
	DEFINE_WAIT(wait);

	LOG_INFO("MR thread %d running", info->id);

	while (!kthread_should_stop()) {
		test_mr_allocate(info);

		if (!kthread_should_stop()) {
			prepare_to_wait_exclusive(&wait_queue, &wait,
						  TASK_INTERRUPTIBLE);
			schedule();
			finish_wait(&wait_queue, &wait);
		}
	}

	LOG_INFO("MR thread %d exiting", info->id);

	return 0;
}

static struct mr_thread_info *mr_thread_init(int thread_id)
{
	struct mr_thread_info *info;
	struct sep_resource_opts res_opts = {};
	struct kfi_av_attr av_attr = {};
	int rc;

	av_attr.type = KFI_AV_UNSPEC;

	res_opts.service = kasprintf(GFP_KERNEL, "%d", thread_id);
	if (!res_opts.service) {
		rc = -ENOMEM;
		goto err;
	}

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info) {
		LOG_ERR("Failed to allocate service string");
		rc = -ENOMEM;
		goto err_free_service;
	}
	info->id = thread_id;

	get_random_bytes(&info->len, sizeof(info->len));
	info->len = info->len % 4096;

	info->buf = kzalloc(info->len, GFP_KERNEL);
	if (!info->buf) {
		LOG_ERR("Failed to allocate buffer to be mapped");
		rc = -ENOMEM;
		goto err_free_info;
	}
	LOG_INFO("Thread %d buffer size: %lu", thread_id, info->len);

	info->mrs = kcalloc(MR_ALLOC_LIMIT, sizeof(*info->mrs),
			    GFP_KERNEL);
	if (!info->mrs) {
		LOG_ERR("Failed to allocate MR descriptors");
		rc = -ENOMEM;
		goto err_free_buf;
	}

	res_opts.hints = kfi_allocinfo();
	if (!res_opts.hints) {
		LOG_ERR("Failed to allocate info structure");
		rc = -ENOMEM;
		goto err_free_mrs;
	}

	/* Set resource for async MR. */
	res_opts.hints->caps = (KFI_RMA | KFI_WRITE | KFI_READ |
				KFI_REMOTE_READ | KFI_REMOTE_WRITE);
	res_opts.av_attr = &av_attr;
	res_opts.eq_handler = test_eq_cb;
	res_opts.eq_context = info;
	res_opts.async_mr_events = true;
	res_opts.rx_count = 1;

	info->res = sep_resource_alloc(&res_opts);
	if (IS_ERR(info->res)) {
		rc = PTR_ERR(info->res);
		LOG_ERR("Failed to allocate SEP resource: rc=%d", rc);
		goto err_free_hints;
	}

	info->thread = kthread_create(test_run_thread, info, "mr_thread_%d",
				      thread_id);
	if (IS_ERR(info->thread)) {
		rc = PTR_ERR(info->thread);
		LOG_ERR("Failed to create thread: rc=%d", rc);
		goto err_free_res;
	}

	kfi_freeinfo(res_opts.hints);
	kfree(res_opts.service);

	LOG_INFO("MR thread info %d allocated", thread_id);

	return info;

err_free_res:
	sep_resource_free(info->res);
err_free_hints:
	kfi_freeinfo(res_opts.hints);
err_free_mrs:
	kfree(info->mrs);
err_free_buf:
	kfree(info->buf);
err_free_info:
	kfree(info);
err_free_service:
	kfree(res_opts.service);
err:
	return ERR_PTR(rc);
}

static void mr_thread_fini(struct mr_thread_info *info)
{
	int thread_id = info->id;

	kthread_stop(info->thread);
	sep_resource_free(info->res);
	kfree(info->mrs);
	kfree(info->buf);
	kfree(info);

	LOG_INFO("MR Thread Info %d Freed", thread_id);
}

static int __init test_module_init(void)
{
	int rc;
	int i;

	for (i = 0; i < MAX_THREAD_CNT; i++) {
		mr_threads[i] = mr_thread_init(i);
		if (IS_ERR(mr_threads[i])) {
			rc = PTR_ERR(mr_threads[i]);
			goto err;
		}
	}

	for (i = 0; i < MAX_THREAD_CNT; i++)
		wake_up_process(mr_threads[i]->thread);

	return 0;

err:
	for (i -= 1; i >= 0; i--)
		mr_thread_fini(mr_threads[i]);

	return rc;
}

static void __exit test_module_exit(void)
{
	int i;

	for (i = 0; i < MAX_THREAD_CNT; i++)
		mr_thread_fini(mr_threads[i]);

	if (atomic_read(&error_count))
		LOG_ERR("TEST FAILED: %d errors occurred",
			atomic_read(&error_count));
	else
		LOG_INFO("TEST PASSED");
}

module_init(test_module_init);
module_exit(test_module_exit);
