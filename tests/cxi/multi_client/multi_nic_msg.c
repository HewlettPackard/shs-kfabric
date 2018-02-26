//SPDX-License-Identifier: GPL-2.0
/*
 * Multi NIC messaging test.
 * Copyright 2018 Cray Inc. All Rights Reserved.
 */
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/random.h>
#include <linux/mm.h>
#include <kfi_errno.h>
#include <test_common.h>
#include <linux/vmalloc.h>

#ifdef MODULE_NAME
#undef MODULE_NAME
#endif
#define MODULE_NAME "multi-nic-msg"

#define MAX_MSG_SIZE 2048
#define MAX_ITERATIONS 1000
#define MAX_RX_CTX 1
#define MAX_TX_CTX 1
#define MAX_EVENT_TIMEOUT_COUNT 4

static unsigned int max_num_events;
static unsigned int max_thread_cnt = 1;
static bool server;
static unsigned int msg_size = 2048;
static unsigned int iterations = 1;
static char *client_nic = "0x0";
static char *server_nic = "0x1";
static unsigned int batch_size = 16;
static unsigned int event_timeout = 15;

module_param(server, bool, 0000);
MODULE_PARM_DESC(server, "Local node should be treated as the server");
module_param(client_nic, charp, 0000);
MODULE_PARM_DESC(client_nic, "Client NIC address");
module_param(server_nic, charp, 0000);
MODULE_PARM_DESC(server_nic, "Server NIC address");

MODULE_AUTHOR("Ian Ziemba");
MODULE_DESCRIPTION("Multi node message test");
MODULE_LICENSE("GPL v2");

struct msg_thread {
	struct task_struct *thread;
	char *service;
	int id;
	struct sep_resource *res;
	bool tx_trigger;
	bool rx_trigger;
	struct list_head tx_desc;
	struct list_head rx_desc;

	unsigned int event_count;
	unsigned int posted_rx_count;
	unsigned int posted_tx_count;

	bool done;
};

struct msg_buf_desc {
	void *buf;
	struct list_head entry;
	struct msg_thread *thread;
	size_t buf_size;
};

static DECLARE_WAIT_QUEUE_HEAD(wait_queue);
static struct msg_thread **threads;

static void tx_cq_cb(struct kfid_cq *cq, void *context)
{
	struct msg_thread *thread = (struct msg_thread *)context;

	thread->tx_trigger = true;

	wake_up(&wait_queue);
}

static void rx_cq_cb(struct kfid_cq *cq, void *context)
{
	struct msg_thread *thread = (struct msg_thread *)context;

	thread->rx_trigger = true;

	wake_up(&wait_queue);
}

static void thread_sleep(struct wait_queue_entry *wait)
{
	prepare_to_wait_exclusive(&wait_queue, wait, TASK_INTERRUPTIBLE);
	schedule();
	finish_wait(&wait_queue, wait);
}

/* Return the number of buffers posted. */
static size_t post_rx_buffer(struct msg_thread *thread, size_t buf_size,
			     size_t count)
{
	int i;
	int rc;
	struct msg_buf_desc *rx_desc;

	for (i = 0; i < count; i++) {

		rx_desc = kmalloc(sizeof(*rx_desc), GFP_KERNEL);
		if (!rx_desc)
			goto err;

		rx_desc->buf = vmalloc(buf_size);
		if (!rx_desc->buf) {
			kfree(rx_desc);
			goto err;
		}
		rx_desc->buf_size = buf_size;

		rc = kfi_recv(thread->res->rx[0], rx_desc->buf, buf_size, NULL,
			      0, rx_desc);
		if (rc) {
			vfree(rx_desc->buf);
			kfree(rx_desc);
			goto err;
		}

		list_add_tail(&rx_desc->entry, &thread->rx_desc);
		rx_desc->thread = thread;

		thread->posted_rx_count++;
		LOG_INFO("%s: thread %d posted RX count %u", __func__,
			 thread->id, thread->posted_rx_count);
	}

	return count;

err:
	return i;
}

static void free_msg_buf_desc(struct msg_buf_desc *desc)
{
	list_del(&desc->entry);
	vfree(desc->buf);
	kfree(desc);
}

static int server_process_event(struct msg_thread *thread)
{
	int rc = 0;
	struct kfi_cq_tagged_entry event;
	struct kfi_cq_err_entry error;
	struct msg_buf_desc *rx_desc;
	int return_rc = 0;

	/* Completely drain the CQ. */
	while (rc != -EAGAIN) {

		thread->rx_trigger = false;
		rc = kfi_cq_read(thread->res->rx_cq[0], &event, 1);

		/* Repost buffer on success. */
		if (rc == 1) {
			thread->event_count++;

			rx_desc = event.op_context;

			rc = kfi_recv(thread->res->rx[0], rx_desc->buf,
				      rx_desc->buf_size, NULL, 0, rx_desc);
			if (rc) {
				thread->posted_rx_count--;
				LOG_ERR("%s: thread %d posted RX count %u",
					__func__, thread->id,
					thread->posted_rx_count);

				return_rc = rc;
			}
		} else if (rc == -KFI_EAVAIL) {
			rc = kfi_cq_readerr(thread->res->rx_cq[0], &error, 0);
			if (rc != 1) {
				LOG_ERR("%s: unexpected kfi_cq_readerr rc: %d",
					__func__, rc);
				continue;
			}

			/* If canceled, free the desc. */
			if (error.err == ECANCELED) {
				thread->posted_rx_count--;
				LOG_INFO("%s: thread %d posted RX count %u",
					 __func__, thread->id,
					 thread->posted_rx_count);

				rx_desc = error.op_context;

				free_msg_buf_desc(rx_desc);
			}
		}
	}

	return return_rc;
}

/*
 * Free all the RX descs. Not all may be posted, so free it if the cancel call
 * fails. Else, event handler will clean up the buffer when the cancel occurs.
 */
static void server_free_posted_rx(struct msg_thread *thread)
{
	struct msg_buf_desc *pos;
	struct msg_buf_desc *n;
	bool wait_event = false;
	int rc;

	list_for_each_entry_safe(pos, n, &thread->rx_desc, entry) {
		rc = kfi_cancel(&thread->res->rx[0]->fid, pos);
		if (!rc)
			wait_event = true;
		else if (rc == -ENOENT)
			free_msg_buf_desc(pos);
	}

	if (wait_event) {
		rc = wait_event_timeout(wait_queue, thread->rx_trigger == true,
					event_timeout * HZ);
		if (!rc)
			LOG_ERR("%s: timed out waiting for event", __func__);
		else
			server_process_event(thread);
	}
}

/*
 * Server nodes job is maintain batch_size number of receives posted for sends.
 */
static int server_main(void *data)
{
	struct msg_thread *thread = data;
	int rc;
	int timeout_count = 0;
	DEFINE_WAIT(wait);

	thread->rx_trigger = false;

	/* Post initial batch buffers for send operations. */
	rc = post_rx_buffer(thread, msg_size, batch_size);
	if (rc != batch_size)
		goto out;

	while (true) {
		LOG_INFO("%s: thread %d current event count %u", __func__,
			 thread->id, thread->event_count);

		rc = wait_event_timeout(wait_queue, thread->rx_trigger == true,
					event_timeout * HZ);
		if (!rc) {
			timeout_count++;

			LOG_ERR("%s: timed out waiting for event", __func__);

			/* Exit if thread should stop. Else loop again. */
			if (kthread_should_stop() ||
			    timeout_count > MAX_EVENT_TIMEOUT_COUNT) {
				LOG_INFO("%s: closing down thread", __func__);

				rc = -ETIMEDOUT;
				goto out;
			}

			continue;
		}

		rc = server_process_event(thread);
		if (rc)
			goto out;

		timeout_count = 0;
	}

	LOG_INFO("%s: thread %d final event count %u", __func__, thread->id,
		 thread->event_count);

	/* Success. */
	rc = 0;

out:
	/* Sleep until told to stop. */
	if (!kthread_should_stop())
		thread_sleep(&wait);

	server_free_posted_rx(thread);

	LOG_INFO("%s: thread %d exiting", __func__, thread->id);

	return rc;
}

/* Return the number of buffers posted. */
static size_t post_tx_buffer(struct msg_thread *thread, size_t buf_size,
			     size_t count, kfi_addr_t addr)
{
	int i;
	int rc;
	struct msg_buf_desc *tx_desc;

	for (i = 0; i < count; i++) {

		tx_desc = kmalloc(sizeof(*tx_desc), GFP_KERNEL);
		if (!tx_desc)
			goto err;

		tx_desc->buf = vmalloc(buf_size);
		if (!tx_desc->buf) {
			kfree(tx_desc);
			goto err;
		}
		tx_desc->buf_size = buf_size;

		rc = kfi_send(thread->res->tx[0], tx_desc->buf, buf_size, NULL,
			      addr, tx_desc);
		if (rc) {
			LOG_INFO("%s: thread %d kfi_send failed: rc=%d",
				 __func__, thread->id, rc);
			vfree(tx_desc->buf);
			kfree(tx_desc);
			goto err;
		}

		list_add_tail(&tx_desc->entry, &thread->tx_desc);
		tx_desc->thread = thread;

		thread->posted_tx_count++;
		LOG_INFO("%s: thread %d posted TX count %u", __func__,
			 thread->id, thread->posted_tx_count);
	}

	return count;

err:
	return i;
}

static void client_free_posted_tx(struct msg_thread *thread)
{
	struct msg_buf_desc *pos;
	struct msg_buf_desc *n;

	list_for_each_entry_safe(pos, n, &thread->rx_desc, entry)
		free_msg_buf_desc(pos);
}

static int client_process_event(struct msg_thread *thread, kfi_addr_t addr)
{
	int rc = 0;
	struct kfi_cq_tagged_entry event;
	struct kfi_cq_err_entry error;
	struct msg_buf_desc *tx_desc;
	int return_rc = 0;

	/* Completely drain the CQ. */
	while (rc != -EAGAIN) {

		thread->rx_trigger = false;
		rc = kfi_cq_read(thread->res->tx_cq[0], &event, 1);

		/* Repost buffer on success. */
		if (rc == 1 && thread->event_count < max_num_events) {
			thread->event_count++;

			tx_desc = event.op_context;

			rc = kfi_send(thread->res->tx[0], tx_desc->buf,
				      tx_desc->buf_size, NULL, addr, tx_desc);
			if (rc) {
				thread->posted_rx_count--;
				LOG_ERR("%s: thread %d posted RX count %u",
					__func__, thread->id,
					thread->posted_rx_count);

				return_rc = rc;
			}
		} else if (rc == -KFI_EAVAIL) {
			rc = kfi_cq_readerr(thread->res->tx_cq[0], &error, 0);
			if (rc == 1)
				thread->event_count++;

			LOG_ERR("%s: unexpected kfi_cq_readerr rc: %d",
				__func__, rc);
			continue;
		}
	}

	return return_rc;
}

/*
 * Client node job is to send batch_size number buffers to server node.
 */
static int client_main(void *data)
{
	struct msg_thread *thread = data;
	int rc;
	int timeout_count = 0;
	DEFINE_WAIT(wait);
	kfi_addr_t addr;

	/* TODO: Dynamically select service. */
	rc = kfi_av_insertsvc(thread->res->av, server_nic, thread->service,
			      &addr, 0, NULL);
	if (rc != 1) {
		LOG_ERR("%s: thread %d failed to insert AV", __func__,
			thread->id);
		goto out;
	}

	thread->tx_trigger = false;

	/* Post initial send buffers. */
	rc = post_tx_buffer(thread, msg_size, batch_size, addr);
	if (rc != batch_size) {
		LOG_ERR("%s: thread %d failed to post send initial buffers",
			__func__, thread->id);
		goto out;
	}

	while (thread->event_count < max_num_events) {
		LOG_INFO("%s: thread %d current event count %u", __func__,
			 thread->id, thread->event_count);

		rc = wait_event_timeout(wait_queue, thread->tx_trigger == true,
					event_timeout * HZ);
		if (!rc) {
			timeout_count++;

			LOG_ERR("%s: timed out waiting for event", __func__);

			/* Exit if thread should stop. Else loop again. */
			if (kthread_should_stop() ||
			    timeout_count > MAX_EVENT_TIMEOUT_COUNT) {
				LOG_INFO("%s: closing down thread", __func__);

				rc = -ETIMEDOUT;
				goto out;
			}

			continue;
		}

		rc = client_process_event(thread, addr);
		if (rc)
			goto out;

		timeout_count = 0;
	}

	LOG_INFO("%s: thread %d final event count %u", __func__, thread->id,
		 thread->event_count);

	/* Success. */
	rc = 0;

out:
	/* Sleep until told to stop. */
	if (!kthread_should_stop())
		thread_sleep(&wait);

	client_free_posted_tx(thread);

	LOG_INFO("%s: thread %d exiting", __func__, thread->id);

	return rc;
}

static struct msg_thread *thread_init(int thread_id)
{
	void *rx_cq_context[MAX_RX_CTX];
	void *tx_cq_context[MAX_TX_CTX];
	struct kfi_av_attr av_attr = {};
	struct kfi_cq_attr cq_attr = {};
	struct kfi_tx_attr tx_attr = {};
	struct kfi_rx_attr rx_attr = {};
	struct sep_resource_opts res_opts = {};
	struct msg_thread *thread;
	int rc;
	int i;

	thread = kzalloc(sizeof(*thread), GFP_KERNEL);
	if (!thread) {
		LOG_ERR("Failed to allocate msg thread info");
		rc = -ENOMEM;
		goto err;
	}

	INIT_LIST_HEAD(&thread->rx_desc);
	INIT_LIST_HEAD(&thread->tx_desc);
	thread->id = thread_id;

	av_attr.type = KFI_AV_UNSPEC;
	cq_attr.format = KFI_CQ_FORMAT_TAGGED;
	tx_attr.op_flags = (KFI_TRANSMIT_COMPLETE | KFI_COMPLETION);
	rx_attr.op_flags = KFI_COMPLETION;

	if (server)
		res_opts.node = server_nic;
	else
		res_opts.node = client_nic;

	thread->service = kasprintf(GFP_KERNEL, "%d", thread_id);
	if (!thread->service) {
		rc = -ENOMEM;
		goto err_free_thread;
	}
	res_opts.service = thread->service;

	res_opts.hints = kfi_allocinfo();
	if (!res_opts.hints) {
		LOG_ERR("Failed to allocate fabric hints");
		rc = -ENOMEM;
		goto err_free_service;
	}

	res_opts.hints->caps = (KFI_MSG | KFI_SEND | KFI_RECV);
	res_opts.hints->ep_attr->type = KFI_EP_RDM;
	res_opts.hints->ep_attr->max_msg_size = MAX_MSG_SIZE;
	res_opts.hints->ep_attr->tx_ctx_cnt = MAX_TX_CTX;
	res_opts.hints->ep_attr->rx_ctx_cnt = MAX_RX_CTX;
	res_opts.av_attr = &av_attr;
	res_opts.tx_attr = &tx_attr;
	res_opts.rx_attr = &rx_attr;
	res_opts.tx_cq_attr = &cq_attr;
	res_opts.rx_cq_attr = &cq_attr;
	res_opts.tx_cq_handler = tx_cq_cb;
	res_opts.rx_cq_handler = rx_cq_cb;
	res_opts.tx_count = res_opts.hints->ep_attr->tx_ctx_cnt;
	res_opts.rx_count = res_opts.hints->ep_attr->rx_ctx_cnt;

	for (i = 0; i < MAX_TX_CTX; i++)
		tx_cq_context[i] = thread;
	res_opts.tx_cq_context = tx_cq_context;

	for (i = 0; i < MAX_RX_CTX; i++)
		rx_cq_context[i] = thread;
	res_opts.rx_cq_context = rx_cq_context;

	thread->res = sep_resource_alloc(&res_opts);
	if (IS_ERR(thread->res)) {
		LOG_ERR("Failed to allocate SEP resources");
		rc = PTR_ERR(thread->res);
		goto err_free_hints;
	}

	if (server)
		thread->thread = kthread_create(server_main, thread,
						"msg_thread_%d", thread_id);
	else
		thread->thread = kthread_create(client_main, thread,
						"msg_thread_%d", thread_id);

	if (IS_ERR(thread->thread)) {
		LOG_ERR("Failed to create thread");
		rc = PTR_ERR(thread->thread);
		goto err_free_sep_res;
	}

	kfi_freeinfo(res_opts.hints);

	LOG_INFO("MSG thread info %d allocated", thread_id);

	return thread;

err_free_sep_res:
	sep_resource_free(thread->res);
err_free_hints:
	kfi_freeinfo(res_opts.hints);
err_free_service:
	kfree(thread->service);
err_free_thread:
	kfree(thread);
err:
	return ERR_PTR(rc);
}

static void thread_fini(struct msg_thread *thread)
{
	int thread_id = thread->id;

	kthread_stop(thread->thread);
	sep_resource_free(thread->res);
	kfree(thread->service);
	kfree(thread);

	LOG_INFO("MSG thread info %d freed", thread_id);
}

static int __init test_module_init(void)
{
	int rc;
	int i;

	/* Only support 2K message size. */
	if (msg_size > MAX_MSG_SIZE) {
		LOG_ERR("Message size exceeded %u", MAX_MSG_SIZE);
		return -EINVAL;
	}

	if (iterations > MAX_ITERATIONS) {
		LOG_ERR("Iterations exceeded %u", MAX_ITERATIONS);
		return -EINVAL;
	}

	max_num_events = iterations * batch_size;

	threads = kcalloc(max_thread_cnt, sizeof(*threads), GFP_KERNEL);
	if (!threads)
		return -ENOMEM;

	for (i = 0; i < max_thread_cnt; i++) {
		threads[i] = thread_init(i);
		if (IS_ERR(threads[i])) {
			rc = PTR_ERR(threads[i]);
			goto err;
		}
	}

	for (i = 0; i < max_thread_cnt; i++)
		wake_up_process(threads[i]->thread);

	return 0;

err:
	for (i -= 1; i >= 0; i--)
		thread_fini(threads[i]);

	kfree(threads);

	return rc;
}

/* Stop all test threads. */
static void __exit test_module_exit(void)
{
	int i;

	for (i = 0; i < max_thread_cnt; i++)
		thread_fini(threads[i]);
	kfree(threads);
}

module_init(test_module_init);
module_exit(test_module_exit);
