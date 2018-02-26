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
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/random.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <kfi_errno.h>
#include <test_common.h>

#ifdef MODULE_NAME
#undef MODULE_NAME
#endif
#define MODULE_NAME "test_msg_ops_thread"

#define SINGLE_PKT_SIZE 2048
#define MAX_MSG_SIZE (1 << 20) /* 1 MiB */
#define MAX_TX_CTX 1
#define MAX_RX_CTX 1

static unsigned int max_thread_cnt = 1;
static unsigned int max_loop_cnt = 1;
static unsigned int tclass = KFI_TC_UNSPEC;

module_param(max_thread_cnt, uint, 0000);
MODULE_PARM_DESC(max_thread_cnt, "Number of threads to be used");
module_param(max_loop_cnt, uint, 0000);
MODULE_PARM_DESC(max_loop_cnt, "Number of loops per thread");
module_param(tclass, uint, 0000);
MODULE_PARM_DESC(tclass, "Endpoint traffic class value");

MODULE_AUTHOR("Ian Ziemba");
MODULE_DESCRIPTION("kfabric CXI Message Operations with threads");
MODULE_LICENSE("GPL v2");

/* Hard code the node string to use the NIC address 0x0. */
static char *node = "0x0";

struct msg_thread_info {
	struct task_struct *thread;
	int id;
	struct sep_resource *res;
	struct sep_res_loopback *loopback;
	atomic_t event_cntr;
};

enum test_msg_opts {
	DEFAULT,
	NO_SEND_EVENT,
	NO_RECV_EVENT,
};

static DECLARE_WAIT_QUEUE_HEAD(wait_queue);
static struct msg_thread_info **threads;

static atomic_t test_1_errors = ATOMIC_INIT(0);
static atomic_t test_2_errors = ATOMIC_INIT(0);
static atomic_t test_3_errors = ATOMIC_INIT(0);
static atomic_t test_4_errors = ATOMIC_INIT(0);
static atomic_t test_5_errors = ATOMIC_INIT(0);
static atomic_t test_6_errors = ATOMIC_INIT(0);

static void test_rx_cq_cb(struct kfid_cq *cq, void *context)
{
	struct msg_thread_info *info = (struct msg_thread_info *)context;

	LOG_INFO("%s: RX CQ event", __func__);
	atomic_inc(&info->event_cntr);
	wake_up(&wait_queue);
}

static void test_tx_cq_cb(struct kfid_cq *cq, void *context)
{
	struct msg_thread_info *info = (struct msg_thread_info *)context;

	LOG_INFO("%s: TX CQ event", __func__);
	atomic_inc(&info->event_cntr);
	wake_up(&wait_queue);
}

static int test_process_tx_cq(struct kfid_cq *cq, void *op_context,
			      bool truncate_error)
{
	int rc;
	int tmp_rc;
	struct kfi_cq_tagged_entry comp_event;
	struct kfi_cq_err_entry error;

	comp_event.op_context = op_context;
	comp_event.flags = (KFI_MSG | KFI_SEND);
	comp_event.len = 0;
	comp_event.buf = NULL;
	comp_event.data = 0;
	comp_event.tag = 0;

	if (!truncate_error) {
		rc = verify_first_cq_entry(cq, &comp_event,
					   KFI_CQ_FORMAT_TAGGED);
		if (rc) {
			LOG_ERR("%s: failed to process event: rc=%d", __func__,
				rc);

			if (rc == -KFI_EAVAIL) {
				tmp_rc = kfi_cq_readerr(cq, &error, 0);
				if (tmp_rc != 1) {
					LOG_ERR("%s: failed to read CQ error: rc=%d",
						__func__, tmp_rc);
					return tmp_rc;
				}

				LOG_ERR("%s: error info: err=%d, prov_errno=%d",
					__func__, error.err, error.prov_errno);
			} else {
				LOG_ERR("%s: bad TX CQ error: rc=%d", __func__,
					rc);
			}

			return rc;
		}
	} else {
		error.op_context = op_context;
		error.flags = (KFI_MSG | KFI_SEND);
		error.len = 0;
		error.buf = NULL;
		error.data = 0;
		error.tag = 0;
		error.olen = 0;
		error.err = EMSGSIZE;
		error.prov_errno = 1;
		error.err_data = NULL;
		error.err_data_size = 0;

		rc = verify_first_cq_error(cq, &error);
		if (rc) {
			LOG_ERR("%s: failed process error: rc=%d", __func__, rc);
			return rc;
		}
	}

	return 0;
}

static int test_process_multi_rx_cq(struct kfid_cq *cq, void *op_context,
				    void **send_buf_array, size_t send_cnt,
				    size_t send_buf_len, void *recv_buf,
				    enum test_msg_opts opts)
{
	int rc;
	int tmp_rc;
	int i;
	struct kfi_cq_tagged_entry comp_event;
	struct kfi_cq_err_entry error;
	size_t recv_offset = 0;

	/* Last event should be a multi recv. */
	if (opts == NO_RECV_EVENT) {
		comp_event.op_context = op_context;
		comp_event.flags = KFI_MULTI_RECV;
		comp_event.len = 0;
		comp_event.buf = NULL;
		comp_event.data = 0;
		comp_event.tag = 0;

		rc = verify_first_cq_entry(cq, &comp_event,
					   KFI_CQ_FORMAT_TAGGED);
		if (rc)
			LOG_ERR("%s: failed to process RX queue: rc=%d",
				__func__, rc);
		return rc;
	}

	for (i = 0; i < send_cnt; i++, recv_offset += send_buf_len) {
		comp_event.op_context = op_context;
		comp_event.flags = (KFI_MSG | KFI_RECV);
		comp_event.len = send_buf_len;
		comp_event.buf = recv_buf + recv_offset;
		comp_event.data = 0;
		comp_event.tag = 0;

		/*
		 * Last RX CQ event should have KFI_MULTI_RECV set meaning
		 * buffer is unlinked.
		 */
		if ((i + 1) == send_cnt)
			comp_event.flags |= KFI_MULTI_RECV;

		rc = verify_first_cq_entry(cq, &comp_event,
					   KFI_CQ_FORMAT_TAGGED);
		if (rc) {
			LOG_ERR("%s: failed to process event: rc=%d", __func__,
				rc);

			if (rc == -KFI_EAVAIL) {
				tmp_rc = kfi_cq_readerr(cq, &error, 0);
				if (tmp_rc != 1) {
					LOG_ERR("%s: CQ read error fail: rc=%d",
						__func__, tmp_rc);
					return tmp_rc;
				}

				LOG_ERR("%s: error info: err=%d, prov_errno=%d",
					__func__, error.err, error.prov_errno);
			} else {
				LOG_ERR("%s: bad TX CQ error: rc=%d", __func__,
					rc);
			}

			return rc;
		}

		/* Verify data landed in multi recv correctly. */
		rc = verify_data(recv_buf + recv_offset, send_buf_array[i],
				 send_buf_len);
		if (rc != -1) {
			LOG_ERR("%s: data miscompare: send_buf=%d byte=%d",
				__func__, i, rc);
			return rc;
		}
	}

	return 0;
}

static int test_process_rx_cq(struct kfid_cq *cq, void *op_context,
			      size_t op_len, bool truncate, size_t olen)
{
	int rc;
	int tmp_rc;
	struct kfi_cq_tagged_entry comp_event;
	struct kfi_cq_err_entry error;

	comp_event.op_context = op_context;
	comp_event.flags = (KFI_MSG | KFI_RECV);
	comp_event.len = op_len;
	comp_event.buf = NULL;
	comp_event.data = 0;
	comp_event.tag = 0;

	if (!truncate) {
		rc = verify_first_cq_entry(cq, &comp_event, KFI_CQ_FORMAT_TAGGED);
		if (rc) {
			LOG_ERR("%s: failed to process event: rc=%d", __func__, rc);

			if (rc == -KFI_EAVAIL) {
				tmp_rc = kfi_cq_readerr(cq, &error, 0);
				if (tmp_rc != 1) {
					LOG_ERR("%s: failed to read CQ error: rc=%d",
						__func__, tmp_rc);
					return tmp_rc;
				}

				LOG_ERR("%s: error info: err=%d, prov_errno=%d",
					__func__, error.err, error.prov_errno);
			} else {
				LOG_ERR("%s: bad RX CQ error: rc=%d", __func__, rc);
			}

			return rc;
		}
	} else {
		error.op_context = op_context;
		error.flags = (KFI_MSG | KFI_RECV);
		error.len = op_len;
		error.buf = NULL;
		error.data = 0;
		error.tag = 0;
		error.olen = olen;
		error.err = EMSGSIZE;
		error.prov_errno = 1;
		error.err_data = NULL;
		error.err_data_size = 0;

		rc = verify_first_cq_error(cq, &error);
		if (rc) {
			LOG_ERR("%s: failed process error: rc=%d", __func__, rc);
			return rc;
		}

	}

	return 0;
}

static int test_msg(struct msg_thread_info *info, size_t len,
		    enum test_msg_opts opts, bool truncate)
{
	void *recv_buf;
	void *send_buf;
	int rc;
	uint64_t op_flags;
	struct kfi_cq_tagged_entry comp_event;
	unsigned int event_count = 2;
	size_t recv_len = len;

	/* Reset event counter. */
	atomic_set(&info->event_cntr, 0);

	/* Clear the completion operation bit. */
	if (opts == NO_RECV_EVENT) {
		op_flags = KFI_RECV;
		rc = kfi_control(&info->res->rx[0]->fid, KFI_GETOPSFLAG,
				 &op_flags);
		if (rc) {
			LOG_ERR("%s: failed to get RX op flags: rc=%d",
				__func__, rc);
			goto err;
		}

		op_flags &= ~KFI_COMPLETION;
		op_flags |= KFI_RECV;
		rc = kfi_control(&info->res->rx[0]->fid, KFI_SETOPSFLAG,
				 &op_flags);
		if (rc) {
			LOG_ERR("%s: failed to set RX op flags: rc=%d",
				__func__, rc);
			goto err;
		}

		event_count--;
	} else if (opts == NO_SEND_EVENT) {
		op_flags = KFI_TRANSMIT;
		rc = kfi_control(&info->res->tx[0]->fid, KFI_GETOPSFLAG,
				 &op_flags);
		if (rc) {
			LOG_ERR("%s: failed to get TX op flags: rc=%d",
				__func__, rc);
			goto err;
		}

		op_flags &= ~KFI_COMPLETION;
		op_flags |= KFI_TRANSMIT;
		rc = kfi_control(&info->res->tx[0]->fid, KFI_SETOPSFLAG,
				 &op_flags);
		if (rc) {
			LOG_ERR("%s: failed to set TX op flags: rc=%d",
				__func__, rc);
			goto err;
		}

		event_count--;
	}

	/* Setup send/recv buffers. */
	if (truncate)
		recv_len -= 1;

	recv_buf = vzalloc(recv_len);
	if (!recv_buf) {
		rc = -ENOMEM;
		goto err_reset_flags;
	}

	send_buf = vzalloc(len);
	if (!send_buf) {
		rc = -ENOMEM;
		goto err_free_recv_buf;
	}

	get_random_bytes(send_buf, len);


	/* Post recv buffer. */
	rc = kfi_recv(info->res->rx[0], recv_buf, recv_len, NULL, 0, info);
	if (rc) {
		LOG_ERR("Failed to post recv buffer of len=%lu", len);
		goto err_free_send_buf;
	}

	/* Post send buffer. */
	rc = kfi_send(info->res->tx[0], send_buf, len, NULL,
		      info->loopback->rx_addr[0], info);
	if (rc) {
		LOG_ERR("Failed to post send buffer of len=%lu", len);
		goto err_unpost_recv_buf;
	}

	/* Wait for two events (RECV and SEND). */
	wait_event_timeout(wait_queue,
			   atomic_read(&info->event_cntr) == event_count,
			   2 * HZ);

	/* Verify data integrity. */
	rc = verify_data(send_buf, recv_buf, recv_len);
	if (rc != -1) {
		LOG_ERR("Data integrity error in at byte=%u", rc);
		rc = -EIO;
		goto err_free_send_buf;
	}

	/* Verify send event. */
	rc = test_process_tx_cq(info->res->tx_cq[0], info, truncate);
	if (opts == NO_SEND_EVENT) {
		if (rc != -EAGAIN) {
			LOG_ERR("TX events not suppressed");
			rc = -EINVAL;
			goto err_free_send_buf;
		}
	} else if (rc) {
		LOG_ERR("Failed to process send event");
		goto err_free_send_buf;
	}

	/*
	 * Read the CQ again to verify it is drained which will rearm the CQ
	 * completion handler.
	 */
	rc = kfi_cq_read(info->res->tx_cq[0], &comp_event, 1);
	if (rc != -EAGAIN) {
		LOG_ERR("%s: CQ not drained", __func__);
		return -EINVAL;
	}

	/* Verify recv event. */
	rc = test_process_rx_cq(info->res->rx_cq[0], info, recv_len, truncate,
				len - recv_len);
	if (opts == NO_RECV_EVENT) {
		if (rc != -EAGAIN) {
			LOG_ERR("RX events not suppressed");
			rc = -EINVAL;
			goto err_free_send_buf;
		}
	} else if (rc) {
		LOG_ERR("Failed to process recv event");
		goto err_free_send_buf;
	}

	/*
	 * Read the CQ again to verify it is drained which will rearm the CQ
	 * completion handler.
	 */
	rc = kfi_cq_read(info->res->rx_cq[0], &comp_event, 1);
	if (rc != -EAGAIN) {
		LOG_ERR("%s: CQ not drained", __func__);
		return -EINVAL;
	}

	/* Reset op flags. */
	if (opts == NO_RECV_EVENT) {
		op_flags |= (KFI_RECV | KFI_COMPLETION);
		kfi_control(&info->res->rx[0]->fid, KFI_SETOPSFLAG, &op_flags);
	} else if (opts == NO_SEND_EVENT) {
		op_flags |= (KFI_TRANSMIT | KFI_COMPLETION);
		kfi_control(&info->res->tx[0]->fid, KFI_SETOPSFLAG, &op_flags);
	}

	/* Cleanup. */
	vfree(send_buf);
	vfree(recv_buf);
	return 0;

err_unpost_recv_buf:
	kfi_cancel(&info->res->rx[0]->fid, info);
err_free_send_buf:
	vfree(send_buf);
err_free_recv_buf:
	vfree(recv_buf);
err_reset_flags:
	if (opts == NO_RECV_EVENT) {
		op_flags |= (KFI_RECV | KFI_COMPLETION);
		kfi_control(&info->res->rx[0]->fid, KFI_SETOPSFLAG, &op_flags);
	} else if (opts == NO_SEND_EVENT) {
		op_flags |= (KFI_TRANSMIT | KFI_COMPLETION);
		kfi_control(&info->res->tx[0]->fid, KFI_SETOPSFLAG, &op_flags);
	}

err:
	LOG_ERR("MSG %d thread %s failed: rc=%d", info->id, __func__, rc);
	return rc;
}

static int test_msg_multi_recv(struct msg_thread_info *info, size_t len,
			       size_t send_cnt, enum test_msg_opts opts)
{
	void *recv_buf;
	void **send_buf_array;
	size_t send_buf_array_size = 0;
	int rc;
	int i;
	uint64_t op_flags;
	size_t send_buf_len = (len / send_cnt);
	size_t recv_buf_len = ((send_buf_len * send_cnt) + 1);
	size_t min_multi_recv = (send_buf_len - 1);
	size_t read_min_multi_recv;
	size_t buf_size;
	struct kvec msg_iov[1];
	struct kfi_msg recv_msg = {};
	struct kfi_cq_tagged_entry comp_event;
	unsigned int event_count = 2;

	/* Not supported. */
	if (opts == NO_SEND_EVENT) {
		LOG_ERR("%s: invalid options=%d", __func__, opts);
		return -EINVAL;
	}

	LOG_INFO("%s: send_cnt=%lu send_buf_len=%lu recv_buf_len=%lu", __func__,
		 send_cnt, send_buf_len, recv_buf_len);

	/* Setup the min multi recv (unlink value) for recv buffer. */
	rc = kfi_setopt(&info->res->rx[0]->fid, KFI_OPT_ENDPOINT,
			KFI_OPT_MIN_MULTI_RECV, &min_multi_recv,
			sizeof(min_multi_recv));
	if (rc) {
		LOG_ERR("%s: failed to set min_multi_recv: rc=%d", __func__,
			rc);
		goto err;
	}

	buf_size = sizeof(read_min_multi_recv);
	rc = kfi_getopt(&info->res->rx[0]->fid, KFI_OPT_ENDPOINT,
			KFI_OPT_MIN_MULTI_RECV, &read_min_multi_recv,
			&buf_size);
	if (rc) {
		LOG_ERR("%s: failed to get min_multi_recv: rc=%d", __func__,
			rc);
		goto err;
	}

	if (min_multi_recv != read_min_multi_recv) {
		LOG_ERR("%s: failed to set min_multi_recv: value=%lu", __func__,
			min_multi_recv);
		rc = -EINVAL;
		goto err;
	}

	LOG_INFO("%s: min_multi_recv=%lu", __func__, min_multi_recv);

	op_flags = KFI_RECV;
	rc = kfi_control(&info->res->rx[0]->fid, KFI_GETOPSFLAG, &op_flags);
	if (rc) {
		LOG_ERR("%s: failed to get RX op flags: rc=%d", __func__, rc);
		goto err;
	}
	op_flags |= KFI_MULTI_RECV;

	if (opts == NO_RECV_EVENT)
		op_flags &= ~KFI_COMPLETION;

	LOG_INFO("%s: op_flags=%llx", __func__, op_flags);

	/* Setup send/recv buffers. */
	recv_buf = vzalloc(recv_buf_len);
	if (!recv_buf) {
		rc = -ENOMEM;
		goto err;
	}

	send_buf_array = kcalloc(send_cnt, sizeof(*send_buf_array),
				 GFP_KERNEL);
	if (!send_buf_array) {
		rc = -ENOMEM;
		goto err_free_recv_buf;
	}

	for (i = 0; i < send_cnt; i++) {
		send_buf_array[i] = vzalloc(send_buf_len);
		if (!send_buf_array[i])
			goto err_free_send_buf;

		get_random_bytes(send_buf_array[i], send_buf_len);
		send_buf_array_size++;
	}

	/* Build the multi recv operation. */
	msg_iov[0].iov_base = recv_buf;
	msg_iov[0].iov_len = recv_buf_len;

	recv_msg.type = KFI_KVEC;
	recv_msg.msg_iov = msg_iov;
	recv_msg.iov_count = 1;
	recv_msg.context = info;

	rc = kfi_recvmsg(info->res->rx[0], &recv_msg, op_flags);
	if (rc) {
		LOG_ERR("Failed to post multi recv buffer of len=%lu", len);
		goto err_free_send_buf;
	}

	/* Perform multiple sends to multi recv. */
	for (i = 0; i < send_cnt; i++) {

		if (i == 0 && opts != NO_RECV_EVENT)
			event_count = 2;
		else if (i == (send_cnt - 1) && opts == NO_RECV_EVENT)
			event_count = 2;
		else
			event_count = 1;

		/* Reset event counter. */
		atomic_set(&info->event_cntr, 0);

		rc = kfi_send(info->res->tx[0], send_buf_array[i], send_buf_len,
			      NULL, info->loopback->rx_addr[0], info);
		if (rc) {
			LOG_ERR("Failed to post send buffer of len=%lu", len);
			goto err_unpost_recv_buf;
		}

		/* Wait for all events (RECV and SEND). */
		wait_event_timeout(wait_queue,
				   atomic_read(&info->event_cntr) == event_count,
				   10 * HZ);

		rc = test_process_tx_cq(info->res->tx_cq[0], info, false);
		if (rc) {
			LOG_ERR("Failed to process send event");
			goto err_free_send_buf;
		}

		/*
		 * Read the CQ again to verify it is drained which will rearm
		 * the CQ completion handler.
		 */
		rc = kfi_cq_read(info->res->tx_cq[0], &comp_event, 1);
		if (rc != -EAGAIN) {
			LOG_ERR("%s: CQ not drained", __func__);
			return -EINVAL;
		}
	}

	/* Short sleep to ensure second recv event is written. */
	msleep(500);

	/* Verify recv event with data verification. */
	rc = test_process_multi_rx_cq(info->res->rx_cq[0], info, send_buf_array,
				      send_cnt, send_buf_len, recv_buf, opts);
	if (rc) {
		LOG_ERR("Failed to process recv event");
		goto err_free_send_buf;
	}

	/*
	 * Read the CQ again to verify it is drained which will rearm the CQ
	 * completion handler.
	 */
	rc = kfi_cq_read(info->res->rx_cq[0], &comp_event, 1);
	if (rc != -EAGAIN) {
		LOG_ERR("%s: CQ not drained", __func__);
		return -EINVAL;
	}

	/* Cleanup. */
	for (i = 0; i < send_buf_array_size; i++)
		vfree(send_buf_array[i]);
	kfree(send_buf_array);
	vfree(recv_buf);
	return 0;

err_unpost_recv_buf:
	kfi_cancel(&info->res->rx[0]->fid, info);
err_free_send_buf:
	for (i = 0; i < send_buf_array_size; i++)
		vfree(send_buf_array[i]);
	kfree(send_buf_array);
err_free_recv_buf:
	vfree(recv_buf);
err:
	LOG_ERR("MSG %d thread %s failed: rc=%d", info->id, __func__, rc);
	return rc;
}

static void test_1_single_pkt_msg(struct msg_thread_info *info)
{
	size_t len;
	int rc;

	/* Generate a random length. */
	get_random_bytes(&len, sizeof(len));
	len = (len % SINGLE_PKT_SIZE) + 1;

	LOG_INFO("MSG thread %d %s buf length=%lu", info->id, __func__, len);

	rc = test_msg(info, len, DEFAULT, false);
	if (rc) {
		LOG_ERR("MSG thread %d FAILED %s", info->id, __func__);
		atomic_inc(&test_1_errors);
	} else {
		LOG_INFO("MSG thread %d PASSED %s", info->id, __func__);
	}

}

static void test_2_single_pkt_multi_recv_msg(struct msg_thread_info *info)
{
	size_t len;
	size_t send_cnt = 2;
	int rc;

	/* Generate a random length. */
	get_random_bytes(&len, sizeof(len));
	len = (len % SINGLE_PKT_SIZE) + 1;

	LOG_INFO("MSG thread %d %s buf length=%lu", info->id, __func__, len);

	rc = test_msg_multi_recv(info, len * send_cnt, send_cnt, DEFAULT);
	if (rc) {
		LOG_ERR("MSG thread %d FAILED %s", info->id, __func__);
		atomic_inc(&test_2_errors);
	} else {
		LOG_INFO("MSG thread %d PASSED %s", info->id, __func__);
	}

}

static void test_3_single_pkt_msg_no_rx_events(struct msg_thread_info *info)
{
	size_t len;
	int rc;

	/* Generate a random length. */
	get_random_bytes(&len, sizeof(len));
	len = (len % SINGLE_PKT_SIZE) + 1;

	LOG_INFO("MSG thread %d %s buf length=%lu", info->id, __func__, len);

	rc = test_msg(info, len, NO_RECV_EVENT, false);
	if (rc) {
		LOG_ERR("MSG thread %d FAILED %s", info->id, __func__);
		atomic_inc(&test_3_errors);
	} else {
		LOG_INFO("MSG thread %d PASSED %s", info->id, __func__);
	}

}

static void test_4_single_pkt_msg_no_tx_events(struct msg_thread_info *info)
{
	size_t len;
	int rc;

	/* Generate a random length. */
	get_random_bytes(&len, sizeof(len));
	len = (len % SINGLE_PKT_SIZE) + 1;

	LOG_INFO("MSG thread %d %s buf length=%lu", info->id, __func__, len);

	rc = test_msg(info, len, NO_SEND_EVENT, false);
	if (rc) {
		LOG_ERR("MSG thread %d FAILED %s", info->id, __func__);
		atomic_inc(&test_4_errors);
	} else {
		LOG_INFO("MSG thread %d PASSED %s", info->id, __func__);
	}

}

static void test_5_single_pkt_msg_truncate(struct msg_thread_info *info)
{
	size_t len;
	int rc;

	/* Generate a random length. */
	get_random_bytes(&len, sizeof(len));
	len = (len % SINGLE_PKT_SIZE) + 1;

	LOG_INFO("MSG thread %d %s buf length=%lu", info->id, __func__, len);

	rc = test_msg(info, len, DEFAULT, true);
	if (rc) {
		LOG_ERR("MSG thread %d FAILED %s", info->id, __func__);
		atomic_inc(&test_5_errors);
	} else {
		LOG_INFO("MSG thread %d PASSED %s", info->id, __func__);
	}

}

static void test_6_single_pkt_multi_recv_msg_no_recv(struct msg_thread_info *info)
{
	size_t len;
	size_t send_cnt = 2;
	int rc;

	/* Generate a random length. */
	get_random_bytes(&len, sizeof(len));
	len = (len % SINGLE_PKT_SIZE) + 1;

	LOG_INFO("MSG thread %d %s buf length=%lu", info->id, __func__, len);

	rc = test_msg_multi_recv(info, len * send_cnt, send_cnt, NO_RECV_EVENT);
	if (rc) {
		LOG_ERR("MSG thread %d FAILED %s", info->id, __func__);
		atomic_inc(&test_6_errors);
	} else {
		LOG_INFO("MSG thread %d PASSED %s", info->id, __func__);
	}

}

static int test_run_thread(void *data)
{
	struct msg_thread_info *info = data;
	int count = 0;
	DEFINE_WAIT(wait);

	LOG_INFO("MSG thread %d running", info->id);

	while (!kthread_should_stop()) {
		while (count < max_loop_cnt) {
			count++;

			test_1_single_pkt_msg(info);
			test_2_single_pkt_multi_recv_msg(info);
			test_3_single_pkt_msg_no_rx_events(info);
			test_4_single_pkt_msg_no_tx_events(info);
			test_5_single_pkt_msg_truncate(info);
			test_6_single_pkt_multi_recv_msg_no_recv(info);
		}

		if (!kthread_should_stop()) {
			prepare_to_wait_exclusive(&wait_queue, &wait,
						  TASK_INTERRUPTIBLE);
			schedule();
			finish_wait(&wait_queue, &wait);
		}
	}

	LOG_INFO("MSG thread %d exiting", info->id);

	return 0;
}

/*
 * Initialize threads info. Each thread will have a unique set of resources to
 * work with.
 */
static struct msg_thread_info *thread_init(int thread_id)
{
	void *rx_cq_context[MAX_RX_CTX];
	void *tx_cq_context[MAX_RX_CTX];
	struct kfi_av_attr av_attr = {};
	struct kfi_cq_attr cq_attr = {};
	struct kfi_tx_attr tx_attr = {};
	struct kfi_rx_attr rx_attr = {};
	struct sep_resource_opts res_opts = {};
	struct msg_thread_info *info;
	int rc;
	int i;

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info) {
		LOG_ERR("Failed to allocate msg thread info");
		rc = -ENOMEM;
		goto err;
	}

	info->id = thread_id;

	av_attr.type = KFI_AV_UNSPEC;
	cq_attr.format = KFI_CQ_FORMAT_TAGGED;
	tx_attr.op_flags = (KFI_TRANSMIT_COMPLETE | KFI_COMPLETION);
	tx_attr.tclass = tclass;
	rx_attr.op_flags = KFI_COMPLETION;

	res_opts.node = node;
	res_opts.service = kasprintf(GFP_KERNEL, "%d", thread_id);
	if (!res_opts.service) {
		rc = -ENOMEM;
		goto err_free_info;
	}

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
	res_opts.tx_cq_handler = test_tx_cq_cb;
	res_opts.rx_cq_handler = test_rx_cq_cb;
	res_opts.tx_count = res_opts.hints->ep_attr->tx_ctx_cnt;
	res_opts.rx_count = res_opts.hints->ep_attr->rx_ctx_cnt;
	res_opts.tx_selective_completion = true;
	res_opts.rx_selective_completion = true;

	for (i = 0; i < MAX_TX_CTX; i++)
		tx_cq_context[i] = info;
	res_opts.tx_cq_context = tx_cq_context;

	for (i = 0; i < MAX_RX_CTX; i++)
		rx_cq_context[i] = info;
	res_opts.rx_cq_context = rx_cq_context;

	info->res = sep_resource_alloc(&res_opts);
	if (IS_ERR(info->res)) {
		LOG_ERR("Failed to allocate SEP resources");
		rc = PTR_ERR(info->res);
		goto err_free_hints;
	}

	info->loopback = sep_res_loopback_alloc(info->res);
	if (!info->loopback) {
		LOG_ERR("Failed to allocate SEP loopback resources");
		rc = PTR_ERR(info->loopback);
		goto err_free_sep_res;
	}

	info->thread = kthread_create(test_run_thread, info, "msg_thread_%d",
				      thread_id);
	if (IS_ERR(info->thread)) {
		LOG_ERR("Failed to create thread");
		rc = PTR_ERR(info->thread);
		goto err_free_sep_loopback_res;
	}

	kfree(res_opts.service);
	kfi_freeinfo(res_opts.hints);

	LOG_INFO("MSG thread info %d allocated", thread_id);

	return info;

err_free_sep_loopback_res:
	sep_res_loopback_free(info->loopback);
err_free_sep_res:
	sep_resource_free(info->res);
err_free_hints:
	kfi_freeinfo(res_opts.hints);
err_free_service:
	kfree(res_opts.service);
err_free_info:
	kfree(info);
err:
	return ERR_PTR(rc);
}

static void thread_fini(struct msg_thread_info *info)
{
	int thread_id = info->id;

	kthread_stop(info->thread);
	sep_res_loopback_free(info->loopback);
	sep_resource_free(info->res);
	kfree(info);

	LOG_INFO("MSG thread info %d freed", thread_id);
}

/* Allocate and start test threads. */
static int __init test_module_init(void)
{
	int rc;
	int i;

	/* Only allow 4 threads. */
	if (max_thread_cnt > 4 || !max_thread_cnt) {
		LOG_ERR("Max thread count is between 1 and 4");
		return -EINVAL;
	}

	/* Only allow 10 loops. */
	if (max_loop_cnt > 10 || !max_loop_cnt) {
		LOG_ERR("Max loop count is between 1 and 10");
		return -EINVAL;
	}

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

	LOG_INFO("Test 1 (single packet message) had %d errors",
		 atomic_read(&test_1_errors));
	LOG_INFO("Test 2 (single pkt msg multi recv) had %d errors",
		 atomic_read(&test_2_errors));
	LOG_INFO("Test 3 (single pkt msg no rx events) had %d errors",
		 atomic_read(&test_3_errors));
	LOG_INFO("Test 4 (single pkt msg no tx events) had %d errors",
		 atomic_read(&test_4_errors));
	LOG_INFO("Test 5 (single pkt msg truncate) had %d errors",
		 atomic_read(&test_5_errors));
	LOG_INFO("Test 6 (single pkt msg multi recv no recv evt) had %d errors",
		 atomic_read(&test_6_errors));

	if (atomic_read(&test_1_errors) || atomic_read(&test_2_errors) ||
	    atomic_read(&test_3_errors) || atomic_read(&test_4_errors) ||
	    atomic_read(&test_5_errors) || atomic_read(&test_6_errors))
		LOG_ERR("TESTS FAILED");
	else
		LOG_ERR("ALL TESTS PASSED");
}

module_init(test_module_init);
module_exit(test_module_exit);
