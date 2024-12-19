/*
 * Kfabric fabric tests.
 * Copyright 2018-2024 Hewlett Packard Enterprise Development LP
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
#include <kfi_rma.h>
#include <kfi_errno.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/random.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/scatterlist.h>
#include <linux/dma-mapping.h>
#include <test_common.h>

#ifdef MODULE_NAME
#undef MODULE_NAME
#endif
#define MODULE_NAME "test_rma_ops_thread"

/* TODO: Bump up number of threads. Netsim cannot handle more than 1. */
#define SINGLE_PKT_SIZE 2048
#define MAX_TX_CTX 1
#define MAX_RX_CTX MAX_TX_CTX

static unsigned int max_thread_cnt = 1;
static unsigned int max_loop_cnt = 1;
static unsigned int rma_timeout = 2;
static bool selective_comp;
static bool comp_op_flag;
static bool remote_rma_events;
static unsigned int xfer_size = SINGLE_PKT_SIZE;

module_param(max_thread_cnt, uint, 0000);
MODULE_PARM_DESC(max_thread_cnt, "Number of threads to be used");
module_param(max_loop_cnt, uint, 0000);
MODULE_PARM_DESC(max_loop_cnt, "Number of loops per thread");
module_param(rma_timeout, uint, 0000);
MODULE_PARM_DESC(rma_timeout, "Timeout for RMA event (selective_comp is true)");
module_param(selective_comp, bool, 0000);
MODULE_PARM_DESC(selective_comp,
		 "Bind CQ to EP using KFI_SELECTIVE_COMPLETION");
module_param(comp_op_flag, bool, 0000);
MODULE_PARM_DESC(comp_op_flag,
		 "Set the KFI_COMPLETION flag for TX context");
module_param(remote_rma_events, bool, 0000);
MODULE_PARM_DESC(remote_rma_events,
		 "Generate remote RMA events");
module_param(xfer_size, uint, 0000);
MODULE_PARM_DESC(xfer_size, "Transfer size (RMA read/write size)");

MODULE_AUTHOR("Ian Ziemba");
MODULE_DESCRIPTION("kfabric CXI RMA Operations with threads");
MODULE_LICENSE("GPL v2");

static bool expect_no_completion;

/* Hard code the node string to use the NIC address 0x0. */
static char *node = "0x0";

struct rma_thread_info {
	struct task_struct *thread;
	int id;
	struct kfi_av_attr av_attr;
	struct kfi_cq_attr cq_attr;
	struct sep_resource_opts res_opts;
	struct sep_resource *res;
	struct sep_res_loopback *loopback;
	struct device *device;
	bool tx_event;
	bool rx_event;
};

static DECLARE_WAIT_QUEUE_HEAD(wait_queue);
static struct rma_thread_info **threads;

static atomic_t test_1_errors = ATOMIC_INIT(0);
static atomic_t test_2_errors = ATOMIC_INIT(0);
static atomic_t test_3_errors = ATOMIC_INIT(0);
static atomic_t test_4_errors = ATOMIC_INIT(0);
static atomic_t test_5_errors = ATOMIC_INIT(0);
static atomic_t test_6_errors = ATOMIC_INIT(0);
static atomic_t test_7_errors = ATOMIC_INIT(0);
static atomic_t test_8_errors = ATOMIC_INIT(0);
static atomic_t test_9_errors = ATOMIC_INIT(0);
static atomic_t test_10_errors = ATOMIC_INIT(0);
static atomic_t test_11_errors = ATOMIC_INIT(0);
static atomic_t test_12_errors = ATOMIC_INIT(0);
static atomic_t test_13_errors = ATOMIC_INIT(0);
static atomic_t test_14_errors = ATOMIC_INIT(0);
static atomic_t test_15_errors = ATOMIC_INIT(0);
static atomic_t test_16_errors = ATOMIC_INIT(0);
static atomic_t test_17_errors = ATOMIC_INIT(0);
static atomic_t test_18_errors = ATOMIC_INIT(0);
static atomic_t test_19_errors = ATOMIC_INIT(0);
static atomic_t test_20_errors = ATOMIC_INIT(0);
static atomic_t test_21_errors = ATOMIC_INIT(0);
static atomic_t test_22_errors = ATOMIC_INIT(0);
static atomic_t test_23_errors = ATOMIC_INIT(0);
static atomic_t test_24_errors = ATOMIC_INIT(0);
static atomic_t test_25_errors = ATOMIC_INIT(0);
static atomic_t test_26_errors = ATOMIC_INIT(0);
static atomic_t test_27_errors = ATOMIC_INIT(0);
static atomic_t test_28_errors = ATOMIC_INIT(0);
static atomic_t test_29_errors = ATOMIC_INIT(0);
static atomic_t test_30_errors = ATOMIC_INIT(0);
static atomic_t test_31_errors = ATOMIC_INIT(0);
static atomic_t test_32_errors = ATOMIC_INIT(0);
static atomic_t test_33_errors = ATOMIC_INIT(0);
static atomic_t test_34_errors = ATOMIC_INIT(0);
static atomic_t test_35_errors = ATOMIC_INIT(0);
static atomic_t test_36_errors = ATOMIC_INIT(0);
static atomic_t test_37_errors = ATOMIC_INIT(0);
static atomic_t test_38_errors = ATOMIC_INIT(0);
static atomic_t test_39_errors = ATOMIC_INIT(0);
static atomic_t test_40_errors = ATOMIC_INIT(0);
static atomic_t test_41_errors = ATOMIC_INIT(0);
static atomic_t test_42_errors = ATOMIC_INIT(0);

/*
 * Callback function to be registered with a kfabric CQ. This function sets
 * wakeup to true which unblocks a thread.
 */
static void test_tx_cq_cb(struct kfid_cq *cq, void *context)
{
	struct rma_thread_info *info = (struct rma_thread_info *)context;

	info->tx_event = true;
	wake_up(&wait_queue);
}

static void test_rx_cq_cb(struct kfid_cq *cq, void *context)
{
	struct rma_thread_info *info = (struct rma_thread_info *)context;

	info->rx_event = true;
	wake_up(&wait_queue);
}

static int test_process_tx_cq(struct kfid_cq *cq, void *op_context, bool write)
{
	int rc;
	int tmp_rc;
	struct kfi_cq_tagged_entry comp_event;
	struct kfi_cq_err_entry error;

	comp_event.op_context = op_context;
	if (write)
		comp_event.flags = (KFI_RMA | KFI_WRITE);
	else
		comp_event.flags = (KFI_RMA | KFI_READ);
	comp_event.len = 0;
	comp_event.buf = NULL;
	comp_event.data = 0;
	comp_event.tag = 0;

	rc = verify_first_cq_entry(cq, &comp_event, KFI_CQ_FORMAT_TAGGED);
	if (rc) {
		if (rc == -EAGAIN && expect_no_completion)
			goto success;

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
			LOG_ERR("%s: bad CQ error: rc=%d", __func__, rc);
		}

		return rc;
	}

	/*
	 * Read the CQ again to verify it is drained which will rearm the CQ
	 * completion handler.
	 */
	rc = kfi_cq_read(cq, &comp_event, 1);
	if (rc != -EAGAIN) {
		LOG_ERR("%s: CQ not drained", __func__);
		return -EINVAL;
	}

success:
	return 0;
}

static int test_process_rx_cq(struct kfid_cq *cq, void *op_context, bool write)
{
	int rc;
	int tmp_rc;
	struct kfi_cq_tagged_entry comp_event;
	struct kfi_cq_err_entry error;

	msleep(1000);

	comp_event.op_context = op_context;
	if (write)
		comp_event.flags = (KFI_RMA | KFI_REMOTE_WRITE);
	else
		comp_event.flags = (KFI_RMA | KFI_REMOTE_READ);
	comp_event.len = 0;
	comp_event.buf = NULL;
	comp_event.data = 0;
	comp_event.tag = 0;

	rc = verify_first_cq_entry(cq, &comp_event, KFI_CQ_FORMAT_TAGGED);
	if (rc) {
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
			LOG_ERR("%s: bad CQ error: rc=%d", __func__, rc);
		}

		return rc;
	}

	/*
	 * Read the CQ again to verify it is drained which will rearm the CQ
	 * completion handler.
	 */
	rc = kfi_cq_read(cq, &comp_event, 1);
	if (rc != -EAGAIN) {
		LOG_ERR("%s: CQ not drained", __func__);
		return -EINVAL;
	}

	return 0;
}

/*
 * Perform a generic RMA read/write test. Return 0 for success. Else, negative
 * value.
 */
static int test_rma(struct rma_thread_info *info, size_t len, bool write,
		    bool force_comp)
{
	void *mr_buf = NULL;
	void *buf = NULL;
	uint64_t access;
	uint64_t rkey;
	struct kfid_mr *mr;
	struct kfid_domain *domain = info->res->domain;
	struct kfid_cq *rx_cq = info->res->rx_cq[0];
	struct kfid_cq *tx_cq = info->res->tx_cq[0];
	struct kfid_ep *tx = info->res->tx[0];
	kfi_addr_t addr = info->loopback->mr_addr;
	struct kvec iov;
	struct kfi_rma_iov rma_iov;
	struct kfi_msg_rma msg_rma = {};
	int rc;

	if (write)
		access = KFI_REMOTE_WRITE;
	else
		access = KFI_REMOTE_READ;

	/* The kfabric CQ callback will set wakeup to true. */
	info->tx_event = false;
	info->rx_event = false;

	if (len) {
		mr_buf = vzalloc(len);
		if (!mr_buf) {
			LOG_ERR("RMA thread %d failed to allocate MR buf", info->id);
			goto err;
		}

		buf = vzalloc(len);
		if (!buf) {
			LOG_ERR("RMA thread %d failed to allocate buf", info->id);
			goto err_free_mr_buf;
		}
	}

	/* Fill the buffer to be transferred with garbage. */
	if (write)
		get_random_bytes(buf, len);
	else
		get_random_bytes(mr_buf, len);

	/* Generate a random key. */
	get_random_bytes(&rkey, sizeof(rkey));
	rkey = rkey >> 12;
	LOG_INFO("RMA thread %d remote key: %llx", info->id, rkey);

	/* Register the zero MR buff. */
	rc = kfi_mr_reg(domain, mr_buf, len, access, 0, rkey, 0, &mr, NULL);
	if (rc) {
		LOG_ERR("RMA thread %d failed to allocate MR: %d", info->id,
			rc);
		goto err_free_buf;
	}

	rc = mr_enable(info->res->rx[0], mr);
	if (rc) {
		LOG_ERR("RMA thread %d failed to enabled MR: %d", info->id, rc);
		goto err_free_mr;
	}

	/*
	 * Force a completion event for an RMA operation.
	 */
	if (expect_no_completion && force_comp) {
		iov.iov_base = buf;
		iov.iov_len = len;

		rma_iov.addr = 0;
		rma_iov.len = len;
		rma_iov.key = rkey;

		msg_rma.type = KFI_KVEC;
		msg_rma.msg_iov = &iov;
		msg_rma.iov_count = 1;
		msg_rma.addr = addr;
		msg_rma.rma_iov = &rma_iov;
		msg_rma.rma_iov_count = 1;
		msg_rma.context = info;

		if (write)
			rc = kfi_writemsg(tx, &msg_rma, KFI_COMPLETION);
		else
			rc = kfi_readmsg(tx, &msg_rma, KFI_COMPLETION);
	} else {
		if (write)
			rc = kfi_write(tx, buf, len, NULL, addr, 0, rkey, info);
		else
			rc = kfi_read(tx, buf, len, NULL, addr, 0, rkey, info);
	}

	if (rc) {
		LOG_ERR("RMA thread %d failed to submit RMA cmd: %d", info->id,
			rc);
		goto err_free_mr;
	}

	/*
	 * If expect_no_completion, a timeout should occur if the test was run
	 * with force_comp to false. Else, wait for the event.
	 */
	rc = wait_event_timeout(wait_queue, info->tx_event == true,
				rma_timeout * HZ);
	if (!rc && !expect_no_completion) {
		LOG_ERR("RMA thread %d timed out waiting for event", info->id);
		goto err_free_mr;
	} else if (rc && expect_no_completion && !force_comp) {
		LOG_ERR("RMA thread %d events not suppressed", info->id);
		goto err_free_mr;
	}

	/*
	 * Seems like a short delay is needed for netsim to write data to
	 * buffer.
	 */
	msleep(100);

	rc = test_process_tx_cq(tx_cq, info, write);
	if (rc) {
		LOG_ERR("RMA thread %d failed to process CQ", info->id);
		goto err_free_mr;
	}

	if (remote_rma_events) {
		rc = wait_event_timeout(wait_queue, info->rx_event == true,
					rma_timeout * HZ);
		if (!rc) {
			LOG_ERR("RMA thread %d timed out waiting for event",
				info->id);
			goto err_free_mr;

		}
	}

	/* RC should be success if remote RMA events is set. */
	rc = test_process_rx_cq(rx_cq, NULL, write);
	if (remote_rma_events && rc) {
		LOG_ERR("RMA thread %d failed to process CQ", info->id);
		goto err_free_mr;
	} else if (!remote_rma_events && !rc) {
		LOG_ERR("RMA thread %d had unexpected remote event", info->id);
		goto err_free_mr;
	}

	/* Verify buffers match. */
	rc = verify_data(mr_buf, buf, len);
	if (rc != -1) {
		LOG_ERR("RMA thread %d failed due; data miscompare at byte %d",
			info->id, rc);
		goto err_free_mr;
	}

	/* Tear down. */
	kfi_close(&mr->fid);
	vfree(buf);
	vfree(mr_buf);

	return 0;

err_free_mr:
	kfi_close(&mr->fid);
err_free_buf:
	vfree(buf);
err_free_mr_buf:
	vfree(mr_buf);
err:
	return -EINVAL;
}

#define EMPTY_IOV_COUNT 5U

/*
 * Perform a generic RMA read/write test. Return 0 for success. Else, negative
 * value.
 */
static int test_rma_kvec(struct rma_thread_info *info, size_t len, bool write,
			 bool mr_iov, bool empty_iov, bool use_msg)
{
	void *buf = NULL;
	struct kvec *iov = NULL;
	struct kvec e_iov[EMPTY_IOV_COUNT] = {};
	struct kfi_msg_rma msg = {};
	struct kfi_rma_iov rma_iov = {};
	uint64_t access;
	uint64_t rkey;
	struct kfid_mr *mr = NULL;
	struct kfid_domain *domain = info->res->domain;
	struct kfid_cq *rx_cq = info->res->rx_cq[0];
	struct kfid_cq *tx_cq = info->res->tx_cq[0];
	struct kfid_ep *tx = info->res->tx[0];
	kfi_addr_t addr = info->loopback->mr_addr;
	uint64_t flags = info->res_opts.hints->tx_attr->op_flags;
	int rc;
	int i;
	size_t iov_count = 0;

	if (len && empty_iov) {
		LOG_ERR("Empty IOV only supported with zero len transfers");
		rc = -EINVAL;
		goto err;
	}

	if (write)
		access = KFI_REMOTE_WRITE;
	else
		access = KFI_REMOTE_READ;

	/* The kfabric CQ callback will set wakeup to true. */
	info->tx_event = false;
	info->rx_event = false;

	if (len) {
		buf = vzalloc(len);
		if (!buf) {
			LOG_ERR("RMA thread %d failed to allocate buf", info->id);
			goto err;
		}

		/* Allocate the kvec. */
		iov = alloc_iov(len, &iov_count);
		if (!iov) {
			LOG_ERR("RMA thread %d failed to allocate kvec", info->id);
			goto err_free_buf;
		}
	}

	/* Fill the buffer to be transferred with garbage. */
	if ((write && !mr_iov) || (!write && mr_iov)) {
		for (i = 0; i < iov_count; i++)
			get_random_bytes(iov[i].iov_base, iov[i].iov_len);
	} else {
		get_random_bytes(buf, len);
	}

	/* Generate a random key. */
	get_random_bytes(&rkey, sizeof(rkey));
	rkey = rkey >> 12;
	LOG_INFO("RMA thread %d remote key: %llx", info->id, rkey);

	/* Register the MR buff. */
	if (mr_iov) {
		if (empty_iov)
			rc = kfi_mr_regv(domain, e_iov, EMPTY_IOV_COUNT, access,
					 0, rkey, 0, &mr, NULL);
		else
			rc = kfi_mr_regv(domain, iov, iov_count, access, 0,
					 rkey, 0, &mr, NULL);
	} else {
		rc = kfi_mr_reg(domain, buf, len, access, 0, rkey, 0, &mr,
				NULL);
	}

	if (rc) {
		LOG_ERR("RMA thread %d failed to allocate MR: %d", info->id,
			rc);
			goto err_free_iov;
	}

	rc = mr_enable(info->res->rx[0], mr);
	if (rc) {
		LOG_ERR("RMA thread %d failed to enabled MR: %d", info->id, rc);
		goto err_free_mr;
	}

	/* Perform the test operation. */
	rma_iov.addr = 0;
	rma_iov.len = len;
	rma_iov.key = rkey;

	msg.type = KFI_KVEC;
	msg.msg_iov = iov;
	msg.desc = 0;
	msg.iov_count = iov_count;
	msg.addr = 0;
	msg.rma_iov = &rma_iov;
	msg.rma_iov_count = 1;
	msg.context = info;
	msg.data = 0;

	if (write && !mr_iov) {
		if (empty_iov)
			rc = kfi_writev(tx, e_iov, NULL, EMPTY_IOV_COUNT, addr,
					0, rkey, info);
		else
			if (use_msg)
				rc = kfi_writemsg(tx, &msg, flags);
			else
				rc = kfi_writev(tx, iov, NULL, iov_count, addr, 0, rkey,
						info);
	} else if (write && mr_iov) {
		rc = kfi_write(tx, buf, len, NULL, addr, 0, rkey, info);
	} else if (!write && !mr_iov) {
		if (empty_iov)
			rc = kfi_readv(tx, e_iov, NULL, EMPTY_IOV_COUNT, addr,
				       0, rkey, info);
		else
			if (use_msg)
				rc = kfi_readmsg(tx, &msg, flags);
			else
				rc = kfi_readv(tx, iov, NULL, iov_count, addr, 0, rkey,
					       info);
	} else {
		rc = kfi_read(tx, buf, len, NULL, addr, 0, rkey, info);
	}

	if (rc) {
		LOG_ERR("RMA thread %d failed to submit RMA cmd: %d", info->id,
			rc);
		goto err_free_mr;
	}

	/*
	 * If expect_no_completion, a timeout should occur. Else, wait for the
	 * event.
	 */
	rc = wait_event_timeout(wait_queue, info->tx_event == true,
				rma_timeout * HZ);
	if (!rc && !expect_no_completion) {
		LOG_ERR("RMA thread %d timed out waiting for event", info->id);
		goto err_free_mr;
	} else if (rc && expect_no_completion) {
		LOG_ERR("RMA thread %d events not suppressed", info->id);
		goto err_free_mr;
	}

	/*
	 * Seems like a short delay is needed for netsim to write data to
	 * buffer.
	 */
	msleep(100);

	rc = test_process_tx_cq(tx_cq, info, write);
	if (rc) {
		LOG_ERR("RMA thread %d failed to process CQ", info->id);
		goto err_free_mr;
	}

	/* RC should be success if remote RMA events is set. */
	rc = test_process_rx_cq(rx_cq, NULL, write);
	if (remote_rma_events && rc) {
		LOG_ERR("RMA thread %d failed to process CQ", info->id);
		goto err_free_mr;
	} else if (!remote_rma_events && !rc) {
		LOG_ERR("RMA thread %d had unexpected remote event", info->id);
		goto err_free_mr;
	}

	/* Verify buffers match. */
	if (len) {
		rc = verify_data_iov(buf, iov, iov_count);
		if (rc != -1) {
			LOG_ERR("RMA thread %d failed due; data miscompare at byte %d",
				info->id, rc);
			goto err_free_mr;
		}
	}

	/* Tear down. */
	kfi_close(&mr->fid);
	free_iov(iov, iov_count);
	vfree(buf);

	return 0;

err_free_mr:
	kfi_close(&mr->fid);
err_free_iov:
	free_iov(iov, iov_count);
err_free_buf:
	vfree(buf);
err:
	return -EINVAL;
}

/*
 * Perform a generic RMA read/write test. Return 0 for success. Else, negative
 * value.
 */
static int test_rma_bvec(struct rma_thread_info *info, size_t len, bool write,
			 bool first_page_offset, bool mr_biov, bool empty_iov, bool use_msg)
{
	void *buf = NULL;
	void *tmp_buf;
	struct bio_vec *biov = NULL;
	struct bio_vec e_biov[EMPTY_IOV_COUNT] = {};
	struct kfi_msg_rma msg = {};
	struct kfi_rma_iov rma_iov = {};
	size_t iov_count = 0;
	uint64_t access;
	uint64_t rkey;
	struct kfid_mr *mr;
	struct kfid_domain *domain = info->res->domain;
	struct kfid_cq *rx_cq = info->res->rx_cq[0];
	struct kfid_cq *tx_cq = info->res->tx_cq[0];
	struct kfid_ep *tx = info->res->tx[0];
	kfi_addr_t addr = info->loopback->mr_addr;
	uint64_t flags = info->res_opts.hints->tx_attr->op_flags;
	int rc;
	int i;

	if (len && empty_iov) {
		LOG_ERR("Empty IOV only supported with zero len transfers");
		rc = -EINVAL;
		goto err;
	}

	if (write)
		access = KFI_REMOTE_WRITE;
	else
		access = KFI_REMOTE_READ;

	/* The kfabric CQ callback will set wakeup to true. */
	info->tx_event = false;
	info->rx_event = false;

	if (len) {
		buf = vzalloc(len);
		if (!buf) {
			LOG_ERR("RMA thread %d failed to allocate buf", info->id);
			goto err;
		}

		/* Allocate the biov. */
		biov = alloc_biov(len, &iov_count, first_page_offset);
		if (!biov) {
			LOG_ERR("RMA thread %d failed to allocate biov", info->id);
			goto err_free_mr_buf;
		}
	}

	/* Fill the buffer to be transferred with garbage. */
	if ((write && !mr_biov) || (!write && mr_biov)) {
		for (i = 0; i < iov_count; i++) {
			tmp_buf = page_to_virt(biov[i].bv_page);
			tmp_buf += biov[i].bv_offset;
			get_random_bytes(tmp_buf, biov[i].bv_len);
		}
	} else {
		get_random_bytes(buf, len);
	}

	/* Generate a random key. */
	get_random_bytes(&rkey, sizeof(rkey));
	rkey = rkey >> 12;
	LOG_INFO("RMA thread %d remote key: %llx", info->id, rkey);

	/* Register the zero MR buff. */
	if (mr_biov) {
		if (empty_iov)
			rc = kfi_mr_regbv(domain, e_biov, EMPTY_IOV_COUNT,
					  access, 0, rkey, 0, &mr, NULL);
		else
			rc = kfi_mr_regbv(domain, biov, iov_count, access, 0,
					  rkey, 0, &mr, NULL);
	} else {
		rc = kfi_mr_reg(domain, buf, len, access, 0, rkey, 0, &mr,
				NULL);
	}

	if (rc) {
		LOG_ERR("RMA thread %d failed to allocate MR: %d", info->id,
			rc);
		goto err_free_bvec_buf;
	}

	rc = mr_enable(info->res->rx[0], mr);
	if (rc) {
		LOG_ERR("RMA thread %d failed to enabled MR: %d", info->id, rc);
		goto err_free_mr;
	}

	/* Write the garbage buffer to the MR buffer. */
	rma_iov.addr = 0;
	rma_iov.len = len;
	rma_iov.key = rkey;

	msg.type = KFI_BVEC;
	msg.msg_biov = biov;
	msg.desc = 0;
	msg.iov_count = iov_count;
	msg.addr = 0;
	msg.rma_iov = &rma_iov;
	msg.rma_iov_count = 1;
	msg.context = info;
	msg.data = 0;

	if (write && !mr_biov) {
		if (empty_iov)
			rc = kfi_writebv(tx, e_biov, NULL, EMPTY_IOV_COUNT,
					 addr, 0, rkey, info);
		else
			if (use_msg)
				rc = kfi_writemsg(tx, &msg, flags);
			else
				rc = kfi_writebv(tx, biov, NULL, iov_count, addr, 0,
						 rkey, info);
	} else if (write && mr_biov) {
		rc = kfi_write(tx, buf, len, NULL, addr, 0, rkey, info);
	} else if (!write && !mr_biov) {
		if (empty_iov)
			rc = kfi_readbv(tx, e_biov, NULL, EMPTY_IOV_COUNT, addr,
					0, rkey, info);
		else
			if (use_msg)
				rc = kfi_readmsg(tx, &msg, flags);
			else
				rc = kfi_readbv(tx, biov, NULL, iov_count, addr, 0,
						rkey, info);
	} else {
		rc = kfi_read(tx, buf, len, NULL, addr, 0, rkey, info);
	}

	if (rc) {
		LOG_ERR("RMA thread %d failed to submit RMA cmd: %d", info->id,
			rc);
		goto err_free_mr;
	}

	/*
	 * If expect_no_completion, a timeout should occur. Else, wait for the
	 * event.
	 */
	rc = wait_event_timeout(wait_queue, info->tx_event == true,
				rma_timeout * HZ);
	if (!rc && !expect_no_completion) {
		LOG_ERR("RMA thread %d timed out waiting for event", info->id);
		goto err_free_mr;
	} else if (rc && expect_no_completion) {
		LOG_ERR("RMA thread %d events not suppressed", info->id);
		goto err_free_mr;
	}

	/*
	 * Seems like a short delay is needed for netsim to write data to
	 * buffer.
	 */
	msleep(100);

	rc = test_process_tx_cq(tx_cq, info, write);
	if (rc) {
		LOG_ERR("RMA thread %d failed to process CQ", info->id);
		goto err_free_mr;
	}

	/* RC should be success if remote RMA events is set. */
	rc = test_process_rx_cq(rx_cq, NULL, write);
	if (remote_rma_events && rc) {
		LOG_ERR("RMA thread %d failed to process CQ", info->id);
		goto err_free_mr;
	} else if (!remote_rma_events && !rc) {
		LOG_ERR("RMA thread %d had unexpected remote event", info->id);
		goto err_free_mr;
	}

	/* Verify buffers match. */
	if (len) {
		rc = verify_data_biov(buf, biov, iov_count);
		if (rc != -1) {
			LOG_ERR("RMA thread %d failed due; data miscompare at byte %d",
				info->id, rc);
			goto err_free_mr;
		}
	}

	/* Tear down. */
	kfi_close(&mr->fid);
	free_biov(biov, iov_count);
	vfree(buf);

	return 0;

err_free_mr:
	kfi_close(&mr->fid);
err_free_bvec_buf:
	free_biov(biov, iov_count);
err_free_mr_buf:
	vfree(buf);
err:
	return -EINVAL;
}

/*
 * Perform a generic RMA read/write test. Return 0 for success. Else, negative
 * value.
 */
static int test_rma_sgl(struct rma_thread_info *info, size_t len, bool write,
			 bool first_page_offset, bool mr_sgl, bool empty_iov, bool use_msg)
{
	void *buf = NULL;
	void *tmp_buf;
	struct bio_vec *biov = NULL;
	struct sg_table sgt = {};
	struct scatterlist *sg = NULL;
	struct kfi_msg_rma msg = {};
	struct kfi_rma_iov rma_iov = {};
	size_t iov_count = 0;
	int64_t access;
	uint64_t rkey;
	struct kfid_mr *mr;
	struct kfid_domain *domain = info->res->domain;
	struct device *device = info->res->device;
	struct kfid_cq *rx_cq = info->res->rx_cq[0];
	struct kfid_cq *tx_cq = info->res->tx_cq[0];
	struct kfid_ep *tx = info->res->tx[0];
	kfi_addr_t addr = info->loopback->mr_addr;
	uint64_t flags = info->res_opts.hints->tx_attr->op_flags;
	int rc;
	int i;

	if (len && empty_iov) {
		LOG_ERR("Empty IOV only supported with zero len transfers");
		rc = -EINVAL;
		goto err;
	}

	if (write)
		access = KFI_REMOTE_WRITE;
	else
		access = KFI_REMOTE_READ;

	/* The kfabric CQ callback will set wakeup to true. */
	info->tx_event = false;
	info->rx_event = false;

	if (len) {
		buf = vzalloc(len);
		if (!buf) {
			LOG_ERR("RMA thread %d failed to allocate buf", info->id);
			goto err;
		}

		/* Allocate the biov used to populate the sgt. */
		biov = alloc_biov(len, &iov_count, first_page_offset);
		if (!biov) {
			LOG_ERR("RMA thread %d failed to allocate biov", info->id);
			goto err_free_mr_buf;
		}
	}

	/* Fill the buffer to be transferred with garbage. */
	if ((write && !mr_sgl) || (!write && mr_sgl)) {
		for (i = 0; i < iov_count; i++) {
			tmp_buf = page_to_virt(biov[i].bv_page);
			tmp_buf += biov[i].bv_offset;
			get_random_bytes(tmp_buf, biov[i].bv_len);
		}
	} else {
		get_random_bytes(buf, len);
	}

	/* Populate and map the sgt */
	if (len) {
		rc = sg_alloc_table(&sgt, iov_count, GFP_KERNEL);
			if (rc) {
				LOG_ERR("RMA thread %d failed to populate sgt", info->id);
				goto err_free_bvec_buf;
			}

		sg = sgt.sgl;
		for (i = 0; i < iov_count; i++) {
			sg_set_page(sg, biov[i].bv_page, biov[i].bv_len, biov[i].bv_offset);
			sg = sg_next(sg);
		}

		rc = dma_map_sgtable(device, &sgt, DMA_BIDIRECTIONAL, 0);
		if (rc) {
			LOG_ERR("RMA thread %d failed to map sgt", info->id);
			goto err_free_table;
		}

		LOG_INFO("RMA thread %d sgt orig_nents: %d nents: %d len: %d offset %d", info->id,
			sgt.orig_nents, sgt.nents, sg_dma_len(sgt.sgl), sgt.sgl->offset);
	}

	/* Generate a random key. */
	get_random_bytes(&rkey, sizeof(rkey));
	rkey = rkey >> 12;
	LOG_INFO("RMA thread %d remote key: %llx", info->id, rkey);

	/* Register the zero MR buff. */
	if (mr_sgl) {
		if (empty_iov)
			rc = kfi_mr_regsgl(domain, NULL, 0, access, 0,
					   rkey, 0, &mr, NULL);
		else
			rc = kfi_mr_regsgl(domain, sgt.sgl, sgt.nents, access, 0,
					   rkey, 0, &mr, NULL);
	} else {
		rc = kfi_mr_reg(domain, buf, len, access, 0, rkey, 0, &mr,
				NULL);
	}

	if (rc) {
		LOG_ERR("RMA thread %d failed to allocate MR: %d", info->id,
			rc);
		goto err_unmap_sgt;
	}

	rc = mr_enable(info->res->rx[0], mr);
	if (rc) {
		LOG_ERR("RMA thread %d failed to enabled MR: %d", info->id, rc);
		goto err_free_mr;
	}

	/* Write the garbage buffer to the MR buffer. */
	rma_iov.addr = 0;
	rma_iov.len = len;
	rma_iov.key = rkey;

	msg.type = KFI_SGL;
	msg.msg_sgl = sgt.sgl;
	msg.desc = 0;
	msg.iov_count = sgt.nents;
	msg.addr = 0;
	msg.rma_iov = &rma_iov;
	msg.rma_iov_count = 1;
	msg.context = info;
	msg.data = 0;

	if (write && !mr_sgl) {
		if (empty_iov)
			rc = kfi_writesgl(tx, NULL, NULL, 0, addr, 0,
					 rkey, info);
		else
			if (use_msg)
				rc = kfi_writemsg(tx, &msg, flags);
			else
				rc = kfi_writesgl(tx, sgt.sgl, NULL, sgt.nents, addr, 0,
						 rkey, info);
	} else if (write && mr_sgl) {
		rc = kfi_write(tx, buf, len, NULL, addr, 0, rkey, info);
	} else if (!write && !mr_sgl) {
		if (empty_iov)
			rc = kfi_readsgl(tx, NULL, NULL, 0, addr, 0,
					rkey, info);
		else
			if (use_msg)
				rc = kfi_readmsg(tx, &msg, flags);
			else
				rc = kfi_readsgl(tx, sgt.sgl, NULL, sgt.nents, addr, 0,
						rkey, info);
	} else {
		rc = kfi_read(tx, buf, len, NULL, addr, 0, rkey, info);
	}

	if (rc) {
		LOG_ERR("RMA thread %d failed to submit RMA cmd: %d", info->id,
			rc);
		goto err_free_mr;
	}

	/*
	 * If expect_no_completion, a timeout should occur. Else, wait for the
	 * event.
	 */
	rc = wait_event_timeout(wait_queue, info->tx_event == true,
				rma_timeout * HZ);
	if (!rc && !expect_no_completion) {
		LOG_ERR("RMA thread %d timed out waiting for event", info->id);
		goto err_free_mr;
	} else if (rc && expect_no_completion) {
		LOG_ERR("RMA thread %d events not suppressed", info->id);
		goto err_free_mr;
	}

	/*
	 * Seems like a short delay is needed for netsim to write data to
	 * buffer.
	 */
	msleep(100);

	rc = test_process_tx_cq(tx_cq, info, write);
	if (rc) {
		LOG_ERR("RMA thread %d failed to process CQ", info->id);
		goto err_free_mr;
	}

	/* RC should be success if remote RMA events is set. */
	rc = test_process_rx_cq(rx_cq, NULL, write);
	if (remote_rma_events && rc) {
		LOG_ERR("RMA thread %d failed to process CQ", info->id);
		goto err_free_mr;
	} else if (!remote_rma_events && !rc) {
		LOG_ERR("RMA thread %d had unexpected remote event", info->id);
		goto err_free_mr;
	}

	/* Verify buffers match. */
	if (len) {
		rc = verify_data_biov(buf, biov, iov_count);
		if (rc != -1) {
			LOG_ERR("RMA thread %d failed due; data miscompare at byte %d",
				info->id, rc);
			goto err_free_mr;
		}
	}

	/* Tear down. */
	kfi_close(&mr->fid);
	if (len) {
		dma_unmap_sgtable(device, &sgt, DMA_BIDIRECTIONAL, 0);
		sg_free_table(&sgt);
	}
	free_biov(biov, iov_count);
	vfree(buf);

	return 0;

err_free_mr:
	kfi_close(&mr->fid);
err_unmap_sgt:
	if (len)
		dma_unmap_sgtable(device, &sgt, DMA_BIDIRECTIONAL, 0);
err_free_table:
	if (len)
		sg_free_table(&sgt);
err_free_bvec_buf:
	if (len)
		free_biov(biov, iov_count);
err_free_mr_buf:
	if (len)
		vfree(buf);
err:
	return -EINVAL;
}

/* Perform a single packet RMA write. */
static void test_1_rma_write(struct rma_thread_info *info)
{
	size_t len = xfer_size;
	int rc;

	LOG_INFO("RMA thread %d write length: %lu", info->id, len);

	rc = test_rma(info, len, true, false);
	if (rc) {
		LOG_ERR("RMA thread %d FAILED %s", info->id, __func__);
		atomic_inc(&test_1_errors);
	} else {
		LOG_INFO("RMA thread %d PASSED %s", info->id, __func__);
	}
}

/* Perform a single packet RMA read. */
static void test_2_rma_read(struct rma_thread_info *info)
{
	size_t len = xfer_size;
	int rc;

	LOG_INFO("RMA thread %d read length: %lu", info->id, len);

	rc = test_rma(info, len, false, false);
	if (rc) {
		LOG_ERR("RMA thread %d FAILED %s", info->id, __func__);
		atomic_inc(&test_2_errors);
	} else {
		LOG_INFO("RMA thread %d PASSED %s", info->id, __func__);
	}
}

/*
 * Perform a single packet RMA write where the initiator buffer is a kvec that
 * does not contains gaps.
 */
static void test_3_rma_kvec_write(struct rma_thread_info *info)
{
	size_t len = xfer_size;
	int rc;

	LOG_INFO("RMA thread %d write kvec length: %lu", info->id, len);

	rc = test_rma_kvec(info, len, true, false, false, false);
	if (rc) {
		LOG_ERR("RMA thread %d FAILED %s", info->id, __func__);
		atomic_inc(&test_3_errors);
	} else {
		LOG_INFO("RMA thread %d PASSED %s", info->id, __func__);
	}
}

/*
 * Perform a single packet RMA read where the initiator buffer is a kvec that
 * does not contain gaps.
 */
static void test_4_rma_kvec_read(struct rma_thread_info *info)
{
	size_t len = xfer_size;
	int rc;

	LOG_INFO("RMA thread %d read kvec length: %lu", info->id, len);

	rc = test_rma_kvec(info, len, false, false, false, false);
	if (rc) {
		LOG_ERR("RMA thread %d FAILED %s", info->id, __func__);
		atomic_inc(&test_4_errors);
	} else {
		LOG_INFO("RMA thread %d PASSED %s", info->id, __func__);
	}
}

/*
 * Perform a single packet RMA write where the initiator buffer is a bvec that
 * does not contains gaps.
 */
static void test_5_rma_bvec_write(struct rma_thread_info *info)
{
	size_t len = xfer_size;
	int rc;

	LOG_INFO("RMA thread %d write bvec length: %lu", info->id, len);

	rc = test_rma_bvec(info, len, true, false, false, false, false);
	if (rc) {
		LOG_ERR("RMA thread %d FAILED %s", info->id, __func__);
		atomic_inc(&test_5_errors);
	} else {
		LOG_INFO("RMA thread %d PASSED %s", info->id, __func__);
	}
}

/*
 * Perform a single packet RMA read where the initiator buffer is a bvec that
 * does not contain gaps.
 */
static void test_6_rma_bvec_read(struct rma_thread_info *info)
{
	size_t len = xfer_size;
	int rc;

	LOG_INFO("RMA thread %d read bvec length: %lu", info->id, len);

	rc = test_rma_bvec(info, len, false, false, false, false, false);
	if (rc) {
		LOG_ERR("RMA thread %d FAILED %s", info->id, __func__);
		atomic_inc(&test_6_errors);
	} else {
		LOG_INFO("RMA thread %d PASSED %s", info->id, __func__);
	}
}

/*
 * Perform a single packet RMA write where the initiator buffer is a bvec that
 * does not contains gaps but the first page may contain an offset.
 */
static void test_7_rma_bvec_write_offset(struct rma_thread_info *info)
{
	size_t len = xfer_size;
	int rc;

	LOG_INFO("RMA thread %d write bvec length: %lu", info->id, len);

	rc = test_rma_bvec(info, len, true, true, false, false, false);
	if (rc) {
		LOG_ERR("RMA thread %d FAILED %s", info->id, __func__);
		atomic_inc(&test_7_errors);
	} else {
		LOG_INFO("RMA thread %d PASSED %s", info->id, __func__);
	}
}

/*
 * Perform a single packet RMA read where the initiator buffer is a bvec that
 * does not contain gaps but the first page may contain an offset.
 */
static void test_8_rma_bvec_read_offset(struct rma_thread_info *info)
{
	size_t len = xfer_size;
	int rc;

	LOG_INFO("RMA thread %d read bvec length: %lu", info->id, len);

	rc = test_rma_bvec(info, len, false, true, false, false, false);
	if (rc) {
		LOG_ERR("RMA thread %d FAILED %s", info->id, __func__);
		atomic_inc(&test_8_errors);
	} else {
		LOG_INFO("RMA thread %d PASSED %s", info->id, __func__);
	}
}

/*
 * Perform a single packet RMA write where the initiator buffer is a sgl that
 * does not contains gaps.
 */
static void test_9_rma_sgl_write(struct rma_thread_info *info)
{
	size_t len = xfer_size;
	int rc;

	LOG_INFO("RMA thread %d write sgl length: %lu", info->id, len);

	rc = test_rma_sgl(info, len, true, false, false, false, false);
	if (rc) {
		LOG_ERR("RMA thread %d FAILED %s", info->id, __func__);
		atomic_inc(&test_9_errors);
	} else {
		LOG_INFO("RMA thread %d PASSED %s", info->id, __func__);
	}
}

/*
 * Perform a single packet RMA read where the initiator buffer is a sgl that
 * does not contain gaps.
 */
static void test_10_rma_sgl_read(struct rma_thread_info *info)
{
	size_t len = xfer_size;
	int rc;

	LOG_INFO("RMA thread %d read sgl length: %lu", info->id, len);

	rc = test_rma_sgl(info, len, false, false, false, false, false);
	if (rc) {
		LOG_ERR("RMA thread %d FAILED %s", info->id, __func__);
		atomic_inc(&test_10_errors);
	} else {
		LOG_INFO("RMA thread %d PASSED %s", info->id, __func__);
	}
}

/*
 * Perform a single packet RMA write where the initiator buffer is a sgl that
 * does not contains gaps but the first page may contain an offset.
 */
static void test_11_rma_sgl_write_offset(struct rma_thread_info *info)
{
	size_t len = xfer_size;
	int rc;

	LOG_INFO("RMA thread %d write sgl length: %lu", info->id, len);

	rc = test_rma_sgl(info, len, true, true, false, false, false);
	if (rc) {
		LOG_ERR("RMA thread %d FAILED %s", info->id, __func__);
		atomic_inc(&test_11_errors);
	} else {
		LOG_INFO("RMA thread %d PASSED %s", info->id, __func__);
	}
}

/*
 * Perform a single packet RMA read where the initiator buffer is a sgl that
 * does not contain gaps but the first page may contain an offset.
 */
static void test_12_rma_sgl_read_offset(struct rma_thread_info *info)
{
	size_t len = xfer_size;
	int rc;

	LOG_INFO("RMA thread %d read sgl length: %lu", info->id, len);

	rc = test_rma_sgl(info, len, false, true, false, false, false);
	if (rc) {
		LOG_ERR("RMA thread %d FAILED %s", info->id, __func__);
		atomic_inc(&test_12_errors);
	} else {
		LOG_INFO("RMA thread %d PASSED %s", info->id, __func__);
	}
}

/*
 * Perform a single packet RMA write where the MR buffer is a kvec that
 * does not contains gaps.
 */
static void test_13_rma_mr_kvec_write(struct rma_thread_info *info)
{
	size_t len = xfer_size;
	int rc;

	LOG_INFO("RMA thread %d write MR kvec length: %lu", info->id, len);

	rc = test_rma_kvec(info, len, true, true, false, false);
	if (rc) {
		LOG_ERR("RMA thread %d FAILED %s", info->id, __func__);
		atomic_inc(&test_13_errors);
	} else {
		LOG_INFO("RMA thread %d PASSED %s", info->id, __func__);
	}
}

/*
 * Perform a single packet RMA read where the MR buffer is a kvec that
 * does not contain gaps.
 */
static void test_14_rma_mr_kvec_read(struct rma_thread_info *info)
{
	size_t len = xfer_size;
	int rc;

	LOG_INFO("RMA thread %d read MR kvec length: %lu", info->id, len);

	rc = test_rma_kvec(info, len, false, true, false, false);
	if (rc) {
		LOG_ERR("RMA thread %d FAILED %s", info->id, __func__);
		atomic_inc(&test_14_errors);
	} else {
		LOG_INFO("RMA thread %d PASSED %s", info->id, __func__);
	}
}

/*
 * Perform a single packet RMA write where the MR buffer is a bvec that
 * does not contains gaps.
 */
static void test_15_rma_mr_bvec_write(struct rma_thread_info *info)
{
	size_t len = xfer_size;
	int rc;

	LOG_INFO("RMA thread %d write MR bvec length: %lu", info->id, len);

	rc = test_rma_bvec(info, len, true, false, true, false, false);
	if (rc) {
		LOG_ERR("RMA thread %d FAILED %s", info->id, __func__);
		atomic_inc(&test_15_errors);
	} else {
		LOG_INFO("RMA thread %d PASSED %s", info->id, __func__);
	}
}

/*
 * Perform a single packet RMA read where the MR buffer is a bvec that
 * does not contain gaps.
 */
static void test_16_rma_mr_bvec_read(struct rma_thread_info *info)
{
	size_t len = xfer_size;
	int rc;

	LOG_INFO("RMA thread %d read MR bvec length: %lu", info->id, len);

	rc = test_rma_bvec(info, len, false, false, true, false, false);
	if (rc) {
		LOG_ERR("RMA thread %d FAILED %s", info->id, __func__);
		atomic_inc(&test_16_errors);
	} else {
		LOG_INFO("RMA thread %d PASSED %s", info->id, __func__);
	}
}

/*
 * Perform a single packet RMA write where the MR buffer is a bvec that
 * does not contains gaps but the first page may contain an offset.
 */
static void
test_17_rma_mr_bvec_write_off(struct rma_thread_info *info)
{
	size_t len = xfer_size;
	int rc;

	LOG_INFO("RMA thread %d write MR bvec length: %lu", info->id, len);

	rc = test_rma_bvec(info, len, true, true, true, false, false);
	if (rc) {
		LOG_ERR("RMA thread %d FAILED %s", info->id, __func__);
		atomic_inc(&test_17_errors);
	} else {
		LOG_INFO("RMA thread %d PASSED %s", info->id, __func__);
	}
}

/*
 * Perform a single packet RMA read where the MR buffer is a bvec that
 * does not contain gaps but the first page may contain an offset.
 */
static void
test_18_rma_mr_bvec_read_off(struct rma_thread_info *info)
{
	size_t len = xfer_size;
	int rc;

	LOG_INFO("RMA thread %d read MR bvec length: %lu", info->id, len);

	rc = test_rma_bvec(info, len, false, true, true, false, false);
	if (rc) {
		LOG_ERR("RMA thread %d FAILED %s", info->id, __func__);
		atomic_inc(&test_18_errors);
	} else {
		LOG_INFO("RMA thread %d PASSED %s", info->id, __func__);
	}
}


/*
 * Perform a single packet RMA write where the MR buffer is a sgl that
 * does not contains gaps.
 */
static void test_19_rma_mr_sgl_write(struct rma_thread_info *info)
{
	size_t len = xfer_size;
	int rc;

	LOG_INFO("RMA thread %d write MR sgl length: %lu", info->id, len);

	rc = test_rma_sgl(info, len, true, false, true, false, false);
	if (rc) {
		LOG_ERR("RMA thread %d FAILED %s", info->id, __func__);
		atomic_inc(&test_19_errors);
	} else {
		LOG_INFO("RMA thread %d PASSED %s", info->id, __func__);
	}
}

/*
 * Perform a single packet RMA read where the MR buffer is a sgl that
 * does not contain gaps.
 */
static void test_20_rma_mr_sgl_read(struct rma_thread_info *info)
{
	size_t len = xfer_size;
	int rc;

	LOG_INFO("RMA thread %d read MR sgl length: %lu", info->id, len);

	rc = test_rma_sgl(info, len, false, false, true, false, false);
	if (rc) {
		LOG_ERR("RMA thread %d FAILED %s", info->id, __func__);
		atomic_inc(&test_20_errors);
	} else {
		LOG_INFO("RMA thread %d PASSED %s", info->id, __func__);
	}
}

/*
 * Perform a single packet RMA write where the MR buffer is a sgl that
 * does not contains gaps but the first page may contain an offset.
 */
static void
test_21_rma_mr_sgl_write_off(struct rma_thread_info *info)
{
	size_t len = xfer_size;
	int rc;

	LOG_INFO("RMA thread %d write MR sgl length: %lu", info->id, len);

	rc = test_rma_sgl(info, len, true, true, true, false, false);
	if (rc) {
		LOG_ERR("RMA thread %d FAILED %s", info->id, __func__);
		atomic_inc(&test_21_errors);
	} else {
		LOG_INFO("RMA thread %d PASSED %s", info->id, __func__);
	}
}

/*
 * Perform a single packet RMA read where the MR buffer is a sgl that
 * does not contain gaps but the first page may contain an offset.
 */
static void
test_22_rma_mr_sgl_read_off(struct rma_thread_info *info)
{
	size_t len = xfer_size;
	int rc;

	LOG_INFO("RMA thread %d read MR sgl length: %lu", info->id, len);

	rc = test_rma_sgl(info, len, false, true, true, false, false);
	if (rc) {
		LOG_ERR("RMA thread %d FAILED %s", info->id, __func__);
		atomic_inc(&test_22_errors);
	} else {
		LOG_INFO("RMA thread %d PASSED %s", info->id, __func__);
	}
}

/* Perform a single packet RMA write and force events. */
static void test_23_rma_write_comp(struct rma_thread_info *info)
{
	size_t len = xfer_size;
	int rc;

	LOG_INFO("RMA thread %d write length: %lu", info->id, len);

	rc = test_rma(info, len, true, true);
	if (rc) {
		LOG_ERR("RMA thread %d FAILED %s", info->id, __func__);
		atomic_inc(&test_23_errors);
	} else {
		LOG_INFO("RMA thread %d PASSED %s", info->id, __func__);
	}
}

/* Perform a single packet RMA read and force events. */
static void test_24_rma_read_comp(struct rma_thread_info *info)
{
	size_t len = xfer_size;
	int rc;

	LOG_INFO("RMA thread %d read length: %lu", info->id, len);

	rc = test_rma(info, len, false, true);
	if (rc) {
		LOG_ERR("RMA thread %d FAILED %s", info->id, __func__);
		atomic_inc(&test_24_errors);
	} else {
		LOG_INFO("RMA thread %d PASSED %s", info->id, __func__);
	}
}

/* Perform a zero byte RMA operation with an empty target MR kvec array. */
static void test_25_rma_read_empty_mr_kvec_array(struct rma_thread_info *info)
{
	size_t len = 0;
	int rc;

	LOG_INFO("RMA thread %d read length: %lu", info->id, len);

	rc = test_rma_kvec(info, len, false, true, true, false);
	if (rc) {
		LOG_ERR("RMA thread %d FAILED %s", info->id, __func__);
		atomic_inc(&test_25_errors);
	} else {
		LOG_INFO("RMA thread %d PASSED %s", info->id, __func__);
	}
}

/* Perform a zero byte RMA operation with an empty initiator kvec array. */
static void test_26_rma_read_empty_kvec_array(struct rma_thread_info *info)
{
	size_t len = 0;
	int rc;

	LOG_INFO("RMA thread %d read length: %lu", info->id, len);

	rc = test_rma_kvec(info, len, false, false, true, false);
	if (rc) {
		LOG_ERR("RMA thread %d FAILED %s", info->id, __func__);
		atomic_inc(&test_26_errors);
	} else {
		LOG_INFO("RMA thread %d PASSED %s", info->id, __func__);
	}
}

/* Perform a zero byte RMA operation with an empty target MR kvec array. */
static void test_27_rma_write_empty_mr_kvec_array(struct rma_thread_info *info)
{
	size_t len = 0;
	int rc;

	LOG_INFO("RMA thread %d write length: %lu", info->id, len);

	rc = test_rma_kvec(info, len, true, true, true, false);
	if (rc) {
		LOG_ERR("RMA thread %d FAILED %s", info->id, __func__);
		atomic_inc(&test_27_errors);
	} else {
		LOG_INFO("RMA thread %d PASSED %s", info->id, __func__);
	}
}

/* Perform a zero byte RMA operation with an empty initiator kvec array. */
static void test_28_rma_write_empty_kvec_array(struct rma_thread_info *info)
{
	size_t len = 0;
	int rc;

	LOG_INFO("RMA thread %d write length: %lu", info->id, len);

	rc = test_rma_kvec(info, len, true, false, true, false);
	if (rc) {
		LOG_ERR("RMA thread %d FAILED %s", info->id, __func__);
		atomic_inc(&test_28_errors);
	} else {
		LOG_INFO("RMA thread %d PASSED %s", info->id, __func__);
	}
}

/* Perform a zero byte RMA operation with an empty target MR bvec array. */
static void test_29_rma_read_empty_mr_bvec_array(struct rma_thread_info *info)
{
	size_t len = 0;
	int rc;

	LOG_INFO("RMA thread %d read length: %lu", info->id, len);

	rc = test_rma_bvec(info, len, false, false, true, true, false);
	if (rc) {
		LOG_ERR("RMA thread %d FAILED %s", info->id, __func__);
		atomic_inc(&test_29_errors);
	} else {
		LOG_INFO("RMA thread %d PASSED %s", info->id, __func__);
	}
}

/* Perform a zero byte RMA operation with an empty initiator bvec array. */
static void test_30_rma_read_empty_bvec_array(struct rma_thread_info *info)
{
	size_t len = 0;
	int rc;

	LOG_INFO("RMA thread %d read length: %lu", info->id, len);

	rc = test_rma_bvec(info, len, false, false, false, true, false);
	if (rc) {
		LOG_ERR("RMA thread %d FAILED %s", info->id, __func__);
		atomic_inc(&test_30_errors);
	} else {
		LOG_INFO("RMA thread %d PASSED %s", info->id, __func__);
	}
}

/* Perform a zero byte RMA operation with an empty target MR bvec array. */
static void test_31_rma_write_empty_mr_bvec_array(struct rma_thread_info *info)
{
	size_t len = 0;
	int rc;

	LOG_INFO("RMA thread %d write length: %lu", info->id, len);

	rc = test_rma_bvec(info, len, true, false, true, true, false);
	if (rc) {
		LOG_ERR("RMA thread %d FAILED %s", info->id, __func__);
		atomic_inc(&test_31_errors);
	} else {
		LOG_INFO("RMA thread %d PASSED %s", info->id, __func__);
	}
}

/* Perform a zero byte RMA operation with an empty initiator bvec array. */
static void test_32_rma_write_empty_bvec_array(struct rma_thread_info *info)
{
	size_t len = 0;
	int rc;

	LOG_INFO("RMA thread %d write length: %lu", info->id, len);

	rc = test_rma_bvec(info, len, true, false, false, true, false);
	if (rc) {
		LOG_ERR("RMA thread %d FAILED %s", info->id, __func__);
		atomic_inc(&test_32_errors);
	} else {
		LOG_INFO("RMA thread %d PASSED %s", info->id, __func__);
	}
}

/* Perform a zero byte RMA operation with an empty target MR sgl array. */
static void test_33_rma_read_empty_mr_sgl_array(struct rma_thread_info *info)
{
	size_t len = 0;
	int rc;

	LOG_INFO("RMA thread %d read length: %lu", info->id, len);

	rc = test_rma_sgl(info, len, false, false, true, true, false);
	if (rc) {
		LOG_ERR("RMA thread %d FAILED %s", info->id, __func__);
		atomic_inc(&test_33_errors);
	} else {
		LOG_INFO("RMA thread %d PASSED %s", info->id, __func__);
	}
}

/* Perform a zero byte RMA operation with an empty initiator sgl array. */
static void test_34_rma_read_empty_sgl_array(struct rma_thread_info *info)
{
	size_t len = 0;
	int rc;

	LOG_INFO("RMA thread %d read length: %lu", info->id, len);

	rc = test_rma_sgl(info, len, false, false, false, true, false);
	if (rc) {
		LOG_ERR("RMA thread %d FAILED %s", info->id, __func__);
		atomic_inc(&test_34_errors);
	} else {
		LOG_INFO("RMA thread %d PASSED %s", info->id, __func__);
	}
}

/* Perform a zero byte RMA operation with an empty target MR sgl array. */
static void test_35_rma_write_empty_mr_sgl_array(struct rma_thread_info *info)
{
	size_t len = 0;
	int rc;

	LOG_INFO("RMA thread %d write length: %lu", info->id, len);

	rc = test_rma_sgl(info, len, true, false, true, true, false);
	if (rc) {
		LOG_ERR("RMA thread %d FAILED %s", info->id, __func__);
		atomic_inc(&test_35_errors);
	} else {
		LOG_INFO("RMA thread %d PASSED %s", info->id, __func__);
	}
}

/* Perform a zero byte RMA operation with an empty initiator sgl array. */
static void test_36_rma_write_empty_sgl_array(struct rma_thread_info *info)
{
	size_t len = 0;
	int rc;

	LOG_INFO("RMA thread %d write length: %lu", info->id, len);

	rc = test_rma_sgl(info, len, true, false, false, true, false);
	if (rc) {
		LOG_ERR("RMA thread %d FAILED %s", info->id, __func__);
		atomic_inc(&test_36_errors);
	} else {
		LOG_INFO("RMA thread %d PASSED %s", info->id, __func__);
	}
}

/*
 * Perform a RMA writemsg with kfi_msg_rma using kvec buffers
 */
static void test_37_rma_kvec_writemsg(struct rma_thread_info *info)
{
	size_t len = xfer_size;
	int rc;

	LOG_INFO("RMA thread %d write length: %lu", info->id, len);

	rc = test_rma_kvec(info, len, true, false, false, true);
	if (rc) {
		LOG_ERR("RMA thread %d FAILED %s", info->id, __func__);
		atomic_inc(&test_37_errors);
	} else {
		LOG_INFO("RMA thread %d PASSED %s", info->id, __func__);
	}
}

/*
 * Perform a RMA readmsg with kfi_msg_rma using kvec buffers
 */
static void test_38_rma_kvec_readmsg(struct rma_thread_info *info)
{
	size_t len = xfer_size;
	int rc;

	LOG_INFO("RMA thread %d read length: %lu", info->id, len);

	rc = test_rma_kvec(info, len, false, false, false, true);
	if (rc) {
		LOG_ERR("RMA thread %d FAILED %s", info->id, __func__);
		atomic_inc(&test_38_errors);
	} else {
		LOG_INFO("RMA thread %d PASSED %s", info->id, __func__);
	}
}

/*
 * Perform a RMA writemsg with kfi_msg_rma using bvec buffers
 */
static void test_39_rma_bvec_writemsg(struct rma_thread_info *info)
{
	size_t len = xfer_size;
	int rc;

	LOG_INFO("RMA thread %d write length: %lu", info->id, len);

	rc = test_rma_bvec(info, len, true, false, false, false, true);
	if (rc) {
		LOG_ERR("RMA thread %d FAILED %s", info->id, __func__);
		atomic_inc(&test_39_errors);
	} else {
		LOG_INFO("RMA thread %d PASSED %s", info->id, __func__);
	}
}

/*
 * Perform a RMA readmsg with kfi_msg_rma using bvec buffers
 */
static void test_40_rma_bvec_readmsg(struct rma_thread_info *info)
{
	size_t len = xfer_size;
	int rc;

	LOG_INFO("RMA thread %d read length: %lu", info->id, len);

	rc = test_rma_bvec(info, len, false, false, false, false, true);
	if (rc) {
		LOG_ERR("RMA thread %d FAILED %s", info->id, __func__);
		atomic_inc(&test_40_errors);
	} else {
		LOG_INFO("RMA thread %d PASSED %s", info->id, __func__);
	}
}

/*
 * Perform a RMA writemsg with kfi_msg_rma using sgl buffers
 */
static void test_41_rma_sgl_writemsg(struct rma_thread_info *info)
{
	size_t len = xfer_size;
	int rc;

	LOG_INFO("RMA thread %d write length: %lu", info->id, len);

	rc = test_rma_sgl(info, len, true, false, false, false, true);
	if (rc) {
		LOG_ERR("RMA thread %d FAILED %s", info->id, __func__);
		atomic_inc(&test_41_errors);
	} else {
		LOG_INFO("RMA thread %d PASSED %s", info->id, __func__);
	}
}

/*
 * Perform a RMA readmsg with kfi_msg_rma using sgl buffers
 */
static void test_42_rma_sgl_readmsg(struct rma_thread_info *info)
{
	size_t len = xfer_size;
	int rc;

	LOG_INFO("RMA thread %d read length: %lu", info->id, len);

	rc = test_rma_sgl(info, len, false, false, false, false, true);
	if (rc) {
		LOG_ERR("RMA thread %d FAILED %s", info->id, __func__);
		atomic_inc(&test_42_errors);
	} else {
		LOG_INFO("RMA thread %d PASSED %s", info->id, __func__);
	}
}

/*
 * Each thread will progress through its set of tests N times and then sleep.
 * The threads are terminated with the module is removed.
 */
static int test_run_thread(void *data)
{
	struct rma_thread_info *info = data;
	int count = 0;
	DEFINE_WAIT(wait);

	LOG_INFO("RMA thread %d running", info->id);

	while (!kthread_should_stop()) {
		while (count < max_loop_cnt) {
			count++;

			test_1_rma_write(info);
			test_2_rma_read(info);

			test_3_rma_kvec_write(info);
			test_4_rma_kvec_read(info);

			test_5_rma_bvec_write(info);
			test_6_rma_bvec_read(info);
			test_7_rma_bvec_write_offset(info);
			test_8_rma_bvec_read_offset(info);

			test_9_rma_sgl_write(info);
			test_10_rma_sgl_read(info);
			test_11_rma_sgl_write_offset(info);
			test_12_rma_sgl_read_offset(info);

			test_13_rma_mr_kvec_write(info);
			test_14_rma_mr_kvec_read(info);

			test_15_rma_mr_bvec_write(info);
			test_16_rma_mr_bvec_read(info);
			test_17_rma_mr_bvec_write_off(info);
			test_18_rma_mr_bvec_read_off(info);

			test_19_rma_mr_sgl_write(info);
			test_20_rma_mr_sgl_read(info);
			test_21_rma_mr_sgl_write_off(info);
			test_22_rma_mr_sgl_read_off(info);

			if (expect_no_completion) {
				test_23_rma_write_comp(info);
				test_24_rma_read_comp(info);
			}

			if (!xfer_size) {
				test_25_rma_read_empty_mr_kvec_array(info);
				test_26_rma_read_empty_kvec_array(info);
				test_27_rma_write_empty_mr_kvec_array(info);
				test_28_rma_write_empty_kvec_array(info);

				test_29_rma_read_empty_mr_bvec_array(info);
				test_30_rma_read_empty_bvec_array(info);
				test_31_rma_write_empty_mr_bvec_array(info);
				test_32_rma_write_empty_bvec_array(info);

				test_33_rma_read_empty_mr_sgl_array(info);
				test_34_rma_read_empty_sgl_array(info);
				test_35_rma_write_empty_mr_sgl_array(info);
				test_36_rma_write_empty_sgl_array(info);
			}

			if (xfer_size) {
				test_37_rma_kvec_writemsg(info);
				test_38_rma_kvec_readmsg(info);
				test_39_rma_bvec_writemsg(info);
				test_40_rma_bvec_readmsg(info);
				test_41_rma_sgl_writemsg(info);
				test_42_rma_sgl_readmsg(info);
			}
		}

		if (!kthread_should_stop()) {
			prepare_to_wait_exclusive(&wait_queue, &wait,
						  TASK_INTERRUPTIBLE);
			schedule();
			finish_wait(&wait_queue, &wait);
		}
	}

	LOG_INFO("RMA thread %d exiting", info->id);

	return 0;
}

/*
 * Initialize threads info. Each thread will have a unique set of resources to
 * work with.
 */
static struct rma_thread_info *thread_init(int thread_id)
{
	struct rma_thread_info *info;
	void *cq_context[MAX_TX_CTX];
	int rc;
	int i;

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info) {
		LOG_ERR("Failed to allocate rma thread info");
		rc = -ENOMEM;
		goto err;
	}

	info->id = thread_id;
	info->av_attr.type = KFI_AV_UNSPEC;
	info->cq_attr.format = KFI_CQ_FORMAT_TAGGED;

	info->res_opts.node = node;
	info->res_opts.service = kasprintf(GFP_KERNEL, "%d", thread_id);
	if (!info->res_opts.service) {
		rc = -ENOMEM;
		goto err_free_info;
	}

	info->res_opts.hints = kfi_allocinfo();
	if (!info->res_opts.hints) {
		LOG_ERR("Failed to allocate fabric hints");
		rc = -ENOMEM;
		goto err_free_service;
	}

	info->res_opts.hints->caps = (KFI_RMA | KFI_WRITE | KFI_READ |
				      KFI_REMOTE_READ | KFI_REMOTE_WRITE);
	if (remote_rma_events)
		info->res_opts.hints->caps |= KFI_RMA_EVENT;

	info->res_opts.hints->ep_attr->type = KFI_EP_RDM;
	info->res_opts.hints->ep_attr->tx_ctx_cnt = MAX_TX_CTX;
	info->res_opts.hints->ep_attr->rx_ctx_cnt = MAX_RX_CTX;
	info->res_opts.hints->tx_attr->op_flags = KFI_TRANSMIT_COMPLETE;
	info->res_opts.av_attr = &info->av_attr;
	info->res_opts.tx_cq_attr = &info->cq_attr;
	info->res_opts.tx_cq_handler = test_tx_cq_cb;
	info->res_opts.tx_count = info->res_opts.hints->ep_attr->tx_ctx_cnt;
	info->res_opts.rx_cq_attr = &info->cq_attr;
	info->res_opts.rx_cq_handler = test_rx_cq_cb;
	info->res_opts.rx_count = info->res_opts.hints->ep_attr->rx_ctx_cnt;

	if (comp_op_flag)
		info->res_opts.hints->tx_attr->op_flags |= KFI_COMPLETION;

	if (selective_comp)
		info->res_opts.tx_selective_completion = true;

	for (i = 0; i < info->res_opts.hints->ep_attr->tx_ctx_cnt; i++)
		cq_context[i] = info;
	info->res_opts.tx_cq_context = cq_context;
	info->res_opts.rx_cq_context = cq_context;

	info->res = sep_resource_alloc(&info->res_opts);
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

	LOG_INFO("MSG thread info %d allocated", thread_id);

	return info;

err_free_sep_loopback_res:
	sep_res_loopback_free(info->loopback);
err_free_sep_res:
	sep_resource_free(info->res);
err_free_hints:
	kfi_freeinfo(info->res_opts.hints);
err_free_service:
	kfree(info->res_opts.service);
err_free_info:
	kfree(info);
err:
	return ERR_PTR(rc);
}

static void thread_fini(struct rma_thread_info *info)
{
	int thread_id = info->id;

	kthread_stop(info->thread);

	sep_res_loopback_free(info->loopback);
	sep_resource_free(info->res);
	kfi_freeinfo(info->res_opts.hints);
	kfree(info->res_opts.service);
	kfree(info);

	LOG_INFO("RMA thread info %d freed", thread_id);
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

	/* Limit the timeout for RMA events. */
	if (selective_comp && rma_timeout > 10) {
		LOG_ERR("RMA timeout cannot exceed 10 seconds");
		return -EINVAL;
	}

	if (selective_comp && !comp_op_flag)
		expect_no_completion = true;

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

	LOG_INFO("Test 1 (RMA write) had %d errors",
		 atomic_read(&test_1_errors));
	LOG_INFO("Test 2 (RMA read) had %d errors",
		 atomic_read(&test_2_errors));
	LOG_INFO("Test 3 (kvec RMA write) had %d errors",
		 atomic_read(&test_3_errors));
	LOG_INFO("Test 4 (kvec RMA read) had %d errors",
		 atomic_read(&test_4_errors));
	LOG_INFO("Test 5 (bvec RMA write) had %d errors",
		 atomic_read(&test_5_errors));
	LOG_INFO("Test 6 (bvec RMA read) had %d errors",
		 atomic_read(&test_6_errors));
	LOG_INFO("Test 7 (bvec w/ off RMA write) had %d errors",
		 atomic_read(&test_7_errors));
	LOG_INFO("Test 8 (bvec w/ off RMA read) had %d errors",
		 atomic_read(&test_8_errors));
	LOG_INFO("Test 9 (sgl RMA write) had %d errors",
		 atomic_read(&test_9_errors));
	LOG_INFO("Test 10 (sgl RMA read) had %d errors",
		 atomic_read(&test_10_errors));
	LOG_INFO("Test 11 (sgl w/ off RMA write) had %d errors",
		 atomic_read(&test_11_errors));
	LOG_INFO("Test 12 (sgl w/ off RMA read) had %d errors",
		 atomic_read(&test_12_errors));
	LOG_INFO("Test 13 (MR kvec RMA write) had %d errors",
		 atomic_read(&test_13_errors));
	LOG_INFO("Test 14 (MR kvec RMA read) had %d errors",
		 atomic_read(&test_14_errors));
	LOG_INFO("Test 15 (MR bvec RMA write) had %d errors",
		 atomic_read(&test_15_errors));
	LOG_INFO("Test 16 (MR bvec RMA read) had %d errors",
		 atomic_read(&test_16_errors));
	LOG_INFO("Test 17 (MR bvec w/ off RMA write) had %d errors",
		 atomic_read(&test_17_errors));
	LOG_INFO("Test 18 (MR bvec w/ off RMA read) had %d errors",
		 atomic_read(&test_18_errors));
	LOG_INFO("Test 19 (MR sgl RMA write) had %d errors",
		 atomic_read(&test_19_errors));
	LOG_INFO("Test 20 (MR sgl RMA read) had %d errors",
		 atomic_read(&test_20_errors));
	LOG_INFO("Test 21 (MR sgl w/ off RMA write) had %d errors",
		 atomic_read(&test_21_errors));
	LOG_INFO("Test 22 (MR sgl w/ off RMA read) had %d errors",
		 atomic_read(&test_22_errors));

	if (expect_no_completion) {
		LOG_INFO("Test 23 (RMA write comp) had %d errors",
			 atomic_read(&test_23_errors));
		LOG_INFO("Test 24 (RMA read comp) had %d errors",
			 atomic_read(&test_24_errors));
	}

	if (!xfer_size) {
		LOG_INFO("Test 25 (RMA read empty MR kvec) had %d errors",
			 atomic_read(&test_25_errors));
		LOG_INFO("Test 26 (RMA read empty init kvec) had %d errors",
			 atomic_read(&test_26_errors));
		LOG_INFO("Test 27 (RMA write empty MR kvec) had %d errors",
			 atomic_read(&test_27_errors));
		LOG_INFO("Test 28 (RMA write empty init kvec) had %d errors",
			 atomic_read(&test_28_errors));
		LOG_INFO("Test 29 (RMA read empty MR bvec) had %d errors",
			 atomic_read(&test_29_errors));
		LOG_INFO("Test 30 (RMA read empty init bvec) had %d errors",
			 atomic_read(&test_30_errors));
		LOG_INFO("Test 31 (RMA write empty MR bvec) had %d errors",
			 atomic_read(&test_31_errors));
		LOG_INFO("Test 32 (RMA write empty init bvec) had %d errors",
			 atomic_read(&test_32_errors));
		LOG_INFO("Test 33 (RMA read empty MR sgl) had %d errors",
			 atomic_read(&test_33_errors));
		LOG_INFO("Test 34 (RMA read empty init sgl) had %d errors",
			 atomic_read(&test_34_errors));
		LOG_INFO("Test 35 (RMA write empty MR sgl) had %d errors",
			 atomic_read(&test_35_errors));
		LOG_INFO("Test 36 (RMA write empty init sgl) had %d errors",
			 atomic_read(&test_36_errors));
	}

	if (xfer_size) {
		LOG_INFO("Test 37 (RMA kvec writemsg) had %d errors",
			 atomic_read(&test_37_errors));
		LOG_INFO("Test 38 (RMA kvec readmsg) had %d errors",
			 atomic_read(&test_38_errors));
		LOG_INFO("Test 39 (RMA kvec writemsg) had %d errors",
			 atomic_read(&test_39_errors));
		LOG_INFO("Test 40 (RMA kvec readmsg) had %d errors",
			 atomic_read(&test_40_errors));
		LOG_INFO("Test 41 (RMA sgl writemsg) had %d errors",
			 atomic_read(&test_41_errors));
		LOG_INFO("Test 42 (RMA sgl readmsg) had %d errors",
			 atomic_read(&test_42_errors));
	}

	if (atomic_read(&test_1_errors) || atomic_read(&test_2_errors) ||
	    atomic_read(&test_3_errors) || atomic_read(&test_4_errors) ||
	    atomic_read(&test_5_errors) || atomic_read(&test_6_errors) ||
	    atomic_read(&test_7_errors) || atomic_read(&test_8_errors) ||
	    atomic_read(&test_9_errors) || atomic_read(&test_10_errors) ||
	    atomic_read(&test_11_errors) || atomic_read(&test_12_errors) ||
	    atomic_read(&test_13_errors) || atomic_read(&test_14_errors) ||
	    atomic_read(&test_15_errors) || atomic_read(&test_16_errors) ||
	    atomic_read(&test_17_errors) || atomic_read(&test_16_errors) ||
	    atomic_read(&test_19_errors) || atomic_read(&test_20_errors) ||
	    atomic_read(&test_21_errors) || atomic_read(&test_22_errors) ||
	    atomic_read(&test_23_errors) || atomic_read(&test_24_errors) ||
	    atomic_read(&test_25_errors) || atomic_read(&test_26_errors) ||
	    atomic_read(&test_27_errors) || atomic_read(&test_28_errors) ||
	    atomic_read(&test_29_errors) || atomic_read(&test_30_errors) ||
	    atomic_read(&test_31_errors) || atomic_read(&test_32_errors) ||
	    atomic_read(&test_33_errors) || atomic_read(&test_34_errors) ||
	    atomic_read(&test_35_errors) || atomic_read(&test_36_errors) ||
	    atomic_read(&test_37_errors) || atomic_read(&test_38_errors) ||
	    atomic_read(&test_39_errors) || atomic_read(&test_40_errors) ||
	    atomic_read(&test_41_errors) || atomic_read(&test_42_errors))
		LOG_ERR("TESTS FAILED");
	else
		LOG_ERR("ALL TESTS PASSED");
}

module_init(test_module_init);
module_exit(test_module_exit);
