TOPDIR := $(src)/../../..
TEST_COMMON_DIR := $(TOPDIR)/tests/cxi/common
TEST_COMMON_LIB := ../common/test_common.o

obj-m := \
	test_tagged_ops.o \
	test_cq_readfrom.o \
	test_getinfo_domain.o \
	test_getinfo_fabric.o \
	test_resource_mgmt.o \
	test_getinfo.o \
	test_fabric.o \
	test_eq.o \
	test_eq_thread.o \
	test_domain.o \
	test_av.o \
	test_cq.o \
	test_cq_thread.o \
	test_sep_multi_ep.o \
	test_sep_enable_tx.o \
	test_sep_enable_rx.o \
	test_sep_enable.o \
	test_sep_domain.o \
	test_sep_cq_tx.o \
	test_sep_cq_rx.o \
	test_sep_cq.o \
	test_sep_av.o \
	test_sep_attr.o \
	test_sep_alloc_tx.o \
	test_sep_alloc_rx.o \
	test-sep-rx-tx-ctx.o \
	test-mr-alloc-sync.o \
	test-mr-alloc-async.o \
	test-mr-alloc-async-thread.o \
	test-rma-ops-thread.o \
	test_rx_cancel.o \
	test-msg-ops-thread.o \
	test-rx-ctx-opts.o \
	test-tx-ctx-opts.o \
	test_shared_cq.o \
	test_auth_key.o \
	test_multi_recv.o \
	test_run_getinfo.o \
	test_msg_rnr.o \
	test_more.o \
	test_tagged_rma.o \
	test_rma_md_cache.o

test-msg-ops-thread-objs := test_msg_ops_thread.o $(TEST_COMMON_LIB)
test-rma-ops-thread-objs := test_rma_ops_thread.o $(TEST_COMMON_LIB)
test-mr-alloc-async-objs := test_mr_alloc_async.o $(TEST_COMMON_LIB)
test-mr-alloc-sync-objs := test_mr_alloc_sync.o $(TEST_COMMON_LIB)
test-mr-alloc-async-thread-objs := test_mr_alloc_async_thread.o $(TEST_COMMON_LIB)
test-rx-ctx-opts-objs := test_rx_ctx_opts.o $(TEST_COMMON_LIB)
test-tx-ctx-opts-objs := test_tx_ctx_opts.o $(TEST_COMMON_LIB)
test-sep-rx-tx-ctx-objs := test_sep_rx_tx_ctx.o $(TEST_COMMON_LIB)

ccflags-y += -I$(TOPDIR)/include -I$(TOPDIR)/../cxi-driver/include \
	-I$(TOPDIR)/../cassini-headers/install/include \
	-I$(TEST_COMMON_DIR)
