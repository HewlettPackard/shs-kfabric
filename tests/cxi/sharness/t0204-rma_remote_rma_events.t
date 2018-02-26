#!/bin/bash

# Test CXI RMA operations

test_description="CXI RMA operations with remote RMA events"

. ./sharness.sh

. ../cxi_test_setup.sh

cxi_test_setup

test_expect_success "Test CXI RMA operations with remote RMA events" "
	insmod ${KFAB_DIR}/tests/cxi/single_client/test-rma-ops-thread.ko remote_rma_events=1 max_thread_cnt=1 max_loop_cnt=1 &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Removing CXI RMA operations with remote RMA events" "
	rmmod test-rma-ops-thread &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Zero Errors" "
	[ $(dmesg | grep -c 'ALL TESTS PASSED') -eq 1 ]
"

cxi_test_finish

dmesg > ../output/$(basename "$0").dmesg.txt

test_done
