#!/bin/bash

# Test CXI RMA operations

test_description="CXI 0 byte RMA operations with threads"

. ./sharness.sh

. ../cxi_test_setup.sh

cxi_test_setup

test_expect_success "Test CXI 0 byte RMA operations with threads" "
	insmod ${KFAB_DIR}/tests/cxi/single_client/test-rma-ops-thread.ko xfer_size=0 max_thread_cnt=1 max_loop_cnt=1 &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Removing CXI 0 byte RMA operations with threads" "
	rmmod test-rma-ops-thread &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Zero Errors" "
	[ $(dmesg | grep -c 'ALL TESTS PASSED') -eq 1 ]
"

cxi_test_finish

dmesg > ../output/$(basename "$0").dmesg.txt

test_done
