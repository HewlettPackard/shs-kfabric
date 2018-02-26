#!/bin/bash

# Test CXI MR Allocation

test_description="CXI MR Allocation Async with Threads"

. ./sharness.sh

. ../cxi_test_setup.sh

cxi_test_setup

test_expect_success "Test CXI MR Allocation Async Threads" "
	insmod ${KFAB_DIR}/tests/cxi/single_client/test-mr-alloc-async-thread.ko &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Removing CXI MR Allocation Async Threads" "
	rmmod test-mr-alloc-async-thread &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Zero Errors" "
	[ $(dmesg | grep -c 'test_mr_alloc_async_thread: TEST PASSED') -eq 1 ]
"

cxi_test_finish

dmesg > ../output/$(basename "$0").dmesg.txt

test_done
