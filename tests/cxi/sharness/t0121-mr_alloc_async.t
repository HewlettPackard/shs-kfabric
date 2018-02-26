#!/bin/bash

# Test CXI MR Allocation

test_description="CXI MR Allocation Async"

. ./sharness.sh

. ../cxi_test_setup.sh

cxi_test_setup

test_expect_success "Test CXI MR Allocation Async" "
	insmod ${KFAB_DIR}/tests/cxi/single_client/test-mr-alloc-async.ko &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Removing CXI MR Allocation Async" "
	rmmod test-mr-alloc-async &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

cxi_test_finish

dmesg > ../output/$(basename "$0").dmesg.txt

test_done
