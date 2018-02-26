#!/bin/bash

# Test CXI MR Allocation

test_description="CXI MR Allocation"

. ./sharness.sh

. ../cxi_test_setup.sh

cxi_test_setup

test_expect_success "Test CXI MR Allocation Sync" "
	insmod ${KFAB_DIR}/tests/cxi/single_client/test-mr-alloc-sync.ko &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Removing CXI MR Allocation Sync" "
	rmmod test-mr-alloc-sync &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

cxi_test_finish

dmesg > ../output/$(basename "$0").dmesg.txt

test_done
