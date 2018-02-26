#!/bin/bash

# Test CXI MSG operations

test_description="CXI MSG operations using Bulk Data"

. ./sharness.sh

. ../cxi_test_setup.sh

cxi_test_setup

test_expect_success "Test CXI MSG operations using Bulk Data" "
	insmod ${KFAB_DIR}/tests/cxi/single_client/test-msg-ops-thread.ko max_thread_cnt=1 max_loop_cnt=1 tclass=515 &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Removing CXI MSG operations using Bulk Data" "
	rmmod test-msg-ops-thread &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Zero Errors" "
	[ $(dmesg | grep -c 'ALL TESTS PASSED') -eq 1 ]
"

cxi_test_finish

dmesg > ../output/$(basename "$0").dmesg.txt

test_done
