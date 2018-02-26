#!/bin/bash

# Test CXI CQ Thread

test_description="CXI CQ Thread Tests"

. ./sharness.sh

. ../cxi_test_setup.sh

cxi_test_setup

test_expect_success "Test CXI CQ Thread" "
	insmod ${KFAB_DIR}/tests/cxi/single_client/test_cq_thread.ko &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

sleep 5

test_expect_success "Remove CXI CQ Thread" "
	rmmod test_cq_thread
"

test_expect_success "Check DMESG" "
	[ $(dmesg | grep -c 'All entries consumed') -eq 1 ]
"

cxi_test_finish

dmesg > ../output/$(basename "$0").dmesg.txt

test_done
