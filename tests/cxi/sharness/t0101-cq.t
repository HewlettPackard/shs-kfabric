#!/bin/bash

# Test CXI CQ

test_description="CXI CQ Tests"

. ./sharness.sh

. ../cxi_test_setup.sh

cxi_test_setup

test_expect_success "Test CXI CQ" "
	insmod ${KFAB_DIR}/tests/cxi/single_client/test_cq.ko &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Removing CXI CQ" "
	rmmod test_cq &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

cxi_test_finish

dmesg > ../output/$(basename "$0").dmesg.txt

test_done
