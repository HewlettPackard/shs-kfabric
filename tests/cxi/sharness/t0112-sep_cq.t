#!/bin/bash

# Test CXI SEP CQ

test_description="CXI SEP CQ"

. ./sharness.sh

. ../cxi_test_setup.sh

cxi_test_setup

test_expect_success "Test CXI SEP CQ" "
	insmod ${KFAB_DIR}/tests/cxi/single_client/test_sep_cq.ko &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Removing CXI SEP CQ" "
	rmmod test_sep_cq &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

cxi_test_finish

dmesg > ../output/$(basename "$0").dmesg.txt

test_done