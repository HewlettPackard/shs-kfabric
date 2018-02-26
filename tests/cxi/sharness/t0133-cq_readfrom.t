#!/bin/bash

# Test CQ readfrom.

test_description="CXI CQ readfrom"

. ./sharness.sh

. ../cxi_test_setup.sh

cxi_test_setup

test_expect_success "Test CXI CQ readfrom" "
	insmod ${KFAB_DIR}/tests/cxi/single_client/test_cq_readfrom.ko &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Removing CXI CQ readfrom" "
	rmmod test_cq_readfrom &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

cxi_test_finish

dmesg > ../output/$(basename "$0").dmesg.txt

test_done
