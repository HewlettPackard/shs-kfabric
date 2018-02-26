#!/bin/bash

# Test shared CQ

test_description="CXI shared CQ"

. ./sharness.sh

. ../cxi_test_setup.sh

cxi_test_setup

test_expect_success "Test CXI shared CQ" "
	insmod ${KFAB_DIR}/tests/cxi/single_client/test_shared_cq.ko &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Removing CXI shared CQ" "
	rmmod test_shared_cq &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

cxi_test_finish

dmesg > ../output/$(basename "$0").dmesg.txt

test_done
