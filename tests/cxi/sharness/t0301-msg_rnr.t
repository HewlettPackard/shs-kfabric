#!/bin/bash

# Test authorization keys

test_description="CXI receiver not ready tests"

. ./sharness.sh

. ../cxi_test_setup.sh

cxi_test_setup

test_expect_success "Test CXI message receiver not ready" "
	insmod ${KFAB_DIR}/tests/cxi/single_client/test_msg_rnr.ko &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Removing CXI message receiver not ready" "
	rmmod test_msg_rnr &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

cxi_test_finish

dmesg > ../output/$(basename "$0").dmesg.txt

test_done
