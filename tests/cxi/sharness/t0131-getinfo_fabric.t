#!/bin/bash

# Test getinfo fabric

test_description="CXI getinfo fabric"

. ./sharness.sh

. ../cxi_test_setup.sh

cxi_test_setup

test_expect_success "Test CXI getinfo fabric" "
	insmod ${KFAB_DIR}/tests/cxi/single_client/test_getinfo_fabric.ko &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Removing CXI getinfo fabric" "
	rmmod test_getinfo_fabric &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

cxi_test_finish

dmesg > ../output/$(basename "$0").dmesg.txt

test_done
