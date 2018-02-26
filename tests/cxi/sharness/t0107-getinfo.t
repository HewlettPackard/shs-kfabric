#!/bin/bash

# Test CXI getinfo

test_description="CXI Getinfo Tests"

. ./sharness.sh

. ../cxi_test_setup.sh

cxi_test_setup

test_expect_success "Test CXI Getinfo" "
	insmod ${KFAB_DIR}/tests/cxi/single_client/test_getinfo.ko &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Removing CXI Getinfo" "
	rmmod test_getinfo &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

cxi_test_finish

dmesg > ../output/$(basename "$0").dmesg.txt

test_done
