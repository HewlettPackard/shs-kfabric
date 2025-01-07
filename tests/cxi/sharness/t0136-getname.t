#!/bin/bash

# Test CXI getname

test_description="CXI Getname Tests"

. ./sharness.sh

. ../cxi_test_setup.sh

cxi_test_setup

test_expect_success "Test CXI Getname" "
	insmod ${KFAB_DIR}/tests/cxi/single_client/test_getname.ko &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Removing CXI Getname" "
	rmmod test_getname &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

cxi_test_finish

dmesg > ../output/$(basename "$0").dmesg.txt

test_done
