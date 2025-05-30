#!/bin/bash

# Test CXI fabric

test_description="CXI Fabric Tests"

. ./sharness.sh

. ../cxi_test_setup.sh

cxi_test_setup

test_expect_success "Test CXI Fabric" "
	insmod ${KFAB_DIR}/tests/cxi/single_client/test_fabric.ko &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Removing CXI Fabric" "
	rmmod test_fabric &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

cxi_test_finish

dmesg > ../output/$(basename "$0").dmesg.txt

test_done
