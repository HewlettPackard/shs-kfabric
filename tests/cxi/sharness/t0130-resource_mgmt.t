#!/bin/bash

# Test resource management

test_description="CXI resource management"

. ./sharness.sh

. ../cxi_test_setup.sh

cxi_test_setup

test_expect_success "Test CXI resource management" "
	insmod ${KFAB_DIR}/tests/cxi/single_client/test_resource_mgmt.ko &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Removing CXI resource management" "
	rmmod test_resource_mgmt &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

cxi_test_finish

dmesg > ../output/$(basename "$0").dmesg.txt

test_done
