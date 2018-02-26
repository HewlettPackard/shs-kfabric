#!/bin/bash

# Test CXI TX context options

test_description="CXI TX context options"

. ./sharness.sh

. ../cxi_test_setup.sh

cxi_test_setup

test_expect_success "Test CXI TX context options" "
	insmod ${KFAB_DIR}/tests/cxi/single_client/test-tx-ctx-opts.ko &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Removing CXI TX context options" "
	rmmod test-tx-ctx-opts &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

cxi_test_finish

dmesg > ../output/$(basename "$0").dmesg.txt

test_done
