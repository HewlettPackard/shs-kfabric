#!/bin/bash

# Test CXI RX context options

test_description="CXI RX context options"

. ./sharness.sh

. ../cxi_test_setup.sh

cxi_test_setup

test_expect_success "Test CXI RX context options" "
	insmod ${KFAB_DIR}/tests/cxi/single_client/test-rx-ctx-opts.ko &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Removing CXI RX context options" "
	rmmod test-rx-ctx-opts &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

cxi_test_finish

dmesg > ../output/$(basename "$0").dmesg.txt

test_done
