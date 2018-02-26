#!/bin/bash

# Test CXI canceling of RX operations

test_description="CXI Cancel RX Operations"

. ./sharness.sh

. ../cxi_test_setup.sh

cxi_test_setup

test_expect_success "Test CXI Cancel RX Operations" "
	insmod ${KFAB_DIR}/tests/cxi/single_client/test_rx_cancel.ko &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Removing CXI Cancel RX Operations" "
	rmmod test_rx_cancel &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

cxi_test_finish

dmesg > ../output/$(basename "$0").dmesg.txt

test_done
