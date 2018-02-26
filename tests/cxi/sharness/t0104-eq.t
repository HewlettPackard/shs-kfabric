#!/bin/bash

# Test CXI EQ

test_description="Testing CXI OFI EQs"

. ./sharness.sh

. ../cxi_test_setup.sh

cxi_test_setup

test_expect_success "Test CXI EQ" "
	insmod ${KFAB_DIR}/tests/cxi/single_client/test_eq.ko &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Removing CXI EQ" "
	rmmod test_eq &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

cxi_test_finish

dmesg > ../output/$(basename "$0").dmesg.txt

test_done
