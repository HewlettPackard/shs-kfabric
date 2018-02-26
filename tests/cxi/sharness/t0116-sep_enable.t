#!/bin/bash

# Test CXI SEP Enable

test_description="CXI SEP Enable"

. ./sharness.sh

. ../cxi_test_setup.sh

cxi_test_setup

test_expect_success "Test CXI SEP Enable" "
	insmod ${KFAB_DIR}/tests/cxi/single_client/test_sep_enable.ko &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Removing CXI SEP Enable" "
	rmmod test_sep_enable &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

cxi_test_finish

dmesg > ../output/$(basename "$0").dmesg.txt

test_done
