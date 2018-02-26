#!/bin/bash

# Test CXI SEP Enable TX

test_description="CXI SEP Enable TX"

. ./sharness.sh

. ../cxi_test_setup.sh

cxi_test_setup

test_expect_success "Test CXI SEP Enable TX" "
	insmod ${KFAB_DIR}/tests/cxi/single_client/test_sep_enable_tx.ko &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Removing CXI SEP Enable TX" "
	rmmod test_sep_enable_tx &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

cxi_test_finish

dmesg > ../output/$(basename "$0").dmesg.txt

test_done
