#!/bin/bash

# Test CXI SEP Alloc TX Context

test_description="CXI SEP Alloc TX Tests"

. ./sharness.sh

. ../cxi_test_setup.sh

cxi_test_setup

test_expect_success "Test CXI SEP Alloc TX" "
	insmod ${KFAB_DIR}/tests/cxi/single_client/test_sep_alloc_tx.ko &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Removing CXI SEP Alloc TX" "
	rmmod test_sep_alloc_tx &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

cxi_test_finish

dmesg > ../output/$(basename "$0").dmesg.txt

test_done
