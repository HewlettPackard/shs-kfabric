#!/bin/bash

# Teset SEP Alloc RC Context

test_description="CXI SEP Alloc RX Tests"

. ./sharness.sh

. ../cxi_test_setup.sh

cxi_test_setup

test_expect_success "Test CXI SEP Alloc RX" "
	insmod ${KFAB_DIR}/tests/cxi/single_client/test_sep_alloc_rx.ko &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Removing CXI SEP Alloc RX" "
	rmmod test_sep_alloc_rx &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

cxi_test_finish

dmesg > ../output/$(basename "$0").dmesg.txt

test_done
