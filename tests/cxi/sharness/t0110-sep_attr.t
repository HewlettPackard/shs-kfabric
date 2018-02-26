#!/bin/bash

# Test CXI SEP Attr

test_description="CXI SEP Attr Tests"

. ./sharness.sh

. ../cxi_test_setup.sh

cxi_test_setup

test_expect_success "Test CXI SEP Attr" "
	insmod ${KFAB_DIR}/tests/cxi/single_client/test_sep_attr.ko &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Removing CXI SEP Attr" "
	rmmod test_sep_attr &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

cxi_test_finish

dmesg > ../output/$(basename "$0").dmesg.txt

test_done
