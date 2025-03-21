#!/bin/bash

# Test CXI SEP Domain

test_description="CXI SEP Domain"

. ./sharness.sh

. ../cxi_test_setup.sh

cxi_test_setup

test_expect_success "Test CXI SEP Domain" "
	insmod ${KFAB_DIR}/tests/cxi/single_client/test_sep_domain.ko &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Removing CXI SEP Domain" "
	rmmod test_sep_domain &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

cxi_test_finish

dmesg > ../output/$(basename "$0").dmesg.txt

test_done
