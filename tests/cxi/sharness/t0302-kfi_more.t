#!/bin/bash

test_description="CXI KFI_MORE tests"

. ./sharness.sh

. ../cxi_test_setup.sh

cxi_test_setup

test_expect_success "Test CXI KFI_MORE" "
	insmod ${KFAB_DIR}/tests/cxi/single_client/test_more.ko &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Removing CXI KFI_MORE" "
	rmmod test_more &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

cxi_test_finish

dmesg > ../output/$(basename "$0").dmesg.txt

test_done
