#!/bin/bash

# Test CXI SEP AV

test_description="CXI SEP AV"

. ./sharness.sh

. ../cxi_test_setup.sh

cxi_test_setup

test_expect_success "Test CXI SEP AV" "
	insmod ${KFAB_DIR}/tests/cxi/single_client/test_sep_av.ko &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Removing CXI SEP AV" "
	rmmod test_sep_av &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

cxi_test_finish

dmesg > ../output/$(basename "$0").dmesg.txt

test_done
