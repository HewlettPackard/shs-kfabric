#!/bin/bash

# Test CXI SEP Multi EP

test_description="CXI SEP Multi EP"

. ./sharness.sh

. ../cxi_test_setup.sh

cxi_test_setup

test_expect_success "Test CXI SEP Multi EP" "
	insmod ${KFAB_DIR}/tests/cxi/single_client/test_sep_multi_ep.ko &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Removing CXI SEP Multi EP" "
	rmmod test_sep_multi_ep &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

cxi_test_finish

dmesg > ../output/$(basename "$0").dmesg.txt

test_done
