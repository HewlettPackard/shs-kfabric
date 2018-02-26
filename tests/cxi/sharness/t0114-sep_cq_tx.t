#!/bin/bash

# Test CXi SEP CQ TX

test_description="CXI SEP CQ TX"

. ./sharness.sh

. ../cxi_test_setup.sh

cxi_test_setup

test_expect_success "Test CXI SEP CQ TX" "
	insmod ${KFAB_DIR}/tests/cxi/single_client/test_sep_cq_tx.ko &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Removing CXI SEP CQ TX" "
	rmmod test_sep_cq_tx &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

cxi_test_finish

dmesg > ../output/$(basename "$0").dmesg.txt

test_done
