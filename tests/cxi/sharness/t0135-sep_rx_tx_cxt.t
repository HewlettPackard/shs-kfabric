#!/bin/bash

# Test CXI SEP Domain

test_description="CXI SEP RX TX Context Limits"

. ./sharness.sh

. ../cxi_test_setup.sh

cxi_test_setup

test_expect_success "Test CXI SEP RX TX Context Limits" "
	insmod ${KFAB_DIR}/tests/cxi/single_client/test-sep-rx-tx-ctx.ko &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Removing CXI SEP RX TX Context Limits" "
	rmmod test-sep-rx-tx-ctx &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

cxi_test_finish

dmesg > ../output/$(basename "$0").dmesg.txt

test_done
