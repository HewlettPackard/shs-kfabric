#!/bin/bash

# Test NUMA node spreading for TX/RX contexts

test_description="CXI NUMA node spreading tests"

. ./sharness.sh

. ../cxi_test_setup.sh

cxi_test_setup

test_expect_success "Test CXI NUMA node spreading" "
	insmod ${KFAB_DIR}/tests/cxi/single_client/test-numa-spread.ko &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Removing CXI NUMA node spreading test" "
	rmmod test-numa-spread &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

cxi_test_finish

dmesg > ../output/$(basename "$0").dmesg.txt

test_done
