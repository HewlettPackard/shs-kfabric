#!/bin/bash

# Test CXI domain

test_description="Testing CXI OFI domains"

. ./sharness.sh

. ../cxi_test_setup.sh

cxi_test_setup

test_expect_success "Test CXI Domain" "
	insmod ${KFAB_DIR}/tests/cxi/single_client/test_domain.ko &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Removing CXI Domain" "
	rmmod test_domain &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

cxi_test_finish

dmesg > ../output/$(basename "$0").dmesg.txt

test_done
