#!/bin/bash

# Test getinfo domain

test_description="CXI getinfo domain"

. ./sharness.sh

. ../cxi_test_setup.sh

cxi_test_setup

test_expect_success "Test CXI getinfo domain" "
	insmod ${KFAB_DIR}/tests/cxi/single_client/test_getinfo_domain.ko &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Removing CXI getinfo domain" "
	rmmod test_getinfo_domain &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

cxi_test_finish

dmesg > ../output/$(basename "$0").dmesg.txt

test_done
