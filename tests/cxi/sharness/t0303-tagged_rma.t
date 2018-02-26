#!/bin/bash

# Test tagged rma

test_description="CXI tagged rma"

. ./sharness.sh

. ../cxi_test_setup.sh

cxi_test_setup

test_expect_success "Test CXI tagged rma" "
	insmod ${KFAB_DIR}/tests/cxi/single_client/test_tagged_rma.ko &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Removing CXI tagged rma" "
	rmmod test_tagged_rma &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

cxi_test_finish

dmesg > ../output/$(basename "$0").dmesg.txt

test_done
