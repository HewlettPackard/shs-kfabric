#!/bin/bash

# Test authorization keys

test_description="CXI authorization keys"

. ./sharness.sh

. ../cxi_test_setup.sh

cxi_test_setup

test_expect_success "Test CXI authorization keys" "
	insmod ${KFAB_DIR}/tests/cxi/single_client/test_auth_key.ko &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Removing CXI authorization keys" "
	rmmod test_auth_key &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

cxi_test_finish

dmesg > ../output/$(basename "$0").dmesg.txt

test_done
