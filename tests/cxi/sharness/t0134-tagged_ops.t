#!/bin/bash

test_description="Testing tagged send/recv"

. ./sharness.sh

. ../cxi_test_setup.sh

cxi_test_setup

test_expect_success "Test tagged send/recv" "
	insmod ${KFAB_DIR}/tests/cxi/single_client/test_tagged_ops.ko &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Removing tagged send/recv" "
	rmmod test_tagged_ops &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

cxi_test_finish

dmesg > ../output/$(basename "$0").dmesg.txt

test_done
