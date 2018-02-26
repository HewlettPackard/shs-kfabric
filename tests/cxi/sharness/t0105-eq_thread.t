#!/bin/bash

# Test CXI EQ with threads

test_description="CXI EQ Thread Tests"

. ./sharness.sh

. ../cxi_test_setup.sh


cxi_test_setup

test_expect_success "Test CXI EQ Thread" "
	insmod ${KFAB_DIR}/tests/cxi/single_client/test_eq_thread.ko &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

sleep 5

test_expect_success "Remove CXI EQ Thread" "
	rmmod test_eq_thread
"

test_expect_success "Check DMESG" "
	[ $(dmesg | grep -c 'All entries consumed') -eq 1 ]
"

cxi_test_finish

dmesg > ../output/$(basename "$0").dmesg.txt

test_done
