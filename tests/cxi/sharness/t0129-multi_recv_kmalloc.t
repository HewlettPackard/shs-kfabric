#!/bin/bash

# Test multi-receive kmalloc buffers

test_description="CXI multi-receive kmalloc buffers"

. ./sharness.sh

. ../cxi_test_setup.sh

cxi_test_setup

test_expect_success "Test CXI multi-receive kmalloc buffers" "
	insmod ${KFAB_DIR}/tests/cxi/single_client/test_multi_recv.ko kmalloc_buf=1 &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Removing CXI mutil-receive kmalloc buffers" "
	rmmod test_multi_recv &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

cxi_test_finish

dmesg > ../output/$(basename "$0").dmesg.txt

test_done
