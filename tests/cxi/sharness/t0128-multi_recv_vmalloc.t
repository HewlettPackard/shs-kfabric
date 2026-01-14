#!/bin/bash

# Test untagged/tagged multi-receive vmalloc buffers

test_description="CXI untagged/tagged multi-receive vmalloc buffers"

. ./sharness.sh

. ../cxi_test_setup.sh

cxi_test_setup

test_expect_success "Test CXI untagged multi-receive vmalloc buffers" "
	insmod ${KFAB_DIR}/tests/cxi/single_client/test_multi_recv.ko kmalloc_buf=0 mode_tagged=0 &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Removing CXI untagged mutil-receive vmalloc buffers" "
	rmmod test_multi_recv &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Test CXI tagged multi-receive vmalloc buffers" "
	insmod ${KFAB_DIR}/tests/cxi/single_client/test_multi_recv.ko kmalloc_buf=0 mode_tagged=1 &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Removing CXI tagged mutil-receive vmalloc buffers" "
	rmmod test_multi_recv &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

cxi_test_finish

dmesg > ../output/$(basename "$0").dmesg.txt

test_done
