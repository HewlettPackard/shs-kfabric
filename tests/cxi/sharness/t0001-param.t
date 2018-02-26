#!/bin/bash

# Test loading CXI provider with parameters

test_description="Loading of CXI provider with parameters"

. ./sharness.sh

. ../cxi_test_setup.sh

cxi_test_setup

test_expect_success "Removing CXI provider" "
	rmmod kfi_cxi
"

test_expect_success "Confirming CXI provider removed" "
	[ $(lsmod | awk '{ print $1 }' | grep -c 'kfi_cxi') -eq 0 ]
"

test_expect_success "Inserting CXI provider with invalid params" "
	test_must_fail insmod ${KFAB_DIR}/prov/cxi/kfi_cxi.ko skip_device_ready_checks=1 rnr_timeout=1000000000 address_contexts=9 completion_queues=257 transmit_contexts=129 receive_contexts=129 message_buffers=65537
"

test_expect_success "Confirming CXI provider invalid params" "
	[ $(dmesg | grep -c 'Param Error') -eq 5 ]
"

test_expect_success "Inserting CXI provider with valid params" "
	insmod ${KFAB_DIR}/prov/cxi/kfi_cxi.ko skip_device_ready_checks=1 rnr_timeout=1000000000 address_contexts=4 completion_queues=128 transmit_contexts=64 receive_contexts=64 message_buffers=32768
"

test_expect_success "Confirming CXI provider installed" "
	[ $(lsmod | awk '{ print $1 }' | grep -c 'kfi_cxi') -eq 1 ]
"

test_expect_success "Removing CXI provider" "
	rmmod kfi_cxi
"

test_expect_success "Inserting CXI provider with max valid params" "
	insmod ${KFAB_DIR}/prov/cxi/kfi_cxi.ko skip_device_ready_checks=1 rnr_timeout=1000000000 address_contexts=4 completion_queues=256 transmit_contexts=128 receive_contexts=128 message_buffers=65536
"

test_expect_success "Confirming CXI provider installed" "
	[ $(lsmod | awk '{ print $1 }' | grep -c 'kfi_cxi') -eq 1 ]
"

cxi_test_finish

dmesg > ../output/$(basename "$0").dmesg.txt

test_done
