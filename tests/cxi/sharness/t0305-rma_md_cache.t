#!/bin/bash

# Test tagged rma

test_description="CXI rma md cache"

. ./sharness.sh

. ../cxi_test_setup.sh

cxi_test_setup

test_expect_success "Removing CXI provider to reload with md cache enabled" "
	rmmod kfi_cxi
"

test_expect_success "Confirming CXI provider removed" "
        [ $(lsmod | awk '{ print $1 }' | grep -c 'kfi_cxi') -eq 0 ]
"

test_expect_success "Inserting CXI provider with md cache enabled" "
	insmod ${KFAB_DIR}/prov/cxi/kfi_cxi.ko skip_device_ready_checks=1 rnr_timeout=1000000000 md_cache_enable=1 &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

echo -n 'module cxi_ss1 -p' > /sys/kernel/debug/dynamic_debug/control
echo -n 'module kfi_cxi +p' > /sys/kernel/debug/dynamic_debug/control

test_expect_success "Test CXI rma md cache" "
	insmod ${KFAB_DIR}/tests/cxi/single_client/test_rma_md_cache.ko &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Removing CXI rma md cache" "
	rmmod test_rma_md_cache &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

cxi_test_finish

dmesg > ../output/$(basename "$0").dmesg.txt

test_done
