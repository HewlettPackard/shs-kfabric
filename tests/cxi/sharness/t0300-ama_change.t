#!/bin/bash

# Test CXI getinfo

test_description="Change AMA and verify kfi_getinfo() functions"

. ./sharness.sh

. ../cxi_test_setup.sh

IPV4_ADDR="192.168.1.128"
AMA_MAC="02:0E:AB:00:55:00"
NON_AMA_MAC="00:0E:AB:01:23:00"
DEV="cxi0"
cxi_test_setup

test_expect_success "Change IPv4 Address to $IPV4_ADDR" "
	ip addr add dev $CXI_ETH_INTERFACE $IPV4_ADDR &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Verify kfi_getinfo success with $IPV4_ADDR and pre-configured AMA MAC" "
	insmod ${KFAB_DIR}/tests/cxi/single_client/test_run_getinfo.ko node=$IPV4_ADDR expected_rc=0 &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Removing kfi_getinfo test module" "
	rmmod test_run_getinfo &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Verify kfi_getinfo success with $DEV and pre-configured AMA MAC" "
	insmod ${KFAB_DIR}/tests/cxi/single_client/test_run_getinfo.ko node=$DEV expected_rc=0 &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Removing kfi_getinfo test module" "
	rmmod test_run_getinfo &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Change MAC address to AMA $AMA_MAC" "
	ip link set dev $CXI_ETH_INTERFACE down &&
	ip link set $CXI_ETH_INTERFACE address $AMA_MAC &&
	ip link set dev $CXI_ETH_INTERFACE up &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Verify kfi_getinfo success with $IPV4_ADDR and $AMA_MAC" "
	insmod ${KFAB_DIR}/tests/cxi/single_client/test_run_getinfo.ko node=$IPV4_ADDR expected_rc=0 &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Removing kfi_getinfo test module" "
	rmmod test_run_getinfo &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Verify kfi_getinfo success with $DEV and $AMA_MAC" "
	insmod ${KFAB_DIR}/tests/cxi/single_client/test_run_getinfo.ko node=$DEV expected_rc=0 &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Removing kfi_getinfo test module" "
	rmmod test_run_getinfo &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"
test_expect_success "Change MAC address to non-AMA $NON_AMA_MAC" "
	ip link set dev $CXI_ETH_INTERFACE down &&
	ip link set $CXI_ETH_INTERFACE address $NON_AMA_MAC &&
	ip link set dev $CXI_ETH_INTERFACE up &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Verify kfi_getinfo -ENODEV failure with $IPV4_ADDR and $NON_AMA_MAC" "
	insmod ${KFAB_DIR}/tests/cxi/single_client/test_run_getinfo.ko node=$IPV4_ADDR expected_rc=-61 &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Removing kfi_getinfo test module" "
	rmmod test_run_getinfo &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Verify kfi_getinfo -ENODEV failure with $DEV and $NON_AMA_MAC" "
	insmod ${KFAB_DIR}/tests/cxi/single_client/test_run_getinfo.ko node=$DEV expected_rc=-61 &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

test_expect_success "Removing kfi_getinfo test module" "
	rmmod test_run_getinfo &&
	[ $(dmesg | grep -c 'Modules linked in') -eq 0 ]
"

cxi_test_finish

dmesg > ../output/$(basename "$0").dmesg.txt

test_done
