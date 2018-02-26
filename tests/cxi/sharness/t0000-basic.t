#!/bin/bash

# Test loading CXI provider

test_description="Loading of CXI provider"

. ./sharness.sh

. ../cxi_test_setup.sh

cxi_test_setup

cxi_test_finish

dmesg > ../output/$(basename "$0").dmesg.txt

test_done
