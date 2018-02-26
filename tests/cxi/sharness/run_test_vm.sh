#!/bin/bash

. ./preamble.sh

export TOP_DIR=$(realpath ../../../../)
export KFAB_DIR=$(realpath ../../../)

make prove

exit_code=$?
echo "$exit_code" > exit_code_file
exit $exit_code
