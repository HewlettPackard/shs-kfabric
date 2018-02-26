#!/bin/bash
make clean
make -j4
# We need a TTY, otherswise the tests will not finish. So ssh to self.
ssh -tt localhost "cd ~/workspace/workspace/os-networking-team/cassini-vm/kfabric; PROVE='prove -j2' make cxi_check"
