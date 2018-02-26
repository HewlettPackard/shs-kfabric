#!/bin/bash
git checkout -b rebase-test-branch

# Build only first as it's fast
git rebase `git merge-base origin/integration HEAD` --exec 'set -e; git log -1 && make clean && make -j4'

# Then build and test
# We need a TTY, otherswise the tests will not finish. So ssh to self.
ssh -tt localhost "cd ~/workspace/workspace/os-networking-team/cassini-vm/PR-kfabric; PROVE='prove -j2' make cxi_check"
