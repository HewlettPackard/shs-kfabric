TOPDIR := $(src)/../../..
TEST_COMMON_DIR := $(TOPDIR)/tests/cxi/common
TEST_COMMON_LIB := ../common/test_common.o

obj-m := multi-nic-msg.o

multi-nic-msg-objs := multi_nic_msg.o $(TEST_COMMON_LIB)

ccflags-y += -I$(TOPDIR)/include -I$(TOPDIR)/../cxi-driver/include \
	-I$(TOPDIR)/../cassini-headers/install/include \
	-I$(TEST_COMMON_DIR)
