ifeq ($(KERNELRELEASE),)

KVER	:= $(shell uname -r)
KDIR ?= /lib/modules/$(shell uname -r)/build
TARGETS := install clean
INSTALL_MOD_DIR := kfabric
DEPMOD	:= /usr/sbin/depmod
PWD := $(shell pwd)

PACKAGE=cray-kfabric
VERSION=0.1.0
DISTFILES = $(shell git ls-files 2>/dev/null || find . -type f)

real_man_pages=\
 Documentation/kfi/man3/kfi_atomic.3\
 Documentation/kfi/man3/kfi_av.3\
 Documentation/kfi/man3/kfi_cm.3\
 Documentation/kfi/man3/kfi_cntr.3\
 Documentation/kfi/man3/kfi_control.3\
 Documentation/kfi/man3/kfi_cq.3\
 Documentation/kfi/man3/kfi_domain.3\
 Documentation/kfi/man3/kfi_endpoint.3\
 Documentation/kfi/man3/kfi_eq.3\
 Documentation/kfi/man3/kfi_errno.3\
 Documentation/kfi/man3/kfi_fabric.3\
 Documentation/kfi/man3/kfi_getinfo.3\
 Documentation/kfi/man3/kfi_mr.3\
 Documentation/kfi/man3/kfi_msg.3\
 Documentation/kfi/man3/kfi_poll.3\
 Documentation/kfi/man3/kfi_rma.3\
 Documentation/kfi/man3/kfi_tagged.3\
 Documentation/kfi/man3/kfi_trigger.3\
 Documentation/kfi/man3/kfi_version.3\
\
 Documentation/kfi/man7/kfabric.7\
 Documentation/kfi/man7/kfi_direct.7\
\
$(__END_OF_LIST__)

.PHONY: build install clean dist rpm

all: build

build:
	$(MAKE) -C $(KDIR) M=$(PWD) KBUILD_EXTRA_SYMBOLS=$(PWD)/../cxi-driver/cxi/Module.symvers modules

install:
	$(MAKE) INSTALL_MOD_DIR=$(INSTALL_MOD_DIR) -C $(KDIR) M=$(PWD) modules_install

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

cxi_check:
	cd ./tests/cxi/sharness; ./run_test_vm.sh

dist: $(DISTFILES)
	tar czf $(PACKAGE)-$(VERSION).tar.gz --transform 's/^/$(PACKAGE)-$(VERSION)\//' $(DISTFILES)

$(PACKAGE)-$(VERSION).tar.gz: dist

rpm: $(PACKAGE)-$(VERSION).tar.gz
	BUILD_METADATA=0 rpmbuild -ta $<

$(real_man_pages): nroff

nroff:
	@for file in $(real_man_pages) ; \
	do \
	    source=`echo $$file | sed -e 's@/man[0-9]@@'`; \
	    perl config/md2nroff.pl --source=$$source.md; \
	done

else

.NOTPARALLEL: tests/cxi/single_client/ tests/cxi/multi_client/

obj-y += kfi/
obj-y += prov/cxi/
#obj-y += prov/ibverbs/
#obj-y += tests/ibverbs/simple/
obj-y += tests/cxi/single_client/
obj-y += tests/cxi/multi_client/

endif
