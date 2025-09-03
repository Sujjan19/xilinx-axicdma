# SPDX-License-Identifier: GPL-2.0
# Simple Kbuild wrapper to build the axi_cdma kernel module out-of-tree
#
# Author: Sujan
# Date:   10-Jun-2025

obj-m := axi_cdma.o

KSRC ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	@echo "Building axi_cdma module against $(KSRC)"
	$(MAKE) -C $(KSRC) M=$(PWD) modules

clean:
	$(MAKE) -C $(KSRC) M=$(PWD) clean

.PHONY: all clean
