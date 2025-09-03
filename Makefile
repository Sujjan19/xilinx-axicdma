# SPDX-License-Identifier: GPL-2.0
#
# Build dynamic library for axicdma
#

# Cross-compilation variables (override on make command line)
# Example: make lib CROSS_COMPILE=aarch64-linux-gnu- ARCH=arm64
CROSS_COMPILE ?=
ARCH ?=

# Kernel build directory for out-of-tree module builds. Default to current kernel's build dir.
KERNEL_DIR ?= /lib/modules/$(shell uname -r)/build

# Toolchain
CC = $(CROSS_COMPILE)gcc
AR = $(CROSS_COMPILE)ar

# Directories for userspace library
SRC_DIR = src
INC_DIR = include
BUILD_DIR = build
LIB_DIR = lib

# Source and object files
SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)

# Library name
LIB_NAME = libaxicdma
SHARED_LIB = $(LIB_DIR)/$(LIB_NAME).so

# Compiler flags
CFLAGS = -fPIC -Wall -Wextra -I$(INC_DIR)
LDFLAGS = -shared

# Default target builds the userspace library
all: lib

.PHONY: all lib driver clean dirs

dirs:
	@mkdir -p $(BUILD_DIR)
	@mkdir -p $(LIB_DIR)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(SHARED_LIB): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

# Build userspace library
lib: dirs $(SHARED_LIB)



# Build kernel driver (out-of-tree module). Uses KERNEL_DIR, ARCH and CROSS_COMPILE if provided.
# Example: make driver KERNEL_DIR=/path/to/kernel CROSS_COMPILE=aarch64-linux-gnu- ARCH=arm64
driver:
	@echo "Building kernel module in $(KERNEL_DIR) (ARCH=$(ARCH), CROSS_COMPILE=$(CROSS_COMPILE))"
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD)/driver ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) modules

# Clean both userspace and driver build output
clean:
	rm -rf $(BUILD_DIR) $(LIB_DIR)
	-$(MAKE) -C $(KERNEL_DIR) M=$(PWD)/driver clean || true
