# xilinx-axicdma

Xilinx AXI CDMA character-device driver and a small user-space library that wraps the driver to provide simple, convenient APIs for moving data between PS DDR and PL BRAM on Xilinx Zynq/ZynqMP systems.

This repository contains two primary components:

- Kernel character device driver: `driver/axi_cdma.c` — exposes `/dev/axicdma<N>` device nodes and supports mmap-based DMA buffer allocation, ioctl-based transfers, and registering external dma-buf buffers.
- User-space library: `src/libaxicdma.c` with header `include/axicdma/libaxicdma.h` — a thin wrapper that provides easy-to-use functions: `axicdma_init`, `axicdma_malloc`, `axicdma_transfer`, `axicdma_register_buffer`, and `axicdma_close`.

License: GPL-2.0

## Repository layout

- `driver/` — kernel driver source (character device). Add this to your kernel build tree or compile as an out-of-tree module.
- `include/axicdma/` — public user-space header `libaxicdma.h` used to compile applications against the library.
- `src/` — user-space library implementation `libaxicdma.c`.
- `lib/`, `build/` — build output for the userspace library.
- `Makefile` — builds the userspace shared library (`lib/libaxicdma.so`).

## Device-tree bindings (expected)

The driver matches the compatible string `axicdma-chrdev`. The driver expects a device-tree property named `bram` that encodes the BRAM physical base and size as two 64-bit integers. Example snippet:

```
axicdma@... {
	compatible = "axicdma-chrdev";
	reg = <...>; /* device registers */
	bram = <0x00000000 0xNNNNNNNN  /* base (u64) */
			0x00000000 0xMMMMMMMM>; /* size (u64) */
	interrupts = <...>;
};
```

Adjust the exact formatting to your DT convention; the driver reads `bram[0]` as base and `bram[1]` as size.

## Building the user-space library

The repository includes a simple Makefile that builds a position-independent shared library for user-space usage.



Build userspace library (native build):

```bash
make          # builds lib/libaxicdma.so
```

Link your application against the library (example):

```bash
aarch64-linux-gnu-gcc -o myapp myapp.c -L./lib -laxicdma
```

Include the header in your code with:

```c
#include <axicdma/libaxicdma.h>
```

## Kernel driver: notes for building and installing

This repo contains the kernel driver source in `driver/axi_cdma.c`. It is not packaged as a full kernel module build system here. You can build it as an out-of-tree module against your kernel build directory or integrate into your kernel tree.



Driver (out-of-tree) build

This repo now includes a small `driver/Makefile` that acts as a Kbuild wrapper to build the module in-tree or out-of-tree. You can either use the top-level `make driver` target, or build directly inside the `driver/` directory.

Build from repository root (for current kernel build dir):

```bash
make driver
```

Build driver directly (recommended when you have a kernel source dir):

```bash
cd driver
make KSRC=/path/to/kernel/build
```

Cross-compile example (aarch64 target):

```bash
make driver KERNEL_DIR=/path/to/kernel/build CROSS_COMPILE=aarch64-linux-gnu- ARCH=arm64
```

The built module object appears under `driver/` as produced by the kernel build system (for example `driver/axi_cdma.ko` or similar). Install with:

Petalinux Driver Build example:

Create a petalinux app in your build
```bash
petalinux-create -t modules -n xilinx-axicdma --enable
```

Next, copy all of the C source files and header files under the driver directory to the driver source directory, and remove the auto-generated file there:

```bash
cp -a driver/*.c driver/*.h <path/to/PetaLinux/project>/project-spec/meta-user/recipes-modules/xilinx-axicdma/files
rm <path/to/PetaLinux/project>/project-spec/meta-user/recipes-modules/xilinx-axicdma/files/xilinx-axicdma.c
```

Then, replace the first line of the Makefile at <path/to/PetaLinux/project>/project-spec/meta-user/recipes-modules/xilinx-axidma/files/Makefile with the following:

```bash
DRIVER_NAME = xilinx-axicdma
$(DRIVER_NAME)-objs = axi_dma.o
obj-m := $(DRIVER_NAME).o
````

The module will be packaged with your rootfs image, and you can find the kernel object file under /lib/modules/$(shell uname -r)/extra/xilinx-axicdma.ko.

```bash
sudo insmod /lib/modules/$(shell uname -r)/extra/xilinx-axicdma.ko
```

On success the driver creates device nodes named `/dev/axicdma0`, `/dev/axicdma1`, ...

## User-space usage overview

The user-space library wraps the ioctl and mmap interactions. Typical flow:

1. Initialize the device handle:

```c
axicdma_handle_t h = axicdma_init("/dev/axicdma0");
```

2. Allocate or map a DMA-capable buffer:

```c
void *buf = axicdma_malloc(h, size); // returns userspace pointer (mmap)
```

3. Perform a transfer:

```c
axicdma_transfer(h, buf, bram_offset, length, AXICDMA_PS_TO_PL); //AXICDMA_PS_TO_PL (MM2S) or AXICDMA_PL_TO_PS (for S2MM)
```

4. Free and close:

```c
axicdma_free(h, buf);
axicdma_close(h);
```

## IOCTLs and behaviour

- `AXICDMA_IOCTL_TRANSFER` — start a transfer described by `struct axicdma_transfer` (userspace pointer, length, bram_offset, direction).
- `AXICDMA_IOCTL_REGISTER_BUF` — register an external dma-buf by passing `struct axicdma_register_buffer` with the FD, userspace address, and size.
- `AXICDMA_IOCTL_UNREGISTER_BUF` — unregister previously registered buffer by passing the userspace address.

The kernel driver programs the CDMA registers and waits for an interrupt (IOC or ERR). Transfers time out after a configurable timeout (default 5000 ms in the driver).

## Limitations and notes

- The current driver and userspace library are intended as a minimal example and convenience wrapper. It assumes the caller that issues ioctls has access to the mmap'd region (same process that called `axicdma_malloc`).
- External dma-buf registration currently requires a single contiguous physical region (single sg entry).
- Building the kernel module requires a working kernel build environment; the repo does not include a full `Kbuild` file for automatic building in all environments.

## Contributing and contact

If you find bugs or want to propose improvements, please open an issue or submit a pull request.

Author: Sujan

