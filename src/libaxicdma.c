/* SPDX-License-Identifier: GPL-2.0 */
/*
 * libaxicdma.c - User-space helper library for Xilinx AXI CDMA
 *
 * Author: Sujan
 * Date:   10-Jun-2025
 *
 * This file implements the user-space wrapper around the kernel
 * character device driver. It provides simple functions for mapping
 * DMA buffers and issuing transfers.
 */

#include "../include/axicdma/libaxicdma.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <errno.h>

#define AXICDMA_IOCTL_MAGIC 'x'

// IOCTL commands (must match kernel driver)
#define AXICDMA_IOCTL_TRANSFER       _IOW(AXICDMA_IOCTL_MAGIC, 1, struct axicdma_transfer)
#define AXICDMA_IOCTL_REGISTER_BUF   _IOW(AXICDMA_IOCTL_MAGIC, 2, struct axicdma_register_buffer)
#define AXICDMA_IOCTL_UNREGISTER_BUF _IOW(AXICDMA_IOCTL_MAGIC, 3, unsigned long)

// Structures (must match kernel driver)
// Note: Using the enum from the header file instead of redefining it
struct axicdma_transfer {
    void *ps_buffer;
    size_t length;
    size_t bram_offset;
    axicdma_dir_t dir;  // Use the typedef from header
};

struct axicdma_register_buffer {
    int fd;
    void *user_addr;
    size_t size;
};

// Internal handle structure
struct axicdma_handle {
    int fd;
    char device_path[256];
};

// Error code to string mapping
static const char* error_strings[] = {
    [0] = "Success",
    [EPERM] = "Operation not permitted",
    [ENOENT] = "No such file or directory",
    [ESRCH] = "No such process",
    [EINTR] = "Interrupted system call",
    [EIO] = "I/O error",
    [ENXIO] = "No such device or address",
    [E2BIG] = "Argument list too long",
    [ENOEXEC] = "Exec format error",
    [EBADF] = "Bad file number",
    [ECHILD] = "No child processes",
    [EAGAIN] = "Try again",
    [ENOMEM] = "Out of memory",
    [EACCES] = "Permission denied",
    [EFAULT] = "Bad address",
    [ENOTBLK] = "Block device required",
    [EBUSY] = "Device or resource busy",
    [EEXIST] = "File exists",
    [EXDEV] = "Cross-device link",
    [ENODEV] = "No such device",
    [ENOTDIR] = "Not a directory",
    [EISDIR] = "Is a directory",
    [EINVAL] = "Invalid argument",
    [ENFILE] = "File table overflow",
    [EMFILE] = "Too many open files",
    [ENOTTY] = "Not a typewriter",
    [ETXTBSY] = "Text file busy",
    [EFBIG] = "File too large",
    [ENOSPC] = "No space left on device",
    [ESPIPE] = "Illegal seek",
    [EROFS] = "Read-only file system",
    [EMLINK] = "Too many links",
    [EPIPE] = "Broken pipe",
    [EDOM] = "Math argument out of domain of func",
    [ERANGE] = "Math result not representable",
    [ETIMEDOUT] = "Connection timed out",
};

axicdma_handle_t axicdma_init(const char* device_path)
{
    struct axicdma_handle *handle;
    
    if (!device_path) {
        errno = EINVAL;
        return NULL;
    }
    
    // Allocate handle structure
    handle = malloc(sizeof(struct axicdma_handle));
    if (!handle) {
        errno = ENOMEM;
        return NULL;
    }
    
    // Open device
    handle->fd = open(device_path, O_RDWR);
    if (handle->fd < 0) {
        free(handle);
        return NULL;
    }
    
    // Store device path
    strncpy(handle->device_path, device_path, sizeof(handle->device_path) - 1);
    handle->device_path[sizeof(handle->device_path) - 1] = '\0';
    
    return handle;
}

void axicdma_close(axicdma_handle_t handle)
{
    if (!handle) {
        return;
    }
    
    if (handle->fd >= 0) {
        close(handle->fd);
    }
    
    free(handle);
}

void* axicdma_malloc(axicdma_handle_t handle, size_t size)
{
    void *buffer;
    
    if (!handle || size == 0) {
        errno = EINVAL;
        return NULL;
    }
    
    // Use mmap to allocate DMA buffer through the driver
    buffer = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, handle->fd, 0);
    if (buffer == MAP_FAILED) {
        return NULL;
    }
    
    return buffer;
}

void axicdma_free(axicdma_handle_t handle, void* buffer)
{
    if (!handle || !buffer) {
        return;
    }
    
    // The kernel driver's VMA close operation will handle the cleanup
    // We just need to unmap the memory from userspace
    // Note: We don't know the size here, but munmap will handle partial unmapping
    // In practice, the application should track buffer sizes if needed
    
    // Since we don't have the size, we'll rely on the VMA operations
    // to clean up properly when the mapping is destroyed
    munmap(buffer, 0); // Size 0 should unmap the entire VMA
}

int axicdma_register_buffer(axicdma_handle_t handle, int fd, 
                            void* user_addr, size_t size)
{
    struct axicdma_register_buffer reg_buf;
    
    if (!handle || fd < 0 || !user_addr || size == 0) {
        errno = EINVAL;
        return -EINVAL;
    }
    
    reg_buf.fd = fd;
    reg_buf.user_addr = user_addr;
    reg_buf.size = size;
    
    if (ioctl(handle->fd, AXICDMA_IOCTL_REGISTER_BUF, &reg_buf) < 0) {
        return -errno;
    }
    
    return 0;
}

int axicdma_unregister_buffer(axicdma_handle_t handle, void* user_addr)
{
    if (!handle || !user_addr) {
        errno = EINVAL;
        return -EINVAL;
    }
    
    if (ioctl(handle->fd, AXICDMA_IOCTL_UNREGISTER_BUF, 
              (unsigned long)user_addr) < 0) {
        return -errno;
    }
    
    return 0;
}

int axicdma_transfer(axicdma_handle_t handle, void* buffer, 
                     size_t bram_offset, size_t length, axicdma_dir_t dir)
{
    struct axicdma_transfer xfer;
    
    if (!handle || !buffer || length == 0) {
        errno = EINVAL;
        return -EINVAL;
    }
    
    if (dir != AXICDMA_PS_TO_PL && dir != AXICDMA_PL_TO_PS) {
        errno = EINVAL;
        return -EINVAL;
    }
    
    xfer.ps_buffer = buffer;
    xfer.length = length;
    xfer.bram_offset = bram_offset;
    xfer.dir = dir;  // No cast needed now
    
    if (ioctl(handle->fd, AXICDMA_IOCTL_TRANSFER, &xfer) < 0) {
        return -errno;
    }
    
    return 0;
}

const char* axicdma_strerror(int error)
{
    unsigned int abs_error = abs(error);
    
    if (abs_error < sizeof(error_strings) / sizeof(error_strings[0]) && 
        error_strings[abs_error]) {
        return error_strings[abs_error];
    }
    
    return "Unknown error";
}
