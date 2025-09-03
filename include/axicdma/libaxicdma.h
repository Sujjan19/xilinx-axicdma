/* SPDX-License-Identifier: GPL-2.0 */
/*
 * libaxicdma.h - User-space API for Xilinx AXI CDMA
 *
 * Author: Sujan
 * Date:   10-Jun-2025
 *
 * Description:
 * This header declares the public user-space API for the libaxicdma
 * helper library. The library wraps interactions with the kernel
 * character device driver (driver/axi_cdma.c) and provides simple
 * functions for allocating mmap'd DMA buffers, registering external
 * dma-buf-backed buffers, and issuing DMA transfers between PS DDR
 * and PL BRAM.
 *
 */
#ifndef AXICDMA_H
#define AXICDMA_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief DMA transfer direction
 */
typedef enum {
    AXICDMA_PS_TO_PL = 0, /**< Transfer from ARM PS DDR to PL BRAM */
    AXICDMA_PL_TO_PS = 1  /**< Transfer from PL BRAM to ARM PS DDR */
} axicdma_dir_t;

/**
 * @brief AXICDMA device handle
 */
typedef struct axicdma_handle* axicdma_handle_t;

/**
 * @brief Initialize and open the AXI CDMA device
 *
 * @param device_path Path to device (e.g., "/dev/axicdma0", "/dev/axicdma1")
 * @return Device handle on success, NULL on failure
 */
axicdma_handle_t axicdma_init(const char* device_path);

/**
 * @brief Close the AXI CDMA device
 *
 * @param handle Device handle
 */
void axicdma_close(axicdma_handle_t handle);

/**
 * @brief Allocate a DMA buffer
 *
 * Allocates a buffer suitable for DMA transfers.
 *
 * @param handle Device handle
 * @param size Size of the buffer in bytes
 * @return Direct pointer to allocated buffer on success, NULL on failure
 */
void* axicdma_malloc(axicdma_handle_t handle, size_t size);

/**
 * @brief Free a DMA buffer
 *
 * Frees a buffer previously allocated with axicdma_malloc.
 *
 * @param handle Device handle
 * @param buffer Pointer to buffer returned by axicdma_malloc
 */
void axicdma_free(axicdma_handle_t handle, void* buffer);

/**
 * @brief Register an external DMA buffer (from another driver)
 *
 * @param handle Device handle
 * @param fd File descriptor of the DMA buffer
 * @param user_addr User-space address of the buffer
 * @param size Size of the buffer in bytes
 * @return 0 on success, negative error code on failure
 */
int axicdma_register_buffer(axicdma_handle_t handle, int fd, 
                            void* user_addr, size_t size);

/**
 * @brief Unregister an external DMA buffer
 *
 * @param handle Device handle
 * @param user_addr User-space address of the buffer
 * @return 0 on success, negative error code on failure
 */
int axicdma_unregister_buffer(axicdma_handle_t handle, void* user_addr);

/**
 * @brief Perform a DMA transfer between PS DDR and PL BRAM
 *
 * @param handle Device handle
 * @param buffer Pointer to buffer (from axicdma_malloc or registered buffer)
 * @param bram_offset Offset within the BRAM in bytes
 * @param length Number of bytes to transfer
 * @param dir Transfer direction
 * @return 0 on success, negative error code on failure
 */
int axicdma_transfer(axicdma_handle_t handle, void* buffer, 
                     size_t bram_offset, 
                     size_t length, axicdma_dir_t dir);

/**
 * @brief Get a string description for an error code
 *
 * @param error Error code
 * @return String description of the error
 */
const char* axicdma_strerror(int error);

#ifdef __cplusplus
}
#endif

#endif /* AXICDMA_H */