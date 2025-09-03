/* SPDX-License-Identifier: GPL-2.0 */
/*
 * axi_cdma.h - Driver public definitions for Xilinx AXI CDMA
 *
 * Author: Sujan
 * Date:   10-Jun-2025
 */

#ifndef __AXI_CDMA_H
#define __AXI_CDMA_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define DRIVER_NAME "xilinx_axicdma"
#define AXICDMA_DEV_NAME "axicdma"
#define AXICDMA_IOCTL_MAGIC 'x'

#define AXICDMA_IOCTL_TRANSFER       _IOW(AXICDMA_IOCTL_MAGIC, 1, struct axicdma_transfer)
#define AXICDMA_IOCTL_REGISTER_BUF   _IOW(AXICDMA_IOCTL_MAGIC, 2, struct axicdma_register_buffer)
#define AXICDMA_IOCTL_UNREGISTER_BUF _IOW(AXICDMA_IOCTL_MAGIC, 3, unsigned long)

#define AXICDMA_REG_CONTROL    0x00
#define AXICDMA_REG_STATUS     0x04
#define AXICDMA_REG_SRC_ADDR   0x18
#define AXICDMA_REG_DST_ADDR   0x20
#define AXICDMA_REG_BTT        0x28

#define AXICDMA_STATUS_IOC_IRQ 0x00001000
#define AXICDMA_STATUS_ERR_IRQ 0x00004000

#define XAXICDMA_XR_IRQ_SIMPLE_ALL_MASK  0x00005000

#define AXICDMA_TIMEOUT_MS     5000

enum axicdma_dir {
    AXICDMA_PS_TO_PL = 0,
    AXICDMA_PL_TO_PS = 1,
};

struct axicdma_transfer {
    void __user *ps_buffer;  /* userspace pointer to DDR buffer (with offset) */
    size_t length;
    size_t bram_offset;
    enum axicdma_dir dir;
};

struct axicdma_register_buffer {
    int fd;                  /* File descriptor of DMA buffer to share */
    void __user *user_addr;  /* Userspace address of the buffer */
    size_t size;             /* Size of the buffer */
};

#endif /* __AXI_CDMA_H */
