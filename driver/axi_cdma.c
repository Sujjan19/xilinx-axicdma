// SPDX-License-Identifier: GPL-2.0
/*
 * Xilinx AXI CDMA Character Device Driver
 *
 * Author: Sujan
 * Date:   10-Jun-2025
 *
 * Supports DMA transfers between PS DDR (userspace buffers) and PL BRAM.
 */

#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_dma.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/dma-mapping.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/io.h>
#include <linux/delay.h>
#include <linux/mm.h>
#include <linux/device.h>
#include <linux/ioctl.h>
#include <linux/completion.h>
#include <linux/list.h>
#include <linux/interrupt.h>
#include <linux/time.h>
#include <linux/types.h>
#include <linux/dma-buf.h>
#include <linux/scatterlist.h>
#include <linux/of_device.h>
#include "axi_cdma.h"

static int axicdma_major = 0;
static struct class *axicdma_class = NULL;
static int device_count = 0;
static DEFINE_MUTEX(device_count_mutex);

/* A structure that represents our internally allocated DMA buffer */
struct axicdma_dma_allocation
{
    size_t size;              // Size of the buffer
    void *user_virt;          // User virtual address of the buffer
    dma_addr_t phys;          // DMA bus address of the buffer
    struct list_head list;    // List node for allocation list
    struct axicdma_dev *cdma; // Pointer back to the device
};

/* A structure for external DMA buffer allocations (from other drivers) */
struct axicdma_external_allocation
{
    int fd;                                // File descriptor for buffer share
    struct dma_buf *dma_buf;               // DMA buffer structure
    struct dma_buf_attachment *dma_attach; // DMA buffer attachment
    size_t size;                           // Total size of the buffer
    void *user_virt;                       // Buffer's userspace address
    struct sg_table *sg_table;             // DMA scatter-gather table
    struct list_head list;                 // Node for list tracking
    struct axicdma_dev *cdma;              // Pointer back to the device
};

struct axicdma_dev
{
    struct device *dev;
    void __iomem *cdma_regs;
    dma_addr_t bram_phys;
    size_t bram_size;
    struct cdev cdev;
    dev_t devt;
    int device_id; // Add this field
    struct mutex lock;
    int irq;
    struct completion dma_done;
    int dma_status;
    struct list_head dma_allocations;      // Internal DMA allocations
    struct list_head external_allocations; // External DMA allocations
};

static int axicdma_open(struct inode *inode, struct file *file)
{
    struct axicdma_dev *cdma = container_of(inode->i_cdev, struct axicdma_dev, cdev);
    file->private_data = cdma;
    return 0;
}

static int axicdma_release(struct inode *inode, struct file *file)
{
    return 0;
}

/* Helper function to check if a DMA request is valid within the buffer range */
static bool valid_dma_request(void *dma_start, size_t dma_size,
                              void __user *user_addr, size_t user_size)
{
    return dma_start <= user_addr &&
           (char __user *)user_addr + user_size <= (char *)dma_start + dma_size;
}

/* Converts userspace virtual address to DMA physical address */
static int axicdma_get_phys_addr(struct axicdma_dev *cdma, void __user *user_ptr,
                                 size_t length, dma_addr_t *phys)
{
    dma_addr_t offset;
    struct list_head *iter;
    struct axicdma_dma_allocation *dma_alloc;
    struct axicdma_external_allocation *ext_alloc;

    // First check internal DMA allocations
    list_for_each(iter, &cdma->dma_allocations)
    {
        dma_alloc = list_entry(iter, struct axicdma_dma_allocation, list);
        if (valid_dma_request(dma_alloc->user_virt, dma_alloc->size, user_ptr, length))
        {
            offset = (dma_addr_t)((uintptr_t)user_ptr - (uintptr_t)dma_alloc->user_virt);
            *phys = dma_alloc->phys + offset;
            return 0;
        }
    }

    // Then check external DMA allocations
    list_for_each(iter, &cdma->external_allocations)
    {
        ext_alloc = list_entry(iter, struct axicdma_external_allocation, list);
        if (valid_dma_request(ext_alloc->user_virt, ext_alloc->size, user_ptr, length))
        {
            offset = (dma_addr_t)((uintptr_t)user_ptr - (uintptr_t)ext_alloc->user_virt);
            *phys = sg_dma_address(&ext_alloc->sg_table->sgl[0]) + offset;
            return 0;
        }
    }

    dev_err(cdma->dev, "No matching DMA buffer found for user address %p\n", user_ptr);
    return -EINVAL;
}

/* Registers an external DMA buffer (from another driver) */
static int axicdma_register_buffer(struct axicdma_dev *cdma,
                                   struct axicdma_register_buffer *ext_buf)
{
    int rc;
    struct axicdma_external_allocation *ext_alloc;

    // Allocate tracking structure
    ext_alloc = kmalloc(sizeof(*ext_alloc), GFP_KERNEL);
    if (!ext_alloc)
    {
        dev_err(cdma->dev, "Unable to allocate external DMA allocation structure\n");
        return -ENOMEM;
    }

    // Get the DMA buffer corresponding to the file descriptor
    ext_alloc->fd = ext_buf->fd;
    ext_alloc->dma_buf = dma_buf_get(ext_buf->fd);
    if (IS_ERR(ext_alloc->dma_buf))
    {
        dev_err(cdma->dev, "Unable to find the external DMA buffer\n");
        rc = PTR_ERR(ext_alloc->dma_buf);
        goto free_ext_alloc;
    }

    // Attach to the DMA buffer
    ext_alloc->dma_attach = dma_buf_attach(ext_alloc->dma_buf, cdma->dev);
    if (IS_ERR(ext_alloc->dma_attach))
    {
        dev_err(cdma->dev, "Unable to attach to the external DMA buffer\n");
        rc = PTR_ERR(ext_alloc->dma_attach);
        goto put_ext_dma;
    }

    // Map the DMA buffer
    ext_alloc->sg_table = dma_buf_map_attachment(ext_alloc->dma_attach,
                                                 DMA_BIDIRECTIONAL);
    if (IS_ERR(ext_alloc->sg_table))
    {
        dev_err(cdma->dev, "Unable to map external DMA buffer for usage\n");
        rc = PTR_ERR(ext_alloc->sg_table);
        goto detach_ext_dma;
    }

    // Require contiguous memory region
    if (ext_alloc->sg_table->nents != 1)
    {
        dev_err(cdma->dev, "External DMA allocations must be a single contiguous "
                           "region of physical memory\n");
        rc = -EINVAL;
        goto unmap_ext_dma;
    }

    // Initialize and add to list
    ext_alloc->size = ext_buf->size;
    ext_alloc->user_virt = ext_buf->user_addr;
    ext_alloc->cdma = cdma;
    list_add(&ext_alloc->list, &cdma->external_allocations);

    dev_info(cdma->dev, "Registered external DMA buffer: user=%p, size=%zu\n",
             ext_alloc->user_virt, ext_alloc->size);
    return 0;

unmap_ext_dma:
    dma_buf_unmap_attachment(ext_alloc->dma_attach, ext_alloc->sg_table,
                             DMA_BIDIRECTIONAL);
detach_ext_dma:
    dma_buf_detach(ext_alloc->dma_buf, ext_alloc->dma_attach);
put_ext_dma:
    dma_buf_put(ext_alloc->dma_buf);
free_ext_alloc:
    kfree(ext_alloc);
    return rc;
}

/* Unregisters an external DMA buffer */
static int axicdma_unregister_buffer(struct axicdma_dev *cdma, void __user *user_addr)
{
    void *end_user_addr;
    struct list_head *iter, *tmp;
    struct axicdma_external_allocation *ext_alloc;

    // Find the allocation matching the user address
    list_for_each_safe(iter, tmp, &cdma->external_allocations)
    {
        ext_alloc = list_entry(iter, struct axicdma_external_allocation, list);
        end_user_addr = (char *)ext_alloc->user_virt + ext_alloc->size;

        if (ext_alloc->user_virt <= user_addr && user_addr < end_user_addr)
        {
            // Unmap, detach, and release the buffer
            dma_buf_unmap_attachment(ext_alloc->dma_attach,
                                     ext_alloc->sg_table, DMA_BIDIRECTIONAL);
            dma_buf_detach(ext_alloc->dma_buf, ext_alloc->dma_attach);
            dma_buf_put(ext_alloc->dma_buf);

            // Remove from list and free the structure
            list_del(&ext_alloc->list);
            kfree(ext_alloc);

            dev_info(cdma->dev, "Unregistered external DMA buffer at user addr %p\n",
                     user_addr);
            return 0;
        }
    }

    dev_err(cdma->dev, "No matching external DMA buffer found for address %p\n",
            user_addr);
    return -ENOENT;
}

// Interrupt handler
static irqreturn_t axicdma_irq_handler(int irq, void *dev_id)
{
    struct axicdma_dev *cdma = dev_id;
    u32 status = readl(cdma->cdma_regs + AXICDMA_REG_STATUS);

    // Acknowledge interrupts
    writel(status, cdma->cdma_regs + AXICDMA_REG_STATUS);

    if (status & AXICDMA_STATUS_ERR_IRQ)
    {
        cdma->dma_status = -EIO;
        complete(&cdma->dma_done);
        return IRQ_HANDLED;
    }
    if (status & AXICDMA_STATUS_IOC_IRQ)
    {
        cdma->dma_status = 0;
        complete(&cdma->dma_done);
        return IRQ_HANDLED;
    }
    return IRQ_NONE;
}

// DMA transfer logic (interrupt-driven)
static int axicdma_do_transfer(struct axicdma_dev *cdma, struct axicdma_transfer *xfer)
{
    dma_addr_t ps_phys, bram_phys;
    int ret = 0;

    if (xfer->length == 0 || xfer->bram_offset + xfer->length > cdma->bram_size)
        return -EINVAL;

    ret = axicdma_get_phys_addr(cdma, xfer->ps_buffer, xfer->length, &ps_phys);
    if (ret)
        return ret;

    bram_phys = cdma->bram_phys + xfer->bram_offset;

    mutex_lock(&cdma->lock);

    reinit_completion(&cdma->dma_done);
    cdma->dma_status = -ETIMEDOUT;

    // Reset CDMA
    // writel(0x4, cdma->cdma_regs + AXICDMA_REG_CONTROL);

    // Enable all interrupts (IOC and ERR)
    // writel(XAXICDMA_XR_IRQ_SIMPLE_ALL_MASK, cdma->cdma_regs + AXICDMA_REG_CONTROL);

    // Set addresses
    if (xfer->dir == AXICDMA_PS_TO_PL)
    {
        writel(ps_phys, cdma->cdma_regs + AXICDMA_REG_SRC_ADDR);
        writel(bram_phys, cdma->cdma_regs + AXICDMA_REG_DST_ADDR);
    }
    else
    {
        writel(bram_phys, cdma->cdma_regs + AXICDMA_REG_SRC_ADDR);
        writel(ps_phys, cdma->cdma_regs + AXICDMA_REG_DST_ADDR);
    }

    dev_dbg(cdma->dev, "DMA: ps_phys=0x%llx bram_phys=0x%llx len=%zu\n",
            (unsigned long long)ps_phys, (unsigned long long)bram_phys, xfer->length);

    // Writing to BTT register starts the transfer
    writel(xfer->length, cdma->cdma_regs + AXICDMA_REG_BTT);

    // Wait for completion or error
    ret = wait_for_completion_timeout(&cdma->dma_done, msecs_to_jiffies(AXICDMA_TIMEOUT_MS));
    if (ret == 0)
    {
        dev_err(cdma->dev, "DMA transfer timed out after %d ms\n", AXICDMA_TIMEOUT_MS);
        mutex_unlock(&cdma->lock);
        return -ETIMEDOUT;
    }
    ret = cdma->dma_status;

    mutex_unlock(&cdma->lock);
    return ret;
}

static void axicdma_vma_close(struct vm_area_struct *vma)
{
    struct axicdma_dma_allocation *dma_alloc = vma->vm_private_data;
    struct axicdma_dev *cdma = dma_alloc->cdma;

    if (dma_alloc)
    {
        // Free the DMA memory
        dma_free_coherent(cdma->dev, dma_alloc->size,
                          dma_alloc->user_virt, dma_alloc->phys);

        // Remove from tracking list and free the structure
        list_del(&dma_alloc->list);
        kfree(dma_alloc);
    }
}

static const struct vm_operations_struct axicdma_vm_ops = {
    .close = axicdma_vma_close,
};

static int axicdma_mmap(struct file *file, struct vm_area_struct *vma)
{
    struct axicdma_dev *cdma = file->private_data;
    size_t size = vma->vm_end - vma->vm_start;
    struct axicdma_dma_allocation *dma_alloc;
    void *cpu_addr;
    dma_addr_t dma_handle;
    int rc;

    // Allocate tracking structure
    dma_alloc = kzalloc(sizeof(*dma_alloc), GFP_KERNEL);
    if (!dma_alloc)
    {
        dev_err(cdma->dev, "Unable to allocate DMA allocation structure\n");
        return -ENOMEM;
    }

    // Configure the DMA device
    of_dma_configure(cdma->dev, NULL, true);

    // Allocate contiguous and coherent DMA memory
    cpu_addr = dma_alloc_coherent(cdma->dev, size, &dma_handle, GFP_KERNEL);
    if (!cpu_addr)
    {
        dev_err(cdma->dev, "Unable to allocate contiguous DMA memory region of size %zu\n",
                size);
        dev_err(cdma->dev, "Make sure CMA is properly configured in your kernel\n");
        rc = -ENOMEM;
        goto free_alloc;
    }

    // Initialize the allocation record
    dma_alloc->size = size;
    dma_alloc->user_virt = (void *)vma->vm_start;
    dma_alloc->phys = dma_handle;
    dma_alloc->cdma = cdma;

    // Add to tracking list
    list_add(&dma_alloc->list, &cdma->dma_allocations);

    // Set up VM flags
    vma->vm_flags |= VM_IO | VM_DONTEXPAND | VM_DONTDUMP | VM_DONTCOPY;
    vma->vm_ops = &axicdma_vm_ops;
    vma->vm_private_data = dma_alloc;

    // Map the DMA memory to userspace
    rc = dma_mmap_coherent(cdma->dev, vma, cpu_addr, dma_handle, size);
    if (rc)
    {
        dev_err(cdma->dev, "Failed to map DMA memory to userspace: %d\n", rc);
        goto free_dma;
    }

    dev_info(cdma->dev, "Mapped DMA buffer: user=%p, phys=0x%llx, size=%zu\n",
             dma_alloc->user_virt, (unsigned long long)dma_alloc->phys, size);
    return 0;

free_dma:
    list_del(&dma_alloc->list);
    dma_free_coherent(cdma->dev, size, cpu_addr, dma_handle);
free_alloc:
    kfree(dma_alloc);
    return rc;
}

static long axicdma_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct axicdma_dev *cdma = file->private_data;
    struct axicdma_transfer xfer;
    struct axicdma_register_buffer ext_buf;

    switch (cmd)
    {
    case AXICDMA_IOCTL_TRANSFER:
        if (copy_from_user(&xfer, (void __user *)arg, sizeof(xfer)))
            return -EFAULT;
        return axicdma_do_transfer(cdma, &xfer);

    case AXICDMA_IOCTL_REGISTER_BUF:
        if (copy_from_user(&ext_buf, (void __user *)arg, sizeof(ext_buf)))
            return -EFAULT;
        return axicdma_register_buffer(cdma, &ext_buf);

    case AXICDMA_IOCTL_UNREGISTER_BUF:
        return axicdma_unregister_buffer(cdma, (void __user *)arg);

    default:
        return -ENOTTY;
    }
}

static const struct file_operations axicdma_fops = {
    .owner = THIS_MODULE,
    .open = axicdma_open,
    .release = axicdma_release,
    .unlocked_ioctl = axicdma_ioctl,
    .mmap = axicdma_mmap,
};

static int axicdma_probe(struct platform_device *pdev)
{
    struct axicdma_dev *cdma;
    struct resource *res;
    int ret;
    u64 bram_phys64, bram_size64;

    cdma = devm_kzalloc(&pdev->dev, sizeof(*cdma), GFP_KERNEL);
    if (!cdma)
        return -ENOMEM;

    cdma->dev = &pdev->dev;
    mutex_init(&cdma->lock);
    init_completion(&cdma->dma_done);
    INIT_LIST_HEAD(&cdma->dma_allocations);
    INIT_LIST_HEAD(&cdma->external_allocations);

    // Assign device ID
    mutex_lock(&device_count_mutex);
    cdma->device_id = device_count++;
    mutex_unlock(&device_count_mutex);

    // Map CDMA registers
    res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
    cdma->cdma_regs = devm_ioremap_resource(&pdev->dev, res);
    if (IS_ERR(cdma->cdma_regs))
        return PTR_ERR(cdma->cdma_regs);

    // Fetch BRAM address/size from device tree
    ret = of_property_read_u64(pdev->dev.of_node, "bram", &bram_phys64);
    if (ret)
        return dev_err_probe(&pdev->dev, ret, "Missing 'bram' property\n");
    ret = of_property_read_u64_index(pdev->dev.of_node, "bram", 1, &bram_size64);
    if (ret)
        return dev_err_probe(&pdev->dev, ret, "Missing 'bram' size\n");

    cdma->bram_phys = (dma_addr_t)bram_phys64;
    cdma->bram_size = (size_t)bram_size64;

    // Request IRQ
    cdma->irq = platform_get_irq(pdev, 0);
    if (cdma->irq < 0)
        return cdma->irq;
    ret = devm_request_irq(&pdev->dev, cdma->irq, axicdma_irq_handler, 0,
                           DRIVER_NAME, cdma);
    if (ret)
        return ret;

    // Reset CDMA
    writel(0x4, cdma->cdma_regs + AXICDMA_REG_CONTROL);
    mdelay(1);

    // Enable all interrupts (IOC and ERR)
    writel(XAXICDMA_XR_IRQ_SIMPLE_ALL_MASK, cdma->cdma_regs + AXICDMA_REG_CONTROL);

    // Create class on first device
    if (axicdma_major == 0)
    {
        ret = alloc_chrdev_region(&cdma->devt, 0, 256, AXICDMA_DEV_NAME);
        if (ret)
            return ret;
        axicdma_major = MAJOR(cdma->devt);

        axicdma_class = class_create(THIS_MODULE, AXICDMA_DEV_NAME);
        if (IS_ERR(axicdma_class))
        {
            ret = PTR_ERR(axicdma_class);
            unregister_chrdev_region(MKDEV(axicdma_major, 0), 256);
            axicdma_major = 0;
            return ret;
        }
    }
    else
    {
        cdma->devt = MKDEV(axicdma_major, cdma->device_id);
    }

    // Initialize and add character device
    cdev_init(&cdma->cdev, &axicdma_fops);
    cdma->cdev.owner = THIS_MODULE;
    ret = cdev_add(&cdma->cdev, cdma->devt, 1);
    if (ret)
        goto err_cleanup;

    // Create device node (e.g., /dev/axicdma0, /dev/axicdma1, etc.)
    device_create(axicdma_class, NULL, cdma->devt, NULL,
                  "%s%d", AXICDMA_DEV_NAME, cdma->device_id);

    platform_set_drvdata(pdev, cdma);
    dev_info(&pdev->dev, "Xilinx AXI CDMA driver loaded, device_id=%d, bram=0x%llx, size=0x%llx\n",
             cdma->device_id, (unsigned long long)cdma->bram_phys,
             (unsigned long long)cdma->bram_size);
    return 0;

err_cleanup:
    // Cleanup logic if this is the last device
    mutex_lock(&device_count_mutex);
    device_count--;
    if (device_count == 0 && axicdma_class)
    {
        class_destroy(axicdma_class);
        axicdma_class = NULL;
        unregister_chrdev_region(MKDEV(axicdma_major, 0), 256);
        axicdma_major = 0;
    }
    mutex_unlock(&device_count_mutex);
    return ret;
}

static int axicdma_remove(struct platform_device *pdev)
{
    struct axicdma_dev *cdma = platform_get_drvdata(pdev);
    struct axicdma_dma_allocation *dma_alloc, *dma_tmp;
    struct axicdma_external_allocation *ext_alloc, *ext_tmp;

    // Clean up all internal DMA allocations
    list_for_each_entry_safe(dma_alloc, dma_tmp, &cdma->dma_allocations, list)
    {
        list_del(&dma_alloc->list);
        dma_free_coherent(cdma->dev, dma_alloc->size,
                          dma_alloc->user_virt, dma_alloc->phys);
        kfree(dma_alloc);
    }

    // Clean up all external DMA allocations
    list_for_each_entry_safe(ext_alloc, ext_tmp, &cdma->external_allocations, list)
    {
        dma_buf_unmap_attachment(ext_alloc->dma_attach,
                                 ext_alloc->sg_table, DMA_BIDIRECTIONAL);
        dma_buf_detach(ext_alloc->dma_buf, ext_alloc->dma_attach);
        dma_buf_put(ext_alloc->dma_buf);
        list_del(&ext_alloc->list);
        kfree(ext_alloc);
    }

    // Destroy device node
    device_destroy(axicdma_class, cdma->devt);
    cdev_del(&cdma->cdev);

    // Clean up class and major number if this is the last device
    mutex_lock(&device_count_mutex);
    device_count--;
    if (device_count == 0)
    {
        if (axicdma_class)
        {
            class_destroy(axicdma_class);
            axicdma_class = NULL;
        }
        if (axicdma_major)
        {
            unregister_chrdev_region(MKDEV(axicdma_major, 0), 256);
            axicdma_major = 0;
        }
    }
    mutex_unlock(&device_count_mutex);

    return 0;
}

static const struct of_device_id axicdma_of_match[] = {
    {
        .compatible = "axicdma-chrdev",
    },
    {},
};
MODULE_DEVICE_TABLE(of, axicdma_of_match);

static struct platform_driver axicdma_driver = {
    .probe = axicdma_probe,
    .remove = axicdma_remove,
    .driver = {
        .name = DRIVER_NAME,
        .of_match_table = axicdma_of_match,
    },
};

module_platform_driver(axicdma_driver);

MODULE_AUTHOR("Sujan");
MODULE_DESCRIPTION("Xilinx AXI CDMA Character Device Driver");
MODULE_LICENSE("GPL");
