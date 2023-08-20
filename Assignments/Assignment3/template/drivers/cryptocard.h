#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kdev_t.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include<linux/slab.h>                 //kmalloc()
#include<linux/uaccess.h>              //copy_to/from_user()
#include<linux/sysfs.h> 
#include<linux/kobject.h> 
#include <linux/err.h>
#include <linux/vmalloc.h>
#include <linux/pci.h>
#include <linux/delay.h>
#include <linux/list.h>

#define CRYPTOCARD_DEVICE(vendor_id, device_id) {\
	PCI_DEVICE(vendor_id, device_id)}

#define ENCRYPT 'e'
#define DECRYPT 'd'

#define BAR_0 0
#define LIVENESS_CHECK 0x04
#define KEYS    0x08
#define MMIO_MSG_LENGTH 0x0c
#define MMIO_STATUS_REG 0x20
#define INTERRUPT_STATUS_REG 0x24
#define INTERRUPT_ACK_REG 0x64
#define MMIO_DATA_ADDR 0x80
#define DMA_DATA_ADDR 0x90
#define DMA_MSG_LENGTH 0x98
#define DMA_COMMAND_REG 0xa0
#define MMIO_BUFFER_REGION 0xa8

#define OP_ENCRYPT 0x0
#define OP_DECRYPT 0x02
#define DMA_MODE  0x100
#define MMIO_MODE 0x001
#define MMIO_INTERRUPT 0x80
#define DMA_INTERRUPT 0x04

struct crypto_adapter {
    u8 __iomem *hw_addr;
    struct pci_dev *pdev;
    int bars;
    void *dma_base_addr;
    dma_addr_t dma_handle;
};

struct config {
    int interrupt;
    int  dma;
    int keys;
};


struct user_info {
    unsigned int _handle;
    pid_t u_pid;
    char *res_buf;
    int keys;
    struct list_head list;
    unsigned int result_length;
    atomic_t interrupt_handled;
    struct config _config;
};

#define INTERRUPT_SET 1
#define INTERRUPT_UNSET 0
#define DMA_SET 3
#define DMA_UNSET 2


#define DMA_MEM_SIZE 32768
#define IRQ_NO 10
