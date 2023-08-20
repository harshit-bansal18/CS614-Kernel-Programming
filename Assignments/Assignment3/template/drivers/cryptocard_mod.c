#include "./cryptocard.h"

#define DEVNAME "crypto"

const char cryptocard_driver_name [] = "cryptocard";

struct crypto_adapter *adapter;
struct config global_config;
// Maintains the current avaiable handle. Increments when that handle gets alloted
atomic_t handle;

int num_ops = 0;

spinlock_t list_lock;

// This lock should be held while an operation is under way. Release this lock when any operation
// completes. This will ensure that we process exactly one request at a time since device only does
// one operation at a time.
// Functions where this lock should be released:
// read_result;
// set_keys;
// set_config;
static DEFINE_MUTEX(operation_lock);


// Maintains the user performing the current operation
struct user_info *live_user;

struct list_head user_list;

static int major;
atomic_t  device_opened;
struct device *crypto_device;
static struct class *crypto_class;

static const struct pci_device_id crypto_pci_tbl[] = {
    CRYPTOCARD_DEVICE(0x1234, 0xdeba),
    {0,}    
};

static int cryptocard_probe(struct pci_dev *pdev, const struct pci_device_id *ent);
static void cryptocard_remove(struct pci_dev *pdev);

static struct pci_driver cryptocard_driver = {
	.name     = cryptocard_driver_name,
	.id_table = crypto_pci_tbl,
	.probe    = cryptocard_probe,
	.remove   = cryptocard_remove,
};


static ssize_t keys_set(struct kobject *kobj, struct kobj_attribute *attr, const char* buf, size_t count);
// static ssize_t do_encrypt(struct kobject *kobj, struct kobj_attribute *attr, const char* buf, size_t count);
// static ssize_t read_encrypt_result(struct kobject *kobj, struct kobj_attribute *attr, char *buf);
// static ssize_t do_decrypt(struct kobject *kobj, struct kobj_attribute *attr, const char* buf, size_t count);
// static ssize_t read_result(struct kobject *kobj, struct kobj_attribute *attr, char *buf);
static ssize_t get_new_handle(struct kobject *kobj, struct kobj_attribute *attr, char *buf);
static ssize_t set_live_handle(struct kobject *kobj, struct kobj_attribute *attr, const char* buf, size_t count);
static ssize_t close_handle(struct kobject *kobj, struct kobj_attribute *attr, const char* buf, size_t count);
static ssize_t set_config(struct kobject *kobj, struct kobj_attribute *attr, const char* buf, size_t count);
static ssize_t set_map(struct kobject *kobj, struct kobj_attribute *attr, const char* buf, size_t count);

// chardev operations
static int crypto_open(struct inode *inode, struct file *file);
static int crypto_close(struct inode *inode, struct file *file);
static ssize_t crypto_read(struct file *file, char* user_buffer, size_t length, loff_t *offset);
static ssize_t crypto_write(struct file *file, const char __user *user_buffer, size_t length, loff_t *offset);

static irqreturn_t irq_handler(int irq, void *dev_id);

static struct kobj_attribute keys_attr = __ATTR(keys, 0660, NULL, keys_set);
// static struct kobj_attribute encrypt_attr = __ATTR(encrypt, 0660, read_result, do_encrypt);
// static struct kobj_attribute decrypt_attr = __ATTR(decrypt, 0660, read_result, do_decrypt);
static struct kobj_attribute handle_attr = __ATTR(handle, 0660, get_new_handle, close_handle);
static struct kobj_attribute live_handle_attr = __ATTR(live_handle, 0660, NULL, set_live_handle);
static struct kobj_attribute config_attr = __ATTR(config, 0660, NULL, set_config);
static struct kobj_attribute map_attr = __ATTR(map, 0660, NULL, set_map);

static struct attribute *crypto_attrs[] = {
        &keys_attr.attr,
        &handle_attr.attr,
        &live_handle_attr.attr,
        &config_attr.attr,
        &map_attr.attr,
        NULL,
};
static struct attribute_group crypto_attr_group = {
        .attrs = crypto_attrs,
        .name = cryptocard_driver_name,
};

static struct file_operations fops = {
        .read = crypto_read,
        .write = crypto_write,
        .open = crypto_open,
        .release = crypto_close,
};

static char *device_devnode(struct device *dev, umode_t *mode)
{
        if (mode && dev->devt == MKDEV(major, 0))
                *mode = 0666;
        return NULL;
}

/*
** Module Init function
*/
static int      __init cryptocard_init_module(void)
{
    int ret, err;
    pr_info("%s\n", "CryptoCard PCI Driver");
    ret = sysfs_create_group(kernel_kobj, &crypto_attr_group);
    if (unlikely(ret)) {
        pr_info("%s: cannot create sysfs group\n", cryptocard_driver_name);
        return ret;
    }
    major = register_chrdev(0, DEVNAME, &fops);
    err =  major;
    if (err < 0) {
            printk(KERN_ALERT "Registering char device1 failed with %d\n", major);
            goto error_regdev;
    }

    crypto_class = class_create(THIS_MODULE, DEVNAME);
    err = PTR_ERR(crypto_class);
    if (IS_ERR(crypto_class))
            goto error_class;
    
    crypto_class->devnode = device_devnode;

    crypto_device = device_create(crypto_class, NULL,
                                    MKDEV(major, 0),
                                    NULL, DEVNAME);
    err = PTR_ERR(crypto_device);
    if (IS_ERR(crypto_device))
            goto error_device;
    
    // d_buf = kzalloc(4096, GFP_KERNEL); 
    printk(KERN_INFO "Device1: Assigned major number %d\n", major);
    pr_info("Device Driver Insert...Done!!!\n");

    atomic_set(&device_opened, 0);

    ret = pci_register_driver(&cryptocard_driver);
    return ret;

error_device:
        class_destroy(crypto_class);
error_class:
        unregister_chrdev(major, DEVNAME);
error_regdev:
        sysfs_remove_group(kernel_kobj, &crypto_attr_group);
        return err;
}

/*
** Module exit function
*/
static void     __exit cryptocard_exit_module(void)
{   

    pci_unregister_driver(&cryptocard_driver);
    device_destroy(crypto_class, MKDEV(major, 0));
    class_destroy(crypto_class);
    unregister_chrdev(major, DEVNAME);
    sysfs_remove_group(kernel_kobj, &crypto_attr_group);
    printk(KERN_INFO "%s:Device Driver Remove...Done!!!\n", cryptocard_driver_name);
}

module_init(cryptocard_init_module);
module_exit(cryptocard_exit_module);




/*********CryptoCard Function Definitions**********/
static int cryptocard_probe(struct pci_dev *pdev, const struct pci_device_id *ent) {
    int bars, err;
    void *_addr;
    pr_info("%s: driver is running\n", cryptocard_driver_name);
    bars = pci_select_bars(pdev, IORESOURCE_MEM);
	err = pci_enable_device_mem(pdev);
    if (err)
        return err;
    
    err = pci_request_selected_regions(pdev, bars, cryptocard_driver_name);
	if (err)
		goto err_pci_reg;

    // pci_set_master(pdev);
    // err = pci_save_state(pdev);
    // if (err) {
    //     goto err_alloc;
    // }

    adapter = (struct crypto_adapter*)kzalloc(sizeof(struct crypto_adapter), GFP_KERNEL);
    adapter->pdev = pdev;
    adapter->bars = bars;
    adapter->hw_addr = pci_ioremap_bar(pdev, BAR_0);
    if (!adapter->hw_addr)
        goto err_alloc;

    
    if (dma_set_mask_and_coherent(&adapter->pdev->dev, DMA_BIT_MASK(64))){
        pr_info("%s: failed to set dma mask\n", cryptocard_driver_name);
        goto err_alloc;
    }

    _addr = dma_alloc_coherent(&adapter->pdev->dev, DMA_MEM_SIZE, &adapter->dma_handle, GFP_DMA);
    if(!_addr){
        pr_info("%s: failed to allocate dma memory\n", cryptocard_driver_name);
        goto err_alloc;
    }
    adapter->dma_base_addr = _addr;

    if(request_irq(IRQ_NO, irq_handler, IRQF_SHARED, cryptocard_driver_name, (void *)adapter)){
        pr_info("%s: Failed to get irq\n", cryptocard_driver_name);
        goto err_alloc;
    }

    writeq((unsigned long)adapter->dma_handle, adapter->hw_addr + DMA_DATA_ADDR);


    global_config.dma = 0;
    global_config.interrupt = 0;
    global_config.keys = 0;
    // Init the list  head
    INIT_LIST_HEAD(&user_list);
    spin_lock_init(&list_lock);
    pr_info("%s: probe success\n", cryptocard_driver_name);

    return 0;

err_alloc:
    pci_release_selected_regions(pdev, bars);
err_pci_reg:
    pci_disable_device(pdev);
    return err;
}

static void cryptocard_remove(struct pci_dev *pdev) {
    dma_free_coherent(&adapter->pdev->dev, DMA_MEM_SIZE, adapter->dma_base_addr, adapter->dma_handle);
    free_irq(IRQ_NO, (void *)adapter);
    iounmap(adapter->hw_addr);
    pci_release_selected_regions(pdev, adapter->bars);
    pci_disable_device(pdev);
    kfree(adapter);
}
/*********************************************************/
//*****************Helper Functions***********************/
// list_lock should be held before calling this function
static inline struct user_info *find_user_handle(int user_handle) {
    struct user_info *pos;
    list_for_each_entry(pos, &user_list, list) {
        if (pos->_handle == user_handle) {
            return pos;
        }
    }
    return NULL;
}

static irqreturn_t irq_handler(int irq, void *dev_id) {
    // handle the interrupt
    int val;
    val = readl(adapter->hw_addr + INTERRUPT_STATUS_REG);
    writel(val, adapter->hw_addr + INTERRUPT_ACK_REG);

    atomic_inc(&live_user->interrupt_handled);
    
    // pr_info("%s: interrupt handled\n", cryptocard_driver_name);
    return IRQ_HANDLED;
}

static inline void set_interrupt_mode(void) {

    global_config.interrupt = 1;
    live_user->_config.interrupt = 1;
    pr_info("%s: interrupt mode set\n", cryptocard_driver_name);
}

static inline void set_dma_mode(void) {

    pr_info("%s: dma mode set\n", cryptocard_driver_name);
    live_user->_config.dma = 1;
    global_config.dma = 1;

}

/****************SYSFS Function Definitions***************/

static ssize_t keys_set(struct kobject *kobj, struct kobj_attribute *attr, const char* buf, size_t count) {
    int _handle, err;
    struct user_info *ui;
    err = kstrtoint(buf+2, 10, &_handle);
    if (err || (_handle < 0)){
        pr_info("%s: %d: invalid handle\n", cryptocard_driver_name, _handle);
        return -EINVAL;
    }
    // pr_info("%s: value of handle is %d\n", cryptocard_driver_name, _handle);
    spin_lock(&list_lock);
    ui = find_user_handle(_handle);
    spin_unlock(&list_lock);
    
    if(!ui){
        pr_info("%s: %d is not a valid handle\n", cryptocard_driver_name, _handle);
        return -1;
    }

    ui->keys = buf[1] | (buf[0] << 8);
    global_config.keys = ui->keys;
    return 2;
}

static ssize_t get_new_handle(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    
    int ret;
    int _i_handle;
    struct user_info *info;
    
    spin_lock(&list_lock);
    _i_handle = atomic_read(&handle);
    ret = sprintf(buf, "%d", _i_handle);
    info = (struct user_info*)kzalloc(sizeof(struct user_info), GFP_KERNEL);
    info->_handle = _i_handle;
    info->_config = global_config;
    info->keys = global_config.keys;
    info->u_pid = current->pid;
    atomic_set(&info->interrupt_handled, 0);
    list_add(&info->list, &user_list);
    spin_unlock(&list_lock);

    atomic_inc(&handle);
    return ret;
}



static ssize_t set_live_handle(struct kobject *kobj, struct kobj_attribute *attr, const char* buf, size_t count) {
    
    int _live_handle, err;
    struct user_info *ui;

    err = kstrtoint(buf, 10, &_live_handle);
    if (err) {
        pr_info("%s: invalid handle\n", cryptocard_driver_name);
        return -EINVAL;
    }
    spin_lock(&list_lock);
    ui = find_user_handle(_live_handle);
    spin_unlock(&list_lock);

    if (ui) {
        if (mutex_lock_interruptible(&operation_lock)){
            pr_info("%s: cannot grab mutex\n", cryptocard_driver_name);
            return -1;
        }
        live_user = ui;
        return count;
    }

    pr_info("%s: %d: invalid handle\n", cryptocard_driver_name, _live_handle);
    return -1;
}

static ssize_t close_handle(struct kobject *kobj, struct kobj_attribute *attr, const char* buf, size_t count) {
    struct user_info *ui;
    int _handle, err;

    err = kstrtoint(buf, 10, &_handle);
    if (err) {
        pr_info("%s: invalid handle\n", cryptocard_driver_name);
        return -EINVAL;
    }

    spin_lock(&list_lock);
    ui = find_user_handle(_handle);
    if (!ui){
        spin_unlock(&list_lock);
        pr_info("%s: %d is not a valid handle\n", cryptocard_driver_name, _handle);
        return -1;
    }

    list_del(&ui->list);
    spin_unlock(&list_lock);
    
    kfree(ui);
    num_ops = 0;
    return count;
}
static ssize_t set_config(struct kobject *kobj, struct kobj_attribute *attr, const char* buf, size_t count) {
    int val, err, ret;
    err = kstrtoint(buf, 10, &val);
    if (err || val < 0)
        return -EINVAL;
    
    ret = count;

    // pr_info("%s: value of config buf: %s val: %d\n", cryptocard_driver_name, buf, val);

    switch (val)
    {
    case INTERRUPT_SET:
        /* code */
        set_interrupt_mode();
        break;

    case INTERRUPT_UNSET:
        global_config.interrupt = false;
        live_user->_config.interrupt = false;
        break;

    case DMA_SET:
        // set the DMA mode
        set_dma_mode();
        break;

    case DMA_UNSET:
        global_config.dma = false;
        live_user->_config.dma = false;
        break;
    default:
        break;
    }

    mutex_unlock(&operation_lock);
    return ret;
}

pte_t *check_ptes(unsigned long address, struct mm_struct *mm)
{
        pgd_t *pgd;
        p4d_t *p4d;
        pud_t *pud;
        pmd_t *pmd;
        pte_t *ptep;

        pgd = pgd_offset(mm, address);
        if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd)))
                goto nul_ret;
        p4d = p4d_offset(pgd, address);
        if (p4d_none(*p4d))
                goto nul_ret;
        if (unlikely(p4d_bad(*p4d)))
                goto nul_ret;
        pud = pud_offset(p4d, address);
        if (pud_none(*pud))
                goto nul_ret;
        if (unlikely(pud_bad(*pud)))
                goto nul_ret;
        pmd = pmd_offset(pud, address);
        if (pmd_none(*pmd))
                goto nul_ret;
                
        if (unlikely(pmd_trans_huge(*pmd))){
                printk(KERN_INFO "I am huge\n");
                goto nul_ret;
        }

        ptep = pte_offset_map(pmd, address);

        if(!ptep){
			printk(KERN_INFO "pte_p is null\n\n");
			goto nul_ret;
        }
		
		if(ptep->pte == 0)
			return NULL;
        
		return ptep;

nul_ret:
        return NULL;

}

unsigned get_pfn(struct mm_struct* mm, unsigned long addr){
    pte_t* pte;

	pte = check_ptes(addr, mm);
	if(pte == NULL){
		printk("No mapping present in kernel for the given address\n");
		return 0;
	}
	return pte_pfn(*pte);
}

static ssize_t set_map(struct kobject *kobj, struct kobj_attribute *attr, const char* buf, size_t count) {

	struct mm_struct* mm;
	struct vm_area_struct* vma;
	unsigned long vm_addr;
	unsigned long size;
	unsigned long pfn;

	if(kstrtoul(buf, 10, &vm_addr) < 0 ){
		printk("Unable to read user buffer\n");
		return -EINVAL;
	}

	mm = get_task_mm(current);
	vma = find_vma(mm, vm_addr);

	if(vma->vm_start > vm_addr) {
		printk("No VMA present corresponding to start_addr: %lx\n", vm_addr);
		return -EINVAL;
	}

	size = vma->vm_end - vma->vm_start;

	pfn = get_pfn(mm, (unsigned long) adapter->hw_addr);

	if(io_remap_pfn_range(vma, vma->vm_start, pfn, size, vma->vm_page_prot) < 0){
		printk("Page Mapping Failed to userspace\n");
		return -EINVAL;
	}

	return count;
}

////////***********************CHARDEV Operations****************/////////////
static int crypto_open(struct inode *inode, struct file *file){
        atomic_inc(&device_opened);
        try_module_get(THIS_MODULE);
        // printk(KERN_INFO "Device1 opened successfully\n");
        return 0;
}

static int crypto_close(struct inode *inode, struct file *file){
        atomic_dec(&device_opened);
        module_put(THIS_MODULE);
        // printk(KERN_INFO "Device1 closed successfully\n");
        return 0;
}

static ssize_t crypto_read(struct file *file, char* user_buffer, size_t length, loff_t *offset) {
    // int _len = live_user->result_length;
    // char *kbuf;
    // if(live_user->_config.dma) {
    //     if(copy_to_user(user_buffer, adapter->dma_base_addr, _len))
    //         _len = -EINVAL;
        
    //     mutex_unlock(&operation_lock);
    //     return _len; 
    // }

    // kbuf = (char*)kzalloc(_len, GFP_KERNEL);
    // for(int i=0; i < _len; i++) {
    //     kbuf[i] = readb(adapter->hw_addr + MMIO_BUFFER_REGION + i);
    //     // pr_info("%s: byte read: %c\n", cryptocard_driver_name, kbuf[i]);
    // }
    
    // if(copy_to_user(user_buffer, kbuf, _len)) {
    //     _len = -EINVAL;
    // }
    
    // // encryption/decryption is complete here. Release the op_lock
    // mutex_unlock(&operation_lock);
    // kfree(kbuf);
    // return _len;

    struct user_info *pos;

    spin_lock(&list_lock);
    list_for_each_entry(pos, &user_list, list) {
        if (pos->u_pid == current->pid) {
            break;
        }
    }
    spin_unlock(&list_lock);

    if (copy_to_user(user_buffer, pos->res_buf, pos->result_length))
        goto end;

    kfree(pos->res_buf);
    return pos->result_length;

end:
    kfree(pos->res_buf);
    return -1;
}

static inline void do_mmio_operation(char *kbuf, int data_len) {
    unsigned int status;
    status = 0x0;
    if (live_user->_config.interrupt){
        status = status | MMIO_INTERRUPT;
        writel(MMIO_MODE, adapter->hw_addr + INTERRUPT_STATUS_REG);
    }
    // set the status
    if(kbuf[0] == ENCRYPT)
        writel(status | OP_ENCRYPT, adapter->hw_addr + MMIO_STATUS_REG);
    else
        writel(status | OP_DECRYPT, adapter->hw_addr + MMIO_STATUS_REG);

    
    // write data to device buffer area
    if(kbuf[1] == 'n'){
        for(int i=1; i <= data_len; i++) {
            writeb(kbuf[i], adapter->hw_addr + MMIO_BUFFER_REGION + i-1);
        }
    }

    // set the length of data
    writel(data_len, adapter->hw_addr + MMIO_MSG_LENGTH);
    // trigger the encryption
    writel(MMIO_BUFFER_REGION, adapter->hw_addr + MMIO_DATA_ADDR);
    
    if(live_user->_config.interrupt){
        // int counter = 0;
        while(atomic_read(&live_user->interrupt_handled) == 0);
        atomic_dec(&live_user->interrupt_handled);
        goto read;
    }

    //poll on device
    while(true) {
        status = readl(adapter->hw_addr + MMIO_STATUS_REG);
        if (status%2 == 0)
            break;
    }
read:
    if(kbuf[1] == 'n'){
        live_user->result_length = data_len;
        live_user->res_buf = (char*)kzalloc(data_len, GFP_KERNEL);
        for(int i=0; i < data_len; i++) {
            live_user->res_buf[i] = readb(adapter->hw_addr + MMIO_BUFFER_REGION + i);
        }
    }
    mutex_unlock(&operation_lock);
}

static inline void do_dma_operation(char *kbuf, int data_len) {
    unsigned int status;
    status = 0x01;
    // pr_info("%s: DMA. dma addr = %lld\n", cryptocard_driver_name, readq(adapter->hw_addr + DMA_DATA_ADDR));
    memcpy(adapter->dma_base_addr, kbuf+1, data_len);
    writel(data_len, adapter->hw_addr + DMA_MSG_LENGTH);

    if (live_user->_config.interrupt){
        status = status | DMA_INTERRUPT ;
        writel(DMA_MODE, adapter->hw_addr + INTERRUPT_STATUS_REG);
    }
    if(kbuf[0] == ENCRYPT)
        writel(status | OP_ENCRYPT, adapter->hw_addr + DMA_COMMAND_REG);
    else
        writel(status | OP_DECRYPT, adapter->hw_addr + DMA_COMMAND_REG);

    if (live_user->_config.interrupt){
        while(atomic_read(&live_user->interrupt_handled) == 0);
        atomic_dec(&live_user->interrupt_handled);
        goto read;
    }
    
    while(true) {
        status = readl(adapter->hw_addr + DMA_COMMAND_REG);
        if (status%2 == 0)
            break;
    }

read:
    live_user->result_length = data_len;
    live_user->res_buf = (char *)kzalloc(data_len, GFP_KERNEL);
    memcpy(live_user->res_buf, adapter->dma_base_addr, data_len);
    mutex_unlock(&operation_lock);
}

static ssize_t crypto_write(struct file *file, const char __user *user_buffer, size_t length, loff_t *offset) {
    char *kbuf;
    int data_len = length - 1;

    kbuf = (char *)kzalloc(length, GFP_KERNEL);
    if(copy_from_user(kbuf, user_buffer, length))
        goto copy_err;
    
    // set the keys
    writel(live_user->keys, adapter->hw_addr + KEYS);
    
    if(live_user->_config.dma){
        if(kbuf[1] == 'm'){
            printk("Mapping feature not for dma\n");
            mutex_unlock(&operation_lock);
            kfree(kbuf);
            return -EINVAL;
        }
        do_dma_operation(kbuf, data_len);
    }
    else
        do_mmio_operation(kbuf, data_len);



    kfree(kbuf);
    num_ops++;
    if (num_ops%100 == 0)
        pr_info("%s: ops performed: %d\n", cryptocard_driver_name, num_ops);
    
    if(user_buffer[1] == 'm'){
        mutex_unlock(&operation_lock);
    }
    return length;
copy_err:
    kfree(kbuf);
    return -1;
}

MODULE_LICENSE("GPL");
