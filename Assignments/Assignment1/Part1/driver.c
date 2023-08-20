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


//values to read
#define PID 		0
#define	STATIC_PRIO 	1
#define	COMM 		2
#define PPID		3
#define NVCSW		4
#define DEVNAME         "cs614_device"

static int command, major;
static __kernel_pid_t pid, ppid;
atomic_t device_opened;
static struct class *device_class;
struct device *device1;

static ssize_t device_read(struct file *file, char* user_buffer,
                                size_t length,
                                loff_t *offset)
{
        char buf[1024];
        int ret = 0;
        
        if (current->pid != pid) {
                printk(KERN_ALERT "Permission Denied: different process accessing device\n");
                return -EINVAL;
        }

        switch (command) {
                case PID:
                        ret = sprintf(buf, "%d", pid);
                        break;
                
                case STATIC_PRIO:
                        ret = sprintf(buf, "%d", current->static_prio);
                        break;
                
                case COMM:
                        ret = sprintf(buf, "%s", current->comm);
                        break;
                
                case PPID:
                        ret = sprintf(buf, "%d", ppid);
                        break;

                case NVCSW:
                        ret = sprintf(buf, "%ld", current->nvcsw);
        }

        if (copy_to_user(user_buffer, buf, ret))
                return -EINVAL;

        return ret;
}

static int device_open(struct inode *inode, struct file *file)
{
        atomic_inc(&device_opened);
        try_module_get(THIS_MODULE);
        printk(KERN_INFO "Device1 opened successfully\n");
        return 0;
}

static int device_close(struct inode *inode, struct file *file)
{
        atomic_dec(&device_opened);
        module_put(THIS_MODULE);
        printk(KERN_INFO "Device1 closed successfully\n");
        return 0;
}

static ssize_t command_set(struct kobject *kobj,
                                struct kobj_attribute *attr,
                                const char* buf, size_t count)
{
        int newcomm;
        int err = kstrtoint(buf, 10, &newcomm);
        if (err || newcomm > 7 || newcomm < 0)
                return -EINVAL;
        
        
        command = newcomm;
        pid = current->pid;
        ppid = current->real_parent->pid;

        return count;
}

static ssize_t command_value(struct kobject *kobj,
                                struct kobj_attribute *attr, char *buf)
{
        return sprintf(buf, "%d\n", command);
}

static struct kobj_attribute driver_attr = __ATTR(cs614_value, 0660, command_value, command_set);
static struct attribute *driver_attrs[] = {
        &driver_attr.attr,
        NULL,
};
static struct attribute_group driver_attr_group = {
        .attrs = driver_attrs,
        .name = "cs614_sysfs",
};
static struct file_operations fops = {
        .read = device_read,
        .open = device_open,
        .release = device_close,
};

static char *device_devnode(struct device *dev, umode_t *mode)
{
        if (mode && dev->devt == MKDEV(major, 0))
                *mode = 0666;
        return NULL;
}

/*
** Function Prototypes
*/
static int      __init cs614_driver_init(void);
static void     __exit cs614_driver_exit(void);
 
/*
** Module Init function
*/
static int      __init cs614_driver_init(void)
{
        int err, ret;
        
        ret = sysfs_create_group(kernel_kobj, &driver_attr_group);
        if (unlikely(ret)) {
                printk(KERN_INFO "driver1: can't create sysfs\n");
        }
        
        
        major = register_chrdev(0, DEVNAME, &fops);
        err =  major;
        if (err < 0) {
                printk(KERN_ALERT "Registering char device1 failed with %d\n", major);
                goto error_regdev;
        }

        device_class = class_create(THIS_MODULE, DEVNAME);
        err = PTR_ERR(device_class);
        if (IS_ERR(device_class))
                goto error_class;
        
        device_class->devnode = device_devnode;

        device1 = device_create(device_class, NULL,
                                        MKDEV(major, 0),
                                        NULL, DEVNAME);
        err = PTR_ERR(device1);
        if (IS_ERR(device1))
                goto error_device;
        

        printk(KERN_INFO "Device1: Assigned major number %d\n", major);
        pr_info("Device Driver Insert...Done!!!\n");
        atomic_set(&device_opened, 0);

	return 0;

error_device:
        class_destroy(device_class);
error_class:
        unregister_chrdev(major, DEVNAME);
error_regdev:
        sysfs_remove_group(kernel_kobj, &driver_attr_group);
        return err;
}

/*
** Module exit function
*/
static void     __exit cs614_driver_exit(void)
{       
        
        device_destroy(device_class, MKDEV(major, 0));
        class_destroy(device_class);
        unregister_chrdev(major, DEVNAME);
        sysfs_remove_group (kernel_kobj, &driver_attr_group);
        printk(KERN_INFO "Device Driver Remove...Done!!!\n");
}

module_init(cs614_driver_init);
module_exit(cs614_driver_exit);
 
MODULE_LICENSE("GPL");
