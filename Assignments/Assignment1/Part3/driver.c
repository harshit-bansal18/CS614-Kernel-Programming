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
#include <linux/fdtable.h>
#include <linux/list.h>
#include <asm/processor.h>
#include <linux/sched/task_stack.h>
#include <asm/page_64_types.h>

//values to read
#define PID 		0
#define	STATIC_PRIO 	1
#define	COMM 		2
#define PPID            3
#define NVCSW           4
#define NUM_THREADS	5
#define NUM_FILES_OPEN	6
#define STACK_SIZE	7
#define DEVNAME         "cs614_device"

struct exec_struct {
        int command;
        __kernel_pid_t pid;
        __kernel_pid_t ppid;
        __kernel_pid_t tgid;
        struct list_head list;
};

static int major;
atomic_t device_opened;
static struct class *device_class;
struct device *device1;

struct list_head proc_list;
spinlock_t lock;

struct exec_struct* find_proc(__kernel_pid_t id, __kernel_pid_t group_id) 
{
        struct exec_struct *pos;

        list_for_each_entry(pos, &proc_list, list) {
                if (pos->tgid == group_id)
                        // proc found
                        return pos;
        }
        // no proc found
        return NULL;
}

void add_proc(__kernel_pid_t pid,
                __kernel_pid_t ppid,
                __kernel_pid_t tgid, int command)
{
        struct exec_struct *exec, *new_exec;
        
        exec = find_proc(pid, tgid);
        if (exec) {
                exec->command = command;
                return;
        }

        new_exec = (struct exec_struct*)kzalloc(sizeof(struct exec_struct), GFP_KERNEL);
        new_exec->command = command;
        new_exec->pid = pid;
        new_exec->ppid = ppid;
        new_exec->tgid = tgid;

        list_add(&new_exec->list, &proc_list);

}

/*
Function prototypes
*/
int count_threads(void);
int count_open_files(void);
__kernel_pid_t get_pid_max_stack_usage(void) ;

int count_threads(void) 
{
        return get_nr_threads(current);
}

int count_open_files(void) 
{
        struct files_struct *current_files; 
        struct fdtable *files_table;
        int count=0, _fd = 0;

        current_files = current->files;
        files_table = files_fdtable(current_files);

        while(_fd < files_table->max_fds) {
                if (files_table->fd[_fd] != NULL)
                        count++;
                _fd++;
        }

        return count;
}

bool check_valid_addr(unsigned long addr) {
        return access_ok((void*)addr,  8);
}

__kernel_pid_t get_pid_max_stack_usage(void) 
{
        struct task_struct *task;
        long max, t;
        struct pt_regs *regs;
        __kernel_pid_t p;
	unsigned long _bp, nbp, top;

        max = 0;
        task = current;

	rcu_read_lock();

        do {
                regs = task_pt_regs(task);

                _bp = regs->bp ; // addr where prev bp is stored
                
       
                while (!copy_from_user(&nbp, (void*)_bp, 8)) {
                        top = _bp;
                        _bp = nbp;
                }

                t = top - regs->sp;
                if (t > max) {
                        p = task->pid;
                        max = t;
                }

                top = 0;nbp=0;

        } while_each_thread(current, task);
        
        rcu_read_unlock();
        
        return p;
}

static ssize_t device_read(struct file *file, char* user_buffer,
                                size_t length,
                                loff_t *offset)
{
        char buf[1024];
        int ret = 0;
        struct exec_struct *exec;

        spin_lock(&lock);
        exec  = find_proc(current->pid, current->tgid);
        spin_unlock(&lock);

        if (!exec) {
                printk(KERN_ALERT "Permission Denied: different process accessing device\n");
                return -EINVAL;
        }

        switch (exec->command) {
                case PID:
                        ret = sprintf(buf, "%d", exec->pid);
                        break;
                
                case STATIC_PRIO:
                        ret = sprintf(buf, "%d", current->static_prio);
                        break;
                
                case COMM:
                        ret = sprintf(buf, "%s", current->comm);
                        break;
                
                case PPID:
                        ret = sprintf(buf, "%d", exec->ppid);
                        break;

                case NVCSW:
                        ret = sprintf(buf, "%ld", current->nvcsw);
                        break;
                
                case NUM_THREADS:
                        ret = sprintf(buf, "%d", count_threads());
                        break;

                case NUM_FILES_OPEN:
                        ret = sprintf(buf, "%d", count_open_files());
                        break;
                
                case STACK_SIZE:
                        ret = sprintf(buf, "%d", get_pid_max_stack_usage());

        }

        if (ret <= 0 || copy_to_user(user_buffer, buf, ret))
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
        
        spin_lock(&lock);
        add_proc(current->pid,
                        current->real_parent->pid,
                        current->tgid,
                        newcomm);
        spin_unlock(&lock);
        return count;
}


static struct kobj_attribute driver_attr = __ATTR(cs614_value, 0660, NULL, command_set);
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
static int __init cs614_driver_init(void)
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
        
        // d_buf = kzalloc(4096, GFP_KERNEL); 
        printk(KERN_INFO "Device1: Assigned major number %d\n", major);
        pr_info("Device Driver Insert...Done!!!\n");

        atomic_set(&device_opened, 0);
        INIT_LIST_HEAD(&proc_list);
        spin_lock_init(&lock);

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
static void __exit cs614_driver_exit(void)
{
        struct exec_struct *pos, *t ;

        list_for_each_entry_safe(pos, t, &proc_list, list) {
                list_del(&pos->list);
                kfree(pos);
        }

        device_destroy(device_class, MKDEV(major, 0));
        class_destroy(device_class);
        unregister_chrdev(major, DEVNAME);

        sysfs_remove_group (kernel_kobj, &driver_attr_group);

        pr_info("Device Driver Remove...Done!!!\n");
}
 
module_init(cs614_driver_init);
module_exit(cs614_driver_exit);
 
MODULE_LICENSE("GPL");
