/**
 * Vulnerable kernel driver
 *
 * This module is vulnerable to OOB access and allows arbitrary code
 * execution.
 * An arbitrary offset can be passed from user space via the provided ioctl().
 * This offset is then used as an index for the 'ops' array to obtain the
 * function address to be executed.
 * 
 *
 * Full article: https://cyseclabs.com/page?n=17012016
 *
 * Author: Vitaly Nikolenko
 * Email: vnik@cyseclabs.com
 **/

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/device.h>
#include "drv.h"

#define DEVICE_NAME "vulndrv"
#define DEVICE_PATH "/dev/vulndrv"

typedef void op_t(struct file *file, char *allocated);

static int device_open(struct inode *, struct file *);
static long device_ioctl(struct file *, unsigned int, unsigned long);
static int device_release(struct inode *, struct file *f);
static ssize_t device_write(struct file *file, const char *buff, size_t len, loff_t *off);

static struct class *class;
unsigned long *ops[3];
static int major_no;

static char *allocated = 0;

static struct file_operations fops = {
	.open = device_open,
	.release = device_release,
	.unlocked_ioctl = device_ioctl,
	.write = device_write 
};


static int device_release(struct inode *i, struct file *f) {
	kfree(allocated);
	printk(KERN_INFO "device released!\n");
	return 0;
}


static int device_open(struct inode *i, struct file *f) {
	allocated = kmalloc(168, GFP_KERNEL);
	printk(KERN_INFO "device opened!\n");
	printk(KERN_INFO "addr(allocated) = %px\n", allocated);
	return 0;
}

static ssize_t device_write(struct file *file, const char *buff, size_t len, loff_t *off) {
	if (len > 160 + 8) return -EINVAL;
	if (copy_from_user(allocated, buff, len)) return -EFAULT;
	return len;
}

static void aaa(op_t *fn, struct file *file, char *buffer) {
	__asm__ __volatile__ ("mov %0, %%rbx": : "r" (buffer) : "%ebx");
		fn(file, allocated + 16);
}

static long device_ioctl(struct file *file, unsigned int cmd, unsigned long args) {
	struct drv_req req;
	char *buffer;
	op_t *fn;
	
	switch(cmd) {
	case 0:
		copy_from_user(&req, (struct drv_req *)args, sizeof(struct drv_req));
		printk(KERN_INFO "size = %ld\n", req.offset);
        printk(KERN_INFO "fn ptr is at %lu\n", (unsigned long)ops + req.offset);
		fn = *(op_t **)((unsigned long)ops + req.offset);
        printk(KERN_INFO "fn is at %lu\n", (unsigned long)fn);
		buffer = kmalloc(256, GFP_KERNEL);
		printk(KERN_INFO "buffer = %lx\n", (unsigned long)buffer);
		// __asm__ __volatile__ ("mov %0, %%rbx": : "r" (buffer) : "%ebx");
		// fn(file, allocated + 16);
		aaa(fn, file, buffer);
		kfree(buffer);
		break;
	case 1:
		return (long)allocated & 0xffffffff;
		break;
	case 2000:
		return (long)allocated >> 32;
		break;
	default:
		break;
	}

	return 0;
}

static int m_init(void) {
	printk(KERN_INFO "addr(ops) = %px\n", &ops);
	printk(KERN_INFO "kaslr offset = %lu\n", (unsigned long)&kfree - 0xffffffff812ba450);
	major_no = register_chrdev(0, DEVICE_NAME, &fops);
	class = class_create(THIS_MODULE, DEVICE_NAME);
	device_create(class, NULL, MKDEV(major_no, 0), NULL, DEVICE_NAME);

	return 0;
}

static void m_exit(void) {
	device_destroy(class, MKDEV(major_no, 0));
	class_unregister(class);
	class_destroy(class);
	unregister_chrdev(major_no, DEVICE_NAME);
	printk(KERN_INFO "Driver unloaded\n");
}

module_init(m_init);
module_exit(m_exit);

MODULE_LICENSE("GPL");
