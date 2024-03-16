/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/fs.h> // file_operations
#include <linux/slab.h>
#include "aesdchar.h"
#include <linux/uaccess.h>

//#include <linux/stdbool.h>
int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("Pranjal Gupta"); /** TODO: fill in your name **/
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

int aesd_open(struct inode *inode, struct file *filp)
{
    PDEBUG("open");
    filp->private_data = container_of(inode->i_cdev, struct aesd_dev, cdev);
    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    filp->private_data = NULL;
    return 0;
}
ssize_t aesd_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos)
{
    ssize_t retval = 0;

    PDEBUG("read %zu bytes with offset %lld", count, *f_pos);

    if (filp == NULL || buf == NULL || f_pos == NULL || *f_pos < 0)
        return -EINVAL; // Invalid argument

    struct aesd_dev *dev = filp->private_data;
    if (dev == NULL)
        return -EINVAL; // Invalid argument

    if (mutex_lock_interruptible(&dev->mutex))
        return -ERESTARTSYS;

    struct aesd_buffer_entry *temp_entry = aesd_circular_buffer_find_entry_offset_for_fpos(&dev->buffer, *f_pos, NULL);
    if (temp_entry == NULL) {
        mutex_unlock(&dev->mutex);
        return 0; // End of file
    }

    size_t entry_offset = *f_pos % temp_entry->size; // Adjust offset within the entry
    size_t remaining_bytes = temp_entry->size - entry_offset;
    size_t bytes_to_copy = min(remaining_bytes, count);

    unsigned long bytes_not_copied = copy_to_user(buf, temp_entry->buffptr + entry_offset, bytes_to_copy);
    if (bytes_not_copied != 0) {
        mutex_unlock(&dev->mutex);
        return -EFAULT; // Failed to copy data to user space
    }

    *f_pos += bytes_to_copy;
    mutex_unlock(&dev->mutex);
    return bytes_to_copy;
}



ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos)
{
    ssize_t retval = -ENOMEM;
    int pos = 0;
    int prev_length = 0;
    bool rec_complete = false;
    struct aesd_dev *dev = NULL;
    char *data_ptr;
    char *ptr;

    if (filp == NULL || buf == NULL)
        return retval;

    PDEBUG("write %zu bytes with offset %lld", count, *f_pos);

    data_ptr = kmalloc(sizeof(char) * count, GFP_KERNEL);
    if (data_ptr == NULL) {
        PDEBUG("Memory Allocation Failed\n");
        return retval;
    }

    unsigned long bytes_not_copied = copy_from_user(data_ptr, buf, count);
    if (bytes_not_copied != 0) {
        PDEBUG("Data copy failed\n");
        kfree(data_ptr);
        return retval;
    }

    ptr = memchr(data_ptr, '\n', count);
    if (ptr == NULL) {
        pos = count;
    } else {
        pos = ptr - data_ptr + 1;
        rec_complete = true;
    }

    dev = filp->private_data;
    if (mutex_lock_interruptible(&dev->mutex)) {
        kfree(data_ptr);
        return -ERESTARTSYS;
    }

    prev_length = dev->entry.size;
    dev->entry.size += pos;
    char *new_data_ptr = (char *)krealloc(dev->entry.buffptr, dev->entry.size, GFP_KERNEL);
    if (new_data_ptr == NULL) {
        PDEBUG("Memory reallocation Failed\n");
        kfree(data_ptr);
        mutex_unlock(&dev->mutex);
        return retval;
    }

    dev->entry.buffptr = new_data_ptr;

    // Cast away const qualifier
    memcpy(dev->entry.buffptr + prev_length, (void *)data_ptr, pos);

    if (rec_complete) {
        const char *ret_ptr = aesd_circular_buffer_add_entry(&dev->buffer, &dev->entry);
        if (ret_ptr != NULL) {
            kfree(ret_ptr);
        }
    }

    mutex_unlock(&dev->mutex);
    kfree(data_ptr);
    return pos;
}


struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add (&dev->cdev, devno, 1);
    if (err) {
        printk(KERN_ERR "Error %d adding aesd cdev", err);
    }
    return err;
}



int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;
    result = alloc_chrdev_region(&dev, aesd_minor, 1,
            "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0) {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    memset(&aesd_device,0,sizeof(struct aesd_dev));
	aesd_circular_buffer_init(&aesd_device.buffer);
	mutex_init(&aesd_device.mutex);


    result = aesd_setup_cdev(&aesd_device);

    if( result ) {
        unregister_chrdev_region(dev, 1);
    }
    return result;

}

void aesd_cleanup_module(void)
{
    dev_t devno = MKDEV(aesd_major, aesd_minor);

    cdev_del(&aesd_device.cdev);
struct aesd_buffer_entry *entry;
uint8_t index = 0;
AESD_CIRCULAR_BUFFER_FOREACH(entry, &aesd_device.buffer, index){
kfree(entry->buffptr);
}

mutex_destroy(&aesd_device.mutex);

    unregister_chrdev_region(devno, 1);
}



module_init(aesd_init_module);
module_exit(aesd_cleanup_module);

