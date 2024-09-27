// SPDX-License-Identifier: GPL-2.0-only
/*
 * This module emits "Hello, world" on printk when loaded.
 *
 * It is designed to be used for basic evaluation of the module loading
 * subsystem (for example when validating module signing/verification). It
 * lacks any extra dependencies, and will not normally be loaded by the
 * system unless explicitly requested by name.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/proc_fs.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/time.h>
#include <linux/jiffies.h>
#include <linux/workqueue.h>
#include <linux/mutex.h>
#include "mp1_given.h"

// !!!!!!!!!!!!! IMPORTANT !!!!!!!!!!!!!
// Please put your name and email here
MODULE_AUTHOR("Manvik Nanda <mbnanda2@illinois.edu>");
MODULE_LICENSE("GPL");

/* Implement WorkQueue */
static struct workqueue_struct *my_wq;
struct work_struct work;
void work_handler(struct work_struct *work);
// Define Mutex for Linked List
static DEFINE_MUTEX(list_lock);

/* Implementing the Proc FIle */
#define PROC_DIRNAME "mp1"
#define PROC_FILENAME "status"
struct proc_dir_entry *my_proc_dir;
struct proc_dir_entry *my_proc_file;
// Define the Kernel Linked List
struct myliststruct {
    int pid;
	unsigned long cpu_time;
    struct list_head mylist;
};
static LIST_HEAD(list_of_processes);

static ssize_t mywrite(struct file *file, const char __user *ubuf,size_t count, loff_t *ppos) 
{
	int pid; 
	char *kbuf;
	struct myliststruct *tmp;

	kbuf = kmalloc(count + 1, GFP_KERNEL);
	kbuf[count] = '\0';
	if(copy_from_user(kbuf,ubuf,count))
		return -EFAULT;

	if (kstrtoint(kbuf, 10, &pid) == 0) {
        printk(KERN_DEBUG "Converted PID: %d\n", pid);
    } else {
        printk(KERN_ERR "Invalid PID format\n");
        return -EINVAL;
    }
	/* Adding the pid to the process Linked List  */
	tmp = kmalloc(sizeof(struct myliststruct), GFP_KERNEL);
	tmp->pid = pid;
	list_add_tail(&tmp->mylist, &list_of_processes);
	kfree(kbuf);
	return count;
}
static ssize_t myread(struct file *file, char __user *ubuf,size_t count, loff_t *ppos) 
{
	struct myliststruct *entry;
    struct list_head *pos_iter;
    char *output_buffer;
    size_t output_size = 0;
    ssize_t ret;

    // Calculate the output size needed
    list_for_each(pos_iter, &list_of_processes) {
        entry = list_entry(pos_iter, struct myliststruct, mylist);
        output_size += snprintf(NULL, 0, "%d: %lu seconds\n", entry->pid, (entry->cpu_time)/HZ);
    }

    // Allocate memory for the output buffer
    output_buffer = kmalloc(output_size + 1, GFP_KERNEL);
    if (!output_buffer) {
        return -ENOMEM;
    }

    // Fill the output buffer with the process data
    output_buffer[0] = '\0';
    list_for_each(pos_iter, &list_of_processes) {
        entry = list_entry(pos_iter, struct myliststruct, mylist);
        snprintf(output_buffer + strlen(output_buffer), output_size - strlen(output_buffer), 
                 "%d: %lu\n", entry->pid, entry->cpu_time);
    }

    // Copy the output buffer to user space
    ret = simple_read_from_buffer(ubuf, count, ppos, output_buffer, output_size);
    
    kfree(output_buffer); // Free the allocated memory
    return ret;
}
static struct proc_ops myops = 
{
	.proc_read = myread,
	.proc_write = mywrite,
};

/* Implementing TIMER */
static struct timer_list my_timer;
static void timer_handler(struct timer_list *t)
{
	if (my_wq) {
	queue_work(my_wq, &work);
	}
	mod_timer(&my_timer, jiffies + 5 * HZ);

}

void work_handler(struct work_struct *work) {
	struct myliststruct *tmp, *next;
	long unsigned cpu_value;
    int result;

    // Lock the linked list to ensure safe access
    mutex_lock(&list_lock);

    // Iterate through the linked list
    list_for_each_entry_safe(tmp, next, &list_of_processes, mylist) {
        result = get_cpu_use(tmp->pid, &cpu_value);
        // printk("CPU USAGE TIME: %lu\n", cpu_value);
        if (result == 0) {
            // Update the CPU time for this process
            tmp->cpu_time = cpu_value;
        } else if (result == -1) {
            // Process has terminated, remove from the list
            list_del(&tmp->mylist);
            kfree(tmp);
        }
    }

    // Unlock the linked list after accessing it
    mutex_unlock(&list_lock);

}

static int __init test_module_init(void)
{
	/* Creating a proc file */ 
	my_proc_dir = proc_mkdir(PROC_DIRNAME, NULL);
	if(!my_proc_dir){
		printk("Failed to create directory /proc/%s", PROC_DIRNAME);
		return -ENOMEM;
	}
	my_proc_file = proc_create(PROC_FILENAME, 0666 , my_proc_dir, &myops);
	if(!my_proc_file){
		printk("Failed to create file /proc/mp1/%s", PROC_FILENAME);
		return -ENOMEM;
	}
	printk("Created file /proc/mp1/status");

	/* Initialize Timer */
    timer_setup(&my_timer, timer_handler, 0);

    // Set the timer to expire 5 seconds from now
    mod_timer(&my_timer, jiffies + 5 * HZ);

	/* WorkQueue */
	my_wq = alloc_workqueue("my_custom_wq", WQ_UNBOUND | WQ_HIGHPRI, 0);
    if (!my_wq) {
        printk(KERN_ERR "Failed to allocate custom workqueue\n");
        return -ENOMEM; 
    }
    // Initialize the work structure
    INIT_WORK(&work, work_handler);

	return 0;
}

module_init(test_module_init);

static void __exit test_module_exit(void)
{
	struct myliststruct *tmp, *next;

	printk("Removing file /proc/mp1/status");
	proc_remove(my_proc_file);
	proc_remove(my_proc_dir);
	del_timer(&my_timer);
	flush_workqueue(my_wq);
	destroy_workqueue(my_wq);

	// Free up the linked list 
	list_for_each_entry_safe(tmp, next, &list_of_processes, mylist){
		list_del(&tmp->mylist);
		kfree(tmp);
	}
	pr_warn("Goodbye\n");
}

module_exit(test_module_exit);
