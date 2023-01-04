#include<linux/kernel.h>
#include<linux/syscalls.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/init_task.h>

SYSCALL_DEFINE0(turn_on_record) {

	current->record_state = true;
	printk(KERN_INFO "Turn on process %d Record State\n", current->pid);
	return 0;
}

