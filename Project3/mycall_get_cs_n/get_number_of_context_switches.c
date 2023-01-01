#include<linux/kernel.h>
#include<linux/syscalls.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/init_task.h>

SYSCALL_DEFINE1(get_number_of_context_switches, unsigned int*, count) {
    
	unsigned int answer = current->cs_count;
    printk("pid = %d ; cs_count = %u ; nvcsw = %lu ; nivcsw = %lu\n", 
           current->pid, answer, current->nvcsw, current->nivcsw);
    return -copy_to_user(count, &(answer), sizeof(unsigned int));
}

