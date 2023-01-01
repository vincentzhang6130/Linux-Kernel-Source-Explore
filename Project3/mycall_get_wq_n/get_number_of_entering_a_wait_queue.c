#include<linux/kernel.h>
#include<linux/syscalls.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/init_task.h>

SYSCALL_DEFINE1(get_number_of_entering_a_wait_queue, unsigned int*, count) {
    
	unsigned int answer = current->wq_count;
    printk("pid = %d ; wq_count = %u", current->pid, answer);
    return -copy_to_user(count, &(answer), sizeof(unsigned int));
}
