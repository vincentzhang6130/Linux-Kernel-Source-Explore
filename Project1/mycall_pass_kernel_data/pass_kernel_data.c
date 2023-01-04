#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/init_task.h>
#include <linux/syscalls.h>

struct data_segment
{
	unsigned long start_code;
	unsigned long end_code;
};


SYSCALL_DEFINE2(pass_kernel_data, pid_t, user_pid,  void*, __user user_address){


	struct data_segment my_data_segment;
	struct task_struct *task;
	for_each_process(task)
	{
		if(task->pid == user_pid)
		{
			
			my_data_segment.start_code = task->mm->start_code;
			my_data_segment.end_code = task->mm->end_code;
			copy_to_user(user_address, &my_data_segment, sizeof(struct data_segment));
			break;
		}
	}

	return 0;

}
