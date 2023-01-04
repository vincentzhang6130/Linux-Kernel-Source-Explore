#include<syscall.h>
#include<sys/types.h>
#include<stdio.h>
#include<unistd.h>
#include<time.h>

struct data_segment{

	unsigned long start_code;
	unsigned long end_code;

};

#define __NR_pass_kernel_data 443


int main(){

	struct data_segment my_data_segment;
	//用system call 從 kernel space 中傳出這個process的 code段的起始與結束address
	int a = syscall(__NR_pass_kernel_data,  getpid(), (void*)&my_data_segment);

	printf("Start: %lx\nEnd: %lx\n", my_data_segment.start_code, my_data_segment.end_code);

	return 0;
}


