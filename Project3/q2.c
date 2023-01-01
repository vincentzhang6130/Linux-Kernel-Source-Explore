#include <stdio.h>
#include <unistd.h>
#include <syscall.h>
#define NUMBER_OF_IO_ITERATIONS 6
#define NUMBER_OF_ITERATIONS 99999999


#define __NR_get_number_of_context_switches 440
#define __NR_get_number_of_entering_a_wait_queue 441

int main ()
{
	char         c;
	int          i,t=2,u=3,v;
	unsigned int w;

	for(i=0; i<NUMBER_OF_IO_ITERATIONS; i++)
	{
		v=1;
		c = getchar();
	}

	for(i=0; i<NUMBER_OF_ITERATIONS; i++)
		v=(++t)*(u++);


	long syscall_result_get_cs_n = syscall(__NR_get_number_of_context_switches, &w);
	
	if(syscall_result_get_cs_n)
		printf("Error (1)!\n");
	else
		printf("This process encounters %u times context switches.\n", w);
	
	long syscall_result_get_wq_n = syscall(__NR_get_number_of_entering_a_wait_queue, &w);
	
	if(syscall_result_get_wq_n)
		printf("Error (2)!\n");
	else
		printf("This process enters a wait queue %u times.\n", w);

	for(i=0; i<NUMBER_OF_IO_ITERATIONS; i++)
	{
		v=1;
		printf("I love my home.\n");
	}

	syscall_result_get_wq_n = syscall(__NR_get_number_of_entering_a_wait_queue, &w);

	if(syscall_result_get_wq_n) 
		printf("Error (3)!\n");
	else
		printf("This process enters a wait queue %u times.\n", w);
	
	printf("pid=%d\n", getpid());
	

	return 0;
}
