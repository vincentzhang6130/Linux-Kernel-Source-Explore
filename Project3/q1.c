#include<stdio.h>
#include<syscall.h>
#include<unistd.h>

#define NUMBER_OF_ITERATIONS 99999999
#define __NR_get_number_of_context_switches 440 

int main(){

	int i, t=2, u=3, v;
	unsigned int w;
	for(i=0; i<NUMBER_OF_ITERATIONS; i++)
		v = (++t)*(u++);
	
	long syscallResult = syscall(__NR_get_number_of_context_switches, &w); 
	
	if(syscallResult)
		printf("Error!\n");
	else
		printf("This process encounters %u times context switches.\n",w);
	

	printf("w = %u\tsystem call result = %ld\n", w, syscallResult);
	printf("pid=%d\n", getpid());	


  	return 0;
}



