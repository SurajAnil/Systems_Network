/*
 * sum_on_many_threads.c
 *
 *  Created on: Mar 27, 2016
 *      Author: suraj
 */

#include<stdio.h>
#include<stdlib.h>
#include<pthread.h>

struct sum_runner_struct{
	long long limit;
	long long answer;
};

//Function to compute the sum
void* sum_runner(void* arg){
	struct sum_runner_struct *arg_struct= (struct sum_runner_struct*)arg;

	long long sum=0;
	for (long long i=0; i<= arg_struct->limit;i++){
		sum+=i;
	}

	arg_struct->answer=sum;

	pthread_exit(0);
}

int main(int argc, char **argv){
	if(argc<2){
		printf("incorrect usage, please enter all the arguments\n");
		exit(-1);
	}
	int num_args=argc-1;

	struct sum_runner_struct args[num_args];

	//threadID
	pthread_t tids[num_args];
//	printf("Hello from outside of first for loop\n");
	for (int i=0; i<num_args; i++){
		args[i].limit=atoll(argv[i+1]);
		pthread_attr_t attr;
		pthread_attr_init(&attr);
//		printf("Hello from inside of first for loop\n");
		pthread_create(&tids[i], &attr, sum_runner, &args[i]);
//		printf("Hello after pthread_create inside of first for loop\n");

	}
		printf("Hello after the first for loop\n");
	//wait untill thread is done
	for(int i=0; i<num_args;i++){
//		printf("Hello from inside second for loop\n");
		pthread_join(tids[i], NULL);
		//print the value of sum
		printf("The sum is %lld\n", args[i].answer);

	}




return 0;

}



