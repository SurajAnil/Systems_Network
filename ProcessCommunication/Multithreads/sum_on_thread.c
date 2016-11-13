/*
 * sum_on_thread.c
 *
 *  Created on: Mar 27, 2016
 *      Author: suraj
 */

#include<stdio.h>
#include<stdlib.h>
#include<pthread.h>
long long sum=0;

//Function to compute the sum
void* sum_runner(void* arg){
	long long *limit_ptr= (long long*)arg;
	long long limit = *limit_ptr;

	for (long long i=0; i<=limit;i++){
		sum+=i;
	}

	pthread_exit(0);
}

int main(int argc, char **argv){
	if(argc<2){
		printf("incorrect usage, please enter all the arguments\n");
		exit(-1);
	}

	long long limit=atoll(argv[1]);
	//threadID
	pthread_t tid;


	pthread_attr_t attr;

	pthread_attr_init(&attr);

	pthread_create(&tid, &attr, (void*)sum_runner, &limit);

	//wait untill thread is done
	pthread_join(tid, NULL);

	//print the value of sum
	printf("The sum is %lld\n", sum);


}


