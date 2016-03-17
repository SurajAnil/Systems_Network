#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>

void sigint_handler(int sig)
{
	printf("Ouch, signal %d recvd.\n", sig);
	(void) signal(SIGINT, SIG_DFL);
}

int main()
{
	(void) signal(SIGINT, sigint_handler);
	while(1){
		printf("Hello\n");
		sleep(2);
	}


}
