#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "mtcp_server.h"

/* ThreadID for Sending Thread and Receiving Thread */
static pthread_t send_thread_pid;
static pthread_t recv_thread_pid;

static pthread_cond_t app_thread_sig = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t app_thread_sig_mutex = PTHREAD_MUTEX_INITIALIZER;

static pthread_cond_t send_thread_sig = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t send_thread_sig_mutex = PTHREAD_MUTEX_INITIALIZER;

static pthread_mutex_t info_mutex = PTHREAD_MUTEX_INITIALIZER;

/* The Sending Thread and Receive Thread Function */
static void *send_thread();
static void *receive_thread();

struct thread_arg {
	int socket_fd;
	struct sockaddr_in *client_addr;
}

void mtcp_accept(int socket_fd, struct sockaddr_in *client_addr){
	//Store arguments in struct
	struct thread_arg *arg = malloc(sizeof(struct thread_arg));
	(*arg).socket_fd = socket_fd;
	(*arg).client_addr = client_addr;
	//Create send and receive thread
	pthread_create(send_thread_pid,NULL,send_thread,(void *)arg);
	pthread_create(recv_thread_pid,NULL,receive_thread,(void *)arg);
	//Application thread sleep
	pthread_cond_wait(app_thread_sig,app_thread_sig_mutex);
	return;
}

int mtcp_read(int socket_fd, unsigned char *buf, int buf_len){

}

void mtcp_close(int socket_fd){

}

static void *send_thread(){
	//Sending thread sleep
	pthread_cond_wait(send_thread_sig,send_thread_sig_mutex);

}

static void *receive_thread(void *argv){
	struct thread_arg *arg = (struct thread_arg*)argv;
	int socket_fd = (*arg).socket_fd;
	struct sockaddr_in *client_addr = (*arg).client_addr;

	while(1){
		char buff[1016];
		int len;
		if((len=recv(socket_fd,buff,sizeof(buff),0))<=0){
			printf("receive error: %s (Errno:%d)\n", strerror(errno),errno);
			exit(1);
		}
		buff[len-1]='\0';
		if(strlen(buff)!=0)printf("%s\n",buff);
	}
}
