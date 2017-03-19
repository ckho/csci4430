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

static int last_packet_received = 0;
static int sequence_number = 0;

static int sendto_error = 0;

static int data_len = 0;
static char data_buf[1000];

/* The Sending Thread and Receive Thread Function */
static void *send_thread();
static void *receive_thread();

struct thread_arg {
	int socket_fd;
	struct sockaddr_in client_addr;
}

void mtcp_accept(int socket_fd, struct sockaddr_in *client_addr){
	//Initialize mutex
	pthread_mutex_init(&app_thread_sig_mutex, NULL);
  	pthread_mutex_init(&send_thread_sig_mutex, NULL);
  	pthread_mutex_init(&info_mutex, NULL);

	//Store arguments in struct
	struct thread_arg *arg = malloc(sizeof(struct thread_arg));
	(*arg).socket_fd = socket_fd;
	(*arg).client_addr = client_addr;

	//Create send and receive thread
	pthread_create(send_thread_pid,NULL,send_thread,(void *)arg);
	pthread_create(recv_thread_pid,NULL,receive_thread,(void *)arg);

	//Application thread sleep
	pthread_mutex_lock(&app_thread_sig_mutex);
	pthread_cond_wait(&app_thread_sig,&app_thread_sig_mutex);
	pthread_mutex_unlock(&app_thread_sig_mutex);

	if (sendto_error == 1) {
    	pthread_join(send_thread_pid, NULL);
    	pthread_join(recv_thread_pid, NULL);
  	}

	return;
}

int mtcp_read(int socket_fd, unsigned char *buf, int buf_len){
	//Application thread sleep
	pthread_mutex_lock(&app_thread_sig_mutex);
	pthread_cond_wait(&app_thread_sig,&app_thread_sig_mutex);
	pthread_mutex_unlock(&app_thread_sig_mutex);

	memcpy(&buf,data_buf,buf_len);
}

void mtcp_close(int socket_fd){

}

static void *send_thread(){
	struct thread_arg *arg = (struct thread_arg*)argv;
	int socket_fd = (*arg).socket_fd;
	struct sockaddr_in client_addr = (*arg).client_addr;
	unsigned int addrlen = sizeof(struct sockaddr_in);

	//Sending thread sleep
	pthread_mutex_lock(&send_thread_sig_mutex);
	pthread_cond_wait(&send_thread_sig,&send_thread_sig_mutex);
	pthread_mutex_unlock(&send_thread_sig_mutex);

	//Send SYN-ACK
	unsigned int seq;
  	unsigned char mode;
  	unsigned char buffer[4];

  	mode = 1;
  	seq = htonl(sequence_number);
  	memcpy(buffer,&seq,4);
  	buffer[0] = buffer[0] | (mode << 4);

  	if (sendto(socket_fd, buffer, sizeof(buffer), 0, (struct sockaddr *) &client_addr, addrlen) < 0) {
        sendto_error = 1;

        //wake up app thread
        pthread_mutex_lock(&app_thread_sig_mutex);
        pthread_cond_signal(&app_thread_sig);
        pthread_mutex_unlock(&app_thread_sig_mutex);
    }else{
    	//Sending thread sleep
    	pthread_mutex_lock(&send_thread_sig_mutex);
    	pthread_cond_wait(&send_thread_sig,&send_thread_sig_mutex);
    	pthread_mutex_unlock(&send_thread_sig_mutex);
    }

  	mode = 4;
  	seq = htonl(sequence_number+data_len);
  	memcpy(buffer,&seq,4);
  	buffer[0] = buffer[0] | (mode << 4);

  	if (sendto(socket_fd, buffer, sizeof(buffer), 0, (struct sockaddr *) &client_addr, addrlen) < 0) {
        sendto_error = 1;
    }

    //wake up app thread
    pthread_mutex_lock(&app_thread_sig_mutex);
    pthread_cond_signal(&app_thread_sig);
    pthread_mutex_unlock(&app_thread_sig_mutex);

    //Sending thread sleep
    pthread_mutex_lock(&send_thread_sig_mutex);
    pthread_cond_wait(&send_thread_sig,&send_thread_sig_mutex);
    pthread_mutex_unlock(&send_thread_sig_mutex);
}

static void *receive_thread(void *argv){
	struct thread_arg *arg = (struct thread_arg*)argv;
	int socket_fd = (*arg).socket_fd;
	struct sockaddr_in client_addr = (*arg).client_addr;

	int connection_state = 0;
	//0: Three-way handshake
	//1: Data transmission
	//2: Four-way handshake

  	unsigned int seq;
  	unsigned char mode;
  	unsigned char buffer[4];
  	unsigned char data[1024+1];

	while(connection_state == 0){
		//Monitor for SYN/ACK
		recvFrom(socket_fd,buffer,4,0,NULL,NULL);

		mode = buffer[0] >> 4;
		buffer[0] = buffer[0] & 0x0F;
		memcpy(&seq,buffer,4);
		seq = ntohl(seq);

		last_packet_received = mode;
		sequence_number = seq;

		//Receive SYN/ACK
		if(mode == 0){
			//Wake up sending thread
			pthread_mutex_lock(&send_thread_sig_mutex);
			pthread_cond_signal(&send_thread_sig);
			pthread_mutex_unlock(&send_thread_sig_mutex);
		}else if(mode == 4){
			//Wake up application thread
			pthread_mutex_lock(&app_thread_sig_mutex);
			pthread_cond_signal(&app_thread_sig);
			pthread_mutex_unlock(&app_thread_sig_mutex);
			connection_state = 1;
		}
	}

	while(connection_state == 1){
		//Monitor for DATA
		int len = recvFrom(socket_fd,data,sizeof(data),0,NULL,NULL);

		mode = data[0] >> 4;
		data[0] = data[0] & 0x0F;
		memcpy(&seq,data,4);
		seq = ntohl(seq);

		last_packet_received = mode;
		sequence_number = seq;

		len -= 4;
		data_len = len;

		if(mode == 5){
			//Wake up sending thread
			pthread_mutex_lock(&send_thread_sig_mutex);
			pthread_cond_signal(&send_thread_sig);
			pthread_mutex_unlock(&send_thread_sig_mutex);

			//Get data part

			memcpy(&data_buf,data,data_len);
		}
	}
}
