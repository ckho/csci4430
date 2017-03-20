#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "mtcp_server.h"
#include <mtcp_common.h>

/* ThreadID for Sending Thread and Receiving Thread */
static pthread_t send_thread_pid;
static pthread_t recv_thread_pid;

static pthread_cond_t app_thread_sig = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t app_thread_sig_mutex = PTHREAD_MUTEX_INITIALIZER;

static pthread_cond_t send_thread_sig = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t send_thread_sig_mutex = PTHREAD_MUTEX_INITIALIZER;

static pthread_mutex_t info_mutex = PTHREAD_MUTEX_INITIALIZER;

static int last_packet_received = 0;
static int last_packet_sent = 0;
static int sequence_number = 0;

static int sendto_error = 0;

static char data_buf[5000];
static int buf_idx = 0;
static int packet_size = 0;
static int connection_state = 0;
//0: Three-way handshake
//1: Data transmission
//2: Four-way handshake

/* The Sending Thread and Receive Thread Function */
static void *send_thread();
static void *receive_thread();

struct thread_arg {
	int socket_fd;
	struct sockaddr_in *client_addr;
};

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
	pthread_create(&send_thread_pid,NULL,send_thread,(void *)arg);
	pthread_create(&recv_thread_pid,NULL,receive_thread,(void *)arg);

	//Application thread sleep
	pthread_mutex_lock(&app_thread_sig_mutex);
	pthread_cond_wait(&app_thread_sig,&app_thread_sig_mutex);
	pthread_mutex_unlock(&app_thread_sig_mutex);

	if (sendto_error == 1) {
    	pthread_join(send_thread_pid, NULL);
    	pthread_join(recv_thread_pid, NULL);
    	printf("Send to error\n");
  	}

	return;
}

int mtcp_read(int socket_fd, unsigned char *buf, int buf_len){
	//Application thread sleep
	pthread_mutex_lock(&app_thread_sig_mutex);
	pthread_cond_wait(&app_thread_sig,&app_thread_sig_mutex);
	pthread_mutex_unlock(&app_thread_sig_mutex);

	if(packet_size-4 < 1000){ //Size of data in buffer < 1000
		pthread_mutex_lock(&info_mutex);
		int data_size = packet_size-4;
		memcpy(buf,&data_buf[buf_idx],data_size);
		buf_idx += data_size;
		pthread_mutex_unlock(&info_mutex);
		return data_size;
	}else{ //Size of data in buffer >= 1000
		pthread_mutex_lock(&info_mutex);
		memcpy(buf,&data_buf[buf_idx],buf_len);
		buf_idx += buf_len;
		pthread_mutex_unlock(&info_mutex);
		return buf_len;
	}
}

void mtcp_close(int socket_fd){
	//Application thread sleep
	pthread_mutex_lock(&app_thread_sig_mutex);
	pthread_cond_wait(&app_thread_sig,&app_thread_sig_mutex);
	pthread_mutex_unlock(&app_thread_sig_mutex);

	//Wait sending thread and receiving thread to end
	pthread_join(send_thread_pid,NULL);
	pthread_join(recv_thread_pid,NULL);

	return;
}

static void *send_thread(void *argv){
	struct thread_arg *arg = (struct thread_arg*)argv;

	int socket_fd = (*arg).socket_fd;
	struct sockaddr_in *client_addr = (*arg).client_addr;
	unsigned int addrlen = sizeof(struct sockaddr_in);
	int state = -1;
	int last_packet = -1;
	int seq = 0;

	while(1){
		//Sending thread sleep
		pthread_mutex_lock(&send_thread_sig_mutex);
		pthread_cond_wait(&send_thread_sig,&send_thread_sig_mutex);
		pthread_mutex_unlock(&send_thread_sig_mutex);

		pthread_mutex_lock(&info_mutex);
		//Retrieve global variables
		seq = sequence_number;
		if(connection_state > -1 && connection_state < 3){
			state = connection_state;
		}
		if((last_packet_received > -1 && last_packet_received < 3) || 
			(last_packet_received > 3 && last_packet_received <= 5)){
			last_packet = last_packet_received;
		}
		pthread_mutex_unlock(&info_mutex);

		if(state == 0){
			//Three-way handshake
			if(last_packet == 0){//SYN received
				//Send SYN-ACK
				unsigned char mode;
				unsigned char buffer[4];
				//Construct mtcp header
				mode = '1';
				seq += 1;
				seq = htonl(seq);
				memcpy(buffer,&seq,4);
				buffer[0] = buffer[0] | (mode << 4);

				if (sendto(socket_fd, buffer, sizeof(buffer), 0, (struct sockaddr *) &client_addr, addrlen) < 0) {
			        sendto_error = 1;
			        printf("Send error\n");
			        exit(1);
			    }else{
			    	//Update info
			    	pthread_mutex_lock(&info_mutex);
			    	last_packet_sent = 1;
			    	pthread_mutex_unlock(&info_mutex);
			    	//Sending thread sleep
			    	pthread_mutex_lock(&send_thread_sig_mutex);
			    	pthread_cond_wait(&send_thread_sig,&send_thread_sig_mutex);
			    	pthread_mutex_unlock(&send_thread_sig_mutex);
			    }
			}else if(last_packet == 4){//ACK received
				//Update info
				pthread_mutex_lock(&info_mutex);
				connection_state = 1;
				pthread_mutex_unlock(&info_mutex);
				//Wake up application thread
				pthread_mutex_lock(&app_thread_sig_mutex);
				pthread_cond_signal(&app_thread_sig);
				pthread_mutex_unlock(&app_thread_sig_mutex);

			}else{
				printf("Error while three-way handshake\n");
			}
		}else if(state == 1){
			//Data transmission
			//Send ACK
			unsigned char mode;
			unsigned char buffer[4];
			//Construct mtcp header
			mode = '4';
			pthread_mutex_lock(&info_mutex);
			seq += packet_size - 4;
			pthread_mutex_unlock(&info_mutex);
			seq = htonl(seq);
			memcpy(buffer,&seq,4);
			buffer[0] = buffer[0] | (mode << 4);

			if (sendto(socket_fd, buffer, sizeof(buffer), 0, (struct sockaddr *) &client_addr, addrlen) < 0) {
		        sendto_error = 1;
		        printf("Send error\n");
		        exit(1);
			}

			//Update info
			pthread_mutex_lock(&info_mutex);
			last_packet_sent = 4;
			pthread_mutex_unlock(&info_mutex);
			//Wake up application thread
			pthread_mutex_lock(&app_thread_sig_mutex);
			pthread_cond_signal(&app_thread_sig);
			pthread_mutex_unlock(&app_thread_sig_mutex);
		}else if(state == 2){
			//Four-way handshake
			if(last_packet == 2){
				//Send FIN-ACK
				unsigned char mode;
				unsigned char buffer[4];
				//Construct mtcp header
				mode = '3';
				seq += 1;
				seq = htonl(seq);
				memcpy(buffer,&seq,4);
				buffer[0] = buffer[0] | (mode << 4);

				if (sendto(socket_fd, buffer, sizeof(buffer), 0, (struct sockaddr *) &client_addr, addrlen) < 0) {
			        sendto_error = 1;
			        printf("Send error\n");
			        exit(1);
				}	

				//Update info
				pthread_mutex_lock(&info_mutex);
				last_packet_sent = 3;
				pthread_mutex_unlock(&info_mutex);
				//Wake up application thread
				pthread_mutex_lock(&app_thread_sig_mutex);
				pthread_cond_signal(&app_thread_sig);
				pthread_mutex_unlock(&app_thread_sig_mutex);
			}else if(last_packet == 4){
				pthread_mutex_lock(&info_mutex);
				last_packet_received = 4;
				pthread_mutex_unlock(&info_mutex);
				//Wake up application thread
				pthread_mutex_lock(&app_thread_sig_mutex);
				pthread_cond_signal(&app_thread_sig);
				pthread_mutex_unlock(&app_thread_sig_mutex);
			}
		}else{
			printf("State error\n");
		}
	}
}

static void *receive_thread(void *argv){
	struct thread_arg *arg = (struct thread_arg*)argv;
	int socket_fd = (*arg).socket_fd;
	struct sockaddr_in *client_addr = (*arg).client_addr;
	socklen_t addrlen = sizeof(client_addr);

	while(1){
	  	unsigned int seq;
	  	unsigned char mode;
	  	unsigned char buffer[1000+4];

	  	//Monitor for packet
	  	pthread_mutex_lock(&info_mutex);
	  	packet_size = recvfrom(socket_fd,buffer,sizeof(buffer),0,(struct sockaddr*)&client_addr,&addrlen);
	  	pthread_mutex_unlock(&info_mutex);

	  	if(packet_size < 0){
	  		printf("Receive error");
	  		exit(1);
	  	}

	  	//Extract mtcp header
		mode = buffer[0] >> 4;
		buffer[0] = buffer[0] & 0x0F;
		memcpy(&seq,buffer,4);
		seq = ntohl(seq);

	  	switch(mode){
	  		//SYN
	  		case 0:
	  			//Update info
	  			pthread_mutex_lock(&info_mutex);
	  			last_packet_received = 0;
	  			connection_state = 0;
	  			pthread_mutex_unlock(&info_mutex);
	  			//Wake up sending thread
	  			pthread_mutex_lock(&send_thread_sig_mutex);
	  			pthread_cond_signal(&send_thread_sig);
	  			pthread_mutex_unlock(&send_thread_sig_mutex);
	  			break;
	  		//FIN
	  		case 2:
	  			//Update info
	  			pthread_mutex_lock(&info_mutex);
	  			last_packet_received = 2;
	  			connection_state = 2;
	  			sequence_number = seq;
	  			pthread_mutex_unlock(&info_mutex);
	  			//Wake up sending thread
	  			pthread_mutex_lock(&send_thread_sig_mutex);
	  			pthread_cond_signal(&send_thread_sig);
	  			pthread_mutex_unlock(&send_thread_sig_mutex);
	  			break;
	  		//ACK
	  		case 4:
		  		//Update info
		  		pthread_mutex_lock(&info_mutex);
		  		last_packet_received = 4;
		  		pthread_mutex_unlock(&info_mutex);
		  		//Wake up sending thread
		  		pthread_mutex_lock(&send_thread_sig_mutex);
		  		pthread_cond_signal(&send_thread_sig);
		  		pthread_mutex_unlock(&send_thread_sig_mutex);
		  		break;
		  	//DATA
		  	case 5:
		  		//Update info
		  		pthread_mutex_lock(&info_mutex);
		  		last_packet_received = 5;
		  		if(seq > sequence_number){
		  			sequence_number = seq;
		  			memcpy(&data_buf[seq-1],&buffer[4],packet_size-4);
		  		}
		  		pthread_mutex_unlock(&info_mutex);
		  		//Wake up sending thread
		  		pthread_mutex_lock(&send_thread_sig_mutex);
		  		pthread_cond_signal(&send_thread_sig);
		  		pthread_mutex_unlock(&send_thread_sig_mutex);
		  		break;
		  	default:
		  		printf("Receive error\n");
	  	}

	  	if(connection_state == 2){
	  		if(last_packet_received == 4){
	  			//Connection close
	  			break;
	  		}
	  	}
	}

	return 0;
}
