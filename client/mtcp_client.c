#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include "mtcp_client.h"

/* -------------------- Global Variables -------------------- */

/* ThreadID for Sending Thread and Receiving Thread */
static pthread_t send_thread_pid;
static pthread_t recv_thread_pid;

static pthread_cond_t app_thread_sig = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t app_thread_sig_mutex = PTHREAD_MUTEX_INITIALIZER;

static pthread_cond_t send_thread_sig = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t send_thread_sig_mutex = PTHREAD_MUTEX_INITIALIZER;

static pthread_mutex_t info_mutex = PTHREAD_MUTEX_INITIALIZER;

static int connection_state = 0;
//0: not yet connected
//1: During 3-way handshake
//2: Data transmission
//3: During 4-way handshake
//4: connection ended

static int last_packet_received = 0;
//0: Initialize
//1: SYN-ACK
//2: ACK
//3: FIN-ACK

static int last_packet_sent = 0;
//0: Initialize
//1: SYN
//2: ACK
//3: DATA
//4: FIN

static int sequence_number = 0;
static char send_buf[268435453+1];
static int send_buf_len = 0;
static int send_buf_pointer = 0;
static int current_len_sent = 0;
static int sendto_error = 0;
static int timeout = 0;

struct thread_args {
  int socket_fd;
  struct sockaddr_in server_addr;
};


static void *send_thread(void *argp){
  struct thread_args *args = argp;

  int socket_fd = args->socket_fd;
  struct sockaddr_in server_addr = args->server_addr;
  unsigned int addrlen = sizeof(struct sockaddr_in);

  int four_way_handshake_finished = 0;
  int in_thread_connection_state = 0;
  char current_send_buf[1000+1];

  unsigned int seq;
  unsigned char mode;
  unsigned char buffer[4];
  unsigned char data[1024+1];

  struct timespec ts;
  struct timeval tp;
  while (four_way_handshake_finished == 0 && sendto_error == 0) {
    //Sleep for 1 Second
    gettimeofday(&tp, NULL);
    ts.tv_sec  = tp.tv_sec;
    ts.tv_nsec = tp.tv_usec * 1000;
    ts.tv_sec += 1;
    pthread_mutex_lock(&send_thread_sig_mutex);
    pthread_cond_timedwait(&send_thread_sig, &send_thread_sig_mutex, &ts);
    pthread_mutex_unlock(&send_thread_sig_mutex);

    //Check & update state
    pthread_mutex_lock(&info_mutex);
    in_thread_connection_state = connection_state;
    pthread_mutex_unlock(&info_mutex);

    //Send packet
    switch (in_thread_connection_state) {
      case 1:
        if (last_packet_received != 1) {
          //update info
          pthread_mutex_lock(&info_mutex);
          last_packet_sent = 1;
          pthread_mutex_unlock(&info_mutex);

          //send SYN
          mode = 0;
          seq = htonl(sequence_number);
          memcpy(&buffer, &seq, 4);
          buffer[0] = buffer[0] | (mode << 4);

          if (sendto(socket_fd, buffer, sizeof(buffer), 0, (struct sockaddr *) &server_addr, addrlen) < 0) {
            sendto_error = 1;

            //wake up app thread
            pthread_mutex_lock(&app_thread_sig_mutex);
            pthread_cond_signal(&app_thread_sig);
            pthread_mutex_unlock(&app_thread_sig_mutex);
          }
        } else {
          //update info
          pthread_mutex_lock(&info_mutex);
          last_packet_sent = 2;
          connection_state = 2;
          pthread_mutex_unlock(&info_mutex);

          //send ACK
          mode = 4;
          seq = htonl(sequence_number);
          memcpy(&buffer, &seq, 4);
          buffer[0] = buffer[0] | (mode << 4);

          if (sendto(socket_fd, buffer, sizeof(buffer), 0, (struct sockaddr *) &server_addr, addrlen) < 0) {
            sendto_error = 1;

            //wake up app thread
            pthread_mutex_lock(&app_thread_sig_mutex);
            pthread_cond_signal(&app_thread_sig);
            pthread_mutex_unlock(&app_thread_sig_mutex);
          } else {
            //wake up app thread
            pthread_mutex_lock(&app_thread_sig_mutex);
            pthread_cond_signal(&app_thread_sig);
            pthread_mutex_unlock(&app_thread_sig_mutex);

            //Sleep
            pthread_mutex_lock(&app_thread_sig_mutex);
            pthread_cond_wait(&app_thread_sig, &app_thread_sig_mutex);
            pthread_mutex_unlock(&app_thread_sig_mutex);
          }
        }
        break;
      case 2:
        if (send_buf_len - send_buf_pointer > 0){
          //
          pthread_mutex_lock(&info_mutex);
          if (timeout == 0){
            if (send_buf_len - send_buf_pointer <= 1000)
              current_len_sent = send_buf_len - send_buf_pointer;
            else
              current_len_sent = 1000;
          }
          pthread_mutex_unlock(&info_mutex);

          memcpy(&current_send_buf, &send_buf + send_buf_pointer, current_len_sent);

          //update info
          pthread_mutex_lock(&info_mutex);
          last_packet_sent = 3;
          timeout = 1;
          pthread_mutex_unlock(&info_mutex);

          //Send data

          mode = 5;
          seq = htonl(sequence_number);
          memcpy(&buffer, &seq, 4);
          buffer[0] = buffer[0] | (mode << 4);
          memcpy(&data, &buffer, sizeof(buffer));
          memcpy(&data + 4, &current_send_buf, current_len_sent);
          if (sendto(socket_fd, data, 4 + current_len_sent, 0, (struct sockaddr *) &server_addr, addrlen) < 0) {
            sendto_error = 1;
          }

        } else {
          //Sleep
          pthread_mutex_lock(&app_thread_sig_mutex);
          pthread_cond_wait(&app_thread_sig, &app_thread_sig_mutex);
          pthread_mutex_unlock(&app_thread_sig_mutex);
        }
        break;
      case 3:
        if (last_packet_received != 3) {
          //update info
          pthread_mutex_lock(&info_mutex);
          last_packet_sent = 4;
          pthread_mutex_unlock(&info_mutex);

          //Send FIN
          mode = 2;
          seq = htonl(sequence_number);
          memcpy(&buffer, &seq, 4);
          buffer[0] = buffer[0] | (mode << 4);

          if (sendto(socket_fd, buffer, sizeof(buffer), 0, (struct sockaddr *) &server_addr, addrlen) < 0) {
            sendto_error = 1;

            //wake up app thread
            pthread_mutex_lock(&app_thread_sig_mutex);
            pthread_cond_signal(&app_thread_sig);
            pthread_mutex_unlock(&app_thread_sig_mutex);
          }
        } else {
          //update info
          pthread_mutex_lock(&info_mutex);
          last_packet_sent = 2;
          pthread_mutex_unlock(&info_mutex);

          //Send ACK
          mode = 4;
          seq = htonl(sequence_number);
          memcpy(&buffer, &seq, 4);
          buffer[0] = buffer[0] | (mode << 4);

          if (sendto(socket_fd, buffer, sizeof(buffer), 0, (struct sockaddr *) &server_addr, addrlen) < 0) {
            sendto_error = 1;
          }

          //wake up app thread
          pthread_mutex_lock(&app_thread_sig_mutex);
          pthread_cond_signal(&app_thread_sig);
          pthread_mutex_unlock(&app_thread_sig_mutex);

          //Terminate itself
          four_way_handshake_finished = 1;
        }
        break;
    }
  }
  return 0;
}

static void *receive_thread(void *argp){
  struct thread_args *args = argp;

  int socket_fd = args->socket_fd;

  int four_way_handshake_finished = 0;

  unsigned int rev_seq;
  unsigned char mode;
  unsigned char header[4];
  while (four_way_handshake_finished == 0 && sendto_error == 0) {
    //Monitor socket
    recvfrom(socket_fd, header, 4, 0, NULL, NULL);

    mode = header[0] >> 4;
    header[0] = header[0] & 0x0F;
    memcpy(&rev_seq, header, 4);
    rev_seq = ntohl(rev_seq);

    last_packet_received = mode;

    //Check & update state
    pthread_mutex_lock(&info_mutex);

    switch (connection_state) {
      case 1:
        if (last_packet_received == 1 && rev_seq == 1) {
          sequence_number++;
          pthread_mutex_lock(&send_thread_sig_mutex);
          pthread_cond_signal(&send_thread_sig);
          pthread_mutex_unlock(&send_thread_sig_mutex);
        }
        break;
      case 2:
        if (last_packet_received == 2 && rev_seq == sequence_number + current_len_sent) {
          timeout = 0;
          sequence_number += current_len_sent;
          send_buf_pointer += current_len_sent;
          pthread_mutex_lock(&send_thread_sig_mutex);
          pthread_cond_signal(&send_thread_sig);
          pthread_mutex_unlock(&send_thread_sig_mutex);
        }
        break;
      case 3:
        if (last_packet_received == 3 && rev_seq == sequence_number + 1) {
          sequence_number++;
          pthread_mutex_lock(&send_thread_sig_mutex);
          pthread_cond_signal(&send_thread_sig);
          pthread_mutex_unlock(&send_thread_sig_mutex);

          //Terminate itself
          four_way_handshake_finished = 1;
        }
        break;
    }

    pthread_mutex_unlock(&info_mutex);
  }
  return 0;
}

/* Connect Function Call (mtcp Version) */
void mtcp_connect(int socket_fd, struct sockaddr_in *server_addr){
//You should finish the implementation of this function in the μTCP protocol API such that it can act like connect() of a typical socket programming API. It starts a μTCP connection and performs the 3-way handshake. Moreover, it is a blocking call and will not stop until the 3-way handshake is complete.

  //Intialize mutexs
  pthread_mutex_init(&app_thread_sig_mutex, NULL);
  pthread_mutex_init(&send_thread_sig_mutex, NULL);
  pthread_mutex_init(&info_mutex, NULL);

  struct thread_args *args = malloc(sizeof *args);
  args->socket_fd = socket_fd;
  args->server_addr = *server_addr;

  //Create and Start Sending Thread
  pthread_create(&send_thread_pid, NULL, send_thread, args);

  //Create and Start Receiving Thread
  pthread_create(&recv_thread_pid, NULL, receive_thread, args);

  //Update Global Variable
  pthread_mutex_lock(&info_mutex);
  connection_state = 1;
  pthread_mutex_unlock(&info_mutex);

  //Wake Up Sending Thread
  //if sending thread is sleeping
  pthread_mutex_lock(&send_thread_sig_mutex);
  pthread_cond_signal(&send_thread_sig);
  pthread_mutex_unlock(&send_thread_sig_mutex);

  //Sleep
  pthread_mutex_lock(&app_thread_sig_mutex);
  pthread_cond_wait(&app_thread_sig, &app_thread_sig_mutex);
  pthread_mutex_unlock(&app_thread_sig_mutex);

  if (sendto_error == 1) {
    pthread_join(send_thread_pid, NULL);
    pthread_join(recv_thread_pid, NULL);
  }

  return;
}

/* Write Function Call (mtcp Version) */
int mtcp_write(int socket_fd, unsigned char *buf, int buf_len){
//You should finish the implementation of this function in the μTCP protocol API such that it can act like write() of a typical socket programming API. When mtcp_write() is invoked, new application data will be copied to the send buffer of the μTCP layer (see Figure 2). Then, the call returns. Meanwhile, the μTCP layer then asynchronously sends the data to the server side.

  if (connection_state != 2 || sendto_error == 1) return -1;

  //write data to mTCP internal buffer
  memcpy(&send_buf+send_buf_len, &buf, buf_len);
  send_buf_len += buf_len;

  //Wake Up Sending Thread
  //if sending thread is sleeping
  pthread_mutex_lock(&send_thread_sig_mutex);
  pthread_cond_signal(&send_thread_sig);
  pthread_mutex_unlock(&send_thread_sig_mutex);

  return buf_len;
}

/* Close Function Call (mtcp Version) */
void mtcp_close(int socket_fd){
//You should finish the implementation of this function in the μTCP protocol API such that it can act like close() of a typical socket programming API. If the connection is not closed, it starts the 4-way handshake. Otherwise, it does nothing. Note that you can safely assume that the client will always invoke this call before the server in order to guarantee that it is always the client which triggers the 4-way handshake. Moreover, it is a blocking call when the connection is not closed and does not return until the 4-way handshake process has been finished. After the process is completed, both programs should close the UDP socket.

  //Update Global Variable
  pthread_mutex_lock(&info_mutex);
  connection_state = 3;
  pthread_mutex_unlock(&info_mutex);

  //Wake Up Sending Thread
  //if sending thread is sleeping
  pthread_mutex_lock(&send_thread_sig_mutex);
  pthread_cond_signal(&send_thread_sig);
  pthread_mutex_unlock(&send_thread_sig_mutex);

  //Sleep
  pthread_mutex_lock(&app_thread_sig_mutex);
  pthread_cond_wait(&app_thread_sig, &app_thread_sig_mutex);
  pthread_mutex_unlock(&app_thread_sig_mutex);

  pthread_join(send_thread_pid, NULL);
  pthread_join(recv_thread_pid, NULL);

  //Update Global Variable
  pthread_mutex_lock(&info_mutex);
  connection_state = 4;
  pthread_mutex_unlock(&info_mutex);

  return;
}