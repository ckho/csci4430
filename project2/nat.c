#include <netinet/in.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "table.h"
#include "checksum.h"

unsigned int local_mask;
uint32_t public_ip_addr;
uint32_t internal_ip_addr;


/*
 * Callback function installed to netfilter queue
 */
static int Callback(struct nfq_q_handle *qh, struct nfgenmsg *msg,
                    struct nfq_data *pkt, void *data) {


  unsigned int id = 0;
  struct nfqnl_msg_packet_hdr *header;


  header = nfq_get_msg_packet_hdr(pkt);

  // GET Packet ID
  if (header != NULL) {
    id = ntohl(header->packet_id);
  }

  // GET Payload
  unsigned char *payload;
  int data_len = nfq_get_payload(pkt, (char**) &payload);
  // struct ip* ip_hdr = (struct ip *) payload;


  struct iphdr *iph = (struct iphdr*) payload;
  // // source IP
  // iph->saddr;
  // // destination IP
  // iph->daddr;
  // // checksum
  // iph->check;

  // CHECK if it is TCP packet
  if (iph->protocol == IPPROTO_TCP) {
    // TCP packets

    struct tcphdr *tcph = (struct tcphdr *) (((char*) iph) + (iph->ihl << 2));

    // // source port
    // tcph->source;
    // // destination port
    // tcph->dest;
    // // flags
    // tcph->syn; tcph->ack; tcph->fin; tcph->rst;
    // // checksum
    // tcph->check;

    struct table_record *record;

    // CHECK if it is INBOUND or OUTBOUND
    if ((ntohl(iph->saddr) & local_mask) == (ntohl(internal_ip_addr) & local_mask)) {
      // OUTBOUND

      // Searches if the source IP-port pair of the packet has already been stored in the translation table.
      record = table_outbound(iph->saddr, tcph->source);

      if (record) {
        //use the previously assigned port number and modifies the IP and TCP headers of the packet accordingly
        iph->saddr = htonl(public_ip_addr);
        tcph->source = htons(record->external_port);
        tcph->check = tcp_checksum((unsigned char *)iph);
        iph->check = ip_checksum((unsigned char *)iph);

        // 4-way handshake started by source
        if ((record->state == 0) && (tcph->fin)) {
          record->state = 10;
        }
        if ((record->state == 12) && (tcph->ack)) {
          record->state = 13;
          table_delete_outbound(iph->saddr, tcph->source);
          table_print();
        }
        // 4-way handshake started by destination
        if ((record->state == 20) && (tcph->ack)) {
          if (tcph->fin) {
            record->state = 22;
          } else {
            record->state = 21;
          }
        }
        if ((record->state == 21) && (tcph->fin)) {
          record->state = 22;
        }

        // RST
        if (tcph->rst) {
          table_delete_outbound(iph->saddr, tcph->source);
          table_print();
        }
        //forwards it.
        return nfq_set_verdict(qh, id, NF_ACCEPT, data_len, payload);
      } else {
        if (tcph->syn) {
          //creates a new entry in the translation table
          record = table_add(iph->saddr, tcph->source);
          table_print();
          //modifies the IP and TCP headers of the packet accordingly, and forwards it.
          iph->saddr = htonl(public_ip_addr);
          tcph->source = htons(record->external_port);
          tcph->check = tcp_checksum((unsigned char *)iph);
          iph->check = ip_checksum((unsigned char *)iph);
          return nfq_set_verdict(qh, id, NF_ACCEPT, data_len, payload);
        } else {
          // DROP Packet
          return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
        }
      }

    } else {
      // INBOUND
      record = table_inbound(tcph->dest);
      if (record) {
        //modifies the IP and TCP headers of the packet accordingly
        iph->daddr = htonl(record->internal_ip);
        tcph->dest = htons(record->internal_port);
        tcph->check = tcp_checksum((unsigned char*)iph);
        iph->check = ip_checksum((unsigned char*)iph);

        // 4-way handshake started by source
        if ((record->state == 10) && (tcph->ack)) {
          if (tcph->fin) {
            record->state = 12;
          } else {
            record->state = 11;
          }
        }
        if ((record->state == 11) && (tcph->fin)) {
          record->state = 12;
        }
        // 4-way handshake started by destination
        if ((record->state == 0) && (tcph->fin)) {
          record->state = 20;
        }
        if ((record->state == 12) && (tcph->ack)) {
          record->state = 13;
          table_delete_outbound(iph->saddr, tcph->source);
          table_print();
        }

        // RST
        if (tcph->rst) {
          table_delete_inbound(tcph->dest);
          table_print();
        }
        //and sends it to the target VM.
        return nfq_set_verdict(qh, id, NF_ACCEPT, data_len, payload);
      } else {
        // DROP Packet
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
      }
    }
  } else {
    // DROP Packet
    return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
  }
}

/*
 * Main program
 */
int main(int argc, char **argv) {
  struct nfq_handle *h;
  struct nfq_q_handle *qh;
  // struct nfnl_handle *nh;
  int fd;
  int len;
  char buf[4096];

  // Check the number of run-time argument
  if(argc != 4){
    fprintf(stderr, "Usage: %s [public ip] [internal ip] [subnet mask]\n", argv[0]);
    exit(1);
  }

  // GET public IP address
  if(inet_pton(AF_INET, (const char*) argv[1], &public_ip_addr) == 0) {
    fprintf(stderr, "\tError: Wrong public ip address format\n");
    exit(1);
  }

  // GET internal IP address
  if(inet_pton(AF_INET, (const char*) argv[2], &internal_ip_addr) == 0) {
    fprintf(stderr, "\tError: Wrong internal ip address format\n");
    exit(1);
  }

  // GET subnet mask
  local_mask = 0xffffffff << (32 - atoi(argv[3]));

  // Open library handle
  if (!(h = nfq_open())) {
    fprintf(stderr, "Error: nfq_open()\n");
    exit(-1);
  }

  // Unbind existing nf_queue handler (if any)
  if (nfq_unbind_pf(h, AF_INET) < 0) {
    fprintf(stderr, "Error: nfq_unbind_pf()\n");
    exit(1);
  }

  // Bind nfnetlink_queue as nf_queue handler of AF_INET
  if (nfq_bind_pf(h, AF_INET) < 0) {
    fprintf(stderr, "Error: nfq_bind_pf()\n");
    exit(1);
  }

  // bind socket and install a callback on queue 0
  if (!(qh = nfq_create_queue(h, 0, &Callback, NULL))) {
    fprintf(stderr, "Error: nfq_create_queue()\n");
    exit(1);
  }

  // Setting packet copy mode
  if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
    fprintf(stderr, "Could not set packet copy mode\n");
    exit(1);
  }



  fd = nfq_fd(h);

  while ((len = recv(fd, buf, sizeof(buf), 0)) && len >= 0) {
    nfq_handle_packet(h, buf, len);
  }


  printf("unbinding from queue 0\n");
  nfq_destroy_queue(qh);

  nfq_close(h);

  return 0;
}