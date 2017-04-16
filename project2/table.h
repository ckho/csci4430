#include <linux/types.h>

#define MIN_EXTERNAL_PORT 10000
#define MAX_EXTERNAL_PORT 12000

struct table_record {
    uint32_t    internal_ip;
    uint16_t    internal_port;
    uint16_t    external_port;
    int         state;
    //0=normal,
    //Start by source
    //10=after FIN,
    //11=after ACK,
    //12=after 2nd FIN,
    //13=after 2nd ACK
    //Start by destination
    //20=after FIN,
    //21=after ACK,
    //22=after 2nd FIN,
    //23=after 2nd ACK
    struct table_record *next;
} *table;


void table_print();

struct table_record *table_add(uint32_t internal_ip, uint16_t internal_port);

int table_delete_outbound(uint32_t internal_ip, uint16_t internal_port);

int table_delete_inbound(uint16_t external_port);

struct table_record *table_outbound(uint32_t internal_ip, uint16_t internal_port);

struct table_record *table_inbound(uint16_t external_port);