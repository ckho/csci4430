#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "table.h"


void table_print()
{
    struct table_record *record;

    printf("  internal IP | in. port | ex. port");


    printf("\n");

    for (record = table; record; record = record->next) {
        printf("%13s | %8u | %8u \n",
                inet_ntoa(*(struct in_addr *)&(record->internal_ip)),
                record->internal_port, record->external_port);
    }

    printf("\n");
}

uint16_t table_get_external_port() {
    uint16_t external_port = MIN_EXTERNAL_PORT;
    struct table_record *record;

    int duplicate;

    do {
        duplicate = 0;
        record = table;
        while (record) {
            if (record->external_port == external_port) {
                if (external_port < MAX_EXTERNAL_PORT) {
                    external_port++;
                    duplicate = 1;
                    break;
                } else {
                    external_port = 0;
                    break;
                }
            }

            record = record->next;
        }


    } while (duplicate);


    return external_port;
}


struct table_record *table_add(uint32_t internal_ip, uint16_t internal_port) {
    struct table_record *record;

    if ((record = (struct table_record *)malloc(sizeof(struct table_record)))
            == NULL) {
        perror("Unable to allocate a new record (No Avaiable Memory)");
        return NULL;
    }

    uint16_t external_port;
    if ((external_port = table_get_external_port()) == 0) {
        perror("Unable to allocate a new record (No Available Ports)");
        return NULL;
    }

    record->internal_ip = internal_ip;
    record->internal_port = internal_port;
    record->external_port = external_port;
    record->state = 0;

    if (table) {
        record->next = table;
        table = record;
    } else {
        table = record;
    }

    return table;
}

int table_delete_outbound(uint32_t internal_ip, uint16_t internal_port) {
    struct table_record *record = table;
    struct table_record *before = NULL;

    while (record) {
        if (record->internal_ip == internal_ip &&
                record->internal_port == internal_port) {

            if (before != NULL) {
                before->next = record->next;
            } else {
                table = record->next;
            }
            free(record);
            return 1;
        }
        before = record;
        record = record->next;
    }
    return -1;
}

int table_delete_inbound(uint16_t external_port) {
    struct table_record *record = table;
    struct table_record *before = NULL;

    while (record) {
        if (record->external_port == external_port) {

            if (before != NULL) {
                before->next = record->next;
            } else {
                table = record->next;
            }
            free(record);
            return 1;
        }
        before = record;
        record = record->next;
    }
    return -1;
}

struct table_record *table_outbound(uint32_t internal_ip, uint16_t internal_port) {
    struct table_record *record = table;

    while (record) {
        if (record->internal_ip == internal_ip &&
                record->internal_port == internal_port) {
            return record;
        }

        record = record->next;
    }

    return NULL;
}

struct table_record *table_inbound(uint16_t external_port) {
    struct table_record *record = table;

    while (record) {
        if (record->external_port == external_port) {
            return record;
        }

        record = record->next;
    }


    return NULL;
}