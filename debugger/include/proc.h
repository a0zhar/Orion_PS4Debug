#pragma once
#ifndef _PROC_H
#define _PROC_H
#include <ps4.h>
#include <stdbool.h>
#include "protocol.h"
#include "net.h"

// Structure representing a single entry in the process's virtual memory map
struct proc_vm_map_entry {
    char name[32];       // Name of the memory region (up to 31 characters + null terminator)
    uint64_t start;      // Starting address of the memory region (inclusive)
    uint64_t end;        // Ending address of the memory region (exclusive)
    uint64_t offset;     // Offset within the memory region (used for mapping files)
    uint16_t prot;       // Protection flags for the memory region (e.g., read, write, execute)
} __attribute__((packed)); // Pack the structure to avoid padding between fields

int proc_list_handle(int fd, struct cmd_packet* packet);
int proc_read_handle(int fd, struct cmd_packet* packet);
int proc_write_handle(int fd, struct cmd_packet* packet);
int proc_maps_handle(int fd, struct cmd_packet* packet);
int proc_install_handle(int fd, struct cmd_packet* packet);
int proc_call_handle(int fd, struct cmd_packet* packet);
int proc_protect_handle(int fd, struct cmd_packet* packet);
int proc_scan_handle(int fd, struct cmd_packet* packet);
int proc_info_handle(int fd, struct cmd_packet* packet);
int proc_alloc_handle(int fd, struct cmd_packet* packet);
int proc_free_handle(int fd, struct cmd_packet* packet);
int proc_handle(int fd, struct cmd_packet* packet);

#endif
