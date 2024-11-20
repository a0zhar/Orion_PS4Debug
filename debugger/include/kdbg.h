#pragma once
#ifndef _KDEBUGGER_H
#define _KDEBUGGER_H

#include <ps4.h>
#include <stdarg.h>


#define SYS_PROC_ALLOC      1
#define SYS_PROC_FREE       2
#define SYS_PROC_PROTECT    3
#define SYS_PROC_VM_MAP     4
#define SYS_PROC_INSTALL    5
#define SYS_PROC_CALL       6
#define SYS_PROC_ELF        7
#define SYS_PROC_INFO       8
#define SYS_PROC_THRINFO    9

#define SYS_CONSOLE_CMD_REBOOT       1
#define SYS_CONSOLE_CMD_PRINT        2
#define SYS_CONSOLE_CMD_JAILBREAK    3

// Structure definition for process list entries
struct proc_list_entry {
    char p_comm[32]; // Command name of the process (up to 31 characters + null terminator)
    int pid;         // Process ID (PID) of the process
} __attribute__((packed));

// Structure representing arguments for allocating memory for a process
struct sys_proc_alloc_args {
    uint64_t address; // Memory address to allocate
    uint64_t length;  // Length of memory to allocate
} __attribute__((packed)); 

// Structure representing arguments for freeing memory for a process
struct sys_proc_free_args {
    uint64_t address; // Memory address to free
    uint64_t length;  // Length of memory to free
} __attribute__((packed)); 

// Structure representing arguments for protecting memory of a process
struct sys_proc_protect_args {
    uint64_t address; // Memory address to set protection on
    uint64_t length;  // Length of memory to protect
    uint64_t prot;    // Protection flags (e.g., read, write, execute)
} __attribute__((packed)); 

// Structure representing arguments for mapping a virtual memory region for a process
struct sys_proc_vm_map_args {
    struct proc_vm_map_entry* maps; // Pointer to an array of memory map entries
    uint64_t num;                    // Number of memory map entries
} __attribute__((packed)); 

// Structure representing arguments for installing a process
struct sys_proc_install_args {
    uint64_t stubentryaddr; // Address of the stub entry for the process
} __attribute__((packed)); 

// Structure representing arguments for calling a function within a process
struct sys_proc_call_args {
    uint32_t pid;         // Process ID to call the function in
    uint64_t rpcstub;     // RPC (Remote Procedure Call) stub address
    uint64_t rax;         // Value to be returned (RAX register)
    uint64_t rip;         // Instruction pointer (RIP register)
    uint64_t rdi;         // 1st argument (RDI register)
    uint64_t rsi;         // 2nd argument (RSI register)
    uint64_t rdx;         // 3rd argument (RDX register)
    uint64_t rcx;         // 4th argument (RCX register)
    uint64_t r8;          // 5th argument (R8 register)
    uint64_t r9;          // 6th argument (R9 register)
} __attribute__((packed)); 

// Structure representing arguments for processing ELF files
struct sys_proc_elf_args {
    void* elf; // Pointer to the ELF data in memory
} __attribute__((packed)); 

// Structure representing arguments for retrieving information about a process
struct sys_proc_info_args {
    int pid;                 // Process ID for which to retrieve information
    char name[40];           // Name of the process
    char path[64];           // Path to the executable of the process
    char titleid[16];        // Title ID associated with the process
    char contentid[64];      // Content ID associated with the process
} __attribute__((packed)); 

// Structure representing arguments for retrieving thread information of a process
struct sys_proc_thrinfo_args {
    uint32_t lwpid;          // process ID (LWP ID) for the thread
    uint32_t priority;       // Priority level of the thread
    char name[32];           // Name of the thread
} __attribute__((packed));


int sys_console_cmd(uint64_t cmd, void* data);
int sys_kern_base(uint64_t* kbase);
int sys_kern_rw(uint64_t address, void* data, uint64_t length, uint64_t write);
int sys_proc_cmd(uint64_t pid, uint64_t cmd, void* data);
int sys_proc_list(struct proc_list_entry* procs, uint64_t* num);
int sys_proc_rw(uint64_t pid, uint64_t address, void* data, uint64_t length, uint64_t write);

void prefault(void* address, size_t size);
void* pfmalloc(size_t size);
void hexdump(void* data, size_t size);


// Temporary! A Macro that can be used for logging purposes
// Im planning on replacing this with a function, but for now this will do.
// Supports arguments, and can be used like one would with printf
#define uprintf(fmt, ...) {                          \
    char buffer[256];                                \
    snprintf(buffer, 256, fmt, ##__VA_ARGS__);       \
    sys_console_cmd(SYS_CONSOLE_CMD_PRINT, buffer);  \
}

#endif
