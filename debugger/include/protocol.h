#pragma once
#ifndef _PROTOCOL_H
#define _PROTOCOL_H

#include "errno.h"
#include "kdbg.h"

// Defines the packet version and magic number
#define PACKET_VERSION          "1.2"
#define PACKET_MAGIC            0xFFAABBCC

// Command definitions
#define CMD_VERSION             0xBD000001

// Remote Process management commands
#define CMD_PROC_LIST           0xBDAA0001 // To list processes
#define CMD_PROC_READ           0xBDAA0002 // To read process memory
#define CMD_PROC_WRITE          0xBDAA0003 // To write to process memory
#define CMD_PROC_MAPS           0xBDAA0004 // To retrieve process memory maps
#define CMD_PROC_INSTALL        0xBDAA0005 // To install a process
#define CMD_PROC_CALL           0xBDAA0006 // To call a function in a process
#define CMD_PROC_ELF            0xBDAA0007 // Related to Elf's
#define CMD_PROC_PROTECT        0xBDAA0008 // To change memory protection
#define CMD_PROC_SCAN           0xBDAA0009 // To scan process memory
#define CMD_PROC_INFO           0xBDAA000A // To get process info
#define CMD_PROC_ALLOC          0xBDAA000B // To allocate memory in a process
#define CMD_PROC_FREE           0xBDAA000C // To free memory in a process

// Remote Debugger (Debugging) Commands:
// PS4Debug uses these to figure out which debugger function to run, upon 
// recieving a command code sent from the Remote Client-PC (PS4Cheater) 
#define CMD_DEBUG_ATTACH        0xBDBB0001 // To attach debugger to a process
#define CMD_DEBUG_DETACH        0xBDBB0002 // To detach the debugger
#define CMD_DEBUG_BREAKPT       0xBDBB0003 // To set a breakpoint
#define CMD_DEBUG_WATCHPT       0xBDBB0004 // To set a watchpoint
#define CMD_DEBUG_THREADS       0xBDBB0005 // To list threads
#define CMD_DEBUG_STOPTHR       0xBDBB0006 // To stop a thread
#define CMD_DEBUG_RESUMETHR     0xBDBB0007 // To resume a thread
#define CMD_DEBUG_GETREGS       0xBDBB0008 // To get registers of a thread
#define CMD_DEBUG_SETREGS       0xBDBB0009 // To set registers of a thread
#define CMD_DEBUG_GETFPREGS     0xBDBB000A // To get floating-point registers
#define CMD_DEBUG_SETFPREGS     0xBDBB000B // To set floating-point registers
#define CMD_DEBUG_GETDBGREGS    0xBDBB000C // To get debug registers
#define CMD_DEBUG_SETDBGREGS    0xBDBB000D // To set debug registers
#define CMD_DEBUG_STOPGO        0xBDBB0010 // To stop and go a thread
#define CMD_DEBUG_THRINFO       0xBDBB0011 // To get thread information
#define CMD_DEBUG_SINGLESTEP    0xBDBB0012 // To enable single-stepping

// Kernel-related commands
#define CMD_KERN_BASE           0xBDCC0001 // Command to get kernel base
#define CMD_KERN_READ           0xBDCC0002 // Command to read from kernel memory
#define CMD_KERN_WRITE          0xBDCC0003 // Command to write to kernel memory

// Console-related commands
#define CMD_CONSOLE_REBOOT      0xBDDD0001 // Command to reboot the console
#define CMD_CONSOLE_END         0xBDDD0002 // Command to end the console process
#define CMD_CONSOLE_PRINT       0xBDDD0003 // Command to print to console
#define CMD_CONSOLE_NOTIFY      0xBDDD0004 // Command to notify the console
#define CMD_CONSOLE_INFO        0xBDDD0005 // Command to get console info

// Command validation macros
#define VALID_CMD(cmd)          (((cmd & 0xFF000000) >> 24) == 0xBD)
#define VALID_PROC_CMD(cmd)     (((cmd & 0x00FF0000) >> 16) == 0xAA)
#define VALID_DEBUG_CMD(cmd)    (((cmd & 0x00FF0000) >> 16) == 0xBB)
#define VALID_KERN_CMD(cmd)     (((cmd & 0x00FF0000) >> 16) == 0xCC)
#define VALID_CONSOLE_CMD(cmd)  (((cmd & 0x00FF0000) >> 16) == 0xDD)

// Command status codes
#define CMD_SUCCESS              0x80000000 // Command executed successfully
#define CMD_ERROR                0xF0000001 // Command execution error
#define CMD_TOO_MUCH_DATA        0xF0000002 // Too much data passed to command
#define CMD_DATA_NULL            0xF0000003 // Null data passed to command
#define CMD_ALREADY_DEBUG        0xF0000004 // Already in debug mode
#define CMD_INVALID_INDEX        0xF0000005 // Invalid index for command

// Macro to determine if command indicates a fatal status
#define CMD_FATAL_STATUS(s) ((s >> 28) == 15)
// Maximum number of breakpoints and watchpoints
#define MAX_BREAKPOINTS 30 // Maximum number of breakpoints
#define MAX_WATCHPOINTS 4  // Maximum number of watchpoints


// Command size definitions
#define CMD_PACKET_SIZE                   12  // Size of command packet
#define CMD_PROC_READ_PACKET_SIZE         16  // Size of read packet
#define CMD_PROC_WRITE_PACKET_SIZE        16  // Size of write packet
#define CMD_PROC_MAPS_PACKET_SIZE         4   // Size of maps packet
#define CMD_PROC_INSTALL_PACKET_SIZE      4   // Size of install packet
#define CMD_PROC_INSTALL_RESPONSE_SIZE    8   // Size of install response
#define CMD_PROC_CALL_PACKET_SIZE         68  // Size of call packet
#define CMD_PROC_CALL_RESPONSE_SIZE       12  // Size of call response
#define CMD_PROC_ELF_PACKET_SIZE          8   // Size of ELF packet
#define CMD_PROC_PROTECT_PACKET_SIZE      20  // Size of protect packet
#define CMD_PROC_SCAN_PACKET_SIZE         10  // Size of scan packet
#define CMD_PROC_INFO_PACKET_SIZE         4   // Size of info packet
#define CMD_PROC_INFO_RESPONSE_SIZE       188 // Size of info response
#define CMD_PROC_ALLOC_PACKET_SIZE        8   // Size of allocation packet
#define CMD_PROC_ALLOC_RESPONSE_SIZE      8   // Size of allocation response
#define CMD_DEBUG_ATTACH_PACKET_SIZE      4   // Size of attach packet
#define CMD_DEBUG_BREAKPT_PACKET_SIZE     16  // Size of breakpoint packet
#define CMD_DEBUG_WATCHPT_PACKET_SIZE     24  // Size of watchpoint packet
#define CMD_DEBUG_STOPTHR_PACKET_SIZE     4   // Size of stop thread packet
#define CMD_DEBUG_RESUMETHR_PACKET_SIZE   4   // Size of resume thread packet
#define CMD_DEBUG_GETREGS_PACKET_SIZE     4   // Size of get registers packet
#define CMD_DEBUG_SETREGS_PACKET_SIZE     8   // Size of set registers packet
#define CMD_DEBUG_STOPGO_PACKET_SIZE      4   // Size of stop/go packet
#define CMD_DEBUG_THRINFO_PACKET_SIZE     4   // Size of thread info packet
#define CMD_DEBUG_THRINFO_RESPONSE_SIZE   40  // Size of thread info response
#define CMD_KERN_READ_PACKET_SIZE         12  // Size of kernel read packet
#define CMD_KERN_WRITE_PACKET_SIZE        12  // Size of kernel write packet
#define CMD_CONSOLE_PRINT_PACKET_SIZE     4   // Size of console print packet
#define CMD_CONSOLE_NOTIFY_PACKET_SIZE    8   // Size of console notify packet
#define CMD_CONSOLE_INFO_RESPONSE_SIZE    8   // Size of console info response


// General command packet for communication between the debugger and the target process
struct cmd_packet {
    uint32_t magic;    // A magic number to identify the packet type or integrity check.
    uint32_t cmd;      // Command identifier, represents the specific action to be performed.
    uint32_t datalen;  // Length of the data that follows, helps in processing received packets.
    void *data;        // A pointer to the actual data (varies based on the command).
} __attribute__((packed));

// Used for reading data from a target process's memory
struct cmd_proc_read_packet {
    uint32_t pid;      // Process ID (PID) of the target process.
    uint64_t address;  // Memory address in the target process to start reading from.
    uint32_t length;   // The number of bytes to read from the specified address.
} __attribute__((packed));

// Used for writing data into a target process's memory
struct cmd_proc_write_packet {
    uint32_t pid;      // Process ID of the target process.
    uint64_t address;  // Memory address where the data should be written.
    uint32_t length;   // Length of the data to write.
} __attribute__((packed));

// Used to retrieve the memory mapping of the target process
struct cmd_proc_maps_packet {
    uint32_t pid;            // Process ID of the target process.
} __attribute__((packed));

// Used to install a process into the debugger's control
struct cmd_proc_install_packet {
    uint32_t pid;            // Process ID of the process to be installed for debugging.
} __attribute__((packed));

// Response sent after a process is successfully installed into the debugger
struct cmd_proc_install_response {
    uint64_t rpcstub;        // Address of the RPC stub used for interacting with the process.
} __attribute__((packed));

// Used to call a function in the target process's memory via RPC (Remote Procedure Call)
struct cmd_proc_call_packet {
    uint32_t pid;      // Process ID of the target process.
    uint64_t rpcstub;  // Address of the RPC stub to call.
    uint64_t rpc_rip;  // Return Instruction Pointer (the address of the function to call).
    uint64_t rpc_rdi;  // 1st argument for the function.
    uint64_t rpc_rsi;  // 2nd argument for the function.
    uint64_t rpc_rdx;  // 3rd argument for the function.
    uint64_t rpc_rcx;  // 4th argument for the function.
    uint64_t rpc_r8;   // 5th argument for the function.
    uint64_t rpc_r9;   // 6th argument for the function.
} __attribute__((packed));

// cmd_proc_call_response: Response sent after the RPC function call execution
struct cmd_proc_call_response {
    uint32_t pid;            // Process ID of the target process.
    uint64_t rpc_rax;        // The result of the function call (usually returned in the RAX register).
} __attribute__((packed));

// Retrieves information about the ELF binary of the target process
struct cmd_proc_elf_packet {
    uint32_t pid;            // Process ID of the target process.
    uint32_t length;         // The length of the ELF binary or the data to retrieve.
} __attribute__((packed));

// Used to change the memory protection of a given region in a target process's memory
struct cmd_proc_protect_packet {
    uint32_t pid;            // Process ID of the target process.
    uint64_t address;        // Memory address where protection is to be applied.
    uint32_t length;         // Length of the memory region to modify.
    uint32_t newprot;        // New memory protection flags (e.g., read, write, execute).
} __attribute__((packed));

// Scans the target process's memory to find a specific value
struct cmd_proc_scan_packet {
    uint32_t pid;            // Process ID of the target process.
    uint8_t valueType;       // The type of value to search for (e.g., integer, float, etc.).
    uint8_t compareType;     // The comparison method (e.g., equal, greater than).
    uint32_t lenData;        // The length of the data to search for in memory.
} __attribute__((packed));

// Retrieves information about the target process such as its name, path, and associated identifiers
struct cmd_proc_info_packet {
    uint32_t pid;            // Process ID of the target process.
} __attribute__((packed));

// Response with detailed information about the target process
struct cmd_proc_info_response {
    uint32_t pid;            // Process ID of the target process.
    char name[40];           // The name of the process (e.g., the executable name).
    char path[64];           // Path to the executable.
    char titleid[16];        // Title ID associated with the process.
    char contentid[64];      // Content ID.
} __attribute__((packed));

// Requests the allocation of memory within a target process
struct cmd_proc_alloc_packet {
    uint32_t pid;            // Process ID of the target process.
    uint32_t length;         // The amount of memory to allocate.
} __attribute__((packed));

// Response with the address of the allocated memory block for the target process
struct cmd_proc_alloc_response {
    uint64_t address;        // Address of the allocated memory region.
} __attribute__((packed));

// Requests the deallocation (free) of memory within a target process
struct cmd_proc_free_packet {
    uint32_t pid;            // Process ID of the target process.
    uint64_t address;        // Address of the memory to free.
    uint32_t length;         // Length of the memory region to free.
} __attribute__((packed));

// Attaches the debugger to a target process
struct cmd_debug_attach_packet {
    uint32_t pid;            // Process ID of the target process to attach to.
} __attribute__((packed));
 
// Sets or clears breakpoints in the target process
struct cmd_debug_breakpt_packet {
    uint32_t index;          // The index of the breakpoint.
    uint32_t enabled;        // Flag to enable or disable the breakpoint.
    uint64_t address;        // The memory address of the breakpoint.
} __attribute__((packed));

// Sets or clears watchpoints in the target process
struct cmd_debug_watchpt_packet {
    uint32_t index;          // The index of the watchpoint.
    uint32_t enabled;        // Flag to enable or disable the watchpoint.
    uint32_t length;         // The length of the memory region being watched.
    uint32_t breaktype;      // Type of watchpoint (e.g., read, write).
    uint64_t address;        // The memory address where the watchpoint is set.
} __attribute__((packed));

// Stops a specific thread in the target process for debugging purposes
struct cmd_debug_stopthr_packet {
    uint32_t lwpid;          // The ID of the thread to stop (Lightweight Process ID).
} __attribute__((packed));

// Resumes the execution of a stopped thread in the target process
struct cmd_debug_resumethr_packet {
    uint32_t lwpid;          // The ID of the thread to resume.
} __attribute__((packed));

// Requests the current state of registers for a specific thread
struct cmd_debug_getregs_packet {
    uint32_t lwpid;          // Thread ID (LWPID) for which registers are requested.
} __attribute__((packed));

// Sets the values of registers for a specific thread
struct cmd_debug_setregs_packet {
    uint32_t lwpid;          // The thread ID for which registers are set.
    uint32_t length;         // Length of the register data being set (e.g., 16 registers).
} __attribute__((packed));

// Controls the state of the debugger (stop or resume the entire process)
struct cmd_debug_stopgo_packet {
    uint32_t stop;           // A flag to indicate whether to stop or resume execution (1 for stop, 0 for resume).
} __attribute__((packed));

// Retrieves information about a specific thread in the target process
struct cmd_debug_thrinfo_packet {
    uint32_t lwpid;          // Thread ID (LWPID) for which information is requested.
} __attribute__((packed));

// Provides detailed information about a specific thread
struct cmd_debug_thrinfo_response {
    uint32_t lwpid;          // Thread ID (LWPID).
    uint32_t priority;       // The priority of the thread.
    char name[32];           // The name of the thread.
} __attribute__((packed));

// Allows reading from the kernel memory
struct cmd_kern_read_packet {
    uint64_t address;        // Memory address in the kernel to read from.
    uint32_t length;         // Length of the memory region to read.
} __attribute__((packed));

// Used for writing data into kernel memory
struct cmd_kern_write_packet {
    uint64_t address;        // Kernel memory address to write to.
    uint32_t length;         // Length of the data to write.
} __attribute__((packed));

// Prints information to the console from the target process
struct cmd_console_print_packet {
    uint32_t length;         // Length of the message to print to the console.
} __attribute__((packed));

// Sends notifications to the debugger or console
struct cmd_console_notify_packet {
    uint32_t messageType;    // Type of message (error, info, warning).
    uint32_t length;         // Length of the message data.
} __attribute__((packed));

// Contains system information related to the console, such as OS type, version, hardware details, etc
struct cmd_console_info_response {
    char kern_ostype[50];     // OS type
    char kern_osrelease[50];  // OS release version
    int kern_osrev;           // OS revision number
    char kern_version[100];   // Full kernel version string
    char hw_model[100];       // Hardware model
    int hw_ncpu;              // Number of CPUs on the hardware system
} __attribute__((packed));

// Represents a breakpoint for debugging purposes
struct debug_breakpoint {
    uint32_t enabled;   // Flag indicating whether the breakpoint is enabled.
    uint64_t address;   // Memory address where the breakpoint is set.
    uint8_t original;   // The original value at the address before setting the breakpoint.
};

// Represents a watchpoint for debugging purposes
struct debug_watchpoint {
    uint32_t enabled;   // Flag indicating whether the watchpoint is enabled.
    uint64_t address;   // Memory address being watched.
    uint8_t breaktype;  // Type of memory access that triggers the watchpoint (e.g., read, write).
    uint8_t length;     // Length of the watched memory region.
};

// Holds the state of the debugger for a particular process or thread
struct debug_context {
    int pid;                // Process ID of the target process.
    int dbgfd;              // File descriptor for the debugger's control interface.
    struct debug_breakpoint breakpoints[MAX_BREAKPOINTS]; // List of breakpoints.
    struct {
        uint64_t dr[16];    // Debug registers (may be used for watchpoints).
    } watchdata;
};

// Holds information about a server-client connection for debugging
struct server_client {
    int id;                       // Unique identifier for the client.
    int fd;                       // File descriptor for the connection.
    int debugging;                // Flag indicating whether the client is currently debugging a process.
    struct sockaddr_in client;    // Client's socket address.
    struct debug_context dbgctx;  // The debugging context associated with the client.
};

typedef struct cmd_packet cmd_packet_t;
typedef struct cmd_proc_read_packet cmd_proc_read_packet_t;
typedef struct cmd_proc_write_packet cmd_proc_write_packet_t;
typedef struct cmd_proc_maps_packet cmd_proc_maps_packet_t;
typedef struct cmd_proc_install_packet cmd_proc_install_packet_t;
typedef struct cmd_proc_install_response cmd_proc_install_response_t;
typedef struct cmd_proc_call_packet cmd_proc_call_packet_t;
typedef struct cmd_proc_call_response cmd_proc_call_response_t;
typedef struct cmd_proc_elf_packet cmd_proc_elf_packet_t;
typedef struct cmd_proc_protect_packet cmd_proc_protect_packet_t;
typedef struct cmd_proc_scan_packet cmd_proc_scan_packet_t;
typedef struct cmd_proc_info_packet cmd_proc_info_packet_t;
typedef struct cmd_proc_info_response cmd_proc_info_response_t;
typedef struct cmd_proc_alloc_packet cmd_proc_alloc_packet_t;
typedef struct cmd_proc_alloc_response cmd_proc_alloc_response_t;
typedef struct cmd_proc_free_packet cmd_proc_free_packet_t;
typedef struct cmd_debug_attach_packet cmd_debug_attach_packet_t;
typedef struct cmd_debug_breakpt_packet cmd_debug_breakpt_packet_t;
typedef struct cmd_debug_watchpt_packet cmd_debug_watchpt_packet_t;
typedef struct cmd_debug_stopthr_packet cmd_debug_stopthr_packet_t;
typedef struct cmd_debug_resumethr_packet cmd_debug_resumethr_packet_t;
typedef struct cmd_debug_getregs_packet cmd_debug_getregs_packet_t;
typedef struct cmd_debug_setregs_packet cmd_debug_setregs_packet_t;
typedef struct cmd_debug_stopgo_packet cmd_debug_stopgo_packet_t;
typedef struct cmd_debug_thrinfo_packet cmd_debug_thrinfo_packet_t;
typedef struct cmd_debug_thrinfo_response cmd_debug_thrinfo_response_t;
typedef struct cmd_kern_read_packet cmd_kern_read_packet_t;
typedef struct cmd_kern_write_packet cmd_kern_write_packet_t;
typedef struct cmd_console_print_packet cmd_console_print_packet_t;
typedef struct cmd_console_notify_packet cmd_console_notify_packet_t;
typedef struct cmd_console_info_response cmd_console_info_response_t;
typedef struct debug_breakpoint debug_breakpoint_t;

#endif
