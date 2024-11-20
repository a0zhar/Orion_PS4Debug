#pragma once
#ifndef _DEBUG_H
#define _DEBUG_H

#include <ps4.h>
#include "protocol.h"
#include "net.h"
#include "ptrace.h"

// typedef enum { bt_OnInstruction = 0, bt_OnWrites = 1, bt_OnIOAccess = 2, bt_OnReadsAndWrites = 3} BreakType;
// typedef enum {bl_1byte = 0, bl_2byte = 1, bl_8byte = 2, bl_4byte = 3} BreakLength;

#define DEBUG_PORT 755

// Size of the debug interrupt packet to ensure correct data handling.
#define DEBUG_INTERRUPT_PACKET_SIZE 0x4A0

#define DBREG_DR7_DISABLE       0x00  // TODO: Comment
#define DBREG_DR7_LOCAL_ENABLE  0x01  // TODO: Comment
#define DBREG_DR7_GLOBAL_ENABLE 0x02  // TODO: Comment
#define	DBREG_DR7_GD          0x2000  // TODO: Comment

#define	DBREG_DR7_MASK(i)                     ((uint64_t)(0xf) << ((i) * 4 + 16) | 0x3 << (i) * 2)
#define	DBREG_DR7_SET(i, len, access, enable) ((uint64_t)((len) << 2 | (access)) << ((i) * 4 + 16) | (enable) << (i) * 2)
#define	DBREG_DR7_ENABLED(d, i)	              (((d) & 0x3 << (i) * 2) != 0)
#define	DBREG_DR7_ACCESS(d, i)	              ((d) >> ((i) * 4 + 16) & 0x3)
#define	DBREG_DR7_LEN(d, i)	                  ((d) >> ((i) * 4 + 18) & 0x3)

// Debug Register DR7: Break Lengths
#define DBREG_DR7_LEN_1   0x00 // Break Length: 1 byte
#define DBREG_DR7_LEN_2   0x01 // Break Length: 2 byte
#define DBREG_DR7_LEN_4   0x03 // Break Length: 4 byte
#define DBREG_DR7_LEN_8   0x02 // Break Length: 8 byte (ONLY in 64-bit?)

// Debug Register DR7: Break Types
#define DBREG_DR7_EXEC    0x00 // Break Type: on Instruction Execution
#define DBREG_DR7_WRONLY  0x01 // Break Type: on Write operations
#define DBREG_DR7_RDWR    0x03 // Break Type: on Read and Write
#define	DBREG_DR7_GD    0x2000 // TODO: Comment (Global Debug?)

#define	DBREG_DRX(d, x) ((d)->dr[(x)]) // TODO: Comment

// Struct representing the complete state of the 64-bit CPU registers
// This is crucial for context switching and for restoring execution state during debugging
struct __reg64 {
    uint64_t r_r15;     // General-purpose register R15, typically used for temporary storage
    uint64_t r_r14;     // General-purpose register R14, often used in function calls
    uint64_t r_r13;     // General-purpose register R13, usually reserved for specific uses
    uint64_t r_r12;     // General-purpose register R12, commonly used for calculations
    uint64_t r_r11;     // General-purpose register R11, frequently used during function prologues/epilogues
    uint64_t r_r10;     // General-purpose register R10, generally caller-saved
    uint64_t r_r9;      // General-purpose register R9, another caller-saved register
    uint64_t r_r8;      // General-purpose register R8, typically caller-saved
    uint64_t r_rdi;     // Register for the first argument to functions (RDI)
    uint64_t r_rsi;     // Register for the second argument to functions (RSI)
    uint64_t r_rbp;     // Base Pointer; points to the current stack frame base for stack management
    uint64_t r_rbx;     // General-purpose register RBX, callee-saved during function calls
    uint64_t r_rdx;     // Register for the third argument to functions (RDX)
    uint64_t r_rcx;     // Register for the fourth argument to functions (RCX)
    uint64_t r_rax;     // Accumulator register; used for return values and arithmetic operations
    uint32_t r_trapno;  // Trap number indicating the particular exception or interrupt type
    uint16_t r_fs;      // Segment selector for the FS segment, often used for thread-local storage in user space
    uint16_t r_gs;      // Segment selector for the GS segment, used for additional global variables
    uint32_t r_err;     // Error code associated with the last exception that occurred
    uint16_t r_es;      // Segment selector for the ES segment (generally for data storage)
    uint16_t r_ds;      // Segment selector for the DS segment (often for data segment)
    uint64_t r_rip;     // Instruction Pointer, pointing to the next instruction to be executed
    uint64_t r_cs;      // Segment selector for the code segment, defines the currently executing code segment
    uint64_t r_rflags;  // Flags register representing the current state and conditions (eg, zero flag, carry flag)
    uint64_t r_rsp;     // Stack Pointer, points to the current top of the stack for managing function calls
    uint64_t r_ss;      // Segment selector for the stack segment, used in conjunction with RSP
};

// Contents of each x87 floating point accumulator
struct fpacc87 { uint8_t fp_bytes[10]; };

// Contents of each SSE extended accumulator
struct xmmacc { uint8_t xmm_bytes[16]; }; // Contents of each SSE extended accumulator


// Contents of the upper 16 bytes of each AVX extended accumulator
struct ymmacc { uint8_t ymm_bytes[16]; };

// Struct defining the environment for floating-point operations (x87 and SSE)
// Contains control and status information essential for restoring and inspecting floating-point computations
struct envxmm {
    uint16_t en_cw;          // control word (16bits) 
    uint16_t en_sw;          // status word (16bits) 
    uint8_t en_tw;           // tag word (8bits) 
    uint8_t en_zero;
    uint16_t en_opcode;      // opcode last executed (11 bits ) 
    uint64_t en_rip;         // floating point instruction pointer 
    uint64_t en_rdp;         // floating operand pointer 
    uint32_t en_mxcsr;       // SSE sontorol/status register 
    uint32_t en_mxcsr_mask;  // valid bits in mxcsr 
};

// Struct to save the entire state of the floating-point unit, including both x87 and SSE context 
// Essential for restoring the correct state during debugging, especially for floating-point heavy applications
struct savefpu {
    struct envxmm sv_env;         // Environment state for managing floating-point operations
    struct {
        struct fpacc87 fp_acc;    // State of the x87 floating-point accumulator
        uint8_t fp_pad[6];        // Padding to ensure proper alignment in memory
    } sv_fp[8];                   // Array of eight floating-point accumulators (x87)
    struct xmmacc sv_xmm[16];     // Array of 16 XMM registers holding SSE states
    uint8_t sv_pad[96];           // Padding to maintain alignment of the entire struct
} __attribute__((aligned(16)));

// Header struct for extended state information about floating-point processes
// Useful in contexts where multiple floating-point contexts need to be managed
struct xstate_hdr {
    uint64_t xstate_bv;        // Bit vector indicating which extended state components are active
    uint8_t xstate_rsrv0[16];  // Reserved space for future use or alignment
    uint8_t xstate_rsrv[40];   // Additional reserve space for extended features
};

// Struct to save the state of AVX registers together with their extended contexts
// Essential for debugging applications that utilize advanced vectorization techniques
struct savefpu_xstate {
    struct xstate_hdr sx_hd;   // Header containing information about the extended states
    struct ymmacc sx_ymm[16];  // Array of 16 AVX YMM registers holding their states
};

// Comprehensive struct that consolidates floating-point states from x87, SSE, and AVX
// Provides a complete view for debugging floating-point operations in a highly optimized environment
struct savefpu_ymm {
    struct envxmm sv_env;             // Environment context for floating-point operations and calculations
    struct {
        struct fpacc87 fp_acc;        // State of the x87 floating-point accumulator
        int8_t fp_pad[6];             // Padding to meet proper alignment demands
    } sv_fp[8];                       // Array of floating-point accumulators for x87
    struct xmmacc sv_xmm[16];         // Array storing states of XMM registers used in SSE execution
    uint8_t sv_pad[96];               // Additional padding for alignment and memory structuring
    struct savefpu_xstate sv_xstate;  // State information for managing extended floating-point operations
} __attribute__((aligned(64)));

// Struct defining the 64-bit debug registers used for hardware breakpoints
// Includes multiple registers tailored for handling breakpoints essential in process debugging
struct __dbreg64 {
    // Array of debug registers (16 total)
    // -----------------------------------------------
    // Index 0-3:  debug address registers
    // Index 4-5:  reserved
    // Index 6:    debug status 
    // Index 7:    debug control 
    // Index 8-15: reserved
    uint64_t dr[16];
};

// Struct containing the data communicated during a debug interrupt event.
// This packet contains important information about the process being debugged 
// and about its current state.
struct debug_interrupt_packet {
    uint32_t lwpid;              // process ID for the current context
    uint32_t status;             // Status of the debug operation
    char tdname[40];             // Thread name for identification
    struct __reg64 reg64;        // Registers state at the time of the debug interrupt
    struct savefpu_ymm savefpu;  // Floating-point unit state
    struct __dbreg64 dbreg64;    // Debug registers state
} __attribute__((__packed__));  


int debugger_attach(int fd, struct cmd_packet* packet);
int debugger_detach(int fd, struct cmd_packet* packet);
int debugger_connect(struct debug_context* dbgctx, struct sockaddr_in* client);
int debugger_cleanup(struct debug_context* dbgctx);
int debug_handle(int fd, struct cmd_packet* packet);

int debugger_handle_breakpoint(int fd, struct cmd_packet* packet);
int debugger_handle_watchpoint(int fd, struct cmd_packet* packet);
int debugger_do_single_step(int fd, struct cmd_packet* packet);

int debugger_handle_threads(int fd, struct cmd_packet* packet);
int debugger_get_thread_info(int fd, struct cmd_packet* packet);
int debugger_suspend_thread(int fd, struct cmd_packet* packet);
int debugger_resume_thread(int fd, struct cmd_packet* packet);
int debugger_stopgo_handle(int fd, struct cmd_packet* packet);

int debugger_get_regs(int fd, struct cmd_packet* packet);
int debugger_set_regs(int fd, struct cmd_packet* packet);
int debugger_get_fpregs(int fd, struct cmd_packet* packet);
int debugger_set_fpregs(int fd, struct cmd_packet* packet);
int debugger_get_dbregs(int fd, struct cmd_packet* packet);
int debugger_set_dbregs(int fd, struct cmd_packet* packet);


extern int g_debugging;
extern struct server_client* curdbgcli;
extern struct debug_context* current_dbgr_ctx;
#endif
