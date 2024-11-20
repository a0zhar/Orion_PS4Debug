#include "../include/kdbg.h"

#define SYS_PROC_CMD_ALLOC      1
#define SYS_PROC_CMD_FREE       2
#define SYS_PROC_CMD_PROTECT    3
#define SYS_PROC_VM_MAP         4
#define SYS_PROC_CMD_CALL       5

// Define page size for the platform, to be used during prefaulting; 
// typically 4KB on x86_64 Archetecture
#define PREFAULT_PAGE_SIZE 4096

// This function prefaults a memory region by accessing each page 
// within the specified range, ensuring that all pages in the 
// given range are loaded into RAM.
void prefault(void* address, size_t size) {
    // Access each page to bring it into memory
    for (size_t i = 0; i < size; i += PAGE_SIZE) {
        // Use a volatile read to prevent compiler optimizations
        // that remove this access
        volatile uint8_t c = ((uint8_t*)address)[i];
        (void)c;  // Avoid unused variable warning
    }

    // Access the last byte to ensure the entire range is covered
    if (size % PAGE_SIZE != 0) {
        volatile uint8_t c = ((uint8_t*)address)[size - 1];
        (void)c;
    }
}

// This function allocates a block of memory using malloc and then 
// calls prefault to ensure all pages within the allocated memory 
// range are paged into RAM, before returning pointer to the mem.
void* pfmalloc(size_t size) {
    // Allocate memory block of requested size
    void *prefaulted_mem = malloc(size);
    
    // Ensure allocation succeeded before attempting to prefault.
    // If it failed, we return NULL early
    if (prefaulted_mem == NULL)
        return NULL;

    // Prefault the newly allocated memory, before returning the
    // pointer to that memory region
    prefault(prefaulted_mem, size);
    return prefaulted_mem;
}

void hexdump(void* data, size_t size) {
    unsigned char* p;
    int i;

    p = (unsigned char*)data;

    for (i = 0; i < size; i++) {
        uprintf("%02X ", *p++);
        if (!(i % 16) && i != 0)
            uprintf("\n");
        
    }

    uprintf("\n");
}

// Custom syscall 107: 
// Function retrieves a list of processes.
int sys_proc_list(struct proc_list_entry* procs, uint64_t* num) {
    return syscall(107, procs, num);
}

// Custom syscall 108: 
// Read from or write to a process's memory.
int sys_proc_rw(uint64_t pid, uint64_t address, void* data, uint64_t length, uint64_t write) {
    return syscall(108, pid, address, data, length, write);
}

// Custom syscall 109:
// Execute commands related to process management.
int sys_proc_cmd(uint64_t pid, uint64_t cmd, void* data) {
    return syscall(109, pid, cmd, data);
}

// Custom syscall 110:
// Retrieve the kernel base address.
int sys_kern_base(uint64_t* kbase) {
    return syscall(110, kbase);
}

// Custom syscall 111:
// Read from or write to kernel memory.
int sys_kern_rw(uint64_t address, void* data, uint64_t length, uint64_t write) {
    return syscall(111, address, data, length, write);
}

// Custom syscall 112:
// Execute console commands.
int sys_console_cmd(uint64_t cmd, void* data) {
    return syscall(112, cmd, data);
}
