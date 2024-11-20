#include "../include/installer.h"

void patch_kern_505(uint64_t kernbase) {

    // patch memcpy first
    *(uint8_t*)(kernbase + 0x1EA53D) = 0xEB;

    // patch sceSblACMgrIsAllowedSystemLevelDebugging
    memcpy((void*)(kernbase + 0x11730), "\x48\xC7\xC0\x01\x00\x00\x00\xC3", 8);

    // patch sceSblACMgrHasMmapSelfCapability
    memcpy((void*)(kernbase + 0x117B0), "\x48\xC7\xC0\x01\x00\x00\x00\xC3", 8);

    // patch sceSblACMgrIsAllowedToMmapSelf
    memcpy((void*)(kernbase + 0x117C0), "\x48\xC7\xC0\x01\x00\x00\x00\xC3", 8);

    // disable sysdump_perform_dump_on_fatal_trap
    // will continue execution and give more information on crash, such as rip
    *(uint8_t*)(kernbase + 0x7673E0) = 0xC3;

    // self patches
    memcpy((void*)(kernbase + 0x13F03F), "\x31\xC0\x90\x90\x90", 5);

    // patch vm_map_protect check
    memcpy((void*)(kernbase + 0x1A3C08), "\x90\x90\x90\x90\x90\x90", 6);

    // patch ptrace, thanks 2much4u
    *(uint8_t*)(kernbase + 0x30D9AA) = 0xEB;

    // remove all these bullshit checks from ptrace, by golden
    memcpy((void*)(kernbase + 0x30DE01), "\xE9\xD0\x00\x00\x00", 5);

    // patch ASLR, thanks 2much4u
    *(uint16_t*)(kernbase + 0x194875) = 0x9090;

    // patch kmem_alloc
    *(uint8_t*)(kernbase + 0xFCD48) = VM_PROT_ALL;
    *(uint8_t*)(kernbase + 0xFCD56) = VM_PROT_ALL;
}

void patch_kern_672(uint64_t kernbase) {
    // Patch memcpy first
    *(uint8_t*)(kernbase + MEMCPY_PATCH_672) = 0xEB;

    // Patch sceSblACMgrIsAllowedSystemLevelDebugging
    memcpy((void*)(kernbase + AC_MGR_DEBUG_PATCH_672), "\x48\xC7\xC0\x01\x00\x00\x00\xC3", 8);

    // Patch sceSblACMgrHasMmapSelfCapability
    memcpy((void*)(kernbase + AC_MGR_SELF_PATCH_672), "\x48\xC7\xC0\x01\x00\x00\x00\xC3", 8);

    // Patch sceSblACMgrIsAllowedToMmapSelf
    memcpy((void*)(kernbase + AC_MGR_MMAP_PATCH_672), "\x48\xC7\xC0\x01\x00\x00\x00\xC3", 8);

    // disable sysdump_perform_dump_on_fatal_trap
    // will continue execution and give more information on crash, such as rip
    *(uint8_t*)(kernbase + SYSDUMP_PATCH_672) = 0xC3;

    // self patches0xAD2E4
    memcpy((void*)(kernbase + SELF_PATCH_672), "\x31\xC0\x90\x90\x90", 5);

    // patch vm_map_protect check
    memcpy((void*)(kernbase + VM_PROTECT_PATCH_672), "\x90\x90\x90\x90\x90\x90", 6);

    // patch ptrace
    *(uint8_t*)(kernbase + PTRACE_PATCH_672) = 0xEB;
    memcpy((void*)(kernbase + PTRACE_CHECK_PATCH_672), "\xE9\xE2\x02\x00\x00", 5);

    // disable ASLR
    *(uint8_t*)(kernbase + ASLR_PATCH_672) = 0xEB;

    // patch kmem_alloc
    *(uint8_t*)(kernbase + KMEM_ALLOC_PATCH1_672) = VM_PROT_ALL;
    *(uint8_t*)(kernbase + KMEM_ALLOC_PATCH2_672) = VM_PROT_ALL;
}

void patch_kern_70X(uint64_t kernbase) {
    // patch memcpy first
    *(uint8_t*)(kernbase + 0x2F04D) = 0xEB;

    // patch sceSblACMgrIsAllowedSystemLevelDebugging
    memcpy((void*)(kernbase + 0x1CB880), "\x48\xC7\xC0\x01\x00\x00\x00\xC3", 8);

    // patch sceSblACMgrHasMmapSelfCapability
    memcpy((void*)(kernbase + 0x1CB8F0), "\x48\xC7\xC0\x01\x00\x00\x00\xC3", 8);

    // patch sceSblACMgrIsAllowedToMmapSelf
    memcpy((void*)(kernbase + 0x1CB910), "\x48\xC7\xC0\x01\x00\x00\x00\xC3", 8);

    // disable sysdump_perform_dump_on_fatal_trap
    // will continue execution and give more information on crash, such as rip
    *(uint8_t*)(kernbase + 0x7889E0) = 0xC3;

    // self patches
    memcpy((void*)(kernbase + 0x1D40BB), "\x31\xC0\x90\x90\x90", 5);

    // patch vm_map_protect check
    memcpy((void*)(kernbase + 0x264C08), "\x90\x90\x90\x90\x90\x90", 6);

    // patch ptrace, thanks 2much4u
    *(uint8_t*)(kernbase + 0x448D5) = 0xEB;

    // remove all these bullshit checks from ptrace, by golden
    memcpy((void*)(kernbase + 0x44DAF), "\xE9\xD0\x00\x00\x00", 5);

    // patch ASLR, thanks 2much4u
    *(uint16_t*)(kernbase + 0xC1F9A) = 0x9090;

    // patch kmem_alloc
    *(uint8_t*)(kernbase + 0x1171BE) = VM_PROT_ALL;
    *(uint8_t*)(kernbase + 0x1171C6) = VM_PROT_ALL;
}

void patch_kern_755(uint64_t kernbase) {
    // patch memcpy first
    *(uint8_t*)(kernbase + 0x28F80D) = 0xEB;

    // patch sceSblACMgrIsAllowedSystemLevelDebugging
    memcpy((void*)(kernbase + 0x364CD0), "\x48\xC7\xC0\x01\x00\x00\x00\xC3", 8);

    // patch sceSblACMgrHasMmapSelfCapability
    memcpy((void*)(kernbase + 0x364D40), "\x48\xC7\xC0\x01\x00\x00\x00\xC3", 8);

    // patch sceSblACMgrIsAllowedToMmapSelf
    memcpy((void*)(kernbase + 0x364D60), "\x48\xC7\xC0\x01\x00\x00\x00\xC3", 8);

    // disable sysdump_perform_dump_on_fatal_trap
    // will continue execution and give more information on crash, such as rip
    *(uint8_t*)(kernbase + 0x77F9A0) = 0xC3;

    // self patches
    memcpy((void*)(kernbase + 0xDCEB1), "\x31\xC0\x90\x90\x90", 5);

    // patch vm_map_protect check
    memcpy((void*)(kernbase + 0x3014C8), "\x90\x90\x90\x90\x90\x90", 6);

    // patch ptrace, thanks 2much4u
    *(uint8_t*)(kernbase + 0x361CF5) = 0xEB;

    // remove all these bullshit checks from ptrace, by golden
    memcpy((void*)(kernbase + 0x3621CF), "\xE9\xD0\x00\x00\x00", 5);

    // patch ASLR, thanks 2much4u
    *(uint16_t*)(kernbase + 0x218AA2) = 0x9090;

    // patch kmem_alloc
    *(uint8_t*)(kernbase + 0x1754AC) = VM_PROT_ALL;
    *(uint8_t*)(kernbase + 0x1754B4) = VM_PROT_ALL;
}

void patch_kern_900(uint64_t kernbase) {
    // patch memcpy first
    *(uint8_t*)(kernbase + 0x2714BD) = 0xEB;

    // patch sceSblACMgrIsAllowedSystemLevelDebugging
    memcpy((void*)(kernbase + 0x8BC20), "\x48\xC7\xC0\x01\x00\x00\x00\xC3", 8);

    // patch sceSblACMgrHasMmapSelfCapability
    memcpy((void*)(kernbase + 0x8BC90), "\x48\xC7\xC0\x01\x00\x00\x00\xC3", 8);

    // patch sceSblACMgrIsAllowedToMmapSelf
    memcpy((void*)(kernbase + 0x8BCB0), "\x48\xC7\xC0\x01\x00\x00\x00\xC3", 8);

    // disable sysdump_perform_dump_on_fatal_trap
    // will continue execution and give more information on crash, such as rip
    *(uint8_t*)(kernbase + 0x767E30) = 0xC3;

    // self patches
    memcpy((void*)(kernbase + 0x168051), "\x31\xC0\x90\x90\x90", 5);

    // patch vm_map_protect check
    memcpy((void*)(kernbase + 0x80B8B), "\x90\x90\x90\x90\x90\x90", 6);

    // patch ptrace, thanks 2much4u
    *(uint8_t*)(kernbase + 0x41F4E5) = 0xEB;

    // remove all these bullshit checks from ptrace, by golden
    memcpy((void*)(kernbase + 0x41F9D1), "\xE9\xD0\x00\x00\x00", 5);

    // patch ASLR, thanks 2much4u
    *(uint16_t*)(kernbase + 0x5F824) = 0x9090;

    // patch kmem_alloc
    *(uint8_t*)(kernbase + 0x37BF3C) = VM_PROT_ALL;
    *(uint8_t*)(kernbase + 0x37BF44) = VM_PROT_ALL;
}

