// A collection of PS4 Firmware Specific Kernel Patch Offsets.
// Much Thanks to DeathRGH and his frame4 repository:
// - https://github.com/DeathRGH/frame4
//
// The Installer is not fully firmware agnostic as of now, but
// i was able to make it be compatible with the following fw's:
// - 5.05, 6.72, 7.02, 9.00, and 11.00?
#pragma once
#ifndef KERNEL_PATCH_OFFSETS_H
#define KERNEL_PATCH_OFFSETS_H

// Patch memcpy
#define MEMCPY_PATCH_505           0x1EA53D
#define MEMCPY_PATCH_672           0x3C15BD
#define MEMCPY_PATCH_702           0x2F04D
#define MEMCPY_PATCH_900           0x2714BD
#define MEMCPY_PATCH_1100          0x2DDDFD

// SceSblACMgr Patches
#define AC_MGR_DEBUG_PATCH_505     0x11730
#define AC_MGR_DEBUG_PATCH_672     0x233BD0
#define AC_MGR_DEBUG_PATCH_702     0x1CB880
#define AC_MGR_DEBUG_PATCH_900     0x8BC20
#define AC_MGR_DEBUG_PATCH_1100    0x3D0DE0

#define AC_MGR_SELF_PATCH_505      0x117B0
#define AC_MGR_SELF_PATCH_672      0x233C40
#define AC_MGR_SELF_PATCH_702      0x1CB8F0
#define AC_MGR_SELF_PATCH_900      0x8BC90
#define AC_MGR_SELF_PATCH_1100     0x3D0E50

#define AC_MGR_MMAP_PATCH_505      0x117C0
#define AC_MGR_MMAP_PATCH_672      0x233C50
#define AC_MGR_MMAP_PATCH_702      0x1CB910
#define AC_MGR_MMAP_PATCH_900      0x8BCB0
#define AC_MGR_MMAP_PATCH_1100     0x3D0E70

// Sysdump disable
#define SYSDUMP_PATCH_505          0x7673E0
#define SYSDUMP_PATCH_672          0x784120
#define SYSDUMP_PATCH_702          0x7889E0
#define SYSDUMP_PATCH_900          0x767E30
#define SYSDUMP_PATCH_1100         0x76D210

// Self patches
#define SELF_PATCH_505             0x13F03F
#define SELF_PATCH_672             0xAD2E4
#define SELF_PATCH_702             0x1D40BB
#define SELF_PATCH_900             0x168051
#define SELF_PATCH_1100            0x157F91

// VM map protect check
#define VM_PROTECT_PATCH_505       0x1A3C08
#define VM_PROTECT_PATCH_672       0x451DB8
#define VM_PROTECT_PATCH_702       0x264C08
#define VM_PROTECT_PATCH_900       0x80B8B
#define VM_PROTECT_PATCH_1100      0x35C8EC

// Ptrace patches
#define PTRACE_PATCH_505           0x30D9AA
#define PTRACE_PATCH_672           0x10F879
#define PTRACE_PATCH_702           0x448D5
#define PTRACE_PATCH_900           0x41F4E5
#define PTRACE_PATCH_1100          0x384285

#define PTRACE_CHECK_PATCH_505     0x30DE01
#define PTRACE_CHECK_PATCH_672     0x10FD22
#define PTRACE_CHECK_PATCH_702     0x44DAF
#define PTRACE_CHECK_PATCH_900     0x41F9D1
#define PTRACE_CHECK_PATCH_1100    0x384771

// ASLR patches
#define ASLR_PATCH_505             0x194875
#define ASLR_PATCH_672             0x3CECE1
#define ASLR_PATCH_702             0xC1F9A
#define ASLR_PATCH_900             0x5F824
#define ASLR_PATCH_1100            0x3B11A4

// Kmem alloc patches
#define KMEM_ALLOC_PATCH1_505      0xFCD48
#define KMEM_ALLOC_PATCH2_505      0xFCD56
#define KMEM_ALLOC_PATCH1_672      0x2507F5
#define KMEM_ALLOC_PATCH2_672      0x250803
#define KMEM_ALLOC_PATCH1_702      0x1171BE
#define KMEM_ALLOC_PATCH2_702      0x1171C6
#define KMEM_ALLOC_PATCH1_900      0x37BF3C
#define KMEM_ALLOC_PATCH2_900      0x37BF44
#define KMEM_ALLOC_PATCH1_1100     0x245EDC
#define KMEM_ALLOC_PATCH2_1100     0x245EE4

// Kernel ELF loading patches
#define ELF_LOADING_PATCH_505      0x1A439D
#define ELF_LOADING_PATCH_672      0x45255D
#define ELF_LOADING_PATCH_702      0x2653D6
#define ELF_LOADING_PATCH_900      0x81376
#define ELF_LOADING_PATCH_1100     0x35D221

// Copyin/copyout patches
#define COPYINOUT_PATCH1_505       0x1EA767
#define COPYINOUT_PATCH2_505       0x1EA682
#define COPYINOUT_PATCH1_672       0x3C17F7
#define COPYINOUT_PATCH2_672       0x3C1702
#define COPYINOUT_PATCH3_672       0x3C1803
#define COPYINOUT_PATCH4_672       0x3C170E
#define COPYINOUT_PATCH1_702       0x2F287
#define COPYINOUT_PATCH2_702       0x2F192
#define COPYINOUT_PATCH3_702       0x2F293
#define COPYINOUT_PATCH4_702       0x2F19E
#define COPYINOUT_PATCH1_900       0x2716F7
#define COPYINOUT_PATCH2_900       0x271602
#define COPYINOUT_PATCH3_900       0x271703
#define COPYINOUT_PATCH4_900       0x27160E
#define COPYINOUT_PATCH1_1100      0x2DE037
#define COPYINOUT_PATCH2_1100      0x2DDF42
#define COPYINOUT_PATCH3_1100      0x2DE043
#define COPYINOUT_PATCH4_1100      0x2DDF4E

// Copyinstr patches
#define COPYINSTR_PATCH1_505       0x1EAB93
#define COPYINSTR_PATCH2_505       0x1EABC3
#define COPYINSTR_PATCH1_672       0x3C1CA3
#define COPYINSTR_PATCH2_672       0x3C1CE0
#define COPYINSTR_PATCH3_672       0x3C1CAF
#define COPYINSTR_PATCH1_702       0x2F733
#define COPYINSTR_PATCH2_702       0x2F770
#define COPYINSTR_PATCH3_702       0x2F73F
#define COPYINSTR_PATCH1_900       0x271BA3
#define COPYINSTR_PATCH2_900       0x271BE0
#define COPYINSTR_PATCH3_900       0x271BAF
#define COPYINSTR_PATCH1_1100      0x2DE4E3
#define COPYINSTR_PATCH2_1100      0x2DE520
#define COPYINSTR_PATCH3_1100      0x2DE4EF

// Fault patches
#define FAULT_PATCH_505            0x2A4EB3
#define FAULT_PATCH_672            0xBC8F6
#define FAULT_PATCH_702            0x2BF756
#define FAULT_PATCH_900            0x152966
#define FAULT_PATCH_1100           0x31E8A6

#define AIO_BUG_PATCH_505          0x68F188
#define BUDGET_KERNEL_PATCH_672    0x459763
#define BUDGET_KERNEL_PATCH_702    0x26C5F3
#define BUDGET_KERNEL_PATCH_900    0x884BE
#define BUDGET_KERNEL_PATCH_1100   0x36434E
#define EXEC_MEM_PATCH_1100        0x15626A

#endif
