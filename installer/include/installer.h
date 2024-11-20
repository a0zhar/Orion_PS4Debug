#pragma once
#ifndef _INSTALLER_H
#define _INSTALLER_H

#include <ksdk.h>
#include "proc.h"
#include "fw_offsets.h"

#define PAYLOAD_BASE 0x926200000
#define PAYLOAD_SIZE 0x400000

int runinstaller();

void patch_kern_505(uint64_t kernbase);
void patch_kern_672(uint64_t kernbase);
void patch_kern_70X(uint64_t kernbase);
void patch_kern_755(uint64_t kernbase);
void patch_kern_900(uint64_t kernbase);


#endif
