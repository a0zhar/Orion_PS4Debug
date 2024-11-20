#pragma once
#ifndef _RPCASM_H
#define _RPCASM_H
#include <stdint.h>

#define RPCSTUB_MAGIC 0x42545352
#define RPCLDR_MAGIC 0x52444C52

struct rpcstub_header {
    uint32_t magic;
    uint64_t entry;
    uint64_t rpc_rip;
    uint64_t rpc_rdi;
    uint64_t rpc_rsi;
    uint64_t rpc_rdx;
    uint64_t rpc_rcx;
    uint64_t rpc_r8;
    uint64_t rpc_r9;
    uint64_t rpc_rax;
    uint8_t rpc_go;
    uint8_t rpc_done;
} __attribute__((packed));


struct rpcldr_header {
    uint32_t magic;
    uint64_t entry;
    uint8_t ldrdone;
    uint64_t stubentry;
    uint64_t scePthreadAttrInit;
    uint64_t scePthreadAttrSetstacksize;
    uint64_t scePthreadCreate;
    uint64_t thr_initial;
} __attribute__((packed));

static const uint8_t rpcstub[410] = {
    0x52, 0x53, 0x54, 0x42, 0xA3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6C, 0x69, 0x62, 0x6B, 0x65, 0x72,
    0x6E, 0x65, 0x6C, 0x2E, 0x73, 0x70, 0x72, 0x78, 0x00, 0x6C, 0x69, 0x62,
    0x6B, 0x65, 0x72, 0x6E, 0x65, 0x6C, 0x5F, 0x77, 0x65, 0x62, 0x2E, 0x73,
    0x70, 0x72, 0x78, 0x00, 0x6C, 0x69, 0x62, 0x6B, 0x65, 0x72, 0x6E, 0x65,
    0x6C, 0x5F, 0x73, 0x79, 0x73, 0x2E, 0x73, 0x70, 0x72, 0x78, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x73, 0x63, 0x65, 0x4B, 0x65,
    0x72, 0x6E, 0x65, 0x6C, 0x55, 0x73, 0x6C, 0x65, 0x65, 0x70, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xB9, 0x00, 0x00, 0x00, 0x00,
    0x48, 0x8D, 0x15, 0xD4, 0xFF, 0xFF, 0xFF, 0xBE, 0x00, 0x00, 0x00, 0x00,
    0x48, 0x8D, 0x3D, 0x93, 0xFF, 0xFF, 0xFF, 0xE8, 0xC4, 0x00, 0x00, 0x00,
    0x48, 0x85, 0xC0, 0x74, 0x3F, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D,
    0x15, 0xB2, 0xFF, 0xFF, 0xFF, 0xBE, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D,
    0x3D, 0x80, 0xFF, 0xFF, 0xFF, 0xE8, 0xA2, 0x00, 0x00, 0x00, 0x48, 0x85,
    0xC0, 0x74, 0x1D, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x15, 0x90,
    0xFF, 0xFF, 0xFF, 0xBE, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x3D, 0x71,
    0xFF, 0xFF, 0xFF, 0xE8, 0x80, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x15, 0x90,
    0xFF, 0xFF, 0xFF, 0x48, 0x8D, 0x35, 0x79, 0xFF, 0xFF, 0xFF, 0x48, 0x8B,
    0x3D, 0x6A, 0xFF, 0xFF, 0xFF, 0xE8, 0x71, 0x00, 0x00, 0x00, 0x80, 0x3D,
    0x27, 0xFF, 0xFF, 0xFF, 0x00, 0x74, 0x49, 0x4C, 0x8B, 0x0D, 0x0E, 0xFF,
    0xFF, 0xFF, 0x4C, 0x8B, 0x05, 0xFF, 0xFE, 0xFF, 0xFF, 0x48, 0x8B, 0x0D,
    0xF0, 0xFE, 0xFF, 0xFF, 0x48, 0x8B, 0x15, 0xE1, 0xFE, 0xFF, 0xFF, 0x48,
    0x8B, 0x35, 0xD2, 0xFE, 0xFF, 0xFF, 0x48, 0x8B, 0x3D, 0xC3, 0xFE, 0xFF,
    0xFF, 0x4C, 0x8B, 0x25, 0xB4, 0xFE, 0xFF, 0xFF, 0x41, 0xFF, 0xD4, 0x48,
    0x89, 0x05, 0xE2, 0xFE, 0xFF, 0xFF, 0xC6, 0x05, 0xE3, 0xFE, 0xFF, 0xFF,
    0x00, 0xC6, 0x05, 0xDD, 0xFE, 0xFF, 0xFF, 0x01, 0xBF, 0xA0, 0x86, 0x01,
    0x00, 0x4C, 0x8B, 0x25, 0x1F, 0xFF, 0xFF, 0xFF, 0x41, 0xFF, 0xD4, 0xEB,
    0x9D, 0x31, 0xC0, 0xC3, 0xB8, 0x52, 0x02, 0x00, 0x00, 0x49, 0x89, 0xCA,
    0x0F, 0x05, 0xC3, 0xB8, 0x4F, 0x02, 0x00, 0x00, 0x49, 0x89, 0xCA, 0x0F,
    0x05, 0xC3
};

static const uint8_t rpcldr[255] = {
    0x52, 0x4C, 0x44, 0x52, 0x4D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x72, 0x70, 0x63,
    0x73, 0x74, 0x75, 0x62, 0x00, 0x48, 0x8B, 0x3D, 0xD9, 0xFF, 0xFF, 0xFF,
    0x48, 0x8B, 0x37, 0x48, 0x8B, 0xBE, 0xE0, 0x01, 0x00, 0x00, 0xE8, 0x7A,
    0x00, 0x00, 0x00, 0x48, 0x8D, 0x3D, 0xD3, 0xFF, 0xFF, 0xFF, 0x4C, 0x8B,
    0x25, 0xA4, 0xFF, 0xFF, 0xFF, 0x41, 0xFF, 0xD4, 0xBE, 0x00, 0x00, 0x08,
    0x00, 0x48, 0x8D, 0x3D, 0xBD, 0xFF, 0xFF, 0xFF, 0x4C, 0x8B, 0x25, 0x96,
    0xFF, 0xFF, 0xFF, 0x41, 0xFF, 0xD4, 0x4C, 0x8D, 0x05, 0xB4, 0xFF, 0xFF,
    0xFF, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x15, 0x70, 0xFF, 0xFF,
    0xFF, 0x48, 0x8D, 0x35, 0x99, 0xFF, 0xFF, 0xFF, 0x48, 0x8D, 0x3D, 0x8A,
    0xFF, 0xFF, 0xFF, 0x4C, 0x8B, 0x25, 0x73, 0xFF, 0xFF, 0xFF, 0x41, 0xFF,
    0xD4, 0xC6, 0x05, 0x50, 0xFF, 0xFF, 0xFF, 0x01, 0xBF, 0x00, 0x00, 0x00,
    0x00, 0xE8, 0x01, 0x00, 0x00, 0x00, 0xC3, 0xB8, 0xAF, 0x01, 0x00, 0x00,
    0x49, 0x89, 0xCA, 0x0F, 0x05, 0xC3, 0xB8, 0xA5, 0x00, 0x00, 0x00, 0x49,
    0x89, 0xCA, 0x0F, 0x05, 0xC3, 0x55, 0x48, 0x89, 0xE5, 0x53, 0x48, 0x83,
    0xEC, 0x18, 0x48, 0x89, 0x7D, 0xE8, 0x48, 0x8D, 0x75, 0xE8, 0xBF, 0x81,
    0x00, 0x00, 0x00, 0xE8, 0xDA, 0xFF, 0xFF, 0xFF, 0x48, 0x83, 0xC4, 0x18,
    0x5B, 0x5D, 0xC3
};

#endif
