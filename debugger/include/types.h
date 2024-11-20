#pragma once

#ifndef TYPES_H
#define TYPES_H

#include <stdint.h>

// Macro to suppress unused variable warnings
#ifndef UNUSED
#define UNUSED(x) (void)(x)
#endif

// Null pointer macro
#ifndef NULL
#define NULL 0
#endif

// Bit manipulation macro
#define BIT(n) (1 << (n))

// Error type definitions
typedef int errno_t;
typedef int errno;

// Boolean type
typedef int BOOL;

// Common size types
typedef uint64_t size_t;
typedef uint64_t rsize_t;
typedef int64_t ssize_t;

// Reduced type aliases for consistency
typedef uint8_t uint8;
typedef uint16_t uint16;
typedef uint32_t uint32;
typedef uint64_t uint64;

typedef int8_t int8;
typedef int16_t int16;
typedef int32_t int32;
typedef int64_t int64;

typedef float float32;
typedef double float64;

// Volatile types
typedef volatile uint8_t vuint8;
typedef volatile uint16_t vuint16;
typedef volatile uint32_t vuint32;
typedef volatile uint64_t vuint64;

typedef volatile int8_t vint8;
typedef volatile int16_t vint16;
typedef volatile int32_t vint32;
typedef volatile int64_t vint64;

typedef uint8_t byte;

// POSIX types
typedef uint32_t blksize_t;
typedef int64_t blkcnt_t;
typedef uint32_t dev_t;
typedef uint32_t fflags_t;
typedef uint32_t gid_t;
typedef uint32_t ino_t;
typedef uint16_t mode_t;
typedef uint16_t nlink_t;
typedef int64_t off_t;
typedef uint32_t uid_t;
typedef int64_t time_t;
typedef long suseconds_t;

#define RSIZE_MAX (SIZE_MAX >> 1)

// Time-related structures
struct timespec {
  time_t tv_sec;
  long tv_nsec;
};

struct timeval {
  time_t tv_sec;
  suseconds_t tv_usec;
};

struct tm {
  int tm_sec;
  int tm_min;
  int tm_hour;
  int tm_mday;
  int tm_mon;
  int tm_year;
  int tm_wday;
  int tm_yday;
  int tm_isdst;
};

// SCE type
typedef unsigned int SceKernelUseconds;

#endif
