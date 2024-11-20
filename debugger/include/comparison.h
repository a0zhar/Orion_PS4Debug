#pragma once
#ifndef _SCAN_COMPARISON_HH
#define _SCAN_COMPARISON_HH
#include <types.h>
typedef unsigned char _BYTE;

// Enumeration containing the different value types for the value that
// the process memory is scanned to find. On the remote PC running the
// PS4Cheater (RPC Client) Tool connected to this program, the user is
// able to choose what kind of value they want to search for
typedef enum CMD_PROCESS_SCAN_VALUE_TYPE_T ProcScanValueType;
enum CMD_PROCESS_SCAN_VALUE_TYPE_T {
    valTypeUInt8 = 0,    // Unsigned 8-bit integer
    valTypeInt8,         // Signed 8-bit integer
    valTypeUInt16,       // Unsigned 16-bit integer
    valTypeInt16,        // Signed 16-bit integer
    valTypeUInt32,       // Unsigned 32-bit integer
    valTypeInt32,        // Signed 32-bit integer
    valTypeUInt64,       // Unsigned 64-bit integer
    valTypeInt64,        // Signed 64-bit integer
    valTypeFloat,        // Float type
    valTypeDouble,       // Double type
    valTypeArrBytes,     // Array of bytes
    valTypeString        // String type
} __attribute__((__packed__));

// Enumeration for different types of comparison operations used 
// to filter found values during the process memory scanning
typedef enum CMD_PROCESS_SCAN_COMPARISON_TYPE_T ProcScanCompareType;
enum CMD_PROCESS_SCAN_COMPARISON_TYPE_T {
    ST_Exact_Value = 0,     // Compare for exact value
    ST_Fuzzy_Value,         // Fuzzy value comparison
    ST_Bigger_Than,         // Compare for values bigger than provided
    ST_Smaller_Than,        // Compare for values smaller than provided
    ST_Value_Between,       // Compare for values within a range
    ST_Increased_Value,     // Compare for increased values
    ST_Increased_Value_By,  // Compare for values increased by a specific amount
    ST_Decreased_Value,     // Compare for decreased values
    ST_Decreased_Value_By,  // Compare for values decreased by a specific amount
    ST_Changed_Value,       // Compare for changed values
    ST_Unchanged_Value,     // Compare for unchanged values
    ST_Unknown_Value        // Compare for unknown initial values
} __attribute__((__packed__));

int compare_exact_value(_BYTE* pScanValue, _BYTE* pMemoryValue, size_t valTypeLength);
int compare_fuzzy_value(ProcScanValueType valType, _BYTE* pScanValue, _BYTE* pMemoryValue);
int compare_bigger_than(ProcScanValueType valType, _BYTE* pScanValue, _BYTE* pMemoryValue);
int compare_smaller_than(ProcScanValueType valType, _BYTE* pScanValue, _BYTE* pMemoryValue);
int compare_value_between(_BYTE* pMemoryValue, _BYTE* pScanValue, _BYTE* pExtraValue, ProcScanValueType valType);
int compare_increased_value_by(ProcScanValueType valType, _BYTE* pScanValue, _BYTE* pMemoryValue, _BYTE* pExtraValue);
int compare_decreased_value_by(ProcScanValueType valType, _BYTE* pScanValue, _BYTE* pMemoryValue, _BYTE* pExtraValue);
int compare_increased_value(ProcScanValueType valType, _BYTE* pScanValue, _BYTE* pMemoryValue, _BYTE* pExtraValue);
int compare_decreased_value(ProcScanValueType valType, _BYTE* pScanValue, _BYTE* pMemoryValue, _BYTE* pExtraValue);
int compare_changed_value(ProcScanValueType valType, _BYTE* pScanValue, _BYTE* pMemoryValue, _BYTE* pExtraValue);
int compare_unchanged_value(ProcScanValueType valType, _BYTE* pScanValue, _BYTE* pMemoryValue, _BYTE* pExtraValue);
#endif