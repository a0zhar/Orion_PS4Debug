#pragma once
#ifndef _SCAN_RESULTS_QUEUE_HH
#define _SCAN_RESULTS_QUEUE_HH
#include <ps4.h>

// Initial capacity for the array of found memory addresses
#define INITIAL_CAPACITY 2000

// Structure to hold process scan results, including addresses and metadata
typedef struct PROCESS_SCAN_RESULTS_T {
    uint64_t* addressResults; // Dynamically growing array of 64-bit memory addresses
    size_t space_avail;       // Number of address slots remaining before resizing is needed
    int length;               // Number of addresses currently stored
    size_t memorySize;        // Total allocated memory size (in bytes) for address storage
} PROC_SCAN_RESULTS;

int initializeAddressQueue(PROC_SCAN_RESULTS* pScanResultsQueue);
int ResultQueueAddNewAddress(PROC_SCAN_RESULTS* resultsQueue, uint64_t address);
int cleanupResultsQueue(PROC_SCAN_RESULTS* resultsQueue);
#endif