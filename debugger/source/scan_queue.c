//
// This is a Proof-of-Concept that will be used in PS4Debug's debugger
// component, in the function where the process memory is scanned for
// memory addreses containing a specific (in-game) value.
// 
// In summary:
// It's a dynamically growing array of unsigned 64-bit integers each
// representing a memory address found during scan post-filtering.
// Once the scan has been finished the memory addresses stored will
// then be sent back one by bone.
//

#include "../include/scan_queue.h"
//
// Function to initialize the process scan results structure
// Parameters:
// - pNewResultsQueue: pointer to the results queue struct
// Returns:
// - (-1) Upon Allocation Error | (1) Upon Success
int initializeAddressQueue(PROC_SCAN_RESULTS* pScanResultsQueue) {
    // Allocate and zero-initialize memory for the address results 
    // with the specified initial max capacity, and check if the
    // allocation failed, which if true we handle it
    uint64_t* pTempBodyMem = (uint64_t*)calloc(INITIAL_CAPACITY, sizeof(uint64_t));
    if (pTempBodyMem == NULL)
        return -1;


    // Initialize the fields of our process scan results queue structure instance
    pScanResultsQueue->addressResults = pTempBodyMem;       // Assign body with the allocated memory
    pScanResultsQueue->length = 0;                          // Initially no addresses stored
    pScanResultsQueue->space_avail = INITIAL_CAPACITY;      // Initial capacity (2000)

    // Initial memory size
    pScanResultsQueue->memorySize = INITIAL_CAPACITY * sizeof(uint64_t);

    return 1; // Return Success
}

// Function to add a new memory address to the results queue, resizing if needed
// Parameters:
// - resultsQueue: pointer to the results queue struct
// - address: the 64-bit memory address to add
// Returns:
// - (1) If the adding of the address was
// - (-1) In case of body being invalid
// - (-2) In case of realloc failing
int ResultQueueAddNewAddress(PROC_SCAN_RESULTS* resultsQueue, uint64_t address) {
    if (resultsQueue->addressResults == NULL)
        return -1;

    // First we perform a check for whether or not we need to resize
    // the memory region for the body before we can add new address
    if (resultsQueue->length >= resultsQueue->space_avail) {
        // Double the capacity to accommodate more addresses
        size_t new_capacity = resultsQueue->space_avail * 2;

        size_t new_mem_size = new_capacity * sizeof(uint64_t);
        // Re-allocate the memory region, to fit more addresses and then 
        // check if the allocation failed, which if true we handle it
        uint64_t* pNewResizedMem = (uint64_t*)realloc(resultsQueue->addressResults, new_mem_size);
        if (pNewResizedMem == NULL) {
            //uprintf("Failed to allocate memory for resizing.");
            return -2; // Exit if resizing fails
        }

        // Update the structure fields
        resultsQueue->addressResults = pNewResizedMem; // Update the address array pointer
        resultsQueue->space_avail = new_capacity;      // Update available space
        resultsQueue->memorySize = new_mem_size;       // Update memory size
    }

    // Add the new address and increment the length
    resultsQueue->addressResults[resultsQueue->length++] = address;
    return 1;
}


// Function to clean up after usage of the queue like implementation.
// Releases memory allocated for the results queue, and resets fields
// Parameters:
// - resultsQueue: pointer to the results queue struct
// Returns:
// - (1) Upon success
// - (-1) In case of body being invalid
int cleanupResultsQueue(PROC_SCAN_RESULTS* resultsQueue) {
    // Perform a check on the provided body variable, to see if it's
    // memory region isn't invalid which will result in an error
    if (resultsQueue->addressResults == NULL)
        return -1;

    // Deallocate the memory for address list storage
    free(resultsQueue->addressResults);
    resultsQueue->addressResults = NULL;
    resultsQueue->length = 0;      // Reset
    resultsQueue->space_avail = 0; // Reset
    resultsQueue->memorySize = 0;  // Reset
    return 1;
}