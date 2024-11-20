#include <libc.h>
#include <network.h>
#include "../include/proc.h"
#include "../include/comparison.h"
#include "../include/kdbg.h"
#include "../include/net.h"
#include "../include/scan_queue.h"


int proc_list_handle(int fd, struct cmd_packet* packet) {
   uint64_t num;
   sys_proc_list(NULL, &num);
   if (num <= 0) {
      net_send_status(fd, CMD_DATA_NULL);
      return 1;
   }
   
   uint32_t length = sizeof(struct proc_list_entry) * num;
   void* data = pfmalloc(length);
   if (!data) {
      net_send_status(fd, CMD_DATA_NULL);
      return 1;
   }

   sys_proc_list(data, &num);
   net_send_status(fd, CMD_SUCCESS);
   networkSendData(fd, &num, sizeof(uint32_t));
   networkSendData(fd, data, length);

   free(data);
   return 0;
}



int proc_read_handle(int fd, struct cmd_packet* packet) {
   struct cmd_proc_read_packet* rp;
   void* data;

   // Cast packet data to the read command structure, before we 
   // check if the command packet is valid or not
   rp = (struct cmd_proc_read_packet*)packet->data;
   if (!rp) {
      net_send_status(fd, CMD_DATA_NULL);
      return 1;
   }

   // Allocate a buffer for reading data, and check if the memory
   // allocation failed or not. If it failed we handle it
   data = pfmalloc(NET_MAX_LENGTH);
   if (!data) {
      net_send_status(fd, CMD_DATA_NULL);
      return 1;
   }

   uint64_t left = rp->length;      // Remaining length to read
   uint64_t address = rp->address;  // Starting address to read from

   // Read in chunks
   while (left > 0) {
      memset(data, 0, NET_MAX_LENGTH);  // Clear the buffer

      // Determine the size to read in this iteration
      uint64_t bytes_to_read = (left > NET_MAX_LENGTH) ? NET_MAX_LENGTH : left;

      // Attempt to read the requested memory
      if (sys_proc_rw(rp->pid, address, data, bytes_to_read, 0) < 0) {
         free(data);  // Free allocated buffer
         net_send_status(fd, CMD_ERROR);  // Send error status
         return -1;  // Return with an error
      }

      // Send the read data back to the client
      networkSendData(fd, data, bytes_to_read);

      // Update the address and remaining bytes
      address += bytes_to_read;  // Move to the next address
      left -= bytes_to_read;     // Decrease the remaining length
   }

   // Send success status to PS4Cheater
   net_send_status(fd, CMD_SUCCESS);

   // Free the allocated buffer
   free(data);
   return 0;
}

int proc_write_handle(int fd, struct cmd_packet* packet) {
   struct cmd_proc_write_packet* wp;
   void* data;
   uint64_t left;
   uint64_t address;

   wp = (struct cmd_proc_write_packet*)packet->data;

   if (wp) {
      // only allocate a small buffer
      data = pfmalloc(NET_MAX_LENGTH);
      if (!data) {
         net_send_status(fd, CMD_DATA_NULL);
         return 1;
      }

      net_send_status(fd, CMD_SUCCESS);

      left = wp->length;
      address = wp->address;

      // write in chunks
      while (left > 0) {
         if (left > NET_MAX_LENGTH) {
            networkReceiveData(fd, data, NET_MAX_LENGTH, 1);
            sys_proc_rw(wp->pid, address, data, NET_MAX_LENGTH, 1);

            address += NET_MAX_LENGTH;
            left -= NET_MAX_LENGTH;
         }
         else {
            networkReceiveData(fd, data, left, 1);
            sys_proc_rw(wp->pid, address, data, left, 1);

            address += left;
            left -= left;
         }
      }

      net_send_status(fd, CMD_SUCCESS);

      free(data);

      return 0;
   }

   net_send_status(fd, CMD_DATA_NULL);
   return 1;
}

int proc_maps_handle(int fd, struct cmd_packet* packet) {
   struct cmd_proc_maps_packet* mp;
   struct sys_proc_vm_map_args args;
   uint32_t size;
   uint32_t num;

   mp = (struct cmd_proc_maps_packet*)packet->data;
   if (!mp) {
      net_send_status(fd, CMD_ERROR);
      return 1;
   }

   memset(&args, NULL, sizeof(args));

   if (sys_proc_cmd(mp->pid, SYS_PROC_VM_MAP, &args)) {
      net_send_status(fd, CMD_ERROR);
      return 1;
   }

   size = args.num * sizeof(struct proc_vm_map_entry);

   args.maps = (struct proc_vm_map_entry*)pfmalloc(size);
   if (!args.maps) {
      net_send_status(fd, CMD_DATA_NULL);
      return 1;
   }

   if (sys_proc_cmd(mp->pid, SYS_PROC_VM_MAP, &args)) {
      free(args.maps);
      net_send_status(fd, CMD_ERROR);
      return 1;
   }

   net_send_status(fd, CMD_SUCCESS);
   num = (uint32_t)args.num;
   networkSendData(fd, &num, sizeof(uint32_t));
   networkSendData(fd, args.maps, size);

   free(args.maps);

   return 0;

}

int proc_install_handle(int fd, struct cmd_packet* packet) {
   struct cmd_proc_install_packet* ip;
   struct sys_proc_install_args args;
   struct cmd_proc_install_response resp;

   ip = (struct cmd_proc_install_packet*)packet->data;
   if (!ip) {
      net_send_status(fd, CMD_DATA_NULL);
      return 1;
   }

   args.stubentryaddr = NULL;
   sys_proc_cmd(ip->pid, SYS_PROC_INSTALL, &args);

   if (!args.stubentryaddr) {
      net_send_status(fd, CMD_DATA_NULL);
      return 1;
   }

   resp.rpcstub = args.stubentryaddr;

   net_send_status(fd, CMD_SUCCESS);
   networkSendData(fd, &resp, CMD_PROC_INSTALL_RESPONSE_SIZE);

   return 0;
}

int proc_call_handle(int fd, struct cmd_packet* packet) {
   struct cmd_proc_call_response resp;
   struct cmd_proc_call_packet* cp;

   cp = (struct cmd_proc_call_packet*)packet->data;
   if (!cp) {
      net_send_status(fd, CMD_DATA_NULL);
      return 1;
   }

   struct sys_proc_call_args args;
   // copy over the arguments for the call
   args.pid = cp->pid;
   args.rpcstub = cp->rpcstub;
   args.rax = NULL;
   args.rip = cp->rpc_rip;
   args.rdi = cp->rpc_rdi;
   args.rsi = cp->rpc_rsi;
   args.rdx = cp->rpc_rdx;
   args.rcx = cp->rpc_rcx;
   args.r8 = cp->rpc_r8;
   args.r9 = cp->rpc_r9;
   sys_proc_cmd(cp->pid, SYS_PROC_CALL, &args);

   resp.pid = cp->pid;
   resp.rpc_rax = args.rax;
   net_send_status(fd, CMD_SUCCESS);
   networkSendData(fd, &resp, CMD_PROC_CALL_RESPONSE_SIZE);
   return 0;
}

int proc_elf_handle(int fd, struct cmd_packet* packet) {
   struct cmd_proc_elf_packet* ep;
   struct sys_proc_elf_args args;
   void* elf;

   ep = (struct cmd_proc_elf_packet*)packet->data;
   if (!ep) {
      net_send_status(fd, CMD_ERROR);
      return 1;
   }

   elf = pfmalloc(ep->length);
   if (!elf) {
      net_send_status(fd, CMD_DATA_NULL);
      return 1;
   }

   net_send_status(fd, CMD_SUCCESS);
   networkReceiveData(fd, elf, ep->length, 1);
   args.elf = elf;
   if (sys_proc_cmd(ep->pid, SYS_PROC_ELF, &args)) {
      free(elf);
      net_send_status(fd, CMD_ERROR);
      return 1;
   }

   free(elf);
   net_send_status(fd, CMD_SUCCESS);
   return 0;
}

int proc_protect_handle(int fd, struct cmd_packet* packet) {
   struct cmd_proc_protect_packet* pp;
   struct sys_proc_protect_args args;

   pp = (struct cmd_proc_protect_packet*)packet->data;
   if (!pp) {
      net_send_status(fd, CMD_DATA_NULL);
      return 0;
   }

   args.address = pp->address;
   args.length = pp->length;
   args.prot = pp->newprot;
   sys_proc_cmd(pp->pid, SYS_PROC_PROTECT, &args);
   net_send_status(fd, CMD_SUCCESS);
   return 0;
}

size_t get_size_of_process_scan_value_type(ProcScanValueType valType) {
   switch (valType) {
      case valTypeUInt8:
      case valTypeInt8:
         return 1;
      case valTypeUInt16:
      case valTypeInt16:
         return 2;
      case valTypeUInt32:
      case valTypeInt32:
      case valTypeFloat:
         return 4;
      case valTypeUInt64:
      case valTypeInt64:
      case valTypeDouble:
         return 8;
      case valTypeArrBytes:
      case valTypeString:
      default:
         return NULL;
   }
}
bool ProcessScanValueComparison(ProcScanCompareType cmpType, ProcScanValueType valType, size_t valTypeLength, _BYTE* pScanValue, _BYTE* pMemoryValue, _BYTE* pExtraValue) {
   switch (cmpType) {
      case ST_Exact_Value:          return compare_exact_value(pScanValue, pMemoryValue, valTypeLength);
      case ST_Fuzzy_Value:          return compare_fuzzy_value(valType, pScanValue, pMemoryValue);
      case ST_Bigger_Than:          return compare_bigger_than(valType, pScanValue, pMemoryValue);
      case ST_Smaller_Than:         return compare_smaller_than(valType, pScanValue, pMemoryValue);
      case ST_Value_Between:        return compare_value_between(pMemoryValue, pScanValue, pExtraValue, valType);
      case ST_Increased_Value:      return compare_increased_value(valType, pScanValue, pMemoryValue, pExtraValue);
      case ST_Decreased_Value:      return compare_decreased_value(valType, pScanValue, pMemoryValue, pExtraValue);
      case ST_Increased_Value_By:    return compare_increased_value_by(valType, pScanValue, pMemoryValue, pExtraValue);
      case ST_Decreased_Value_By:    return compare_decreased_value_by(valType, pScanValue, pMemoryValue, pExtraValue);
      case ST_Changed_Value:        return compare_changed_value(valType, pScanValue, pMemoryValue, pExtraValue);
      case ST_Unchanged_Value:      return compare_unchanged_value(valType, pScanValue, pMemoryValue, pExtraValue);
      case ST_Unknown_Value: return true;
      default:                         return false;
   }
}

int proc_scan_handle(int fd, struct cmd_packet* packet) {
   struct cmd_proc_scan_packet* sp = (struct cmd_proc_scan_packet*)packet->data;

   if (!sp) {
      net_send_status(fd, CMD_DATA_NULL);
      return 1;
   }

   // get and set data
   size_t valueLength = get_size_of_process_scan_value_type(sp->valueType);
   if (!valueLength) {
      valueLength = sp->lenData;
   }

   unsigned char* data = (unsigned char*)pfmalloc(sp->lenData);
   if (!data) {
      net_send_status(fd, CMD_DATA_NULL);
      return 1;
   }

   net_send_status(fd, CMD_SUCCESS);

   networkReceiveData(fd, data, sp->lenData, 1);

   // query for the process id
   struct sys_proc_vm_map_args args;
   memset(&args, NULL, sizeof(struct sys_proc_vm_map_args));
   if (sys_proc_cmd(sp->pid, SYS_PROC_VM_MAP, &args)) {
      free(data);
      net_send_status(fd, CMD_ERROR);
      return 1;
   }

   size_t size = args.num * sizeof(struct proc_vm_map_entry);
   args.maps = (struct proc_vm_map_entry*)pfmalloc(size);
   if (!args.maps) {
      free(data);
      net_send_status(fd, CMD_DATA_NULL);
      return 1;
   }

   if (sys_proc_cmd(sp->pid, SYS_PROC_VM_MAP, &args)) {
      free(args.maps);
      free(data);
      net_send_status(fd, CMD_ERROR);
      return 1;
   }

   net_send_status(fd, CMD_SUCCESS);

   uprintf("scan start");

   unsigned char* pExtraValue = valueLength == sp->lenData ? NULL : &data[valueLength];
   unsigned char* scanBuffer = (unsigned char*)pfmalloc(PAGE_SIZE);
   for (size_t i = 0; i < args.num; i++) {
      if ((args.maps[i].prot & PROT_READ) != PROT_READ) {
         continue;
      }

      uint64_t sectionStartAddr = args.maps[i].start;
      size_t sectionLen = args.maps[i].end - sectionStartAddr;

      // scan
      for (uint64_t j = 0; j < sectionLen; j += valueLength) {
         if (j == 0 || !(j % PAGE_SIZE)) {
            sys_proc_rw(sp->pid, sectionStartAddr, scanBuffer, PAGE_SIZE, 0);
         }

         uint64_t scanOffset = j % PAGE_SIZE;
         uint64_t curAddress = sectionStartAddr + j;
         if (ProcessScanValueComparison(sp->compareType, sp->valueType, valueLength, data, scanBuffer + scanOffset, pExtraValue)) {
            networkSendData(fd, &curAddress, sizeof(uint64_t));
         }
      }
   }

   uprintf("scan done");

   uint64_t endflag = 0xFFFFFFFFFFFFFFFF;
   networkSendData(fd, &endflag, sizeof(uint64_t));

   free(scanBuffer);
   free(args.maps);
   free(data);

   return 0;
}

int ConsoleBasedProcessScanner(int fd, struct cmd_packet* packet) {
   struct sys_proc_vm_map_args args; // Structure for storing the memory map of the target process
   struct cmd_proc_scan_packet* sp;  // Pointer to structure holding packet data for scanning commands
   PROC_SCAN_RESULTS resultsQueue;   // Queue structure for storing found matching addresses
   unsigned char* pExtraValue;       // Pointer for holding any additional value data if specified
   unsigned char* scanBuffer;        // Buffer for reading memory pages during scanning
   unsigned char* data;              // Buffer to hold value data received from the client
   size_t ScanValueTypeLen;          // Size of the value type specified in the scan packet
   size_t size;                      // Size needed to hold all process memory map entries

   // Cast the packet's data to a specific structure for process 
   // scanning commands, and check if the packet data is invalid
   // which if this is true, we handle it
   sp = (struct cmd_proc_scan_packet*)packet->data;
   if (!sp) {
      // Notify client of null data error
      net_send_status(fd, CMD_DATA_NULL);
      return 1;
   }

   // Retrieve the size of the value type specified in the PS4Cheater GUI that
   // the user wants to look for. Example: byte, 2 bytes, 4 bytes
   ScanValueTypeLen = get_size_of_process_scan_value_type(sp->valueType);
   if (!ScanValueTypeLen)
      ScanValueTypeLen = sp->lenData;

   // Allocate memory for the value data received from the client. 
   // Then we check if allocation failed, and handle it
   data = (unsigned char*)pfmalloc(sp->lenData);
   if (!data) {
      // Notify client of data allocation error
      net_send_status(fd, CMD_DATA_NULL);
      return 1;
   }

   net_send_status(fd, CMD_SUCCESS);        // Notify client of successful initialization
   networkReceiveData(fd, data, sp->lenData, 1); // Receive the data to be scanned from client

   // Initialize the process memory map structure, and clear it from junk using memset
   memset(&args, NULL, sizeof(struct sys_proc_vm_map_args));
   // Populate memory map entries for process
   if (sys_proc_cmd(sp->pid, SYS_PROC_VM_MAP, &args)) {
      free(data); // Free allocated data memory
      // Notify client of command execution error
      net_send_status(fd, CMD_ERROR);
      return 1;
   }

   // Allocate memory to hold process memory segments based on number of entries
   // Then Check if allocation failed and handle it
   size = args.num * sizeof(struct proc_vm_map_entry);
   args.maps = (struct proc_vm_map_entry*)pfmalloc(size);
   if (!args.maps) {
      free(data); // Free previous allocations  
      // Notify client of allocation error
      net_send_status(fd, CMD_DATA_NULL);
      return 1;
   }

   // Refresh the process memory map to confirm allocations and populate memory segments
   if (sys_proc_cmd(sp->pid, SYS_PROC_VM_MAP, &args)) {
      free(args.maps); // Free allocated memory for process segments
      free(data);      // Free allocated data memory
      // Notify client of error
      net_send_status(fd, CMD_ERROR);
      return 1;
   }

   net_send_status(fd, CMD_SUCCESS); // Notify client of successful command completion
   uprintf("Scan started");          // Log message to indicate scan has started

   // Initialize queue structure for storing found memory addresses
   // And check for errors
   if (initializeAddressQueue(&resultsQueue) < 0) {
      free(args.maps); // Free memory for process segments
      free(data); // Free allocated data memory
      // Notify client of queue initialization error
      net_send_status(fd, CMD_ERROR);
      return 1;
   }

   // Define extra value buffer if value length is different from data length
   pExtraValue = ScanValueTypeLen == sp->lenData ? NULL : &data[ScanValueTypeLen];

   // Allocate buffer for reading memory pages, and check if 
   // allocation with prefaulting failed
   scanBuffer = (unsigned char*)pfmalloc(PAGE_SIZE);
   if (scanBuffer == NULL) {
      // Cleanup allocated resources and notify client of allocation error
      free(args.maps);
      free(data);
      cleanupResultsQueue(&resultsQueue);
      net_send_status(fd, CMD_DATA_NULL);
      return 1;
   }

   // Begin scanning through each segment in the process memory map
   for (size_t i = 0; i < args.num; i++) {
      // Skip segments without read permissions
      if ((args.maps[i].prot & PROT_READ) != PROT_READ)
         continue;

      // Start address of the current memory segment
      uint64_t sectionStartAddr = args.maps[i].start;

      // Length of the current memory segment
      size_t sectionLen = args.maps[i].end - sectionStartAddr;

      // Scan each value-sized chunk within the segment
      for (uint64_t j = 0; j < sectionLen; j += ScanValueTypeLen) {
         // Load a new page of memory if needed, based on scan offset
         if (j == 0 || !(j % PAGE_SIZE)) {
            // Read page into buffer
            sys_proc_rw(
               sp->pid,          // Process ID of the target process to read memory from
               sectionStartAddr, // Base address of the segment from which to read memory
               scanBuffer,       // Buffer to store the memory data read from the process
               PAGE_SIZE,        // Number of bytes to read from memory
               0                 // Flag indicating read operation (write = 0)
            );
         }
         // Offset within the scan buffer for reading memory addresses
         uint64_t scanOffset = j % PAGE_SIZE; // Calculate offset within page buffer

         // Current address being scanned in the memory segment
         uint64_t curAddress = sectionStartAddr + j; // Calculate current address in segment

         // Compare current address's value with target using specified compare type and value
         if (ProcessScanValueComparison(sp->compareType, sp->valueType, ScanValueTypeLen, data, scanBuffer + scanOffset, pExtraValue)) {
            // Add matching address to results queue; handle error if it fails
            if (ResultQueueAddNewAddress(&resultsQueue, curAddress) < 0) {
               uprintf("Failed to add address to queue"); // Log failure
               cleanupResultsQueue(&resultsQueue); // Clean up queue
               free(scanBuffer); // Free scan buffer
               free(args.maps); // Free memory for process segments
               free(data); // Free allocated data memory
               return -1; // Exit function with error status
            }
         }
      }
   }

   uprintf("Scan complete"); // Log message indicating scan is complete

   // Send each stored address in the queue back to the client
   for (int k = 0; k < resultsQueue.length; k++)
      // Send each address
      networkSendData(
         fd,
         &resultsQueue.addressResults[k],
         sizeof(uint64_t)
      );

   // Flag indicating the end of address transmission to client
   uint64_t endflag = 0xFFFFFFFFFFFFFFFF;

   // Send end-of-scan flag to client to signal end of transmission
   networkSendData(fd, &endflag, sizeof(uint64_t));


   // Cleanup dynamically allocated memory to prevent leaks
   cleanupResultsQueue(&resultsQueue); // Free memory used by address results queue
   free(scanBuffer);                   // Free scan buffer used during memory reading
   free(args.maps);                    // Free memory used by process segments
   free(data);                         // Free received data buffer

   return 0; // Return success status
}


int proc_info_handle(int fd, struct cmd_packet* packet) {
   struct cmd_proc_info_packet* ip;
   struct sys_proc_info_args args;
   struct cmd_proc_info_response resp;

   ip = (struct cmd_proc_info_packet*)packet->data;
   if (!ip) {
      net_send_status(fd, CMD_DATA_NULL);
      return 0;
   }

   sys_proc_cmd(ip->pid, SYS_PROC_INFO, &args);
   resp.pid = args.pid;
   memcpy(resp.name, args.name, sizeof(resp.name));
   memcpy(resp.path, args.path, sizeof(resp.path));
   memcpy(resp.titleid, args.titleid, sizeof(resp.titleid));
   memcpy(resp.contentid, args.contentid, sizeof(resp.contentid));
   net_send_status(fd, CMD_SUCCESS);
   networkSendData(fd, &resp, CMD_PROC_INFO_RESPONSE_SIZE);
   return 0;
}

int proc_alloc_handle(int fd, struct cmd_packet* packet) {
   struct cmd_proc_alloc_packet* ap;
   struct sys_proc_alloc_args args;
   struct cmd_proc_alloc_response resp;

   ap = (struct cmd_proc_alloc_packet*)packet->data;
   if (!ap) {
      net_send_status(fd, CMD_DATA_NULL);
      return 0;
   }

   args.length = ap->length;
   sys_proc_cmd(ap->pid, SYS_PROC_ALLOC, &args);
   resp.address = args.address;
   net_send_status(fd, CMD_SUCCESS);
   networkSendData(fd, &resp, CMD_PROC_ALLOC_RESPONSE_SIZE);
   return 0;
}

int proc_free_handle(int fd, struct cmd_packet* packet) {
   struct cmd_proc_free_packet* fp;
   struct sys_proc_free_args args;

   fp = (struct cmd_proc_free_packet*)packet->data;
   if (!fp) {
      net_send_status(fd, CMD_DATA_NULL);
      return 0;
   }

   args.address = fp->address;
   args.length = fp->length;
   sys_proc_cmd(fp->pid, SYS_PROC_FREE, &args);
   net_send_status(fd, CMD_SUCCESS);
   return 0;
}

int proc_handle(int fd, struct cmd_packet* packet) {
   switch (packet->cmd) {
      case CMD_PROC_LIST:return proc_list_handle(fd, packet);
      case CMD_PROC_READ:return proc_read_handle(fd, packet);
      case CMD_PROC_WRITE:return proc_write_handle(fd, packet);
      case CMD_PROC_MAPS:return proc_maps_handle(fd, packet);
      case CMD_PROC_INSTALL:return proc_install_handle(fd, packet);
      case CMD_PROC_CALL:return proc_call_handle(fd, packet);
      case CMD_PROC_ELF:return proc_elf_handle(fd, packet);
      case CMD_PROC_PROTECT:return proc_protect_handle(fd, packet);
      case CMD_PROC_SCAN:return proc_scan_handle(fd, packet);
      case CMD_PROC_INFO:return proc_info_handle(fd, packet);
      case CMD_PROC_ALLOC:return proc_alloc_handle(fd, packet);
      case CMD_PROC_FREE:return proc_free_handle(fd, packet);
   };

   return 1;
}
