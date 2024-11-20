# PS4Debug
PS4Debug is a payload-based debugger for the PS4, written in C. It is a critical tool for enabling applications like **PS4Cheater** to perform remote debugging operations on a PS4 system via a PC.

Currently, the debugger operates in **User-Mode**, as kernel-mode debugging is not supported yet. However, there are plans to explore and implement kernel-mode functionality in the future.

## Support
This fork of PS4Debug supports PS4 system firmware: 5.05, 6.72, and 7.00 to 11.00.
- Thanks to [EchoStretch](https://github.com/EchoStretch)


## Features

The debugger offers several powerful features for managing processes, memory, and threads on the PS4. Below is a breakdown of its capabilities:

<details>
  <summary>General Debugging Features</summary>

- **Debugger is able to**:
  - Add, remove, and manage both software and hardware breakpoints.
  - Monitor specific memory addresses for read/write access using watchpoints.
  
</details>

<details>
  <summary>Process Execution Control</summary>
  
- **Debugger is able to**:
  - Pause the execution of a process (causes the game to freeze on the screen).  
  - Resume a paused process.  
  - Terminate a process by forcefully ending its execution.  
  - Execute instructions one at a time after a breakpoint is hit (Single-Step Execution), allowing for detailed analysis of program behavior.

</details>

<details>
  <summary>Memory Operations</summary>
  
- **Debugger is able to**:
  - Read memory from a process: Allowing access to data stored in the process’s memory.  
  - Write memory to a process: Modifying the values stored in the process’s memory.  
  - View the memory layout of a process: And inspect its memory regions and protections.

</details>

<details>
  <summary>Process Information</summary>
  
- **Debugger is able to**:
  - Retrieve metadata of running processes: Such as their process IDs (PIDs), names, paths, and other relevant details.

</details>

<details>
  <summary>Thread Management</summary>
  
- **Debugger is able to**:
  - pause individual threads within a process.  
  - resume paused threads.  
  - inspect thread details: including their state and register values.

</details>

<details>
  <summary>Debug Registers</summary>
  
- **Debugger is able to**:
  - access and control CPU debug registers: enabling advanced breakpoint and watchpoint handling.

</details>


## Goals and Future Plans
- **1. Firmware-Agnostic Support**:  
  Implement a method to make PS4Debug adaptable to any PS4 firmware version by dynamically selecting offsets and configurations based on the detected firmware.  
- **2. Improved Performance**:  
  Optimize the scanning and comparison algorithms for better efficiency and faster processing.  
- **3. Enhanced Stability**:  
  Reduce the likelihood of kernel panics and process crashes during debugging operations.  
- **4. Terminate PS4Debug Function**:  
  Add a function to cleanly stop PS4Debug when the user no longer wishes to debug. This would involve:  
  - Removing all breakpoints and watchpoints.  
  - Canceling ongoing scans and other tasks.  
  - Shutting down the network server.  
