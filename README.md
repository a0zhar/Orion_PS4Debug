# PS4Debug
This payload project is a debugger for the PS4, written in C. It plays a crucial role in enabling programs like **PS4Cheater** and **PS4Reaper** to remotely perform debugging operations on the PS4 system from a PC.  

Currently, the debugger operates only in **User-Mode**, as kernel-mode debugging is not yet supported. While this limitation exists, there are plans to explore and implement kernel-mode functionality in the future.  


## Debugger Features
### Breakpoints and Watchpoints  
- You can set, remove, or manage software breakpoints as needed.  
- Hardware breakpoints are supported, using the PS4 CPU’s debug registers to pause programs conditionally.  
- Watchpoints are available to monitor specific memory locations for read or write access.

### Process Being Debugged
#### Process Execution Control Hijack
`The Debugger is able to hijack and control the execution, of the currently debugged process`
- Process control, include causing the Process to:
  - **Pause:** Temporarily stop process execution.
  - **Resume:** Continue execution after pausing.
  - **Terminate:** Forcefully stop running processes.
  - **Step Execution:** Run one instruction at a time for detailed debugging.

#### Process Memory Operations
- **Read and Write Process Memory**: 
  - The Debugger can read from, and write to, locations within the process memory.
- **Memory Map**: View the memory layout and protections for a process.
---

### Process Info  
- Get details about running processes, like IDs, names, paths, and more.

### Thread Management  
- Pause or resume specific threads within a process.  
- Get detailed info about threads, like their state and registers.

### Debug Context  
- Clean up resources when detaching from a process to ensure smooth operation.

### Debug Registers  
- Access and control CPU debug registers for managing breakpoints and watchpoints.

### Notifications and Errors  
- Get status updates and helpful error messages to understand what’s happening.

### Memory Management  
- **Allocate Memory**: Add memory to a target process for debugging purposes.  
- **Free Memory**: Remove memory allocations when they’re no longer needed.

### Communication  
- The debugger uses a reliable client-server system (RPC) to make sure everything communicates smoothly.

</details>
# TODO/Goal's List
- Making it PS4 Firmware agnostic:
  - So that instead of having to work with multiple projects, each supporting a different firmware version.<br>
    One could instead, implement a method that would automatically choose what FW-specific (ex: Offsets) to use in accordance to current fw.
- More **efficient**, and **optimized** comparison algorithm/logic used for scan results.
- More Stable version of PS4Debug, in which the likleyhood of kernel panics, freezing of processes, etc. are less
- A **Terminate PS4Debug** function, that the user can select on the PS4Cheater.
  - Function to be used in the event of the user not wanting to debug anymore:<br>
    It should do a full scale cleanup, doing things such:
    - Unsetting any current breakpoints or watchpoint.
    - Terminating any ongoing scans, or tasks being ran by the debugger.
    - Shutting down the network server any breakpoints, watchpoints, thenThis function will in the event of user wanting to quit debuggingFunction that will stop a more stable
Implementing a PS4 Firmware Agnostic approach:Firmware Agnostic approach
   Rather than having 5 Projects for each supported firmware (5.05, 6.72, 7.02, 7.55, 9.00).
   We can have a single project, that will automatically adjust offsets in accordance to fw.
