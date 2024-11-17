# PS4Debug
PS4Debug is a payload-based debugger for the PS4, written in C. It is a critical tool for enabling applications like **PS4Cheater** to perform remote debugging operations on a PS4 system via a PC.

Currently, the debugger operates in **User-Mode**, as kernel-mode debugging is not supported yet. However, there are plans to explore and implement kernel-mode functionality in the future.
<br><br>

## Quickstart Guide
**If you're not looking to modify the source code of PS4Debug and just want to use it, here's a simple step-by-step guide:**
<details>
  <summary>See Steps</summary>

1. **Download PS4Cheater**  
   Get the latest version of PS4Cheater from [this link](https://github.com/ctn123/PS4_Cheater/releases/download/1.5.4.7/PS4_Cheater_v1.5.4.7_rev2_x64.rar).
2. **Download PS4Debug**  
   Download the latest version of the `ps4debug.bin` file from one of the following sources:  
   - This repository’s [Releases page](https://github.com/a0zhar/PS4_Debug/releases/)  
   - [CTN123's Release Page](https://github.com/ctn123/PS4_Cheater/releases/download/1.5.4.7/ps4debug.bin)
3. **Visit an Exploit Host**  
   Choose an exploit host and run a Homebrew Enabler. I recommend one of the following:
   - [Karo218](https://Kar0218.github.io/)
   - [GamerHack](https://gamerhack.github.io)
4. **Run the Bin Loader Payload**  
   **(Avoid using the one from GOLDHEN)**.  
   After running the Bin Loader, your PS4 should show a system notification with a code—either 9021 or 9020.
5. **Configure PS4Cheater**  
   On your PC, open PS4Cheater and enter:
   - Your PS4’s **IP Address**
   - The **Port number** displayed in the notification after loading the Bin Loader.
6. **Confirm Connection**  
   If successful, PS4Cheater will display **"PS4Debug.bin Successfully Injected!"**.
7. **Start the Game**  
   Launch your favorite game on the PS4.
8. **Attach to the Process**  
   Attach PS4Cheater to the game or userland process you want to debug.
9. **Enjoy the Debugging**  
   You’re now set to enjoy remote debugging and more!
</details>

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
