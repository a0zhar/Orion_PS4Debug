# PS4Debug
### Originally Created by **golden**
PS4Debug is a payload-based debugger for the PS4, written in C. It is a critical tool for enabling applications like **PS4Cheater** to perform remote debugging operations on a PS4 system via a PC.

Currently, the debugger operates in **User-Mode**, as kernel-mode debugging is not supported yet. However, there are plans to explore and implement kernel-mode functionality in the future.

## Support
This fork of PS4Debug supports PS4 system firmware: 5.05, 6.72, and 7.00 to 11.00.
- Thanks to [EchoStretch](https://github.com/EchoStretch)


## Features

The debugger offers several powerful features for managing processes, memory, and threads on the PS4. 
Below is a breakdown of its capabilities:
- Add, remove, and manage both software and hardware breakpoints.  
- Monitor specific memory addresses for read or write access using watchpoints.  
- Pause the execution of a process (freezing the game on the screen).  
- Resume a paused process.  
- Terminate a process by forcefully ending its execution.  
- Execute instructions one at a time after a breakpoint is hit (single-step execution), allowing for detailed analysis of program behavior.  
- Read memory from a process, enabling access to data stored in the process's memory.  
- Write memory to a process, modifying values stored in the process's memory.  
- View the memory layout of a process and inspect its memory regions and protections.  
- Retrieve metadata of running processes, such as process IDs (PIDs), names, paths, and other relevant details.  
- Pause individual threads within a process.  
- Resume paused threads.  
- Inspect thread details, including their state and register values.  
- Access and control CPU debug registers, enabling advanced breakpoint and watchpoint handling.

## Contributing
Contributions are welcome! If you’d like to report bugs, suggest features, or submit pull requests, feel free to open an issue.


### Contributors
- ChendoChap - For his intial work till 5.05 and his guidance during 6.72 porting on ptrace
- berkayylmao
- 2much4u
- idc
- zecoxao
- DeathRGH - For second [ptrace](https://github.com/GiantPluto/ps4debug/blob/457c2bf5468329e68a272b5f1e1ab88957f5f2d8/installer/source/installer.c#L53) patch for 6.72

## Credits
- [jogolden](https://github.com/jogolden/ps4debug) - for originally creating this
- [DeathRGH](https://github.com/DeathRGH/frame4) - for multi fw example
- [BestPig](https://github.com/BestPig) - Help with offsets
- [EchoStretch](https://github.com/EchoStretch/ps4debug) - Putting it all together
