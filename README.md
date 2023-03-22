# Summary

A library and binary (both built via cargo build) for testing unhooking ntdll by identifying hooks via in-memory disassembly,
identifying the original/relocated syscall block for the hooked function and fixing up the IAT pointer appropriately.

Only works for IAT functions (won't unhook runtime discovered functions e.g. via GetProcAddress).

Tested against Sophos free AV.

Only for a sample of unhooking using a technique other than loading a second ntdll or using direct/inline syscalls.

This repository consists of the following:

- src\bin.rs
    - Test code that's expected to be ran with a debugger attached (as it contains "int3" instructions to be caught by the debugger), point of this is to run it, step through the first NtWriteVirtualMemory call which should be hooked, then step through the second NtWriteVirtualMemory call which should be unhooked
- src\lib.rs
    - Exposes one function 'unhook_iat' which will walk the IAT and unhook any identified hooked NTDLL entries
- src\pe_helper.rs
    - Various helper functions for parsing in-memory PE32+ files 
- src\pe_defs.rs
    - Additional types for PE32+ file parsing
    
    
# Hooked vs Unhooked Comparison

Hooked:
![hooked_iat](https://user-images.githubusercontent.com/16039802/226813526-63c0278d-a6d8-4004-aed6-dc9cadf05d0d.png)

Unhooked:
![unhooked_iat](https://user-images.githubusercontent.com/16039802/226813548-d9b83110-64e4-42b9-8d5d-edd9205ff7f9.png)
