# Summary

A library and binary (both built via cargo build) for testing unhooking ntdll by identifying hooks via in-memory disassembly.

`unhook_exports` will walk through the export table of NTDLL and unhook each exported function via in-memory disassembly + patching a jmp to the correct (relocated by EDR) function.

`unhook_iat` only works for IAT functions (won't unhook runtime discovered functions e.g. via GetProcAddress), note that this doesn't mean we are limited to fixing patched/modified IAT entries, most tested EDRs/AVs don't patch the IAT directly but the actual start of the function in ntdll itself that the IAT points to. We change the IAT pointer to point to the proper (relocated by the AV/EDR) syscall stub.

Tested against Sophos free AV.

Only for a sample of unhooking using a technique other than loading a second ntdll or using direct/inline syscalls.

This repository consists of the following:

- src\bin.rs
    - Test code that's expected to be ran with a debugger attached (as it contains "int3" instructions to be caught by the debugger), point of this is to run it, step through the first NtWriteVirtualMemory call which should be hooked, then step through the second NtWriteVirtualMemory call which should be unhooked
- src\lib.rs
    - Exposes the functions 'unhook_iat' and `unhook_exports`
- src\pe_helper.rs
    - Various helper functions for parsing in-memory PE32+ files 
- src\pe_defs.rs
    - Additional types for PE32+ file parsing
    
    
# Hooked vs Unhooked Comparison

Hooked:
![hooked_iat](https://user-images.githubusercontent.com/16039802/226813526-63c0278d-a6d8-4004-aed6-dc9cadf05d0d.png)

Unhooked:
![unhooked_iat](https://user-images.githubusercontent.com/16039802/226813548-d9b83110-64e4-42b9-8d5d-edd9205ff7f9.png)
