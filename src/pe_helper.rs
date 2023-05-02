extern crate alloc;

use crate::pe_def;
use crate::pe_helper::pe_def::{
    ASCIIString, ImageDataDirectory, ImageDataDirectoryEntry, ImageDataDirectoryInfo,
    ImageDataDirectoryVec, ImportAddressEntry, PEType, Pe64C, UnicodeString, PE64, RVA32,
};
use alloc::sync::Arc;
use core::arch::asm;
use core::mem::transmute;
use iced_x86::code_asm::*;
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, OpKind, Register};
use std::sync::Mutex;
use windows::Win32::Foundation::{GetLastError, HANDLE};
use windows::Win32::System::Memory::{PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS};

/// Error type for the PE helper
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PEHelperError {
    LockFailure,
    ModuleNotFound,
    VirtualProtectFailed,
    PEFileNotParsed,
    IATNotFound,
    AddressNotWithinModuleRange,
    ExportNameNotFound,
    ExportOrdinalNotFound,
    ExportAddressNotFound,
    ExportIsFowarder,
    ExportDirectoryTableNotFound,
    PeAlreadyParsed,
    InvalidDosSignature,
    InvalidPeSignature,
    UnhandledPeType,
    InvalidNumberOfDataDirectoryEntries,
    InvalidArgument,
    CodeAssemblerError(String),
    ExportNotFound,
    ExportNamePtrEntryNotFound,
    ExportOrdinalEntryNotFound,
}

// Global mutable vec of ModuleHandles using Mutex and Arc
static MODULES: Mutex<Vec<Arc<ModuleHandle64>>> = Mutex::new(Vec::new());
static VPROTECT: Mutex<Option<extern "system" fn(isize, *mut u64, usize, u64, *mut u32) -> i64>> =
    Mutex::new(None);

/// Attempts to unhook a single address, if hooked
pub fn unpatch_single(
    target: usize,
    ntdll_start: u64,
    ntdll_end: u64,
    addr_list: &Vec<usize>,
) -> Result<bool, PEHelperError> {
    let inner = unhook_iat_entry(
        None,
        Some(target as u64),
        ntdll_start,
        ntdll_end,
        None,
        addr_list,
    )?;
    return Ok(inner);
}

/// Attempts to unhook the IAT of the current process, returns Ok(true) if successful,
/// Ok(false) if no hooks were detected, or Err if an error occurred.
pub fn unpatch_iat_hooks(hmod: &ModuleHandle64) -> Result<bool, PEHelperError> {
    if !hmod.is_pe_parsed()? {
        // Parse the pe if its not already parsed
        hmod.parse_pe()?;
    }
    // We only unhook ntdll, ensure all unhooked entries
    // fall within ntdll
    let ntdll = match get_module_by_name("ntdll.dll") {
        Some(ntdll) => ntdll,
        None => return Err(PEHelperError::ModuleNotFound),
    };
    let ntdll_start = ntdll.get_base_address() as u64;
    let ntdll_end = ntdll_start + ntdll.get_size() as u64;
    let addr_listr = get_export_table(&ntdll).expect("Failed to get export table");
    let addr_list = &addr_listr;

    // Get exclusive access to the pe file
    let pe_lock = hmod.pe.lock().map_err(|_| PEHelperError::LockFailure)?;
    let pe = match pe_lock.as_ref() {
        Some(pe) => pe,
        None => return Err(PEHelperError::PEFileNotParsed),
    };

    // Get access to the import directory table
    let iat = match pe.get_data_directories().get_import_address_table() {
        Some(iat) => iat,
        None => return Err(PEHelperError::IATNotFound),
    };
    if iat.addresses.is_empty() {
        // No iat? No hooks
        return Ok(false);
    }
    let mut patched = false;
    // Loop through the iat, and check if any of the entries are hooked
    //println!("Looping through iat addresses");
    for iat_entry in iat.addresses.iter() {
        // Ensure the target is within ntdll, otherwise its another module or potentially uninitialized
        if iat_entry.target_function_address < (ntdll_start as u64)
            || iat_entry.target_function_address > (ntdll_end as u64)
        {
            continue;
        }
        /*println!(
            "IAT address :{:#x}, target: {:#x}",
            iat_entry.iat_entry_address, iat_entry.target_function_address
        );*/
        let result = unhook_iat_entry(
            Some(iat_entry),
            None,
            ntdll_start as u64,
            ntdll_end as u64,
            None,
            addr_list,
        )?;
        if result {
            println!(
                "Unhooked iat entry at {:x}, orig_target:{:#x}",
                iat_entry.iat_entry_address, iat_entry.target_function_address
            );
            patched = true;
        }
    }
    Ok(patched)
}

/// Attempts to get the unhooked start address of VirtualProtect
fn get_vprotect_addr(
    addr_list: &Vec<usize>,
) -> extern "system" fn(isize, *mut u64, usize, u64, *mut u32) -> i64 {
    // Get the address of ntdll
    let ntdll = get_module_by_name("ntdll.dll").unwrap();
    let target_str = "ZwProtectVirtualMemory";
    let target_addr = ntdll.get_export_addr_from_name(target_str).unwrap();
    let mut target_addr_ptr: usize = 0;
    let _res = unhook_iat_entry(
        None,
        Some(target_addr as u64),
        ntdll.get_base_address() as u64,
        (ntdll.get_base_address() + ntdll.get_size()) as u64,
        Some(&mut target_addr_ptr),
        &addr_list,
    )
    .unwrap();

    // Transmute target_addr_ptr and return
    let vprotect: extern "system" fn(isize, *mut u64, usize, u64, *mut u32) -> i64 =
        unsafe { transmute(target_addr_ptr) };
    vprotect
}

/// Takes an iat_entry, disassembles the target function to determine if its hooked,
/// if it is, it will unhook it and return Ok(true), if it is not hooked, it will return Ok(false),
/// if an error occurs, it will return Err.
fn unhook_iat_entry(
    iat_entry: Option<&ImportAddressEntry>,
    single_addr: Option<u64>,
    ntdll_start: u64,
    ntdll_end: u64,
    out_address: Option<&mut usize>,
    addr_list: &Vec<usize>,
) -> Result<bool, PEHelperError> {
    let is_single = single_addr.is_some();
    let is_iat = iat_entry.is_some();
    if is_single == is_iat {
        return Err(PEHelperError::InvalidArgument);
    }

    let (target_addr, mut replace_addr) = {
        if is_single {
            (single_addr.unwrap(), single_addr.unwrap())
        } else {
            (
                iat_entry.unwrap().target_function_address,
                iat_entry.unwrap().iat_entry_address,
            )
        }
    };
    //println!("Target addr: {:#x}, replace addr: {:#x}", target_addr, replace_addr);
    // Ensure the addresses are at least non-zero
    if target_addr == 0 || replace_addr == 0 {
        return Ok(false);
    }

    let virtual_protect = {
        if out_address.is_some() {
            None
        } else {
            let mut vprotect = VPROTECT.lock().map_err(|_| PEHelperError::LockFailure)?;
            match vprotect.as_ref() {
                Some(vprotect) => Some(*vprotect),
                None => {
                    let addr = get_vprotect_addr(addr_list);
                    vprotect.replace(addr);
                    //println!("Replaced vprotect, new address: {:#x}", addr as usize);
                    Some(addr)
                }
            }
        }
    };

    // Define the buffer of bytes to disassemble, we will disassemble 512-bytes at a time.
    // This is unsafe as we do little to no bounds checking.

    let target_len = 2000;
    let jmp_len = 8*4;
    // We loop until we patch the hook or reach the end of our analysis for this target address.

    let target_bytes = {
        let mut bytes = Vec::new();
        for i in 0..target_len {
            let byte = unsafe {
                std::ptr::read_unaligned((target_addr + i) as *const u8)
            };
            bytes.push(byte);
        }
        bytes
    };
    // Disassemble
    let mut decoder = Decoder::with_ip(
        64,
        &target_bytes,
        target_addr,
        DecoderOptions::NO_INVALID_CHECK,
    );
    // Determine what the opcode is for the first instruction
    let mut instruction = Instruction::default();
    // Decode the first instruction
    decoder.decode_out(&mut instruction);
    // If its not a Jmp, we assume its not hooked
    if instruction.code().op_code().mnemonic() != iced_x86::Mnemonic::Jmp {
        return Ok(false);
    }
    //println!("Found jmp hook");
    // Now change the decoder to decode the target of the jmp
    let target = instruction.near_branch_target();
    if target == 0 {
        // Not the jmp we expected
        return Ok(false);
    }
    //println!("Stage 1 jmp target: {:#x}", target);
    let target_bytes = {
        let mut bytes = Vec::new();
        for i in 0..jmp_len {
            let byte = unsafe {
                std::ptr::read_unaligned((target + i) as *const u8)
            };
            bytes.push(byte);
        }
        bytes
    };

    decoder = Decoder::with_ip(64, &target_bytes, target, DecoderOptions::NO_INVALID_CHECK);

    // This should be the second stage jmp
    instruction = Instruction::default();
    // Decode the second instruction
    decoder.decode_out(&mut instruction);
    let target_bytes ;
    // Support cases where its *not* a jmp, but if it is, we need to follow it
    if instruction.code().op_code().mnemonic() == iced_x86::Mnemonic::Jmp {
        // We expect this to be a jmp[mem], so we get the memory location, deref it and start a new decoder
        // at the new target
        let target_ptr = unsafe { &*(instruction.memory_displacement64() as *const u64) };
        //println!("Stage 2 jmp target: {:#x}", *target_ptr);
        target_bytes = {
            let mut bytes = Vec::new();
            for i in 0..target_len {
                let byte = unsafe {
                    std::ptr::read_unaligned((std::ptr::read_unaligned(target_ptr) + i) as *const u8)
                };
                bytes.push(byte);
            }
            bytes
        };

        decoder = Decoder::with_ip(
            64,
            &target_bytes,
            unsafe {std::ptr::read_unaligned(target_ptr)},
            DecoderOptions::NO_INVALID_CHECK,
        );
    }

    // Continue decoding instructions until we reach the end of the bytes or hit an end condition
    // (ret or syscall), if the instruction is a syscall then we assume the target is not hooked.
    let mut instr_since_rax = 0;
    // Keep track of the last rax indirect load, we expect this to be the address of the syscall stub
    // we want to restore when we find the target indirect call
    let mut rax_indirect_load = None;
    instruction = Instruction::default();
    while decoder.can_decode() {
        // Decode the next instruction
        decoder.decode_out(&mut instruction);

        // Check if the instruction is a syscall or a ret, in which case we assume its not hooked
        if instruction.code().op_code().mnemonic() == iced_x86::Mnemonic::Syscall
            || instruction.code().op_code().mnemonic() == iced_x86::Mnemonic::Ret
        {
            //println!("Found syscall or ret\n");
            return Ok(false);
        }

        if instruction.op_kind(0) == OpKind::Register && instruction.op_register(0) == Register::RAX
        {
            if instruction.op_kind(1) == OpKind::Memory {
                /*println!(
                    "Found RAX indirect load at instruction addr: {:#x}",
                    instruction.ip()
                );*/
                let displacement = instruction.memory_displacement64();
                if displacement < 0x10000 || displacement > 0x7FFF_FFFF_FFFF_FFFF {
                    // This is not a valid address, ignore it
                    rax_indirect_load = None;
                    instr_since_rax = 0;
                } else {
                    rax_indirect_load = Some(displacement);
                    instr_since_rax = 1;
                }
            } else {
                // Other operation on RAX, this may not actually modify RAX but its unexpected
                // so lets reset the counter
                instr_since_rax = 0;
                rax_indirect_load = None;
            }
        }
        // Not expecting more than 8 instructions between the RAX indirect load and the indirect call
        if instr_since_rax > 8 {
            instr_since_rax = 0;
            rax_indirect_load = None;
        }

        if instr_since_rax > 0 {
            instr_since_rax += 1;
        }
        // Check if the instruction is an indirect call
        if instruction.is_call_far_indirect() || instruction.is_call_near_indirect() {
            //println!("Found indirect far call");
            match rax_indirect_load {
                Some(rax_indirect_load_in) => {
                    let displacement = rax_indirect_load_in;
                    // Further validate the load contains a valid address, this can either be
                    // a syscall stub (starting with mov r10, rcx) this is the bytes 0x4c8bd1,
                    // or it can be an address within ntdll itself (as ntdll has functions
                    // that don't always result in instant syscalling)
                    let syscall_stub_start: [u8; 3] = [0x4c, 0x8b, 0xd1];
                    let syscall_stub_bytes = {
                        let mut bytes = Vec::new();
                        for i in 0..3 {
                            let byte = unsafe {
                                std::ptr::read_unaligned((displacement + i) as *const u8)
                            };
                            bytes.push(byte);
                        }
                        bytes
                    };
                    let is_syscall_stub = syscall_stub_bytes == syscall_stub_start;
                    // Now check if it falls within the address range of ntdll (we check for 1-level
                    // jmp, e.g. if the target contains an unconditional jmp to within ntdll)
                    let is_in_ntdll = {
                        if !is_syscall_stub {
                            // We treat the displacement as a pointer to the location to execute,
                            // we need to extract the containing 64-bit address
                            let target_ptr = unsafe { &*(displacement as *const u64) };
                            if replace_addr == 0x7ff82cd78e10 {
                                println!(
                                    "Pss target_ptr = {:#x}, raw displacement: {:#x}",
                                    *target_ptr, displacement
                                );
                            }
                            //println!("Checking if {:#x} contains a jmp within ntdll", *target_ptr);
                            contains_ntdll_jmp(*target_ptr, ntdll_start, ntdll_end, addr_list)
                        } else {
                            // Doesn't matter what we return here, we've determined the location
                            // is a syscall stub regardless
                            false
                        }
                    };

                    if !is_syscall_stub && !is_in_ntdll {
                        /*println!(
                            "Not syscall stub or within ntdll at address {:#x}",
                            displacement
                        );*/
                        rax_indirect_load = None;
                        instr_since_rax = 0;
                        continue;
                    } else {
                        /*println!(
                            "Found syscall stub or ntdll function at address {:#x}, for ip: {:#x}",
                            displacement,
                            instruction.ip()
                        );*/
                    }

                    /*println!(
                        "replace_addrp: {:#x}, rax_indirect_load_ptr: {:#x}",
                        replace_addr, rax_indirect_load_in
                    );*/
                    // We have a potential match
                    // Patch the IAT
                    //println!("Getting vprotect address");

                    let virtual_protect = match out_address {
                        Some(out_address) => {
                            *out_address = unsafe { *(rax_indirect_load_in as *const usize) };
                            return Ok(true);
                        }
                        None => virtual_protect.unwrap(),
                    };
                    //println!("Got it!, addr: {:#x}", virtual_protect as usize);
                    // First, call virtual_protect to make the page writable
                    let mut old_protect = PAGE_PROTECTION_FLAGS(0);
                    let sz: u64 = 8;
                    //println!("Calling vprotect to mark rwx");
                    let replace_addr_orig = replace_addr;

                    let result = {
                        let res = virtual_protect(
                            HANDLE(-1).0,
                            &mut replace_addr as *mut u64,
                            &sz as *const _ as usize,
                            PAGE_EXECUTE_READWRITE.0 as u64,
                            &mut old_protect.0,
                        );
                        let res = {
                            if res == 0xc0000045 {
                                let res_tmp = virtual_protect(
                                    HANDLE(-1).0,
                                    &mut replace_addr as *mut u64,
                                    &sz as *const _ as usize,
                                    PAGE_EXECUTE_READWRITE.0 as u64,
                                    &mut old_protect.0,
                                );
                                if res_tmp >= 0 {
                                    true
                                } else {
                                    false
                                }
                            } else {
                                if res >= 0 {
                                    true
                                } else {
                                    false
                                }
                            }
                        };
                        res
                    };
                    replace_addr = replace_addr_orig;
                    if !result {
                        println!("Error calling virtual protect: {:#x}", unsafe {
                            GetLastError().0
                        });
                        return Err(PEHelperError::VirtualProtectFailed);
                    }

                    // Get the actual target address
                    let rax_indirect_load = unsafe { *(rax_indirect_load_in as *const u64) };

                    if replace_addr == 0x7ff82cd78e10 {
                        println!(
                            "Found Pss, is_syscall_stub: {}, is_in_ntdll: {}, with addr:{:#x}",
                            is_syscall_stub, is_in_ntdll, rax_indirect_load
                        );
                    }

                    // Now we can patch the iat entry
                    let replace_ptr = replace_addr as *mut u64;
                    if is_iat {
                        unsafe { *replace_ptr = rax_indirect_load };
                    } else {
                        // Assemble a JMP <rax_indirect_load> instruction
                        let mut jmp_instruction = match CodeAssembler::new(64)
                            .map_err(|e| PEHelperError::CodeAssemblerError(format!("{:?}", e)))
                        {
                            Ok(jmp_instruction) => jmp_instruction,
                            Err(e) => {
                                let result = {
                                    let res = virtual_protect(
                                        HANDLE(-1).0,
                                        &mut replace_addr as *mut u64,
                                        &sz as *const _ as usize,
                                        old_protect.0 as u64,
                                        &mut old_protect.0,
                                    );
                                    let res = {
                                        if res == 0xc0000045 {
                                            let res_tmp = virtual_protect(
                                                HANDLE(-1).0,
                                                &mut replace_addr as *mut u64,
                                                &sz as *const _ as usize,
                                                old_protect.0 as u64,
                                                &mut old_protect.0,
                                            );
                                            if res_tmp >= 0 {
                                                true
                                            } else {
                                                false
                                            }
                                        } else {
                                            if res >= 0 {
                                                true
                                            } else {
                                                false
                                            }
                                        }
                                    };
                                    res
                                };
                                replace_addr = replace_addr_orig;
                                if !result {
                                    println!("Error calling virtual protect: {:#x}", unsafe {
                                        GetLastError().0
                                    });
                                    return Err(PEHelperError::VirtualProtectFailed);
                                }
                                return Err(e);
                            }
                        };
                        match jmp_instruction
                            .jmp(rax_indirect_load)
                            .map_err(|e| PEHelperError::CodeAssemblerError(format!("{:?}", e)))
                        {
                            Ok(_) => (),
                            Err(e) => {
                                let result = {
                                    let res = virtual_protect(
                                        HANDLE(-1).0,
                                        &mut replace_addr as *mut u64,
                                        &sz as *const _ as usize,
                                        old_protect.0 as u64,
                                        &mut old_protect.0,
                                    );
                                    let res = {
                                        if res == 0xc0000045 {
                                            let res_tmp = virtual_protect(
                                                HANDLE(-1).0,
                                                &mut replace_addr as *mut u64,
                                                &sz as *const _ as usize,
                                                old_protect.0 as u64,
                                                &mut old_protect.0,
                                            );
                                            if res_tmp >= 0 {
                                                true
                                            } else {
                                                false
                                            }
                                        } else {
                                            if res >= 0 {
                                                true
                                            } else {
                                                false
                                            }
                                        }
                                    };
                                    res
                                };
                                replace_addr = replace_addr_orig;
                                if !result {
                                    println!("Error calling virtual protect: {:#x}", unsafe {
                                        GetLastError().0
                                    });
                                    return Err(PEHelperError::VirtualProtectFailed);
                                }
                                return Err(e);
                            }
                        };
                        let bytes = jmp_instruction
                            .assemble(replace_addr)
                            .map_err(|e| PEHelperError::CodeAssemblerError(format!("{:?}", e)))?;
                        unsafe {
                            println!("Overwriting addr:{:#x}", replace_addr);
                            core::intrinsics::volatile_copy_nonoverlapping_memory(
                                replace_ptr as *mut u8,
                                bytes.as_ptr(),
                                bytes.len(),
                            );
                        }
                    }
                    // Now we can call virtual_protect to restore the old protection
                    let result = {
                        let res = virtual_protect(
                            HANDLE(-1).0,
                            &mut replace_addr as *mut u64,
                            &sz as *const _ as usize,
                            old_protect.0 as u64,
                            &mut old_protect.0,
                        );
                        let res = {
                            if res == 0xc0000045 {
                                let res_tmp = virtual_protect(
                                    HANDLE(-1).0,
                                    &mut replace_addr as *mut u64,
                                    &sz as *const _ as usize,
                                    old_protect.0 as u64,
                                    &mut old_protect.0,
                                );
                                if res_tmp >= 0 {
                                    true
                                } else {
                                    false
                                }
                            } else {
                                if res >= 0 {
                                    true
                                } else {
                                    false
                                }
                            }
                        };
                        res
                    };
                    replace_addr = replace_addr_orig;
                    if !result {
                        println!("Error calling virtual protect: {:#x}", unsafe {
                            GetLastError().0
                        });
                        return Err(PEHelperError::VirtualProtectFailed);
                    }
                    //println!("Done");
                    // Done, return
                    return Ok(true);
                }
                None => {
                    // Not expecting any other indirect calls, simply continue to the next instruction
                    continue;
                }
            };
        }
        // Check if instruction is a return
        if instruction.flow_control() == FlowControl::Return || instruction.is_invalid() {
            // Assume target isn't hooked as we didn't find the syscall stub
            //println!("Invalid instruction or return");
            return Ok(false);
        }
        instruction = Instruction::default();
    }
    // If we reached here, we didn't find the hook
    Ok(false)
}

fn contains_ntdll_jmp(
    displacement: u64,
    ntdll_start: u64,
    ntdll_end: u64,
    addr_list: &Vec<usize>,
) -> bool {
    // Check if the displacement is within the ntdll range, in which case we simply return true
    if displacement >= ntdll_start && displacement < ntdll_end {
        // Ensure displacement is not the start of a function, if so its not the hooked jmp
        // we expect and is likely a regular function call.
        for addr in addr_list {
            if *addr as u64 == displacement {
                return false;
            }
        }
        return true;
    }
    let mut instrs = 0;
    // Now check if the displacement contains a jmp to within ntdll
    let mut instruction = Instruction::default();
    let bytes = {
        let mut bytes = Vec::new();
        for i in 0..30 {
            let byte = unsafe {
                std::ptr::read_unaligned((displacement + i) as *const u8)
            };
            bytes.push(byte);
        }
        bytes
    };
    let mut decoder = Decoder::with_ip(64, &bytes, displacement, DecoderOptions::NO_INVALID_CHECK);
    while decoder.can_decode() {
        instrs += 1;
        // Check if we've exceeded our instr count, we don't expect the jmp to be more than
        // 30 instrs away
        if instrs > 30 {
            return false;
        }
        decoder.decode_out(&mut instruction);

        // Check if the instruction is a syscall or a ret, in which case we assume its not hooked
        if instruction.code().op_code().mnemonic() == iced_x86::Mnemonic::Syscall
            || instruction.code().op_code().mnemonic() == iced_x86::Mnemonic::Ret
        {
            //println!("Found syscall or ret\n");
            return false;
        }

        // Check if instr is an unconditional jmp
        if instruction.is_jmp_far_indirect() || instruction.is_jmp_near_indirect() {
            // Ensure its a jmp on memory
            if instruction.op_kind(0) == OpKind::Memory {
                // Check if the jmp target is within ntdll
                let jmp_target = instruction.memory_displacement64();
                if jmp_target >= ntdll_start && jmp_target < ntdll_end {
                    // Ensure displacement is not the start of a function, if so its not the hooked jmp
                    // we expect and is likely a regular function call.
                    for addr in addr_list {
                        if *addr as u64 == displacement {
                            continue;
                        }
                    }
                    return true;
                }
                // Expect jmp_target to be a pointer to a u64 we must deref in this case
                if jmp_target < 0x10000 || jmp_target > 0x7FFF_FFFF_FFFF_FFFF {
                    continue;
                }
                let jmp_target_ptr = unsafe { &*(jmp_target as *const u64) };
                if *jmp_target_ptr >= ntdll_start && *jmp_target_ptr < ntdll_end {
                    // Ensure displacement is not the start of a function, if so its not the hooked jmp
                    // we expect and is likely a regular function call.
                    for addr in addr_list {
                        if *addr as u64 == displacement {
                            continue;
                        }
                    }
                    return true;
                }
            }
        }
    }
    // Didn't find a jmp to within ntdll
    return false;
}

/// Returns an array of function pointers for a module's export table
pub fn get_export_table(hmod: &ModuleHandle64) -> Result<Vec<usize>, PEHelperError> {
    if !hmod.is_pe_parsed()? {
        // Parse the pe if its not already parsed
        hmod.parse_pe()?;
    }
    // At this point we guarantee the pe in the module handle is parsed
    let pe_lock = hmod.pe.lock().map_err(|_| PEHelperError::LockFailure)?;
    let pe = match pe_lock.as_ref() {
        Some(pe) => pe,
        None => return Err(PEHelperError::PEFileNotParsed),
    };
    let base_addr = hmod.get_base_address();
    // Get the export table so we can get the address of the export name pointer table and find
    // the index of the target function name
    let export_directory_table = match pe.get_data_directories().get_export_table() {
        Some(export_directory_table) => export_directory_table,
        None => return Err(PEHelperError::ExportDirectoryTableNotFound),
    };
    let mut export_addrs = Vec::new();
    for idx in 0..export_directory_table.number_of_functions {
        let export_entry = export_directory_table
            .get_export_address_table_entry(idx, base_addr)
            .ok_or(PEHelperError::ExportDirectoryTableNotFound)?;
        let addr = export_entry.0.get(base_addr);
        // transmute addr to a usize
        let addr: usize = unsafe { transmute(addr) };
        export_addrs.push(addr);
    }
    return Ok(export_addrs);
}

/// Custom GetProcAddress implementation by parsing the export directory table of a PE64 module
pub fn get_proc_address(
    hmod: &ModuleHandle64,
    target_func_name: &str,
) -> Result<extern "C" fn(), PEHelperError> {
    if !hmod.is_pe_parsed()? {
        // Parse the pe if its not already parsed
        hmod.parse_pe()?;
    }
    // At this point we guarantee the pe in the module handle is parsed
    let pe_lock = hmod.pe.lock().map_err(|_| PEHelperError::LockFailure)?;
    let pe = match pe_lock.as_ref() {
        Some(pe) => pe,
        None => return Err(PEHelperError::PEFileNotParsed),
    };
    // Get the export table so we can get the address of the export name pointer table and find
    // the index of the target function name
    let export_directory_table = match pe.get_data_directories().get_export_table() {
        Some(export_directory_table) => export_directory_table,
        None => return Err(PEHelperError::ExportDirectoryTableNotFound),
    };
    let ordinal_table_index = match export_directory_table
        .get_export_name_ptr_table_entry(target_func_name, pe.base_address)
    {
        Some(ordinal_table_index) => ordinal_table_index,
        None => return Err(PEHelperError::ExportNameNotFound),
    };
    let export_addr_index = match export_directory_table
        .get_export_ordinal_table_entry(ordinal_table_index, pe.base_address)
    {
        Some(export_addr_index) => export_addr_index,
        None => return Err(PEHelperError::ExportOrdinalNotFound),
    };
    let export_addr = match export_directory_table
        .get_export_address_table_entry(export_addr_index.0 as u32, pe.base_address)
    {
        Some(export_addr) => export_addr,
        None => return Err(PEHelperError::ExportAddressNotFound),
    };
    // Ensure the export address is within the module range
    let export_absolute = export_addr.0.get(pe.base_address) as *const _ as usize;
    let is_within_mod_range = {
        let mod_base = hmod.get_base_address();
        let mod_end = mod_base + hmod.get_size();
        export_absolute >= mod_base && export_absolute < mod_end
    };
    if !is_within_mod_range {
        return Err(PEHelperError::AddressNotWithinModuleRange);
    }
    // Determine if the export address is a forwarder by checking if its within range of the module's
    // export table
    let is_forwarder = pe
        .get_data_directories()
        .is_within_range(ImageDataDirectoryEntry::ExportTable, export_absolute)
        .unwrap();
    if is_forwarder {
        // Get the forwarder ASCII string and print it, we don't support forwarders
        let forwarder: &ASCIIString = unsafe { &*(export_absolute as *const ASCIIString) };
        let _forwarder_str = forwarder.to_string();
        return Err(PEHelperError::ExportIsFowarder);
    }
    // At this point we know the export address is not a forwarder
    Ok(unsafe { transmute(export_absolute) })
}

/// Finds a [`ModuleHandle`] in the PEB that matches the provided name.
/// Returns a handle to the module if found, otherwise returns None.
pub fn get_module_by_name(target_module_name: &str) -> Option<Arc<ModuleHandle64>> {
    // Search MODULES for an existing ModuleHandle with the same name
    // If found, return it
    // If not found, create a new ModuleHandle and return it
    let mut mod_array = match MODULES.lock() {
        Ok(mod_array) => mod_array,
        Err(_err) => return None,
    };
    for module in mod_array.iter() {
        if module.name.to_lowercase() == target_module_name.to_lowercase() {
            return Some(module.clone());
        }
    }
    let peb = match get_peb() {
        Some(peb) => peb,
        None => return None,
    };
    let ldr = unsafe { core::ptr::read_volatile(peb.ldr) };
    let mut current = ldr.in_memory_order_module_list.flink;
    // loop through in_memory_order_module_list
    loop {
        // adjust current pointer by subtracting the size of a ListEntry from it
        current = unsafe { current.sub(1) };
        let current_module = unsafe { &*(current as *const LdrDataTableEntry) };
        let current_module_name = match current_module.base_dll_name.extract_string() {
            Some(name) => name,
            None => return None,
        };
        if current_module_name.to_lowercase() == target_module_name.to_lowercase() {
            let module_handle = Arc::new(ModuleHandle64 {
                name: current_module_name,
                base: current_module.dll_base,
                size: current_module.size_of_image,
                pe: Mutex::new(None),
            });
            mod_array.push(module_handle.clone());
            return Some(module_handle);
        }
        current = current_module.in_memory_order_links.flink;
        if current == ldr.in_memory_order_module_list.flink {
            return None;
        }
    }
}

/// Finds a [`ModuleHandle`] in the PEB that matches the provided base address.
/// Returns a handle to the module if found, otherwise returns None.
pub fn get_module_by_address(target_module_address: usize) -> Option<Arc<ModuleHandle64>> {
    // Search MODULES for an existing ModuleHandle with the same address
    // If found, return it
    // If not found, create a new ModuleHandle and return it
    let mut mod_array = match MODULES.lock() {
        Ok(mod_array) => mod_array,
        Err(_err) => return None,
    };
    for module in mod_array.iter() {
        if module.base == target_module_address {
            return Some(module.clone());
        }
    }
    let peb = match get_peb() {
        Some(peb) => peb,
        None => return None,
    };
    let ldr = unsafe { core::ptr::read_volatile(peb.ldr) };
    let mut current = ldr.in_memory_order_module_list.flink;
    // loop through in_memory_order_module_list
    loop {
        // adjust current pointer by subtracting the size of a ListEntry from it
        current = unsafe { current.sub(1) };
        let current_module = unsafe { &*(current as *const LdrDataTableEntry) };
        let current_module_name = match current_module.base_dll_name.extract_string() {
            Some(name) => name,
            None => return None,
        };
        if current_module.dll_base == target_module_address {
            let module_handle = Arc::new(ModuleHandle64 {
                name: current_module_name,
                base: current_module.dll_base,
                size: current_module.size_of_image,
                pe: Mutex::new(None),
            });
            mod_array.push(module_handle.clone());
            return Some(module_handle);
        }
        current = current_module.in_memory_order_links.flink;
        if current == ldr.in_memory_order_module_list.flink {
            return None;
        }
    }
}

fn get_peb() -> Option<PEB> {
    // Check if GS register is null
    unsafe {
        let r_gs: usize;
        asm!("mov {}, gs", out(reg) r_gs, options(nomem, nostack));
        if r_gs == 0 {
            return None;
        }
    }
    let peb: *const PEB;
    unsafe {
        asm!("mov {}, gs:[0x60]", out(reg) peb);
        Some(core::ptr::read_volatile(peb))
    }
}

/// A handle to a loaded module.
pub struct ModuleHandle64 {
    /// The name of the module.
    name: String,
    /// The base address of the module.
    base: usize,
    /// The size of the module.
    size: usize,
    /// An optional parsed PE representation of the module
    pe: Mutex<Option<Box<PE64>>>,
}

impl ModuleHandle64 {
    /// Returns the name of the module.
    pub fn get_name(&self) -> &str {
        &self.name
    }
    /// Gets the internal PE
    pub fn get_pe(&self) -> &Mutex<Option<Box<PE64>>> {
        return &self.pe;
    }
    /// Returns the base field of the module.
    pub fn get_base_address(&self) -> usize {
        self.base
    }
    /// Returns the size field of the module
    pub fn get_size(&self) -> usize {
        self.size
    }
    pub fn get_export_addr_from_name(&self, target_str: &str) -> Result<usize, PEHelperError> {
        let mut pe_self = self.pe.lock().map_err(|_| PEHelperError::LockFailure)?;
        let pe = match pe_self.as_mut() {
            Some(pe) => pe,
            None => return Err(PEHelperError::PEFileNotParsed),
        };
        let export_table = match pe.get_data_directories().get_export_table() {
            Some(export_table) => export_table,
            None => return Err(PEHelperError::ExportDirectoryTableNotFound),
        };
        let target_ord = match export_table.get_export_name_ptr_table_entry(target_str, self.base) {
            Some(target_ord) => target_ord,
            None => return Err(PEHelperError::ExportNamePtrEntryNotFound),
        };
        let target_entry = match export_table.get_export_ordinal_table_entry(target_ord, self.base)
        {
            Some(target_entry) => target_entry,
            None => return Err(PEHelperError::ExportOrdinalEntryNotFound),
        };
        let target_addr =
            match export_table.get_export_address_table_entry(target_entry.0 as u32, self.base) {
                Some(target_addr) => target_addr,
                None => return Err(PEHelperError::ExportAddressNotFound),
            };
        let target_raw_addr = target_addr.0.get(self.base) as *const _ as usize;
        return Ok(target_raw_addr);
    }
    /// Parses the pe file represented by this module, stores the result
    /// in the associated pe variable and returns a result
    pub fn parse_pe(&self) -> Result<(), PEHelperError> {
        // Get a lock to the pe field, if the lock fails return an error
        let mut pe_self = self.pe.lock().map_err(|_| PEHelperError::LockFailure)?;
        // If the pe is already populated, return an error
        if pe_self.is_some() {
            return Err(PEHelperError::PeAlreadyParsed);
        }
        // Get the base address of the module
        let base_address = self.base;
        // Get the base address as a pointer to a PE64
        let pe_header = unsafe { &*(base_address as *const Pe64C) };
        // Verify the DOS signature is valid
        if !pe_header.dos_header.e_magic.is_valid() {
            return Err(PEHelperError::InvalidDosSignature);
        }
        // Get the NT headers from the pe_header e_lfanew
        let nt_headers = pe_header.get_nt_headers();
        // Verify the PE signature is valid
        if !nt_headers.signature.is_valid() {
            return Err(PEHelperError::InvalidPeSignature);
        }
        // Verify the PE type is valid
        if nt_headers.optional_header.magic != PEType::PE64 {
            return Err(PEHelperError::UnhandledPeType);
        }
        // parse the data directory entries and create the pe struct
        let num_data_directory_entries =
            nt_headers.optional_header.number_of_rva_and_sizes as usize;
        // Validate that the number of data directory entries is reasonable
        if num_data_directory_entries > 16 {
            return Err(PEHelperError::InvalidNumberOfDataDirectoryEntries);
        }
        // Create a vec of data directory entries from the PE header
        let data_directory_entries = unsafe {
            core::slice::from_raw_parts(
                &nt_headers.optional_header.data_directory as *const _ as *const ImageDataDirectory,
                num_data_directory_entries,
            )
        };
        // Turn data_directory_entries into a vec of ImageDataDirectoryInfo, the ImageDataDirectoryInfo.name
        // is obtained from the index of the data_directory_entries array
        let data_directory_info = data_directory_entries
            .iter()
            .enumerate()
            .map(|(i, entry)| ImageDataDirectoryInfo {
                virtual_address: RVA32::<()>(entry.virtual_address, core::marker::PhantomData),
                size: entry.size,
                base_address,
                name: ImageDataDirectoryEntry::from_index(i).unwrap(),
            })
            .collect::<Vec<_>>();

        let pe = Box::new(PE64 {
            pe64: Box::new((*pe_header).clone()),
            base_address,
            data_directories: ImageDataDirectoryVec(data_directory_info),
        });
        // Lock the pe field and set it to the parsed PE
        pe_self.replace(pe);
        Ok(())
    }
    /// Checks if the pe field is populated and returns a result with errors if
    /// the pe field is not populated, or if the lock failed to be obtained
    pub fn is_pe_parsed(&self) -> Result<bool, PEHelperError> {
        let pe_self = self.pe.lock().map_err(|_| PEHelperError::LockFailure)?;
        Ok(pe_self.is_some())
    }
}

// Create tests for this library
#[cfg(test)]
mod tests {
    use super::*;

    /// Get the 64-bit PEB
    #[test]
    fn test_get_peb() {
        let peb = get_peb();
        assert!(peb.is_some());
    }

    /// Get a module handle by name
    #[test]
    fn test_get_module_by_name() {
        let hmod = get_module_by_name("kernel32.dll");
        assert!(hmod.is_some());
    }
    /// Get multiple handles to the same module and verify the ref_count increase
    #[test]
    fn test_get_module_by_name_ref_count() {
        let hmod = get_module_by_name("kernel32.dll");
        assert!(hmod.is_some());
        // Assert hmod Arc ref_count is 2
        assert_eq!(Arc::strong_count(hmod.as_ref().unwrap()), 2);
        let hmod2 = get_module_by_name("kernel32.dll");
        assert!(hmod2.is_some());
        // Assert ref_count is 3
        assert_eq!(Arc::strong_count(hmod.as_ref().unwrap()), 3);
        drop(hmod2.unwrap());
        // Assert ref_count is 2
        assert_eq!(Arc::strong_count(hmod.as_ref().unwrap()), 2);
    }
    /// Test parsing a module as a PE file
    #[test]
    fn test_parse_pe() {
        let hmod = get_module_by_name("kernelbase.dll").unwrap();
        assert!(hmod.is_pe_parsed() == Ok(false));
        let res = hmod.parse_pe();
        assert!(res.is_ok(), "Failed to parse PE: {:#?}", res.err().unwrap());
        // assert that hmod.pe is populated
        assert!(hmod.is_pe_parsed() == Ok(true));
        // Assert that attempting to parse it again returns an error
        assert!(hmod.parse_pe().is_err());
    }
    /// Tests finding a function pointer by obtaining the ExportDirectoryTable and searching for
    /// the function name in the ExportNameTable, using its index in the ExportAddressTable and
    /// checking if the range is within the Export section
    #[test]
    fn get_ntdll_ntopenfile_function() {
        let target_function = "NtOpenFile";
        let hmod = get_module_by_name("ntdll.dll").unwrap();
        let res = hmod.parse_pe();
        assert!(res.is_ok(), "Failed to parse PE: {:#?}", res.err().unwrap());
        let pe_lock = hmod.pe.lock().unwrap();
        let pe = pe_lock.as_ref().unwrap();
        let export_directory_table = pe.get_data_directories().get_export_table().unwrap();
        let ordinal_table_index = export_directory_table
            .get_export_name_ptr_table_entry(target_function, pe.base_address)
            .unwrap();
        let export_addr_index = export_directory_table
            .get_export_ordinal_table_entry(ordinal_table_index, pe.base_address)
            .unwrap();
        let export_addr = export_directory_table
            .get_export_address_table_entry(export_addr_index.0 as u32, pe.base_address)
            .unwrap();
        let export_absolute = export_addr.0.get(pe.base_address) as *const _ as usize;
        let is_within_mod_range = {
            let export_addr_abs = export_addr as *const _ as usize;
            let mod_base = hmod.get_base_address();
            let mod_end = mod_base + hmod.get_size();
            export_addr_abs >= mod_base && export_addr_abs < mod_end
        };
        assert!(is_within_mod_range);
        let is_forwarder = pe
            .get_data_directories()
            .is_within_range(ImageDataDirectoryEntry::ExportTable, export_absolute)
            .unwrap();
        assert!(!is_forwarder);
    }

    /// Test get_proc_address to get CreateFileA from kernel32
    #[test]
    fn test_get_proc_address() {
        let hmod = get_module_by_name("kernel32.dll").unwrap();
        let res = hmod.parse_pe();
        assert!(res.is_ok(), "Failed to parse PE: {:#?}", res.err().unwrap());
        let enter_crit_sect = get_proc_address(hmod.as_ref(), "EnterCriticalSection");
        assert!(enter_crit_sect.is_err());
        let hmod2 = get_module_by_name("ntdll.dll").unwrap();
        let nt_create_file = get_proc_address(hmod2.as_ref(), "NtCreateFile");
        assert!(nt_create_file.is_ok());
    }
}

/// 64-bit LdrDataTableEntry
#[derive(Copy, Clone, Debug)]
#[repr(C)]
struct LdrDataTableEntry {
    in_load_order_links: ListEntry,
    in_memory_order_links: ListEntry,
    in_initialization_order_links: ListEntry,
    dll_base: usize,
    entry_point: usize,
    size_of_image: usize,
    full_dll_name: UnicodeString,
    base_dll_name: UnicodeString,
    flags: u32,
    load_count: u16,
    tls_index: u16,
    hash_links: ListEntry,
    time_date_stamp: u32,
}

/// Doubly linked list entry
#[derive(Copy, Clone, Debug)]
#[repr(C)]
struct ListEntry {
    flink: *const ListEntry,
    blink: *const ListEntry,
}

/// 64-bit PebLdrData
#[derive(Copy, Clone)]
#[repr(C)]
struct PebLdrData {
    junk: [usize; 4],
    in_memory_order_module_list: ListEntry,
}

/// Basic 64-bit PEB
#[derive(Copy, Clone)]
#[repr(C)]
struct PEB {
    junk1: u32,
    junk2: usize,
    junk3: usize,
    ldr: *const PebLdrData,
}
