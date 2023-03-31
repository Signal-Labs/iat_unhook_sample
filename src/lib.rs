#![feature(core_intrinsics)]

mod pe_def;
pub mod pe_helper;

use crate::pe_helper::{unpatch_iat_hooks, unpatch_single};
use windows::Win32::System::LibraryLoader::GetModuleHandleA;

/// Unhooks via disassembling each exported function and patching any identified jmps directly
/// at the function's start, this enables unhooking of functions regardless if they're in our
/// current IAT and works for functions that are called dynamically via GetProcAddress.
pub fn unhook_exports() -> bool {
    // Get a handle to the module ntdll using pehelper
    let ntdll = match pe_helper::get_module_by_name("ntdll.dll") {
        Some(ntdll) => ntdll,
        None => return false,
    };
    let ntdll_start = ntdll.get_base_address() as u64;
    let ntdll_end = ntdll_start + ntdll.get_size() as u64;
    let addr_list = pe_helper::get_export_table(&ntdll).expect("Failed to get export table");
    let addr_list_clone = addr_list.clone();
    for addr in addr_list {
        //println!("Checking addr for hooks: {:#x}", addr);
        unpatch_single(addr, ntdll_start, ntdll_end, &addr_list_clone)
            .expect("Failed to unpatch addr");
    }
    return true;
}

/// Attempts to unhook the IAT of the current process, returns true if hooks were patched,
/// or false if there were no hooks or an error occurred
pub fn unhook_iat() -> bool {
    // Lets unhook our own IAT, and additionally the IAT of kernelbase.
    // First, get the base address of the current process.
    let base_address = match unsafe { GetModuleHandleA(None) } {
        Ok(base_address) => base_address,
        Err(_) => return false,
    };
    let kernelbase_address = match pe_helper::get_module_by_name("kernelbase.dll") {
        Some(kernelbase_address) => kernelbase_address,
        None => return false,
    };
    println!("Address: {:#x}", base_address.0 as usize);
    // Get a parsed PE file from the base address.
    let pe_file = match pe_helper::get_module_by_address(base_address.0 as usize) {
        Some(pe_file) => pe_file,
        None => return false,
    };

    let res = match unpatch_iat_hooks(&pe_file) {
        Ok(res) => res,
        Err(e) => {
            println!("Error: {:#?}", e);
            false
        }
    };

    println!("Unpatching kernelbase.dll");
    let res2 = match unpatch_iat_hooks(&kernelbase_address) {
        Ok(res) => res,
        Err(e) => {
            println!("Error: {:#?}", e);
            false
        }
    };

    return res | res2;
}
