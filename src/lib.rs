mod pe_def;
pub mod pe_helper;

use crate::pe_helper::unpatch_iat_hooks;
use windows::Win32::System::LibraryLoader::GetModuleHandleA;

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

    let mut res = match unpatch_iat_hooks(&pe_file) {
        Ok(res) => res,
        Err(e) => {
            println!("Error: {:#?}", e);
            false
        }
    };
    if !res {
        return res;
    } else {
        res = match unpatch_iat_hooks(&kernelbase_address) {
            Ok(res) => res,
            Err(e) => {
                println!("Error: {:#?}", e);
                false
            }
        };
    }
    return res;
}
