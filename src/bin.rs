use core::arch::asm;
use iat_unhook_lib::{unhook_exports, unhook_iat};

// import NtWriteVirtualMemory from NTDLL
#[link(name = "ntdll")]
extern "system" {
    fn NtWriteVirtualMemory(
        process_handle: u64,
        base_address: u64,
        buffer: u64,
        number_of_bytes_to_write: u32,
        number_of_bytes_written: u64,
    ) -> u32;
}

/// Tests unhooking NTDLL, expected to be launched with an attached debugger to catch the int3's
/// and see the difference in behavior between the first execution of NtWriteVirtualMemory (hooked)
/// and the second execution of NtWriteVirtualMemory (unhooked)
fn main() {
    // Wait for user to press any key
    println!("Press any key to unhook IAT");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();

    // Int3 to catch in debugger
    unsafe {
        asm!("int3");
    }
    {
        // Call hooked NtWriteVirtualMemory
        let mut bytes_written: u32 = 0;
        let mut buffer: [u8; 4] = [0; 4];
        let mut buffer_ptr = buffer.as_mut_ptr();
        let mut bytes_written_ptr = &mut bytes_written as *mut u32;
        let _status = unsafe {
            NtWriteVirtualMemory(
                u64::MAX,
                &mut buffer_ptr as *mut _ as u64,
                &mut buffer_ptr as *mut _ as u64,
                4,
                &mut bytes_written_ptr as *mut _ as u64,
            )
        };
    }

    //println!("Unhooked IAT: {}", unhook_iat());
    println!("Unhooked NTDLL Exports: {}", unhook_exports());

    // Below should be unhooked now
    {
        let mut bytes_written: u32 = 0;
        let mut buffer: [u8; 4] = [0; 4];
        let mut buffer_ptr = buffer.as_mut_ptr();
        let mut bytes_written_ptr = &mut bytes_written as *mut u32;
        unsafe {
            asm!("int3");
        }
        // Call unhooked NtWriteVirtualMemory
        let _status = unsafe {
            NtWriteVirtualMemory(
                u64::MAX,
                &mut buffer_ptr as *mut _ as u64,
                &mut buffer_ptr as *mut _ as u64,
                4,
                &mut bytes_written_ptr as *mut _ as u64,
            )
        };
    }

    // Wait for user to press any key
    println!("Press any key to exit");
    input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();
}
