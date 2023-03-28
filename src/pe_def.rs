use core::mem::transmute;
use std::slice;

use bitflags::bitflags;

// A parsed PE32+ structure
pub struct PE64 {
    pub pe64: Box<Pe64C>,
    pub base_address: usize,
    pub data_directories: ImageDataDirectoryVec,
}

// Return a reference to the ImageDataDirectoryVec
impl PE64 {
    pub fn get_data_directories(&self) -> &ImageDataDirectoryVec {
        &self.data_directories
    }
}

// The proper "C" style representation of a parsed PE32+ structure
#[derive(Clone)]
#[repr(C)]
pub struct Pe64C {
    pub dos_header: ImageDosHeader,
}

impl Pe64C {
    pub fn get_nt_headers(&self) -> &ImageNtHeaders64 {
        let nt_headers = self.dos_header.e_lfanew.get(self as *const _ as usize);
        nt_headers
    }
}

// A constant representing a valid MS-DOS signature
pub const IMAGE_DOS_SIGNATURE: u16 = u16::from_le_bytes(*b"MZ");

/// A MS-DOS signature, e.g. "MZ"
#[derive(Copy, Clone)]
#[repr(transparent)]
pub struct ImageDosSignature(u16);

// impl ImageDosSignature and verify the signature is valid
impl ImageDosSignature {
    pub fn is_valid(&self) -> bool {
        self.0 == IMAGE_DOS_SIGNATURE
    }
}

#[derive(Clone)]
#[repr(C)]
pub struct ImageDosHeader {
    pub e_magic: ImageDosSignature,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    // A offset from the module base to a ImageNtHeaders64 structure
    pub e_lfanew: RVA32<ImageNtHeaders64>,
}

#[derive(Clone)]
#[repr(C)]
pub struct ImageNtHeaders64 {
    pub signature: PESignature,
    pub file_header: ImageFileHeader,
    pub optional_header: ImageOptionalHeader64,
}

// PEType is an enum representing pe32 or pe32+ identifiers
#[derive(PartialEq, Eq, Copy, Clone)]
#[repr(u16)]
pub enum PEType {
    _PE32 = 0x10b,
    PE64 = 0x20b,
}

// Define the ImageOptionalHeader64 structure
#[derive(Clone)]
#[repr(C)]
pub struct ImageOptionalHeader64 {
    pub magic: PEType,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: RVA32<extern "C" fn()>,
    pub base_of_code: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: WindowsSubsystem,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    // The data directory is an array of ImageDataDirectory structures
    // Its size is based on the number_of_rva_and_sizes field in this structure
    pub data_directory: [ImageDataDirectory; 0],
}

// Define the ImageDataDirectory structure
pub struct ImageDataDirectoryVec(pub Vec<ImageDataDirectoryInfo>);

impl ImageDataDirectoryVec {
    // Gets the entry corresponding to the export table
    pub fn get_export_table(&self) -> Option<&ExportDirectoryTable> {
        // Loop through the data directories and find the entry with the
        // matching type
        for entry in self.0.iter() {
            if entry.name == ImageDataDirectoryEntry::ExportTable {
                // Get the table pointer by converting the RVA32 to the actual address
                // using .get and the virtual_address base, then cast to the ExportDirectoryTable
                // pointer type
                let table = entry.virtual_address.get(entry.base_address);
                // Cast table to a reference to an ExportDirectoryTable
                let table = unsafe { transmute(table) };
                // Return the table
                return Some(table);
            }
        }
        None
    }

    pub fn get_import_lookup_table(&self) -> Option<&ImportLookupTable> {
        // Loop through the data directories and find the entry with the
        // matching type
        for entry in self.0.iter() {
            if entry.name == ImageDataDirectoryEntry::ImportTable {
                // Get the table pointer by converting the RVA32 to the actual address
                // using .get and the virtual_address base, then cast to the ImportDirectoryTable
                // pointer type
                let table = entry.virtual_address.get(entry.base_address);
                // Cast table to a reference to an ImportDirectoryTable
                let table: &ImportDirectoryTable = unsafe { transmute(table) };
                let import_lookup_table = table.import_lookup_table_rva.get(entry.base_address);
                let import_lookup_table = unsafe { transmute(import_lookup_table) };
                // Return the table
                return Some(import_lookup_table);
            }
        }
        None
    }
    // Gets the entry corresponding to the import table
    pub fn get_import_address_table(&self) -> Option<ImportAddressTableR> {
        // Get a pointer to the ImportLookupTable
        let import_lookup_table = self.get_import_lookup_table().unwrap();

        // Loop through the data directories and find the entry with the
        // matching type
        for entry in self.0.iter() {
            if entry.name == ImageDataDirectoryEntry::IAT {
                // Get the table pointer by converting the RVA32 to the actual address
                // using .get and the virtual_address base, then cast to the ImportDirectoryTable
                // pointer type
                let table = entry.virtual_address.get(entry.base_address);
                // Cast table to a reference to an ImportDirectoryTable
                let table: &ImportAddressTable = unsafe { transmute(table) };
                // Create an ImportAddressTableR struct and fill it with all the entries
                // from the ImportAddressTable
                let mut table_r = ImportAddressTableR::default();
                // Get the count of entries in table by dividing entry.size by the size of a u64
                let count = entry.size as usize / core::mem::size_of::<u64>();
                // Loop through the entries in table and add them to table_r
                for i in 0..count {
                    let entry = unsafe { table.addresses.get_unchecked(i) };
                    let import_lookup_table_entry =
                        unsafe { import_lookup_table.entry.get_unchecked(i) };
                    // If the entries are identical, the target has not been bound.
                    // We could handle this, but we just skip it instead.
                    // TODO: handle
                    if *entry == *import_lookup_table_entry {
                        continue;
                    }
                    // ensure entry is not null
                    assert_ne!(entry as *const u64 as *const _ as u64, 0);
                    // Create the ImportAddressEntry struct
                    let entry_r = ImportAddressEntry {
                        iat_entry_address: entry as *const _ as u64,
                        target_function_address: *entry,
                    };
                    // Add the entry to the ImportAddressTableR
                    table_r.addresses.push(entry_r);
                }

                // Return the table
                return Some(table_r);
            }
        }
        None
    }
    pub fn is_within_range(
        &self,
        target_type: ImageDataDirectoryEntry,
        address: usize,
    ) -> Option<bool> {
        // Loop through the data directories and find the entry with the
        // matching type
        for entry in self.0.iter() {
            if entry.name == target_type {
                // Get the table pointer by converting the RVA32 to the actual address
                // using .get and the virtual_address base, then cast to the ExportDirectoryTable
                // pointer type
                let start_addr = entry.virtual_address.get(entry.base_address) as *const _ as usize;
                let end_addr = start_addr + entry.size as usize;
                return Some(address >= start_addr && address < end_addr);
            }
        }
        None
    }
}

// Define the ImageDataDirectory structure
#[derive(Clone)]
#[repr(C)]
pub struct ImageDataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

pub struct ImageDataDirectoryInfo {
    pub virtual_address: RVA32<()>,
    pub size: u32,
    pub base_address: usize,
    pub name: ImageDataDirectoryEntry,
}

// Define the Export Directory Table as described in the PE format
#[derive(Clone)]
#[repr(C)]
pub struct ExportDirectoryTable {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub name: u32,
    pub ordinal_base: u32,
    pub number_of_functions: u32,
    pub number_of_names: u32,
    pub export_address_table_rva: RVA32<ExportAddressTable>,
    pub name_ptr_rva: RVA32<ExportNamePtrTable>,
    pub ordinal_table_rva: RVA32<ExportOrdinalTable>,
}

// Define the import directory table as described in the PE format
#[derive(Clone)]
#[repr(C)]
pub struct ImportDirectoryTable {
    pub import_lookup_table_rva: RVA32<ImportLookupTable>,
    pub time_date_stamp: u32,
    pub forwarder_chain: u32,
    pub name_rva: RVA32<ASCIIString>,
    pub import_address_table_rva: RVA32<ImportAddressTable>,
}

// Define the import address table
#[derive(Clone)]
#[repr(C)]
pub struct ImportAddressTable {
    pub addresses: [u64; 0],
}

#[derive(Clone)]
#[repr(C)]
pub struct ImportAddressEntry {
    pub iat_entry_address: u64,
    pub target_function_address: u64,
}

#[derive(Clone, Default)]
pub struct ImportAddressTableR {
    pub addresses: Vec<ImportAddressEntry>,
}

// Define the import lookup table
#[derive(Clone)]
#[repr(C)]
pub struct ImportLookupTable {
    pub entry: [u64; 0],
}

// Define the ExportOrdinalTable which is an array of u16
#[derive(Clone)]
#[repr(C)]
pub struct ExportOrdinalTable {
    pub ordinals: [ExportAddressTableIndex; 0],
}

// ExportNamePtrTable is a array of RVA32's to ASCII strings
#[derive(Clone)]
#[repr(C)]
pub struct ExportNamePtrTable {
    pub name_ptr: [RVA32<ASCIIString>; 0],
}

// Defines the ASCIIString type, which is a null terminated ASCII string
#[derive(Clone)]
#[repr(C)]
pub struct ASCIIString {
    pub string: [u8; 0],
}

impl ASCIIString {
    // Enumerates the bytes of the string until it finds a null byte, returns the length.
    // We manually count the bytes as the type has no associated size information
    pub fn len(&self) -> usize {
        let mut len = 0;
        loop {
            if unsafe { *self.string.get_unchecked(len) } == 0 {
                return len;
            }
            len += 1;
        }
    }
    // Converts the ASCIIString to a Rust String
    pub fn to_string(&self) -> String {
        let len = self.len();
        let mut string = String::with_capacity(len);
        for i in 0..len {
            string.push(unsafe { *self.string.get_unchecked(i) } as char);
        }
        string
    }
}

impl ExportDirectoryTable {
    // Get an entry from the export_address_table_rva by obtaining the underlying
    // ExportAddressTable and indexing into it with the provided index, checking that the
    // index is within bounds based on the number_of_functions field
    pub fn get_export_address_table_entry(
        &self,
        index: u32,
        base_address: usize,
    ) -> Option<&ExportAddressTableEntry> {
        let index = index as usize;
        if index >= self.number_of_functions as usize {
            return None;
        }
        // Get the underlying ExportAddressTable by applying the base_address to the RVA32
        let export_address_table = self.export_address_table_rva.get(base_address);
        // Index into the table, using an unchecked index as the table is defined as a 0-size array
        // and the index is checked above
        let entry = unsafe { export_address_table.entries.get_unchecked(index) };
        Some(entry)
    }
    // Gets an entry from the ExportOrdinalTable, similar to how we get entries from the
    // ExportAddressTable
    pub fn get_export_ordinal_table_entry(
        &self,
        index: OrdinalTableIndex,
        base_address: usize,
    ) -> Option<&ExportAddressTableIndex> {
        let index = index.0 as usize;
        if index >= self.number_of_names as usize {
            return None;
        }
        let export_ordinal_table = self.ordinal_table_rva.get(base_address);
        Some(unsafe { export_ordinal_table.ordinals.get_unchecked(index) })
    }
    // Enumerates the ExportNamePtrTable looking for a String match with the provided name, gets
    // the ExportNamePtrTable using the provided base_address, similar to how we get the tables in
    // get_export_address_table_entry and get_export_ordinal_table_entry. The return value is an
    // Option around the index corresponding to the String match we found (if any)
    pub fn get_export_name_ptr_table_entry(
        &self,
        name: &str,
        base_address: usize,
    ) -> Option<OrdinalTableIndex> {
        let export_name_ptr_table = self.name_ptr_rva.get(base_address);
        for i in 0..self.number_of_names {
            let export_name_ptr =
                unsafe { export_name_ptr_table.name_ptr.get_unchecked(i as usize) };
            let export_name = export_name_ptr.get(base_address);
            if export_name.to_string().to_lowercase() == name.to_lowercase() {
                return Some(OrdinalTableIndex(i));
            }
        }
        None
    }
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct ExportAddressTableIndex(pub u16);

#[derive(Clone, Copy)]
#[repr(C)]
pub struct OrdinalTableIndex(u32);

// define the ExportAddressTableEntry which is a RVA32 to either a function or a string
#[derive(Clone)]
#[repr(transparent)]
pub struct ExportAddressTableEntry(pub RVA32<()>);

// Defines the ExportAddressTable
#[derive(Clone)]
#[repr(C)]
pub struct ExportAddressTable {
    // The export address table is an array of u32 values
    // Its size is based on the number_of_functions field in the ExportDirectoryTable
    pub entries: [ExportAddressTableEntry; 0],
}

// enum representing the ImageDataDirectory entries
#[derive(PartialEq, Eq, Copy, Clone)]
pub enum ImageDataDirectoryEntry {
    ExportTable = 0,
    ImportTable = 1,
    ResourceTable = 2,
    ExceptionTable = 3,
    CertificateTable = 4,
    BaseRelocationTable = 5,
    Debug = 6,
    Architecture = 7,
    GlobalPtr = 8,
    TLSTable = 9,
    LoadConfigTable = 10,
    BoundImport = 11,
    IAT = 12,
    DelayImportDescriptor = 13,
    CLRRuntimeHeader = 14,
    Reserved = 15,
}

// impl ImageDataDirectoryEntry to convert a index into an enum
impl ImageDataDirectoryEntry {
    pub fn from_index(index: usize) -> Option<ImageDataDirectoryEntry> {
        match index {
            0 => Some(ImageDataDirectoryEntry::ExportTable),
            1 => Some(ImageDataDirectoryEntry::ImportTable),
            2 => Some(ImageDataDirectoryEntry::ResourceTable),
            3 => Some(ImageDataDirectoryEntry::ExceptionTable),
            4 => Some(ImageDataDirectoryEntry::CertificateTable),
            5 => Some(ImageDataDirectoryEntry::BaseRelocationTable),
            6 => Some(ImageDataDirectoryEntry::Debug),
            7 => Some(ImageDataDirectoryEntry::Architecture),
            8 => Some(ImageDataDirectoryEntry::GlobalPtr),
            9 => Some(ImageDataDirectoryEntry::TLSTable),
            10 => Some(ImageDataDirectoryEntry::LoadConfigTable),
            11 => Some(ImageDataDirectoryEntry::BoundImport),
            12 => Some(ImageDataDirectoryEntry::IAT),
            13 => Some(ImageDataDirectoryEntry::DelayImportDescriptor),
            14 => Some(ImageDataDirectoryEntry::CLRRuntimeHeader),
            15 => Some(ImageDataDirectoryEntry::Reserved),
            _ => None,
        }
    }
}

// enum representing valid Windows Subsystem values
#[derive(PartialEq, Eq, Copy, Clone)]
#[repr(u16)]
pub enum WindowsSubsystem {
    _ImageSubsystemUnknown = 0,
    _ImageSubsystemNative = 1,
    _ImageSubsystemWindowsGui = 2,
    _ImageSubsystemWindowsCui = 3,
    _ImageSubsystemOs2Cui = 5,
    _ImageSubsystemPosixCui = 7,
    _ImageSubsystemNativeWindows = 8,
    _ImageSubsystemWindowsCeGui = 9,
    _ImageSubsystemEfiApplication = 10,
    _ImageSubsystemEfiBootServiceDriver = 11,
    _ImageSubsystemEfiRuntimeDriver = 12,
    _ImageSubsystemEfiRom = 13,
    _ImageSubsystemXbox = 14,
    _ImageSubsystemWindowsBootApplication = 16,
}

bitflags! {
    /// The `SectionCharacteristics` bitflags are used to describe the characteristics of a section.
    pub struct SectionCharacteristics: u32 {
        const IMAGE_SCN_TYPE_NO_PAD = 0x00000008;
        const IMAGE_SCN_CNT_CODE = 0x00000020;
        const IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040;
        const IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080;
        const IMAGE_SCN_LNK_OTHER = 0x00000100;
        const IMAGE_SCN_LNK_INFO = 0x00000200;
        const IMAGE_SCN_LNK_REMOVE = 0x00000800;
        const IMAGE_SCN_LNK_COMDAT = 0x00001000;
        const IMAGE_SCN_GPREL = 0x00008000;
        const IMAGE_SCN_MEM_PURGEABLE = 0x00020000;
        const IMAGE_SCN_MEM_16BIT = 0x00020000;
        const IMAGE_SCN_MEM_LOCKED = 0x00040000;
        const IMAGE_SCN_MEM_PRELOAD = 0x00080000;
        const IMAGE_SCN_ALIGN_1BYTES = 0x00100000;
        const IMAGE_SCN_ALIGN_2BYTES = 0x00200000;
        const IMAGE_SCN_ALIGN_4BYTES = 0x00300000;
        const IMAGE_SCN_ALIGN_8BYTES = 0x00400000;
        const IMAGE_SCN_ALIGN_16BYTES = 0x00500000;
        const IMAGE_SCN_ALIGN_32BYTES = 0x00600000;
        const IMAGE_SCN_ALIGN_64BYTES = 0x00700000;
        const IMAGE_SCN_ALIGN_128BYTES = 0x00800000;
        const IMAGE_SCN_ALIGN_256BYTES = 0x00900000;
        const IMAGE_SCN_ALIGN_512BYTES = 0x00A00000;
        const IMAGE_SCN_ALIGN_1024BYTES = 0x00B00000;
        const IMAGE_SCN_ALIGN_2048BYTES = 0x00C00000;
        const IMAGE_SCN_ALIGN_4096BYTES = 0x00D00000;
        const IMAGE_SCN_ALIGN_8192BYTES = 0x00E00000;
        const IMAGE_SCN_LNK_NRELOC_OVFL = 0x01000000;
        const IMAGE_SCN_MEM_DISCARDABLE = 0x02000000;
        const IMAGE_SCN_MEM_NOT_CACHED = 0x04000000;
        const IMAGE_SCN_MEM_NOT_PAGED = 0x08000000;
        const IMAGE_SCN_MEM_SHARED = 0x10000000;
        const IMAGE_SCN_MEM_EXECUTE = 0x20000000;
        const IMAGE_SCN_MEM_READ = 0x40000000;
        const IMAGE_SCN_MEM_WRITE = 0x80000000;
    }
}

#[derive(Clone)]
#[repr(packed)]
pub struct SectionHeader {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_line_numbers: u32,
    pub number_of_relocations: u16,
    pub number_of_line_numbers: u16,
    pub characteristics: SectionCharacteristics,
}

#[derive(Clone)]
#[repr(packed)]
pub struct ImageFileHeader {
    pub machine: ImageFileMachine,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

// An enum representing valid ImageFileMachine values
#[derive(PartialEq, Eq, Clone, Copy)]
#[repr(u16)]
pub enum ImageFileMachine {
    // All possible Machine Types
    _Unknown = 0x0,
    _Am33 = 0x1d3,
    _Amd64 = 0x8664,
    _Arm = 0x1c0,
    _Arm64 = 0xaa64,
    _ArmNT = 0x1c4,
    _Ebc = 0xebc,
    _I386 = 0x14c,
    _Ia64 = 0x200,
    _M32R = 0x9041,
    _Mips16 = 0x266,
    _MipsFpu = 0x366,
    _MipsFpu16 = 0x466,
    _PowerPC = 0x1f0,
    _PowerPCFP = 0x1f1,
    _R4000 = 0x166,
    _RiscV32 = 0x5032,
    _RiscV64 = 0x5064,
    _RiscV128 = 0x5128,
    _SH3 = 0x1a2,
    _SH3DSP = 0x1a3,
    _SH4 = 0x1a6,
    _SH5 = 0x1a8,
    _Thumb = 0x1c2,
    _WceMipsV2 = 0x169,
}

// Constant representing a PE signature, e.g. "PE\0\0"
pub const PE_SIGNATURE: u32 = u32::from_le_bytes(*b"PE\0\0");

#[derive(Copy, Clone)]
#[repr(transparent)]
pub struct PESignature(u32);

// Implement PESignature and verify the signature is valid
impl PESignature {
    pub fn is_valid(&self) -> bool {
        self.0 == PE_SIGNATURE
    }
}

// RVA32 is a relative virtual address to an underlying type
#[derive(Copy, Clone)]
#[repr(transparent)]
pub struct RVA32<T: ?Sized>(pub u32, pub core::marker::PhantomData<T>);

// impl RVA32 with a function that adds the usize base_address and then dereferences the pointer
impl<T> RVA32<T> {
    pub fn get(&self, base_address: usize) -> &T {
        unsafe { &*((base_address + self.0 as usize) as *const T) }
    }
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *const u16,
}

impl UnicodeString {
    // Convert the buffer to a utf16 string based on the length field
    pub fn extract_string(&self) -> Option<String> {
        if self.length == 0 || self.buffer as *const _ as usize == 0 {
            return None;
        }
        let slice = unsafe { slice::from_raw_parts(self.buffer, self.length as usize / 2) };
        // Convert slice to a String
        core::char::decode_utf16(slice.iter().cloned())
            .collect::<Result<String, _>>()
            .ok()
    }
}
