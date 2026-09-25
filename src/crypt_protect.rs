//! `CryptProtectData` and `CryptUnprotectData`, user scope, no prompt: the
//! two DPAPI calls the key home makes on Windows, and the `LocalFree` each
//! answer needs.
//!
//! The one file in this crate that may hold unsafe code (ADR-0050, amendment
//! 2026-09-25): DPAPI is a C interface and is reached no other way. Every
//! block says where its pointers come from, how long they live and who frees
//! what they hand back. Machine scope is never asked for: it would let any
//! account on the machine open the key.
#![allow(unsafe_code)]

use std::ptr;
use std::slice;

use windows_sys::Win32::Foundation::{GetLastError, LocalFree};
use windows_sys::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
};
use zeroize::{Zeroize, Zeroizing};

/// Seal `data` for this identity on this machine, bound to `entropy`.
///
/// # Errors
///
/// The data is larger than DPAPI takes, or Windows refused, with its error
/// code.
pub(crate) fn protect(data: &[u8], entropy: &[u8]) -> Result<Vec<u8>, String> {
    let input = borrowed(data)?;
    let salt = borrowed(entropy)?;
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };

    // SAFETY: `input` and `salt` point into `data` and `entropy`, borrowed
    // for this call and only read by it. The description, reserved and prompt
    // pointers are null, which the call documents as absent. `output` is a
    // local the call fills with a buffer it allocated by LocalAlloc; the
    // `taken` below copies it and frees it.
    let sealed = unsafe {
        CryptProtectData(
            &raw const input,
            ptr::null(),
            &raw const salt,
            ptr::null(),
            ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &raw mut output,
        )
    };

    if sealed == 0 {
        return Err(format!("CryptProtectData failed: {}", last_error()));
    }

    Ok(taken(&mut output, false))
}

/// Open what [`protect`] sealed under the same `entropy`. The answer is
/// overwritten when it is dropped, and so is DPAPI's own copy before it is
/// freed.
///
/// # Errors
///
/// The data is larger than DPAPI takes, or Windows refused — another
/// identity, another machine, other entropy — with its error code.
pub(crate) fn unprotect(sealed: &[u8], entropy: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    let input = borrowed(sealed)?;
    let salt = borrowed(entropy)?;
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };

    // SAFETY: as in `protect`: `input` and `salt` point into the caller's
    // slices, borrowed for this call and only read. The description pointer
    // is null, so the call allocates no description for us to free; the
    // reserved and prompt pointers are null. `output` is filled with a
    // LocalAlloc'd buffer, which `taken` copies, wipes and frees.
    let opened = unsafe {
        CryptUnprotectData(
            &raw const input,
            ptr::null_mut(),
            &raw const salt,
            ptr::null(),
            ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &raw mut output,
        )
    };

    if opened == 0 {
        return Err(format!("CryptUnprotectData failed: {}", last_error()));
    }

    Ok(Zeroizing::new(taken(&mut output, true)))
}

/// A blob DPAPI reads: a view of `data`, which the caller keeps alive for
/// the call. DPAPI declares the pointer mutable and does not write through
/// an input blob.
fn borrowed(data: &[u8]) -> Result<CRYPT_INTEGER_BLOB, String> {
    Ok(CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(data.len())
            .map_err(|_| format!("{} bytes is more than DPAPI takes", data.len()))?,
        pbData: data.as_ptr().cast_mut(),
    })
}

/// Copy the buffer DPAPI allocated into `output`, wipe it first where it
/// held a secret, and free it.
fn taken(output: &mut CRYPT_INTEGER_BLOB, secret: bool) -> Vec<u8> {
    if output.pbData.is_null() {
        return Vec::new();
    }

    // SAFETY: `pbData` is non-null and was allocated by the DPAPI call that
    // just succeeded, `cbData` bytes long, owned by us until LocalFree below
    // and touched by nothing else meanwhile.
    let bytes = unsafe { slice::from_raw_parts_mut(output.pbData, output.cbData as usize) };
    let copy = bytes.to_vec();

    if secret {
        bytes.zeroize();
    }

    // SAFETY: `pbData` came from LocalAlloc inside DPAPI, as its contract
    // says, and is freed exactly once, here; the slice above is not used
    // after this, and the pointer is cleared so nothing can.
    unsafe {
        LocalFree(output.pbData.cast());
    }
    output.pbData = ptr::null_mut();
    output.cbData = 0;

    copy
}

/// The calling thread's last Windows error, as a number and in hex.
fn last_error() -> String {
    // SAFETY: GetLastError reads a thread-local value and takes no pointer.
    let code = unsafe { GetLastError() };

    format!("error {code} (0x{code:08X})")
}
