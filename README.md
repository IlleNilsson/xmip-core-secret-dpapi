# xmip-core-secret-dpapi

Windows DPAPI as the key home's store (ADR-0063 clause 4). A technology of
[xmip-core-secret](https://github.com/IlleNilsson/xmip-core-secret).

A key-encryption key is thirty-two random bytes, sealed by `CryptProtectData`
in user scope under the Service Identity and written to
`<directory>/<name>.kek`. Only that identity on that machine can unseal it;
another account, or the file copied elsewhere, is refused by Windows. The
key's name is DPAPI's entropy too, so a file renamed to another key's name
does not open. A key file is created once and never replaced.

`Dpapi` is a `secret::KekHolder`; `secret::Held::new(Dpapi::new(dir))` is the
`KeyStore`. On other platforms the crate is empty.

## The system call

`CryptProtectData`, `CryptUnprotectData` and `LocalFree` are called through
`windows-sys` in `src/crypt_protect.rs`, the one file of this crate that
allows unsafe code (ADR-0050, amendment 2026-09-25); every block there says
where its pointers come from, how long they live and who frees them.
`Cargo.toml` sets `unsafe_code = "deny"`, and `test/Unsafe.Test.ps1` in the
estate lists the file. The unsealed key is wiped in DPAPI's own buffer before
it is freed. Machine scope is never used: it would let any account on the
machine open the key. Until 2026-09-25 the calls went through the
`windows-dpapi` crate, built on the unmaintained `winapi`.

## Verification

Tested on Windows: a key wraps and unwraps through DPAPI across two store
instances, the file on disk is not the key, a missing key is refused by name,
a key file renamed to another name does not open, an existing key is never
replaced. The workflow is manual-only and calls the versioned shared workflow
at `IlleNilsson/.github@v1`.
