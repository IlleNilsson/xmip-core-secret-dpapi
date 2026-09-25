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

`CryptProtectData` and `CryptUnprotectData` are reached through the
`windows-dpapi` crate, whose safe functions hold the FFI, so this crate keeps
`unsafe_code = "forbid"`. Machine scope is never used: it would let any
account on the machine open the key. ADR-0050's amendment of 2026-09-25
permits the two calls in one file of this crate over `windows-sys` instead;
not done, because the safe crate serves and because the amendment's
mechanism — `forbid` in `Cargo.toml`, lowered by that one file — is refused
by the compiler (E0453: an `allow` cannot follow a `forbid`), which is the
owner's to settle first.

## Verification

Tested on Windows: a key wraps and unwraps through DPAPI across two store
instances, the file on disk is not the key, a missing key is refused by name,
a key file renamed to another name does not open, an existing key is never
replaced. The workflow is manual-only and calls the versioned shared workflow
at `IlleNilsson/.github@v1`.
