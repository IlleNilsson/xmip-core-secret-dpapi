//! Windows DPAPI as the key home's store (ADR-0063 clause 4).
//!
//! A key-encryption key is thirty-two random bytes, sealed by
//! `CryptProtectData` in user scope under the Service Identity and written
//! to `<directory>/<name>.kek`. Only that identity, on that machine, can
//! unseal it: another account, or the file copied to another machine, is
//! refused by Windows itself. The key's name is DPAPI's entropy as well, so
//! a file renamed to another key's name does not open.
//!
//! [`Dpapi`] is a [`secret::KekHolder`]; wrap it in [`secret::Held`] for a
//! [`secret::KeyStore`]. Windows only: on any other platform this crate is
//! empty, and the `file` or `keychain` technology is the store there.
//!
//! The two DPAPI calls are in `src/crypt_protect.rs`, the one file of this crate
//! that may hold unsafe code (ADR-0050, amendment 2026-09-25).

#[cfg(windows)]
mod crypt_protect;

#[cfg(windows)]
use crypt_protect::{protect, unprotect};
#[cfg(windows)]
use secret::{KekHolder, KekName, SecretError, Store};
#[cfg(windows)]
use std::fs::{self, OpenOptions};
#[cfg(windows)]
use std::io::{ErrorKind, Write};
#[cfg(windows)]
use std::path::PathBuf;
#[cfg(windows)]
use zeroize::Zeroizing;

/// Key-encryption keys as DPAPI-sealed files in one directory.
#[cfg(windows)]
pub struct Dpapi {
    directory: PathBuf,
}

#[cfg(windows)]
impl Dpapi {
    /// A store keeping its keys in `directory`, which is created when the
    /// first key is.
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
        }
    }

    fn path(&self, name: &KekName) -> PathBuf {
        self.directory.join(format!("{name}.kek"))
    }
}

/// DPAPI's optional entropy: the key's name, so a sealed file opens only
/// under the name it was sealed for.
#[cfg(windows)]
fn entropy(name: &KekName) -> Vec<u8> {
    [
        b"xmip-core-secret-dpapi/".as_slice(),
        name.as_str().as_bytes(),
    ]
    .concat()
}

#[cfg(windows)]
impl KekHolder for Dpapi {
    fn store(&self) -> Store {
        Store {
            technology: "dpapi",
            place: self.directory.display().to_string(),
        }
    }

    fn read(&self, name: &KekName) -> Result<Option<Zeroizing<Vec<u8>>>, SecretError> {
        let path = self.path(name);
        let sealed = match fs::read(&path) {
            Ok(sealed) => sealed,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(SecretError::store(format!("{}: {error}", path.display()))),
        };
        unprotect(&sealed, &entropy(name))
            .map(Some)
            .map_err(|error| {
                SecretError::store(format!(
                    "{} does not open for this identity on this machine: {error}",
                    path.display()
                ))
            })
    }

    fn create(&self, name: &KekName, material: &[u8]) -> Result<(), SecretError> {
        let path = self.path(name);
        let sealed = protect(material, &entropy(name)).map_err(SecretError::store)?;
        fs::create_dir_all(&self.directory).map_err(SecretError::store)?;
        // create_new: a key already there is never replaced (KekHolder).
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| SecretError::store(format!("{}: {error}", path.display())))?;
        file.write_all(&sealed)
            .and_then(|()| file.sync_all())
            .map_err(|error| SecretError::store(format!("{}: {error}", path.display())))
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use secret::{DataKey, Held, KeyStore};

    fn directory(test: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("xmip-secret-dpapi-{test}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        path
    }

    fn name(text: &str) -> KekName {
        KekName::new(text).expect("name")
    }

    #[test]
    fn a_key_wraps_and_unwraps_through_dpapi() {
        let dir = directory("round");
        let store = Held::new(Dpapi::new(&dir));
        let key = DataKey::generate().expect("key");
        let wrapped = store.wrap(&name("runtime"), &key).expect("wrapped");
        let again = Held::new(Dpapi::new(&dir));
        let back = again.unwrap(&name("runtime"), &wrapped).expect("unwrapped");
        // The same key seals what the other opens.
        let sealed = key.seal(b"a", b"payload").expect("sealed");
        assert_eq!(back.open(b"a", &sealed).expect("opened"), b"payload");
        assert_eq!(store.store().technology, "dpapi");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_file_on_disk_is_not_the_key() {
        let dir = directory("sealed");
        let holder = Dpapi::new(&dir);
        holder.create(&name("k"), &[7u8; 32]).expect("created");
        let on_disk = fs::read(dir.join("k.kek")).expect("file");
        assert!(!on_disk.windows(32).any(|w| w == [7u8; 32]));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_key_is_refused_by_name() {
        let dir = directory("missing");
        let store = Held::new(Dpapi::new(&dir));
        let refused = store.unwrap(&name("absent"), &[0; 60]);
        let Err(SecretError::MissingKek { name, store: place }) = refused else {
            panic!("expected MissingKek, got {refused:?}");
        };
        assert_eq!(name, "absent");
        assert!(place.starts_with("dpapi at "), "{place}");
    }

    #[test]
    fn a_key_file_renamed_to_another_name_does_not_open() {
        let dir = directory("renamed");
        let holder = Dpapi::new(&dir);
        holder.create(&name("one"), &[7u8; 32]).expect("created");
        fs::rename(dir.join("one.kek"), dir.join("two.kek")).expect("renamed");
        assert!(matches!(
            holder.read(&name("two")),
            Err(SecretError::Store { .. })
        ));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_existing_key_is_never_replaced() {
        let dir = directory("replace");
        let holder = Dpapi::new(&dir);
        holder.create(&name("k"), &[1u8; 32]).expect("created");
        assert!(holder.create(&name("k"), &[2u8; 32]).is_err());
        let kept = holder.read(&name("k")).expect("read").expect("held");
        assert_eq!(kept.as_slice(), &[1u8; 32]);
        let _ = fs::remove_dir_all(&dir);
    }
}
