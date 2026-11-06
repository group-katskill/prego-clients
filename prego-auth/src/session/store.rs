//! Secure storage for device sessions, and the refresh lock.
//!
//! A session is kept only in secure storage: the OS keychain (macOS Keychain, Windows Credential Manager,
//! Secret Service on a Linux desktop) or, on Linux without a desktop, the kernel keyring of the user session.
//! There is no plain file store.

use std::fs::File;
use std::path::{Path, PathBuf};

use crate::env::Env;
use crate::error::Error;

/// The service name of all Prego entries in the keychain.
pub const SERVICE: &str = "prego";

/// The text when no secure storage is available.
pub const NO_SECURE_STORAGE: &str = "this computer has no secure storage for a login session (no OS keychain, \
     no Secret Service and no kernel keyring). prego login never writes a session to a plain file. Use \
     PREGO_API_KEY, or a workload identity in CI";

/// Keeps text values under a key in secure storage.
pub trait SessionStore: Send + Sync {
    /// The name of the storage, for `prego status`.
    fn name(&self) -> &'static str;
    /// Returns the value of `key`, or `None` if there is none.
    fn load(&self, key: &str) -> Result<Option<String>, String>;
    /// Writes the value of `key`.
    fn save(&self, key: &str, value: &str) -> Result<(), String>;
    /// Deletes `key`. A missing key is not an error.
    fn delete(&self, key: &str) -> Result<(), String>;
}

/// Opens the secure storage of this computer.
pub fn open_store(env: &dyn Env) -> Result<Box<dyn SessionStore>, Error> {
    #[cfg(feature = "test-support")]
    if let Some(dir) = env.var("PREGO_TEST_SESSION_DIR") {
        return Ok(Box::new(test_store::DirStore(PathBuf::from(dir))));
    }
    #[cfg(feature = "session")]
    {
        keychain::open(env)
    }
    #[cfg(not(feature = "session"))]
    {
        let _ = env;
        Err(Error::Storage(NO_SECURE_STORAGE.into()))
    }
}

/// An exclusive lock around a session refresh, so that parallel processes do not use the same refresh
/// token. The lock file holds no secret. It is released when the value is dropped.
pub struct RefreshLock(#[allow(dead_code)] Option<File>);

/// Takes the refresh lock for `key` in `dir`. If no lock file can be made, the refresh goes on without a
/// lock: the STS gives the same answer to a second use of a refresh token within 10 s.
pub fn refresh_lock(dir: Option<&Path>, key: &str) -> RefreshLock {
    let Some(dir) = dir else {
        return RefreshLock(None);
    };
    if std::fs::create_dir_all(dir).is_err() {
        return RefreshLock(None);
    }
    let path = dir.join(format!("session-{:016x}.lock", fnv1a(key)));
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(path)
        .ok();
    match file {
        Some(f) if f.lock().is_ok() => RefreshLock(Some(f)),
        _ => RefreshLock(None),
    }
}

/// The directory of the lock files: `$XDG_RUNTIME_DIR/prego`, `%LOCALAPPDATA%\prego` or `~/.cache/prego`.
pub fn lock_dir(env: &dyn Env) -> Option<PathBuf> {
    if let Some(d) = env.var("XDG_RUNTIME_DIR") {
        return Some(PathBuf::from(d).join("prego"));
    }
    if let Some(d) = env.var("LOCALAPPDATA") {
        return Some(PathBuf::from(d).join("prego"));
    }
    if let Some(h) = env.var("HOME") {
        return Some(PathBuf::from(h).join(".cache").join("prego"));
    }
    None
}

/// FNV-1a, 64 bit. For key names only, not for security.
pub fn fnv1a(text: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in text.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

/// The name of the kernel keyring store.
pub const KERNEL_KEYRING: &str = "kernel keyring (lost at reboot)";

/// The file that records which store holds each entry: `prego/session-stores.json` in the settings
/// directory. It holds only key hashes and store names, no secret.
pub fn marker_path(env: &dyn Env) -> Option<PathBuf> {
    crate::FileConfig::path(env).and_then(|p| p.parent().map(|d| d.join("session-stores.json")))
}

/// Several stores in order (Linux: Secret Service, then the kernel keyring). A value is written to the first
/// store that accepts it. The marker file records that store, and reads use only that store, so an old
/// value in another store is never read. A delete goes to all stores.
pub struct Chain {
    stores: Vec<Box<dyn SessionStore>>,
    marker: Option<PathBuf>,
    used: std::sync::Mutex<Option<&'static str>>,
}

impl Chain {
    /// A chain of `stores`, with the marker file at `marker`.
    pub fn new(stores: Vec<Box<dyn SessionStore>>, marker: Option<PathBuf>) -> Self {
        Chain {
            stores,
            marker,
            used: std::sync::Mutex::new(None),
        }
    }

    fn marks(&self) -> std::collections::BTreeMap<String, String> {
        self.marker
            .as_ref()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }

    fn set_mark(&self, key: &str, store: Option<&str>) {
        let Some(path) = &self.marker else { return };
        let mut marks = self.marks();
        let id = format!("{:016x}", fnv1a(key));
        match store {
            Some(s) => marks.insert(id, s.to_string()),
            None => marks.remove(&id),
        };
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let tmp = path.with_extension("json.tmp");
        if let Ok(text) = serde_json::to_string(&marks) {
            if std::fs::write(&tmp, text).is_ok() {
                let _ = std::fs::rename(&tmp, path);
            }
        }
    }

    fn marked(&self, key: &str) -> Option<&dyn SessionStore> {
        let name = self.marks().remove(&format!("{:016x}", fnv1a(key)))?;
        self.stores
            .iter()
            .find(|s| s.name() == name)
            .map(|s| s.as_ref())
    }

    fn note(&self, name: &'static str) {
        if let Ok(mut u) = self.used.lock() {
            *u = Some(name);
        }
    }
}

impl SessionStore for Chain {
    fn name(&self) -> &'static str {
        self.used
            .lock()
            .ok()
            .and_then(|u| *u)
            .or_else(|| self.stores.first().map(|s| s.name()))
            .unwrap_or("none")
    }

    fn load(&self, key: &str) -> Result<Option<String>, String> {
        if let Some(store) = self.marked(key) {
            self.note(store.name());
            return store.load(key);
        }
        // No marker (for example, the settings directory was deleted): the first store that has the key.
        for store in &self.stores {
            if let Some(v) = store.load(key)? {
                self.note(store.name());
                return Ok(Some(v));
            }
        }
        Ok(None)
    }

    fn save(&self, key: &str, value: &str) -> Result<(), String> {
        let mut errors = Vec::new();
        for (i, store) in self.stores.iter().enumerate() {
            match store.save(key, value) {
                Ok(()) => {
                    self.set_mark(key, Some(store.name()));
                    self.note(store.name());
                    for (j, other) in self.stores.iter().enumerate() {
                        if j != i {
                            let _ = other.delete(key);
                        }
                    }
                    return Ok(());
                }
                Err(e) => errors.push(format!("{}: {e}", store.name())),
            }
        }
        Err(errors.join("; "))
    }

    fn delete(&self, key: &str) -> Result<(), String> {
        let mut result = Ok(());
        for store in &self.stores {
            if let Err(e) = store.delete(key) {
                result = Err(e);
            }
        }
        self.set_mark(key, None);
        result
    }
}

/// Values in memory. For tests.
#[cfg(any(test, feature = "test-support"))]
#[derive(Default)]
pub struct MemStore(pub std::sync::Mutex<std::collections::HashMap<String, String>>);

#[cfg(any(test, feature = "test-support"))]
impl SessionStore for MemStore {
    fn name(&self) -> &'static str {
        "memory"
    }
    fn load(&self, key: &str) -> Result<Option<String>, String> {
        Ok(self.0.lock().unwrap().get(key).cloned())
    }
    fn save(&self, key: &str, value: &str) -> Result<(), String> {
        self.0
            .lock()
            .unwrap()
            .insert(key.to_string(), value.to_string());
        Ok(())
    }
    fn delete(&self, key: &str) -> Result<(), String> {
        self.0.lock().unwrap().remove(key);
        Ok(())
    }
}

/// A directory store, for the integration tests of the binaries only (`PREGO_TEST_SESSION_DIR`). It is not
/// in a release build: the `test-support` feature is only on for tests.
#[cfg(feature = "test-support")]
mod test_store {
    use super::{fnv1a, SessionStore};
    use std::path::PathBuf;

    pub struct DirStore(pub PathBuf);

    impl DirStore {
        fn path(&self, key: &str) -> PathBuf {
            self.0.join(format!("{:016x}.json", fnv1a(key)))
        }
    }

    impl SessionStore for DirStore {
        fn name(&self) -> &'static str {
            "test directory"
        }
        fn load(&self, key: &str) -> Result<Option<String>, String> {
            match std::fs::read_to_string(self.path(key)) {
                Ok(s) => Ok(Some(s)),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(e.to_string()),
            }
        }
        fn save(&self, key: &str, value: &str) -> Result<(), String> {
            std::fs::create_dir_all(&self.0).map_err(|e| e.to_string())?;
            std::fs::write(self.path(key), value).map_err(|e| e.to_string())
        }
        fn delete(&self, key: &str) -> Result<(), String> {
            match std::fs::remove_file(self.path(key)) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.to_string()),
                _ => Ok(()),
            }
        }
    }
}

#[cfg(feature = "session")]
mod keychain {
    #[cfg(target_os = "linux")]
    use super::KERNEL_KEYRING;
    use super::{SessionStore, NO_SECURE_STORAGE, SERVICE};
    use crate::env::Env;
    use crate::error::Error;
    use keyring::Entry;

    #[derive(Clone, Copy)]
    enum Backend {
        /// The platform default: macOS Keychain or Windows Credential Manager.
        #[cfg_attr(target_os = "linux", allow(dead_code))]
        Native,
        #[cfg(target_os = "linux")]
        SecretService,
        #[cfg(target_os = "linux")]
        Kernel,
    }

    pub struct Keychain(Backend);

    fn entry(backend: Backend, key: &str) -> keyring::Result<Entry> {
        match backend {
            Backend::Native => Entry::new(SERVICE, key),
            #[cfg(target_os = "linux")]
            Backend::SecretService => Ok(Entry::new_with_credential(Box::new(
                keyring::secret_service::SsCredential::new_with_target(None, SERVICE, key)?,
            ))),
            #[cfg(target_os = "linux")]
            Backend::Kernel => Ok(Entry::new_with_credential(Box::new(
                keyring::keyutils::KeyutilsCredential::new_with_target(None, SERVICE, key)?,
            ))),
        }
    }

    /// True if a read of a probe key works (a missing key is a working store).
    fn works(backend: Backend) -> bool {
        match entry(backend, "probe").and_then(|e| e.get_password()) {
            Ok(_) | Err(keyring::Error::NoEntry) => true,
            Err(_) => false,
        }
    }

    pub fn open(env: &dyn Env) -> Result<Box<dyn SessionStore>, Error> {
        #[cfg(target_os = "linux")]
        {
            // The Secret Service first (a desktop), then the kernel keyring. A Secret Service can answer
            // reads but refuse writes (a locked collection with no unlock prompt): then the kernel keyring
            // takes the session.
            let mut backends: Vec<Box<dyn SessionStore>> = Vec::new();
            if env.var("DBUS_SESSION_BUS_ADDRESS").is_some() && works(Backend::SecretService) {
                backends.push(Box::new(Keychain(Backend::SecretService)));
            }
            if works(Backend::Kernel) {
                backends.push(Box::new(Keychain(Backend::Kernel)));
            }
            if backends.is_empty() {
                return Err(Error::Storage(NO_SECURE_STORAGE.into()));
            }
            Ok(Box::new(super::Chain::new(
                backends,
                super::marker_path(env),
            )))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = env;
            if works(Backend::Native) {
                return Ok(Box::new(Keychain(Backend::Native)));
            }
            Err(Error::Storage(NO_SECURE_STORAGE.into()))
        }
    }

    impl SessionStore for Keychain {
        fn name(&self) -> &'static str {
            match self.0 {
                #[cfg(target_os = "macos")]
                Backend::Native => "macOS Keychain",
                #[cfg(windows)]
                Backend::Native => "Windows Credential Manager",
                #[cfg(not(any(target_os = "macos", windows)))]
                Backend::Native => "OS keychain",
                #[cfg(target_os = "linux")]
                Backend::SecretService => "Secret Service",
                #[cfg(target_os = "linux")]
                Backend::Kernel => KERNEL_KEYRING,
            }
        }
        fn load(&self, key: &str) -> Result<Option<String>, String> {
            match entry(self.0, key).and_then(|e| e.get_password()) {
                Ok(v) => Ok(Some(v)),
                Err(keyring::Error::NoEntry) => Ok(None),
                Err(e) => Err(e.to_string()),
            }
        }
        fn save(&self, key: &str, value: &str) -> Result<(), String> {
            entry(self.0, key)
                .and_then(|e| e.set_password(value))
                .map_err(|e| e.to_string())
        }
        fn delete(&self, key: &str) -> Result<(), String> {
            match entry(self.0, key).and_then(|e| e.delete_credential()) {
                Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
                Err(e) => Err(e.to_string()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    /// A store like a locked Secret Service: reads work, writes can be refused.
    struct Lockable {
        name: &'static str,
        values: Arc<MemStore>,
        locked: Arc<AtomicBool>,
    }

    impl SessionStore for Lockable {
        fn name(&self) -> &'static str {
            self.name
        }
        fn load(&self, key: &str) -> Result<Option<String>, String> {
            self.values.load(key)
        }
        fn save(&self, key: &str, value: &str) -> Result<(), String> {
            if self.locked.load(Ordering::SeqCst) {
                return Err("locked collection".into());
            }
            self.values.save(key, value)
        }
        fn delete(&self, key: &str) -> Result<(), String> {
            if self.locked.load(Ordering::SeqCst) {
                return Err("locked collection".into());
            }
            self.values.delete(key)
        }
    }

    fn chain(dir: &str) -> (Chain, Arc<MemStore>, Arc<MemStore>, Arc<AtomicBool>) {
        let ss = Arc::new(MemStore::default());
        let kernel = Arc::new(MemStore::default());
        let locked = Arc::new(AtomicBool::new(false));
        let marker = std::env::temp_dir()
            .join(format!("prego-marker-{dir}-{}", std::process::id()))
            .join("session-stores.json");
        let _ = std::fs::remove_file(&marker);
        let c = Chain::new(
            vec![
                Box::new(Lockable {
                    name: "secret service",
                    values: ss.clone(),
                    locked: locked.clone(),
                }),
                Box::new(Lockable {
                    name: "kernel",
                    values: kernel.clone(),
                    locked: Arc::new(AtomicBool::new(false)),
                }),
            ],
            Some(marker),
        );
        (c, ss, kernel, locked)
    }

    #[test]
    fn a_refused_write_goes_to_the_next_store_and_the_old_value_is_never_read() {
        let (c, ss, kernel, locked) = chain("refused");
        c.save("k", "rt-1").unwrap();
        assert_eq!(c.name(), "secret service");
        assert_eq!(ss.load("k").unwrap().as_deref(), Some("rt-1"));

        // The Secret Service is locked now: reads work, writes do not. The new value goes to the kernel
        // keyring, and the stale "rt-1" in the Secret Service is not read again.
        locked.store(true, Ordering::SeqCst);
        c.save("k", "rt-2").unwrap();
        assert_eq!(kernel.load("k").unwrap().as_deref(), Some("rt-2"));
        assert_eq!(ss.load("k").unwrap().as_deref(), Some("rt-1"));
        assert_eq!(c.load("k").unwrap().as_deref(), Some("rt-2"));
        assert_eq!(c.name(), "kernel");

        // Unlocked again: the next write goes to the Secret Service, and the kernel copy is deleted.
        locked.store(false, Ordering::SeqCst);
        c.save("k", "rt-3").unwrap();
        assert_eq!(c.load("k").unwrap().as_deref(), Some("rt-3"));
        assert_eq!(kernel.load("k").unwrap(), None);

        // A delete goes to all stores and removes the mark.
        c.delete("k").unwrap();
        assert_eq!(c.load("k").unwrap(), None);
    }

    #[test]
    fn all_stores_refuse() {
        let ss = Arc::new(MemStore::default());
        let locked = Arc::new(AtomicBool::new(true));
        let c = Chain::new(
            vec![Box::new(Lockable {
                name: "secret service",
                values: ss,
                locked,
            })],
            None,
        );
        let e = c.save("k", "v").unwrap_err();
        assert!(e.contains("secret service: locked collection"), "{e}");
    }

    /// A write, read and delete in the real secure storage of this computer. Not in CI: run it by hand with
    /// `cargo test -p prego-auth -- --ignored real_store`.
    #[test]
    #[ignore]
    #[cfg(feature = "session")]
    fn real_store_round_trip() {
        let store = open_store(&crate::ProcessEnv).expect("secure storage");
        let key = format!("test:round-trip-{}", std::process::id());
        store.save(&key, "value-1").unwrap();
        assert_eq!(store.load(&key).unwrap().as_deref(), Some("value-1"));
        store.save(&key, "value-2").unwrap();
        assert_eq!(store.load(&key).unwrap().as_deref(), Some("value-2"));
        store.delete(&key).unwrap();
        assert_eq!(store.load(&key).unwrap(), None);
        store.delete(&key).unwrap();
        eprintln!("store: {}", store.name());
    }
}
