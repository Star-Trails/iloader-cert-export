// Adapted from black-night-heron/iloader-export (MIT); see ../LICENSE.
use std::path::PathBuf;

use isideload::anisette::remote_v3::ANISETTE_STATE_KEY;
use isideload::util::{
    fs_storage::FsStorage,
    keyring_storage::KeyringStorage,
    storage::{InMemoryStorage, SideloadingStorage},
};
use rsa::{RsaPrivateKey, pkcs8::DecodePrivateKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// iLoader stores the private key at SHA256(lowercase email)/key, not under the email.
/// This function never invokes CertificateIdentity::retrieve, which can create a new key.
pub fn load_existing(apple_id: &str) -> Result<(RsaPrivateKey, InMemoryStorage), &'static str> {
    let entry = format!("{}/key", hex::encode(Sha256::digest(apple_id.to_lowercase())));
    let mut backends: Vec<Box<dyn SideloadingStorage>> =
        vec![Box::new(KeyringStorage::new("iloader".to_string()))];
    if let Some(appdata) = std::env::var_os("APPDATA") {
        backends.push(Box::new(FsStorage::new(
            PathBuf::from(appdata).join("me.nabdev.iloader"),
        )));
    }

    for backend in backends {
        let Ok(Some(der)) = backend.retrieve_data(&entry) else {
            continue;
        };
        let der = Zeroizing::new(der);
        let Ok(key) = RsaPrivateKey::from_pkcs8_der(&der) else {
            continue;
        };
        // Authentication may refresh anisette state. Keep all such changes in memory:
        // neither the Windows credential store nor iLoader's app-data files are modified.
        let storage = InMemoryStorage::new();
        if let Ok(Some(state)) = backend.retrieve_data(ANISETTE_STATE_KEY) {
            let state = Zeroizing::new(state);
            storage.store_data(ANISETTE_STATE_KEY, &state).map_err(|_| "storage")?;
        }
        return Ok((key, storage));
    }
    Err("storage")
}

pub fn data_dir() -> Option<PathBuf> {
    std::env::var_os("APPDATA").map(|base| PathBuf::from(base).join("me.nabdev.iloader"))
}

/// iLoader saves passwords under the email as originally typed, with service "iloader".
/// Failure leaves export offline-only; no manual password prompt is introduced.
pub fn saved_password(apple_id: &str) -> Result<Zeroizing<String>, &'static str> {
    let lowercase = apple_id.to_lowercase();
    for account in [apple_id, lowercase.as_str()] {
        if let Ok(entry) = keyring::Entry::new("iloader", account)
            && let Ok(password) = entry.get_password()
            && !password.is_empty()
        {
            return Ok(Zeroizing::new(password));
        }
    }
    Err("saved_credentials")
}
