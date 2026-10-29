// Reads what iLoader stored on this Windows account. Own code: no Apple library here.

use std::path::PathBuf;

use keyring::Entry;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const SERVICE: &str = "iloader";

/// Tauri's app data directory for iLoader, its filesystem fallback.
pub fn data_dir() -> Option<PathBuf> {
    std::env::var_os("APPDATA").map(|base| PathBuf::from(base).join("me.nabdev.iloader"))
}

/// iLoader names each entry after SHA256(lowercased email); Windows adds the service as a suffix.
fn entry(apple_id: &str) -> String {
    format!("{}/key", hex::encode(Sha256::digest(apple_id.to_lowercase())))
}

/// Reads a value from the credential store, then from iLoader's app data directory.
pub fn read_data(key: &str) -> Option<Vec<u8>> {
    if let Ok(entry) = Entry::new(SERVICE, key)
        && let Ok(secret) = entry.get_secret()
    {
        return Some(secret);
    }
    let path = data_dir()?.join(key);
    std::fs::read(path).ok()
}

pub fn key_der(apple_id: &str) -> Option<Zeroizing<Vec<u8>>> {
    read_data(&entry(apple_id)).map(Zeroizing::new)
}

/// iLoader saves the password under the email as typed, then lowercased.
pub fn saved_password(apple_id: &str) -> Option<Zeroizing<String>> {
    let lowercase = apple_id.to_lowercase();
    for account in [apple_id, lowercase.as_str()] {
        if let Ok(entry) = Entry::new(SERVICE, account)
            && let Ok(password) = entry.get_password()
            && !password.is_empty()
        {
            return Some(Zeroizing::new(password));
        }
    }
    None
}
