// Parses provisioning profiles iLoader left on disk. Third-party adapter: apple-codesign-quick.

use std::time::SystemTime;

use apple_codesign_quick::ProvisioningProfile;
use rsa::{RsaPrivateKey, pkcs1::EncodeRsaPublicKey, pkcs8::DecodePrivateKey};
use x509_cert::{Certificate as X509Certificate, der::Decode};

use crate::model::{Certificate, Found, Team};

const MAX_PROFILE_BYTES: u64 = 32 * 1024 * 1024;

/// Returns the matching certificate with the latest expiry. Profile expiry does not
/// imply certificate expiry, so the embedded certificates are inspected directly.
pub fn find_local(key_der: &[u8]) -> Result<Option<Found>, &'static str> {
    let key = RsaPrivateKey::from_pkcs8_der(key_der).map_err(|_| "storage")?;
    let public_key = key.to_public_key().to_pkcs1_der().map_err(|_| "encode")?;
    let Some(directory) = crate::credentials::data_dir() else {
        return Ok(None);
    };
    let Ok(entries) = std::fs::read_dir(directory) else {
        return Ok(None);
    };
    let now = SystemTime::now();
    let mut best: Option<(Vec<u8>, X509Certificate, Team)> = None;
    for entry in entries.flatten() {
        let path = entry.path();
        let is_profile = path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("mobileprovision"));
        if !is_profile {
            continue;
        }
        let Ok(metadata) = entry.metadata() else { continue };
        if !metadata.is_file() || metadata.len() > MAX_PROFILE_BYTES {
            continue;
        }
        let Ok(bytes) = std::fs::read(path) else { continue };
        let Ok(profile) = ProvisioningProfile::parse(&bytes) else { continue };
        let Some(certificates) = profile.plist().get("DeveloperCertificates").and_then(|value| value.as_array()) else {
            continue;
        };
        for value in certificates {
            let Some(der) = value.as_data() else { continue };
            let Ok(certificate) = X509Certificate::from_der(der) else { continue };
            if certificate.tbs_certificate.subject_public_key_info.subject_public_key.as_bytes()
                != Some(public_key.as_bytes())
            {
                continue;
            }
            let validity = &certificate.tbs_certificate.validity;
            let expires = SystemTime::from(&validity.not_after);
            if SystemTime::from(&validity.not_before) > now || expires <= now {
                continue;
            }
            let better = best.as_ref().is_none_or(|(_, previous, _)| {
                expires > SystemTime::from(&previous.tbs_certificate.validity.not_after)
            });
            if better {
                let team = Team {
                    id: profile.team_id().to_owned(),
                    name: profile
                        .plist()
                        .get("TeamName")
                        .and_then(|value| value.as_string())
                        .unwrap_or_default()
                        .to_owned(),
                };
                best = Some((der.to_vec(), certificate, team));
            }
        }
    }
    Ok(best.map(|(der, _, team)| Found {
        certificate: Certificate {
            der,
            machine_id: String::new(),
            machine_name: String::new(),
        },
        team,
    }))
}
