// Adapted from black-night-heron/iloader-export (MIT); see ../LICENSE.
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use apple_codesign_quick::ProvisioningProfile;
use isideload::dev::{
    certificates::CertificatesApi,
    developer_session::DeveloperSession,
    teams::{DeveloperTeam, TeamsApi},
};
use isideload::sideload::cert_identity::CertificateIdentity;
use rsa::{RsaPrivateKey, pkcs1::EncodeRsaPublicKey};
use x509_cert::{Certificate, der::Decode};
use zeroize::Zeroizing;

pub struct Found {
    pub identity: CertificateIdentity,
    pub team: DeveloperTeam,
}

/// Profile expiry does not imply certificate expiry. Inspect the embedded signing
/// certificates themselves; this offline path cannot query Apple's revocation state.
pub fn find_local(
    private_key: &RsaPrivateKey,
) -> Result<Option<(Certificate, DeveloperTeam)>, &'static str> {
    let public_key_der = private_key.to_public_key().to_pkcs1_der().map_err(|_| "encode")?;
    let Some(directory) = crate::store::data_dir() else {
        return Ok(None);
    };
    let Ok(entries) = std::fs::read_dir(directory) else {
        return Ok(None);
    };
    let now = SystemTime::now();
    let mut best: Option<(Certificate, DeveloperTeam)> = None;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.extension().and_then(|ext| ext.to_str()).is_some_and(|ext| ext.eq_ignore_ascii_case("mobileprovision")) {
            continue;
        }
        let Ok(metadata) = entry.metadata() else { continue };
        if !metadata.is_file() || metadata.len() > 32 * 1024 * 1024 {
            continue;
        }
        let Ok(bytes) = std::fs::read(path) else { continue };
        let Ok(profile) = ProvisioningProfile::parse(&bytes) else { continue };
        let Some(certificates) = profile.plist().get("DeveloperCertificates").and_then(|value| value.as_array()) else {
            continue;
        };
        for value in certificates {
            let Some(der) = value.as_data() else { continue };
            let Ok(certificate) = Certificate::from_der(der) else { continue };
            if certificate.tbs_certificate.subject_public_key_info.subject_public_key.as_bytes()
                != Some(public_key_der.as_bytes())
            {
                continue;
            }
            let validity = &certificate.tbs_certificate.validity;
            let expires = SystemTime::from(&validity.not_after);
            if SystemTime::from(&validity.not_before) > now || expires <= now {
                continue;
            }
            if best.as_ref().is_none_or(|(previous, _)| {
                expires > SystemTime::from(&previous.tbs_certificate.validity.not_after)
            }) {
                best = Some((certificate, DeveloperTeam {
                    name: profile.plist().get("TeamName").and_then(|value| value.as_string()).map(str::to_owned),
                    team_id: profile.team_id().to_owned(),
                    r#type: None,
                    status: None,
                }));
            }
        }
    }
    Ok(best)
}

/// Only list APIs are used: no certificate issuance, revocation or profile mutation.
pub async fn find_existing(
    session: &mut DeveloperSession,
    private_key: RsaPrivateKey,
) -> Result<Found, &'static str> {
    let public_key_der = private_key
        .to_public_key()
        .to_pkcs1_der()
        .map_err(|_| "encode")?;
    let teams = session.list_teams().await.map_err(|_| "certificates")?;
    let now = SystemTime::now();
    let mut best: Option<(Certificate, DeveloperTeam, String, String)> = None;

    for team in teams {
        for cert in session.list_ios_certs(&team).await.map_err(|_| "certificates")? {
            if cert.status.as_deref().is_some_and(|status| status.eq_ignore_ascii_case("revoked")) {
                continue;
            }
            let Some(content) = cert.cert_content else {
                continue;
            };
            let Ok(x509) = Certificate::from_der(content.as_ref()) else {
                continue;
            };
            if x509.tbs_certificate.subject_public_key_info.subject_public_key.as_bytes()
                != Some(public_key_der.as_bytes())
            {
                continue;
            }
            let validity = &x509.tbs_certificate.validity;
            let expires = SystemTime::from(&validity.not_after);
            if SystemTime::from(&validity.not_before) > now || expires <= now {
                continue;
            }
            let machine_id = cert.machine_id.unwrap_or_default();
            let rank = (!machine_id.is_empty(), expires);
            let better = best.as_ref().is_none_or(|(existing, _, id, _)| {
                rank > (!id.is_empty(), SystemTime::from(&existing.tbs_certificate.validity.not_after))
            });
            if better {
                best = Some((x509, team.clone(), machine_id, cert.machine_name.unwrap_or_default()));
            }
        }
    }
    let (certificate, team, machine_id, machine_name) = best.ok_or("no_match")?;
    Ok(Found {
        identity: CertificateIdentity { machine_id, machine_name, private_key, certificate },
        team,
    })
}

pub async fn write_p12(
    found: &Found,
    password: &str,
    directory: &Path,
) -> Result<PathBuf, &'static str> {
    let bytes = Zeroizing::new(found.identity.as_p12(password).await.map_err(|_| "encode")?);
    // Use fixed safe file names and exclusive creation; never overwrite an earlier export.
    for index in 0..10_000 {
        let filename = if index == 0 {
            "iloader-certificate.p12".to_string()
        } else {
            format!("iloader-certificate-{index}.p12")
        };
        let path = directory.join(filename);
        let mut file = match std::fs::OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err("output"),
        };
        let written = file.write_all(&bytes).and_then(|()| file.sync_all());
        drop(file);
        if written.is_err() {
            let _ = std::fs::remove_file(&path);
            return Err("output");
        }
        return Ok(path);
    }
    Err("output")
}
