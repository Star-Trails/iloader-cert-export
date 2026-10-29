// The only module that uses isideload. Upgrading that library should touch this file alone.
//
// The certificate lookup by public key and the exclusive .p12 naming follow
// black-night-heron/iloader-export (MIT); see ../LICENSE.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use isideload::anisette::{AnisetteClientInfo, remote_v3::{ANISETTE_STATE_KEY, RemoteV3AnisetteProvider}};
use isideload::auth::apple_account::{AppleAccount, TwoFactorCallbackParams, TwoFactorCallbackResponse};
use isideload::dev::{certificates::CertificatesApi, developer_session::DeveloperSession, teams::TeamsApi};
use isideload::sideload::cert_identity::CertificateIdentity;
use isideload::util::storage::SideloadingStorage;
use rootcause::prelude::*;
use rsa::{RsaPrivateKey, pkcs1::EncodeRsaPublicKey, pkcs8::DecodePrivateKey};
use x509_cert::{Certificate as X509Certificate, der::Decode};
use zeroize::Zeroizing;

use crate::model::{Certificate, Found, Team};
use crate::protocol::{self, Event, TwoFactorReply};

const ANISETTE_SERVER: &str = "https://mac-ani.jkcoxson.com";
// Matches iLoader's own client: the AuthKit profile Apple expects from a modern Mac.
const CLIENT_INFO: &str = "<Mac15,7> <macOS;27.0;26A5378j> <com.apple.AuthKit/1 (com.apple.akd/1.0)>";
const USER_AGENT: &str = "akd/1.0 CFNetwork/811.5.4";

pub fn anisette_state() -> Option<Vec<u8>> {
    crate::credentials::read_data(ANISETTE_STATE_KEY)
}

/// Keeps iLoader's files and credential store untouched: the provider may refresh the
/// anisette state, and those writes are dropped.
struct ReadOnlyState {
    state: Option<Vec<u8>>,
}

impl SideloadingStorage for ReadOnlyState {
    fn store(&self, _key: &str, _value: &str) -> Result<(), Report> {
        Ok(())
    }

    fn retrieve(&self, _key: &str) -> Result<Option<String>, Report> {
        Ok(None)
    }

    fn store_data(&self, _key: &str, _value: &[u8]) -> Result<(), Report> {
        Ok(())
    }

    fn retrieve_data(&self, key: &str) -> Result<Option<Vec<u8>>, Report> {
        Ok(if key == ANISETTE_STATE_KEY {
            self.state.clone()
        } else {
            None
        })
    }
}

pub struct Session(DeveloperSession);

pub async fn sign_in(apple_id: &str, password: &str) -> Result<Session, &'static str> {
    let state = ReadOnlyState { state: anisette_state() };
    let provider = RemoteV3AnisetteProvider::default()
        .map_err(|_| "authentication")?
        .set_serial_number("0".to_string())
        .set_storage(Box::new(state))
        .set_client_info_override(Some(AnisetteClientInfo {
            client_info: CLIENT_INFO.to_string(),
            user_agent: USER_AGENT.to_string(),
        }))
        .set_url(ANISETTE_SERVER);
    let mut account = AppleAccount::builder(&apple_id.to_lowercase())
        .anisette_provider(provider)
        .login(password, two_factor)
        .await
        .map_err(|_| "authentication")?;
    let session = DeveloperSession::from_account(&mut account)
        .await
        .map_err(|_| "authentication")?;
    Ok(Session(session))
}

async fn two_factor(_params: TwoFactorCallbackParams) -> Result<TwoFactorCallbackResponse, Report> {
    // Apple's errors, phone numbers and responses stay out of the protocol.
    protocol::progress("two_factor").map_err(|_| report!("Two-factor communication failed"))?;
    protocol::emit(Event::TwoFactor).map_err(|_| report!("Two-factor communication failed"))?;
    let reply: TwoFactorReply = protocol::receive().map_err(|_| report!("Invalid two-factor response"))?;
    if reply.kind != "two_factor" || reply.code.len() != 6 || !reply.code.bytes().all(|c| c.is_ascii_digit()) {
        bail!("Invalid two-factor response");
    }
    Ok(TwoFactorCallbackResponse::SubmitCode(reply.code.clone()))
}

/// Lists the account's certificates and returns the valid one matching the private key.
/// Only list calls are made: nothing is created, renewed or revoked.
pub async fn find_remote(session: &mut Session, key_der: &[u8]) -> Result<Found, &'static str> {
    let key = RsaPrivateKey::from_pkcs8_der(key_der).map_err(|_| "storage")?;
    let public_key = key.to_public_key().to_pkcs1_der().map_err(|_| "encode")?;
    let teams = session.0.list_teams().await.map_err(|_| "certificates")?;
    let now = SystemTime::now();
    let mut best: Option<(Vec<u8>, X509Certificate, Team, String, String)> = None;
    for team in teams {
        for cert in session.0.list_ios_certs(&team).await.map_err(|_| "certificates")? {
            if cert.status.as_deref().is_some_and(|status| status.eq_ignore_ascii_case("revoked")) {
                continue;
            }
            let Some(content) = cert.cert_content else { continue };
            let Ok(certificate) = X509Certificate::from_der(content.as_ref()) else { continue };
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
            let machine_id = cert.machine_id.unwrap_or_default();
            let rank = (!machine_id.is_empty(), expires);
            let better = best.as_ref().is_none_or(|(_, existing, _, id, _)| {
                rank > (!id.is_empty(), SystemTime::from(&existing.tbs_certificate.validity.not_after))
            });
            if better {
                best = Some((
                    content.as_ref().to_vec(),
                    certificate,
                    Team { id: team.team_id.clone(), name: team.name.clone().unwrap_or_default() },
                    machine_id,
                    cert.machine_name.unwrap_or_default(),
                ));
            }
        }
    }
    let (der, _, team, machine_id, machine_name) = best.ok_or("no_match")?;
    Ok(Found {
        certificate: Certificate {
            der,
            machine_id,
            machine_name,
        },
        team,
    })
}

pub async fn write_p12(
    found: &Found,
    key_der: &[u8],
    password: &str,
    directory: &Path,
) -> Result<PathBuf, &'static str> {
    let certificate = X509Certificate::from_der(&found.certificate.der).map_err(|_| "encode")?;
    let identity = CertificateIdentity {
        machine_id: found.certificate.machine_id.clone(),
        machine_name: found.certificate.machine_name.clone(),
        private_key: RsaPrivateKey::from_pkcs8_der(key_der).map_err(|_| "storage")?,
        certificate,
    };
    let bytes = Zeroizing::new(identity.as_p12(password).await.map_err(|_| "encode")?);
    // Safe fixed names, exclusive creation: an earlier export is never overwritten.
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
        let written = std::io::Write::write_all(&mut file, &bytes).and_then(|()| file.sync_all());
        drop(file);
        if written.is_err() {
            let _ = std::fs::remove_file(&path);
            return Err("output");
        }
        return Ok(path);
    }
    Err("output")
}
