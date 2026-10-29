mod export;
mod store;

use std::io::{BufRead, Read, Write};
use std::path::Path;

use isideload::anisette::{AnisetteClientInfo, remote_v3::RemoteV3AnisetteProvider};
use isideload::auth::apple_account::{AppleAccount, TwoFactorCallbackParams, TwoFactorCallbackResponse};
use isideload::dev::developer_session::DeveloperSession;
use base64::Engine as _;
use rootcause::prelude::*;
use serde::{Deserialize, Serialize};
use x509_cert::der::Encode;
use zeroize::{ZeroizeOnDrop, Zeroizing};

#[derive(Deserialize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct Request {
    apple_id: String,
    output_dir: String,
    p12_password: String,
}

#[derive(Deserialize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct TwoFactorReply {
    #[serde(rename = "type")]
    kind: String,
    code: String,
}

#[derive(Serialize)]
struct ExportResult {
    p12_path: String,
    team_id: String,
    team_name: String,
    certificate_der: String,
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Event<'a> {
    Progress { stage: &'a str },
    TwoFactor,
    Result { result: &'a ExportResult },
    Error { code: &'a str },
}

fn emit(event: Event<'_>) -> std::io::Result<()> {
    let mut output = std::io::stdout().lock();
    serde_json::to_writer(&mut output, &event)?;
    output.write_all(b"\n")?;
    output.flush()
}

fn progress(stage: &str) -> Result<(), &'static str> {
    emit(Event::Progress { stage }).map_err(|_| "internal")
}

/// The pipe carries one bounded JSON object per line. Raw credentials are erased after parsing.
fn receive<T: serde::de::DeserializeOwned>() -> Result<T, &'static str> {
    const MAX_LINE: u64 = 1024 * 1024;
    let mut bytes = Zeroizing::new(Vec::new());
    std::io::stdin()
        .lock()
        .take(MAX_LINE + 1)
        .read_until(b'\n', &mut bytes)
        .map_err(|_| "invalid_request")?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_LINE || bytes.last() != Some(&b'\n') {
        return Err("invalid_request");
    }
    serde_json::from_slice(&bytes).map_err(|_| "invalid_request")
}

async fn two_factor(_params: TwoFactorCallbackParams) -> Result<TwoFactorCallbackResponse, Report> {
    // Do not forward Apple's raw errors, phone numbers or authentication responses to logs.
    progress("two_factor").map_err(|_| report!("Two-factor communication failed"))?;
    emit(Event::TwoFactor).map_err(|_| report!("Two-factor communication failed"))?;
    let reply: TwoFactorReply = receive().map_err(|_| report!("Invalid two-factor response"))?;
    if reply.kind != "two_factor" || reply.code.len() != 6 || !reply.code.bytes().all(|c| c.is_ascii_digit()) {
        bail!("Invalid two-factor response");
    }
    Ok(TwoFactorCallbackResponse::SubmitCode(reply.code.clone()))
}

async fn run() -> Result<ExportResult, &'static str> {
    let request: Request = receive()?;
    let apple_id = request.apple_id.trim().to_lowercase();
    let output_dir = Path::new(&request.output_dir);
    if apple_id.is_empty() || request.p12_password.is_empty()
        || !output_dir.is_absolute() || !output_dir.is_dir()
    {
        return Err("invalid_request");
    }
    progress("storage")?;
    let (private_key, storage) = store::load_existing(&apple_id)?;
    progress("local_profiles")?;
    let found = if let Some((certificate, team)) = export::find_local(&private_key)? {
        export::Found {
            identity: isideload::sideload::cert_identity::CertificateIdentity {
                certificate,
                private_key,
                machine_id: String::new(),
                machine_name: String::new(),
            },
            team,
        }
    } else {
        // Only the fallback needs network access. Reuse iLoader's saved password;
        // there is no Apple-password field or manual login prompt in this tool.
        progress("saved_credentials")?;
        let password = store::saved_password(request.apple_id.trim())?;
        progress("authenticating")?;
        // Matches current iLoader account.rs, including the modern AuthKit profile.
        let provider = RemoteV3AnisetteProvider::default()
            .map_err(|_| "authentication")?
            .set_serial_number("0".to_string())
            .set_storage(Box::new(storage))
            .set_client_info_override(Some(AnisetteClientInfo {
                client_info: "<Mac15,7> <macOS;27.0;26A5378j> <com.apple.AuthKit/1 (com.apple.akd/1.0)>".to_string(),
                user_agent: "akd/1.0 CFNetwork/811.5.4".to_string(),
            }))
            .set_url("https://mac-ani.jkcoxson.com");
        let mut account = AppleAccount::builder(&apple_id)
            .anisette_provider(provider)
            .login(&password, two_factor)
            .await
            .map_err(|_| "authentication")?;
        let mut session = DeveloperSession::from_account(&mut account)
            .await
            .map_err(|_| "authentication")?;
        progress("certificates")?;
        export::find_existing(&mut session, private_key).await?
    };
    progress("writing")?;
    let certificate_der = found
        .identity
        .certificate
        .to_der()
        .map(|der| base64::engine::general_purpose::STANDARD.encode(der))
        .map_err(|_| "encode")?;
    let path = export::write_p12(&found, &request.p12_password, output_dir).await?;
    progress("complete")?;
    Ok(ExportResult {
        p12_path: path.to_string_lossy().into_owned(),
        team_id: found.team.team_id,
        team_name: found.team.name.unwrap_or_default(),
        certificate_der,
    })
}

#[tokio::main]
async fn main() {
    // No tracing subscriber, debug output, panic payloads, environment credentials or
    // command-line credential options. The stdout stream is exclusively the JSON protocol.
    std::panic::set_hook(Box::new(|_| {}));
    if !cfg!(windows) || std::env::args_os().len() != 1
        || rustls::crypto::ring::default_provider().install_default().is_err()
    {
        let _ = emit(Event::Error { code: "internal" });
        std::process::exit(1);
    }
    match run().await {
        Ok(result) => {
            if emit(Event::Result { result: &result }).is_err() {
                std::process::exit(1);
            }
        }
        Err(code) => {
            let _ = emit(Event::Error { code });
            std::process::exit(1);
        }
    }
}
