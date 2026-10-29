// iloader-cert-helper: exports the identity iLoader already uses.
// Only apple.rs touches isideload and only profiles.rs touches apple-codesign-quick.

mod apple;
mod credentials;
mod model;
mod profiles;
mod protocol;

use std::path::Path;

use base64::Engine as _;
use x509_cert::der::Decode;
use zeroize::Zeroizing;

use protocol::{Event, ExportResult, Request};

async fn run() -> Result<ExportResult, &'static str> {
    let request: Request = protocol::receive()?;
    let apple_id = request.apple_id.trim().to_lowercase();
    let output_dir = Path::new(&request.output_dir);
    if apple_id.is_empty()
        || request.p12_password.is_empty()
        || !output_dir.is_absolute()
        || !output_dir.is_dir()
    {
        return Err("invalid_request");
    }
    protocol::progress("storage")?;
    let key = credentials::key_der(&apple_id).ok_or("storage")?;
    protocol::progress("local_profiles")?;
    let found = match profiles::find_local(&key)? {
        Some(found) => found,
        None => {
            // Only this path needs the network. iLoader's saved password keeps it unattended.
            protocol::progress("saved_credentials")?;
            let password: Zeroizing<String> =
                credentials::saved_password(request.apple_id.trim()).ok_or("saved_credentials")?;
            protocol::progress("authenticating")?;
            let mut session = apple::sign_in(&apple_id, &password).await?;
            protocol::progress("certificates")?;
            apple::find_remote(&mut session, &key).await?
        }
    };
    protocol::progress("writing")?;
    let path = apple::write_p12(&found, &key, &request.p12_password, output_dir).await?;
    protocol::progress("complete")?;
    x509_cert::Certificate::from_der(&found.certificate.der).map_err(|_| "encode")?;
    let certificate_der = found.certificate.der.clone();
    Ok(ExportResult {
        p12_path: path.to_string_lossy().into_owned(),
        team_id: found.team.id,
        team_name: found.team.name,
        certificate_der: base64::engine::general_purpose::STANDARD.encode(certificate_der),
    })
}

#[tokio::main]
async fn main() {
    // No tracing subscriber, panic payloads, environment credentials or credential
    // arguments. The stdout stream is exclusively the JSON protocol.
    std::panic::set_hook(Box::new(|_| {}));
    if !cfg!(windows)
        || std::env::args_os().len() != 1
        || rustls::crypto::ring::default_provider().install_default().is_err()
    {
        let _ = protocol::emit(Event::Error { code: "internal" });
        std::process::exit(1);
    }
    match run().await {
        Ok(result) => {
            if protocol::emit(Event::Result { result: &result }).is_err() {
                std::process::exit(1);
            }
        }
        Err(code) => {
            let _ = protocol::emit(Event::Error { code });
            std::process::exit(1);
        }
    }
}
