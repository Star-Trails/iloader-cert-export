// Line-delimited JSON protocol between the app and this helper. No Apple types here.

use std::io::{BufRead, Read, Write};

use serde::{Deserialize, Serialize};
use zeroize::{ZeroizeOnDrop, Zeroizing};

#[derive(Deserialize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub apple_id: String,
    pub output_dir: String,
    pub p12_password: String,
}

#[derive(Deserialize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct TwoFactorReply {
    #[serde(rename = "type")]
    pub kind: String,
    pub code: String,
}

#[derive(Serialize)]
pub struct ExportResult {
    pub p12_path: String,
    pub team_id: String,
    pub team_name: String,
    pub certificate_der: String,
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event<'a> {
    Progress { stage: &'a str },
    TwoFactor,
    Result { result: &'a ExportResult },
    Error { code: &'a str },
}

pub fn emit(event: Event<'_>) -> std::io::Result<()> {
    let mut output = std::io::stdout().lock();
    serde_json::to_writer(&mut output, &event)?;
    output.write_all(b"\n")?;
    output.flush()
}

pub fn progress(stage: &str) -> Result<(), &'static str> {
    emit(Event::Progress { stage }).map_err(|_| "internal")
}

/// The pipe carries one bounded JSON object per line. Raw credentials are erased after parsing.
pub fn receive<T: serde::de::DeserializeOwned>() -> Result<T, &'static str> {
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
