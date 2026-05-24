use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YintError {
    pub message: String,
    pub status: u16,
}

impl YintError {
    fn new(message: impl Into<String>, status: u16) -> Self {
        Self {
            message: message.into(),
            status,
        }
    }
}

impl fmt::Display for YintError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for YintError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestPackage {
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
    pub nonce: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponsePackage {
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Yint {
    pub core_path: PathBuf,
    pub time_window: i64,
    pub k_enc_hex: String,
    pub k_mac_hex: String,
    nonces: HashMap<String, i64>,
}

impl Yint {
    pub fn new(
        master_key: &[u8],
        core_path: Option<PathBuf>,
        time_window: i64,
    ) -> Result<Self, YintError> {
        if time_window < 1 {
            return Err(YintError::new("bad time window", 400));
        }
        let core_path = core_path.unwrap_or_else(default_core_path);
        if !core_path.is_file() {
            return Err(YintError::new(
                format!("core not found: {}", core_path.display()),
                500,
            ));
        }
        let derived = run_core(&core_path, &["derive", &hex_encode(master_key)], None)?;
        let parts = derived.split_whitespace().collect::<Vec<_>>();
        if parts.len() != 2 || !is_lower_hex(parts[0], 64) || !is_lower_hex(parts[1], 64) {
            return Err(YintError::new("bad derive output", 500));
        }
        Ok(Self {
            core_path,
            time_window,
            k_enc_hex: parts[0].to_string(),
            k_mac_hex: parts[1].to_string(),
            nonces: HashMap::new(),
        })
    }

    pub fn build_request(
        &self,
        method: &str,
        uri: &str,
        plaintext: &[u8],
    ) -> Result<RequestPackage, YintError> {
        let method = method.to_uppercase();
        let timestamp = now()?.to_string();
        let nonce = self.random_hex(16)?;
        let iv = self.random_hex(16)?;
        let plain_hex = hex_encode(plaintext);
        let body_hex = self.run(&["build-body", &self.k_enc_hex, &iv, "-"], Some(&plain_hex))?;
        let sign = self.run(
            &[
                "sign-req",
                &self.k_mac_hex,
                &method,
                uri,
                &timestamp,
                &nonce,
                "-",
            ],
            Some(&body_hex),
        )?;
        Ok(RequestPackage {
            headers: HashMap::from([
                ("X-Yint-Timestamp".to_string(), timestamp),
                ("X-Yint-Nonce".to_string(), nonce.clone()),
                ("X-Yint-Sign".to_string(), sign),
            ]),
            body: hex_decode(&body_hex)?,
            nonce,
        })
    }

    pub fn open_request(
        &mut self,
        method: &str,
        uri: &str,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> Result<Vec<u8>, YintError> {
        let method = method.to_uppercase();
        let h = normalize_headers(headers);
        reject_unknown_yint_headers(&h)?;
        let timestamp = required_header(&h, "x-yint-timestamp")?;
        let nonce = required_header(&h, "x-yint-nonce")?;
        let sign = required_header(&h, "x-yint-sign")?;
        if !timestamp.chars().all(|c| c.is_ascii_digit())
            || !is_lower_hex(nonce, 32)
            || !is_lower_hex(sign, 64)
        {
            return Err(YintError::new("bad yint headers", 400));
        }
        let current = now()?;
        let ts = timestamp
            .parse::<i64>()
            .map_err(|_| YintError::new("bad yint headers", 400))?;
        if (current - ts).abs() > self.time_window {
            return Err(YintError::new("unauthorized", 401));
        }
        self.cleanup_nonces(current);
        if self.nonces.contains_key(nonce) {
            return Err(YintError::new("unauthorized", 401));
        }
        self.verify(
            &[
                "verify-req",
                &self.k_mac_hex,
                &method,
                uri,
                timestamp,
                nonce,
                sign,
                "-",
            ],
            &hex_encode(body),
        )?;
        self.nonces.insert(nonce.to_string(), ts + self.time_window);
        self.decrypt_body(body)
    }

    pub fn build_response(
        &self,
        status: u16,
        req_nonce: &str,
        plaintext: &[u8],
    ) -> Result<ResponsePackage, YintError> {
        let status = status.to_string();
        let timestamp = now()?.to_string();
        let nonce = self.random_hex(16)?;
        let iv = self.random_hex(16)?;
        let plain_hex = hex_encode(plaintext);
        let body_hex = self.run(&["build-body", &self.k_enc_hex, &iv, "-"], Some(&plain_hex))?;
        let sign = self.run(
            &[
                "sign-resp",
                &self.k_mac_hex,
                &status,
                &timestamp,
                &nonce,
                req_nonce,
                "-",
            ],
            Some(&body_hex),
        )?;
        Ok(ResponsePackage {
            headers: HashMap::from([
                ("X-Yint-Timestamp".to_string(), timestamp),
                ("X-Yint-Nonce".to_string(), nonce),
                ("X-Yint-Sign".to_string(), sign),
            ]),
            body: hex_decode(&body_hex)?,
        })
    }

    pub fn open_response(
        &self,
        status: u16,
        req_nonce: &str,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> Result<Vec<u8>, YintError> {
        let h = normalize_headers(headers);
        reject_unknown_yint_headers(&h)?;
        let timestamp = required_header(&h, "x-yint-timestamp")?;
        let nonce = required_header(&h, "x-yint-nonce")?;
        let sign = required_header(&h, "x-yint-sign")?;
        if !timestamp.chars().all(|c| c.is_ascii_digit())
            || !is_lower_hex(nonce, 32)
            || !is_lower_hex(sign, 64)
            || !is_lower_hex(req_nonce, 32)
        {
            return Err(YintError::new("bad yint headers", 400));
        }
        let ts = timestamp
            .parse::<i64>()
            .map_err(|_| YintError::new("bad yint headers", 400))?;
        if (now()? - ts).abs() > self.time_window {
            return Err(YintError::new("unauthorized", 401));
        }
        self.verify(
            &[
                "verify-resp",
                &self.k_mac_hex,
                &status.to_string(),
                timestamp,
                nonce,
                req_nonce,
                sign,
                "-",
            ],
            &hex_encode(body),
        )?;
        self.decrypt_body(body)
    }

    pub fn decrypt_body(&self, body: &[u8]) -> Result<Vec<u8>, YintError> {
        let plain_hex = self.run(
            &["decrypt-body", &self.k_enc_hex, "-"],
            Some(&hex_encode(body)),
        )?;
        hex_decode(&plain_hex)
    }

    fn random_hex(&self, nbytes: usize) -> Result<String, YintError> {
        self.run(&["random", &nbytes.to_string()], None)
    }

    fn run(&self, args: &[&str], stdin: Option<&str>) -> Result<String, YintError> {
        run_core(&self.core_path, args, stdin)
    }

    fn verify(&self, args: &[&str], stdin: &str) -> Result<(), YintError> {
        match self.run(args, Some(stdin)) {
            Ok(out) if out == "OK" => Ok(()),
            Ok(_) => Err(YintError::new("unauthorized", 401)),
            Err(err) if err.message.contains("ERR_SIGN") => {
                Err(YintError::new("unauthorized", 401))
            }
            Err(err) => Err(err),
        }
    }

    fn cleanup_nonces(&mut self, current: i64) {
        self.nonces.retain(|_, expire_at| *expire_at >= current);
    }
}

fn default_core_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../core/bin/yint")
}

fn run_core(core_path: &PathBuf, args: &[&str], stdin: Option<&str>) -> Result<String, YintError> {
    let mut child = Command::new(core_path)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| YintError::new(format!("cannot run core: {err}"), 500))?;
    if let Some(input) = stdin {
        use std::io::Write;
        let mut pipe = child
            .stdin
            .take()
            .ok_or_else(|| YintError::new("cannot write core stdin", 500))?;
        pipe.write_all(input.as_bytes())
            .map_err(|err| YintError::new(format!("cannot write core stdin: {err}"), 500))?;
    }
    let output = child
        .wait_with_output()
        .map_err(|err| YintError::new(format!("cannot read core output: {err}"), 500))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let tag = if stderr.trim().is_empty() {
            stdout.trim()
        } else {
            stderr.trim()
        };
        return Err(YintError::new(format!("core failed: {tag}"), 500));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn normalize_headers(headers: &HashMap<String, String>) -> HashMap<String, String> {
    headers
        .iter()
        .map(|(name, value)| (name.to_ascii_lowercase(), value.to_string()))
        .collect()
}

fn reject_unknown_yint_headers(headers: &HashMap<String, String>) -> Result<(), YintError> {
    for name in headers.keys() {
        if name.starts_with("x-yint-")
            && name != "x-yint-timestamp"
            && name != "x-yint-nonce"
            && name != "x-yint-sign"
        {
            return Err(YintError::new("bad yint headers", 400));
        }
    }
    Ok(())
}

fn required_header<'a>(
    headers: &'a HashMap<String, String>,
    name: &str,
) -> Result<&'a str, YintError> {
    headers
        .get(name)
        .map(String::as_str)
        .ok_or_else(|| YintError::new("missing yint header", 400))
}

fn now() -> Result<i64, YintError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| YintError::new("system clock before unix epoch", 500))?
        .as_secs() as i64)
}

fn is_lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn hex_decode(hex: &str) -> Result<Vec<u8>, YintError> {
    if hex.len() % 2 != 0 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(YintError::new("bad hex", 500));
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    let bytes = hex.as_bytes();
    for chunk in bytes.chunks_exact(2) {
        out.push((hex_value(chunk[0])? << 4) | hex_value(chunk[1])?);
    }
    Ok(out)
}

fn hex_value(byte: u8) -> Result<u8, YintError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(YintError::new("bad hex", 500)),
    }
}
