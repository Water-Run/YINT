use std::collections::HashMap;
use std::path::PathBuf;
use yint::Yint;

fn core_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../core/bin/yint")
}

fn master() -> Vec<u8> {
    decode_hex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
}

#[test]
fn round_trip_and_replay() {
    let mut y = Yint::new(&master(), Some(core_path()), 300).unwrap();
    assert_eq!(
        y.k_enc_hex,
        "82e11a70f85ec6e9a3681385170db8cfb0dd32bc13cfb4fc746329a44a4a5af5"
    );
    assert_eq!(
        y.k_mac_hex,
        "ec8f02816b4e9d632a5e5366f856af59cf7c5322e3588af80341aab7883dee50"
    );

    let req = y
        .build_request("post", "/api/echo?x=1&x=2", b"hello yint")
        .unwrap();
    assert_eq!(
        y.open_request("POST", "/api/echo?x=1&x=2", &req.headers, &req.body)
            .unwrap(),
        b"hello yint"
    );
    assert_eq!(
        y.open_request("POST", "/api/echo?x=1&x=2", &req.headers, &req.body)
            .unwrap_err()
            .status,
        401
    );

    let resp = y.build_response(200, &req.nonce, b"world").unwrap();
    assert_eq!(
        y.open_response(200, &req.nonce, &resp.headers, &resp.body)
            .unwrap(),
        b"world"
    );
    assert_eq!(
        y.open_response(200, &"0".repeat(32), &resp.headers, &resp.body)
            .unwrap_err()
            .status,
        401
    );
}

#[test]
fn unknown_yint_header() {
    let y = Yint::new(&master(), Some(core_path()), 300).unwrap();
    let req = y.build_request("GET", "/api/ping", b"").unwrap();
    let mut headers: HashMap<String, String> = req.headers.clone();
    headers.insert("X-Yint-Extra".to_string(), "1".to_string());
    let mut server = y.clone();
    assert_eq!(
        server
            .open_request("GET", "/api/ping", &headers, &req.body)
            .unwrap_err()
            .status,
        400
    );
}

fn decode_hex(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .chunks_exact(2)
        .map(|chunk| {
            let hi = (chunk[0] as char).to_digit(16).unwrap() as u8;
            let lo = (chunk[1] as char).to_digit(16).unwrap() as u8;
            (hi << 4) | lo
        })
        .collect()
}
