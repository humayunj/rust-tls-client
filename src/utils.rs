use crypto::curve25519;
use hkdf::Hkdf;
use sha2::{Digest, Sha384};

use crate::{
    buffer::{Buffer, Error},
    handshake::Handshake,
    tls_stream::SessionKeys,
};

pub fn concat_bytes_array(b1: &[u8], b2: &[u8]) -> Vec<u8> {
    let mut r: Vec<u8> = vec![];

    r.extend_from_slice(b1);
    r.extend_from_slice(b2);

    r
}

pub fn sha384(data: &[u8]) -> [u8; 48] {
    sha2::Sha384::digest(data).into()
}

pub fn hdkf_expand_label(
    secret: &[u8],
    label: &str,
    context: &[u8],
    length: usize,
) -> Result<Vec<u8>, Error> {
    let mut info: Vec<u8> = Vec::new();

    info.extend_from_slice(&(length as u16).to_be_bytes());
    info.push((6 + label.len()) as u8);
    info.extend_from_slice(&format!("tls13 {}", label).as_bytes());
    info.push(context.len() as u8);
    info.extend_from_slice(&context);

    let mut okm: Vec<u8> = vec![0; length];

    Hkdf::<Sha384>::from_prk(secret)
        .unwrap()
        .expand(&info[..], &mut okm)
        .unwrap();

    Ok(okm)
}

pub fn hkdf_derive_secret(
    secret: &[u8],
    label: &str,
    transcript_msgs: &[u8],
) -> Result<Vec<u8>, Error> {
    let hash = Sha384::digest(transcript_msgs);
    return hdkf_expand_label(secret, label, &hash, 48);
}

pub fn gen_session_keys(
    client_privkey: &[u8; 32],
    server_pubkey: &[u8; 32],
    client_handshake_bytes: &[u8],
    server_handshake_bytes: &[u8],
) -> Result<SessionKeys, Error> {
    let shared_secret = curve25519::curve25519(client_privkey, server_pubkey);

    let hello_hash = sha384(&concat_bytes_array(
        client_handshake_bytes,
        server_handshake_bytes,
    ));

    let (early_secret, _) = Hkdf::<Sha384>::extract(Some(&[0u8; 48]), &[0u8; 48]);
    let early_secret: [u8; 48] = early_secret.try_into().unwrap();

    let empty_hash = Sha384::digest("");

    let derived_secret = hdkf_expand_label(&early_secret, "derived", &empty_hash, 48).unwrap();

    let (handshake_secret, _) =
        hkdf::Hkdf::<Sha384>::extract(Some(&derived_secret[..]), &shared_secret);
    let handshake_secret: [u8; 48] = handshake_secret.try_into().unwrap();

    let client_secret =
        hdkf_expand_label(&handshake_secret, "c hs traffic", &hello_hash, 48).unwrap();

    let server_secret =
        hdkf_expand_label(&handshake_secret, "s hs traffic", &hello_hash, 48).unwrap();

    let server_handshake_key = hdkf_expand_label(&server_secret, "key", "".as_bytes(), 32).unwrap();

    let server_handshake_iv = hdkf_expand_label(&server_secret, "iv", "".as_bytes(), 12).unwrap();

    let client_handshake_key = hdkf_expand_label(&client_secret, "key", "".as_bytes(), 32).unwrap();

    let client_handshake_iv = hdkf_expand_label(&client_secret, "iv", "".as_bytes(), 12).unwrap();

    Ok(SessionKeys {
        handshake_secret: Vec::from(handshake_secret),
        client_secret,
        server_secret,
        client_handshake_key,
        client_handshake_iv,
        server_handshake_key,
        server_handshake_iv,
    })
}
