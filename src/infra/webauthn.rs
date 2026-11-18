//! WebAuthn wire parsing and ES256 / RS256 signature verification.
use std::io::Cursor;

use base64::{
    Engine as _,
    engine::general_purpose,
};
use ciborium::value::Value as CborValue;
use p256::ecdsa::{
    Signature as P256Signature,
    VerifyingKey as P256VerifyingKey,
    signature::Verifier as _,
};
use rsa::{
    BoxedUint,
    PublicKey as RsaPublicKey,
    pkcs1v15::{
        Signature as RsaSignature,
        VerifyingKey as RsaVerifyingKey,
    },
};
use serde::Deserialize;
use sha2::{
    Digest,
    Sha256,
};
use url::Url;

use crate::errors::{
    AppError,
    AuthError,
};

pub fn invalid(message: impl Into<String>) -> AppError {
    AuthError::InvalidCredentials(message.into()).into()
}

#[derive(Debug)]
pub struct ParsedAuthData {
    pub rp_id_hash: [u8; 32],
    pub flags: u8,
    pub sign_count: u32,
    pub credential_id: Option<Vec<u8>>,
    pub credential_public_key_cose: Option<Vec<u8>>,
}

#[derive(Debug, Deserialize)]
pub struct ClientDataJson {
    #[serde(rename = "type")]
    pub typ:          String,
    pub challenge:    String,
    pub origin:       String,
    #[serde(rename = "crossOrigin", default)]
    pub cross_origin: bool,
}

#[derive(Debug, Deserialize)]
pub struct Assertion {
    pub id:       Option<String>,
    #[serde(rename = "rawId")]
    pub raw_id:   Option<String>,
    pub response: AssertionResponse,
}
#[derive(Debug, Deserialize)]
pub struct AssertionResponse {
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    #[serde(rename = "clientDataJson", alias = "clientDataJSON")]
    pub client_data_json:   String,
    pub signature:          String,
    #[serde(rename = "userHandle")]
    pub user_handle:        Option<String>,
}

pub fn relying_party(domain: &str) -> Result<(String, String), AppError> {
    let url =
        Url::parse(domain).map_err(|_| invalid("Invalid WebAuthn DOMAIN"))?;
    let host = url
        .host_str()
        .ok_or_else(|| invalid("WebAuthn DOMAIN needs a host"))?;
    if url.scheme() != "https" &&
        !(url.scheme() == "http" &&
            matches!(host, "localhost" | "127.0.0.1" | "::1"))
    {
        return Err(invalid("WebAuthn requires HTTPS"));
    }
    Ok((host.to_string(), url.origin().ascii_serialization()))
}

pub fn verify_client_data(
    bytes: &[u8],
    expected_type: &str,
    challenge: &str,
    origin: &str,
) -> Result<(), AppError> {
    if bytes.len() > 32768 {
        return Err(invalid("Invalid WebAuthn client data"));
    }
    let data: ClientDataJson = serde_json::from_slice(bytes)
        .map_err(|_| invalid("Invalid WebAuthn client data"))?;
    if data.cross_origin ||
        data.typ != expected_type ||
        data.origin != origin ||
        decode_b64_any(&data.challenge)? != decode_b64_any(challenge)?
    {
        return Err(invalid("WebAuthn challenge, origin or ceremony mismatch"));
    }
    Ok(())
}

pub fn verify_client_data_with_origins(
    bytes: &[u8],
    kind: &str,
    challenge: &str,
    origin: &str,
    extra_origins: &str,
) -> Result<(), AppError> {
    let data: ClientDataJson = serde_json::from_slice(bytes)
        .map_err(|_| invalid("Invalid WebAuthn client data"))?;
    let allowed = extra_origins
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty() && !value.contains('*'))
        .any(|value| value == data.origin);
    let expected = if data.origin == origin || allowed {
        data.origin.as_str()
    } else {
        origin
    };
    verify_client_data(bytes, kind, challenge, expected)
}

pub fn verify_authenticator_data(
    data: &ParsedAuthData,
    rp: &str,
    require_uv: bool,
) -> Result<(), AppError> {
    let expected_rp_id_hash: [u8; 32] = Sha256::digest(rp.as_bytes()).into();
    if expected_rp_id_hash != data.rp_id_hash ||
        data.flags & 1 == 0 ||
        (require_uv && data.flags & 4 == 0)
    {
        return Err(invalid(
            "WebAuthn relying party or user verification mismatch",
        ));
    }
    Ok(())
}
pub fn verify_counter(old: i64, new: i64) -> Result<(), AppError> {
    if (old != 0 || new != 0) && new <= old {
        return Err(invalid("WebAuthn counter did not increase"));
    }
    Ok(())
}

pub fn decode_b64_any(input: &str) -> Result<Vec<u8>, AppError> {
    if input.len() > 65536 {
        return Err(invalid("WebAuthn payload is too large"));
    }
    let s = input.trim();
    if let Ok(v) = general_purpose::URL_SAFE_NO_PAD.decode(s) {
        return Ok(v);
    }
    if let Ok(v) = general_purpose::URL_SAFE.decode(s) {
        return Ok(v);
    }
    if let Ok(v) = general_purpose::STANDARD.decode(s) {
        return Ok(v);
    }
    let mut padded = s.to_string();
    while !padded.len().is_multiple_of(4) {
        padded.push('=');
    }
    if let Ok(v) = general_purpose::URL_SAFE.decode(&padded) {
        return Ok(v);
    }
    general_purpose::STANDARD.decode(&padded).map_err(|_| {
        AppError::bad_request("Invalid base64 payload".to_string())
    })
}

pub fn encode_b64url(bytes: &[u8]) -> String {
    general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

type AttestationData = ([u8; 32], u32, Vec<u8>, Vec<u8>);
pub fn parse_attestation_object(
    bytes: &[u8],
) -> Result<AttestationData, AppError> {
    let value: CborValue = ciborium::de::from_reader(Cursor::new(bytes))
        .map_err(|_| {
            AppError::bad_request("Invalid WebAuthn attestation".to_string())
        })?;
    let map = value.as_map().ok_or_else(|| {
        AppError::bad_request("Invalid WebAuthn attestation".to_string())
    })?;
    let auth_data = map_get_text(map, "authData")
        .and_then(|v| v.as_bytes())
        .ok_or_else(|| {
            AppError::bad_request("Invalid WebAuthn attestation".to_string())
        })?;

    let parsed = parse_auth_data(auth_data, true)?;
    let cred_id = parsed.credential_id.ok_or_else(|| {
        AppError::bad_request("Missing WebAuthn credential id".to_string())
    })?;
    let cred_key = parsed.credential_public_key_cose.ok_or_else(|| {
        AppError::bad_request("Missing WebAuthn credential key".to_string())
    })?;
    Ok((parsed.rp_id_hash, parsed.sign_count, cred_id, cred_key))
}

pub fn parse_auth_data(
    data: &[u8],
    expect_attested_data: bool,
) -> Result<ParsedAuthData, AppError> {
    if data.len() < 37 {
        return Err(AppError::bad_request(
            "Invalid WebAuthn authData".to_string(),
        ));
    }

    let mut rp_id_hash = [0u8; 32];
    rp_id_hash.copy_from_slice(&data[..32]);
    let flags = data[32];
    let sign_count =
        u32::from_be_bytes([data[33], data[34], data[35], data[36]]);

    if (flags & 0x01) == 0 {
        return Err(AppError::bad_request(
            "WebAuthn user presence is required".to_string(),
        ));
    }

    let mut credential_id = None;
    let mut credential_public_key_cose = None;
    if expect_attested_data || (flags & 0x40) != 0 {
        if (flags & 0x40) == 0 {
            return Err(AppError::bad_request(
                "WebAuthn attested credential data missing".to_string(),
            ));
        }
        let mut offset = 37usize;
        if data.len() < offset + 18 {
            return Err(AppError::bad_request(
                "Invalid WebAuthn attested credential data".to_string(),
            ));
        }
        offset += 16; // aaguid
        let cred_len =
            u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        if data.len() < offset + cred_len {
            return Err(AppError::bad_request(
                "Invalid WebAuthn credential id".to_string(),
            ));
        }
        credential_id = Some(data[offset..offset + cred_len].to_vec());
        offset += cred_len;

        let mut cursor = Cursor::new(&data[offset..]);
        let _parsed_key: CborValue = ciborium::de::from_reader(&mut cursor)
            .map_err(|_| {
                AppError::bad_request(
                    "Invalid WebAuthn credential key".to_string(),
                )
            })?;
        let used = cursor.position() as usize;
        if used == 0 || offset + used > data.len() {
            return Err(AppError::bad_request(
                "Invalid WebAuthn credential key".to_string(),
            ));
        }
        credential_public_key_cose = Some(data[offset..offset + used].to_vec());
    }

    Ok(ParsedAuthData {
        rp_id_hash,
        flags,
        sign_count,
        credential_id,
        credential_public_key_cose,
    })
}

#[derive(Debug, Clone)]
pub enum WebAuthnVerifyingKey {
    P256(P256VerifyingKey),
    Rsa(RsaPublicKey),
}

impl WebAuthnVerifyingKey {
    pub fn verify(
        &self,
        signed_data: &[u8],
        signature: &[u8],
    ) -> Result<(), AppError> {
        match self {
            WebAuthnVerifyingKey::P256(vk) => {
                let sig = P256Signature::from_der(signature).map_err(|_| {
                    invalid("Invalid signature format".to_string())
                })?;
                vk.verify(signed_data, &sig).map_err(|_| {
                    invalid("Signature verification failed".to_string())
                })
            }
            WebAuthnVerifyingKey::Rsa(rsa_key) => {
                // RS256: RSASSA-PKCS1-v1_5 with SHA-256
                let verifying_key =
                    RsaVerifyingKey::<Sha256>::new(rsa_key.clone());
                let sig = RsaSignature::try_from(signature).map_err(|_| {
                    invalid("Invalid signature format".to_string())
                })?;
                verifying_key.verify(signed_data, &sig).map_err(|_| {
                    invalid("Signature verification failed".to_string())
                })
            }
        }
    }
}

pub fn parse_webauthn_public_key(
    cose_key_bytes: &[u8],
) -> Result<(WebAuthnVerifyingKey, i64), AppError> {
    let value: CborValue = ciborium::de::from_reader(Cursor::new(
        cose_key_bytes,
    ))
    .map_err(|_| {
        AppError::bad_request("Invalid WebAuthn public key".to_string())
    })?;
    let map = value.as_map().ok_or_else(|| {
        AppError::bad_request("Invalid WebAuthn public key".to_string())
    })?;

    let kty = map_get_i128(map, 1).ok_or_else(|| {
        AppError::bad_request("Invalid WebAuthn public key".to_string())
    })?;
    let alg = map_get_i128(map, 3).ok_or_else(|| {
        AppError::bad_request("Invalid WebAuthn public key".to_string())
    })?;

    match (kty, alg) {
        // EC2 key type (kty=2) with ES256 (alg=-7)
        (2, -7) => {
            let crv = map_get_i128(map, -1).ok_or_else(|| {
                AppError::bad_request("Invalid WebAuthn public key".to_string())
            })?;
            if crv != 1 {
                return Err(AppError::bad_request(
                    "Unsupported WebAuthn curve".to_string(),
                ));
            }

            let x = map_get_bytes(map, -2).ok_or_else(|| {
                AppError::bad_request("Invalid WebAuthn public key".to_string())
            })?;
            let y = map_get_bytes(map, -3).ok_or_else(|| {
                AppError::bad_request("Invalid WebAuthn public key".to_string())
            })?;
            if x.len() != 32 || y.len() != 32 {
                return Err(AppError::bad_request(
                    "Invalid WebAuthn public key length".to_string(),
                ));
            }

            let mut encoded = Vec::with_capacity(65);
            encoded.push(0x04);
            encoded.extend_from_slice(x);
            encoded.extend_from_slice(y);

            let vk =
                P256VerifyingKey::from_sec1_bytes(&encoded).map_err(|_| {
                    AppError::bad_request(
                        "Invalid WebAuthn public key".to_string(),
                    )
                })?;
            Ok((WebAuthnVerifyingKey::P256(vk), alg as i64))
        }
        // RSA key type (kty=3) with RS256 (alg=-257)
        (3, -257) => {
            // RSA public key: n (-1) and e (-2)
            let n = map_get_bytes(map, -1).ok_or_else(|| {
                AppError::bad_request("Invalid RSA public key".to_string())
            })?;
            let e = map_get_bytes(map, -2).ok_or_else(|| {
                AppError::bad_request("Invalid RSA public key".to_string())
            })?;

            if !(256..=1024).contains(&n.len()) || e.is_empty() || e.len() > 4 {
                return Err(invalid("Invalid RSA key size"));
            }
            // COSE key components are public, so their input-dependent
            // precision does not expose secret material.
            let n_biguint = BoxedUint::from_be_slice_vartime(n);
            let e_biguint = BoxedUint::from_be_slice_vartime(e);

            let rsa_key =
                RsaPublicKey::new(n_biguint, e_biguint).map_err(|_| {
                    AppError::bad_request("Invalid RSA public key".to_string())
                })?;
            Ok((WebAuthnVerifyingKey::Rsa(rsa_key), alg as i64))
        }
        _ => Err(AppError::bad_request(format!(
            "Unsupported WebAuthn public key type: kty={}, alg={}",
            kty, alg
        ))),
    }
}

fn map_get_text<'a>(
    map: &'a [(CborValue, CborValue)],
    key: &str,
) -> Option<&'a CborValue> {
    map.iter().find_map(|(k, v)| match k {
        CborValue::Text(t) if t == key => Some(v),
        _ => None,
    })
}

fn map_get_i128(map: &[(CborValue, CborValue)], key: i128) -> Option<i128> {
    map.iter().find_map(|(k, v)| match (k, v) {
        (CborValue::Integer(ki), CborValue::Integer(vi))
            if i128::from(*ki) == key =>
        {
            Some(i128::from(*vi))
        }
        _ => None,
    })
}

fn map_get_bytes(map: &[(CborValue, CborValue)], key: i128) -> Option<&[u8]> {
    map.iter().find_map(|(k, v)| match (k, v) {
        (CborValue::Integer(ki), CborValue::Bytes(b))
            if i128::from(*ki) == key =>
        {
            Some(b.as_slice())
        }
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::{
        SigningKey,
        signature::Signer,
    };

    use super::*;

    #[test]
    fn es256_signature_verification_rejects_modified_authenticator_data() {
        let key = SigningKey::from_slice(&[1u8; 32]).unwrap();
        let public = key.verifying_key().to_sec1_point(false);
        let cose = CborValue::Map(vec![
            (CborValue::Integer(1.into()), CborValue::Integer(2.into())),
            (
                CborValue::Integer(3.into()),
                CborValue::Integer((-7).into()),
            ),
            (
                CborValue::Integer((-1).into()),
                CborValue::Integer(1.into()),
            ),
            (
                CborValue::Integer((-2).into()),
                CborValue::Bytes(public.x().unwrap().to_vec()),
            ),
            (
                CborValue::Integer((-3).into()),
                CborValue::Bytes(public.y().unwrap().to_vec()),
            ),
        ]);
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&cose, &mut encoded).unwrap();
        let verifying = parse_webauthn_public_key(&encoded).unwrap().0;
        let mut data = Sha256::digest(b"vault.example").to_vec();
        data.push(5);
        data.extend_from_slice(&1u32.to_be_bytes());
        let client=br#"{"type":"webauthn.get","origin":"https://vault.example","challenge":"Y2hhbGxlbmdl"}"#;
        data.extend_from_slice(&Sha256::digest(client));
        let signature: P256Signature = key.sign(&data);
        assert!(
            verifying
                .verify(&data, signature.to_der().as_bytes())
                .is_ok()
        );
        // WebAuthn ES256 signatures are ASN.1 DER, not raw r || s.
        assert!(verifying.verify(&data, &signature.to_bytes()).is_err());
        data[0] ^= 1;
        assert!(
            verifying
                .verify(&data, signature.to_der().as_bytes())
                .is_err()
        );
    }
    #[test]
    fn rs256_signature_verification_rejects_modified_data() {
        use rsa::{
            PrivateKey,
            pkcs1v15::SigningKey,
            pkcs8::DecodePrivateKey,
            signature::{
                SignatureEncoding,
                Signer,
            },
            traits::PublicKeyParts,
        };
        let key = PrivateKey::from_pkcs8_pem(include_str!(
            "../../tests/fixtures/webauthn-rs256-test-key.pem"
        ))
        .unwrap();
        let public = key.to_public_key();
        let cose = CborValue::Map(vec![
            (CborValue::Integer(1.into()), CborValue::Integer(3.into())),
            (
                CborValue::Integer(3.into()),
                CborValue::Integer((-257).into()),
            ),
            (
                CborValue::Integer((-1).into()),
                CborValue::Bytes(public.n_bytes().into_vec()),
            ),
            (
                CborValue::Integer((-2).into()),
                CborValue::Bytes(public.e_bytes().into_vec()),
            ),
        ]);
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&cose, &mut encoded).unwrap();
        let (public, algorithm) = parse_webauthn_public_key(&encoded).unwrap();
        assert_eq!(algorithm, -257);
        let signer = SigningKey::<Sha256>::new(key);
        let signature = signer.sign(b"WebAuthn fixed test message");
        assert!(
            public
                .verify(b"WebAuthn fixed test message", &signature.to_bytes())
                .is_ok()
        );
        assert!(
            public
                .verify(
                    b"WebAuthn fixed test message",
                    &signature.to_bytes()[1..]
                )
                .is_err()
        );
        assert!(
            public
                .verify(b"modified message", &signature.to_bytes())
                .is_err()
        );
    }

    #[test]
    fn relying_party_origin_and_uv_are_enforced() {
        let rp = "vault.example";
        let mut data = Sha256::digest(rp.as_bytes()).to_vec();
        data.push(5);
        data.extend_from_slice(&0u32.to_be_bytes());
        let parsed = parse_auth_data(&data, false).unwrap();
        assert!(verify_authenticator_data(&parsed, rp, true).is_ok());
        assert!(
            verify_authenticator_data(&parsed, "evil.example", true).is_err()
        );
        data[32] = 1;
        assert!(
            verify_authenticator_data(
                &parse_auth_data(&data, false).unwrap(),
                rp,
                true
            )
            .is_err()
        );
        let good=br#"{"type":"webauthn.get","origin":"https://vault.example","challenge":"Y2hhbGxlbmdl"}"#;
        assert!(
            verify_client_data(
                good,
                "webauthn.get",
                "Y2hhbGxlbmdl",
                "https://vault.example"
            )
            .is_ok()
        );
        assert!(
            verify_client_data(
                good,
                "webauthn.create",
                "Y2hhbGxlbmdl",
                "https://vault.example"
            )
            .is_err()
        );
        assert!(
            verify_client_data(
                good,
                "webauthn.get",
                "Y2hhbGxlbmdl",
                "https://evil.example"
            )
            .is_err()
        );
        let cross=br#"{"type":"webauthn.get","origin":"https://vault.example","challenge":"Y2hhbGxlbmdl","crossOrigin":true}"#;
        assert!(
            verify_client_data(
                cross,
                "webauthn.get",
                "Y2hhbGxlbmdl",
                "https://vault.example"
            )
            .is_err()
        );
        assert!(relying_party("http://vault.example").is_err());
        assert_eq!(
            relying_party("https://vault.example:443/").unwrap(),
            ("vault.example".into(), "https://vault.example".into())
        );
    }
    #[test]
    fn native_origins_require_exact_explicit_configuration() {
        let data=br#"{"type":"webauthn.get","origin":"android:apk-key-hash:trusted-app","challenge":"YWJj"}"#;
        assert!(
            verify_client_data_with_origins(
                data,
                "webauthn.get",
                "YWJj",
                "https://vault.example",
                ""
            )
            .is_err()
        );
        assert!(
            verify_client_data_with_origins(
                data,
                "webauthn.get",
                "YWJj",
                "https://vault.example",
                "android:apk-key-hash:trusted-app"
            )
            .is_ok()
        );
        assert!(
            verify_client_data_with_origins(
                data,
                "webauthn.get",
                "YWJj",
                "https://vault.example",
                "android:apk-key-hash:*"
            )
            .is_err()
        );
        assert!(
            verify_client_data_with_origins(
                data,
                "webauthn.get",
                "YWJj",
                "https://vault.example",
                "android:apk-key-hash:other-app"
            )
            .is_err()
        );
        let extension=br#"{"type":"webauthn.get","origin":"chrome-extension://trusted-id","challenge":"YWJj"}"#;
        assert!(
            verify_client_data_with_origins(
                extension,
                "webauthn.get",
                "YWJj",
                "https://vault.example",
                "chrome-extension://trusted-id"
            )
            .is_ok()
        );
        assert!(
            verify_client_data_with_origins(
                extension,
                "webauthn.get",
                "YWJj",
                "https://vault.example",
                "chrome-extension://*"
            )
            .is_err()
        );
    }

    #[test]
    fn malformed_attestations_and_unsupported_keys_fail() {
        assert!(parse_auth_data(&[0; 36], false).is_err());
        assert!(parse_attestation_object(&[0xff]).is_err());
        assert!(parse_webauthn_public_key(&[0xa0]).is_err());
    }
}
