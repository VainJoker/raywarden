//! WebAuthn wire parsing and ES256 / RS256 signature verification.
use std::io::Cursor;

use base64::{Engine, engine::general_purpose};
use ciborium::value::Value as CborValue;
use p256::ecdsa::{
    Signature as P256Signature, VerifyingKey as P256VerifyingKey, signature::Verifier,
};
use rsa::{
    BoxedUint, PublicKey as RsaPublicKey,
    pkcs1v15::{Signature as RsaSignature, VerifyingKey as RsaVerifyingKey},
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use url::Url;

use crate::errors::{AppError, AppResult};

#[derive(Debug)]
pub struct AuthenticatorData {
    pub relying_party_id_hash: [u8; 32],
    pub flags: u8,
    pub sign_count: u32,
    pub credential_id: Option<Vec<u8>>,
    pub credential_public_key_cose: Option<Vec<u8>>,
}

#[derive(Deserialize)]
struct ClientDataJson {
    #[serde(rename = "type")]
    ceremony_type: String,
    challenge: String,
    origin: String,
    #[serde(rename = "crossOrigin", default)]
    cross_origin: bool,
}

pub struct ClientData {
    bytes: Vec<u8>,
    json: ClientDataJson,
}

impl ClientData {
    pub fn parse(bytes: Vec<u8>) -> AppResult<Self> {
        if bytes.len() > 32_768 {
            return Err(AppError::invalid_credentials(
                "Invalid WebAuthn client data",
            ));
        }
        let json = serde_json::from_slice(&bytes)
            .map_err(|_error| AppError::invalid_credentials("Invalid WebAuthn client data"))?;
        Ok(Self { bytes, json })
    }

    pub fn challenge(&self) -> &str {
        &self.json.challenge
    }

    pub const fn bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    pub fn verify(
        &self,
        kind: &str,
        challenge: &str,
        origin: &str,
        extra_origins: &str,
    ) -> AppResult<()> {
        if self.bytes.len() > 32_768 {
            return Err(AppError::invalid_credentials(
                "Invalid WebAuthn client data",
            ));
        }
        let allowed = self.json.origin == origin
            || extra_origins
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty() && !value.contains('*'))
                .any(|value| value == self.json.origin);
        if self.json.cross_origin
            || self.json.ceremony_type != kind
            || !allowed
            || decode_base64(self.challenge())? != decode_base64(challenge)?
        {
            return Err(AppError::invalid_credentials(
                "WebAuthn challenge, origin or ceremony mismatch",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
pub struct Assertion {
    pub id: Option<String>,
    #[serde(rename = "rawId")]
    pub raw_id: Option<String>,
    pub response: AssertionResponse,
}
#[derive(Debug, Deserialize)]
pub struct AssertionResponse {
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    #[serde(rename = "clientDataJson", alias = "clientDataJSON")]
    pub client_data_json: String,
    pub signature: String,
    #[serde(rename = "userHandle")]
    pub user_handle: Option<String>,
}

pub fn relying_party(domain: &str) -> AppResult<(String, String)> {
    let url = Url::parse(domain)
        .map_err(|_error| AppError::invalid_credentials("Invalid WebAuthn DOMAIN"))?;
    let host = url
        .host_str()
        .ok_or_else(|| AppError::invalid_credentials("WebAuthn DOMAIN needs a host"))?;
    if url.scheme() != "https"
        && !(url.scheme() == "http" && matches!(host, "localhost" | "127.0.0.1" | "::1"))
    {
        return Err(AppError::invalid_credentials("WebAuthn requires HTTPS"));
    }
    Ok((host.to_string(), url.origin().ascii_serialization()))
}

pub fn verify_authenticator_data(
    data: &AuthenticatorData,
    relying_party_id: &str,
    require_user_verification: bool,
) -> AppResult<()> {
    let expected_rp_id_hash: [u8; 32] = Sha256::digest(relying_party_id.as_bytes()).into();
    if expected_rp_id_hash != data.relying_party_id_hash
        || data.flags & 1 == 0
        || (require_user_verification && data.flags & 4 == 0)
    {
        return Err(AppError::invalid_credentials(
            "WebAuthn relying party or user verification mismatch",
        ));
    }
    Ok(())
}
pub fn verify_counter(previous_counter: i64, next_counter: i64) -> AppResult<()> {
    if (previous_counter != 0 || next_counter != 0) && next_counter <= previous_counter {
        return Err(AppError::invalid_credentials(
            "WebAuthn counter did not increase",
        ));
    }
    Ok(())
}

pub fn decode_base64(input: &str) -> AppResult<Vec<u8>> {
    if input.len() > 65_536 {
        return Err(AppError::invalid_credentials(
            "WebAuthn payload is too large",
        ));
    }
    let encoded = input.trim();
    if let Ok(value) = general_purpose::URL_SAFE_NO_PAD.decode(encoded) {
        return Ok(value);
    }
    if let Ok(value) = general_purpose::URL_SAFE.decode(encoded) {
        return Ok(value);
    }
    if let Ok(value) = general_purpose::STANDARD.decode(encoded) {
        return Ok(value);
    }
    let mut padded = encoded.to_string();
    while !padded.len().is_multiple_of(4) {
        padded.push('=');
    }
    if let Ok(value) = general_purpose::URL_SAFE.decode(&padded) {
        return Ok(value);
    }
    general_purpose::STANDARD
        .decode(&padded)
        .map_err(|_error| AppError::bad_request("Invalid base64 payload".to_string()))
}

pub fn parse_attestation_object(bytes: &[u8]) -> AppResult<AuthenticatorData> {
    let value: CborValue = ciborium::de::from_reader(Cursor::new(bytes))
        .map_err(|_error| AppError::bad_request("Invalid WebAuthn attestation".to_string()))?;
    let map = value
        .as_map()
        .ok_or_else(|| AppError::bad_request("Invalid WebAuthn attestation".to_string()))?;
    let auth_data = cbor_text_value(map, "authData")
        .and_then(|value| value.as_bytes())
        .ok_or_else(|| AppError::bad_request("Invalid WebAuthn attestation".to_string()))?;

    parse_authenticator_data(auth_data, true)
}

pub fn parse_authenticator_data(
    data: &[u8],
    require_attested_data: bool,
) -> AppResult<AuthenticatorData> {
    if data.len() < 37 {
        return Err(AppError::bad_request(
            "Invalid WebAuthn authData".to_string(),
        ));
    }

    let mut relying_party_id_hash = [0u8; 32];
    relying_party_id_hash.copy_from_slice(&data[..32]);
    let flags = data[32];
    let sign_count = u32::from_be_bytes([data[33], data[34], data[35], data[36]]);

    if (flags & 0x01) == 0 {
        return Err(AppError::bad_request(
            "WebAuthn user presence is required".to_string(),
        ));
    }

    let mut credential_id = None;
    let mut credential_public_key_cose = None;
    if require_attested_data || (flags & 0x40) != 0 {
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
        let credential_id_length = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        if data.len() < offset + credential_id_length {
            return Err(AppError::bad_request(
                "Invalid WebAuthn credential id".to_string(),
            ));
        }
        credential_id = Some(data[offset..offset + credential_id_length].to_vec());
        offset += credential_id_length;

        let mut cursor = Cursor::new(&data[offset..]);
        let _parsed_key: CborValue = ciborium::de::from_reader(&mut cursor).map_err(|_error| {
            AppError::bad_request("Invalid WebAuthn credential key".to_string())
        })?;
        let consumed_bytes = cursor.position() as usize;
        if consumed_bytes == 0 || offset + consumed_bytes > data.len() {
            return Err(AppError::bad_request(
                "Invalid WebAuthn credential key".to_string(),
            ));
        }
        credential_public_key_cose = Some(data[offset..offset + consumed_bytes].to_vec());
    }

    Ok(AuthenticatorData {
        relying_party_id_hash,
        flags,
        sign_count,
        credential_id,
        credential_public_key_cose,
    })
}

#[derive(Debug, Clone)]
pub enum WebauthnVerifyingKey {
    P256(P256VerifyingKey),
    Rsa(RsaPublicKey),
}

impl WebauthnVerifyingKey {
    pub fn verify(&self, signed_data: &[u8], signature: &[u8]) -> AppResult<()> {
        match self {
            Self::P256(verifying_key) => {
                let signature = P256Signature::from_der(signature)
                    .map_err(|_error| AppError::invalid_credentials("Invalid signature format"))?;
                verifying_key.verify(signed_data, &signature)
            }
            Self::Rsa(rsa_key) => {
                // RS256: RSASSA-PKCS1-v1_5 with SHA-256
                let verifying_key = RsaVerifyingKey::<Sha256>::new(rsa_key.clone());
                let signature = RsaSignature::try_from(signature)
                    .map_err(|_error| AppError::invalid_credentials("Invalid signature format"))?;
                verifying_key.verify(signed_data, &signature)
            }
        }
        .map_err(|_error| AppError::invalid_credentials("Signature verification failed"))
    }
}

pub fn parse_webauthn_public_key(cose_key_bytes: &[u8]) -> AppResult<WebauthnVerifyingKey> {
    let invalid_key = || AppError::bad_request("Invalid WebAuthn public key");
    let value: CborValue =
        ciborium::de::from_reader(Cursor::new(cose_key_bytes)).map_err(|_error| invalid_key())?;
    let map = value.as_map().ok_or_else(invalid_key)?;

    let key_type = cbor_integer_value(map, 1).ok_or_else(invalid_key)?;
    let algorithm = cbor_integer_value(map, 3).ok_or_else(invalid_key)?;

    match (key_type, algorithm) {
        // EC2 key type (kty=2) with ES256 (alg=-7)
        (2, -7) => {
            let curve = cbor_integer_value(map, -1).ok_or_else(invalid_key)?;
            if curve != 1 {
                return Err(AppError::bad_request("Unsupported WebAuthn curve"));
            }

            let x = cbor_bytes_value(map, -2).ok_or_else(invalid_key)?;
            let y = cbor_bytes_value(map, -3).ok_or_else(invalid_key)?;
            if x.len() != 32 || y.len() != 32 {
                return Err(AppError::bad_request("Invalid WebAuthn public key length"));
            }

            let mut encoded = [0_u8; 65];
            encoded[0] = 0x04;
            encoded[1..33].copy_from_slice(x);
            encoded[33..65].copy_from_slice(y);

            let verifying_key =
                P256VerifyingKey::from_sec1_bytes(&encoded).map_err(|_error| invalid_key())?;
            Ok(WebauthnVerifyingKey::P256(verifying_key))
        }
        // RSA key type (kty=3) with RS256 (alg=-257)
        (3, -257) => {
            // RSA public key: n (-1) and e (-2)
            let modulus = cbor_bytes_value(map, -1)
                .ok_or_else(|| AppError::bad_request("Invalid RSA public key"))?;
            let exponent = cbor_bytes_value(map, -2)
                .ok_or_else(|| AppError::bad_request("Invalid RSA public key"))?;

            if !(256..=1024).contains(&modulus.len()) || exponent.is_empty() || exponent.len() > 4 {
                return Err(AppError::invalid_credentials("Invalid RSA key size"));
            }
            // COSE key components are public, so their input-dependent
            // precision does not expose secret material.
            let modulus_integer = BoxedUint::from_be_slice_vartime(modulus);
            let exponent_integer = BoxedUint::from_be_slice_vartime(exponent);

            let rsa_key = RsaPublicKey::new(modulus_integer, exponent_integer)
                .map_err(|_error| AppError::bad_request("Invalid RSA public key"))?;
            Ok(WebauthnVerifyingKey::Rsa(rsa_key))
        }
        _ => Err(AppError::bad_request(format!(
            "Unsupported WebAuthn public key type: kty={key_type}, \
             alg={algorithm}"
        ))),
    }
}

fn cbor_text_value<'a>(map: &'a [(CborValue, CborValue)], key: &str) -> Option<&'a CborValue> {
    map.iter().find_map(|(k, value)| match k {
        CborValue::Text(t) if t == key => Some(value),
        _ => None,
    })
}

fn cbor_integer_value(map: &[(CborValue, CborValue)], key: i128) -> Option<i128> {
    map.iter().find_map(|(k, value)| match (k, value) {
        (CborValue::Integer(ki), CborValue::Integer(vi)) if i128::from(*ki) == key => {
            Some(i128::from(*vi))
        }
        _ => None,
    })
}

fn cbor_bytes_value(map: &[(CborValue, CborValue)], key: i128) -> Option<&[u8]> {
    map.iter().find_map(|(k, value)| match (k, value) {
        (CborValue::Integer(ki), CborValue::Bytes(b)) if i128::from(*ki) == key => {
            Some(b.as_slice())
        }
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::{SigningKey, signature::Signer};
    use rsa::{
        PrivateKey, pkcs1v15::SigningKey as RsaSigningKey, pkcs8::DecodePrivateKey,
        signature::SignatureEncoding, traits::PublicKeyParts,
    };

    use super::*;

    #[test]
    fn es256_and_rs256_signatures_verify_and_reject_tampering() {
        let key = SigningKey::from_slice(&[1u8; 32]).expect("valid key");
        let pt = key.verifying_key().to_sec1_point(false);
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
                CborValue::Bytes(pt.x().expect("x").to_vec()),
            ),
            (
                CborValue::Integer((-3).into()),
                CborValue::Bytes(pt.y().expect("y").to_vec()),
            ),
        ]);
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&cose, &mut encoded).expect("cbor");
        let verifying = parse_webauthn_public_key(&encoded).expect("cose");
        let mut data = b"webauthn-message".to_vec();
        let sig: P256Signature = key.sign(&data);
        assert!(verifying.verify(&data, sig.to_der().as_bytes()).is_ok());
        assert!(verifying.verify(&data, &sig.to_bytes()).is_err());
        data[0] ^= 1;
        assert!(verifying.verify(&data, sig.to_der().as_bytes()).is_err());

        let rsa_key = PrivateKey::from_pkcs8_pem(include_str!(
            "../../../../tests/fixtures/webauthn-rs256-test-key.pem"
        ))
        .expect("pem");
        let rsa_pub = rsa_key.to_public_key();
        let rsa_cose = CborValue::Map(vec![
            (CborValue::Integer(1.into()), CborValue::Integer(3.into())),
            (
                CborValue::Integer(3.into()),
                CborValue::Integer((-257).into()),
            ),
            (
                CborValue::Integer((-1).into()),
                CborValue::Bytes(rsa_pub.n_bytes().into_vec()),
            ),
            (
                CborValue::Integer((-2).into()),
                CborValue::Bytes(rsa_pub.e_bytes().into_vec()),
            ),
        ]);
        encoded.clear();
        ciborium::ser::into_writer(&rsa_cose, &mut encoded).expect("cbor");
        let rsa_verifying = parse_webauthn_public_key(&encoded).expect("rsa cose");
        let rsa_sig = RsaSigningKey::<Sha256>::new(rsa_key).sign(b"msg");
        assert!(rsa_verifying.verify(b"msg", &rsa_sig.to_bytes()).is_ok());
        assert!(rsa_verifying.verify(b"bad", &rsa_sig.to_bytes()).is_err());
    }

    #[test]
    fn relying_party_origins_flags_and_attestations_are_enforced() {
        let mut auth = Sha256::digest(b"vault.example").to_vec();
        auth.push(5);
        auth.extend_from_slice(&0u32.to_be_bytes());
        let parsed = parse_authenticator_data(&auth, false).expect("auth");
        assert!(verify_authenticator_data(&parsed, "vault.example", true).is_ok());
        assert!(verify_authenticator_data(&parsed, "evil.example", true).is_err());
        auth[32] = 1;
        assert!(
            verify_authenticator_data(
                &parse_authenticator_data(&auth, false).expect("auth"),
                "vault.example",
                true
            )
            .is_err()
        );

        let android = ClientData::parse(
            br#"{"type":"webauthn.get","origin":"android:apk-key-hash:app","challenge":"YWJj"}"#
                .to_vec(),
        )
        .expect("client data");
        assert!(
            android
                .verify("webauthn.get", "YWJj", "https://vault.example", "")
                .is_err()
        );
        assert!(
            android
                .verify(
                    "webauthn.get",
                    "YWJj",
                    "https://vault.example",
                    "android:apk-key-hash:app"
                )
                .is_ok()
        );
        assert!(
            android
                .verify(
                    "webauthn.get",
                    "YWJj",
                    "https://vault.example",
                    "android:apk-key-hash:*"
                )
                .is_err()
        );
        assert!(relying_party("http://vault.example").is_err());
        assert!(parse_attestation_object(&[0xff]).is_err());
        assert!(parse_webauthn_public_key(&[0xa0]).is_err());
    }
}
