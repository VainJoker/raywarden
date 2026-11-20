//! WebAuthn wire parsing and ES256 / RS256 signature verification.
use std::io::Cursor;

use base64::{
    Engine,
    engine::general_purpose,
};
use ciborium::value::Value as CborValue;
use p256::ecdsa::{
    Signature as P256Signature,
    VerifyingKey as P256VerifyingKey,
    signature::Verifier,
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
    AppResult,
};

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
    challenge:     String,
    origin:        String,
    #[serde(rename = "crossOrigin", default)]
    cross_origin:  bool,
}

pub struct ClientData {
    bytes: Vec<u8>,
    json:  ClientDataJson,
}

impl ClientData {
    pub fn parse(bytes: Vec<u8>) -> AppResult<Self> {
        let json = serde_json::from_slice(&bytes).map_err(|_error| {
            AppError::invalid_credentials("Invalid WebAuthn client data")
        })?;
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
        let allowed = self.json.origin == origin ||
            extra_origins
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty() && !value.contains('*'))
                .any(|value| value == self.json.origin);
        if self.json.cross_origin ||
            self.json.ceremony_type != kind ||
            !allowed ||
            decode_base64(self.challenge())? != decode_base64(challenge)?
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

pub fn relying_party(domain: &str) -> AppResult<(String, String)> {
    let url = Url::parse(domain).map_err(|_error| {
        AppError::invalid_credentials("Invalid WebAuthn DOMAIN")
    })?;
    let host = url.host_str().ok_or_else(|| {
        AppError::invalid_credentials("WebAuthn DOMAIN needs a host")
    })?;
    if url.scheme() != "https" &&
        !(url.scheme() == "http" &&
            matches!(host, "localhost" | "127.0.0.1" | "::1"))
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
    let expected_rp_id_hash: [u8; 32] =
        Sha256::digest(relying_party_id.as_bytes()).into();
    if expected_rp_id_hash != data.relying_party_id_hash ||
        data.flags & 1 == 0 ||
        (require_user_verification && data.flags & 4 == 0)
    {
        return Err(AppError::invalid_credentials(
            "WebAuthn relying party or user verification mismatch",
        ));
    }
    Ok(())
}
pub fn verify_counter(
    previous_counter: i64,
    next_counter: i64,
) -> AppResult<()> {
    if (previous_counter != 0 || next_counter != 0) &&
        next_counter <= previous_counter
    {
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
    general_purpose::STANDARD.decode(&padded).map_err(|_error| {
        AppError::bad_request("Invalid base64 payload".to_string())
    })
}

pub fn parse_attestation_object(bytes: &[u8]) -> AppResult<AuthenticatorData> {
    let value: CborValue = ciborium::de::from_reader(Cursor::new(bytes))
        .map_err(|_error| {
            AppError::bad_request("Invalid WebAuthn attestation".to_string())
        })?;
    let map = value.as_map().ok_or_else(|| {
        AppError::bad_request("Invalid WebAuthn attestation".to_string())
    })?;
    let auth_data = cbor_text_value(map, "authData")
        .and_then(|value| value.as_bytes())
        .ok_or_else(|| {
            AppError::bad_request("Invalid WebAuthn attestation".to_string())
        })?;

    let parsed = parse_authenticator_data(auth_data, true)?;
    parsed.credential_id.as_ref().ok_or_else(|| {
        AppError::bad_request("Missing WebAuthn credential id".to_string())
    })?;
    parsed.credential_public_key_cose.as_ref().ok_or_else(|| {
        AppError::bad_request("Missing WebAuthn credential key".to_string())
    })?;
    Ok(parsed)
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
    let sign_count =
        u32::from_be_bytes([data[33], data[34], data[35], data[36]]);

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
        let credential_id_length =
            u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        if data.len() < offset + credential_id_length {
            return Err(AppError::bad_request(
                "Invalid WebAuthn credential id".to_string(),
            ));
        }
        credential_id =
            Some(data[offset..offset + credential_id_length].to_vec());
        offset += credential_id_length;

        let mut cursor = Cursor::new(&data[offset..]);
        let _parsed_key: CborValue = ciborium::de::from_reader(&mut cursor)
            .map_err(|_error| {
                AppError::bad_request(
                    "Invalid WebAuthn credential key".to_string(),
                )
            })?;
        let consumed_bytes = cursor.position() as usize;
        if consumed_bytes == 0 || offset + consumed_bytes > data.len() {
            return Err(AppError::bad_request(
                "Invalid WebAuthn credential key".to_string(),
            ));
        }
        credential_public_key_cose =
            Some(data[offset..offset + consumed_bytes].to_vec());
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
    pub fn verify(
        &self,
        signed_data: &[u8],
        signature: &[u8],
    ) -> AppResult<()> {
        match self {
            Self::P256(verifying_key) => {
                let signature =
                    P256Signature::from_der(signature).map_err(|_error| {
                        AppError::invalid_credentials(
                            "Invalid signature format",
                        )
                    })?;
                verifying_key.verify(signed_data, &signature).map_err(
                    |_error| {
                        AppError::invalid_credentials(
                            "Signature verification failed",
                        )
                    },
                )
            }
            Self::Rsa(rsa_key) => {
                // RS256: RSASSA-PKCS1-v1_5 with SHA-256
                let verifying_key =
                    RsaVerifyingKey::<Sha256>::new(rsa_key.clone());
                let signature =
                    RsaSignature::try_from(signature).map_err(|_error| {
                        AppError::invalid_credentials(
                            "Invalid signature format",
                        )
                    })?;
                verifying_key.verify(signed_data, &signature).map_err(
                    |_error| {
                        AppError::invalid_credentials(
                            "Signature verification failed",
                        )
                    },
                )
            }
        }
    }
}

pub fn parse_webauthn_public_key(
    cose_key_bytes: &[u8],
) -> AppResult<(WebauthnVerifyingKey, i64)> {
    let value: CborValue = ciborium::de::from_reader(Cursor::new(
        cose_key_bytes,
    ))
    .map_err(|_error| {
        AppError::bad_request("Invalid WebAuthn public key".to_string())
    })?;
    let map = value.as_map().ok_or_else(|| {
        AppError::bad_request("Invalid WebAuthn public key".to_string())
    })?;

    let key_type = cbor_integer_value(map, 1).ok_or_else(|| {
        AppError::bad_request("Invalid WebAuthn public key".to_string())
    })?;
    let algorithm = cbor_integer_value(map, 3).ok_or_else(|| {
        AppError::bad_request("Invalid WebAuthn public key".to_string())
    })?;

    match (key_type, algorithm) {
        // EC2 key type (kty=2) with ES256 (alg=-7)
        (2, -7) => {
            let curve = cbor_integer_value(map, -1).ok_or_else(|| {
                AppError::bad_request("Invalid WebAuthn public key".to_string())
            })?;
            if curve != 1 {
                return Err(AppError::bad_request(
                    "Unsupported WebAuthn curve".to_string(),
                ));
            }

            let x = cbor_bytes_value(map, -2).ok_or_else(|| {
                AppError::bad_request("Invalid WebAuthn public key".to_string())
            })?;
            let y = cbor_bytes_value(map, -3).ok_or_else(|| {
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

            let verifying_key = P256VerifyingKey::from_sec1_bytes(&encoded)
                .map_err(|_error| {
                    AppError::bad_request(
                        "Invalid WebAuthn public key".to_string(),
                    )
                })?;
            Ok((WebauthnVerifyingKey::P256(verifying_key), algorithm as i64))
        }
        // RSA key type (kty=3) with RS256 (alg=-257)
        (3, -257) => {
            // RSA public key: n (-1) and e (-2)
            let modulus = cbor_bytes_value(map, -1).ok_or_else(|| {
                AppError::bad_request("Invalid RSA public key".to_string())
            })?;
            let exponent = cbor_bytes_value(map, -2).ok_or_else(|| {
                AppError::bad_request("Invalid RSA public key".to_string())
            })?;

            if !(256..=1024).contains(&modulus.len()) ||
                exponent.is_empty() ||
                exponent.len() > 4
            {
                return Err(AppError::invalid_credentials(
                    "Invalid RSA key size",
                ));
            }
            // COSE key components are public, so their input-dependent
            // precision does not expose secret material.
            let modulus_integer = BoxedUint::from_be_slice_vartime(modulus);
            let exponent_integer = BoxedUint::from_be_slice_vartime(exponent);

            let rsa_key = RsaPublicKey::new(modulus_integer, exponent_integer)
                .map_err(|_error| {
                    AppError::bad_request("Invalid RSA public key".to_string())
                })?;
            Ok((WebauthnVerifyingKey::Rsa(rsa_key), algorithm as i64))
        }
        _ => Err(AppError::bad_request(format!(
            "Unsupported WebAuthn public key type: kty={key_type}, \
             alg={algorithm}"
        ))),
    }
}

fn cbor_text_value<'a>(
    map: &'a [(CborValue, CborValue)],
    key: &str,
) -> Option<&'a CborValue> {
    map.iter().find_map(|(k, value)| match k {
        CborValue::Text(t) if t == key => Some(value),
        _ => None,
    })
}

fn cbor_integer_value(
    map: &[(CborValue, CborValue)],
    key: i128,
) -> Option<i128> {
    map.iter().find_map(|(k, value)| match (k, value) {
        (CborValue::Integer(ki), CborValue::Integer(vi))
            if i128::from(*ki) == key =>
        {
            Some(i128::from(*vi))
        }
        _ => None,
    })
}

fn cbor_bytes_value(
    map: &[(CborValue, CborValue)],
    key: i128,
) -> Option<&[u8]> {
    map.iter().find_map(|(k, value)| match (k, value) {
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
        let key = SigningKey::from_slice(&[1u8; 32])
            .expect("test fixture should be valid");
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
                CborValue::Bytes(
                    public.x().expect("test fixture should be valid").to_vec(),
                ),
            ),
            (
                CborValue::Integer((-3).into()),
                CborValue::Bytes(
                    public.y().expect("test fixture should be valid").to_vec(),
                ),
            ),
        ]);
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&cose, &mut encoded)
            .expect("test fixture should be valid");
        let verifying = parse_webauthn_public_key(&encoded)
            .expect("test fixture should be valid")
            .0;
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
            "../../../../tests/fixtures/webauthn-rs256-test-key.pem"
        ))
        .expect("test fixture should be valid");
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
        ciborium::ser::into_writer(&cose, &mut encoded)
            .expect("test fixture should be valid");
        let (public, algorithm) = parse_webauthn_public_key(&encoded)
            .expect("test fixture should be valid");
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
        let relying_party_id = "vault.example";
        let mut data = Sha256::digest(relying_party_id.as_bytes()).to_vec();
        data.push(5);
        data.extend_from_slice(&0u32.to_be_bytes());
        let parsed = parse_authenticator_data(&data, false)
            .expect("test fixture should be valid");
        assert!(
            verify_authenticator_data(&parsed, relying_party_id, true).is_ok()
        );
        assert!(
            verify_authenticator_data(&parsed, "evil.example", true).is_err()
        );
        data[32] = 1;
        assert!(
            verify_authenticator_data(
                &parse_authenticator_data(&data, false)
                    .expect("test fixture should be valid"),
                relying_party_id,
                true
            )
            .is_err()
        );
        let good = ClientData::parse(
            br#"{"type":"webauthn.get","origin":"https://vault.example","challenge":"Y2hhbGxlbmdl"}"#.to_vec(),
        ).expect("test fixture should be valid");
        assert!(
            good.verify(
                "webauthn.get",
                "Y2hhbGxlbmdl",
                "https://vault.example",
                ""
            )
            .is_ok()
        );
        assert!(
            good.verify(
                "webauthn.create",
                "Y2hhbGxlbmdl",
                "https://vault.example",
                ""
            )
            .is_err()
        );
        assert!(
            good.verify(
                "webauthn.get",
                "Y2hhbGxlbmdl",
                "https://evil.example",
                ""
            )
            .is_err()
        );
        let cross = ClientData::parse(
            br#"{"type":"webauthn.get","origin":"https://vault.example","challenge":"Y2hhbGxlbmdl","crossOrigin":true}"#.to_vec(),
        ).expect("test fixture should be valid");
        assert!(
            cross
                .verify(
                    "webauthn.get",
                    "Y2hhbGxlbmdl",
                    "https://vault.example",
                    ""
                )
                .is_err()
        );
        assert!(relying_party("http://vault.example").is_err());
        assert_eq!(
            relying_party("https://vault.example:443/")
                .expect("test fixture should be valid"),
            ("vault.example".into(), "https://vault.example".into())
        );
    }
    #[test]
    fn native_origins_require_exact_explicit_configuration() {
        let android = ClientData::parse(
            br#"{"type":"webauthn.get","origin":"android:apk-key-hash:trusted-app","challenge":"YWJj"}"#.to_vec(),
        ).expect("test fixture should be valid");
        let extension = ClientData::parse(
            br#"{"type":"webauthn.get","origin":"chrome-extension://trusted-id","challenge":"YWJj"}"#.to_vec(),
        ).expect("test fixture should be valid");
        for (data, extra_origins, accepts) in [
            (&android, "", false),
            (&android, " , android:apk-key-hash:trusted-app ", true),
            (&android, "android:apk-key-hash:*", false),
            (&android, "android:apk-key-hash:other-app", false),
            (&extension, "chrome-extension://trusted-id", true),
            (&extension, "chrome-extension://*", false),
        ] {
            assert_eq!(
                data.verify(
                    "webauthn.get",
                    "YWJj",
                    "https://vault.example",
                    extra_origins
                )
                .is_ok(),
                accepts,
                "allowed origins: {extra_origins}"
            );
        }
    }

    #[test]
    fn attestation_retains_original_verification_flags_and_credential_material()
    {
        for flags in [0x41, 0x45] {
            let mut auth = Sha256::digest(b"vault.example").to_vec();
            auth.push(flags);
            auth.extend_from_slice(&9_u32.to_be_bytes());
            auth.extend_from_slice(&[0; 16]); // AAGUID
            auth.extend_from_slice(&3_u16.to_be_bytes());
            auth.extend_from_slice(&[1, 2, 3]); // Credential ID
            auth.push(0xa0); // Structurally valid COSE map; key checks are separate.
            let attestation = CborValue::Map(vec![(
                CborValue::Text("authData".into()),
                CborValue::Bytes(auth),
            )]);
            let mut encoded = Vec::new();
            ciborium::ser::into_writer(&attestation, &mut encoded)
                .expect("valid attestation fixture");
            let parsed = parse_attestation_object(&encoded)
                .expect("valid attestation fixture");
            assert_eq!(parsed.flags, flags);
            assert_eq!(parsed.sign_count, 9);
            assert_eq!(
                parsed.credential_id.as_deref(),
                Some([1, 2, 3].as_slice())
            );
            assert_eq!(
                parsed.credential_public_key_cose.as_deref(),
                Some([0xa0].as_slice())
            );
            assert!(
                verify_authenticator_data(&parsed, "vault.example", false)
                    .is_ok()
            );
            assert_eq!(
                verify_authenticator_data(&parsed, "vault.example", true)
                    .is_ok(),
                flags & 4 != 0
            );
        }
    }

    #[test]
    fn malformed_attestations_and_unsupported_keys_fail() {
        assert!(parse_authenticator_data(&[0; 36], false).is_err());
        assert!(parse_attestation_object(&[0xff]).is_err());
        assert!(parse_webauthn_public_key(&[0xa0]).is_err());
    }
}
