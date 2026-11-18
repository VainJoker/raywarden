//! Email-factor action proofs shared by factor-management HTTP endpoints.
use serde::{
    Deserialize,
    Serialize,
};
use sha2::{
    Digest,
    Sha256,
};

use crate::{
    api::{
        AppState,
        service::{
            claims::Claims,
            email,
        },
    },
    errors::{
        AppResult,
        AuthError,
    },
    infra::jwt,
    models::user::PasswordOrOtpData,
};

#[derive(Serialize, Deserialize)]
struct FactorProof {
    sub:           String,
    sstamp:        String,
    session_token: String,
    purpose:       String,
    email_state:   String,
    exp:           i64,
    nbf:           i64,
    iat:           i64,
}

fn factor_state(address: Option<&str>) -> String {
    hex::encode(Sha256::digest(address.unwrap_or("disabled").as_bytes()))
}

pub fn mint_email_factor_proof(
    state: &AppState,
    claims: &Claims,
    address: Option<&str>,
) -> AppResult<String> {
    let now = crate::infra::time::now_seconds();
    let proof = FactorProof {
        sub:           claims.sub.clone(),
        sstamp:        claims.sstamp.clone(),
        session_token: claims.session_token.clone(),
        purpose:       "email-factor".into(),
        email_state:   factor_state(address),
        exp:           now + 300,
        nbf:           now,
        iat:           now,
    };
    Ok(jwt::encode(&proof, state.config.jwt_secret.as_bytes())?)
}

pub async fn verify_email_factor_action(
    state: &AppState,
    claims: &Claims,
    payload: &PasswordOrOtpData,
) -> AppResult<()> {
    if let Some(token) = payload.user_verification_token.as_deref() {
        let proof = jwt::decode::<FactorProof>(
            token,
            state.config.jwt_secret.as_bytes(),
            &jwt::ValidationOptions {
                leeway: 0,
                ..Default::default()
            },
        )?
        .claims;
        let current_email =
            email::email_provider(&state.get_db(), &claims.sub).await?;
        if proof.sub != claims.sub ||
            proof.sstamp != claims.sstamp ||
            proof.session_token != claims.session_token ||
            proof.purpose != "email-factor" ||
            proof.email_state != factor_state(current_email.as_deref())
        {
            return Err(AuthError::InvalidCredentials(
                "Invalid email verification proof".into(),
            )
            .into());
        }
        return Ok(());
    }
    email::verify_password_or_otp(state, claims, payload).await
}
