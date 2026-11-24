use email_address::{EmailAddress, Options};
use hmac::{Hmac, KeyInit, Mac};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::Sha256;
use uuid::Uuid;
use worker::{D1Database, Env};

use crate::{
    errors::{AppError, AppResult, AuthError},
    infra::config::{env_bool, env_text},
    models::identity::{
        authorization::VerifiedAccountAction,
        device::SessionSnapshot,
        email::{self as email_model, CodeCheck, VerificationCode, VerifiedCode},
        two_factor::TwoFactorRow,
        user::UserRow,
    },
    service::{
        identity::{
            session::Claims, two_factor::TwoFactorProvider, user::AccountVerificationRequest,
        },
        notifications::{admin as admin_notify, admin::Event, post_json},
        rate_limit,
    },
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmailPurpose {
    ProtectedAction,
    Login,
    Setup,
    VerifyEmail,
    ChangeEmail,
    Registration,
    DeleteRecover,
    PasswordHint,
}

impl EmailPurpose {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProtectedAction => "protected-action",
            Self::Login => "email-login",
            Self::Setup => "email-setup",
            Self::VerifyEmail => "verify-email",
            Self::ChangeEmail => "change-email",
            Self::Registration => "registration",
            Self::DeleteRecover => "delete-recover",
            Self::PasswordHint => "password-hint",
        }
    }
}

pub(crate) fn mail_configured(env: &Env) -> bool {
    env_text(env, "MAIL_WEBHOOK_URL").is_some()
}

/// Send a verification message only to its recipient.
async fn deliver_mail(
    env: &Env,
    to: &str,
    purpose: &str,
    subject: &str,
    text: &str,
) -> AppResult<()> {
    let endpoint = env_text(env, "MAIL_WEBHOOK_URL")
        .ok_or_else(|| AppError::bad_request("Email delivery is not configured"))?;
    let token = env_text(env, "MAIL_WEBHOOK_TOKEN");
    post_json(
        &endpoint,
        json!({"to":to,"purpose":purpose,"subject":subject,"text":text}),
        token.as_deref(),
    )
    .await
}

/// Preserve the canonical value used by stored recipients and verification
/// codes.
pub fn normalize_email(email: &str) -> AppResult<String> {
    let email = email.trim().to_lowercase();
    let Some((local, domain)) = email.rsplit_once('@') else {
        return Err(AppError::bad_request("Invalid email address"));
    };
    if local.is_empty()
        || domain.is_empty()
        || email.len() > 320
        || email.chars().any(char::is_whitespace)
        || email.chars().any(char::is_control)
    {
        return Err(AppError::bad_request("Invalid email address"));
    }
    Ok(email)
}

pub(crate) fn normalize_new_recipient(email: &str) -> AppResult<String> {
    let email = normalize_email(email)?;
    let options = Options::default().without_display_text();
    if EmailAddress::parse_with_options(&email, options).is_err() {
        return Err(AppError::bad_request("Invalid email address"));
    }
    Ok(email)
}

pub fn mask_email(email: &str) -> String {
    let Some((name, domain)) = email.rsplit_once('@') else {
        return "***".into();
    };
    format!("{}***@{domain}", name.chars().next().unwrap_or('*'))
}

pub fn code_hash(
    secret: &str,
    owner: &str,
    purpose: EmailPurpose,
    recipient: &str,
    context: &str,
    code: &str,
) -> AppResult<String> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).map_err(AppError::internal_error)?;
    for part in [owner, purpose.as_str(), recipient, context, code] {
        mac.update(&(part.len() as u64).to_be_bytes());
        mac.update(part.as_bytes());
    }
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn generate_code(format: OtpFormat) -> AppResult<String> {
    if format == OtpFormat::LongToken {
        return Ok(format!(
            "{}{}",
            Uuid::new_v4().simple(),
            Uuid::new_v4().simple()
        ));
    }
    loop {
        let mut bytes = [0; 4];
        getrandom::fill(&mut bytes).map_err(AppError::internal_error)?;
        let number = u32::from_be_bytes(bytes);
        if number < u32::MAX - (u32::MAX % 1_000_000) {
            return Ok(format!("{:06}", number % 1_000_000));
        }
    }
}

fn query_value(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
}

pub(crate) struct VerificationTarget<'a> {
    pub user: Option<&'a UserRow>,
    pub purpose: EmailPurpose,
    pub recipient: &'a str,
    pub context: &'a str,
    pub session: &'a str,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum OtpFormat {
    SixDigit,
    LongToken,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReservationMode {
    ReuseActive,
    Fresh,
}

#[derive(Clone, Copy)]
pub(crate) struct IssuePolicy {
    pub format: OtpFormat,
    pub reservation: ReservationMode,
}

pub(crate) struct EmailVerifier<'a> {
    pub db: &'a D1Database,
    pub env: &'a Env,
    pub domain: &'a str,
    pub access_secret: &'a str,
}

impl EmailVerifier<'_> {
    /// Reserve first, deliver synchronously, then enable the code. Failed delivery
    /// cannot leave an active code behind or report a successful send.
    pub(crate) async fn issue_code(
        &self,
        target: VerificationTarget<'_>,
        policy: IssuePolicy,
    ) -> AppResult<()> {
        let Self {
            db,
            env,
            domain,
            access_secret,
        } = *self;
        let VerificationTarget {
            user,
            purpose,
            recipient,
            context,
            session,
        } = target;
        if !mail_configured(env) {
            return Err(AppError::bad_request("Email delivery is not configured"));
        }
        let recipient = normalize_email(recipient)?;
        let owner = user.map_or(recipient.as_str(), |user| user.id.as_str());
        let stamp = user.map_or("", |user| user.security_stamp.as_str());
        let id = Uuid::new_v4().to_string();
        let raw = generate_code(policy.format)?;
        let hash = code_hash(access_secret, owner, purpose, &recipient, context, &raw)?;
        let purpose_str = purpose.as_str();
        let code = VerificationCode {
            id: &id,
            owner,
            user_id: user.map(|user| user.id.as_str()),
            purpose: purpose_str,
            recipient: &recipient,
            context,
            hash: &hash,
            stamp,
            session,
        };
        let Some(mail) = ReservedMail::reserve(db, code).await? else {
            if policy.reservation == ReservationMode::ReuseActive
                && email_model::can_reuse(db, &code, crate::utils::time::now_seconds()).await?
            {
                return Ok(());
            }
            return Err(AppError::TooManyRequests {
                message: "Wait 60 seconds before requesting another code".into(),
            });
        };
        let link = match purpose {
            EmailPurpose::Registration => Some(format!(
                "{}/#/finish-signup?email={}&emailVerificationToken={}",
                domain,
                query_value(&recipient),
                query_value(&raw)
            )),
            EmailPurpose::VerifyEmail => user.map(|user| {
                format!(
                    "{}/#/verify-email?userId={}&token={}",
                    domain,
                    query_value(&user.id),
                    query_value(&raw)
                )
            }),
            EmailPurpose::DeleteRecover => user.map(|user| {
                format!(
                    "{}/#/delete-account?userId={}&token={}",
                    domain,
                    query_value(&user.id),
                    query_value(&raw)
                )
            }),
            _ => None,
        };
        let text = format!(
            "Your raywarden {purpose_str} verification code is:\n\n{raw}\n\nIt \
         expires in 10 minutes.\nAccount: {recipient}\nContext: {context}{}",
            link.map_or(String::new(), |url| format!("\n\nContinue: {url}"))
        );
        mail.deliver(env, "raywarden verification", &text).await
    }

    pub(crate) async fn issue_login_code(&self, user: &UserRow) -> AppResult<()> {
        let email = email_provider(self.db, &user.id).await?.ok_or_else(|| {
            AppError::bad_request("Email two-factor authentication is not enabled")
        })?;
        self.issue_code(
            VerificationTarget {
                user: Some(user),
                purpose: EmailPurpose::Login,
                recipient: &email,
                context: "",
                session: "",
            },
            IssuePolicy {
                format: OtpFormat::SixDigit,
                reservation: ReservationMode::ReuseActive,
            },
        )
        .await
    }

    pub(crate) async fn verify_password_or_otp(
        &self,
        claims: &Claims,
        payload: &AccountVerificationRequest,
    ) -> AppResult<()> {
        verify_password_or_otp(self.db, self.env, self.access_secret, claims, payload).await
    }

    pub(crate) async fn prepare_password_or_otp(
        &self,
        claims: &Claims,
        payload: &AccountVerificationRequest,
    ) -> AppResult<Option<VerifiedCode>> {
        prepare_password_or_otp(self.db, self.env, self.access_secret, claims, payload).await
    }

    pub(crate) async fn prepare_account_action<'a>(
        &self,
        claims: &'a Claims,
        payload: &AccountVerificationRequest,
    ) -> AppResult<VerifiedAccountAction<'a>> {
        let (user, proof) = check_password_or_otp(
            self.db,
            self.env,
            self.access_secret,
            claims,
            payload,
            CodeCheck::PreserveOnSuccess,
        )
        .await?;
        VerifiedAccountAction::new(claims.session_snapshot()?, user, proof)
    }
}

pub(crate) async fn verify_code(
    db: &D1Database,
    access_secret: &str,
    target: VerificationTarget<'_>,
    raw: &str,
    consume: bool,
) -> AppResult<()> {
    let mode = if consume {
        CodeCheck::Consume
    } else {
        CodeCheck::CountAttempt
    };
    check_code(db, access_secret, target, raw, mode)
        .await
        .map(|_| ())
}

pub(crate) async fn prepare_code(
    db: &D1Database,
    access_secret: &str,
    target: VerificationTarget<'_>,
    raw: &str,
) -> AppResult<VerifiedCode> {
    check_code(db, access_secret, target, raw, CodeCheck::PreserveOnSuccess).await
}

async fn check_code(
    db: &D1Database,
    access_secret: &str,
    target: VerificationTarget<'_>,
    raw: &str,
    mode: CodeCheck,
) -> AppResult<VerifiedCode> {
    let VerificationTarget {
        user,
        purpose,
        recipient,
        context,
        session,
    } = target;
    if raw.is_empty() || raw.len() > 1024 {
        return Err(AppError::bad_request("Invalid verification code"));
    }
    let recipient = normalize_email(recipient)?;
    let owner = user.map_or(recipient.as_str(), |user| user.id.as_str());
    let hash = code_hash(
        access_secret,
        owner,
        purpose,
        &recipient,
        context,
        raw.trim(),
    )?;
    let code = VerificationCode {
        id: "",
        owner,
        user_id: user.map(|user| user.id.as_str()),
        purpose: purpose.as_str(),
        recipient: &recipient,
        context,
        hash: &hash,
        stamp: user.map_or("", |user| user.security_stamp.as_str()),
        session,
    };
    email_model::check(db, &code, crate::utils::time::now_seconds(), mode).await
}

pub async fn fetch_user(db: &D1Database, claims: &Claims) -> AppResult<UserRow> {
    UserRow::fetch_by_id_with(
        db,
        &claims.sub,
        "Failed to fetch verification owner",
        || AuthError::UserNotFound.into(),
    )
    .await
}

pub async fn verify_password_or_otp(
    db: &D1Database,
    env: &Env,
    access_secret: &str,
    claims: &Claims,
    payload: &AccountVerificationRequest,
) -> AppResult<()> {
    check_password_or_otp(db, env, access_secret, claims, payload, CodeCheck::Consume)
        .await
        .map(|_| ())
}

pub(crate) async fn prepare_password_or_otp(
    db: &D1Database,
    env: &Env,
    access_secret: &str,
    claims: &Claims,
    payload: &AccountVerificationRequest,
) -> AppResult<Option<VerifiedCode>> {
    check_password_or_otp(
        db,
        env,
        access_secret,
        claims,
        payload,
        CodeCheck::PreserveOnSuccess,
    )
    .await
    .map(|(_, proof)| proof)
}

async fn check_password_or_otp(
    db: &D1Database,
    env: &Env,
    access_secret: &str,
    claims: &Claims,
    payload: &AccountVerificationRequest,
    mode: CodeCheck,
) -> AppResult<(UserRow, Option<VerifiedCode>)> {
    let user = fetch_user(db, claims).await?;
    rate_limit::check_auth_attempt(env, format!("protected-action:{}", claims.sub)).await?;
    if let Some(hash) = payload.master_password_hash.as_deref() {
        if crate::service::identity::user::verify_master_password(&user, hash)
            .await?
            .is_valid()
        {
            return Ok((user, None));
        }
        return Err(AuthError::InvalidPassword.into());
    }
    if payload.user_verification_token.is_some() {
        return Err(AppError::bad_request(
            "Verification proof cannot be used for this action",
        ));
    }
    let otp = payload
        .otp
        .as_deref()
        .ok_or_else(|| AppError::bad_request("Password or verification code is required"))?;
    let proof = check_code(
        db,
        access_secret,
        VerificationTarget {
            user: Some(&user),
            purpose: EmailPurpose::ProtectedAction,
            recipient: &user.email,
            context: "",
            session: &claims.session_token,
        },
        otp,
        mode,
    )
    .await?;
    Ok((user, Some(proof)))
}

pub async fn email_provider(db: &D1Database, user_id: &str) -> AppResult<Option<String>> {
    #[derive(Deserialize)]
    struct EmailProviderData {
        email: Option<String>,
    }

    let provider =
        TwoFactorRow::find_provider(db, user_id, i32::from(TwoFactorProvider::Email)).await?;
    let Some(provider) = provider.filter(|provider| provider.is_enabled) else {
        return Ok(None);
    };
    let data: EmailProviderData =
        serde_json::from_str(&provider.data).map_err(AppError::internal_error)?;
    Ok(data.email)
}

pub async fn login_metadata(db: &D1Database, user_id: &str) -> AppResult<Value> {
    Ok(email_provider(db, user_id)
        .await?
        .map_or(Value::Null, |email| json!({"Email":mask_email(&email)})))
}

pub(crate) async fn prepare_login_code(
    db: &D1Database,
    access_secret: &str,
    user: &UserRow,
    code: &str,
) -> AppResult<VerifiedCode> {
    let email = email_provider(db, &user.id)
        .await?
        .ok_or_else(|| AppError::bad_request("Email two-factor authentication is not enabled"))?;
    check_code(
        db,
        access_secret,
        VerificationTarget {
            user: Some(user),
            purpose: EmailPurpose::Login,
            recipient: &email,
            context: "",
            session: "",
        },
        code,
        CodeCheck::PreserveOnSuccess,
    )
    .await
}

pub fn registration_verification_required(env: &Env) -> bool {
    env_bool(env, "REQUIRE_EMAIL_VERIFICATION", false)
}

pub(crate) async fn registration_proof(
    db: &D1Database,
    env: &Env,
    access_secret: &str,
    email: &str,
    token: Option<&str>,
) -> AppResult<Option<VerifiedCode>> {
    let required = registration_verification_required(env);
    if !required {
        return Ok(None);
    }
    prepare_code(
        db,
        access_secret,
        VerificationTarget {
            user: None,
            purpose: EmailPurpose::Registration,
            recipient: email,
            context: "",
            session: "",
        },
        token.ok_or_else(|| AppError::bad_request("Email verification is required"))?,
    )
    .await
    .map(Some)
}

pub(crate) async fn set_email_provider(
    db: &D1Database,
    env: &Env,
    session: &SessionSnapshot<'_>,
    email: &str,
    verification: &VerifiedCode,
    authorization: Option<&VerifiedCode>,
) -> AppResult<()> {
    email_model::enable_provider(
        db,
        session,
        email,
        &Uuid::new_v4().simple().to_string(),
        verification,
        authorization,
    )
    .await?;
    admin_notify::emit(env, Event::TwoFactorEnable, session.user_id).await;
    Ok(())
}

pub async fn send_password_hint(
    db: &D1Database,
    env: &Env,
    access_secret: &str,
    user: &UserRow,
) -> AppResult<()> {
    let id = Uuid::new_v4().to_string();
    let hash = code_hash(
        access_secret,
        &user.id,
        EmailPurpose::PasswordHint,
        &user.email,
        "",
        &id,
    )?;
    let marker = VerificationCode {
        id: &id,
        owner: &user.id,
        user_id: Some(&user.id),
        purpose: EmailPurpose::PasswordHint.as_str(),
        recipient: &user.email,
        context: "",
        hash: &hash,
        stamp: &user.security_stamp,
        session: "",
    };
    let Some(mail) = ReservedMail::reserve(db, marker).await? else {
        return Ok(());
    };
    let text = user
        .master_password_hint
        .as_deref()
        .filter(|hint| !hint.trim().is_empty())
        .unwrap_or(
            "No master password hint was set. Your encrypted vault cannot be \
             recovered without an unlock method.",
        );
    mail.deliver(env, "raywarden password hint", text).await?;
    admin_notify::emit(env, Event::PasswordHint, &user.id).await;
    Ok(())
}

pub async fn rate_unauthenticated(env: &Env, ip: &str, purpose: &str) -> AppResult<()> {
    rate_limit::check_auth_attempt(env, format!("{purpose}:{ip}")).await
}

const CODE_TTL_SECONDS: i64 = 600;
const CODE_COOLDOWN_SECONDS: i64 = 60;

struct ReservedMail<'a> {
    db: &'a D1Database,
    code: VerificationCode<'a>,
}

impl<'a> ReservedMail<'a> {
    async fn reserve(db: &'a D1Database, code: VerificationCode<'a>) -> AppResult<Option<Self>> {
        let now = crate::utils::time::now_seconds();
        let reserved = email_model::reserve_until(
            db,
            &code,
            now,
            now + CODE_TTL_SECONDS,
            now - CODE_COOLDOWN_SECONDS,
        )
        .await?;
        Ok(reserved.then_some(Self { db, code }))
    }

    async fn deliver(self, env: &Env, subject: &str, text: &str) -> AppResult<()> {
        let db = self.db;
        if deliver_mail(env, self.code.recipient, self.code.purpose, subject, text)
            .await
            .is_err()
        {
            log::warn!("Email webhook delivery failed for {}", self.code.purpose);
            email_model::cancel(db, self.code.id).await?;
            return Err(AppError::ServiceUnavailable);
        }
        email_model::mark_ready(db, self.code.id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn code_hash_is_bound_to_recipient_purpose_and_context() {
        let hash = code_hash(
            "secret",
            "owner",
            EmailPurpose::Login,
            "a@example.com",
            "",
            "123456",
        )
        .expect("valid email fixture");
        assert_ne!(
            hash,
            code_hash(
                "secret",
                "owner",
                EmailPurpose::Setup,
                "a@example.com",
                "",
                "123456"
            )
            .expect("valid email fixture")
        );
        assert_ne!(
            hash,
            code_hash(
                "secret",
                "owner",
                EmailPurpose::Login,
                "b@example.com",
                "",
                "123456"
            )
            .expect("valid email fixture")
        );
        assert_ne!(
            hash,
            code_hash(
                "secret",
                "owner",
                EmailPurpose::Login,
                "a@example.com",
                "device",
                "123456"
            )
            .expect("valid email fixture")
        );
        assert!(!hash.contains("123456"));
    }
    #[test]
    fn email_validation_and_masking() {
        assert_eq!(
            normalize_email(" User@Example.com ").expect("valid email fixture"),
            "user@example.com"
        );
        assert!(normalize_email("x\n@example.com").is_err());
        assert_eq!(mask_email("alice@example.com"), "a***@example.com");
    }

    #[test]
    fn new_recipients_require_mailbox_syntax() {
        assert_eq!(
            normalize_new_recipient(" User+otp@Example.com ").expect("valid email fixture"),
            "user+otp@example.com"
        );
        assert!(normalize_new_recipient("a@@example.com").is_err());
        assert!(normalize_email("a@@example.com").is_ok());
    }
}
