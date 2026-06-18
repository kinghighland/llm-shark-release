use base64::{Engine as _, engine::general_purpose};
use chrono::{DateTime, Utc};
use rsa::RsaPublicKey;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs8::DecodePublicKey;
use rsa::pss::{Signature as RsaSignature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use signature::Verifier;
use std::collections::HashSet;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PlanTier {
    Free,
    Monthly,
    Yearly,
}

impl Display for PlanTier {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            PlanTier::Free => write!(f, "free"),
            PlanTier::Monthly => write!(f, "monthly"),
            PlanTier::Yearly => write!(f, "yearly"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LicensePayload {
    pub license_id: String,
    pub plan_tier: PlanTier,
    pub topn_limit: i32,
    pub qr_issued_at: String,
    pub qr_expires_at: String,
    pub license_issued_at: String,
    pub license_expire_at: String,
    pub daily_analysis_limit: i32,
    pub nonce: String,
    pub signature: String,
}

#[derive(Debug, Clone)]
pub struct VerifyInput {
    pub payload_json: String,
    pub public_key_pem: String,
    pub now_utc: DateTime<Utc>,
    pub used_today: i32,
    pub seen_nonces: HashSet<String>,
    pub last_trusted_timestamp: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedLicense {
    pub license_id: String,
    pub plan_tier: PlanTier,
    pub topn_limit: i32,
    pub daily_analysis_limit: i32,
    pub nonce: String,
    pub qr_expires_at: String,
    pub license_expire_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifyErrorCode {
    InvalidPayload,
    InvalidPublicKey,
    InvalidSignature,
    InvalidTimestamp,
    InvalidPlanTier,
    InvalidTopnLimit,
    InvalidDailyLimit,
    QrExpired,
    LicenseExpired,
    NonceReplay,
    ClockRollback,
    DailyLimitExceeded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyError {
    pub code: VerifyErrorCode,
    pub message: String,
}

impl VerifyError {
    fn new(code: VerifyErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

pub fn verify_license_payload(input: VerifyInput) -> Result<VerifiedLicense, VerifyError> {
    let payload: LicensePayload = serde_json::from_str(&input.payload_json).map_err(|err| {
        VerifyError::new(
            VerifyErrorCode::InvalidPayload,
            format!("invalid payload json: {err}"),
        )
    })?;

    validate_business_fields(&payload)?;
    validate_clock_rollback(input.now_utc, input.last_trusted_timestamp)?;
    validate_signature(&payload, &input.public_key_pem)?;
    validate_time_window(&payload, input.now_utc)?;
    validate_replay(&payload, &input.seen_nonces)?;
    validate_daily_limit(&payload, input.used_today)?;

    Ok(VerifiedLicense {
        license_id: payload.license_id,
        plan_tier: payload.plan_tier,
        topn_limit: payload.topn_limit,
        daily_analysis_limit: payload.daily_analysis_limit,
        nonce: payload.nonce,
        qr_expires_at: payload.qr_expires_at,
        license_expire_at: payload.license_expire_at,
    })
}

fn validate_business_fields(payload: &LicensePayload) -> Result<(), VerifyError> {
    if payload.license_id.trim().is_empty() {
        return Err(VerifyError::new(
            VerifyErrorCode::InvalidPayload,
            "license_id is empty",
        ));
    }

    let expected_topn = match payload.plan_tier {
        PlanTier::Free => 2,
        PlanTier::Monthly => 5,
        PlanTier::Yearly => 10,
    };

    if payload.topn_limit != expected_topn {
        return Err(VerifyError::new(
            VerifyErrorCode::InvalidTopnLimit,
            format!(
                "topn_limit({}) does not match plan_tier({})",
                payload.topn_limit, payload.plan_tier
            ),
        ));
    }

    if !matches!(payload.daily_analysis_limit, 3 | 10 | -1) {
        return Err(VerifyError::new(
            VerifyErrorCode::InvalidDailyLimit,
            "daily_analysis_limit must be one of 3, 10, -1",
        ));
    }

    if payload.nonce.trim().is_empty() {
        return Err(VerifyError::new(
            VerifyErrorCode::InvalidPayload,
            "nonce is empty",
        ));
    }

    Ok(())
}

fn validate_clock_rollback(
    now_utc: DateTime<Utc>,
    last_trusted_timestamp: Option<DateTime<Utc>>,
) -> Result<(), VerifyError> {
    if let Some(last) = last_trusted_timestamp
        && now_utc < last
    {
        return Err(VerifyError::new(
            VerifyErrorCode::ClockRollback,
            "local clock rollback detected",
        ));
    }
    Ok(())
}

fn validate_signature(payload: &LicensePayload, public_key_pem: &str) -> Result<(), VerifyError> {
    let verifying_key = VerifyingKey::<Sha256>::new(parse_public_key(public_key_pem)?);
    let sig = general_purpose::STANDARD
        .decode(payload.signature.as_bytes())
        .map_err(|err| {
            VerifyError::new(
                VerifyErrorCode::InvalidSignature,
                format!("invalid signature base64: {err}"),
            )
        })?;
    let signature = RsaSignature::try_from(sig.as_slice()).map_err(|err| {
        VerifyError::new(
            VerifyErrorCode::InvalidSignature,
            format!("invalid RSA signature: {err}"),
        )
    })?;

    let canonical = canonical_signing_message(payload);
    verifying_key
        .verify(canonical.as_bytes(), &signature)
        .map_err(|err| {
            VerifyError::new(
                VerifyErrorCode::InvalidSignature,
                format!("signature verify failed: {err}"),
            )
        })?;
    Ok(())
}

fn validate_time_window(
    payload: &LicensePayload,
    now_utc: DateTime<Utc>,
) -> Result<(), VerifyError> {
    let qr_expires_at = parse_utc(&payload.qr_expires_at, "qr_expires_at")?;
    let license_expire_at = parse_utc(&payload.license_expire_at, "license_expire_at")?;
    if now_utc > qr_expires_at {
        return Err(VerifyError::new(
            VerifyErrorCode::QrExpired,
            "qr code expired",
        ));
    }
    if now_utc > license_expire_at {
        return Err(VerifyError::new(
            VerifyErrorCode::LicenseExpired,
            "license expired",
        ));
    }
    Ok(())
}

fn validate_replay(
    payload: &LicensePayload,
    seen_nonces: &HashSet<String>,
) -> Result<(), VerifyError> {
    if seen_nonces.contains(&payload.nonce) {
        return Err(VerifyError::new(
            VerifyErrorCode::NonceReplay,
            "nonce replay detected",
        ));
    }
    Ok(())
}

fn validate_daily_limit(payload: &LicensePayload, used_today: i32) -> Result<(), VerifyError> {
    if payload.daily_analysis_limit == -1 {
        return Ok(());
    }
    if used_today >= payload.daily_analysis_limit {
        return Err(VerifyError::new(
            VerifyErrorCode::DailyLimitExceeded,
            "daily analysis limit exceeded",
        ));
    }
    Ok(())
}

fn parse_utc(value: &str, field_name: &str) -> Result<DateTime<Utc>, VerifyError> {
    DateTime::parse_from_rfc3339(value)
        .map(|ts| ts.with_timezone(&Utc))
        .map_err(|err| {
            VerifyError::new(
                VerifyErrorCode::InvalidTimestamp,
                format!("invalid {field_name}: {err}"),
            )
        })
}

fn parse_public_key(public_key_pem: &str) -> Result<RsaPublicKey, VerifyError> {
    RsaPublicKey::from_public_key_pem(public_key_pem)
        .or_else(|_| RsaPublicKey::from_pkcs1_pem(public_key_pem))
        .map_err(|err| {
            VerifyError::new(
                VerifyErrorCode::InvalidPublicKey,
                format!("unsupported public key format: {err}"),
            )
        })
}

fn canonical_signing_message(payload: &LicensePayload) -> String {
    [
        format!("license_id={}", payload.license_id),
        format!("plan_tier={}", payload.plan_tier),
        format!("topn_limit={}", payload.topn_limit),
        format!("qr_issued_at={}", payload.qr_issued_at),
        format!("qr_expires_at={}", payload.qr_expires_at),
        format!("license_issued_at={}", payload.license_issued_at),
        format!("license_expire_at={}", payload.license_expire_at),
        format!("daily_analysis_limit={}", payload.daily_analysis_limit),
        format!("nonce={}", payload.nonce),
    ]
    .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use rand::thread_rng;
    use rsa::RsaPrivateKey;
    use rsa::pkcs8::EncodePublicKey;
    use rsa::pss::SigningKey;
    use signature::{RandomizedSigner, SignatureEncoding};

    fn sign_payload(payload: &mut LicensePayload, private_key: &RsaPrivateKey) {
        let signing_key = SigningKey::<Sha256>::new(private_key.clone());
        let msg = canonical_signing_message(payload);
        let mut rng = thread_rng();
        let sig = signing_key.sign_with_rng(&mut rng, msg.as_bytes());
        payload.signature = general_purpose::STANDARD.encode(sig.to_bytes());
    }

    fn build_valid_payload(now: DateTime<Utc>) -> LicensePayload {
        LicensePayload {
            license_id: "lic-001".to_string(),
            plan_tier: PlanTier::Monthly,
            topn_limit: 5,
            qr_issued_at: (now - Duration::minutes(1)).to_rfc3339(),
            qr_expires_at: (now + Duration::minutes(4)).to_rfc3339(),
            license_issued_at: (now - Duration::hours(1)).to_rfc3339(),
            license_expire_at: (now + Duration::days(2)).to_rfc3339(),
            daily_analysis_limit: 10,
            nonce: "nonce-123".to_string(),
            signature: String::new(),
        }
    }

    fn verify(
        payload: &LicensePayload,
        public_key_pem: &str,
        now: DateTime<Utc>,
    ) -> Result<VerifiedLicense, VerifyError> {
        verify_license_payload(VerifyInput {
            payload_json: serde_json::to_string(payload).expect("serialize payload"),
            public_key_pem: public_key_pem.to_string(),
            now_utc: now,
            used_today: 0,
            seen_nonces: HashSet::new(),
            last_trusted_timestamp: Some(now - Duration::seconds(10)),
        })
    }

    #[test]
    fn verifies_valid_payload() {
        let now = Utc::now();
        let private_key = RsaPrivateKey::new(&mut thread_rng(), 2048).expect("gen key");
        let public_key_pem = private_key
            .to_public_key()
            .to_public_key_pem(Default::default())
            .expect("to pem");
        let mut payload = build_valid_payload(now);
        sign_payload(&mut payload, &private_key);

        let result = verify(&payload, &public_key_pem, now);
        assert!(result.is_ok());
        assert_eq!(result.expect("ok").topn_limit, 5);
    }

    #[test]
    fn rejects_tampered_payload() {
        let now = Utc::now();
        let private_key = RsaPrivateKey::new(&mut thread_rng(), 2048).expect("gen key");
        let public_key_pem = private_key
            .to_public_key()
            .to_public_key_pem(Default::default())
            .expect("to pem");
        let mut payload = build_valid_payload(now);
        sign_payload(&mut payload, &private_key);
        payload.topn_limit = 10;

        let result = verify(&payload, &public_key_pem, now);
        assert!(result.is_err());
        assert_eq!(
            result.expect_err("err").code,
            VerifyErrorCode::InvalidTopnLimit
        );
    }

    #[test]
    fn rejects_nonce_replay() {
        let now = Utc::now();
        let private_key = RsaPrivateKey::new(&mut thread_rng(), 2048).expect("gen key");
        let public_key_pem = private_key
            .to_public_key()
            .to_public_key_pem(Default::default())
            .expect("to pem");
        let mut payload = build_valid_payload(now);
        sign_payload(&mut payload, &private_key);
        let mut seen_nonces = HashSet::new();
        seen_nonces.insert("nonce-123".to_string());

        let result = verify_license_payload(VerifyInput {
            payload_json: serde_json::to_string(&payload).expect("serialize payload"),
            public_key_pem,
            now_utc: now,
            used_today: 0,
            seen_nonces,
            last_trusted_timestamp: Some(now),
        });
        assert!(result.is_err());
        assert_eq!(result.expect_err("err").code, VerifyErrorCode::NonceReplay);
    }

    #[test]
    fn rejects_daily_limit_exceeded() {
        let now = Utc::now();
        let private_key = RsaPrivateKey::new(&mut thread_rng(), 2048).expect("gen key");
        let public_key_pem = private_key
            .to_public_key()
            .to_public_key_pem(Default::default())
            .expect("to pem");
        let mut payload = build_valid_payload(now);
        sign_payload(&mut payload, &private_key);

        let result = verify_license_payload(VerifyInput {
            payload_json: serde_json::to_string(&payload).expect("serialize payload"),
            public_key_pem,
            now_utc: now,
            used_today: 10,
            seen_nonces: HashSet::new(),
            last_trusted_timestamp: None,
        });
        assert!(result.is_err());
        assert_eq!(
            result.expect_err("err").code,
            VerifyErrorCode::DailyLimitExceeded
        );
    }

    #[test]
    fn allows_unlimited_daily_limit() {
        let now = Utc::now();
        let private_key = RsaPrivateKey::new(&mut thread_rng(), 2048).expect("gen key");
        let public_key_pem = private_key
            .to_public_key()
            .to_public_key_pem(Default::default())
            .expect("to pem");
        let mut payload = build_valid_payload(now);
        payload.daily_analysis_limit = -1;
        sign_payload(&mut payload, &private_key);

        let result = verify_license_payload(VerifyInput {
            payload_json: serde_json::to_string(&payload).expect("serialize payload"),
            public_key_pem,
            now_utc: now,
            used_today: 9_999,
            seen_nonces: HashSet::new(),
            last_trusted_timestamp: None,
        });
        assert!(result.is_ok());
    }

    #[test]
    fn rejects_qr_expired() {
        let now = Utc::now();
        let private_key = RsaPrivateKey::new(&mut thread_rng(), 2048).expect("gen key");
        let public_key_pem = private_key
            .to_public_key()
            .to_public_key_pem(Default::default())
            .expect("to pem");
        let mut payload = build_valid_payload(now);
        payload.qr_expires_at = (now - Duration::seconds(1)).to_rfc3339();
        sign_payload(&mut payload, &private_key);

        let result = verify(&payload, &public_key_pem, now);
        assert!(result.is_err());
        assert_eq!(result.expect_err("err").code, VerifyErrorCode::QrExpired);
    }

    #[test]
    fn rejects_clock_rollback() {
        let now = Utc::now();
        let private_key = RsaPrivateKey::new(&mut thread_rng(), 2048).expect("gen key");
        let public_key_pem = private_key
            .to_public_key()
            .to_public_key_pem(Default::default())
            .expect("to pem");
        let mut payload = build_valid_payload(now);
        sign_payload(&mut payload, &private_key);

        let result = verify_license_payload(VerifyInput {
            payload_json: serde_json::to_string(&payload).expect("serialize payload"),
            public_key_pem,
            now_utc: now,
            used_today: 0,
            seen_nonces: HashSet::new(),
            last_trusted_timestamp: Some(now + Duration::seconds(1)),
        });
        assert!(result.is_err());
        assert_eq!(
            result.expect_err("err").code,
            VerifyErrorCode::ClockRollback
        );
    }

    #[test]
    fn verifies_desktop_mobile_qr_fixture() {
        #[derive(Debug, Deserialize)]
        struct Fixture {
            payload: LicensePayload,
            public_key_pem: String,
        }

        let fixture: Fixture = serde_json::from_str(include_str!(
            "../tests/fixtures/desktop_mobile_qr_yearly.json"
        ))
        .expect("parse fixture");

        let now = DateTime::parse_from_rfc3339("2026-04-11T09:13:55+00:00")
            .expect("now")
            .with_timezone(&Utc);
        let last = (now - Duration::seconds(10)).to_rfc3339();

        let result = verify_license_payload(VerifyInput {
            payload_json: serde_json::to_string(&fixture.payload).expect("payload json"),
            public_key_pem: fixture.public_key_pem,
            now_utc: now,
            used_today: 0,
            seen_nonces: HashSet::new(),
            last_trusted_timestamp: Some(parse_utc(&last, "last_trusted_timestamp").expect("ts")),
        })
        .expect("verified");

        assert_eq!(result.license_id, "Tester");
        assert_eq!(result.plan_tier, PlanTier::Yearly);
        assert_eq!(result.topn_limit, 10);
        assert_eq!(result.daily_analysis_limit, 10);
    }
}
