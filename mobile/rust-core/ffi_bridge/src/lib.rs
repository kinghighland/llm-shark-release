#![allow(clippy::empty_line_after_doc_comments)]

use chrono::{DateTime, Utc};
use case_crypto_core::{
    DecryptedCaseItem, EncryptedCaseItem, WrappedCkBlob, decrypt_candidate_cases,
    encrypt_case_plaintext, generate_ck_b64, unwrap_ck, wrap_ck,
};
use case_search_core::{CaseQuery, KbCase, SearchResult, decrypt_and_parse_kb, hit_case_ids, parse_kb_cases, search_cases};
use license_core::{verify_license_payload, PlanTier, VerifyInput};
use policy_core::{build_runtime_policy, PolicyInput};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FfiValidateLicenseRequest {
    pub payload_json: String,
    pub public_key_pem: String,
    pub now_utc: String,
    pub used_today: i32,
    pub seen_nonces: Vec<String>,
    pub last_trusted_timestamp: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FfiBuildPolicyRequest {
    pub plan_tier: PlanTier,
    pub topn_limit: i32,
    pub daily_analysis_limit: i32,
    pub used_today: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FfiWrapCkRequest {
    pub ck_b64: String,
    pub kek_b64: String,
    pub kek_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FfiUnwrapCkRequest {
    pub wrapped_ck_blob: WrappedCkBlob,
    pub kek_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FfiEncryptCaseRequest {
    pub plaintext: String,
    pub ck_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FfiDecryptCandidateCasesRequest {
    pub encrypted_cases: Vec<EncryptedCaseItem>,
    pub candidate_case_ids: Vec<String>,
    pub ck_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FfiResponse<T> {
    pub ok: bool,
    pub data: Option<T>,
    pub error: Option<String>,
}

pub fn ffi_mobile_qr_public_key_pem() -> String {
    include_str!("mobile_qr_public_pkcs1.pem").to_string()
}

pub fn ffi_generate_ck_b64() -> String {
    generate_ck_b64()
}

pub fn ffi_wrap_ck(request_json: String) -> String {
    let request: FfiWrapCkRequest = match serde_json::from_str(&request_json) {
        Ok(value) => value,
        Err(err) => {
            return to_json(&FfiResponse::<serde_json::Value> {
                ok: false,
                data: None,
                error: Some(format!("invalid request: {err}")),
            });
        }
    };

    match wrap_ck(&request.ck_b64, &request.kek_b64, &request.kek_id) {
        Ok(value) => to_json(&FfiResponse {
            ok: true,
            data: Some(value),
            error: None,
        }),
        Err(err) => to_json(&FfiResponse::<serde_json::Value> {
            ok: false,
            data: None,
            error: Some(err.to_string()),
        }),
    }
}

pub fn ffi_unwrap_ck(request_json: String) -> String {
    let request: FfiUnwrapCkRequest = match serde_json::from_str(&request_json) {
        Ok(value) => value,
        Err(err) => {
            return to_json(&FfiResponse::<serde_json::Value> {
                ok: false,
                data: None,
                error: Some(format!("invalid request: {err}")),
            });
        }
    };

    match unwrap_ck(&request.wrapped_ck_blob, &request.kek_b64) {
        Ok(value) => to_json(&FfiResponse {
            ok: true,
            data: Some(value),
            error: None,
        }),
        Err(err) => to_json(&FfiResponse::<serde_json::Value> {
            ok: false,
            data: None,
            error: Some(err.to_string()),
        }),
    }
}

pub fn ffi_encrypt_case_plaintext(request_json: String) -> String {
    let request: FfiEncryptCaseRequest = match serde_json::from_str(&request_json) {
        Ok(value) => value,
        Err(err) => {
            return to_json(&FfiResponse::<serde_json::Value> {
                ok: false,
                data: None,
                error: Some(format!("invalid request: {err}")),
            });
        }
    };

    match encrypt_case_plaintext(&request.plaintext, &request.ck_b64) {
        Ok(value) => to_json(&FfiResponse {
            ok: true,
            data: Some(value),
            error: None,
        }),
        Err(err) => to_json(&FfiResponse::<serde_json::Value> {
            ok: false,
            data: None,
            error: Some(err.to_string()),
        }),
    }
}

pub fn ffi_decrypt_candidate_cases(request_json: String) -> String {
    let request: FfiDecryptCandidateCasesRequest = match serde_json::from_str(&request_json) {
        Ok(value) => value,
        Err(err) => {
            return to_json(&FfiResponse::<serde_json::Value> {
                ok: false,
                data: None,
                error: Some(format!("invalid request: {err}")),
            });
        }
    };

    match decrypt_candidate_cases(
        &request.encrypted_cases,
        &HashSet::from_iter(request.candidate_case_ids),
        &request.ck_b64,
    ) {
        Ok(value) => to_json(&FfiResponse::<Vec<DecryptedCaseItem>> {
            ok: true,
            data: Some(value),
            error: None,
        }),
        Err(err) => to_json(&FfiResponse::<serde_json::Value> {
            ok: false,
            data: None,
            error: Some(err.to_string()),
        }),
    }
}

pub fn ffi_validate_license(request_json: String) -> String {
    let request: FfiValidateLicenseRequest = match serde_json::from_str(&request_json) {
        Ok(value) => value,
        Err(err) => {
            return to_json(&FfiResponse::<serde_json::Value> {
                ok: false,
                data: None,
                error: Some(format!("invalid request: {err}")),
            });
        }
    };

    let now_utc = match parse_utc(&request.now_utc) {
        Ok(value) => value,
        Err(err) => {
            return to_json(&FfiResponse::<serde_json::Value> {
                ok: false,
                data: None,
                error: Some(err),
            });
        }
    };

    let last_trusted_timestamp = match request.last_trusted_timestamp {
        Some(value) => match parse_utc(&value) {
            Ok(parsed) => Some(parsed),
            Err(err) => {
                return to_json(&FfiResponse::<serde_json::Value> {
                    ok: false,
                    data: None,
                    error: Some(err),
                });
            }
        },
        None => None,
    };

    let result = verify_license_payload(VerifyInput {
        payload_json: request.payload_json,
        public_key_pem: request.public_key_pem,
        now_utc,
        used_today: request.used_today,
        seen_nonces: HashSet::from_iter(request.seen_nonces),
        last_trusted_timestamp,
    });

    match result {
        Ok(value) => to_json(&FfiResponse {
            ok: true,
            data: Some(value),
            error: None,
        }),
        Err(err) => to_json(&FfiResponse::<serde_json::Value> {
            ok: false,
            data: None,
            error: Some(format!(
                "{}: {}",
                serde_json::to_string(&err.code).unwrap_or_default(),
                err.message
            )),
        }),
    }
}

pub fn ffi_build_policy(request_json: String) -> String {
    let request: FfiBuildPolicyRequest = match serde_json::from_str(&request_json) {
        Ok(value) => value,
        Err(err) => {
            return to_json(&FfiResponse::<serde_json::Value> {
                ok: false,
                data: None,
                error: Some(format!("invalid request: {err}")),
            });
        }
    };

    let result = build_runtime_policy(PolicyInput {
        plan_tier: request.plan_tier,
        topn_limit: request.topn_limit,
        daily_analysis_limit: request.daily_analysis_limit,
        used_today: request.used_today,
    });

    match result {
        Ok(value) => to_json(&FfiResponse {
            ok: true,
            data: Some(value),
            error: None,
        }),
        Err(err) => to_json(&FfiResponse::<serde_json::Value> {
            ok: false,
            data: None,
            error: Some(format!("{err:?}")),
        }),
    }
}

fn parse_utc(value: &str) -> Result<DateTime<Utc>, String> {
    DateTime::parse_from_rfc3339(value)
        .map(|ts| ts.with_timezone(&Utc))
        .map_err(|err| format!("invalid utc timestamp: {err}"))
}

fn to_json<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_else(|err| {
        format!("{{\"ok\":false,\"error\":\"serialize response failed: {err}\"}}")
    })
}

// ---------------------------------------------------------------------------
// Case search FFI
// ---------------------------------------------------------------------------

pub fn ffi_parse_kb_cases(kb_text: String) -> String {
    let cases = parse_kb_cases(&kb_text);
    to_json(&FfiResponse {
        ok: true,
        data: Some(cases),
        error: None,
    })
}

pub fn ffi_search_cases(request_json: String) -> String {
    #[derive(Deserialize)]
    struct SearchRequest {
        cases: Vec<KbCase>,
        query: CaseQuery,
        max_results: usize,
    }
    let request: SearchRequest = match serde_json::from_str(&request_json) {
        Ok(v) => v,
        Err(err) => {
            return to_json(&FfiResponse::<serde_json::Value> {
                ok: false,
                data: None,
                error: Some(format!("invalid search request: {err}")),
            });
        }
    };
    let result = search_cases(&request.cases, &request.query, request.max_results);
    to_json(&FfiResponse {
        ok: true,
        data: Some(result),
        error: None,
    })
}

pub fn ffi_hit_case_ids(request_json: String) -> String {
    let result: SearchResult = match serde_json::from_str(&request_json) {
        Ok(v) => v,
        Err(err) => {
            return to_json(&FfiResponse::<serde_json::Value> {
                ok: false,
                data: None,
                error: Some(format!("invalid search result: {err}")),
            });
        }
    };
    let ids = hit_case_ids(&result);
    to_json(&FfiResponse {
        ok: true,
        data: Some(ids),
        error: None,
    })
}

/// Decrypts an encrypted KB `.enc` file and parses it into cases.
/// Input: base64-encoded encrypted KB data.
pub fn ffi_decrypt_and_parse_kb(enc_b64: String) -> String {
    use base64::Engine as _;
    let enc_data = match base64::engine::general_purpose::STANDARD.decode(&enc_b64) {
        Ok(v) => v,
        Err(err) => {
            return to_json(&FfiResponse::<serde_json::Value> {
                ok: false,
                data: None,
                error: Some(format!("base64 decode failed: {err}")),
            });
        }
    };
    match decrypt_and_parse_kb(&enc_data) {
        Ok(cases) => to_json(&FfiResponse {
            ok: true,
            data: Some(cases),
            error: None,
        }),
        Err(err) => to_json(&FfiResponse::<serde_json::Value> {
            ok: false,
            data: None,
            error: Some(err.to_string()),
        }),
    }
}

uniffi::include_scaffolding!("ffi_bridge");

// ---------------------------------------------------------------------------
// LLM FFI
// ---------------------------------------------------------------------------

/// LLM configuration for API calls
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmConfig {
    pub endpoint: String,
    pub api_key: String,
    pub model: String,
    #[serde(default = "default_temperature")]
    pub temperature: f64,
}

fn default_temperature() -> f64 {
    0.7
}

/// Chat message for LLM API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

// ---------------------------------------------------------------------------
// Trial API Key handling (same as desktop version)
// ---------------------------------------------------------------------------

/// Placeholder for trial API key (used in config, replaced at runtime)
const TRIAL_API_KEY_PLACEHOLDER: &str = "__LLMSHARK_TRIAL_KEY__";

/// Built-in trial API key (replace with actual key before compilation, delete after)
/// IMPORTANT: This key should be set before building release APKs and removed after
const BUILTIN_SF_TRIAL_API_KEY: &str = "sk-"; // Replace with actual key before release build

/// Materialize trial configuration: replace placeholder with actual key
fn materialize_trial_key(api_key: &str) -> String {
    if api_key.trim() == TRIAL_API_KEY_PLACEHOLDER {
        // Try environment variable first, fall back to built-in key
        std::env::var("LLMSHARK_SF_TRIAL_KEY")
            .unwrap_or_else(|_| BUILTIN_SF_TRIAL_API_KEY.to_string())
    } else {
        api_key.to_string()
    }
}

/// Default LLM configuration (SiliconFlow)
pub fn ffi_default_llm_config() -> LlmConfig {
    LlmConfig {
        endpoint: "https://api.siliconflow.cn".to_string(),
        api_key: TRIAL_API_KEY_PLACEHOLDER.to_string(),
        model: "Deepseek-ai/DeepSeek-V4-Flash".to_string(),
        temperature: 0.7,
    }
}

/// Convert UI language code to hint string for prompt template
fn ui_lang_hint(ui_lang: Option<&str>) -> String {
    let s = ui_lang.unwrap_or("").trim().to_ascii_lowercase();
    if s.is_empty() {
        "（中文）".to_string()
    } else if s.starts_with("zh") {
        "（中文）".to_string()
    } else if s.starts_with("en") {
        "（English）".to_string()
    } else if s.starts_with("fr") {
        "（Français）".to_string()
    } else if s.starts_with("de") {
        "（Deutsch）".to_string()
    } else if s.starts_with("it") {
        "（Italiano）".to_string()
    } else if s.starts_with("ru") {
        "（Русский）".to_string()
    } else if s.starts_with("fa") {
        "（فارسی）".to_string()
    } else if s.starts_with("ar") {
        "（العربية）".to_string()
    } else if s.starts_with("ja") || s.starts_with("jp") {
        "（日本語）".to_string()
    } else if s.starts_with("ko") || s.starts_with("kr") {
        "（한국어）".to_string()
    } else if s.starts_with("es") {
        "（Español）".to_string()
    } else if s.starts_with("pt") {
        "（Português）".to_string()
    } else if s.starts_with("nl") {
        "（Nederlands）".to_string()
    } else if s.starts_with("pl") {
        "（Polski）".to_string()
    } else if s.starts_with("tr") {
        "（Türkçe）".to_string()
    } else if s.starts_with("ro") {
        "（Română）".to_string()
    } else if s.starts_with("hi") {
        "（हिन्दी）".to_string()
    } else if s.starts_with("id") {
        "（Bahasa Indonesia）".to_string()
    } else if s.starts_with("ms") {
        "（Bahasa Melayu）".to_string()
    } else if s.starts_with("th") {
        "（ไทย）".to_string()
    } else if s.starts_with("vi") {
        "（Tiếng Việt）".to_string()
    } else {
        "（English）".to_string()
    }
}

/// Build mobile diagnostic prompt from query, cases and call description
pub fn ffi_build_mobile_prompt(query_json: String, cases_text: String, call_description: String, ui_lang: Option<String>) -> String {
    let template = include_str!("../../../../app/prompt-mobile.md");
    
    // Build call description section (only if provided)
    let desc_section = if call_description.is_empty() {
        String::new()
    } else {
        format!("\n<呼叫描述文本>\n{}\n", call_description)
    };
    
    let injected = format!(
        r#"
<JSON 数据>
```json
{}
```

<案例知识>
{}{}"#,
        query_json, cases_text, desc_section
    );
    let mut result = template.replace("{程序插入}", &injected);
    result = result.replace("{UI-Lang}", &ui_lang_hint(ui_lang.as_deref()));
    result
}

/// Validate LLM API configuration
#[cfg(feature = "jni")]
pub async fn ffi_validate_llm_async(config: LlmConfig) -> Result<String, String> {
    let url = format!("{}/v1/chat/completions", config.endpoint.trim());
    
    // Materialize trial key if using placeholder
    let api_key = materialize_trial_key(&config.api_key);
    
    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(30))
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("client build failed: {}", e))?;
    
    let body = serde_json::json!({
        "model": config.model,
        "messages": [{"role": "user", "content": "Hi"}],
        "max_tokens": 10
    });
    
    let response = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", api_key.trim()))
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("request failed: {}", e))?;
    
    let status = response.status();
    if status.is_success() {
        Ok(String::new())
    } else {
        let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
        Err(format!("{} - {}", status.as_u16(), error_text))
    }
}

#[cfg(feature = "jni")]
mod jni_exports {
    use super::*;
    use jni::objects::{JClass, JObject, JString, JValue};
    use jni::sys::jstring;
    use jni::JNIEnv;

    #[no_mangle]
    pub extern "system" fn Java_com_llmshark_mobile_FfiBridge_mobileQrPublicKeyPem(
        env: JNIEnv,
        _class: JClass,
    ) -> jstring {
        let out = ffi_mobile_qr_public_key_pem();
        match env.new_string(out) {
            Ok(s) => s.into_raw(),
            Err(_) => env
                .new_string("")
                .ok()
                .map(|s| s.into_raw())
                .unwrap_or(std::ptr::null_mut()),
        }
    }

    #[no_mangle]
    pub extern "system" fn Java_com_llmshark_mobile_FfiBridge_generateCkB64(
        env: JNIEnv,
        _class: JClass,
    ) -> jstring {
        let out = ffi_generate_ck_b64();
        match env.new_string(out) {
            Ok(s) => s.into_raw(),
            Err(_) => env
                .new_string("")
                .ok()
                .map(|s| s.into_raw())
                .unwrap_or(std::ptr::null_mut()),
        }
    }

    #[no_mangle]
    pub extern "system" fn Java_com_llmshark_mobile_FfiBridge_wrapCk(
        mut env: JNIEnv,
        _class: JClass,
        request_json: JString,
    ) -> jstring {
        let request_json: String = match env.get_string(&request_json) {
            Ok(v) => v.into(),
            Err(_) => String::new(),
        };
        let out = ffi_wrap_ck(request_json);
        match env.new_string(out) {
            Ok(s) => s.into_raw(),
            Err(_) => env
                .new_string("")
                .ok()
                .map(|s| s.into_raw())
                .unwrap_or(std::ptr::null_mut()),
        }
    }

    #[no_mangle]
    pub extern "system" fn Java_com_llmshark_mobile_FfiBridge_unwrapCk(
        mut env: JNIEnv,
        _class: JClass,
        request_json: JString,
    ) -> jstring {
        let request_json: String = match env.get_string(&request_json) {
            Ok(v) => v.into(),
            Err(_) => String::new(),
        };
        let out = ffi_unwrap_ck(request_json);
        match env.new_string(out) {
            Ok(s) => s.into_raw(),
            Err(_) => env
                .new_string("")
                .ok()
                .map(|s| s.into_raw())
                .unwrap_or(std::ptr::null_mut()),
        }
    }

    #[no_mangle]
    pub extern "system" fn Java_com_llmshark_mobile_FfiBridge_encryptCasePlaintext(
        mut env: JNIEnv,
        _class: JClass,
        request_json: JString,
    ) -> jstring {
        let request_json: String = match env.get_string(&request_json) {
            Ok(v) => v.into(),
            Err(_) => String::new(),
        };
        let out = ffi_encrypt_case_plaintext(request_json);
        match env.new_string(out) {
            Ok(s) => s.into_raw(),
            Err(_) => env
                .new_string("")
                .ok()
                .map(|s| s.into_raw())
                .unwrap_or(std::ptr::null_mut()),
        }
    }

    #[no_mangle]
    pub extern "system" fn Java_com_llmshark_mobile_FfiBridge_decryptCandidateCases(
        mut env: JNIEnv,
        _class: JClass,
        request_json: JString,
    ) -> jstring {
        let request_json: String = match env.get_string(&request_json) {
            Ok(v) => v.into(),
            Err(_) => String::new(),
        };
        let out = ffi_decrypt_candidate_cases(request_json);
        match env.new_string(out) {
            Ok(s) => s.into_raw(),
            Err(_) => env
                .new_string("")
                .ok()
                .map(|s| s.into_raw())
                .unwrap_or(std::ptr::null_mut()),
        }
    }

    #[no_mangle]
    pub extern "system" fn Java_com_llmshark_mobile_FfiBridge_validateLicense(
        mut env: JNIEnv,
        _class: JClass,
        request_json: JString,
    ) -> jstring {
        let request_json: String = match env.get_string(&request_json) {
            Ok(v) => v.into(),
            Err(_) => String::new(),
        };
        let out = ffi_validate_license(request_json);
        match env.new_string(out) {
            Ok(s) => s.into_raw(),
            Err(_) => env
                .new_string("")
                .ok()
                .map(|s| s.into_raw())
                .unwrap_or(std::ptr::null_mut()),
        }
    }

    #[no_mangle]
    pub extern "system" fn Java_com_llmshark_mobile_FfiBridge_buildPolicy(
        mut env: JNIEnv,
        _class: JClass,
        request_json: JString,
    ) -> jstring {
        let request_json: String = match env.get_string(&request_json) {
            Ok(v) => v.into(),
            Err(_) => String::new(),
        };
        let out = ffi_build_policy(request_json);
        match env.new_string(out) {
            Ok(s) => s.into_raw(),
            Err(_) => env
                .new_string("")
                .ok()
                .map(|s| s.into_raw())
                .unwrap_or(std::ptr::null_mut()),
        }
    }

    #[no_mangle]
    pub extern "system" fn Java_com_llmshark_mobile_FfiBridge_parseKbCases(
        mut env: JNIEnv,
        _class: JClass,
        kb_text: JString,
    ) -> jstring {
        let kb_text: String = match env.get_string(&kb_text) {
            Ok(v) => v.into(),
            Err(_) => String::new(),
        };
        let out = ffi_parse_kb_cases(kb_text);
        match env.new_string(out) {
            Ok(s) => s.into_raw(),
            Err(_) => env
                .new_string("")
                .ok()
                .map(|s| s.into_raw())
                .unwrap_or(std::ptr::null_mut()),
        }
    }

    #[no_mangle]
    pub extern "system" fn Java_com_llmshark_mobile_FfiBridge_searchCases(
        mut env: JNIEnv,
        _class: JClass,
        request_json: JString,
    ) -> jstring {
        let request_json: String = match env.get_string(&request_json) {
            Ok(v) => v.into(),
            Err(_) => String::new(),
        };
        let out = ffi_search_cases(request_json);
        match env.new_string(out) {
            Ok(s) => s.into_raw(),
            Err(_) => env
                .new_string("")
                .ok()
                .map(|s| s.into_raw())
                .unwrap_or(std::ptr::null_mut()),
        }
    }

    #[no_mangle]
    pub extern "system" fn Java_com_llmshark_mobile_FfiBridge_decryptAndParseKb(
        mut env: JNIEnv,
        _class: JClass,
        enc_b64: JString,
    ) -> jstring {
        let enc_b64: String = match env.get_string(&enc_b64) {
            Ok(v) => v.into(),
            Err(_) => String::new(),
        };
        let out = ffi_decrypt_and_parse_kb(enc_b64);
        match env.new_string(out) {
            Ok(s) => s.into_raw(),
            Err(_) => env
                .new_string("")
                .ok()
                .map(|s| s.into_raw())
                .unwrap_or(std::ptr::null_mut()),
        }
    }

    // -----------------------------------------------------------------------
    // LLM JNI exports
    // -----------------------------------------------------------------------

    #[no_mangle]
    pub extern "system" fn Java_com_llmshark_mobile_FfiBridge_defaultLlmConfig(
        env: JNIEnv,
        _class: JClass,
    ) -> jstring {
        let config = ffi_default_llm_config();
        let json = serde_json::to_string(&config).unwrap_or_default();
        match env.new_string(json) {
            Ok(s) => s.into_raw(),
            Err(_) => env
                .new_string("")
                .ok()
                .map(|s| s.into_raw())
                .unwrap_or(std::ptr::null_mut()),
        }
    }

    #[no_mangle]
    pub extern "system" fn Java_com_llmshark_mobile_FfiBridge_buildMobilePrompt(
        mut env: JNIEnv,
        _class: JClass,
        query_json: JString,
        cases_text: JString,
        call_description: JString,
        ui_lang: JString,
    ) -> jstring {
        let query_json: String = match env.get_string(&query_json) {
            Ok(v) => v.into(),
            Err(_) => String::new(),
        };
        let cases_text: String = match env.get_string(&cases_text) {
            Ok(v) => v.into(),
            Err(_) => String::new(),
        };
        let call_description: String = match env.get_string(&call_description) {
            Ok(v) => v.into(),
            Err(_) => String::new(),
        };
        let ui_lang_str: String = match env.get_string(&ui_lang) {
            Ok(v) => v.into(),
            Err(_) => String::new(),
        };
        let ui_lang_opt = if ui_lang_str.trim().is_empty() { None } else { Some(ui_lang_str) };
        let out = ffi_build_mobile_prompt(query_json, cases_text, call_description, ui_lang_opt);
        match env.new_string(out) {
            Ok(s) => s.into_raw(),
            Err(_) => env
                .new_string("")
                .ok()
                .map(|s| s.into_raw())
                .unwrap_or(std::ptr::null_mut()),
        }
    }

    #[no_mangle]
    pub extern "system" fn Java_com_llmshark_mobile_FfiBridge_validateLlm(
        mut env: JNIEnv,
        _class: JClass,
        config_json: JString,
    ) -> jstring {
        let config_json: String = match env.get_string(&config_json) {
            Ok(v) => v.into(),
            Err(_) => String::new(),
        };
        
        let config: LlmConfig = match serde_json::from_str(&config_json) {
            Ok(v) => v,
            Err(e) => {
                let result = FfiResponse::<String> {
                    ok: false,
                    data: None,
                    error: Some(format!("invalid config: {}", e)),
                };
                let json = serde_json::to_string(&result).unwrap_or_default();
                return match env.new_string(json) {
                    Ok(s) => s.into_raw(),
                    Err(_) => std::ptr::null_mut(),
                };
            }
        };
        
        // Create a new tokio runtime for this blocking call
        let rt = match tokio::runtime::Runtime::new() {
            Ok(rt) => rt,
            Err(e) => {
                let result = FfiResponse::<String> {
                    ok: false,
                    data: None,
                    error: Some(format!("runtime error: {}", e)),
                };
                let json = serde_json::to_string(&result).unwrap_or_default();
                return match env.new_string(json) {
                    Ok(s) => s.into_raw(),
                    Err(_) => std::ptr::null_mut(),
                };
            }
        };
        
        let result = rt.block_on(ffi_validate_llm_async(config));
        
        let response = match result {
            Ok(msg) => FfiResponse {
                ok: true,
                data: Some(msg),
                error: None,
            },
            Err(e) => FfiResponse::<String> {
                ok: false,
                data: None,
                error: Some(e),
            },
        };
        
        let json = serde_json::to_string(&response).unwrap_or_default();
        match env.new_string(json) {
            Ok(s) => s.into_raw(),
            Err(_) => std::ptr::null_mut(),
        }
    }

    #[no_mangle]
    pub extern "system" fn Java_com_llmshark_mobile_FfiBridge_llmChat(
        mut env: JNIEnv,
        _class: JClass,
        config_json: JString,
        messages_json: JString,
    ) -> jstring {
        let config_json: String = match env.get_string(&config_json) {
            Ok(v) => v.into(),
            Err(_) => String::new(),
        };
        let messages_json: String = match env.get_string(&messages_json) {
            Ok(v) => v.into(),
            Err(_) => String::new(),
        };
        
        let config: LlmConfig = match serde_json::from_str(&config_json) {
            Ok(v) => v,
            Err(e) => {
                let result = FfiResponse::<String> {
                    ok: false,
                    data: None,
                    error: Some(format!("invalid config: {}", e)),
                };
                let json = serde_json::to_string(&result).unwrap_or_default();
                return match env.new_string(json) {
                    Ok(s) => s.into_raw(),
                    Err(_) => std::ptr::null_mut(),
                };
            }
        };
        
        let messages: Vec<ChatMessage> = match serde_json::from_str(&messages_json) {
            Ok(v) => v,
            Err(e) => {
                let result = FfiResponse::<String> {
                    ok: false,
                    data: None,
                    error: Some(format!("invalid messages: {}", e)),
                };
                let json = serde_json::to_string(&result).unwrap_or_default();
                return match env.new_string(json) {
                    Ok(s) => s.into_raw(),
                    Err(_) => std::ptr::null_mut(),
                };
            }
        };
        
        // Create a new tokio runtime for this blocking call
        let rt = match tokio::runtime::Runtime::new() {
            Ok(rt) => rt,
            Err(e) => {
                let result = FfiResponse::<String> {
                    ok: false,
                    data: None,
                    error: Some(format!("runtime error: {}", e)),
                };
                let json = serde_json::to_string(&result).unwrap_or_default();
                return match env.new_string(json) {
                    Ok(s) => s.into_raw(),
                    Err(_) => std::ptr::null_mut(),
                };
            }
        };
        
        let result = rt.block_on(llm_chat_async(config, messages));
        
        let response = match result {
            Ok(content) => FfiResponse {
                ok: true,
                data: Some(content),
                error: None,
            },
            Err(e) => FfiResponse::<String> {
                ok: false,
                data: None,
                error: Some(e),
            },
        };
        
        let json = serde_json::to_string(&response).unwrap_or_default();
        match env.new_string(json) {
            Ok(s) => s.into_raw(),
            Err(_) => std::ptr::null_mut(),
        }
    }

    /// Streaming LLM chat - calls back to Kotlin for each chunk
    /// The callback is passed as a jobject that implements LlmStreamCallback interface
    #[no_mangle]
    pub extern "system" fn Java_com_llmshark_mobile_FfiBridge_llmChatStream(
        mut env: JNIEnv,
        _class: JClass,
        config_json: JString,
        messages_json: JString,
        callback_obj: JObject,
    ) -> jstring {
        let config_json: String = match env.get_string(&config_json) {
            Ok(v) => v.into(),
            Err(_) => String::new(),
        };
        let messages_json: String = match env.get_string(&messages_json) {
            Ok(v) => v.into(),
            Err(_) => String::new(),
        };
        
        let config: LlmConfig = match serde_json::from_str(&config_json) {
            Ok(v) => v,
            Err(e) => {
                let result = FfiResponse::<String> {
                    ok: false,
                    data: None,
                    error: Some(format!("invalid config: {}", e)),
                };
                let json = serde_json::to_string(&result).unwrap_or_default();
                return match env.new_string(json) {
                    Ok(s) => s.into_raw(),
                    Err(_) => std::ptr::null_mut(),
                };
            }
        };
        
        let messages: Vec<ChatMessage> = match serde_json::from_str(&messages_json) {
            Ok(v) => v,
            Err(e) => {
                let result = FfiResponse::<String> {
                    ok: false,
                    data: None,
                    error: Some(format!("invalid messages: {}", e)),
                };
                let json = serde_json::to_string(&result).unwrap_or_default();
                return match env.new_string(json) {
                    Ok(s) => s.into_raw(),
                    Err(_) => std::ptr::null_mut(),
                };
            }
        };

        // Create tokio runtime
        let rt = match tokio::runtime::Runtime::new() {
            Ok(rt) => rt,
            Err(e) => {
                let result = FfiResponse::<String> {
                    ok: false,
                    data: None,
                    error: Some(format!("runtime error: {}", e)),
                };
                let json = serde_json::to_string(&result).unwrap_or_default();
                return match env.new_string(json) {
                    Ok(s) => s.into_raw(),
                    Err(_) => std::ptr::null_mut(),
                };
            }
        };

        // Create a global reference to the callback object (can be shared across threads)
        let callback_global_ref = match env.new_global_ref(&callback_obj) {
            Ok(ref_) => ref_,
            Err(e) => {
                let result = FfiResponse::<String> {
                    ok: false,
                    data: None,
                    error: Some(format!("create global ref failed: {}", e)),
                };
                let json = serde_json::to_string(&result).unwrap_or_default();
                return match env.new_string(json) {
                    Ok(s) => s.into_raw(),
                    Err(_) => std::ptr::null_mut(),
                };
            }
        };
        
        // Create a thread-local env reference for callbacks
        // We need to attach the current thread to JVM for callbacks
        let jvm = match env.get_java_vm() {
            Ok(jvm) => jvm,
            Err(e) => {
                let result = FfiResponse::<String> {
                    ok: false,
                    data: None,
                    error: Some(format!("get jvm failed: {}", e)),
                };
                let json = serde_json::to_string(&result).unwrap_or_default();
                return match env.new_string(json) {
                    Ok(s) => s.into_raw(),
                    Err(_) => std::ptr::null_mut(),
                };
            }
        };

        let result = rt.block_on(async {
            let callback_for_chunk = |chunk: &str| {
                // Attach current thread to JVM if needed
                if let Ok(mut callback_env) = jvm.attach_current_thread() {
                    // Call Kotlin callback method: onChunk(chunk: String)
                    let chunk_jstr = match callback_env.new_string(chunk) {
                        Ok(s) => s,
                        Err(_) => return,
                    };
                    
                    // Find and call the onChunk method
                    let _ = callback_env.call_method(
                        &callback_global_ref,
                        "onChunk",
                        "(Ljava/lang/String;)V",
                        &[JValue::Object(&chunk_jstr)],
                    );
                }
            };
            
            llm_chat_stream_async(config, messages, callback_for_chunk).await
        });
        
        let response = match result {
            Ok(content) => FfiResponse {
                ok: true,
                data: Some(content),
                error: None,
            },
            Err(e) => FfiResponse::<String> {
                ok: false,
                data: None,
                error: Some(e),
            },
        };
        
        let json = serde_json::to_string(&response).unwrap_or_default();
        match env.new_string(json) {
            Ok(s) => s.into_raw(),
            Err(_) => std::ptr::null_mut(),
        }
    }
}

#[cfg(feature = "jni")]
async fn llm_chat_async(config: LlmConfig, messages: Vec<ChatMessage>) -> Result<String, String> {
    let url = format!("{}/v1/chat/completions", config.endpoint.trim());
    
    // Materialize trial key if using placeholder
    let api_key = materialize_trial_key(&config.api_key);
    
    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(60))
        .timeout(std::time::Duration::from_secs(300))
        .build()
        .map_err(|e| format!("client build failed: {}", e))?;
    
    let body = serde_json::json!({
        "model": config.model,
        "temperature": config.temperature,
        "stream": false,
        "messages": messages
    });
    
    let response = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", api_key.trim()))
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("request failed: {}", e))?;
    
    let status = response.status();
    if !status.is_success() {
        let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
        return Err(format!("LLM 请求失败: {} - {}", status.as_u16(), error_text));
    }
    
    let text = response.text().await.map_err(|e| format!("read response failed: {}", e))?;
    let v: serde_json::Value = serde_json::from_str(&text).map_err(|e| format!("parse response failed: {}", e))?;
    
    let content = v["choices"][0]["message"]["content"]
        .as_str()
        .unwrap_or("")
        .to_string();
    
    if content.trim().is_empty() {
        return Err("LLM 返回为空".to_string());
    }
    
    Ok(content)
}

/// Stream chunk callback type for JNI
/// Parameters: (env, chunk_json)
type StreamChunkCallback = unsafe fn(*mut jni::sys::JNIEnv, jni::sys::jstring);

/// Global callback for stream chunks (set by JNI init)
static mut STREAM_CHUNK_CALLBACK: Option<StreamChunkCallback> = None;

/// Set the stream chunk callback (called from Kotlin during initialization)
#[cfg(feature = "jni")]
pub fn ffi_set_stream_callback(callback: StreamChunkCallback) {
    unsafe {
        STREAM_CHUNK_CALLBACK = Some(callback);
    }
}

/// SSE stream parsing for LLM chat
#[cfg(feature = "jni")]
async fn llm_chat_stream_async<F>(config: LlmConfig, messages: Vec<ChatMessage>, mut on_chunk: F) -> Result<String, String>
where
    F: FnMut(&str) + Send,
{
    let url = format!("{}/v1/chat/completions", config.endpoint.trim());
    
    // Materialize trial key if using placeholder
    let api_key = materialize_trial_key(&config.api_key);
    
    let client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(60))
        .timeout(std::time::Duration::from_secs(300))
        .build()
        .map_err(|e| format!("client build failed: {}", e))?;
    
    let body = serde_json::json!({
        "model": config.model,
        "temperature": config.temperature,
        "stream": true,
        "messages": messages
    });
    
    let response = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", api_key.trim()))
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("request failed: {}", e))?;
    
    let status = response.status();
    if !status.is_success() {
        let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
        return Err(format!("LLM 请求失败: {} - {}", status.as_u16(), error_text));
    }
    
    // Check content type for SSE stream
    let ct = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_lowercase();
    
    if !ct.contains("text/event-stream") {
        // Non-streaming response (some APIs don't support streaming)
        let text = response.text().await.map_err(|e| format!("read response failed: {}", e))?;
        let v: serde_json::Value = serde_json::from_str(&text).map_err(|e| format!("parse response failed: {}", e))?;
        
        let content = v["choices"][0]["message"]["content"]
            .as_str()
            .unwrap_or("")
            .to_string();
        
        if !content.is_empty() {
            on_chunk(&content);
        }
        return Ok(content);
    }
    
    // Parse SSE stream
    use futures_util::StreamExt;
    let mut stream = response.bytes_stream();
    let mut buf = String::new();
    let mut full_content = String::new();
    
    while let Some(item) = stream.next().await {
        let bytes = item.map_err(|e| format!("stream read failed: {}", e))?;
        buf.push_str(&String::from_utf8_lossy(&bytes));
        
        // Process complete SSE events (separated by \n\n)
        while let Some(idx) = buf.find("\n\n") {
            let event = buf[..idx].to_string();
            buf = buf[idx + 2..].to_string();
            
            for line in event.lines() {
                let Some(data) = line.trim_start().strip_prefix("data:") else {
                    continue;
                };
                let data = data.trim();
                if data.is_empty() {
                    continue;
                }
                if data == "[DONE]" {
                    return Ok(full_content);
                }
                
                // Parse JSON and extract delta content
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(data) {
                    if let Some(delta) = v["choices"][0]["delta"]["content"].as_str() {
                        if !delta.is_empty() {
                            full_content.push_str(delta);
                            on_chunk(delta);
                        }
                    }
                }
            }
        }
    }
    
    Ok(full_content)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use chrono::Duration;
    use license_core::{LicensePayload, PlanTier};
    use rand::thread_rng;
    use rsa::pkcs8::EncodePublicKey;
    use rsa::pss::SigningKey;
    use rsa::RsaPrivateKey;
    use sha2::Sha256;
    use signature::{RandomizedSigner, SignatureEncoding};

    fn sign_payload(payload: &mut LicensePayload, private_key: &RsaPrivateKey) {
        let msg = [
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
        .join("\n");
        let signing_key = SigningKey::<Sha256>::new(private_key.clone());
        let mut rng = thread_rng();
        let sig = signing_key.sign_with_rng(&mut rng, msg.as_bytes());
        payload.signature = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());
    }

    #[test]
    fn ffi_policy_success() {
        let req = serde_json::json!({
            "plan_tier": "monthly",
            "topn_limit": 5,
            "daily_analysis_limit": 10,
            "used_today": 4
        });

        let result = ffi_build_policy(req.to_string());
        let parsed: FfiResponse<serde_json::Value> = serde_json::from_str(&result).expect("parse");
        assert!(parsed.ok);
    }

    #[test]
    fn ffi_validate_success() {
        let now = Utc::now();
        let private_key = RsaPrivateKey::new(&mut thread_rng(), 2048).expect("gen key");
        let public_pem = private_key
            .to_public_key()
            .to_public_key_pem(Default::default())
            .expect("pem");
        let mut payload = LicensePayload {
            license_id: "lic-ffi-001".to_string(),
            plan_tier: PlanTier::Monthly,
            topn_limit: 5,
            qr_issued_at: (now - Duration::minutes(1)).to_rfc3339(),
            qr_expires_at: (now + Duration::minutes(1)).to_rfc3339(),
            license_issued_at: (now - Duration::minutes(3)).to_rfc3339(),
            license_expire_at: (now + Duration::days(1)).to_rfc3339(),
            daily_analysis_limit: 10,
            nonce: "nonce-ffi-001".to_string(),
            signature: String::new(),
        };
        sign_payload(&mut payload, &private_key);

        let req = serde_json::json!({
            "payload_json": serde_json::to_string(&payload).expect("payload json"),
            "public_key_pem": public_pem,
            "now_utc": now.to_rfc3339(),
            "used_today": 0,
            "seen_nonces": [],
            "last_trusted_timestamp": null
        });

        let result = ffi_validate_license(req.to_string());
        let parsed: FfiResponse<serde_json::Value> = serde_json::from_str(&result).expect("parse");
        assert!(parsed.ok);
    }

    #[test]
    fn ffi_mobile_key_not_empty() {
        let pem = ffi_mobile_qr_public_key_pem();
        assert!(pem.contains("BEGIN RSA PUBLIC KEY"));
    }

    #[test]
    fn ffi_case_crypto_roundtrip() {
        let ck = ffi_generate_ck_b64();
        let kek = ffi_generate_ck_b64();
        let wrap_req = serde_json::json!({
            "ck_b64": ck,
            "kek_b64": kek,
            "kek_id": "ios-keychain-v1"
        });
        let wrap_out = ffi_wrap_ck(wrap_req.to_string());
        let wrap_parsed: FfiResponse<WrappedCkBlob> = serde_json::from_str(&wrap_out).expect("parse wrap");
        assert!(wrap_parsed.ok);
        let wrapped = wrap_parsed.data.expect("wrap data");

        let unwrap_req = serde_json::json!({
            "wrapped_ck_blob": wrapped,
            "kek_b64": kek
        });
        let unwrap_out = ffi_unwrap_ck(unwrap_req.to_string());
        let unwrap_parsed: FfiResponse<String> =
            serde_json::from_str(&unwrap_out).expect("parse unwrap");
        assert!(unwrap_parsed.ok);
        let unwrapped_ck = unwrap_parsed.data.expect("unwrap data");

        let enc_req = serde_json::json!({
            "plaintext": "case-a",
            "ck_b64": unwrapped_ck
        });
        let enc_out = ffi_encrypt_case_plaintext(enc_req.to_string());
        let enc_parsed: FfiResponse<case_crypto_core::EncryptedCaseBlob> =
            serde_json::from_str(&enc_out).expect("parse enc");
        assert!(enc_parsed.ok);

        let decrypt_req = serde_json::json!({
            "encrypted_cases": [
                { "case_id": "c1", "blob": enc_parsed.data.expect("enc data") }
            ],
            "candidate_case_ids": ["c1"],
            "ck_b64": unwrapped_ck
        });
        let dec_out = ffi_decrypt_candidate_cases(decrypt_req.to_string());
        let dec_parsed: FfiResponse<Vec<DecryptedCaseItem>> =
            serde_json::from_str(&dec_out).expect("parse dec");
        assert!(dec_parsed.ok);
        let out = dec_parsed.data.expect("dec data");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].case_id, "c1");
        assert_eq!(out[0].plaintext, "case-a");
    }
}
