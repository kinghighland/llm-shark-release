use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

// ---------------------------------------------------------------------------
// Data model (mirrors desktop LLM-Shark KbCase + Query)
// ---------------------------------------------------------------------------

/// A single case from the knowledge base.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KbCase {
    pub id: String,
    #[serde(default)]
    pub dna_id: Option<String>,
    #[serde(default)]
    pub flag: Option<String>,
    #[serde(default)]
    pub call_process: Vec<String>,
    #[serde(default)]
    pub issue_location: Option<String>,
    #[serde(default)]
    pub diagnosis: Option<String>,
    #[serde(default)]
    pub root_cause: Option<String>,
    #[serde(default)]
    pub case_numbers: Option<String>,
}

/// User-input query for case search.
/// On the mobile side, the user manually enters these (no PCAP).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CaseQuery {
    // ============== 必选项 ==============
    /// Caller or callee side (caller | callee)
    #[serde(default)]
    pub call_side: Option<String>,
    
    /// Whether the call had a 183 Session Progress
    /// 有: search "183时延", 无: search "无183响应"
    #[serde(default)]
    pub has_183: Option<bool>,
    
    /// Whether the call had a 180 Ring response
    /// 有: search "180时延", 无: search absence of "180时延"
    #[serde(default)]
    pub has_180: Option<bool>,
    
    /// Whether the call had a 200 OK to INVITE
    /// 有: search "200 OK(Invite)时延", 无: search absence of "200 OK(Invite)时延"
    #[serde(default)]
    pub has_200_invite: Option<bool>,
    
    /// Whether the call had an ACK to 200
    /// 有: search "ACK(200 OK)时延", 无: 不检索
    #[serde(default)]
    pub has_ack_200: Option<bool>,
    
    /// Whether the call had a CANCEL
    /// 有: search "取消" or "CANCEL", 无: 不检索
    #[serde(default)]
    pub has_cancel: Option<bool>,
    
    /// Whether the call had a BYE
    /// 有: search "BYE", 无: 不检索
    #[serde(default)]
    pub has_bye: Option<bool>,
    
    /// SIP response code (e.g. "487", "503")
    /// 有: search "响应码XXX" or ", XXX", 无: 不检索
    #[serde(default)]
    pub sip_response_code: Option<String>,
    
    /// SIP text to search for
    /// 有: search user input text, 无: 不检索
    #[serde(default)]
    pub sip_text: Option<String>,
    
    // ============== 可选项 ==============
    /// SIP provisional response code (1xx)
    /// 有: search "中间应答XXX", 无: 不检索
    #[serde(default)]
    pub sip_provisional_code: Option<String>,
    
    /// SIP half-connected state
    /// 有: search "半接通状态", 无: 不检索
    #[serde(default)]
    pub half_connected: Option<String>,
    
    /// SIP retransmission direction (uplink | downlink | both)
    /// 上行: search "SIP上行重传", 下行: search "SIP下行重传", 双向: 同时包含上行和下行重传
    #[serde(default)]
    pub sip_retrans: Option<String>,
    
    /// Media type (183 | UPDATE)
    /// 183: search "183放音", UPDATE: search "UPDATE放音"
    #[serde(default)]
    pub media_type: Option<String>,
    
    /// Mobility management event
    /// Detach | TAU | CSFB | I-RAT HO | Registration | Deregistration
    #[serde(default)]
    pub mm_event: Option<String>,
    
    /// Supplementary service (CF | CW | Hold)
    /// CF: search "补充业务：CF", CW: search "补充业务：CW", Hold: search "补充业务：Hold"
    #[serde(default)]
    pub supplementary_service: Option<String>,
    
    // ============== 高级可选项 ==============
    /// DSM state for advanced filtering
    /// e.g. "DSM: 未发送PRACK", "DSM: 未收到180"
    #[serde(default)]
    pub dsm_state: Option<String>,
    
    // ============== 兼容旧字段 ==============
    /// SIP error code or ISUP cause value (e.g. "487", "31") - legacy, use sip_response_code
    #[serde(default)]
    pub error_code: Option<String>,
    
    /// Call type (VoLTE, VoNR, EPSFB, VOPS, etc.)
    #[serde(default)]
    pub call_type: Option<String>,
}

/// A search hit returned to the caller.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KbHit {
    pub id: String,
    #[serde(default)]
    pub dna_id: Option<String>,
    #[serde(default)]
    pub case_numbers: Option<String>,
    #[serde(default)]
    pub signal_count: usize,
    #[serde(default)]
    pub has_180: bool,
    #[serde(default)]
    pub call_type: Option<String>,
    #[serde(default)]
    pub issue_location: Option<String>,
    #[serde(default)]
    pub diagnosis: Option<String>,
    #[serde(default)]
    pub root_cause: Option<String>,
    #[serde(default)]
    pub call_process: Vec<String>,
}

/// Trace entry for one filter step (for debugging / transparency).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FilterTrace {
    pub step: String,
    #[serde(default)]
    pub criteria: Option<String>,
    pub before: usize,
    pub after: usize,
    pub applied: bool,
}

/// Result of a case search.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SearchResult {
    pub hits: Vec<KbHit>,
    pub trace: Vec<FilterTrace>,
}

// ---------------------------------------------------------------------------
// Case parsing (from the decrypted KB text)
// ---------------------------------------------------------------------------

/// Parse the decrypted KB text into a list of cases.
/// The text format uses `<!-- split -->` separators, same as desktop LLM-Shark.
pub fn parse_kb_cases(text: &str) -> Vec<KbCase> {
    let text = text.replace("\r\n", "\n").replace('\r', "\n");
    let parts: Vec<&str> = text
        .split("<!-- split -->")
        .map(|p| p.trim())
        .filter(|p| !p.is_empty())
        .collect();

    let re_dna = Regex::new(r"DNA ID\s*=\s*(\d+)").unwrap();
    let re_flag = Regex::new(r"Flag(?:\s*值)?\s*=\s*(.+)").unwrap();

    let mut cases = Vec::new();
    for block in parts {
        let dna_id = re_dna
            .captures(block)
            .and_then(|c| c.get(1).map(|m| m.as_str().to_string()));
        let flag = re_flag
            .captures(block)
            .and_then(|c| c.get(1).map(|m| m.as_str().trim().to_string()));

        let call_process = extract_call_process(block);
        let issue_location = extract_section(block, &["问题定位", "Problem location"]);
        let diagnosis = extract_section(block, &["诊断结论", "Diagnosis"]);
        let root_cause = extract_section(block, &["根因分析", "Root cause"]);
        let case_numbers = extract_section(block, &["案例编号", "Case IDs"]);

        let id = dna_id
            .clone()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| {
                case_fingerprint(&flag, &call_process, &issue_location, &diagnosis, &root_cause, &case_numbers)
            });

        cases.push(KbCase {
            id,
            dna_id,
            flag,
            call_process,
            issue_location,
            diagnosis,
            root_cause,
            case_numbers,
        });
    }
    cases
}

// ---------------------------------------------------------------------------
// Search logic (cascading filter + sort + TopN truncate)
// ---------------------------------------------------------------------------

/// Search cases matching the query, returning at most `max_results` hits.
///
/// The algorithm mirrors the desktop LLM-Shark `kb_search`:
/// 1. Start with all cases as candidates.
/// 2. Apply cascading filters.
///    Each filter is only applied if it would reduce the candidate set
///    below max_results (or exactly at max_results for some).
///    If a filter would eliminate all candidates, it is skipped.
/// 3. Sort remaining by signal_count descending, truncate to max_results.
pub fn search_cases(cases: &[KbCase], query: &CaseQuery, max_results: usize) -> SearchResult {
    let mut candidates: Vec<&KbCase> = cases.iter().collect();
    let mut trace: Vec<FilterTrace> = vec![];

    trace.push(FilterTrace {
        step: "init".to_string(),
        criteria: None,
        before: candidates.len(),
        after: candidates.len(),
        applied: true,
    });

    // --- call_side (mandatory if provided) ---
    if let Some(side) = query.call_side.as_deref() {
        let side = side.trim();
        if !side.is_empty() {
            let before = candidates.len();
            let filtered: Vec<&KbCase> = candidates
                .iter()
                .copied()
                .filter(|c| case_call_side(c).as_deref() == Some(side))
                .collect();
            let applied = !filtered.is_empty();
            candidates = if applied { filtered } else { candidates };
            trace.push(FilterTrace {
                step: "call_side".to_string(),
                criteria: Some(side.to_string()),
                before,
                after: candidates.len(),
                applied,
            });
        }
    }

    // --- has_183 ---
    if let Some(want_183) = query.has_183 {
        let before = candidates.len();
        let filtered: Vec<&KbCase> = candidates
            .iter()
            .copied()
            .filter(|c| case_has_183(c) == want_183)
            .collect();
        let applied = !filtered.is_empty();
        if applied {
            candidates = filtered;
        }
        trace.push(FilterTrace {
            step: "has_183".to_string(),
            criteria: Some(format!("{}", want_183)),
            before,
            after: candidates.len(),
            applied,
        });
    }

    // --- has_180 ---
    if let Some(want_180) = query.has_180 {
        let before = candidates.len();
        let filtered: Vec<&KbCase> = candidates
            .iter()
            .copied()
            .filter(|c| case_has_180(c) == want_180)
            .collect();
        let applied = !filtered.is_empty();
        if applied {
            candidates = filtered;
        }
        trace.push(FilterTrace {
            step: "has_180".to_string(),
            criteria: Some(format!("{}", want_180)),
            before,
            after: candidates.len(),
            applied,
        });
    }

    // --- has_200_invite ---
    if let Some(want) = query.has_200_invite {
        let before = candidates.len();
        let filtered: Vec<&KbCase> = candidates
            .iter()
            .copied()
            .filter(|c| case_has_200_invite(c) == want)
            .collect();
        let applied = !filtered.is_empty();
        if applied {
            candidates = filtered;
        }
        trace.push(FilterTrace {
            step: "has_200_invite".to_string(),
            criteria: Some(format!("{}", want)),
            before,
            after: candidates.len(),
            applied,
        });
    }

    // --- has_ack_200 ---
    if let Some(want) = query.has_ack_200 {
        let before = candidates.len();
        let filtered: Vec<&KbCase> = candidates
            .iter()
            .copied()
            .filter(|c| case_has_ack_200(c) == want)
            .collect();
        let applied = !filtered.is_empty();
        if applied {
            candidates = filtered;
        }
        trace.push(FilterTrace {
            step: "has_ack_200".to_string(),
            criteria: Some(format!("{}", want)),
            before,
            after: candidates.len(),
            applied,
        });
    }

    // --- has_cancel ---
    if let Some(want) = query.has_cancel {
        let before = candidates.len();
        let filtered: Vec<&KbCase> = candidates
            .iter()
            .copied()
            .filter(|c| case_has_cancel(c) == want)
            .collect();
        let applied = !filtered.is_empty();
        if applied {
            candidates = filtered;
        }
        trace.push(FilterTrace {
            step: "has_cancel".to_string(),
            criteria: Some(format!("{}", want)),
            before,
            after: candidates.len(),
            applied,
        });
    }

    // --- has_bye ---
    if let Some(want) = query.has_bye {
        let before = candidates.len();
        let filtered: Vec<&KbCase> = candidates
            .iter()
            .copied()
            .filter(|c| case_has_bye(c) == want)
            .collect();
        let applied = !filtered.is_empty();
        if applied {
            candidates = filtered;
        }
        trace.push(FilterTrace {
            step: "has_bye".to_string(),
            criteria: Some(format!("{}", want)),
            before,
            after: candidates.len(),
            applied,
        });
    }

    // --- sip_response_code (mandatory if provided) ---
    if let Some(code) = query.sip_response_code.as_deref() {
        let code = code.trim();
        if !code.is_empty() {
            let before = candidates.len();
            // Search for "响应码XXX" or ", XXX" pattern
            let patterns = [
                format!("响应码{}", code),
                format!(", {}", code),
            ];
            let filtered: Vec<&KbCase> = candidates
                .iter()
                .copied()
                .filter(|c| {
                    c.call_process.iter().any(|l| {
                        patterns.iter().any(|p| l.contains(p))
                    })
                })
                .collect();
            let applied = !filtered.is_empty();
            candidates = if applied { filtered } else { candidates };
            trace.push(FilterTrace {
                step: "sip_response_code".to_string(),
                criteria: Some(code.to_string()),
                before,
                after: candidates.len(),
                applied,
            });
        }
    }

    // --- sip_text (mandatory if provided, case-insensitive) ---
    if let Some(text) = query.sip_text.as_deref() {
        let text = text.trim();
        if !text.is_empty() {
            let before = candidates.len();
            let text_lower = text.to_lowercase();
            let filtered: Vec<&KbCase> = candidates
                .iter()
                .copied()
                .filter(|c| {
                    c.call_process.iter().any(|l| l.to_lowercase().contains(&text_lower))
                })
                .collect();
            let applied = !filtered.is_empty();
            candidates = if applied { filtered } else { candidates };
            trace.push(FilterTrace {
                step: "sip_text".to_string(),
                criteria: Some(text.to_string()),
                before,
                after: candidates.len(),
                applied,
            });
        }
    }

    // --- sip_provisional_code ---
    if let Some(code) = query.sip_provisional_code.as_deref() {
        let code = code.trim();
        if !code.is_empty() {
            let before = candidates.len();
            let pattern = format!("中间应答{}", code);
            let filtered: Vec<&KbCase> = candidates
                .iter()
                .copied()
                .filter(|c| {
                    c.call_process.iter().any(|l| l.contains(&pattern))
                })
                .collect();
            let applied = !filtered.is_empty();
            if applied {
                candidates = filtered;
            }
            trace.push(FilterTrace {
                step: "sip_provisional_code".to_string(),
                criteria: Some(code.to_string()),
                before,
                after: candidates.len(),
                applied,
            });
        }
    }

    // --- half_connected ---
    if let Some(hc) = query.half_connected.as_deref() {
        let hc = hc.trim();
        if !hc.is_empty() {
            let before = candidates.len();
            // 精确匹配 "半接通状态"
            let filtered: Vec<&KbCase> = candidates
                .iter()
                .copied()
                .filter(|c| {
                    c.call_process.iter().any(|l| l.contains(hc))
                })
                .collect();
            let applied = !filtered.is_empty();
            if applied {
                candidates = filtered;
            }
            trace.push(FilterTrace {
                step: "half_connected".to_string(),
                criteria: Some(hc.to_string()),
                before,
                after: candidates.len(),
                applied,
            });
        }
    }

    // --- sip_retrans ---
    if let Some(retrans) = query.sip_retrans.as_deref() {
        let retrans = retrans.trim().to_lowercase();
        if !retrans.is_empty() {
            let before = candidates.len();
            let filtered: Vec<&KbCase> = if retrans == "both" || retrans == "双向" {
                // 双向重传：同时包含上行和下行重传
                candidates
                    .iter()
                    .copied()
                    .filter(|c| {
                        let has_uplink = c.call_process.iter().any(|l| l.contains("SIP上行重传"));
                        let has_downlink = c.call_process.iter().any(|l| l.contains("SIP下行重传"));
                        has_uplink && has_downlink
                    })
                    .collect()
            } else {
                let pattern = match retrans.as_str() {
                    "uplink" | "上行" => "SIP上行重传",
                    "downlink" | "下行" => "SIP下行重传",
                    _ => retrans.as_str(),
                };
                candidates
                    .iter()
                    .copied()
                    .filter(|c| {
                        c.call_process.iter().any(|l| l.contains(pattern))
                    })
                    .collect()
            };
            let applied = !filtered.is_empty();
            if applied {
                candidates = filtered;
            }
            trace.push(FilterTrace {
                step: "sip_retrans".to_string(),
                criteria: Some(retrans),
                before,
                after: candidates.len(),
                applied,
            });
        }
    }

    // --- media_type ---
    if let Some(mt) = query.media_type.as_deref() {
        let mt = mt.trim();
        if !mt.is_empty() {
            let before = candidates.len();
            let pattern = match mt {
                "183" => "183放音",
                "UPDATE" => "UPDATE放音",
                _ => mt,
            };
            let filtered: Vec<&KbCase> = candidates
                .iter()
                .copied()
                .filter(|c| {
                    c.call_process.iter().any(|l| l.contains(pattern))
                })
                .collect();
            let applied = !filtered.is_empty();
            if applied {
                candidates = filtered;
            }
            trace.push(FilterTrace {
                step: "media_type".to_string(),
                criteria: Some(mt.to_string()),
                before,
                after: candidates.len(),
                applied,
            });
        }
    }

    // --- mm_event ---
    if let Some(event) = query.mm_event.as_deref() {
        let event = event.trim();
        if !event.is_empty() {
            let before = candidates.len();
            let search_term = match event {
                "Registration" => "注册",
                "Deregistration" => "注销",
                _ => event,
            };
            let filtered: Vec<&KbCase> = candidates
                .iter()
                .copied()
                .filter(|c| {
                    c.call_process.iter().any(|l| l.contains(search_term))
                })
                .collect();
            let applied = !filtered.is_empty();
            if applied {
                candidates = filtered;
            }
            trace.push(FilterTrace {
                step: "mm_event".to_string(),
                criteria: Some(event.to_string()),
                before,
                after: candidates.len(),
                applied,
            });
        }
    }

    // --- supplementary_service ---
    if let Some(ss) = query.supplementary_service.as_deref() {
        let ss = ss.trim();
        if !ss.is_empty() {
            let before = candidates.len();
            // 搜索模式：兼容全角冒号（：）和半角冒号（:）
            // CF/CW/Hold -> "补充业务：XXX" 或 "补充业务: XXX"
            // 多方会议 -> "补充业务: 多方会议" 或 "补充业务：多方会议"
            let filtered: Vec<&KbCase> = candidates
                .iter()
                .copied()
                .filter(|c| {
                    c.call_process.iter().any(|l| {
                        l.contains(&format!("补充业务：{}", ss)) ||
                        l.contains(&format!("补充业务: {}", ss))
                    })
                })
                .collect();
            let applied = !filtered.is_empty();
            if applied {
                candidates = filtered;
            }
            trace.push(FilterTrace {
                step: "supplementary_service".to_string(),
                criteria: Some(ss.to_string()),
                before,
                after: candidates.len(),
                applied,
            });
        }
    }

    // --- dsm_state ---
    if let Some(dsm) = query.dsm_state.as_deref() {
        let dsm = dsm.trim();
        if !dsm.is_empty() {
            let before = candidates.len();
            let filtered: Vec<&KbCase> = candidates
                .iter()
                .copied()
                .filter(|c| {
                    c.call_process.iter().any(|l| l.contains(dsm))
                })
                .collect();
            let applied = !filtered.is_empty();
            if applied {
                candidates = filtered;
            }
            trace.push(FilterTrace {
                step: "dsm_state".to_string(),
                criteria: Some(dsm.to_string()),
                before,
                after: candidates.len(),
                applied,
            });
        }
    }

    // --- error_code (legacy, mandatory if provided) ---
    if let Some(ec) = query.error_code.as_deref() {
        let ec = ec.trim();
        if !ec.is_empty() {
            let before = candidates.len();
            let re = Regex::new(&format!(r"(?<!\d){}(?!\d)", regex::escape(ec)))
                .unwrap_or_else(|_| Regex::new(&regex::escape(ec)).unwrap());
            let filtered: Vec<&KbCase> = candidates
                .iter()
                .copied()
                .filter(|c| c.call_process.iter().any(|l| re.is_match(l)))
                .collect();
            let applied = !filtered.is_empty();
            candidates = if applied { filtered } else { candidates };
            trace.push(FilterTrace {
                step: "error_code".to_string(),
                criteria: Some(ec.to_string()),
                before,
                after: candidates.len(),
                applied,
            });
        }
    }

    // --- call_type ---
    if let Some(ct) = query.call_type.as_deref() {
        let ct = ct.trim();
        if !ct.is_empty() {
            let want = call_type_set(ct);
            let before = candidates.len();
            let filtered: Vec<&KbCase> = candidates
                .iter()
                .copied()
                .filter(|c| {
                    let got = case_call_type(c)
                        .map(|v| call_type_set(&v))
                        .unwrap_or_default();
                    !got.is_disjoint(&want)
                })
                .collect();
            let applied = !filtered.is_empty();
            if applied {
                candidates = filtered;
            }
            trace.push(FilterTrace {
                step: "call_type".to_string(),
                criteria: Some(ct.to_string()),
                before,
                after: candidates.len(),
                applied,
            });
        }
    }

    // --- sort by signal_count desc, truncate ---
    candidates.sort_by_key(|c| std::cmp::Reverse(case_signal_count(c)));
    let before = candidates.len();
    candidates.truncate(max_results);
    trace.push(FilterTrace {
        step: "sort_and_truncate".to_string(),
        criteria: Some(format!("max_results={}", max_results)),
        before,
        after: candidates.len(),
        applied: true,
    });

    let hits: Vec<KbHit> = candidates
        .iter()
        .map(|c| KbHit {
            id: c.id.clone(),
            dna_id: c.dna_id.clone(),
            case_numbers: c.case_numbers.clone(),
            signal_count: case_signal_count(c),
            has_180: case_has_180(c),
            call_type: case_call_type(c),
            issue_location: c.issue_location.clone(),
            diagnosis: c.diagnosis.clone(),
            root_cause: c.root_cause.clone(),
            call_process: c.call_process.clone(),
        })
        .collect();

    SearchResult { hits, trace }
}

/// Extract the list of candidate case IDs from a search result,
/// suitable for passing to `decrypt_candidate_cases`.
pub fn hit_case_ids(result: &SearchResult) -> Vec<String> {
    result.hits.iter().map(|h| h.id.clone()).collect()
}

// ---------------------------------------------------------------------------
// Encrypted KB decryption (same scheme as desktop LLM-Shark)
// ---------------------------------------------------------------------------

/// Error type for KB decryption operations.
#[derive(Debug)]
pub enum KbDecryptError {
    EncryptedDataTooShort,
    DecryptionFailed,
    Utf8Failed,
}

impl std::fmt::Display for KbDecryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KbDecryptError::EncryptedDataTooShort => write!(f, "encrypted KB data too short"),
            KbDecryptError::DecryptionFailed => write!(f, "KB decryption failed"),
            KbDecryptError::Utf8Failed => write!(f, "KB UTF-8 decode failed"),
        }
    }
}

/// Returns the built-in KB decryption key (XOR of two hardcoded halves).
/// This is the same key used by the desktop LLM-Shark parser.
fn kb_builtin_key() -> [u8; 32] {
    let a: [u8; 32] = [
        0x3f, 0x9a, 0x11, 0x8c, 0x72, 0x51, 0x4d, 0x0a, 0x66, 0x2d, 0xf0, 0x19, 0x5b, 0x7e, 0x8a,
        0x2c, 0xd1, 0x0e, 0x44, 0x9f, 0x2a, 0x33, 0x8b, 0x7c, 0x90, 0x1d, 0x4f, 0xa8, 0x3b, 0x29,
        0x6c, 0x55,
    ];
    let b: [u8; 32] = [
        0x91, 0x07, 0xa2, 0x3d, 0x5c, 0x8e, 0x16, 0xf1, 0x0b, 0x6a, 0x2e, 0x77, 0x18, 0xc9, 0x0d,
        0xe4, 0x24, 0x8d, 0x19, 0x60, 0x7a, 0x95, 0x1a, 0x4b, 0x1f, 0x3c, 0x71, 0x02, 0xb8, 0xe0,
        0x09, 0x13,
    ];
    let mut k = [0u8; 32];
    for i in 0..32 {
        k[i] = a[i] ^ b[i];
    }
    k
}

/// Decrypts a `.enc` KB file using the built-in key.
/// The file format is: [12-byte nonce][ciphertext + 16-byte GCM tag].
/// Returns the plaintext UTF-8 string on success.
pub fn decrypt_builtin_kb(enc_data: &[u8]) -> Result<String, KbDecryptError> {
    if enc_data.len() < 12 + 16 {
        return Err(KbDecryptError::EncryptedDataTooShort);
    }
    let nonce = Nonce::from_slice(&enc_data[..12]);
    let ciphertext = &enc_data[12..];
    let cipher = Aes256Gcm::new_from_slice(&kb_builtin_key())
        .map_err(|_| KbDecryptError::DecryptionFailed)?;
    let plain = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| KbDecryptError::DecryptionFailed)?;
    String::from_utf8(plain).map_err(|_| KbDecryptError::Utf8Failed)
}

/// One-stop function: decrypt the encrypted KB bytes, parse into cases.
pub fn decrypt_and_parse_kb(enc_data: &[u8]) -> Result<Vec<KbCase>, KbDecryptError> {
    let text = decrypt_builtin_kb(enc_data)?;
    Ok(parse_kb_cases(&text))
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Extract a section from a KB block by its `##` heading.
/// Same logic as desktop LLM-Shark `kb_section`.
/// Finds `## <header>` and returns all lines until the next `##` heading.
fn kb_section(block: &str, names: &[&str]) -> Option<String> {
    let mut start: Option<usize> = None;
    let mut end: Option<usize> = None;

    for (idx, line) in block.lines().enumerate() {
        let t = line.trim();
        if start.is_none() {
            if let Some(rest) = t.strip_prefix('#') {
                let rest = rest.trim_start_matches('#').trim();
                if names.iter().any(|name| rest.eq_ignore_ascii_case(name)) {
                    start = Some(idx + 1);
                }
            }
            // Also support `key: value` inline format (legacy)
            if start.is_none() {
                for name in names {
                    if t.starts_with(name) {
                        let after = &t[name.len()..];
                        if after.starts_with(':') || after.starts_with('\u{ff1a}') {
                            // inline `key: value` — return the value part
                            let val = after[1..].trim();
                            if !val.is_empty() {
                                return Some(val.to_string());
                            }
                            start = Some(idx + 1);
                        }
                    }
                }
            }
            continue;
        }

        if t.starts_with('#') && t.trim_start_matches('#').starts_with(' ') {
            end = Some(idx);
            break;
        }
    }

    let start = start?;
    let end = end.unwrap_or_else(|| block.lines().count());
    let body = block
        .lines()
        .skip(start)
        .take(end.saturating_sub(start))
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join("\n");
    let body = body.trim().to_string();
    if body.is_empty() {
        None
    } else {
        Some(body)
    }
}

fn extract_section(block: &str, headers: &[&str]) -> Option<String> {
    kb_section(block, headers)
}

fn extract_call_process(block: &str) -> Vec<String> {
    kb_section(block, &["呼叫过程", "Call Process"])
        .map(|text| {
            text.lines()
                .map(|l| l.trim())
                .filter(|l| !l.is_empty())
                .map(|l| l.to_string())
                .collect()
        })
        .unwrap_or_default()
}

fn case_has_183(c: &KbCase) -> bool {
    c.call_process
        .iter()
        .any(|l| l.contains("183") && l.contains("Session Progress"))
}

fn case_has_180(c: &KbCase) -> bool {
    c.call_process
        .iter()
        .any(|l| l.contains("180时延"))
}

fn case_has_200_invite(c: &KbCase) -> bool {
    c.call_process
        .iter()
        .any(|l| l.contains("200 OK(Invite)时延"))
}

fn case_has_ack_200(c: &KbCase) -> bool {
    c.call_process
        .iter()
        .any(|l| l.contains("ACK") && l.contains("200"))
}

fn case_has_cancel(c: &KbCase) -> bool {
    c.call_process.iter().any(|l| l.contains("CANCEL"))
}

fn case_has_bye(c: &KbCase) -> bool {
    c.call_process.iter().any(|l| l.contains("BYE"))
}

fn case_call_side(c: &KbCase) -> Option<String> {
    // 首先尝试从 call_process 第一行提取（格式: "1. 主叫, ..." 或 "1. 被叫, ..."）
    if let Some(first_line) = c.call_process.first() {
        let line = first_line.trim();
        // 匹配 "1. 主叫" 或 "1. 被叫" 格式
        if line.contains("主叫") {
            return Some("caller".to_string());
        }
        if line.contains("被叫") {
            return Some("callee".to_string());
        }
        // 也尝试匹配 "call side: xxx" 或 "呼叫方: xxx" 格式
        let re = Regex::new(r"(?i)(?:call\s*side|呼叫方)\s*[:：]\s*(\w+)").unwrap();
        if let Some(cap) = re.captures(line) {
            let side = cap.get(1).unwrap().as_str().to_lowercase();
            if side == "caller" || side == "originating" {
                return Some("caller".to_string());
            }
            if side == "callee" || side == "terminating" {
                return Some("callee".to_string());
            }
        }
    }
    
    // 从其他 call_process 行中查找
    let re = Regex::new(r"(?i)(?:call\s*side|呼叫方)\s*[:：]\s*(\w+)").unwrap();
    for l in &c.call_process {
        if let Some(cap) = re.captures(l) {
            let side = cap.get(1).unwrap().as_str().to_lowercase();
            if side == "caller" || side == "originating" {
                return Some("caller".to_string());
            }
            if side == "callee" || side == "terminating" {
                return Some("callee".to_string());
            }
        }
    }
    
    // 最后从 flag 字段中提取
    if let Some(flag) = &c.flag {
        let fu = flag.to_uppercase();
        if fu.contains("主叫") || fu.contains("CALLER") || fu.contains("ORIGINATING") {
            return Some("caller".to_string());
        }
        if fu.contains("被叫") || fu.contains("CALLEE") || fu.contains("TERMINATING") {
            return Some("callee".to_string());
        }
    }
    None
}

fn case_call_type(c: &KbCase) -> Option<String> {
    let patterns = [
        Regex::new(r"呼叫类型\s*:\s*([A-Za-z0-9_-]+)").unwrap(),
        Regex::new(r"(?i)\bscenario\s*:\s*([A-Za-z0-9_-]+)").unwrap(),
        Regex::new(r"(?i)\bcall\s*type\s*:\s*([A-Za-z0-9_-]+)").unwrap(),
    ];
    for l in &c.call_process {
        for re in &patterns {
            if let Some(cap) = re.captures(l) {
                return Some(cap.get(1).unwrap().as_str().to_string());
            }
        }
    }
    None
}

fn call_type_set(v: &str) -> HashSet<String> {
    let s = v.trim();
    if s.is_empty() {
        return HashSet::new();
    }
    let u = s.to_ascii_uppercase();
    if u == "VOPS" {
        return HashSet::from([
            "VOLTE".to_string(),
            "VONR".to_string(),
            "EPSFB".to_string(),
            "VOPS".to_string(),
        ]);
    }
    HashSet::from([u])
}

fn case_signal_count(c: &KbCase) -> usize {
    c.call_process.len()
}

fn case_fingerprint(
    flag: &Option<String>,
    call_process: &[String],
    issue_location: &Option<String>,
    diagnosis: &Option<String>,
    root_cause: &Option<String>,
    case_numbers: &Option<String>,
) -> String {
    use std::hash::{Hash, Hasher};
    use std::collections::hash_map::DefaultHasher;
    let mut h = DefaultHasher::new();
    flag.hash(&mut h);
    for l in call_process {
        l.hash(&mut h);
    }
    issue_location.hash(&mut h);
    diagnosis.hash(&mut h);
    root_cause.hash(&mut h);
    case_numbers.hash(&mut h);
    format!("fp-{:016x}", h.finish())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_cases() -> Vec<KbCase> {
        vec![
            KbCase {
                id: "1".to_string(),
                dna_id: Some("1".to_string()),
                flag: Some("主叫".to_string()),
                call_process: vec![
                    "INVITE -> 100 Trying -> 180 Ring -> 487 Request Terminated -> ACK"
                        .to_string(),
                    "180时延: 120ms".to_string(),
                    "呼叫类型: VoLTE".to_string(),
                ],
                issue_location: Some("UE".to_string()),
                diagnosis: Some("呼叫取消".to_string()),
                root_cause: Some("用户取消".to_string()),
                case_numbers: None,
            },
            KbCase {
                id: "2".to_string(),
                dna_id: Some("2".to_string()),
                flag: Some("被叫".to_string()),
                call_process: vec![
                    "INVITE -> 100 Trying -> 183 Session Progress -> 480 Temporarily Unavailable"
                        .to_string(),
                ],
                issue_location: Some("被叫UE".to_string()),
                diagnosis: Some("被叫不可达".to_string()),
                root_cause: Some("被叫关机".to_string()),
                case_numbers: None,
            },
            KbCase {
                id: "3".to_string(),
                dna_id: Some("3".to_string()),
                flag: None,
                call_process: vec![
                    "INVITE -> 100 Trying -> 200 OK -> ACK -> BYE -> 200 OK".to_string(),
                    "200 OK(Invite)时延: 350ms".to_string(),
                    "呼叫类型: VoNR".to_string(),
                ],
                issue_location: Some("网络".to_string()),
                diagnosis: Some("正常释放".to_string()),
                root_cause: None,
                case_numbers: None,
            },
        ]
    }

    #[test]
    fn search_by_error_code_487() {
        let cases = sample_cases();
        let query = CaseQuery {
            error_code: Some("487".to_string()),
            ..Default::default()
        };
        let result = search_cases(&cases, &query, 10);
        assert_eq!(result.hits.len(), 1);
        assert_eq!(result.hits[0].id, "1");
        assert!(result.hits[0].has_180);
    }

    #[test]
    fn search_by_call_type_vops() {
        let cases = sample_cases();
        let query = CaseQuery {
            call_type: Some("VOPS".to_string()),
            ..Default::default()
        };
        let result = search_cases(&cases, &query, 10);
        // VOPS matches VoLTE and VoNR
        assert!(result.hits.len() >= 2);
    }

    #[test]
    fn search_topn_truncation() {
        let cases = sample_cases();
        let query = CaseQuery {
            ..Default::default()
        };
        let result = search_cases(&cases, &query, 2);
        assert_eq!(result.hits.len(), 2);
    }

    #[test]
    fn hit_case_ids_extraction() {
        let cases = sample_cases();
        let query = CaseQuery {
            error_code: Some("487".to_string()),
            ..Default::default()
        };
        let result = search_cases(&cases, &query, 10);
        let ids = hit_case_ids(&result);
        assert_eq!(ids, vec!["1".to_string()]);
    }

    #[test]
    fn parse_kb_split_format() {
        let text = "DNA ID = 42\n呼叫过程:\nINVITE -> 487\n诊断结论: test\n<!-- split -->\nDNA ID = 43\n呼叫过程:\nINVITE -> 200 OK\n诊断结论: test2";
        let cases = parse_kb_cases(text);
        assert_eq!(cases.len(), 2);
        assert_eq!(cases[0].id, "42");
        assert_eq!(cases[1].id, "43");
    }

    #[test]
    fn decrypt_real_kb_and_search_503() {
        let enc_path = std::path::Path::new("..")
            .join("..")
            .join("..")
            .join("kb")
            .join("flowshark.cases.kb.zh.enc");
        let enc_data = match std::fs::read(&enc_path) {
            Ok(d) => d,
            Err(_) => return, // skip if file not found (CI)
        };
        let cases = decrypt_and_parse_kb(&enc_data).expect("decrypt should succeed");
        assert!(cases.len() > 100, "real KB should have many cases, got {}", cases.len());

        // Check that some cases have non-empty call_process
        let with_cp = cases.iter().filter(|c| !c.call_process.is_empty()).count();
        eprintln!("total cases: {}, with call_process: {}", cases.len(), with_cp);

        // Search for error_code 503
        let query = CaseQuery {
            error_code: Some("503".to_string()),
            ..Default::default()
        };
        let result = search_cases(&cases, &query, 10);
        eprintln!("trace: {:#?}", result.trace);
        eprintln!("hits: {}", result.hits.len());

        // The error_code step should have applied (filtered something)
        let ec_trace = result.trace.iter().find(|t| t.step == "error_code");
        if let Some(ec) = ec_trace {
            eprintln!("error_code trace: before={}, after={}, applied={}", ec.before, ec.after, ec.applied);
            assert!(ec.applied, "error_code filter should apply when 503 exists in KB");
        }

        assert!(result.hits.len() > 0, "should find at least one 503 case");
    }

    #[test]
    fn decrypt_real_kb_and_check_call_side() {
        let enc_path = std::path::Path::new("..")
            .join("..")
            .join("..")
            .join("kb")
            .join("flowshark.cases.kb.zh.enc");
        let enc_data = match std::fs::read(&enc_path) {
            Ok(d) => d,
            Err(_) => return, // skip if file not found (CI)
        };
        let cases = decrypt_and_parse_kb(&enc_data).expect("decrypt should succeed");
        
        // 统计能识别出呼叫侧的案例数量
        let mut caller_count = 0;
        let mut callee_count = 0;
        let mut unknown_count = 0;
        
        for c in &cases {
            match case_call_side(c) {
                Some(side) if side == "caller" => caller_count += 1,
                Some(side) if side == "callee" => callee_count += 1,
                _ => unknown_count += 1,
            }
        }
        
        eprintln!("caller cases: {}", caller_count);
        eprintln!("callee cases: {}", callee_count);
        eprintln!("unknown cases: {}", unknown_count);
        
        // 打印前5个无法识别呼叫侧的案例
        for (i, c) in cases.iter().filter(|c| case_call_side(c).is_none()).take(5).enumerate() {
            eprintln!("Unknown case {}: id={}, flag={:?}, first_line={:?}", 
                i, c.id, c.flag, c.call_process.first());
        }
        
        assert!(caller_count > 100, "should have many caller cases, got {}", caller_count);
        assert!(callee_count > 100, "should have many callee cases, got {}", callee_count);
    }

    #[test]
    fn decrypt_real_kb_and_search_caller_with_503() {
        let enc_path = std::path::Path::new("..")
            .join("..")
            .join("..")
            .join("kb")
            .join("flowshark.cases.kb.zh.enc");
        let enc_data = match std::fs::read(&enc_path) {
            Ok(d) => d,
            Err(_) => return, // skip if file not found (CI)
        };
        let cases = decrypt_and_parse_kb(&enc_data).expect("decrypt should succeed");
        
        // 测试：主叫侧 + 响应码503
        let query = CaseQuery {
            call_side: Some("caller".to_string()),
            sip_response_code: Some("503".to_string()),
            ..Default::default()
        };
        let result = search_cases(&cases, &query, 1000);
        eprintln!("caller + sip_response_code=503: {} hits", result.hits.len());
        eprintln!("trace: {:#?}", result.trace);
        
        // 测试：主叫侧 + error_code 503
        let query2 = CaseQuery {
            call_side: Some("caller".to_string()),
            error_code: Some("503".to_string()),
            ..Default::default()
        };
        let result2 = search_cases(&cases, &query2, 1000);
        eprintln!("caller + error_code=503: {} hits", result2.hits.len());
        eprintln!("trace2: {:#?}", result2.trace);
        
        // 测试：被叫侧 + 响应码503
        let query3 = CaseQuery {
            call_side: Some("callee".to_string()),
            sip_response_code: Some("503".to_string()),
            ..Default::default()
        };
        let result3 = search_cases(&cases, &query3, 1000);
        eprintln!("callee + sip_response_code=503: {} hits", result3.hits.len());
        eprintln!("trace3: {:#?}", result3.trace);
    }
}
