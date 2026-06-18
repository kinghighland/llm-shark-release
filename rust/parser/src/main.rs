use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{anyhow, Result};
use chrono::Timelike;
use clap::Parser;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[cfg(windows)]
use std::os::windows::process::CommandExt;
use std::time::{Duration, Instant};

#[derive(Parser, Debug)]
#[command(
    name = "parser",
    about = "Parse Wireshark PCAP/text output and generate report."
)]
struct Args {
    #[arg(long)]
    license: Option<String>,
    #[arg(short = 'p', long)]
    pcap: Option<String>,

    #[arg(short = 't', long)]
    text: Option<String>,

    #[arg(
        short = 'f',
        long,
        default_value = "(sip || gtpv2 || s1ap || ngap || diameter || gtp || rtcp || bicc || isup || bssap || ranap) && !(tcp.analysis.retransmission)"
    )]
    filter: String,

    #[arg(short = 'j', long)]
    json: Option<String>,

    #[arg(long)]
    csv: Option<String>,

    #[arg(short = 'm', long)]
    mermaid: Option<String>,

    #[arg(short = 'l', long, default_value_t = 100)]
    limit: usize,

    #[arg(long)]
    tshark: Option<String>,

    #[arg(long, default_value_t = 500)]
    max_size_kb: u64,

    #[arg(long)]
    summary: bool,

    #[arg(long)]
    kb_user_path: Option<String>,

    #[arg(long, default_value_t = 10)]
    kb_max: usize,

    #[arg(long)]
    no_kb: bool,

    #[arg(long)]
    debug_tshark: bool,

    #[arg(long)]
    analysis_json: Option<String>,

    #[arg(long)]
    report_json: Option<String>,

    #[arg(long)]
    ui_lang: Option<String>,

    #[arg(long)]
    xdr: Option<String>,

    #[arg(long)]
    fshark: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct SipDetails {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    to: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    status_code: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reason_phrase: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    call_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cseq: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cseq_method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cseq_number: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    p_called_party_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    via_count: Option<i64>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    request_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    request_uri_host: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    via_top: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    via_sent_by: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    route_top: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    route_host: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    record_route_host: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct S1apDetails {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    service_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct Details {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sip: Option<SipDetails>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    s1ap: Option<S1apDetails>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Packet {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    frame: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    timestamp: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    src: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dst: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    src_entity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dst_entity: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cause: Option<String>,
    #[serde(default)]
    details: Details,
    #[serde(default)]
    underlying_protocols: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct Query {
    error_code: Option<String>,
    has_180: bool,
    has_200_invite: bool,
    has_ack_200: bool,
    has_cancel: bool,
    call_side: Option<String>,
    call_type: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct FailurePoint {
    protocol: Option<String>,
    message: Option<String>,
    cause: Option<String>,
    timestamp: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct AnalysisReport {
    call_flow_type: String,
    call_status: String,
    call_side: Option<String>,
    call_parties: CallParties,
    failure_reason: Option<String>,
    failure_point: Option<FailurePoint>,
    error_frames: Vec<u64>,
}

#[derive(Debug, Clone, Serialize)]
struct CallParties {
    from: Option<String>,
    to: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
enum KbSourceType {
    Builtin,
    User,
}

#[derive(Debug, Clone, Serialize)]
struct KbSourceInfo {
    source_type: KbSourceType,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    total: usize,
}

#[derive(Debug, Clone)]
struct KbBuiltinLoad {
    cases: Option<Vec<KbCase>>,
    source: Option<KbSourceInfo>,
    warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct KbCase {
    id: String,
    source_type: KbSourceType,
    source_name: String,
    dna_id: Option<String>,
    flag: Option<String>,
    call_process: Vec<String>,
    issue_location: Option<String>,
    diagnosis: Option<String>,
    root_cause: Option<String>,
    case_numbers: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct KbHit {
    id: String,
    source_type: KbSourceType,
    source_name: String,
    dna_id: Option<String>,
    case_numbers: Option<String>,
    signal_count: usize,
    has_180: bool,
    call_type: Option<String>,
    issue_location: Option<String>,
    diagnosis: Option<String>,
    root_cause: Option<String>,
    call_process: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct KbFilterTrace {
    step: String,
    criteria: Option<String>,
    before: usize,
    after: usize,
    applied: bool,
}

#[derive(Debug, Clone, Serialize)]
struct KbPayload {
    notice: String,
    enabled: bool,
    sources: Vec<KbSourceInfo>,
    total_merged: usize,
    query: Query,
    trace: Vec<KbFilterTrace>,
    hits: Vec<KbHit>,
    warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct Outputs {
    #[serde(skip_serializing_if = "Option::is_none")]
    decoded_text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signaling_csv: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signaling_json: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mermaid: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct Report {
    summary: Option<serde_json::Value>,
    analysis: AnalysisReport,
    kb: Option<KbPayload>,
    outputs: Outputs,
    mermaid_text: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    ip_to_entity: Option<HashMap<String, String>>,
}

fn format_timestamp(ts: &str) -> String {
    let re_hms = Regex::new(r"(\d{2}):(\d{2}):(\d{2})\.(\d+)").unwrap();
    if let Some(cap) = re_hms.captures(ts) {
        let h = cap.get(1).unwrap().as_str();
        let m = cap.get(2).unwrap().as_str();
        let s = cap.get(3).unwrap().as_str();
        let mut ms = cap.get(4).unwrap().as_str().to_string();
        if ms.len() > 3 {
            ms.truncate(3);
        }
        while ms.len() < 3 {
            ms.push('0');
        }
        return format!("{h}:{m}:{s}.{ms}");
    }

    let re_epoch = Regex::new(r"^(\d+)\.(\d+)$").unwrap();
    if let Some(cap) = re_epoch.captures(ts.trim()) {
        if let Ok(sec) = cap.get(1).unwrap().as_str().parse::<i64>() {
            let mut ms = cap.get(2).unwrap().as_str().to_string();
            if ms.len() > 3 {
                ms.truncate(3);
            }
            while ms.len() < 3 {
                ms.push('0');
            }
            if let Some(dt) = chrono::DateTime::<chrono::Utc>::from_timestamp(sec, 0) {
                let dt = dt.with_timezone(&chrono::Local);
                return dt.format(&format!("%H:%M:%S.{ms}")).to_string();
            }
        }
    }

    ts.to_string()
}

fn parse_time_ms(s: &str) -> Option<i64> {
    let t = s.trim();
    if t.is_empty() {
        return None;
    }

    if t.contains(':') {
        // Example: 10:39:49.577
        if let Ok(nt) = chrono::NaiveTime::parse_from_str(t, "%H:%M:%S%.f") {
            let sec = nt.num_seconds_from_midnight() as i64;
            let ms = nt.nanosecond() as i64 / 1_000_000;
            return Some(sec * 1000 + ms);
        }
        return None;
    }

    // Example: epoch seconds: 1493692789.577000000
    if let Ok(v) = t.parse::<f64>() {
        return Some((v * 1000.0) as i64);
    }

    None
}

fn contains_code_with_nondigit_bounds(s: &str, code: &str) -> bool {
    if code.is_empty() {
        return false;
    }
    let s_bytes = s.as_bytes();
    let code_len = code.len();
    if code_len == 0 || code_len > s_bytes.len() {
        return false;
    }

    for (idx, _) in s.match_indices(code) {
        let before_is_digit = if idx == 0 {
            false
        } else {
            let b = s_bytes[idx - 1];
            b.is_ascii_digit()
        };
        let after_is_digit = {
            let end = idx + code_len;
            if end >= s_bytes.len() {
                false
            } else {
                let b = s_bytes[end];
                b.is_ascii_digit()
            }
        };
        if !before_is_digit && !after_is_digit {
            return true;
        }
    }
    false
}

fn infer_call_type(packets: &[Packet]) -> Option<String> {
    let csfb_re = Regex::new(r"CSFB|CS\s*Fallback|Circuit\s*Switched").ok()?;
    let esr_re = Regex::new(r"Extended\s+service\s+request").ok()?;
    let mut protos: HashSet<&str> = HashSet::new();
    for p in packets {
        if let Some(pr) = p.protocol.as_deref() {
            protos.insert(pr);
        }
    }

    let has_sip = protos.contains("SIP");
    let has_s1ap = protos.contains("S1AP");
    let has_ngap = protos.contains("NGAP");

    if has_sip && has_ngap && has_s1ap {
        return Some("EPSFB".to_string());
    }
    if has_sip && has_ngap {
        return Some("VoNR".to_string());
    }
    if has_sip && has_s1ap {
        for p in packets {
            if p.protocol.as_deref() != Some("S1AP") {
                continue;
            }
            let msg = p.message.as_deref().unwrap_or("");
            if csfb_re.is_match(msg) {
                return Some("CSFB".to_string());
            }
            if esr_re.is_match(msg) {
                return Some("EPSFB".to_string());
            }
        }
        return Some("VoLTE".to_string());
    }
    if has_sip {
        return Some("VoLTE".to_string());
    }
    None
}

fn analyze_signaling(packets: &[Packet]) -> AnalysisReport {
    let re_q850 = Regex::new(r"(?i)q\.?850\s*;\s*cause\s*=\s*(\d+)").unwrap();
    let re_sip = Regex::new(r"(?i)sip\s*;\s*cause\s*=\s*(\d+)").unwrap();
    let mut call_flow_type = "unknown".to_string();
    let mut call_parties = CallParties {
        from: None,
        to: None,
    };

    let sip_packets: Vec<&Packet> = packets
        .iter()
        .filter(|p| p.protocol.as_deref() == Some("SIP"))
        .collect();

    for p in &sip_packets {
        let sip = p.details.sip.as_ref();
        let method = sip
            .and_then(|s| s.method.as_deref())
            .or(p.message.as_deref())
            .unwrap_or("");
        if method == "INVITE" {
            call_flow_type = "call_setup".to_string();
            if let Some(s) = sip {
                call_parties.from = s.from.clone();
                call_parties.to = s.to.clone();
            }
            break;
        }
        if method == "REGISTER" {
            call_flow_type = "registration".to_string();
        }
    }

    let mut error_frames: Vec<u64> = vec![];
    let mut failure_reason: Option<String> = None;
    let mut failure_point: Option<FailurePoint> = None;

    for p in &sip_packets {
        let sip = p.details.sip.as_ref();
        let method = sip
            .and_then(|s| s.method.as_deref())
            .or(p.message.as_deref())
            .unwrap_or("");
        let status_code = sip.and_then(|s| s.status_code);

        if method == "CANCEL" {
            if let Some(f) = p.frame {
                error_frames.push(f);
            }
            if failure_reason.is_none() {
                failure_reason = Some("检测到 SIP CANCEL".to_string());
                failure_point = Some(FailurePoint {
                    protocol: p.protocol.clone(),
                    message: p.message.clone(),
                    cause: p.cause.clone(),
                    timestamp: p.timestamp.clone(),
                });
            }
            continue;
        }

        if let Some(sc) = status_code {
            if sc >= 400 {
                if let Some(f) = p.frame {
                    error_frames.push(f);
                }
                if failure_reason.is_none() {
                    failure_reason = Some(format!("检测到 SIP {} 错误响应", sc));
                    failure_point = Some(FailurePoint {
                        protocol: p.protocol.clone(),
                        message: p.message.clone(),
                        cause: p.cause.clone(),
                        timestamp: p.timestamp.clone(),
                    });
                }
                continue;
            }
        }

        if method == "BYE" {
            let reason_h = sip.and_then(|s| s.reason.as_deref()).unwrap_or("");
            let mut bye_error = false;
            if let Some(cap) = re_q850.captures(reason_h) {
                if let Ok(q850) = cap.get(1).unwrap().as_str().parse::<i64>() {
                    if q850 != 16 {
                        bye_error = true;
                    }
                }
            }
            if let Some(cap) = re_sip.captures(reason_h) {
                if let Ok(sc) = cap.get(1).unwrap().as_str().parse::<i64>() {
                    if sc >= 400 {
                        bye_error = true;
                    }
                }
            }

            if bye_error {
                if let Some(f) = p.frame {
                    error_frames.push(f);
                }
                if failure_reason.is_none() {
                    failure_reason = Some("检测到 BYE 携带错误码".to_string());
                    failure_point = Some(FailurePoint {
                        protocol: p.protocol.clone(),
                        message: p.message.clone(),
                        cause: p.cause.clone(),
                        timestamp: p.timestamp.clone(),
                    });
                }
            }
        }
    }

    let mut first_200_invite_ms: Option<i64> = None;
    let mut has_ack = false;
    for p in &sip_packets {
        let sip = p.details.sip.as_ref();
        let status_code = sip.and_then(|s| s.status_code);
        let cseq_method = sip.and_then(|s| s.cseq_method.as_deref());
        let cseq = sip.and_then(|s| s.cseq.as_deref()).unwrap_or("");
        if status_code == Some(200) {
            let is_200_invite = cseq_method == Some("INVITE") || cseq.contains("INVITE");
            if is_200_invite {
                let ms = p.timestamp.as_deref().and_then(parse_time_ms);
                if let Some(v) = ms {
                    first_200_invite_ms = Some(first_200_invite_ms.map_or(v, |cur| cur.min(v)));
                } else if first_200_invite_ms.is_none() {
                    first_200_invite_ms = None;
                }
            }
        }
        let method = sip
            .and_then(|s| s.method.as_deref())
            .or(p.message.as_deref())
            .unwrap_or("");
        if method == "ACK" {
            has_ack = true;
        }
    }

    let mut has_ack_200 = false;
    if has_ack {
        if let Some(b) = first_200_invite_ms {
            for p in &sip_packets {
                let method = p
                    .details
                    .sip
                    .as_ref()
                    .and_then(|s| s.method.as_deref())
                    .or(p.message.as_deref())
                    .unwrap_or("");
                if method != "ACK" {
                    continue;
                }
                let ms = p.timestamp.as_deref().and_then(parse_time_ms);
                match ms {
                    Some(a) if a >= b => {
                        has_ack_200 = true;
                        break;
                    }
                    None => {
                        has_ack_200 = true;
                        break;
                    }
                    _ => {}
                }
            }
        } else {
            has_ack_200 = true;
        }
    }

    let call_status = if failure_reason.is_some() {
        "failure".to_string()
    } else if has_ack_200 {
        "success".to_string()
    } else {
        "unknown".to_string()
    };

    AnalysisReport {
        call_flow_type,
        call_status,
        call_side: infer_call_side(packets),
        call_parties,
        failure_reason,
        failure_point,
        error_frames,
    }
}

fn infer_call_side(packets: &[Packet]) -> Option<String> {
    // Priority: INVITE -> ESR -> Service Notification
    let esr_re = Regex::new(r"Extended\s+service\s+request").ok()?;
    let mo_re = Regex::new(r"\bmo\b").ok()?;
    let mt_re = Regex::new(r"\bmt\b").ok()?;
    let svc_notif_re = Regex::new(r"Service\s+notification").ok()?;

    for p in packets {
        if p.protocol.as_deref() != Some("SIP") {
            continue;
        }
        let Some(sip) = p.details.sip.as_ref() else {
            continue;
        };
        let method = sip.method.as_deref().or(p.message.as_deref()).unwrap_or("");
        if method != "INVITE" {
            continue;
        }

        if !sip
            .p_called_party_id
            .as_deref()
            .unwrap_or("")
            .trim()
            .is_empty()
        {
            return Some("callee".to_string());
        }

        match sip.via_count {
            Some(1) => {
                let ipv6 = p
                    .underlying_protocols
                    .iter()
                    .any(|x| x == "IPv6")
                    || p.src.as_deref().map(|v| v.contains(':')).unwrap_or(false)
                    || p.dst.as_deref().map(|v| v.contains(':')).unwrap_or(false);
                if ipv6 {
                    return Some("caller".to_string());
                } else {
                    continue;
                }
            }
            Some(n) if n > 1 => return Some("callee".to_string()),
            _ => continue,
        }
    }

    for p in packets {
        let pr = p.protocol.as_deref();
        if pr != Some("S1AP") && pr != Some("NGAP") {
            continue;
        }
        let msg = p.message.as_deref().unwrap_or("");
        if !esr_re.is_match(msg) {
            continue;
        }

        let svc = p
            .details
            .s1ap
            .as_ref()
            .and_then(|d| d.service_type.as_deref())
            .unwrap_or("");
        let s = svc.to_ascii_lowercase();
        if s.contains("mobile originating") || mo_re.is_match(&s) {
            return Some("caller".to_string());
        }
        if s.contains("mobile terminated") || mt_re.is_match(&s) {
            return Some("callee".to_string());
        }
    }

    for p in packets {
        let pr = p.protocol.as_deref();
        if pr != Some("S1AP") && pr != Some("NGAP") {
            continue;
        }
        let msg = p.message.as_deref().unwrap_or("");
        if svc_notif_re.is_match(msg) {
            return Some("callee".to_string());
        }
    }

    None
}

fn extract_query(packets: &[Packet], analysis: &AnalysisReport) -> Query {
    let mut has_180 = false;
    let mut has_cancel = false;
    let mut has_200_invite = false;
    let mut has_ack = false;

    let mut first_200_invite_ms: Option<i64> = None;

    for p in packets {
        if p.protocol.as_deref() != Some("SIP") {
            continue;
        }

        let sip = p.details.sip.as_ref();
        let method = sip
            .and_then(|s| s.method.as_deref())
            .or(p.message.as_deref());
        let status_code = sip.and_then(|s| s.status_code);
        let cseq_method = sip.and_then(|s| s.cseq_method.as_deref());
        let cseq = sip.and_then(|s| s.cseq.as_deref()).unwrap_or("");

        if method == Some("CANCEL") {
            has_cancel = true;
        }
        if method == Some("ACK") {
            has_ack = true;
        }

        if status_code == Some(180) || p.message.as_deref().unwrap_or("").starts_with("180") {
            has_180 = true;
        }

        if status_code == Some(200) {
            let is_200_invite = cseq_method == Some("INVITE") || cseq.contains("INVITE");
            if is_200_invite {
                has_200_invite = true;
                let ms = p.timestamp.as_deref().and_then(parse_time_ms);
                if let Some(v) = ms {
                    first_200_invite_ms = Some(first_200_invite_ms.map_or(v, |cur| cur.min(v)));
                }
            }
        }
    }

    let mut has_ack_200 = false;
    if has_200_invite && has_ack {
        if first_200_invite_ms.is_none() {
            has_ack_200 = true;
        } else {
            for p in packets {
                if p.protocol.as_deref() != Some("SIP") {
                    continue;
                }
                let sip = p.details.sip.as_ref();
                let method = sip
                    .and_then(|s| s.method.as_deref())
                    .or(p.message.as_deref())
                    .unwrap_or("");
                if method != "ACK" {
                    continue;
                }
                let ms = p.timestamp.as_deref().and_then(parse_time_ms);
                match (ms, first_200_invite_ms) {
                    (Some(a), Some(b)) if a >= b => {
                        has_ack_200 = true;
                        break;
                    }
                    (None, Some(_)) => {
                        has_ack_200 = true;
                        break;
                    }
                    _ => {}
                }
            }
        }
    }

    let mut error_code: Option<String> = None;
    if let Some(fp) = analysis.failure_point.as_ref() {
        let msg = fp.message.as_deref().unwrap_or("").trim().to_string();
        if !msg.is_empty() {
            let re = Regex::new(r"^(\d{3})\b").unwrap();
            if let Some(cap) = re.captures(&msg) {
                error_code = cap.get(1).map(|m| m.as_str().to_string());
            }
        }
        if error_code.is_none() {
            let cause = fp.cause.as_deref().unwrap_or("");
            let re = Regex::new(r"\b(\d{3})\b").unwrap();
            if let Some(cap) = re.captures(cause) {
                error_code = cap.get(1).map(|m| m.as_str().to_string());
            }
        }
    }

    Query {
        error_code,
        has_180,
        has_200_invite,
        has_ack_200,
        has_cancel,
        call_side: infer_call_side(packets),
        call_type: infer_call_type(packets),
    }
}

fn kb_case_fingerprint(
    flag: &Option<String>,
    call_process: &[String],
    issue_location: &Option<String>,
    diagnosis: &Option<String>,
    root_cause: &Option<String>,
    case_numbers: &Option<String>,
) -> String {
    let mut h = Sha256::new();
    if let Some(v) = flag.as_deref() {
        h.update(v.as_bytes());
    }
    h.update(&[0]);
    if let Some(v) = case_numbers.as_deref() {
        h.update(v.as_bytes());
    }
    h.update(&[0]);
    if let Some(v) = issue_location.as_deref() {
        h.update(v.as_bytes());
    }
    h.update(&[0]);
    if let Some(v) = diagnosis.as_deref() {
        h.update(v.as_bytes());
    }
    h.update(&[0]);
    if let Some(v) = root_cause.as_deref() {
        h.update(v.as_bytes());
    }
    h.update(&[0]);
    for l in call_process {
        h.update(l.as_bytes());
        h.update(&[0]);
    }
    format!("sha256:{}", hex::encode(h.finalize()))
}

fn kb_section(block: &str, names: &[&str]) -> Option<String> {
    let mut start: Option<usize> = None;
    let mut end: Option<usize> = None;

    for (idx, line) in block.lines().enumerate() {
        let t = line.trim();
        if start.is_none() {
            if let Some(rest) = t.strip_prefix("##") {
                let title = rest.trim();
                if names.iter().any(|name| title.eq_ignore_ascii_case(name)) {
                    start = Some(idx + 1);
                }
            }
            continue;
        }

        if t.starts_with("##") {
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

fn kb_parse_cases(text: &str, source_type: KbSourceType, source_name: &str) -> Result<Vec<KbCase>> {
    let text = text.replace("\r\n", "\n").replace('\r', "\n");
    let parts: Vec<&str> = text
        .split("<!-- split -->")
        .map(|p| p.trim())
        .filter(|p| !p.is_empty())
        .collect();

    let re_dna = Regex::new(r"DNA ID\s*=\s*(\d+)")?;
    let re_flag = Regex::new(r"Flag(?:\s*值)?\s*=\s*(.+)")?;

    let mut cases: Vec<KbCase> = vec![];
    for block in parts {
        let dna_id = re_dna
            .captures(block)
            .and_then(|c| c.get(1).map(|m| m.as_str().to_string()));
        let flag = re_flag
            .captures(block)
            .and_then(|c| c.get(1).map(|m| m.as_str().trim().to_string()));

        let mut call_process: Vec<String> = vec![];
        if let Some(cp) = kb_section(block, &["呼叫过程", "Call Process"]) {
            call_process = cp
                .lines()
                .map(|l| l.trim())
                .filter(|l| !l.is_empty())
                .map(|l| l.to_string())
                .collect();
        }

        let issue_location = kb_section(block, &["问题定位", "Problem location"]);
        let diagnosis = kb_section(block, &["诊断结论", "Diagnosis"]);
        let root_cause = kb_section(block, &["根因分析", "Root cause"]);
        let case_numbers = kb_section(block, &["案例编号", "Case IDs"]);

        let id = match &source_type {
            KbSourceType::Builtin => dna_id
                .clone()
                .filter(|v| !v.trim().is_empty())
                .unwrap_or_else(|| {
                    kb_case_fingerprint(
                        &flag,
                        &call_process,
                        &issue_location,
                        &diagnosis,
                        &root_cause,
                        &case_numbers,
                    )
                }),
            KbSourceType::User => kb_case_fingerprint(
                &flag,
                &call_process,
                &issue_location,
                &diagnosis,
                &root_cause,
                &case_numbers,
            ),
        };

        cases.push(KbCase {
            id,
            source_type: source_type.clone(),
            source_name: source_name.to_string(),
            dna_id,
            flag,
            call_process,
            issue_location,
            diagnosis,
            root_cause,
            case_numbers,
        });
    }

    Ok(cases)
}

fn kb_load_cases_from_file(
    path: &str,
    source_type: KbSourceType,
    source_name: &str,
) -> Result<Vec<KbCase>> {
    let text = fs::read_to_string(path)?;
    kb_parse_cases(&text, source_type, source_name)
}

fn kb_find_file(candidates: &[PathBuf], file_name: &str) -> Option<PathBuf> {
    for b in candidates {
        let p = b.join(file_name);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

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

fn kb_decrypt_builtin(enc: &[u8]) -> Result<String> {
    if enc.len() < 12 + 16 {
        return Err(anyhow!("builtin kb enc too short"));
    }
    let nonce = Nonce::from_slice(&enc[..12]);
    let ciphertext = &enc[12..];
    let cipher = Aes256Gcm::new_from_slice(&kb_builtin_key())
        .map_err(|e| anyhow!("kb key init failed: {e}"))?;
    let plain = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow!("builtin kb decrypt failed"))?;
    String::from_utf8(plain).map_err(|e| anyhow!("builtin kb utf8 failed: {e}"))
}

fn kb_load_builtin_cases(ui_lang: Option<&str>) -> Result<KbBuiltinLoad> {
    let name = "builtin_cases";
    let mut warnings: Vec<String> = vec![];

    let mut bases: Vec<PathBuf> = Vec::new();
    if let Ok(exe) = env::current_exe() {
        if let Some(dir) = exe.parent() {
            bases.push(dir.to_path_buf());
            bases.push(dir.join("kb"));
            bases.push(dir.join("..").join("kb"));
        }
    }
    if let Ok(cwd) = env::current_dir() {
        bases.push(cwd.clone());
        bases.push(cwd.join("kb"));
    }
    bases.push(PathBuf::from("..\\..\\kb"));

    let mut targets = Vec::new();
    let lang = ui_lang.unwrap_or("zh-Hans").trim();
    let lang_lower = lang.to_lowercase();
    let is_zh = lang.eq_ignore_ascii_case("zh") || lang_lower.starts_with("zh-");

    if is_zh {
        targets.push("flowshark.cases.kb.enc".to_string());
        targets.push("flowshark.cases.kb.en.enc".to_string());
    } else {
        if !lang_lower.starts_with("en") {
            targets.push(format!("flowshark.cases.kb.{}.enc", lang));
            if let Some((prefix, _)) = lang.split_once('-') {
                targets.push(format!("flowshark.cases.kb.{}.enc", prefix));
            }
        }
        targets.push("flowshark.cases.kb.en.enc".to_string());
        // 添加回退：如果英文版不存在，使用中文版
        targets.push("flowshark.cases.kb.enc".to_string()); 
    }

    let mut dedup = Vec::new();
    for t in targets {
        if !dedup.contains(&t) {
            dedup.push(t);
        }
    }

    let mut tried: Vec<String> = vec![];
    for filename in dedup {
        tried.push(filename.clone());
        if let Some(p) = kb_find_file(&bases, &filename) {
            let enc = fs::read(&p)?;
            let text = kb_decrypt_builtin(&enc)?;
            let cases = kb_parse_cases(&text, KbSourceType::Builtin, name)?;
            let total = cases.len();
            return Ok(KbBuiltinLoad {
                cases: Some(cases),
                source: Some(KbSourceInfo {
                    source_type: KbSourceType::Builtin,
                    name: name.to_string(),
                    path: Some(p.to_string_lossy().to_string()),
                    total,
                }),
                warnings,
            });
        }
    }

    if cfg!(debug_assertions) && is_zh {
        if let Some(p) = kb_find_file(&bases, "flowshark.cases.kb.md") {
            let text = fs::read_to_string(&p)?;
            let cases = kb_parse_cases(&text, KbSourceType::Builtin, name)?;
            let total = cases.len();
            return Ok(KbBuiltinLoad {
                cases: Some(cases),
                source: Some(KbSourceInfo {
                    source_type: KbSourceType::Builtin,
                    name: name.to_string(),
                    path: Some(p.to_string_lossy().to_string()),
                    total,
                }),
                warnings,
            });
        }
    }

    if !tried.is_empty() {
        warnings.push(format!(
            "builtin kb not found for ui_lang={lang}, tried={}",
            tried.join(",")
        ));
    } else {
        warnings.push(format!("builtin kb not found for ui_lang={lang}"));
    }
    Ok(KbBuiltinLoad {
        cases: None,
        source: None,
        warnings,
    })
}

fn kb_case_signal_count(c: &KbCase) -> usize {
    let re = Regex::new(r"^\d+\.").unwrap();
    c.call_process.iter().filter(|l| re.is_match(l)).count()
}

fn kb_case_has_180(c: &KbCase) -> bool {
    c.call_process.iter().any(|l| {
        l.contains("180")
            || l.contains("回铃")
            || l.contains("回鈴")
            || Regex::new(r"(?i)\b(ringback|ringing)\b").unwrap().is_match(l)
    })
}

fn kb_case_has_200_invite(c: &KbCase) -> bool {
    c.call_process.iter().any(|l| {
        contains_code_with_nondigit_bounds(l, "200")
            && Regex::new(r"(?i)\bOK\b").unwrap().is_match(l)
            && Regex::new(r"(?i)Invite").unwrap().is_match(l)
    })
}

fn kb_case_has_ack_200(c: &KbCase) -> bool {
    c.call_process.iter().any(|l| {
        contains_code_with_nondigit_bounds(l, "200")
            && Regex::new(r"(?i)\bACK\b").unwrap().is_match(l)
    })
}

fn kb_case_has_cancel(c: &KbCase) -> bool {
    c.call_process.iter().any(|l| {
        l.contains("取消")
            || Regex::new(r"(?i)\bCANCEL\b").unwrap().is_match(l)
            || Regex::new(r"(?i)\bcancell?ed\b").unwrap().is_match(l)
    })
}

fn kb_case_call_side(c: &KbCase) -> Option<String> {
    let re_caller = Regex::new(r"(?i)\b(MO|caller|calling party)\b").unwrap();
    let re_callee = Regex::new(r"(?i)\b(MT|callee|called party)\b").unwrap();
    for l in &c.call_process {
        if l.contains("主叫") || re_caller.is_match(l) {
            return Some("caller".to_string());
        }
        if l.contains("被叫") || re_callee.is_match(l) {
            return Some("callee".to_string());
        }
    }
    None
}

fn kb_case_call_type(c: &KbCase) -> Option<String> {
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

fn kb_search<'a>(
    cases: &'a [KbCase],
    query: &Query,
    max_results: usize,
) -> (Vec<&'a KbCase>, Vec<KbFilterTrace>) {
    let mut candidates: Vec<&KbCase> = cases.iter().collect();
    let mut trace: Vec<KbFilterTrace> = vec![];

    trace.push(KbFilterTrace {
        step: "init".to_string(),
        criteria: None,
        before: candidates.len(),
        after: candidates.len(),
        applied: true,
    });

    if let Some(ec) = query.error_code.as_deref() {
        let before = candidates.len();
        let prev = candidates;
        let filtered: Vec<&KbCase> = prev
            .iter()
            .copied()
            .filter(|c| {
                c.call_process
                    .iter()
                    .any(|l| contains_code_with_nondigit_bounds(l, ec))
            })
            .collect();
        let applied = !filtered.is_empty();
        candidates = if applied { filtered } else { prev };
        trace.push(KbFilterTrace {
            step: "error_code".to_string(),
            criteria: Some(ec.to_string()),
            before,
            after: candidates.len(),
            applied,
        });
    }

    if candidates.len() > max_results {
        let before = candidates.len();
        let want_180 = query.has_180;
        let filtered: Vec<&KbCase> = candidates
            .iter()
            .copied()
            .filter(|c| kb_case_has_180(c) == want_180)
            .collect();
        let applied = !filtered.is_empty();
        if applied {
            candidates = filtered;
        }
        trace.push(KbFilterTrace {
            step: "has_180".to_string(),
            criteria: Some(format!("{}", want_180)),
            before,
            after: candidates.len(),
            applied,
        });
    }

    if candidates.len() >= max_results {
        if let Some(side) = query.call_side.as_deref() {
            let before = candidates.len();
            let filtered: Vec<&KbCase> = candidates
                .iter()
                .copied()
                .filter(|c| kb_case_call_side(c).as_deref() == Some(side))
                .collect();
            let applied = !filtered.is_empty();
            if applied {
                candidates = filtered;
            }
            trace.push(KbFilterTrace {
                step: "call_side".to_string(),
                criteria: Some(side.to_string()),
                before,
                after: candidates.len(),
                applied,
            });
        }
    }

    if candidates.len() > max_results {
        let before = candidates.len();
        let want_200 = query.has_200_invite;
        let filtered: Vec<&KbCase> = candidates
            .iter()
            .copied()
            .filter(|c| kb_case_has_200_invite(c) == want_200)
            .collect();
        let applied = !filtered.is_empty();
        if applied {
            candidates = filtered;
        }
        trace.push(KbFilterTrace {
            step: "has_200_invite".to_string(),
            criteria: Some(format!("{}", want_200)),
            before,
            after: candidates.len(),
            applied,
        });
    }

    if candidates.len() > max_results {
        let before = candidates.len();
        let want_ack_200 = query.has_ack_200;
        let filtered: Vec<&KbCase> = candidates
            .iter()
            .copied()
            .filter(|c| kb_case_has_ack_200(c) == want_ack_200)
            .collect();
        let applied = !filtered.is_empty();
        if applied {
            candidates = filtered;
        }
        trace.push(KbFilterTrace {
            step: "has_ack_200".to_string(),
            criteria: Some(format!("{}", want_ack_200)),
            before,
            after: candidates.len(),
            applied,
        });
    }

    if candidates.len() > max_results {
        let before = candidates.len();
        let want_cancel = query.has_cancel;
        let filtered: Vec<&KbCase> = candidates
            .iter()
            .copied()
            .filter(|c| kb_case_has_cancel(c) == want_cancel)
            .collect();
        let applied = !filtered.is_empty();
        if applied {
            candidates = filtered;
        }
        trace.push(KbFilterTrace {
            step: "has_cancel".to_string(),
            criteria: Some(format!("{}", want_cancel)),
            before,
            after: candidates.len(),
            applied,
        });
    }

    if candidates.len() > max_results {
        if let Some(ct) = query.call_type.as_deref() {
            let before = candidates.len();
            let want = call_type_set(ct);
            let mut applied = false;
            if !want.is_empty() {
                let filtered: Vec<&KbCase> = candidates
                    .iter()
                    .copied()
                    .filter(|c| {
                        let got = kb_case_call_type(c)
                            .map(|v| call_type_set(&v))
                            .unwrap_or_default();
                        !got.is_disjoint(&want)
                    })
                    .collect();
                applied = !filtered.is_empty();
                if applied {
                    candidates = filtered;
                }
            }
            trace.push(KbFilterTrace {
                step: "call_type".to_string(),
                criteria: Some(ct.to_string()),
                before,
                after: candidates.len(),
                applied,
            });
        }
    }

    candidates.sort_by_key(|c| std::cmp::Reverse(kb_case_signal_count(c)));
    let before = candidates.len();
    candidates.truncate(max_results);
    trace.push(KbFilterTrace {
        step: "sort_and_truncate".to_string(),
        criteria: Some(format!("max_results={}", max_results)),
        before,
        after: candidates.len(),
        applied: true,
    });

    (candidates, trace)
}

fn resolve_tshark_path(tshark_path: Option<&str>) -> Result<PathBuf> {
    let mut candidates: Vec<String> = vec![];
    if let Some(p) = tshark_path {
        if !p.trim().is_empty() {
            candidates.push(p.to_string());
        }
    }
    if let Ok(p) = env::var("TSHARK_PATH") {
        if !p.trim().is_empty() {
            candidates.push(p);
        }
    }

    for c in candidates {
        let p = PathBuf::from(&c);
        if p.is_file() {
            return Ok(p);
        }
        if let Some(found) = which_exe(&c) {
            return Ok(found);
        }
    }

    if let Some(found) = which_exe("tshark") {
        return Ok(found);
    }
    if let Some(found) = which_exe("tshark.exe") {
        return Ok(found);
    }

    let common_paths = [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
    ];
    for p in common_paths {
        let pb = PathBuf::from(p);
        if pb.is_file() {
            return Ok(pb);
        }
    }

    Err(anyhow!(
        "找不到tshark.exe，请安装Wireshark或设置 TSHARK_PATH/--tshark"
    ))
}

fn which_exe(name: &str) -> Option<PathBuf> {
    let name = name.trim();
    if name.is_empty() {
        return None;
    }
    let p = Path::new(name);
    if p.is_file() {
        return Some(p.to_path_buf());
    }

    let path_var = env::var_os("PATH")?;
    for dir in env::split_paths(&path_var) {
        let cand = dir.join(name);
        if cand.is_file() {
            return Some(cand);
        }
        if !name.to_ascii_lowercase().ends_with(".exe") {
            let cand = dir.join(format!("{name}.exe"));
            if cand.is_file() {
                return Some(cand);
            }
        }
    }
    None
}

#[cfg(windows)]
fn apply_no_window(cmd: &mut Command) {
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    const DETACHED_PROCESS: u32 = 0x00000008;
    cmd.creation_flags(CREATE_NO_WINDOW | DETACHED_PROCESS);
}

#[cfg(not(windows))]
fn apply_no_window(_cmd: &mut Command) {}

fn run_tshark(
    pcap_file: &str,
    output_file: &str,
    filter_str: Option<&str>,
    tshark: Option<&str>,
) -> Result<()> {
    if !Path::new(pcap_file).is_file() {
        return Err(anyhow!("找不到PCAP文件: {pcap_file}"));
    }
    let tshark_bin = resolve_tshark_path(tshark)?;
    let mut cmd = Command::new(tshark_bin);
    apply_no_window(&mut cmd);
    cmd.arg("-r").arg(pcap_file).arg("-V");
    if let Some(f) = filter_str {
        if !f.trim().is_empty() {
            cmd.arg("-Y").arg(f);
        }
    }
    let out_f = fs::File::create(output_file)?;
    cmd.stdout(Stdio::from(out_f)).stderr(Stdio::piped());

    let mut child = cmd.spawn()?;
    let start = Instant::now();
    let timeout = Duration::from_secs(300);
    loop {
        if let Some(status) = child.try_wait()? {
            if status.success() {
                return Ok(());
            }
            let mut err_text = String::new();
            if let Some(mut stderr) = child.stderr.take() {
                let _ = stderr.read_to_string(&mut err_text);
            }
            return Err(anyhow!(
                "tshark执行失败(返回码{}): {}",
                status.code().unwrap_or(-1),
                err_text.trim()
            ));
        }

        if start.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(anyhow!("tshark执行超时"));
        }

        std::thread::sleep(Duration::from_millis(50));
    }
}

fn resolve_fshark_path(fshark_path: Option<&str>) -> Result<PathBuf> {
    let mut candidates: Vec<String> = vec![];
    if let Some(p) = fshark_path {
        if !p.trim().is_empty() {
            candidates.push(p.to_string());
        }
    }
    // 与 parser.exe 同目录下的 fshark.exe（实际部署时放在同一 bin/ 目录）
    if let Ok(exe) = env::current_exe() {
        if let Some(dir) = exe.parent() {
            let sibling = dir.join("fshark.exe");
            if sibling.is_file() {
                candidates.push(sibling.to_string_lossy().to_string());
            }
        }
    }
    if let Ok(p) = env::var("FSHARK_PATH") {
        if !p.trim().is_empty() {
            candidates.push(p);
        }
    }

    for c in candidates {
        let p = PathBuf::from(&c);
        if p.is_file() {
            return Ok(p);
        }
        if let Some(found) = which_exe(&c) {
            return Ok(found);
        }
    }

    if let Some(found) = which_exe("fshark") {
        return Ok(found);
    }
    if let Some(found) = which_exe("fshark.exe") {
        return Ok(found);
    }

    Err(anyhow!(
        "找不到fshark，请设置 FSHARK_PATH/--fshark"
    ))
}

fn run_fshark(
    pcap_file: &str,
    output_file: &str,
    fshark_path: Option<&str>,
) -> Result<()> {
    if !Path::new(pcap_file).is_file() {
        return Err(anyhow!("找不到PCAP文件: {pcap_file}"));
    }
    let fshark_bin = resolve_fshark_path(fshark_path)?;
    let mut cmd = Command::new(fshark_bin);
    apply_no_window(&mut cmd);
    cmd.arg("-f").arg(pcap_file).arg("-o").arg(output_file);
    cmd.stderr(Stdio::piped());

    let mut child = cmd.spawn()?;
    let start = Instant::now();
    let timeout = Duration::from_secs(300);
    loop {
        if let Some(status) = child.try_wait()? {
            if status.success() {
                return Ok(());
            }
            let mut err_text = String::new();
            if let Some(mut stderr) = child.stderr.take() {
                let _ = stderr.read_to_string(&mut err_text);
            }
            return Err(anyhow!(
                "fshark执行失败(返回码{}): {}",
                status.code().unwrap_or(-1),
                err_text.trim()
            ));
        }

        if start.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(anyhow!("fshark执行超时"));
        }

        std::thread::sleep(Duration::from_millis(50));
    }
}

fn iter_tshark_fields(
    pcap_file: &str,
    display_filter: Option<&str>,
    fields: &[&str],
    tshark: Option<&str>,
    max_packets: Option<usize>,
    debug: bool,
) -> Result<Vec<Vec<String>>> {
    let tshark_bin = resolve_tshark_path(tshark)?;
    let mut cmd = Command::new(tshark_bin);
    apply_no_window(&mut cmd);
    cmd.arg("-r").arg(pcap_file);
    if let Some(df) = display_filter {
        if !df.trim().is_empty() {
            cmd.arg("-Y").arg(df);
        }
    }
    cmd.arg("-T").arg("fields");
    for f in fields {
        cmd.arg("-e").arg(f);
    }
    cmd.arg("-E")
        .arg("separator=\t")
        .arg("-E")
        .arg("occurrence=f")
        .arg("-E")
        .arg("quote=n")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if debug {
        let pretty = format!("{cmd:?}");
        eprintln!("[tshark] {pretty}");
    }

    let mut child = cmd.spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("tshark stdout 打开失败"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow!("tshark stderr 打开失败"))?;

    let mut out_rows: Vec<Vec<String>> = vec![];
    let mut lines_emitted: usize = 0;
    let mut early_stop = false;
    {
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            let line = line.unwrap_or_default();
            out_rows.push(line.split('\t').map(|s| s.to_string()).collect());
            lines_emitted += 1;
            if let Some(max) = max_packets {
                if lines_emitted >= max {
                    early_stop = true;
                    break;
                }
            }
        }
    }

    let mut err_text = String::new();
    {
        let mut r = BufReader::new(stderr);
        let _ = r.read_to_string(&mut err_text);
    }
    if early_stop {
        if child.try_wait()?.is_none() {
            let _ = child.kill();
            let _ = child.wait();
        }
        if debug && !err_text.trim().is_empty() {
            eprintln!("[tshark-stderr] {}", err_text.trim());
        }
        return Ok(out_rows);
    }

    let status = child.wait()?;
    if !status.success() {
        let msg = err_text.trim().to_string();
        return Err(anyhow!(
            "tshark执行失败(返回码{}): {}",
            status.code().unwrap_or(-1),
            msg
        ));
    }
    if debug && !err_text.trim().is_empty() {
        eprintln!("[tshark-stderr] {}", err_text.trim());
    }
    Ok(out_rows)
}

fn epoch_to_local_iso(epoch: Option<f64>) -> Option<String> {
    let e = epoch?;
    let total_ms = (e * 1000.0).round() as i64;
    let sec = total_ms.div_euclid(1000);
    let ms = total_ms.rem_euclid(1000) as u32;
    let dt = chrono::DateTime::<chrono::Utc>::from_timestamp(sec, ms * 1_000_000)?;
    let dt = dt.with_timezone(&chrono::Local);
    Some(dt.format("%Y-%m-%d %H:%M:%S%.3f").to_string())
}

fn get_pcap_summary(
    pcap_file: &str,
    filter_str: &str,
    max_size_kb: u64,
    tshark: Option<&str>,
    debug_tshark: bool,
) -> Result<serde_json::Value> {
    let size_bytes = fs::metadata(pcap_file).map(|m| m.len()).ok();
    let max_bytes = max_size_kb.saturating_mul(1024);
    let mut summary = serde_json::json!({
        "pcap_file": pcap_file,
        "file_size_bytes": size_bytes,
        "max_size_kb": max_size_kb,
        "too_large": false,
        "stop_reason": serde_json::Value::Null,
        "protocols": [],
        "analyzable": false,
        "analyzable_reason": serde_json::Value::Null,
        "tshark_path": serde_json::Value::Null,
        "time_range": {
            "start_epoch": serde_json::Value::Null,
            "end_epoch": serde_json::Value::Null,
            "start_local": serde_json::Value::Null,
            "end_local": serde_json::Value::Null,
            "duration_ms": serde_json::Value::Null
        },
        "packet_count": serde_json::Value::Null,
        "signaling_count": serde_json::Value::Null,
        "sip": {
            "from": serde_json::Value::Null,
            "to": serde_json::Value::Null,
            "has_invite": false,
            "has_response": false,
            "has_180": false,
            "has_200": false,
            "has_ack_200": false,
            "has_error_response": false,
            "has_cancel": false,
            "bye_has_error_code": false
        },
        "call": {
            "analyzable_voice_call": false,
            "analyzable_reason": serde_json::Value::Null,
            "status": "unknown",
            "failure_trigger": serde_json::Value::Null
        }
    });

    if size_bytes.is_none() {
        return Ok(summary);
    }
    if size_bytes.unwrap_or(0) > max_bytes {
        summary["too_large"] = serde_json::Value::Bool(true);
        summary["stop_reason"] = serde_json::Value::String("too_large".to_string());
        return Ok(summary);
    }

    let tshark_path = resolve_tshark_path(tshark)
        .ok()
        .map(|p| p.to_string_lossy().to_string());
    summary["tshark_path"] = tshark_path
        .clone()
        .map(serde_json::Value::String)
        .unwrap_or(serde_json::Value::Null);

    let rows = iter_tshark_fields(
        pcap_file,
        None,
        &["frame.time_epoch"],
        tshark,
        None,
        debug_tshark,
    )?;
    let mut first_epoch: Option<f64> = None;
    let mut last_epoch: Option<f64> = None;
    let mut packet_count: u64 = 0;
    for r in rows {
        let v = r.first().map(|s| s.trim()).unwrap_or("");
        if v.is_empty() {
            continue;
        }
        if let Ok(epoch) = v.parse::<f64>() {
            if first_epoch.is_none() {
                first_epoch = Some(epoch);
            }
            last_epoch = Some(epoch);
            packet_count += 1;
        }
    }
    summary["packet_count"] = serde_json::Value::Number(packet_count.into());
    summary["time_range"]["start_epoch"] = first_epoch
        .and_then(serde_json::Number::from_f64)
        .map(serde_json::Value::Number)
        .unwrap_or(serde_json::Value::Null);
    summary["time_range"]["end_epoch"] = last_epoch
        .and_then(serde_json::Number::from_f64)
        .map(serde_json::Value::Number)
        .unwrap_or(serde_json::Value::Null);
    summary["time_range"]["start_local"] = epoch_to_local_iso(first_epoch)
        .map(serde_json::Value::String)
        .unwrap_or(serde_json::Value::Null);
    summary["time_range"]["end_local"] = epoch_to_local_iso(last_epoch)
        .map(serde_json::Value::String)
        .unwrap_or(serde_json::Value::Null);
    if let (Some(a), Some(b)) = (first_epoch, last_epoch) {
        let dur_ms = ((b - a) * 1000.0).round() as i64;
        summary["time_range"]["duration_ms"] = serde_json::Value::Number(dur_ms.into());
    }

    let sig_rows = iter_tshark_fields(
        pcap_file,
        Some(filter_str),
        &["frame.number", "frame.protocols"],
        tshark,
        None,
        debug_tshark,
    )?;
    summary["signaling_count"] = serde_json::Value::Number((sig_rows.len() as u64).into());

    let mut proto_set: HashSet<String> = HashSet::new();
    for r in &sig_rows {
        let s = r.get(1).map(|v| v.trim()).unwrap_or("");
        if s.is_empty() {
            continue;
        }
        for raw in s.split(':') {
            let tok = raw.trim().to_ascii_lowercase();
            let mapped = match tok.as_str() {
                "sip" => Some("SIP"),
                "gtpv2" => Some("GTPv2"),
                "gtp" | "gtpv1" | "gtpc" | "gtp-c" | "gtpu" | "gtp-u" => Some("GTP"),
                "s1ap" => Some("S1AP"),
                "ngap" => Some("NGAP"),
                "diameter" => Some("DIAMETER"),
                "bicc" => Some("BICC"),
                "bssap" => Some("BSSAP"),
                "isup" => Some("ISUP"),
                "ranap" => Some("RANAP"),
                _ => None,
            };
            if let Some(v) = mapped {
                proto_set.insert(v.to_string());
            }
        }
    }

    let mut protos: Vec<String> = proto_set.into_iter().collect();
    protos.sort();
    summary["protocols"] = serde_json::Value::Array(
        protos
            .iter()
            .map(|v| serde_json::Value::String(v.clone()))
            .collect(),
    );

    let analyzable = !protos.is_empty();
    summary["analyzable"] = serde_json::Value::Bool(analyzable);
    if !analyzable {
        summary["analyzable_reason"] = serde_json::Value::String("no_target_protocols".to_string());
    }

    let exists = |df: &str| -> bool {
        iter_tshark_fields(
            pcap_file,
            Some(df),
            &["frame.number"],
            tshark,
            Some(1),
            debug_tshark,
        )
        .map(|rows| !rows.is_empty())
        .unwrap_or(false)
    };

    summary["sip"]["has_invite"] = serde_json::Value::Bool(exists(r#"sip.Method == "INVITE""#));
    summary["sip"]["has_response"] = serde_json::Value::Bool(exists("sip && sip.Status-Code"));
    summary["sip"]["has_180"] = serde_json::Value::Bool(exists("sip.Status-Code == 180"));
    summary["sip"]["has_200"] = serde_json::Value::Bool(exists("sip.Status-Code == 200"));
    summary["sip"]["has_error_response"] =
        serde_json::Value::Bool(exists("sip.Status-Code >= 400"));
    summary["sip"]["has_cancel"] = serde_json::Value::Bool(exists(r#"sip.Method == "CANCEL""#));

    if summary["sip"]["has_invite"].as_bool().unwrap_or(false) {
        let attempts: Vec<Vec<&str>> = vec![
            vec!["sip.from.display", "sip.to.display"],
            vec![
                "sip.from.user",
                "sip.from.host",
                "sip.to.user",
                "sip.to.host",
            ],
            vec!["sip.from", "sip.to"],
        ];
        let mut invite_from: Option<String> = None;
        let mut invite_to: Option<String> = None;
        for fields in attempts {
            let rows = iter_tshark_fields(
                pcap_file,
                Some(r#"sip.Method == "INVITE""#),
                &fields,
                tshark,
                Some(1),
                false,
            );
            if let Ok(rows) = rows {
                if let Some(r) = rows.first() {
                    if fields.len() == 2 {
                        let a = r.first().map(|s| s.trim()).unwrap_or("");
                        let b = r.get(1).map(|s| s.trim()).unwrap_or("");
                        if !a.is_empty() {
                            invite_from = Some(a.to_string());
                        }
                        if !b.is_empty() {
                            invite_to = Some(b.to_string());
                        }
                    } else if fields.len() == 4 {
                        let fu = r.first().map(|s| s.trim()).unwrap_or("");
                        let fh = r.get(1).map(|s| s.trim()).unwrap_or("");
                        let tu = r.get(2).map(|s| s.trim()).unwrap_or("");
                        let th = r.get(3).map(|s| s.trim()).unwrap_or("");
                        if !fu.is_empty() || !fh.is_empty() {
                            invite_from =
                                Some(format!("{}@{}", fu, fh).trim_matches('@').to_string());
                        }
                        if !tu.is_empty() || !th.is_empty() {
                            invite_to =
                                Some(format!("{}@{}", tu, th).trim_matches('@').to_string());
                        }
                    }
                }
            }
            if invite_from.is_some() || invite_to.is_some() {
                break;
            }
        }
        if let Some(v) = invite_from {
            summary["sip"]["from"] = serde_json::Value::String(v);
        }
        if let Some(v) = invite_to {
            summary["sip"]["to"] = serde_json::Value::String(v);
        }
    }

    let parse_reason_has_error = |reason_value: &str| -> bool {
        if reason_value.trim().is_empty() {
            return false;
        }
        let re_q850 = Regex::new(r"(?i)q\.?850\s*;\s*cause\s*=\s*(\d+)").unwrap();
        if let Some(cap) = re_q850.captures(reason_value) {
            if let Ok(q850) = cap.get(1).unwrap().as_str().parse::<i64>() {
                if q850 != 16 {
                    return true;
                }
            }
        }
        let re_sip = Regex::new(r"(?i)sip\s*;\s*cause\s*=\s*(\d+)").unwrap();
        if let Some(cap) = re_sip.captures(reason_value) {
            if let Ok(sc) = cap.get(1).unwrap().as_str().parse::<i64>() {
                if sc >= 400 {
                    return true;
                }
            }
        }
        false
    };

    if exists(r#"sip.Method == "BYE" && sip.Reason"#) {
        if let Ok(rows) = iter_tshark_fields(
            pcap_file,
            Some(r#"sip.Method == "BYE" && sip.Reason"#),
            &["sip.Reason"],
            tshark,
            Some(50),
            false,
        ) {
            for r in rows {
                let v = r.first().map(|s| s.as_str()).unwrap_or("");
                if parse_reason_has_error(v) {
                    summary["sip"]["bye_has_error_code"] = serde_json::Value::Bool(true);
                    break;
                }
            }
        }
    }

    let analyzable = summary["sip"]["has_invite"].as_bool().unwrap_or(false)
        && summary["sip"]["has_response"].as_bool().unwrap_or(false);
    summary["call"]["analyzable_voice_call"] = serde_json::Value::Bool(analyzable);
    if !summary["sip"]["has_invite"].as_bool().unwrap_or(false) {
        summary["call"]["analyzable_reason"] =
            serde_json::Value::String("missing_invite".to_string());
    } else if !summary["sip"]["has_response"].as_bool().unwrap_or(false) {
        summary["call"]["analyzable_reason"] =
            serde_json::Value::String("missing_response".to_string());
    }

    if summary["sip"]["has_cancel"].as_bool().unwrap_or(false) {
        summary["call"]["status"] = serde_json::Value::String("failure".to_string());
        summary["call"]["failure_trigger"] = serde_json::Value::String("CANCEL".to_string());
    } else if summary["sip"]["has_error_response"].as_bool().unwrap_or(false) {
        summary["call"]["status"] = serde_json::Value::String("failure".to_string());
        summary["call"]["failure_trigger"] = serde_json::Value::String("4xx/5xx/6xx".to_string());
    } else if summary["sip"]["bye_has_error_code"].as_bool().unwrap_or(false) {
        summary["call"]["status"] = serde_json::Value::String("failure".to_string());
        summary["call"]["failure_trigger"] = serde_json::Value::String("BYE Reason".to_string());
    } else {
        let mut first_200_invite_epoch: Option<f64> = None;
        if let Ok(rows) = iter_tshark_fields(
            pcap_file,
            Some(r#"sip.Status-Code == 200 && sip.CSeq.method == "INVITE""#),
            &["frame.time_epoch"],
            tshark,
            Some(50),
            false,
        ) {
            for r in rows {
                let v = r.first().map(|s| s.trim()).unwrap_or("");
                if let Ok(ep) = v.parse::<f64>() {
                    first_200_invite_epoch = Some(first_200_invite_epoch.map_or(ep, |cur| cur.min(ep)));
                }
            }
        }
        let mut has_ack_200 = false;
        if let Ok(rows) = iter_tshark_fields(
            pcap_file,
            Some(r#"sip.Method == "ACK""#),
            &["frame.time_epoch"],
            tshark,
            Some(50),
            false,
        ) {
            for r in rows {
                let v = r.first().map(|s| s.trim()).unwrap_or("");
                if let Ok(ep) = v.parse::<f64>() {
                    if first_200_invite_epoch.is_none() || ep >= first_200_invite_epoch.unwrap() {
                        has_ack_200 = true;
                        break;
                    }
                } else if first_200_invite_epoch.is_some() {
                    has_ack_200 = true;
                    break;
                }
            }
        }
        summary["sip"]["has_ack_200"] = serde_json::Value::Bool(has_ack_200);
        if has_ack_200 {
            summary["call"]["status"] = serde_json::Value::String("success".to_string());
        }
    }

    Ok(summary)
}

fn extract_cause(line: &str, patterns: &[Regex]) -> Option<String> {
    for re in patterns {
        if let Some(m) = re.find(line) {
            return Some(m.as_str().trim().to_string());
        }
    }
    None
}

fn handle_protocol_sip(lines: &[String], idx: &mut usize, current_packet: &mut Packet) {
    current_packet.protocol = Some("SIP".to_string());
    let sip_request_re = Regex::new(
        r"^(INVITE|ACK|BYE|CANCEL|REGISTER|OPTIONS|SUBSCRIBE|NOTIFY|REFER|INFO|MESSAGE|UPDATE|PRACK)\s",
    )
    .unwrap();
    let sip_status_re = Regex::new(r"SIP/2\.0\s+(\d{3})\s+(.+)").unwrap();

    let mut sip_buffer: Vec<String> = vec![];
    sip_buffer.push(lines[*idx].clone());
    let mut j = *idx + 1;
    while j < lines.len() && sip_buffer.len() < 220 {
        let next_line = lines[j].clone();
        let t = next_line.trim();
        if t.is_empty() || t.starts_with("Frame ") || t.contains("Internet Protocol") {
            break;
        }
        sip_buffer.push(next_line);
        j += 1;
    }

    let find_header = |name: &str| -> Option<String> {
        let prefix = format!("{}:", name.to_ascii_lowercase());

        let looks_like_new_header = |s: &str| -> bool {
            let Some(pos) = s.find(':') else {
                return false;
            };
            let head = s[..pos].trim();
            !head.is_empty() && head.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        };

        for (i, l) in sip_buffer.iter().enumerate() {
            let ls = l.trim();
            if ls.to_ascii_lowercase().starts_with(&prefix) {
                let mut v = ls[prefix.len()..].trim().to_string();

                let mut j = i + 1;
                while j < sip_buffer.len() {
                    let raw = sip_buffer[j].as_str();
                    if raw.starts_with(' ') || raw.starts_with('\t') {
                        let cont = raw.trim();
                        if cont.is_empty() {
                            j += 1;
                            continue;
                        }
                        if looks_like_new_header(cont) {
                            break;
                        }
                        v.push(' ');
                        v.push_str(cont);
                        j += 1;
                        continue;
                    }
                    break;
                }

                return Some(v);
            }
        }
        None
    };

    let find_headers = |name: &str| -> Vec<String> {
        let prefix = format!("{}:", name.to_ascii_lowercase());
        let mut out = vec![];
        for l in &sip_buffer {
            let ls = l.trim();
            if ls.to_ascii_lowercase().starts_with(&prefix) {
                out.push(ls[prefix.len()..].trim().to_string());
            }
        }
        out
    };

    let mut status_code: Option<String> = None;
    let mut reason_phrase: Option<String> = None;
    for l in &sip_buffer {
        let ls = l.trim();
        if ls.contains("Status-Line:") {
            let status_line = ls
                .split_once("Status-Line:")
                .map(|x| x.1)
                .unwrap_or("")
                .trim();
            if let Some(cap) = sip_status_re.captures(status_line) {
                status_code = Some(cap.get(1).unwrap().as_str().to_string());
                reason_phrase = Some(cap.get(2).unwrap().as_str().to_string());
                current_packet.message = Some(format!(
                    "{} {}",
                    status_code.clone().unwrap(),
                    reason_phrase.clone().unwrap()
                ));
                break;
            }
        }
    }
    if status_code.is_none() {
        for l in &sip_buffer {
            let ls = l.trim();
            if ls.starts_with("SIP/2.0") {
                if let Some(cap) = sip_status_re.captures(ls) {
                    status_code = Some(cap.get(1).unwrap().as_str().to_string());
                    reason_phrase = Some(cap.get(2).unwrap().as_str().to_string());
                    current_packet.message = Some(format!(
                        "{} {}",
                        status_code.clone().unwrap(),
                        reason_phrase.clone().unwrap()
                    ));
                    break;
                }
            }
        }
    }

    let mut method: Option<String> = None;
    if current_packet.message.is_none() {
        for l in &sip_buffer {
            let ls = l.trim();
            if ls.contains("Request-Line:") {
                let rest = ls
                    .split_once("Request-Line:")
                    .map(|x| x.1)
                    .unwrap_or("")
                    .trim();
                let m = rest.split_whitespace().next().unwrap_or("").trim();
                if !m.is_empty() {
                    method = Some(m.to_string());
                    current_packet.message = Some(m.to_string());
                    break;
                }
            } else if ls.contains("Method:") {
                let m = ls.split_once("Method:").map(|x| x.1).unwrap_or("").trim();
                if !m.is_empty() {
                    method = Some(m.to_string());
                    current_packet.message = Some(m.to_string());
                    break;
                }
            } else if sip_request_re.is_match(ls) && !ls.contains("CSeq:") {
                if let Some(cap) = sip_request_re.captures(ls) {
                    let m = cap.get(1).unwrap().as_str().to_string();
                    method = Some(m.clone());
                    current_packet.message = Some(m);
                    break;
                }
            }
        }
    }

    let find_field = |name: &str| -> Option<String> {
        let prefix = format!("{}:", name.to_ascii_lowercase());
        for l in &sip_buffer {
            let ls = l.trim();
            if ls.to_ascii_lowercase().starts_with(&prefix) {
                return Some(ls[prefix.len()..].trim().to_string());
            }
        }
        None
    };

    let strip_brackets = |s: String| -> String {
        let t = s.trim();
        if t.starts_with('[') && t.ends_with(']') && t.len() >= 2 {
            t[1..t.len() - 1].to_string()
        } else {
            t.to_string()
        }
    };

    let vias = find_headers("Via");
    let via_top = vias.first().cloned();

    let mut sip_details = SipDetails {
        from: find_header("From"),
        to: find_header("To"),
        call_id: find_header("Call-ID"),
        reason: find_header("Reason"),
        p_called_party_id: find_header("P-Called-Party-ID"),
        request_uri: find_field("Request-URI"),
        request_uri_host: find_field("Request-URI Host Part").map(strip_brackets),
        via_top,
        via_sent_by: find_field("Sent-by Address").map(strip_brackets),
        route_top: find_headers("Route").first().cloned(),
        route_host: find_field("Route Host Part").map(strip_brackets),
        record_route_host: find_field("Record-Route Host Part").map(strip_brackets),
        ..Default::default()
    };

    let cseq = find_header("CSeq");
    if let Some(cseq_v) = cseq.clone() {
        sip_details.cseq = Some(cseq_v.clone());
        let parts: Vec<&str> = cseq_v.split_whitespace().collect();
        if let Some(method_str) = parts.get(1) {
            sip_details.cseq_method = Some((*method_str).to_string());
        }
        if let Some(n_str) = parts.first() {
            if let Ok(n) = (*n_str).parse::<i64>() {
                sip_details.cseq_number = Some(n);
            }
        }
    }

    if !vias.is_empty() {
        sip_details.via_count = Some(vias.len() as i64);
    }

    if let Some(m) = method {
        sip_details.method = Some(m);
    }
    if let Some(sc) = status_code.clone() {
        if let Ok(v) = sc.parse::<i64>() {
            sip_details.status_code = Some(v);
        }
        sip_details.reason_phrase = reason_phrase.clone();
    }

    if let Some(r) = sip_details.reason.clone() {
        if current_packet.cause.is_none() {
            current_packet.cause = Some(format!("SIP Reason: {r}"));
        }
    }

    if current_packet.cause.is_none() {
        if let Some(sc) = status_code.clone() {
            if let Ok(v) = sc.parse::<i64>() {
                if v >= 400 {
                    let rp = reason_phrase.unwrap_or_default();
                    let msg = format!("SIP {sc} {rp}").trim().to_string();
                    if !msg.is_empty() {
                        current_packet.cause = Some(msg);
                    }
                }
            }
        }
    }

    if current_packet.cause.is_none() && sip_details.method.as_deref() == Some("CANCEL") {
        current_packet.cause = Some("SIP CANCEL".to_string());
    }

    current_packet.details.sip = Some(sip_details);
    *idx = j;
}

fn handle_protocol_gtpv2(
    lines: &[String],
    idx: &mut usize,
    current_packet: &mut Packet,
    patterns: &[Regex],
) {
    current_packet.protocol = Some("GTPv2".to_string());
    let mut j = *idx + 1;
    let mut scanned = 0usize;
    while j < lines.len() && scanned < 15 {
        let next_line = lines[j].trim().to_string();
        if next_line.contains("Message Type:") {
            let msg = next_line
                .split_once("Message Type:")
                .map(|x| x.1)
                .unwrap_or("")
                .trim();
            if !msg.is_empty() {
                current_packet.message = Some(msg.to_string());
            }
            j += 1;
            break;
        }
        if next_line.starts_with("Frame ") {
            break;
        }
        j += 1;
        scanned += 1;
    }
    while j < lines.len() {
        let next_line = lines[j].trim();
        if next_line.is_empty() || next_line.starts_with("Frame ") {
            break;
        }
        if let Some(c) = extract_cause(next_line, patterns) {
            current_packet.cause = Some(c);
            break;
        }
        j += 1;
    }
    *idx = j;
}

fn handle_protocol_gtp(
    lines: &[String],
    idx: &mut usize,
    current_packet: &mut Packet,
    patterns: &[Regex],
) {
    // 避免抢占/跳过同一帧内后续更高层协议（如 GTP-U 承载 SIP）：不推进解析游标
    if current_packet.protocol.is_none() {
        current_packet.protocol = Some("GTP".to_string());
    }

    let mut j = *idx + 1;
    let mut scanned = 0usize;
    while j < lines.len() && scanned < 25 {
        let next_line = lines[j].trim();
        if next_line.is_empty() || next_line.starts_with("Frame ") {
            break;
        }
        if next_line.contains("Message Type:") {
            let msg = next_line
                .split_once("Message Type:")
                .map(|x| x.1)
                .unwrap_or("")
                .trim();
            if !msg.is_empty() {
                current_packet.message = Some(msg.to_string());
                break;
            }
        } else if next_line.to_ascii_lowercase().contains("message") && next_line.contains(':') {
            let msg = next_line.split_once(':').map(|x| x.1).unwrap_or("").trim();
            if !msg.is_empty() && msg.len() <= 90 {
                current_packet.message = Some(msg.to_string());
                break;
            }
        }

        if next_line.contains("Internet Protocol") {
            break;
        }

        j += 1;
        scanned += 1;
    }

    while j < lines.len() {
        let next_line = lines[j].trim();
        if next_line.is_empty() || next_line.starts_with("Frame ") {
            break;
        }
        if let Some(c) = extract_cause(next_line, patterns) {
            current_packet.cause = Some(c);
            break;
        }
        j += 1;
    }

    if current_packet.message.is_none() {
        current_packet.message = Some("GTP".to_string());
    }
}

fn handle_protocol_s1ap(
    lines: &[String],
    idx: &mut usize,
    current_packet: &mut Packet,
    patterns: &[Regex],
) {
    current_packet.protocol = Some("S1AP".to_string());
    let mut nas_message: Option<String> = None;
    let mut s1ap_message: Option<String> = None;
    let mut service_type: Option<String> = None;

    let mut j = *idx + 1;
    let mut checked = 0usize;
    while j < lines.len() && checked < 60 {
        let next_line_raw = &lines[j];
        let next_line = next_line_raw.trim();
        if next_line.is_empty()
            || next_line.starts_with("Frame ")
            || next_line.contains("Internet Protocol")
        {
            break;
        }

        if next_line.contains("NAS EPS Mobility Management Message Type:") {
            let mut mm = next_line
                .split_once("NAS EPS Mobility Management Message Type:")
                .map(|x| x.1)
                .unwrap_or("")
                .trim()
                .to_string();
            if let Some(pos) = mm.find('(') {
                mm.truncate(pos);
                mm = mm.trim().to_string();
            }
            if !mm.is_empty() {
                nas_message = Some(mm);
            }
        } else if next_line.contains("NAS EPS session management messages:") {
            let mut sm = next_line
                .split_once("NAS EPS session management messages:")
                .map(|x| x.1)
                .unwrap_or("")
                .trim()
                .to_string();
            if let Some(pos) = sm.find('(') {
                sm.truncate(pos);
                sm = sm.trim().to_string();
            }
            if !sm.is_empty() {
                nas_message = Some(sm);
            }
        } else if nas_message
            .as_deref()
            .map(|s| s.eq_ignore_ascii_case("extended service request"))
            .unwrap_or(false)
            && next_line.contains("Service type:")
        {
            let mut svc = next_line
                .split_once("Service type:")
                .map(|x| x.1)
                .unwrap_or("")
                .trim()
                .to_string();
            if let Some(pos) = svc.find('(') {
                svc.truncate(pos);
                svc = svc.trim().to_string();
            }
            if !svc.is_empty() {
                service_type = Some(svc);
            }
        } else if next_line.contains("procedureCode:") {
            if next_line.contains("id-uplinkNASTransport") || next_line.contains("(13)") {
                s1ap_message = Some("UplinkNASTransport".to_string());
            } else if next_line.contains("id-downlinkNASTransport") || next_line.contains("(11)") {
                s1ap_message = Some("DownlinkNASTransport".to_string());
            } else if next_line.contains("id-UEContextModification") || next_line.contains("(21)") {
                s1ap_message = Some("UEContextModificationRequest".to_string());
            } else if next_line.contains("id-UEContextReleaseRequest") || next_line.contains("(18)")
            {
                s1ap_message = Some("UEContextReleaseRequest".to_string());
            } else if next_line.contains("id-UEContextRelease") || next_line.contains("(23)") {
                s1ap_message = Some("UEContextReleaseCommand".to_string());
            } else if next_line.contains("id-E-RABSetup") || next_line.contains("(5)") {
                s1ap_message = Some("E-RABSetupRequest".to_string());
            } else if next_line.contains("id-E-RABRelease") || next_line.contains("(7)") {
                s1ap_message = Some("E-RABReleaseCommand".to_string());
            } else {
                let proc_part = next_line
                    .split_once("procedureCode:")
                    .map(|x| x.1)
                    .unwrap_or("")
                    .trim();
                let proc_name = proc_part
                    .split_once('(')
                    .map(|(a, _)| a.trim())
                    .unwrap_or(proc_part.split_whitespace().next().unwrap_or("Unknown"))
                    .trim();
                if !proc_name.is_empty() {
                    s1ap_message = Some(proc_name.to_string());
                }
            }
        } else if next_line.contains("radioNetwork:") {
            let mut v = next_line
                .split_once("radioNetwork:")
                .map(|x| x.1)
                .unwrap_or("")
                .trim()
                .to_string();
            if let Some(pos) = v.find('(') {
                v.truncate(pos);
                v = v.trim().to_string();
            }
            if !v.is_empty() {
                current_packet.cause = Some(format!("radioNetwork: {v}"));
            }
        } else if next_line.contains("nas:") {
            let mut v = next_line
                .split_once("nas:")
                .map(|x| x.1)
                .unwrap_or("")
                .trim()
                .to_string();
            if let Some(pos) = v.find('(') {
                v.truncate(pos);
                v = v.trim().to_string();
            }
            if !v.is_empty() {
                current_packet.cause = Some(format!("nas: {v}"));
            }
        } else if next_line.contains("Cause:") {
            if let Some(c) = extract_cause(next_line, patterns) {
                current_packet.cause = Some(c);
            }
        }

        j += 1;
        checked += 1;
    }

    if let Some(n) = nas_message {
        current_packet.message = Some(n);
    } else if let Some(m) = s1ap_message {
        current_packet.message = Some(m);
    }
    if let Some(st) = service_type {
        current_packet.details.s1ap = Some(S1apDetails {
            service_type: Some(st),
        });
    }
    *idx = j;
}

fn handle_protocol_ngap(
    lines: &[String],
    idx: &mut usize,
    current_packet: &mut Packet,
    patterns: &[Regex],
) {
    current_packet.protocol = Some("NGAP".to_string());
    let line = lines[*idx].clone();
    if line.to_ascii_lowercase().contains("procedurecode:") {
        let re = Regex::new(r"(?i)procedureCode:\s*(\w+)\s*\((\d+)\)").unwrap();
        if let Some(cap) = re.captures(&line) {
            current_packet.message = Some(cap.get(1).unwrap().as_str().to_string());
        }
    }
    if current_packet.cause.is_none() {
        if let Some(c) = extract_cause(&line, patterns) {
            current_packet.cause = Some(format!("NGAP: {c}"));
        }
    }
    let cause_value_re = Regex::new(r"Cause.*?Value:\s*([^,\n\r\(]+)(?:\((\d+)\))?").unwrap();
    let mut j = *idx + 1;
    let mut checked = 0usize;
    while j < lines.len() && checked < 35 {
        let next_line = lines[j].trim();
        if next_line.is_empty()
            || next_line.starts_with("Frame ")
            || next_line.contains("Internet Protocol")
            || next_line.starts_with("Ethernet")
        {
            break;
        }
        if next_line.contains("Cause") && next_line.contains("Value") {
            if let Some(cap) = cause_value_re.captures(next_line) {
                let mut v = cap.get(1).unwrap().as_str().trim().to_string();
                if let Some(n) = cap.get(2).map(|m| m.as_str()) {
                    v = format!("{v} ({n})");
                }
                current_packet.cause = Some(format!("NGAP Cause: {v}"));
                break;
            }
        }
        if let Some(c) = extract_cause(next_line, patterns) {
            current_packet.cause = Some(format!("NGAP: {c}"));
            break;
        }
        j += 1;
        checked += 1;
    }
    *idx = j;
}

fn handle_protocol_diameter(
    lines: &[String],
    idx: &mut usize,
    current_packet: &mut Packet,
    patterns: &[Regex],
) {
    current_packet.protocol = Some("DIAMETER".to_string());
    let line = lines[*idx].clone();
    if line.contains("Command Code:") {
        let re = Regex::new(r"Command Code:\s*([^,\n\r\(]+)(?:\((\d+)\))?").unwrap();
        if let Some(cap) = re.captures(&line) {
            current_packet.message = Some(cap.get(1).unwrap().as_str().trim().to_string());
        }
    } else if line.to_ascii_lowercase().contains("application")
        && (line.contains("Application-Id:") || line.contains("Application ID:"))
    {
        let re = Regex::new(r"(?i)Application[-\s]Id:\s*([^,\n\r\(]+)(?:\((\d+)\))?").unwrap();
        if let Some(cap) = re.captures(&line) {
            let app = cap.get(1).unwrap().as_str().trim();
            let msg = current_packet.message.clone().unwrap_or_default();
            current_packet.message = if msg.is_empty() {
                Some(format!("App: {app}"))
            } else {
                Some(format!("{msg} ({app})"))
            };
        }
    }
    if current_packet.cause.is_none() {
        if let Some(c) = extract_cause(&line, patterns) {
            current_packet.cause = Some(format!("Diameter: {c}"));
        }
    }
    let result_code_re = Regex::new(r"Result-Code:\s*([^,\n\r\(]+)(?:\((\d+)\))?").unwrap();
    let mut j = *idx + 1;
    let mut checked = 0usize;
    while j < lines.len() && checked < 40 {
        let next_line = lines[j].trim();
        if next_line.is_empty()
            || next_line.starts_with("Frame ")
            || next_line.contains("Internet Protocol")
            || next_line.starts_with("Ethernet")
        {
            break;
        }
        if next_line.contains("Result-Code:") {
            if let Some(cap) = result_code_re.captures(next_line) {
                let mut v = cap.get(1).unwrap().as_str().trim().to_string();
                if let Some(n) = cap.get(2).map(|m| m.as_str()) {
                    v = format!("{v} ({n})");
                }
                current_packet.cause = Some(format!("Diameter Result-Code: {v}"));
                break;
            }
        }
        if let Some(c) = extract_cause(next_line, patterns) {
            current_packet.cause = Some(format!("Diameter: {c}"));
            break;
        }
        j += 1;
        checked += 1;
    }
    *idx = j;
}

fn handle_protocol_bicc(lines: &[String], idx: &mut usize, current_packet: &mut Packet) {
    current_packet.protocol = Some("BICC".to_string());

    let mut j = *idx + 1;
    let mut scanned = 0usize;
    while j < lines.len() && scanned < 30 {
        let next_line = lines[j].trim();
        if next_line.is_empty()
            || next_line.starts_with("Frame ")
            || next_line.contains("Internet Protocol")
            || next_line.starts_with("Ethernet")
        {
            break;
        }

        if next_line.contains("Message Type:") {
            let msg = next_line
                .split_once("Message Type:")
                .map(|x| x.1)
                .unwrap_or("")
                .trim();
            if !msg.is_empty() {
                current_packet.message = Some(msg.to_string());
                break;
            }
        }

        j += 1;
        scanned += 1;
    }

    if current_packet.message.is_none() {
        current_packet.message = Some("BICC".to_string());
    }
}

fn handle_protocol_bssap(lines: &[String], idx: &mut usize, current_packet: &mut Packet) {
    current_packet.protocol = Some("BSSAP".to_string());

    let mut j = *idx + 1;
    let mut scanned = 0usize;
    while j < lines.len() && scanned < 35 {
        let next_line = lines[j].trim();
        if next_line.is_empty()
            || next_line.starts_with("Frame ")
            || next_line.contains("Internet Protocol")
            || next_line.starts_with("Ethernet")
        {
            break;
        }

        if next_line.contains("GSM A-I/F") && next_line.contains("-") {
            let tail = next_line.splitn(2, '-').nth(1).unwrap_or("").trim();
            if !tail.is_empty() {
                current_packet.message = Some(tail.to_string());
                break;
            }
        }

        if next_line.contains("Message Type:") {
            let msg = next_line
                .split_once("Message Type:")
                .map(|x| x.1)
                .unwrap_or("")
                .trim();
            if !msg.is_empty() {
                current_packet.message = Some(msg.to_string());
                break;
            }
        }

        j += 1;
        scanned += 1;
    }

    if current_packet.message.is_none() {
        current_packet.message = Some("BSSAP".to_string());
    }
}

// ── fshark XDR parsing ────────────────────────────────────────────────

fn interface_to_protocol(interface: &str) -> Option<&'static str> {
    match interface {
        // SIP
        "Gm" | "Mi" | "Mj" | "Mw" | "Ic" | "Mg" | "ISC" | "Mr" | "I2" | "S5s8" | "ATCF_SCCAS"
        | "GmOverGTP" => Some("SIP"),
        // GTPv2
        "S11" | "S5S8" | "Sv" | "N26" => Some("GTPv2"),
        // NGAP
        "N2" | "NGAP" => Some("NGAP"),
        // S1AP (note: "S1" in fshark XDR is S1AP, not SIP)
        "S1-MME" | "S1AP" | "S1" => Some("S1AP"),
        // Diameter
        "S6a" | "Cx" | "Gx" | "Rx" | "Sh" | "S6d" | "S13" | "Gy" => Some("DIAMETER"),
        // HTTP2/SBI
        "SBI" | "N11" | "N7" | "N8" | "N10" | "N12" | "N15" | "N22" | "N28"
        | "Nudm" | "Npcf" | "Nsmf" | "Namf" | "Nnrf" | "Nnssf" | "Nausf"
        | "Nbsf" | "Nchf" | "Nsmsf" | "N5" | "N20" | "N21" | "N14" | "N40" => Some("SBI"),
        // GTP-U
        "S1U" | "S5U" => Some("GTP"),
        // BSSAP/BSSMAP (2G A interface)
        "A" => Some("BSSAP"),
        // BICC (Nc interface)
        "Nc" => Some("BICC"),
        // SGsAP
        "SGs" => Some("SGsAP"),
        // NAS (embedded in S1AP)
        "NAS" => Some("S1AP"),
        // Mc (M3UA/SCCP - maps to BSSAP for DTAP/BSSMAP)
        "Mc" => Some("BSSAP"),
        _ => None,
    }
}

/// Parse SIP keyword1 field from fshark XDR.
/// Returns (method, status_code, reason_phrase).
///
/// Request format:  `INVITE(MF=70, invite, sendrecv)`
/// Response format: `SIP 200 OK(invite, sendrecv)`
fn parse_sip_keyword1(keyword1: &str) -> (Option<String>, Option<i64>, Option<String>) {
    let kw = keyword1.trim();
    if kw.is_empty() {
        return (None, None, None);
    }
    if kw.starts_with("SIP ") {
        // Response: "SIP <code> <reason>(<cseq_method>, ...)"
        let rest = &kw[4..];
        let paren_pos = rest.find('(').unwrap_or(rest.len());
        let before_paren = &rest[..paren_pos];
        let mut parts = before_paren.splitn(2, ' ');
        let code_str = parts.next().unwrap_or("").trim();
        let reason = parts.next().map(|s| s.trim()).filter(|s| !s.is_empty());
        let status_code = code_str.parse::<i64>().ok();
        // Extract cseq_method from inside parentheses
        // Format: "1 invite" or "2 prack" — extract the method name after the space
        let method = if paren_pos < rest.len() {
            let inner = &rest[paren_pos + 1..];
            let content = inner.split(')').next().unwrap_or(inner);
            let first_part = content.split(',').next().unwrap_or("").trim();
            // "1 invite" -> "invite", "invite" -> "invite"
            let method_name = if let Some(space_pos) = first_part.find(' ') {
                &first_part[space_pos + 1..]
            } else {
                first_part
            };
            if method_name.is_empty() { None } else { Some(method_name.to_string()) }
        } else {
            None
        };
        (method, status_code, reason.map(|s| s.to_string()))
    } else {
        // Request: "<METHOD>(...)"
        let method = kw.split('(').next().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        (method, None, None)
    }
}

fn msgtype_to_message(protocol: &str, msgtype: &str) -> Option<String> {
    match protocol {
        "GTPv2" => gtpv2_msgtype_name(msgtype),
        "NGAP" => ngap_msgtype_name(msgtype),
        "S1AP" => s1ap_msgtype_name(msgtype),
        "DIAMETER" => diameter_msgtype_name(msgtype),
        "SBI" => sbi_msgtype_name(msgtype),
        "BSSAP" => bssap_msgtype_name(msgtype),
        "BICC" => bicc_msgtype_name(msgtype),
        "SGsAP" => sgsap_msgtype_name(msgtype),
        _ => None,
    }
}

fn gtpv2_msgtype_name(msgtype: &str) -> Option<String> {
    // fshark XDR msgType is the internal code (from gtpv2Dict values), not the wire msgType byte.
    // Mapping derived from fshark/decoders/gtpv2.py msg_dict.
    Some(match msgtype {
        "307" => "(CSR) Create Session Request",
        "308" => "(CSR) Create Session Response",
        "317" => "(MBR) Modify Bearer Request",
        "318" => "(MBR) Modify Bearer Response",
        "313" => "(DSR) Delete Session Request",
        "314" => "(DSR) Delete Session Response",
        "315" => "(MBC) Modify Bearer Command",
        "316" => "(MBF) Modify Bearer Failure Indication",
        "309" => "(DBC) Delete Bearer Command",
        "310" => "(DBF) Delete Bearer Failure Indication",
        "303" => "(BRC) Bearer Resource Command",
        "304" => "(BRF) Bearer Resource Failure Indication",
        "305" => "(CBR) Create Bearer Request",
        "306" => "(CBR) Create Bearer Response",
        "319" => "(UBR) Update Bearer Request",
        "320" => "(UBR) Update Bearer Response",
        "311" => "(DBR) Delete Bearer Request",
        "312" => "(DBR) Delete Bearer Response",
        "188" => "(DDNF-Ind) Downlink Data Notification Failure Indication",
        "337" => "(RBR) Release Access Bearers Request",
        "338" => "(RBR) Release Access Bearers Response",
        "339" => "Resume ACK",
        "340" => "Resume Notification",
        "341" => "Suspend ACK",
        "342" => "Suspend Notification",
        "399" => "(DDN) Downlink Data Notification",
        "398" => "(DDNA) Downlink Data Notification Acknowledgement",
        // Sv (SRVCC)
        "1042" => "SRVCC PS To CS Handover Cancel ACK",
        "1043" => "SRVCC PS To CS Handover Cancel NOTIFY",
        "1044" => "SRVCC PS To CS Handover Complete ACK",
        "1045" => "SRVCC PS To CS Handover Complete NOTIFY",
        "1046" => "SRVCC PS To CS Handover REQUEST",
        "1047" => "SRVCC PS To CS Handover RESPONSE",
        // N26
        "31000" => "Identification Request",
        "31001" => "Identification Response",
        "31002" => "Context Request",
        "31003" => "Context Response",
        "31004" => "Context Acknowledge",
        "31005" => "Forward Relocation Request",
        "31006" => "Forward Relocation Response",
        "31007" => "Forward Relocation Complete Notification",
        "31008" => "Forward Relocation Complete Acknowledge",
        "31009" => "Forward Access Context Notification",
        "31010" => "Forward Access Context Acknowledge",
        "31011" => "Relocation Cancel Request",
        "31012" => "Relocation Cancel Response",
        "31013" => "Configuration Transfer Tunnel",
        "31014" => "RAN Information Relay",
        _ => return None,
    }.to_string())
}

fn ngap_msgtype_name(msgtype: &str) -> Option<String> {
    Some(match msgtype {
        // NGAP procedures (30000-30077)
        "30000" => "AMF Configuration Update",
        "30001" => "RAN Configuration Update",
        "30002" => "Handover Cancel",
        "30003" => "Handover Required",
        "30004" => "Handover Request",
        "30005" => "Initial Context Setup Request",
        "30006" => "NG Reset",
        "30007" => "NG Setup Request",
        "30008" => "Path Switch Request",
        "30009" => "PDU Session Resource Modify Request",
        "30010" => "PDU Session Resource Modify Indication",
        "30011" => "PDU Session Resource Release Command",
        "30012" => "PDU Session Resource Setup Request",
        "30013" => "UE Context Modification Request",
        "30014" => "UE Context Release Command",
        "30015" => "Write-Replace Warning Request",
        "30016" => "PWS Cancel Request",
        "30017" => "UE Radio Capability Check Request",
        "30018" => "AMF Configuration Update Acknowledge",
        "30019" => "RAN Configuration Update Acknowledge",
        "30020" => "Handover Cancel Acknowledge",
        "30021" => "Handover Command",
        "30022" => "Handover Request Acknowledge",
        "30023" => "Initial Context Setup Response",
        "30024" => "NG Reset Acknowledge",
        "30025" => "NG Setup Response",
        "30026" => "Path Switch Request Acknowledge",
        "30027" => "PDU Session Resource Modify Response",
        "30028" => "PDU Session Resource Modify Confirm",
        "30029" => "PDU Session Resource Release Response",
        "30030" => "PDU Session Resource Setup Response",
        "30031" => "UE Context Modification Response",
        "30032" => "UE Context Release Complete",
        "30033" => "Write-Replace Warning Response",
        "30034" => "PWS Cancel Response",
        "30035" => "UE Radio Capability Check Response",
        "30036" => "AMF Configuration Update Failure",
        "30037" => "RAN Configuration Update Failure",
        "30038" => "Handover Preparation Failure",
        "30039" => "Handover Failure",
        "30040" => "Initial Context Setup Failure",
        "30041" => "NG Setup Failure",
        "30042" => "Path Switch Request Failure",
        "30043" => "UE Context Modification Failure",
        "30044" => "Downlink RAN Configuration Transfer",
        "30045" => "Downlink RAN Status Transfer",
        "30046" => "Downlink NAS Transport",
        "30047" => "Error Indication",
        "30048" => "Uplink RAN Configuration Transfer",
        "30049" => "Uplink RAN Status Transfer",
        "30050" => "Handover Notify",
        "30051" => "Initial UE Message",
        "30052" => "NAS Non Delivery Indication",
        "30053" => "Paging",
        "30054" => "PDU Session Resource Notify",
        "30055" => "Reroute NAS Request",
        "30056" => "UE Context Release Request",
        "30057" => "Uplink NAS Transport",
        "30058" => "AMF Status Indication",
        "30059" => "PWS Restart Indication",
        "30060" => "PWS Failure Indication",
        "30061" => "Downlink UE Associated NRPPA Transport",
        "30062" => "Uplink UE Associated NRPPA Transport",
        "30063" => "Downlink Non UE Associated NRPPA Transport",
        "30064" => "Uplink Non UE Associated NRPPA Transport",
        "30065" => "Trace Start",
        "30066" => "Trace Failure Indication",
        "30067" => "Deactivate Trace",
        "30068" => "Cell Traffic Trace",
        "30069" => "Location Reporting Control",
        "30070" => "Location Reporting Failure Indication",
        "30071" => "Location Report",
        "30072" => "UE TNLA Binding Release Request",
        "30073" => "UE Radio Capability Info Indication",
        "30074" => "RRC Inactive Transition Report",
        "30075" => "Overload Start",
        "30076" => "Overload Stop",
        "30077" => "Secondary RAT Data Usage Report",
        // 5G NAS (5GMM 30100-30139, 5GSM 30228-30249)
        "30100" => "Registration request",
        "30101" => "Registration accept",
        "30102" => "Registration complete",
        "30103" => "Registration reject",
        "30104" => "Deregistration request (UE originating)",
        "30105" => "Deregistration accept (UE originating)",
        "30106" => "Deregistration request (UE terminated)",
        "30107" => "Deregistration accept (UE terminated)",
        "30111" => "Service request",
        "30112" => "Service reject",
        "30113" => "Service accept",
        "30114" => "Control plane service request",
        "30119" => "Configuration update command",
        "30120" => "Configuration update complete",
        "30121" => "Authentication request",
        "30122" => "Authentication response",
        "30123" => "Authentication reject",
        "30124" => "Authentication failure",
        "30125" => "Authentication result",
        "30126" => "Identity request",
        "30127" => "Identity response",
        "30128" => "Security mode command",
        "30129" => "Security mode complete",
        "30130" => "Security mode reject",
        "30135" => "5GMM status",
        "30136" => "Notification",
        "30137" => "Notification response",
        "30138" => "UL NAS transport",
        "30139" => "DL NAS transport",
        "30228" => "PDU session establishment request",
        "30229" => "PDU session establishment accept",
        "30230" => "PDU session establishment reject",
        "30232" => "PDU session authentication command",
        "30233" => "PDU session authentication complete",
        "30234" => "PDU session authentication result",
        "30236" => "PDU session modification request",
        "30237" => "PDU session modification reject",
        "30238" => "PDU session modification command",
        "30239" => "PDU session modification complete",
        "30240" => "PDU session modification command reject",
        "30244" => "PDU session release request",
        "30245" => "PDU session release reject",
        "30246" => "PDU session release command",
        "30247" => "PDU session release complete",
        "30249" => "5GSM status",
        _ => return None,
    }.to_string())
}

fn s1ap_msgtype_name(msgtype: &str) -> Option<String> {
    Some(match msgtype {
        // S1AP procedures (1100-1115 range in fshark, but original dict uses 250-397)
        // fshark XDR uses the s1apDict/emmDict/esmDict integer codes directly.
        // S1AP-level
        "250" => "CELL_TRAFFIC_TRACE",
        "251" => "DEACTIVATE_TRACE",
        "252" => "DL_NAS_TRANSPORT",
        "253" => "ENB_CONFIG_UPDATE",
        "254" => "ENB_CONFIG_UPDATE_ACK",
        "255" => "ENB_CONFIG_UPDATE_FAILURE",
        "256" => "ENB_STATUS_TRANSFER",
        "257" => "ERAB_MODIFY_REQUEST",
        "258" => "ERAB_MODIFY_RESPONSE",
        "259" => "ERAB_RELEASE_COMMAND",
        "260" => "ERAB_RELEASE_IND",
        "261" => "ERAB_RELEASE_RESPONSE",
        "262" => "ERAB_SETUP_REQUEST",
        "263" => "ERAB_SETUP_RESPONSE",
        "264" => "ERROR_INDICATION",
        "265" => "HANDOVER_CANCEL",
        "266" => "HANDOVER_CANCEL_ACK",
        "267" => "HANDOVER_COMMAND",
        "268" => "HANDOVER_FAILURE",
        "269" => "HANDOVER_NOTIFY",
        "270" => "HANDOVER_PREPARE_FAILURE",
        "271" => "HANDOVER_REQUEST",
        "272" => "HANDOVER_REQUEST_ACK",
        "273" => "HANDOVER_REQUIRED",
        "274" => "INITIAL_CONTEXT_SETUP_FAILURE",
        "275" => "INITIAL_CONTEXT_SETUP_REQUEST",
        "276" => "INITIAL_CONTEXT_SETUP_RESPONSE",
        "277" => "INITIAL_UE_MESSAGE",
        "278" => "LOCATION_REPORT",
        "279" => "LOCATION_REPORT_FAILURE_IND",
        "280" => "LOCATION_REPORTING_CONTROL",
        "281" => "MME_CONFIG_UPDATE",
        "282" => "MME_CONFIG_UPDATE_ACK",
        "283" => "MME_CONFIG_UPDATE_FAILURE",
        "284" => "MME_STATUS_TRANSFER",
        "285" => "OVERLOAD_START",
        "286" => "OVERLOAD_STOP",
        "287" => "PAGING",
        "288" => "PATH_SWITCH_REQUEST",
        "289" => "PATH_SWITCH_REQUEST_ACK",
        "290" => "PATH_SWITCH_REQUEST_FAILURE",
        "291" => "RESET",
        "292" => "RESET_ACK",
        "293" => "TRACE_FAILURE_IND",
        "294" => "TRACE_START",
        "295" => "UE_CAPABILITY_INFO_IND",
        "296" => "UE_CONTEXT_MODIFICATION_FAILURE",
        "297" => "UE_CONTEXT_MODIFICATION_REQUEST",
        "298" => "UE_CONTEXT_MODIFICATION_RESPONSE",
        "299" => "UE_CONTEXT_RELEASE_COMMAND",
        "300" => "UE_CONTEXT_RELEASE_COMPLETE",
        "301" => "UE_CONTEXT_RELEASE_REQUEST",
        "302" => "UL_NAS_TRANSPORT",
        "395" => "S1_SETUP_REQUEST",
        "396" => "S1_SETUP_RESPONSE",
        "397" => "S1_SETUP_FAILURE",
        // EMM (4G NAS)
        "196" => "DOWNLINK_NAS_TRANSPORT",
        "197" => "UPLINK_NAS_TRANSPORT",
        "198" => "DOWNLINK_GENERIC_NAS_TRANSPORT",
        "199" => "UPLINK_GENERIC_NAS_TRANSPORT",
        "206" => "ATTACH_ACCEPT",
        "207" => "ATTACH_COMPLETE",
        "208" => "ATTACH_REJECT",
        "209" => "ATTACH_REQUEST",
        "210" => "AUTH_FAILURE",
        "211" => "AUTH_REJECT",
        "212" => "AUTH_REQUEST",
        "213" => "AUTH_RESPONSE",
        "218" => "CS_SERVICE_NOTIFICATION",
        "221" => "DETACH_ACCEPT",
        "222" => "DETACH_REQUEST",
        "223" => "EMM_INFORMATION",
        "224" => "EMM_STATUS",
        "228" => "EXTENDED_SERVICE_REQUEST",
        "229" => "GUTI_REALLOCATION_COMMAND",
        "230" => "GUTI_REALLOCATION_COMPLETE",
        "231" => "IDENTITY_REQUEST",
        "232" => "IDENTITY_RESPONSE",
        "241" => "SECURITY_MODE_COMMAND",
        "242" => "SECURITY_MODE_COMPLETE",
        "243" => "SECURITY_MODE_REJECT",
        "244" => "SERVICE_REJECT",
        "246" => "TAU_ACCEPT",
        "247" => "TAU_COMPLETE",
        "248" => "TAU_REJECT",
        "249" => "TAU_REQUEST",
        // ESM (4G NAS)
        "200" => "ACTIVATE_DEDICATED_EPS_BEARER_CONTEXT_ACCEPT",
        "201" => "ACTIVATE_DEDICATED_EPS_BEARER_CONTEXT_REJECT",
        "202" => "ACTIVATE_DEDICATED_EPS_BEARER_CONTEXT_REQUEST",
        "203" => "ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_ACCEPT",
        "204" => "ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REJECT",
        "205" => "ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REQUEST",
        "214" => "BEARER_RESOURCE_ALLOCATION_REJECT",
        "215" => "BEARER_RESOURCE_ALLOCATION_REQUEST",
        "216" => "BEARER_RESOURCE_MODIFICATION_REJECT",
        "217" => "BEARER_RESOURCE_MODIFICATION_REQUEST",
        "219" => "DEACTIVATE_EPS_CONTEXT_ACCEPT",
        "220" => "DEACTIVATE_EPS_CONTEXT_REQUEST",
        "225" => "ESM_INFORMATION_REQUEST",
        "226" => "ESM_INFORMATION_RESPONSE",
        "227" => "ESM_STATUS",
        "233" => "MODIFY_EPS_BEARER_CONTEXT_ACCEPT",
        "234" => "MODIFY_EPS_BEARER_CONTEXT_REJECT",
        "235" => "MODIFY_EPS_BEARER_CONTEXT_REQUEST",
        "236" => "ESM_NOTIFICATION",
        "237" => "PDN_CONNECTIVITY_REJECT",
        "238" => "PDN_CONNECTIVITY_REQUEST",
        "239" => "PDN_DISCONNECT_REJECT",
        "240" => "PDN_DISCONNECT_REQUEST",
        _ => return None,
    }.to_string())
}

fn diameter_msgtype_name(msgtype: &str) -> Option<String> {
    Some(match msgtype {
        // S6a
        "321" => "S6a_AIA",
        "322" => "S6a_AIR",
        "323" => "S6a_CLA",
        "324" => "S6a_CLR",
        "325" => "S6a_DSA",
        "326" => "S6a_DSR",
        "327" => "S6a_IDA",
        "328" => "S6a_IDR",
        "329" => "S6a_NA",
        "330" => "S6a_NR",
        "331" => "S6a_PUA",
        "332" => "S6a_PUR",
        "333" => "S6a_RA",
        "334" => "S6a_RR",
        "335" => "S6a_ULA",
        "336" => "S6a_ULR",
        // Gx/S7
        "600" => "GxS7_CCA",
        "601" => "GxS7_CCR",
        "602" => "GxS7_RAA",
        "603" => "GxS7_RAR",
        // Gy
        "604" => "Gy_CCA",
        "605" => "Gy_CCR",
        // S13
        "998" => "S13_ECR",
        "999" => "S13_ECA",
        // Cx/Dx
        "1000" => "Cx_LIA",
        "1001" => "Cx_LIR",
        "1002" => "Cx_MAA",
        "1003" => "Cx_MAR",
        "1004" => "Cx_PPA",
        "1005" => "Cx_PPR",
        "1006" => "Cx_RTA",
        "1007" => "Cx_RTR",
        "1008" => "Cx_SAA",
        "1009" => "Cx_SAR",
        "1010" => "Cx_UAA",
        "1011" => "Cx_UAR",
        // Rx
        "1026" => "Rx_AAA",
        "1027" => "Rx_AAR",
        "1028" => "Rx_ASA",
        "1029" => "Rx_ASR",
        "1030" => "Rx_RAA",
        "1031" => "Rx_RAR",
        "1032" => "Rx_STA",
        "1033" => "Rx_STR",
        // Sh
        "1034" => "Sh_PUA",
        "1035" => "Sh_PUR",
        "1036" => "Sh_PNA",
        "1037" => "Sh_PNR",
        "1038" => "Sh_SNA",
        "1039" => "Sh_SNR",
        "1040" => "Sh_UDA",
        "1041" => "Sh_UDR",
        _ => return None,
    }.to_string())
}

fn sbi_msgtype_name(msgtype: &str) -> Option<String> {
    // SBI msgType from fshark XDR (string keys "50000"-"50352" range).
    // Only includes the most common entries; unknown codes fall through.
    Some(match msgtype {
        // Nsmf_PDUSession
        "50000" => "N11 CreateSMContext Request",
        "50002" => "N11 SMContextStatusNotification",
        "50004" => "N11 RetrieveSMContext",
        "50006" => "N11 ModifySMContext",
        "50008" => "N11 ReleaseSMContext",
        "50010" => "N11 CreatePDUSession",
        "50020" => "N11 ModifyPDUSession",
        "50022" => "N11 ReleasePDUSession",
        // Nudm_SDM
        "50026" => "N8 GetSubscriberData",
        "50028" => "N8 GetNSSAI",
        "50030" => "N8 GetAccessAndMobilityData",
        "50032" => "N10 GetSMFSelectionData",
        "50034" => "N8 GetUEContextInSMFData",
        "50040" => "N8 GetSessionManagementData",
        "50046" => "N8 CreateSDMSubscription",
        "50050" => "N8 DeleteSDMSubscription",
        // Nudm_UECM
        "50078" => "N8 RegisterAMF3gppAccess",
        "50084" => "N8 PatchAMF3gppAccess",
        "50086" => "N8 GetAMF3gppAccess",
        "50088" => "N8 RegisterAMFNon3gppAccess",
        "50094" => "N8 PatchAMFNon3gppAccess",
        "50096" => "N8 GetAMFNon3gppAccess",
        "50098" => "N10 RegisterSMF",
        "50102" => "N10 DeregisterSMF",
        // Npcf_AMPolicyControl
        "50120" => "N15 CreateAMPolicyAssociation",
        "50126" => "N15 GetAMPolicyAssociation",
        "50128" => "N15 DeleteAMPolicyAssociation",
        "50130" => "N15 UpdateAMPolicyAssociation",
        // Nausf_UEAuthentication
        "50146" => "N12 UEAuthentication",
        "50148" => "N12 5GAkaConfirmation",
        // Nnrf_NFDiscovery
        "50156" => "Nrf DiscoverNFInstances",
        // Nnrf_NFManagement
        "50168" => "Nrf GetNFInstance",
        "50170" => "Nrf PutNFInstance",
        "50172" => "Nrf PatchNFInstance",
        "50174" => "Nrf DeleteNFInstance",
        "50176" => "Nrf CreateSubscription",
        // Npcf_SMPolicyControl
        "50186" => "N7 CreateSMPolicy",
        "50192" => "N7 GetSMPolicy",
        "50194" => "N7 UpdateSMPolicy",
        "50196" => "N7 DeleteSMPolicy",
        // Npcf_PolicyAuthorization
        "50200" => "N5 CreateAppSession",
        "50206" => "N5 GetAppSession",
        // Namf_Communication
        "50222" => "N14 PutUEContext",
        "50226" => "N14 ReleaseUEContext",
        "50234" => "N11 N1N2MessageTransfer",
        "50246" => "N8 NonUEN2MessageTransfer",
        "50254" => "N8 CreateSubscription",
        // Namf_Location
        "50278" => "N8 ProvidePositioningInfo",
        "50282" => "N8 ProvideLocationInfo",
        // Namf_MT
        "50286" => "N8 GetUEContext",
        // Npcf_UEPolicyControl
        "50292" => "N15 CreateUEPolicyAssociation",
        // Nnssf_NSSelection
        "50322" => "N22 GetNetworkSliceInformation",
        // Nsmsf_SMService
        "50326" => "N20 CreateUEContextForSMS",
        "50330" => "N20 SendSMS",
        // Nbsf_Management
        "50346" => "Nbsf CreatePCFBinding",
        "50348" => "Nbsf GetPCFBinding",
        "50350" => "Nbsf DeletePCFBinding",
        // Heuristic/interface_dict codes
        "50500" => "SBI Unknown Request",
        "50502" => "N12 AUSF Request",
        "50504" => "N13 AUSF_UDM Request",
        "50506" => "N11 AMF_SMF Request",
        "50508" => "N8 AMF_UDM Request",
        "50510" => "N10 SMF_UDM Request",
        "50512" => "N7 SMF_PCF Request",
        "50514" => "N20 AMF_SMSF Request",
        "50516" => "N21 SMSF_UDM Request",
        "50518" => "N22 AMF_NSSF Request",
        "50520" => "NRF Request",
        "50511" => "SBI Unknown Response",
        _ => return None,
    }.to_string())
}

fn bssap_msgtype_name(msgtype: &str) -> Option<String> {
    // BSSAP/DTAP/BSSMAP msgType codes from fshark decoders
    Some(match msgtype {
        // BSSMAP
        "1100" => "BSSMAP COMPLETE LAYER 3 INFORMATION",
        "1101" => "BSSMAP CLASSMARK UPDATE",
        "1126" => "BSSMAP ASSIGNMENT REQUEST",
        "1127" => "BSSMAP ASSIGNMENT COMPLETE",
        "1134" => "BSSMAP COMMON ID",
        "1137" => "BSSMAP CLEAR COMMAND",
        "1138" => "BSSMAP CLEAR COMPLETE",
        "1163" => "BSSMAP SAPI_N_REJECT",
        "1164" => "BSSMAP HANDOVER REQUIRED",
        // DTAP (A interface)
        "1200" => "DTAP CM Service Request",
        "1201" => "DTAP CM Service Accept",
        "1205" => "DTAP Setup",
        "1207" => "DTAP Call Processing",
        "1208" => "DTAP Alerting",
        "1210" => "DTAP Disconnect",
        "1212" => "DTAP Release",
        "1214" => "DTAP Release Complete",
        "1217" => "DTAP Facility",
        "1225" => "DTAP MM Information",
        "1230" => "DTAP Authen Request",
        "1232" => "DTAP Authen Response",
        _ => return None,
    }.to_string())
}

fn bicc_msgtype_name(msgtype: &str) -> Option<String> {
    // BICC msgType codes from fshark decoders
    Some(match msgtype {
        "1200" => "BICC IAM",
        "1201" => "BICC SAM",
        "1204" => "BICC APM",
        "1205" => "BICC COT",
        "1216" => "BICC ACM",
        "1217" => "BICC CPG",
        "1220" => "BICC ANM",
        "1223" => "BICC REL",
        "1224" => "BICC RLC",
        "1225" => "BICC BLO",
        "1226" => "BICC BLA",
        "1227" => "BICC UBL",
        "1228" => "BICC UBA",
        _ => return None,
    }.to_string())
}

fn sgsap_msgtype_name(msgtype: &str) -> Option<String> {
    // SGsAP msgType codes from fshark decoders
    Some(match msgtype {
        "351" => "SGsAP LOCATION_UPDATE_ACCEPT",
        "353" => "SGsAP LOCATION_UPDATE_REQUEST",
        "362" => "SGsAP TMSI_REALLOCATION_COMPLETE",
        "350" => "SGsAP LOCATION_UPDATE_REJECT",
        "355" => "SGsAP SERVICE_REQUEST",
        "356" => "SGsAP DOWNLINK_UNITDATA",
        "357" => "SGsAP UPLINK_UNITDATA",
        "360" => "SGsAP RESET_INDICATION",
        "361" => "SGsAP RESET_ACK",
        "365" => "SGsAP EPS_DETACH_INDICATION",
        "366" => "SGsAP EPS_DETACH_ACK",
        "367" => "SGsAP IMS_DETACH_INDICATION",
        "368" => "SGsAP IMS_DETACH_ACK",
        _ => return None,
    }.to_string())
}

/// Parse fshark XDR output (pipe-delimited text) into Vec<Packet>.
///
/// XDR field layout (26 columns, 0-indexed after main.py drops the `id` field):
///  0:timestamp 1:imsi 2:msisdn 3:src_ip 4:sport 5:dst_ip 6:dport
///  7:cgi 8:interface 9:(empty) 10:dir 11:cause 12:(empty)
///  13:msgType 14:latency 15:retries 16-19:(empty)
///  20:keyword1/strValue 21-24:varies 25:RawData1
fn parse_fshark_xdr(input_file: &str) -> Result<Vec<Packet>> {
    let f = fs::File::open(input_file)?;
    let reader = BufReader::new(f);
    let mut packets: Vec<Packet> = Vec::new();
    let mut frame_no: u64 = 1;

    for line in reader.lines() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split('|').collect();
        if fields.len() < 20 {
            continue;
        }

        let timestamp = fields.get(0).map(|s| s.trim()).filter(|s| !s.is_empty()).map(|s| s.to_string());
        let src = fields.get(3).map(|s| s.trim()).filter(|s| !s.is_empty()).map(|s| s.to_string());
        let dst = fields.get(5).map(|s| s.trim()).filter(|s| !s.is_empty()).map(|s| s.to_string());
        let interface = fields.get(8).map(|s| s.trim()).filter(|s| !s.is_empty()).unwrap_or("");
        let cause = fields.get(11).map(|s| s.trim()).filter(|s| !s.is_empty() && *s != "0").map(|s| s.to_string());
        let msgtype = fields.get(13).map(|s| s.trim()).filter(|s| !s.is_empty()).unwrap_or("");
        // keyword1/strValue: position varies by protocol.
        // SIP: keyword1 is at index 21 (index 20 is empty), calling=22, called=23, keyword4=24, CallID=25
        // Others: strValue at index 20, keyword1 at index 21
        let keyword1 = fields.get(21).map(|s| s.trim()).filter(|s| !s.is_empty()).unwrap_or("");
        let str_value = fields.get(20).map(|s| s.trim()).filter(|s| !s.is_empty()).unwrap_or("");

        let protocol = interface_to_protocol(interface).map(|s| s.to_string());

        // Build message and details based on protocol
        let (message, details, underlying_protocols) = if protocol.as_deref() == Some("SIP") {
            // SIP: keyword1 is at index 21
            let (method, status_code, reason_phrase) = parse_sip_keyword1(keyword1);
            let msg = if let Some(code) = status_code {
                let reason = reason_phrase.as_deref().unwrap_or("");
                if reason.is_empty() { format!("SIP {code}") } else { format!("SIP {code} {reason}") }
            } else {
                method.clone().unwrap_or_else(|| keyword1.to_string())
            };
            let sip_details = SipDetails {
                method: method.clone(),
                status_code,
                reason_phrase,
                cseq_method: method.clone(),
                ..Default::default()
            };
            let up = vec!["SIP".to_string()]; // minimal; no transport info in XDR
            (Some(msg), Details { sip: Some(sip_details), s1ap: None }, up)
        } else if protocol.as_deref() == Some("SBI") {
            // SBI: strValue (field 20) contains "POST /path" or "201 description"
            let msg = if str_value.is_empty() {
                msgtype_to_message("SBI", msgtype).unwrap_or_else(|| msgtype.to_string())
            } else {
                str_value.to_string()
            };
            let up = vec!["SIP".to_string()]; // SBI runs over HTTP2
            (Some(msg), Details::default(), up)
        } else if let Some(ref proto) = protocol {
            // Other protocols: try strValue (field 20) first, then keyword1 (field 21), then msgType mapping
            let msg = msgtype_to_message(proto, msgtype)
                .or_else(|| if keyword1.is_empty() { None } else { Some(keyword1.to_string()) })
                .or_else(|| if str_value.is_empty() { None } else { Some(str_value.to_string()) })
                .unwrap_or_else(|| msgtype.to_string());
            let up = match proto.as_str() {
                "GTPv2" => vec!["GTPv2".to_string()],
                "NGAP" => vec!["NGAP".to_string()],
                "S1AP" => vec!["S1AP".to_string()],
                "DIAMETER" => vec!["DIAMETER".to_string()],
                "GTP" => vec!["GTP".to_string()],
                "BSSAP" => vec!["BSSAP".to_string()],
                "BICC" => vec!["BICC".to_string()],
                "SGsAP" => vec!["SGsAP".to_string()],
                _ => vec![],
            };
            (Some(msg), Details::default(), up)
        } else {
            // Unknown protocol — keep interface as message hint
            let msg = if !keyword1.is_empty() {
                keyword1.to_string()
            } else if !str_value.is_empty() {
                str_value.to_string()
            } else if !msgtype.is_empty() {
                msgtype.to_string()
            } else {
                interface.to_string()
            };
            (Some(msg), Details::default(), vec![])
        };

        let packet = Packet {
            frame: Some(frame_no),
            timestamp,
            src,
            dst,
            src_entity: None,
            dst_entity: None,
            protocol,
            message,
            cause,
            details,
            underlying_protocols,
        };
        packets.push(packet);
        frame_no += 1;
    }

    Ok(packets)
}

/// Build a PCAP summary from fshark-decoded packets, replacing tshark-based get_pcap_summary().
fn build_fshark_summary(
    pcap_file: &str,
    packets: &[Packet],
    max_size_kb: u64,
    fshark_path_val: Option<&str>,
) -> serde_json::Value {
    use serde_json::{Map, Value};

    let file_size_bytes = fs::metadata(pcap_file).map(|m| m.len()).ok();
    let size_bytes_val = file_size_bytes.unwrap_or(0);
    let too_large = size_bytes_val > max_size_kb.saturating_mul(1024);

    let mut summary = Map::new();
    summary.insert("pcap_file".into(), Value::String(pcap_file.to_string()));
    summary.insert("file_size_bytes".into(), serde_json::to_value(&file_size_bytes).unwrap_or(Value::Null));
    summary.insert("max_size_kb".into(), Value::Number(max_size_kb.into()));
    summary.insert("too_large".into(), Value::Bool(too_large));
    summary.insert("stop_reason".into(), if too_large { Value::String("too_large".into()) } else { Value::Null });
    summary.insert("fshark_path".into(), Value::String(
        fshark_path_val.unwrap_or("fshark").to_string()
    ));

    let packet_count = packets.len();
    summary.insert("packet_count".into(), Value::Number(packet_count.into()));
    summary.insert("signaling_count".into(), Value::Number(packet_count.into()));

    // Protocols
    let mut protos: HashSet<String> = HashSet::new();
    for p in packets {
        if let Some(ref proto) = p.protocol {
            protos.insert(proto.clone());
        }
    }
    let mut protos_vec: Vec<String> = protos.into_iter().collect();
    protos_vec.sort();
    summary.insert("protocols".into(), serde_json::to_value(&protos_vec).unwrap_or(Value::Array(vec![])));

    let analyzable = !protos_vec.is_empty();
    summary.insert("analyzable".into(), Value::Bool(analyzable));
    summary.insert("analyzable_reason".into(), if analyzable { Value::Null } else { Value::String("no_target_protocols".into()) });

    // Time range
    let first_ts = packets.first().and_then(|p| p.timestamp.clone());
    let last_ts = packets.last().and_then(|p| p.timestamp.clone());
    let mut time_range = Map::new();
    time_range.insert("start_local".into(), serde_json::to_value(&first_ts).unwrap_or(Value::Null));
    time_range.insert("end_local".into(), serde_json::to_value(&last_ts).unwrap_or(Value::Null));
    // epoch/duration not easily available from fshark timestamps
    time_range.insert("start_epoch".into(), Value::Null);
    time_range.insert("end_epoch".into(), Value::Null);
    time_range.insert("duration_ms".into(), Value::Null);
    summary.insert("time_range".into(), Value::Object(time_range));

    // SIP analysis — scan SIP packets
    let sip_packets: Vec<&Packet> = packets.iter().filter(|p| p.protocol.as_deref() == Some("SIP")).collect();
    let has_invite = sip_packets.iter().any(|p| p.message.as_deref().map(|m| m.starts_with("INVITE")).unwrap_or(false));
    let has_response = sip_packets.iter().any(|p| p.details.sip.as_ref().and_then(|s| s.status_code).is_some());
    let has_180 = sip_packets.iter().any(|p| p.details.sip.as_ref().and_then(|s| s.status_code) == Some(180));
    let has_200 = sip_packets.iter().any(|p| p.details.sip.as_ref().and_then(|s| s.status_code) == Some(200));
    let has_200_invite = sip_packets.iter().any(|p| {
        p.details.sip.as_ref().and_then(|s| s.status_code) == Some(200)
        && p.details.sip.as_ref().and_then(|s| s.cseq_method.as_deref()) == Some("invite")
    });
    let has_error_response = sip_packets.iter().any(|p| {
        p.details.sip.as_ref().and_then(|s| s.status_code).map(|c| c >= 400).unwrap_or(false)
    });
    let has_cancel = sip_packets.iter().any(|p| p.message.as_deref().map(|m| m == "CANCEL").unwrap_or(false));
    let has_ack = sip_packets.iter().any(|p| p.message.as_deref().map(|m| m == "ACK").unwrap_or(false));

    // SIP from/to not directly available in XDR; caller/callee numbers are in fields 22-23
    // which are not stored in Packet. Summary sets these to Null for now.

    let mut sip_obj = Map::new();
    sip_obj.insert("from".into(), Value::Null);
    sip_obj.insert("to".into(), Value::Null);
    sip_obj.insert("has_invite".into(), Value::Bool(has_invite));
    sip_obj.insert("has_response".into(), Value::Bool(has_response));
    sip_obj.insert("has_180".into(), Value::Bool(has_180));
    sip_obj.insert("has_200".into(), Value::Bool(has_200));
    sip_obj.insert("has_ack_200".into(), Value::Bool(has_ack && has_200_invite));
    sip_obj.insert("has_error_response".into(), Value::Bool(has_error_response));
    sip_obj.insert("has_cancel".into(), Value::Bool(has_cancel));
    sip_obj.insert("bye_has_error_code".into(), Value::Bool(false)); // would need BYE Reason parsing
    summary.insert("sip".into(), Value::Object(sip_obj));

    // Call analysis
    let analyzable_voice_call = has_invite && has_response;
    let call_status = if has_cancel {
        "failure"
    } else if has_error_response {
        "failure"
    } else if has_ack && has_200_invite {
        "success"
    } else {
        "unknown"
    };
    let failure_trigger = if has_cancel {
        Some("CANCEL")
    } else if has_error_response {
        Some("4xx/5xx/6xx")
    } else {
        None
    };

    let mut call_obj = Map::new();
    call_obj.insert("analyzable_voice_call".into(), Value::Bool(analyzable_voice_call));
    call_obj.insert("analyzable_reason".into(), if analyzable_voice_call { Value::Null } else { Value::String(if !has_invite { "missing_invite" } else { "missing_response" }.into()) });
    call_obj.insert("status".into(), Value::String(call_status.to_string()));
    call_obj.insert("failure_trigger".into(), serde_json::to_value(&failure_trigger).unwrap_or(Value::Null));
    summary.insert("call".into(), Value::Object(call_obj));

    Value::Object(summary)
}

fn parse_wireshark_output(
    input_file: &str,
    output_csv: Option<&str>,
    output_json: Option<&str>,
) -> Result<Vec<Packet>> {
    let mut f = fs::File::open(input_file)?;
    let mut buf: Vec<u8> = vec![];
    f.read_to_end(&mut buf)?;
    let text = String::from_utf8_lossy(&buf)
        .replace("\r\n", "\n")
        .replace('\r', "\n");
    let lines: Vec<String> = text.lines().map(|l| l.to_string()).collect();

    let frame_re = Regex::new(r"^Frame (\d+):").unwrap();
    let arrival_time_re = Regex::new(r"(\d{2}):(\d{2}):(\d{2})\.(\d+)").unwrap();
    let ip_re = Regex::new(r"Src: ([^,]+), Dst: ([^,]+)").unwrap();

    let cause_patterns: Vec<Regex> = vec![
        Regex::new(r"(?i)ESM\s+cause\s*:?\s*([^,\n\r]+)").unwrap(),
        Regex::new(r"(?i)nas\s*:\s*([^,\n\r\(]+(?:\([^)]+\))?)").unwrap(),
        Regex::new(r"(?i)radioNetwork\s*:\s*([^,\n\r\(]+(?:\([^)]+\))?)").unwrap(),
        Regex::new(r"(?i)Cause\s*:\s*([^,\n\r]+)").unwrap(),
        Regex::new(r"(?i)Cause\s+Value\s*:\s*([^,\n\r\(]+(?:\([^)]+\))?)").unwrap(),
        Regex::new(r"(?i)Result-Code\s*:\s*([^,\n\r\(]+(?:\([^)]+\))?)").unwrap(),
        Regex::new(r"(?i)Experimental-Result(?:-Code)?\s*:\s*([^,\n\r\(]+(?:\([^)]+\))?)").unwrap(),
        Regex::new(r"(?i)Reason\s*:?\s*([^,\n\r]+)").unwrap(),
        Regex::new(r"(?i)Error-Cause\s*:?\s*([^,\n\r]+)").unwrap(),
        Regex::new(r"(?i)Protocol\s+Error\s+Cause\s*:\s*([^,\n\r]+)").unwrap(),
        Regex::new(r"(?i)transport\s*:\s*([^,\n\r\(]+(?:\([^)]+\))?)").unwrap(),
        Regex::new(r"(?i)misc\s*:\s*([^,\n\r\(]+(?:\([^)]+\))?)").unwrap(),
        Regex::new(r"(?i)Failed-AVP\s*:\s*([^,\n\r]+)").unwrap(),
        Regex::new(r"(?i)Error-Message\s*:\s*([^,\n\r]+)").unwrap(),
        Regex::new(r"(?i)5GMM\s+cause\s*:\s*([^,\n\r]+)").unwrap(),
        Regex::new(r"(?i)5GSM\s+cause\s*:\s*([^,\n\r]+)").unwrap(),
    ];

    let mut results: Vec<Packet> = vec![];
    let mut current_packet: Option<Packet> = None;
    let mut protocols_stack: Vec<String> = vec![];

    let mut i: usize = 0;
    while i < lines.len() {
        let line = lines[i].trim().to_string();

        if let Some(cap) = frame_re.captures(&line) {
            if let Some(p) = current_packet.take() {
                if p.protocol.is_some() {
                    results.push(p);
                }
            }
            let frame_number = cap.get(1).and_then(|m| m.as_str().parse::<u64>().ok());
            current_packet = Some(Packet {
                frame: frame_number,
                timestamp: None,
                src: None,
                dst: None,
                src_entity: None,
                dst_entity: None,
                protocol: None,
                message: None,
                cause: None,
                details: Details::default(),
                underlying_protocols: vec![],
            });
            protocols_stack.clear();
            i += 1;
            continue;
        }

        let Some(pkt) = current_packet.as_mut() else {
            i += 1;
            continue;
        };

        if line.contains("Arrival Time:") {
            let ts = line
                .split_once("Arrival Time:")
                .map(|x| x.1)
                .unwrap_or("")
                .trim();
            if let Some(cap) = arrival_time_re.captures(ts) {
                let h = cap.get(1).unwrap().as_str();
                let m = cap.get(2).unwrap().as_str();
                let s = cap.get(3).unwrap().as_str();
                let mut ms = cap.get(4).unwrap().as_str().to_string();
                if ms.len() > 3 {
                    ms.truncate(3);
                }
                pkt.timestamp = Some(format!("{h}:{m}:{s}.{ms}"));
            } else {
                pkt.timestamp = Some(ts.to_string());
            }
        } else if line.contains("Internet Protocol Version") {
            if line.starts_with("Internet Protocol Version 4") {
                protocols_stack.push("IPv4".to_string());
            } else if line.starts_with("Internet Protocol Version 6") {
                protocols_stack.push("IPv6".to_string());
            }
            if let Some(cap) = ip_re.captures(&line) {
                pkt.src = Some(cap.get(1).unwrap().as_str().trim().to_string());
                pkt.dst = Some(cap.get(2).unwrap().as_str().trim().to_string());
            }
        } else if line.starts_with("User Datagram Protocol") {
            protocols_stack.push("UDP".to_string());
        } else if line.starts_with("Transmission Control Protocol") {
            protocols_stack.push("TCP".to_string());
        } else if line.contains("GPRS Tunneling Protocol V2") || line.contains("GTPv2") {
            protocols_stack.push("GTPv2".to_string());
        } else if line.contains("GPRS Tunneling Protocol V1")
            || line.contains("GTPv1")
            || line.contains("GTP-C")
        {
            protocols_stack.push("GTPv1".to_string());
        } else if line.contains("GPRS Tunneling Protocol") || line.contains("GTP-U") {
            protocols_stack.push("GTP-U".to_string());
        } else if line.contains("Session Initiation Protocol")
            || line.contains("Session Description Protocol")
        {
            protocols_stack.push("SIP".to_string());
        } else if line.contains("S1 Application Protocol") || line.contains("S1AP") {
            protocols_stack.push("S1AP".to_string());
        } else if line.contains("NG Application Protocol") || line.contains("NGAP") {
            protocols_stack.push("NGAP".to_string());
        } else if line.contains("Diameter Protocol") || line.contains("Diameter") {
            protocols_stack.push("DIAMETER".to_string());
        } else if line.contains("Bearer Independent Call Control") {
            protocols_stack.push("BICC".to_string());
        } else if line.trim() == "BSSAP" || line.starts_with("BSSAP") {
            protocols_stack.push("BSSAP".to_string());
        }

        if line.contains("Session Initiation Protocol")
            || line.contains("Session Description Protocol")
        {
            handle_protocol_sip(&lines, &mut i, pkt);
            pkt.underlying_protocols = protocols_stack.clone();
        } else if line.contains("GPRS Tunneling Protocol V2") || line.contains("GTPv2") {
            handle_protocol_gtpv2(&lines, &mut i, pkt, &cause_patterns);
            pkt.underlying_protocols = protocols_stack.clone();
        } else if (line.contains("GPRS Tunneling Protocol") || line.contains("GTP-U") || line.contains("GTPv1") || line.contains("GTP-C"))
            && !(line.contains("GPRS Tunneling Protocol V2") || line.contains("GTPv2"))
        {
            handle_protocol_gtp(&lines, &mut i, pkt, &cause_patterns);
            pkt.underlying_protocols = protocols_stack.clone();
        } else if line.contains("S1 Application Protocol") || line.contains("S1AP") {
            handle_protocol_s1ap(&lines, &mut i, pkt, &cause_patterns);
            pkt.underlying_protocols = protocols_stack.clone();
        } else if line.contains("NG Application Protocol") || line.contains("NGAP") {
            handle_protocol_ngap(&lines, &mut i, pkt, &cause_patterns);
            pkt.underlying_protocols = protocols_stack.clone();
        } else if line.contains("Diameter Protocol") || line.contains("Diameter") {
            handle_protocol_diameter(&lines, &mut i, pkt, &cause_patterns);
            pkt.underlying_protocols = protocols_stack.clone();
        } else if line.contains("Bearer Independent Call Control") {
            handle_protocol_bicc(&lines, &mut i, pkt);
            pkt.underlying_protocols = protocols_stack.clone();
        } else if line.trim() == "BSSAP" || line.starts_with("BSSAP") {
            handle_protocol_bssap(&lines, &mut i, pkt);
            pkt.underlying_protocols = protocols_stack.clone();
        }

        i += 1;
    }

    if let Some(p) = current_packet.take() {
        if p.protocol.is_some() {
            results.push(p);
        }
    }

    results.sort_by(|a, b| {
        let ta = a.timestamp.clone().unwrap_or_default();
        let tb = b.timestamp.clone().unwrap_or_default();
        ta.cmp(&tb)
    });

    if let Some(out_csv) = output_csv {
        let mut file = fs::File::create(out_csv)?;
        writeln!(
            file,
            "frame,timestamp,protocol,message,cause,src,dst,details,underlying_protocols"
        )?;
        for p in &results {
            let details_s = python_repr_details(&p.details);
            let underlying_s = python_repr_list(&p.underlying_protocols);
            let row = vec![
                p.frame.map(|v| v.to_string()).unwrap_or_default(),
                p.timestamp
                    .as_deref()
                    .map(format_timestamp)
                    .unwrap_or_default(),
                p.protocol.clone().unwrap_or_default(),
                p.message.clone().unwrap_or_default(),
                p.cause.clone().unwrap_or_default(),
                p.src.clone().unwrap_or_default(),
                p.dst.clone().unwrap_or_default(),
                details_s,
                underlying_s,
            ];
            writeln!(
                file,
                "{}",
                row.into_iter()
                    .map(csv_escape)
                    .collect::<Vec<_>>()
                    .join(",")
            )?;
        }
    }

    if let Some(out_json) = output_json {
        let mut out_packets = results.clone();
        for p in &mut out_packets {
            if let Some(ts) = p.timestamp.clone() {
                p.timestamp = Some(format_timestamp(&ts));
            }
        }
        fs::write(out_json, serde_json::to_string_pretty(&out_packets)?)?;
    }

    Ok(results)
}

fn csv_escape(s: String) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('\r') {
        let escaped = s.replace('"', "\"\"");
        format!("\"{escaped}\"")
    } else {
        s
    }
}

fn python_repr_list(items: &[String]) -> String {
    let mut out = String::from("[");
    for (i, it) in items.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        out.push('\'');
        out.push_str(&it.replace('\'', "\\'"));
        out.push('\'');
    }
    out.push(']');
    out
}

fn python_repr_details(details: &Details) -> String {
    let mut parts: Vec<String> = vec![];
    if let Some(sip) = details.sip.as_ref() {
        let mut sip_parts: Vec<String> = vec![];
        let push = |k: &str, v: &str, buf: &mut Vec<String>| {
            buf.push(format!("'{k}': '{v}'"));
        };
        if let Some(v) = sip.from.as_deref() {
            push("from", v, &mut sip_parts);
        }
        if let Some(v) = sip.to.as_deref() {
            push("to", v, &mut sip_parts);
        }
        if let Some(v) = sip.call_id.as_deref() {
            push("call_id", v, &mut sip_parts);
        }
        if let Some(v) = sip.cseq.as_deref() {
            push("cseq", v, &mut sip_parts);
        }
        if let Some(v) = sip.cseq_method.as_deref() {
            push("cseq_method", v, &mut sip_parts);
        }
        if let Some(v) = sip.cseq_number {
            sip_parts.push(format!("'cseq_number': {v}"));
        }
        if let Some(v) = sip.method.as_deref() {
            push("method", v, &mut sip_parts);
        }
        if let Some(v) = sip.status_code {
            sip_parts.push(format!("'status_code': {v}"));
        }
        if let Some(v) = sip.reason_phrase.as_deref() {
            push("reason_phrase", v, &mut sip_parts);
        }
        if let Some(v) = sip.p_called_party_id.as_deref() {
            push("p_called_party_id", v, &mut sip_parts);
        }
        if let Some(v) = sip.via_count {
            sip_parts.push(format!("'via_count': {v}"));
        }
        if let Some(v) = sip.request_uri.as_deref() {
            push("request_uri", v, &mut sip_parts);
        }
        if let Some(v) = sip.request_uri_host.as_deref() {
            push("request_uri_host", v, &mut sip_parts);
        }
        if let Some(v) = sip.via_top.as_deref() {
            push("via_top", v, &mut sip_parts);
        }
        if let Some(v) = sip.via_sent_by.as_deref() {
            push("via_sent_by", v, &mut sip_parts);
        }
        if let Some(v) = sip.route_top.as_deref() {
            push("route_top", v, &mut sip_parts);
        }
        if let Some(v) = sip.route_host.as_deref() {
            push("route_host", v, &mut sip_parts);
        }
        if let Some(v) = sip.record_route_host.as_deref() {
            push("record_route_host", v, &mut sip_parts);
        }
        if let Some(v) = sip.reason.as_deref() {
            push("reason", v, &mut sip_parts);
        }
        parts.push(format!("'sip': {{{}}}", sip_parts.join(", ")));
    }
    if let Some(s1ap) = details.s1ap.as_ref() {
        let mut s1ap_parts: Vec<String> = vec![];
        if let Some(v) = s1ap.service_type.as_deref() {
            s1ap_parts.push(format!("'service_type': '{v}'"));
        }
        parts.push(format!("'s1ap': {{{}}}", s1ap_parts.join(", ")));
    }
    format!("{{{}}}", parts.join(", "))
}

fn extract_key_signaling(results: Vec<Packet>, max_signals: usize) -> Vec<Packet> {
    if results.len() <= max_signals {
        return results;
    }

    fn has_cause(p: &Packet) -> bool {
        p.cause
            .as_deref()
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false)
    }

    fn add_idx(idx: usize, picked: &mut Vec<usize>, seen: &mut HashSet<usize>) {
        if seen.insert(idx) {
            picked.push(idx);
        }
    }

    fn sip_priority(p: &Packet) -> u32 {
        let mut score = 0u32;
        if has_cause(p) {
            score += 100;
        }

        let proto = p.protocol.as_deref().unwrap_or("");
        if proto != "SIP" {
            score += 80;
        }

        if proto == "SIP" {
            let sip = p.details.sip.as_ref();
            let method = sip
                .and_then(|s| s.method.as_deref())
                .or(p.message.as_deref())
                .unwrap_or("")
                .to_ascii_uppercase();

            let status = sip.and_then(|s| s.status_code).unwrap_or(0);
            if status >= 400 {
                score += 50;
            } else if let Some(msg) = p.message.as_deref() {
                let t = msg.trim();
                if t.len() >= 3 && t.chars().take(3).all(|c| c.is_ascii_digit()) {
                    if let Ok(sc) = t[..3].parse::<i64>() {
                        if sc >= 400 {
                            score += 50;
                        }
                    }
                }
            }

            let important = [
                "INVITE", "REGISTER", "BYE", "CANCEL", "ACK", "PRACK", "UPDATE", "OPTIONS",
            ];
            if important.iter().any(|m| *m == method) {
                score += 60;
            }
        } else if let Some(msg) = p.message.as_deref() {
            let m = msg.to_ascii_lowercase();
            let keywords = [
                "error", "reject", "failure", "fail", "denied", "release", "detach", "delete",
                "abort", "cancel", "auth",
            ];
            if keywords.iter().any(|k| m.contains(k)) {
                score += 30;
            }
        }

        score
    }

    let mut picked: Vec<usize> = vec![];
    let mut seen: HashSet<usize> = HashSet::new();

    for (i, p) in results.iter().enumerate() {
        if has_cause(p) {
            add_idx(i, &mut picked, &mut seen);
        }
    }

    let mut proto_first_last: HashMap<String, (usize, usize)> = HashMap::new();
    for (i, p) in results.iter().enumerate() {
        let proto = p.protocol.clone().unwrap_or_else(|| "".to_string());
        proto_first_last
            .entry(proto)
            .and_modify(|v| v.1 = i)
            .or_insert((i, i));
    }
    for (_proto, (first, last)) in &proto_first_last {
        add_idx(*first, &mut picked, &mut seen);
        add_idx(*last, &mut picked, &mut seen);
    }

    for (i, p) in results.iter().enumerate() {
        if p.protocol.as_deref() != Some("SIP") {
            continue;
        }
        let sip = p.details.sip.as_ref();
        let method = sip
            .and_then(|s| s.method.as_deref())
            .or(p.message.as_deref())
            .unwrap_or("")
            .to_ascii_uppercase();
        let important = [
            "INVITE", "REGISTER", "BYE", "CANCEL", "ACK", "PRACK", "UPDATE", "OPTIONS",
        ];
        if important.iter().any(|m| *m == method) {
            add_idx(i, &mut picked, &mut seen);
        }
    }

    if picked.len() > max_signals {
        picked.sort_by(|&a, &b| {
            let pa = sip_priority(&results[a]);
            let pb = sip_priority(&results[b]);
            pb.cmp(&pa).then_with(|| a.cmp(&b))
        });
        picked.truncate(max_signals);
        picked.sort();
        return picked.into_iter().map(|i| results[i].clone()).collect();
    }

    if picked.len() < max_signals {
        let remaining: Vec<usize> = (0..results.len()).filter(|i| !seen.contains(i)).collect();
        let slots = max_signals - picked.len();
        if !remaining.is_empty() {
            let step = remaining.len() as f64 / slots as f64;
            for k in 0..slots {
                let idx = (k as f64 * step).floor() as usize;
                if idx < remaining.len() {
                    add_idx(remaining[idx], &mut picked, &mut seen);
                }
            }
        }
    }

    picked.sort();
    picked.into_iter().map(|i| results[i].clone()).collect()
}

fn identify_entities(results: &[Packet]) -> HashMap<String, String> {
    fn classify_sip_token(s: &str) -> Option<&'static str> {
        let t = s.to_ascii_lowercase();
        if t.contains("scscf") {
            Some("S-CSCF")
        } else if t.contains("icscf") {
            Some("I-CSCF")
        } else if t.contains("pcscf") || t.contains("p-cscf") || t.contains("p_cscf") {
            Some("SBC")
        } else if t.contains("sbc") {
            Some("SBC")
        } else if t.contains("as") && (t.contains(".as") || t.contains("as.") || t.contains("_as")) {
            Some("AS")
        } else {
            None
        }
    }

    fn set_role(
        roles: &mut HashMap<String, String>,
        conf: &mut HashMap<String, u8>,
        ip: &str,
        role: &str,
        score: u8,
    ) {
        if ip.trim().is_empty() || role.trim().is_empty() {
            return;
        }
        match conf.get(ip).copied() {
            Some(prev) if prev >= score => {}
            _ => {
                roles.insert(ip.to_string(), role.to_string());
                conf.insert(ip.to_string(), score);
            }
        }
    }

    fn strip_ipv6_brackets(s: &str) -> &str {
        let t = s.trim();
        if t.starts_with('[') && t.ends_with(']') && t.len() >= 2 {
            &t[1..t.len() - 1]
        } else {
            t
        }
    }

    fn extract_from_sip_host(from: &str) -> Option<String> {
        let src = from.trim();
        if src.is_empty() {
            return None;
        }
        let lower = src.to_ascii_lowercase();
        let start = lower.find("sip:").or_else(|| lower.find("sips:"))?;
        let after_scheme = &src[start..];
        let at = after_scheme.find('@')?;
        let after_at = &after_scheme[at + 1..];
        let end = after_at
            .find(|c: char| c == ';' || c == '>' || c.is_whitespace())
            .unwrap_or(after_at.len());
        let host = strip_ipv6_brackets(&after_at[..end]).trim();
        if host.is_empty() {
            None
        } else {
            Some(host.to_string())
        }
    }

    let mut ip_entities: HashMap<String, HashSet<String>> = HashMap::new();
    for p in results {
        let src = p.src.as_deref();
        let dst = p.dst.as_deref();
        if let Some(ip) = src {
            ip_entities.entry(ip.to_string()).or_default();
        }
        if let Some(ip) = dst {
            ip_entities.entry(ip.to_string()).or_default();
        }
        if let (Some(ip), Some(proto)) = (src, p.protocol.as_deref()) {
            ip_entities
                .entry(ip.to_string())
                .or_default()
                .insert(proto.to_string());
        }
        if let (Some(ip), Some(proto)) = (dst, p.protocol.as_deref()) {
            ip_entities
                .entry(ip.to_string())
                .or_default()
                .insert(proto.to_string());
        }
    }

    let mut roles: HashMap<String, String> = HashMap::new();
    let mut role_conf: HashMap<String, u8> = HashMap::new();

    for (ip, protocols) in &ip_entities {
        let role = if protocols.contains("GTPv2") && protocols.contains("DIAMETER") {
            "PGW"
        } else if protocols.contains("S1AP") && protocols.contains("GTPv2") {
            "MME"
        } else if protocols.contains("NGAP") {
            "AMF"
        } else if protocols.contains("GTPv2")
            && !protocols.contains("DIAMETER")
            && !protocols.contains("S1AP")
        {
            "SGW"
        } else if protocols.contains("S1AP") && !protocols.contains("GTPv2") {
            "eNB"
        } else if protocols.contains("SIP")
            && !(protocols.contains("S1AP")
                || protocols.contains("GTPv2")
                || protocols.contains("DIAMETER")
                || protocols.contains("NGAP"))
        {
            "IMS"
        } else if protocols.contains("DIAMETER")
            && !protocols.contains("GTPv2")
            && !protocols.contains("SIP")
        {
            "PCRF/HSS"
        } else {
            "Unknown_IP"
        };
        set_role(&mut roles, &mut role_conf, ip, role, 1);
    }

    let call_side = infer_call_side(results);

    for p in results {
        if p.protocol.as_deref() != Some("SIP") {
            continue;
        }

        let src_ip = p.src.as_deref();
        let dst_ip = p.dst.as_deref();
        let sip = p.details.sip.as_ref();

        let msg = p.message.as_deref().unwrap_or("");
        let sip_method = sip
            .and_then(|s| s.method.as_deref())
            .or(p.message.as_deref())
            .unwrap_or("");
        let sip_cseq_method = sip.and_then(|s| s.cseq_method.as_deref()).unwrap_or("");
        let sip_cseq = sip.and_then(|s| s.cseq.as_deref()).unwrap_or("");

        let mut is_response = false;
        if sip.and_then(|s| s.status_code).is_some()
            || (msg.len() >= 3 && msg.chars().take(3).all(|c| c.is_ascii_digit()))
        {
            is_response = true;
        }

        let sip_has_ipv6 = p.underlying_protocols.iter().any(|x| x == "IPv6")
            || src_ip.map(|v| v.contains(':')).unwrap_or(false)
            || dst_ip.map(|v| v.contains(':')).unwrap_or(false);
        let sip_is_access = sip_has_ipv6
            || p
                .underlying_protocols
                .iter()
                .any(|x| x == "GTP-U" || x == "GTP");

        let via_count = sip.and_then(|s| s.via_count);

        if !is_response {
            if let Some(s) = sip {
                if sip_method == "INVITE" || sip_method == "REGISTER" {
                    if let Some(from) = s.from.as_deref().and_then(extract_from_sip_host) {
                        if src_ip == Some(from.as_str()) {
                            if let Some(ip) = src_ip {
                                set_role(&mut roles, &mut role_conf, ip, "UE", 3);
                            }
                            if let Some(ip) = dst_ip {
                                set_role(&mut roles, &mut role_conf, ip, "SBC", 3);
                            }
                        } else if dst_ip == Some(from.as_str()) {
                            if let Some(ip) = dst_ip {
                                set_role(&mut roles, &mut role_conf, ip, "UE", 3);
                            }
                            if let Some(ip) = src_ip {
                                set_role(&mut roles, &mut role_conf, ip, "SBC", 3);
                            }
                        }
                    }

                    if let Some(req_host) = s.request_uri_host.as_deref().map(strip_ipv6_brackets) {
                        if dst_ip == Some(req_host) {
                            if let Some(ip) = src_ip {
                                set_role(&mut roles, &mut role_conf, ip, "UE", 3);
                            }
                            if let Some(ip) = dst_ip {
                                set_role(&mut roles, &mut role_conf, ip, "SBC", 3);
                            }
                        } else if src_ip == Some(req_host) {
                            if let Some(ip) = dst_ip {
                                set_role(&mut roles, &mut role_conf, ip, "UE", 3);
                            }
                            if let Some(ip) = src_ip {
                                set_role(&mut roles, &mut role_conf, ip, "SBC", 3);
                            }
                        }
                    }
                }
            }

            if sip_method == "REGISTER" {
                if let Some(ip) = src_ip {
                    set_role(&mut roles, &mut role_conf, ip, "UE", 3);
                }
                if let Some(ip) = dst_ip {
                    set_role(&mut roles, &mut role_conf, ip, "SBC", 3);
                }
            } else if sip_method == "INVITE" {
                match via_count {
                    Some(1) => {
                        if let Some(ip) = src_ip {
                            set_role(&mut roles, &mut role_conf, ip, "UE", 3);
                        }
                        if let Some(ip) = dst_ip {
                            set_role(&mut roles, &mut role_conf, ip, "SBC", 3);
                        }
                    }
                    Some(n) if n > 1 => {
                        if let Some(ip) = src_ip {
                            set_role(&mut roles, &mut role_conf, ip, "SBC", 3);
                        }
                    }
                    _ => {}
                }
            }
        }

        if let (Some(a), Some(b)) = (src_ip, dst_ip) {
            let a_role = roles.get(a).map(|v| v.as_str());
            let b_role = roles.get(b).map(|v| v.as_str());
            if a_role == Some("UE") && b_role != Some("SBC") {
                set_role(&mut roles, &mut role_conf, b, "SBC", 2);
            } else if b_role == Some("UE") && a_role != Some("SBC") {
                set_role(&mut roles, &mut role_conf, a, "SBC", 2);
            }
        }

        if sip_is_access {
            if !is_response && sip_method == "REGISTER" && sip_has_ipv6 {
                if let Some(ip) = src_ip {
                    set_role(&mut roles, &mut role_conf, ip, "UE", 3);
                }
                if let Some(ip) = dst_ip {
                    set_role(&mut roles, &mut role_conf, ip, "SBC", 3);
                }
            } else {
                let invite_side_from_packet = if !is_response && sip_method == "INVITE" {
                    let p_called = sip
                        .and_then(|s| s.p_called_party_id.as_deref())
                        .unwrap_or("")
                        .trim();
                    if !p_called.is_empty() {
                        Some("callee")
                    } else {
                        match via_count {
                            Some(1) => Some("caller"),
                            Some(n) if n > 1 => Some("callee"),
                            _ => None,
                        }
                    }
                } else {
                    None
                };

                let invite_side = invite_side_from_packet.or(call_side.as_deref());
                let is_invite_txn = sip_cseq_method == "INVITE" || sip_cseq.contains("INVITE");

                if !is_response && sip_method == "INVITE" {
                    if invite_side == Some("callee") {
                        if let Some(ip) = src_ip {
                            set_role(&mut roles, &mut role_conf, ip, "SBC", 3);
                        }
                        if let Some(ip) = dst_ip {
                            set_role(&mut roles, &mut role_conf, ip, "UE", 3);
                        }
                    } else if invite_side == Some("caller") {
                        if let Some(ip) = src_ip {
                            set_role(&mut roles, &mut role_conf, ip, "UE", 3);
                        }
                        if let Some(ip) = dst_ip {
                            set_role(&mut roles, &mut role_conf, ip, "SBC", 3);
                        }
                    }
                } else if is_response && is_invite_txn {
                    if invite_side == Some("callee") {
                        if let Some(ip) = src_ip {
                            set_role(&mut roles, &mut role_conf, ip, "UE", 3);
                        }
                        if let Some(ip) = dst_ip {
                            set_role(&mut roles, &mut role_conf, ip, "SBC", 3);
                        }
                    } else if invite_side == Some("caller") {
                        if let Some(ip) = src_ip {
                            set_role(&mut roles, &mut role_conf, ip, "SBC", 3);
                        }
                        if let Some(ip) = dst_ip {
                            set_role(&mut roles, &mut role_conf, ip, "UE", 3);
                        }
                    }
                }

                let base = if invite_side == Some("callee") {
                    ("SBC", "UE")
                } else {
                    ("UE", "SBC")
                };
                let (src_role, dst_role) = if is_response {
                    (base.1, base.0)
                } else {
                    (base.0, base.1)
                };
                if let Some(ip) = src_ip {
                    set_role(&mut roles, &mut role_conf, ip, src_role, 2);
                }
                if let Some(ip) = dst_ip {
                    set_role(&mut roles, &mut role_conf, ip, dst_role, 2);
                }
            }
        }

        if let Some(s) = sip {
            if !is_response {
                let via_token = s
                    .via_sent_by
                    .as_deref()
                    .and_then(classify_sip_token)
                    .or_else(|| s.via_top.as_deref().and_then(classify_sip_token));
                if let Some(v) = via_token {
                    if let Some(ip) = src_ip {
                        set_role(&mut roles, &mut role_conf, ip, v, 2);
                    }
                }

                let route_token = s
                    .route_host
                    .as_deref()
                    .and_then(classify_sip_token)
                    .or_else(|| s.route_top.as_deref().and_then(classify_sip_token))
                    .or_else(|| s.record_route_host.as_deref().and_then(classify_sip_token))
                    .or_else(|| s.request_uri_host.as_deref().and_then(classify_sip_token));
                if let Some(v) = route_token {
                    if let Some(ip) = dst_ip {
                        set_role(&mut roles, &mut role_conf, ip, v, 2);
                    }
                }
            }
        }
    }

    let has_sbc_like = roles.values().any(|v| v == "SBC");
    let ue_ips: Vec<String> = roles
        .iter()
        .filter_map(|(ip, role)| if role == "UE" { Some(ip.clone()) } else { None })
        .collect();

    if !has_sbc_like && !ue_ips.is_empty() {
        let mut peer_cnt: HashMap<String, usize> = HashMap::new();
        for p in results {
            if p.protocol.as_deref() != Some("SIP") {
                continue;
            }
            let src = p.src.as_deref().unwrap_or("");
            let dst = p.dst.as_deref().unwrap_or("");
            if ue_ips.iter().any(|u| u == src) {
                *peer_cnt.entry(dst.to_string()).or_insert(0) += 1;
            } else if ue_ips.iter().any(|u| u == dst) {
                *peer_cnt.entry(src.to_string()).or_insert(0) += 1;
            }
        }

        if let Some((best_ip, _)) = peer_cnt.into_iter().max_by_key(|(_, c)| *c) {
            if !best_ip.trim().is_empty() && !ue_ips.iter().any(|u| u == &best_ip) {
                set_role(&mut roles, &mut role_conf, &best_ip, "SBC", 2);
            }
        }
    }

    roles
}

fn sanitize_mermaid_label(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\r' | '\n' | '\t' => out.push(' '),
            c if c.is_control() => {}
            '"' | '\'' => out.push(' '),
            ';' => out.push(','),
            c => out.push(c),
        }
    }

    let collapsed = out.split_whitespace().collect::<Vec<_>>().join(" ");
    const MAX_LEN: usize = 220;
    if collapsed.len() > MAX_LEN {
        let mut t = collapsed;
        t.truncate(MAX_LEN);
        t.push_str("...");
        t
    } else {
        collapsed
    }
}

fn sanitize_mermaid_quoted(s: &str) -> String {
    sanitize_mermaid_label(s)
}

fn strip_sip_reason_text_param(s: &str) -> String {
    let src = s.trim();
    if src.is_empty() {
        return String::new();
    }

    let mut out = src.to_string();
    let lower = out.to_ascii_lowercase();
    let Some(pos) = lower.find("text=") else {
        return out;
    };

    let mut rm_start = pos;
    let bytes = out.as_bytes();
    while rm_start > 0 {
        let b = bytes[rm_start - 1];
        if b == b';' || b == b',' || b == b' ' {
            rm_start -= 1;
        } else {
            break;
        }
    }

    let mut rm_end = out.len();
    if let Some(p) = lower[pos..].find("reason protocols") {
        rm_end = pos + p;
    }
    if rm_end == out.len() {
        if let Some(p) = out[pos..].find(';') {
            rm_end = pos + p;
        }
    }
    if rm_end == out.len() {
        if let Some(p) = out[pos..].find(')') {
            rm_end = pos + p;
        }
    }

    if rm_start < rm_end && rm_end <= out.len() {
        out.replace_range(rm_start..rm_end, "");
    }

    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn mermaid_safe_id(name: &str) -> String {
    let n = name.trim();
    let mut out = String::with_capacity(n.len().max(8));
    for ch in n.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    while out.contains("__") {
        out = out.replace("__", "_");
    }
    let out = out.trim_matches('_').to_string();
    let mut out = if out.is_empty() { "E".to_string() } else { out };
    if out.chars().next().unwrap_or('E').is_ascii_digit() {
        out = format!("E_{out}");
    }
    out
}

fn generate_mermaid(
    results: &[Packet],
    ip_to_entity: &HashMap<String, String>,
    call_side: Option<&str>,
) -> String {
    let mut entities: HashSet<String> = HashSet::new();
    for p in results {
        match p.protocol.as_deref() {
            Some("SIP") => {
                entities.insert("UE".to_string());
                entities.insert("SBC".to_string());
                entities.insert("IMS".to_string());
            }
            Some("GTPv2") => {
                entities.insert("SGW".to_string());
                entities.insert("PGW".to_string());
            }
            Some("S1AP") => {
                entities.insert("eNB".to_string());
                entities.insert("MME".to_string());
            }
            Some("DIAMETER") => {
                entities.insert("PCRF".to_string());
            }
            Some("NGAP") => {
                entities.insert("AMF".to_string());
            }
            _ => {}
        }

        if let Some(ip) = p.src.as_deref() {
            let name = ip_to_entity
                .get(ip)
                .cloned()
                .unwrap_or_else(|| ip.to_string());
            entities.insert(name);
        }
        if let Some(ip) = p.dst.as_deref() {
            let name = ip_to_entity
                .get(ip)
                .cloned()
                .unwrap_or_else(|| ip.to_string());
            entities.insert(name);
        }
    }

    let ordered = [
        "UE", "eNB", "MME", "AMF", "SMF", "PGW", "UPF", "PCRF", "SBC", "P-CSCF", "I-CSCF", "S-CSCF", "AS", "IMS",
    ];

    let mut id_map: HashMap<String, String> = HashMap::new();
    let mut used: HashSet<String> = HashSet::new();

    let mut get_id = |name: &str| -> String {
        if let Some(id) = id_map.get(name) {
            return id.clone();
        }
        let base = mermaid_safe_id(name);
        let mut id = base.clone();
        let mut n = 2usize;
        while used.contains(&id) {
            id = format!("{base}_{n}");
            n += 1;
        }
        used.insert(id.clone());
        id_map.insert(name.to_string(), id.clone());
        id
    };

    let mut mermaid: Vec<String> = vec!["sequenceDiagram".to_string()];
    for p in ordered {
        if entities.contains(p) {
            let id = get_id(p);
            let label = sanitize_mermaid_quoted(p);
            mermaid.push(format!("    participant {id} as \"{label}\""));
        }
    }
    let mut extra: Vec<String> = entities
        .iter()
        .filter(|e| !ordered.contains(&e.as_str()))
        .cloned()
        .collect();
    extra.sort();
    for e in extra {
        let id = get_id(&e);
        let label = sanitize_mermaid_quoted(&e);
        mermaid.push(format!("    participant {id} as \"{label}\""));
    }

    let s1ap_ul_nas_re = Regex::new(r"(?i)Uplink NAS Transport|id-uplinkNASTransport").unwrap();
    let s1ap_dl_nas_re = Regex::new(r"(?i)Downlink NAS Transport|id-downlinkNASTransport").unwrap();

    let mut sip_access_ip_role: HashMap<String, String> = HashMap::new();
    let mut sip_access_ip_conf: HashMap<String, u8> = HashMap::new();

    fn set_sip_ip_role(
        sip_access_ip_role: &mut HashMap<String, String>,
        sip_access_ip_conf: &mut HashMap<String, u8>,
        ip: &str,
        role: &str,
        conf: u8,
    ) {
        if role != "UE" && role != "SBC" {
            return;
        }
        match sip_access_ip_conf.get(ip).copied() {
            Some(prev) if prev >= conf => {}
            _ => {
                sip_access_ip_role.insert(ip.to_string(), role.to_string());
                sip_access_ip_conf.insert(ip.to_string(), conf);
            }
        }
    }

    for packet in results {
        let src_ip = packet.src.as_deref();
        let dst_ip = packet.dst.as_deref();
        let protocol = packet.protocol.as_deref().unwrap_or("");
        let message = packet.message.clone().unwrap_or_default();

        let sip = packet.details.sip.as_ref();
        let sip_method = sip
            .and_then(|s| s.method.as_deref())
            .or(packet.message.as_deref())
            .unwrap_or("");
        let sip_cseq_method = sip.and_then(|s| s.cseq_method.as_deref()).unwrap_or("");
        let sip_cseq = sip.and_then(|s| s.cseq.as_deref()).unwrap_or("");

        let mut is_response = false;
        if protocol == "SIP" {
            if sip.and_then(|s| s.status_code).is_some()
                || (message.len() >= 3 && message.chars().take(3).all(|c| c.is_ascii_digit()))
            {
                is_response = true;
            }
        } else if protocol == "GTPv2" {
            is_response = !message.contains("Request");
        } else if protocol == "S1AP" {
            is_response = !message.contains("Request") && !message.contains("request");
        } else if protocol == "NGAP" {
            is_response = !message.contains("Request");
        } else if protocol == "DIAMETER" {
            is_response = message.contains("Answer") || message.contains("Response");
        }

        let mut sip_forced_leg = false;

        let sip_has_ipv6 = packet.underlying_protocols.iter().any(|p| p == "IPv6")
            || src_ip.map(|v| v.contains(':')).unwrap_or(false)
            || dst_ip.map(|v| v.contains(':')).unwrap_or(false);
        let sip_is_access = protocol == "SIP"
            && (sip_has_ipv6
                || packet
                    .underlying_protocols
                    .iter()
                    .any(|p| p == "GTP-U" || p == "GTP"));

        let (src_entity, dst_entity) = if sip_is_access {
            if !is_response && sip_method == "REGISTER" && sip_has_ipv6 {
                sip_forced_leg = true;
                (Some("UE".to_string()), Some("SBC".to_string()))
            } else {
                let invite_side_from_packet = if !is_response && sip_method == "INVITE" {
                    let p_called = sip
                        .and_then(|s| s.p_called_party_id.as_deref())
                        .unwrap_or("")
                        .trim();
                    if !p_called.is_empty() {
                        Some("callee")
                    } else {
                        match sip.and_then(|s| s.via_count) {
                            Some(1) => Some("caller"),
                            Some(n) if n > 1 => Some("callee"),
                            _ => None,
                        }
                    }
                } else {
                    None
                };

                let invite_side = invite_side_from_packet.or(call_side);
                let is_invite_txn = sip_cseq_method == "INVITE" || sip_cseq.contains("INVITE");

                if !is_response && sip_method == "INVITE" {
                    if invite_side == Some("callee") {
                        sip_forced_leg = true;
                        (Some("SBC".to_string()), Some("UE".to_string()))
                    } else if invite_side == Some("caller") {
                        sip_forced_leg = true;
                        (Some("UE".to_string()), Some("SBC".to_string()))
                    } else {
                        (None, None)
                    }
                } else if is_response && is_invite_txn {
                    if invite_side == Some("callee") {
                        sip_forced_leg = true;
                        (Some("UE".to_string()), Some("SBC".to_string()))
                    } else if invite_side == Some("caller") {
                        sip_forced_leg = true;
                        (Some("SBC".to_string()), Some("UE".to_string()))
                    } else {
                        (None, None)
                    }
                } else {
                    (None, None)
                }
            }
        } else {
            (None, None)
        };

        let (src_entity, dst_entity) = if src_entity.is_some() || dst_entity.is_some() {
            (src_entity, dst_entity)
        } else if protocol == "SIP" {
            if let (Some(a), Some(b)) = (
                src_ip.and_then(|ip| sip_access_ip_role.get(ip)).cloned(),
                dst_ip.and_then(|ip| sip_access_ip_role.get(ip)).cloned(),
            ) {
                (Some(a), Some(b))
            } else {
                let up = &packet.underlying_protocols;
                let is_access = sip_has_ipv6 || up.iter().any(|p| p == "GTP-U" || p == "GTP");
                if is_access {
                    let base = if call_side == Some("callee") {
                        ("SBC", "UE")
                    } else {
                        ("UE", "SBC")
                    };
                    let (a, b) = if is_response { (base.1, base.0) } else { base };
                    (Some(a.to_string()), Some(b.to_string()))
                } else {
                    let src_mapped = src_ip.and_then(|ip| ip_to_entity.get(ip)).cloned();
                    let dst_mapped = dst_ip.and_then(|ip| ip_to_entity.get(ip)).cloned();
                    let a = src_mapped.unwrap_or_else(|| src_ip.unwrap_or("Unknown_IP").to_string());
                    let b = dst_mapped.unwrap_or_else(|| dst_ip.unwrap_or("Unknown_IP").to_string());
                    (Some(a), Some(b))
                }
            }
        } else if protocol == "S1AP" && s1ap_ul_nas_re.is_match(&message) {
            (Some("UE".to_string()), Some("MME".to_string()))
        } else if protocol == "S1AP" && s1ap_dl_nas_re.is_match(&message) {
            (Some("MME".to_string()), Some("UE".to_string()))
        } else if protocol == "S1AP" && message.contains("NAS") {
            (Some("UE".to_string()), Some("MME".to_string()))
        } else if protocol == "NGAP" && message.contains("NAS") {
            (Some("UE".to_string()), Some("AMF".to_string()))
        } else if protocol == "S1AP" {
            if message.contains("Extended service request") || message.contains("0x4c") {
                (Some("eNB".to_string()), Some("MME".to_string()))
            } else if message.contains("id-UEContextModification") || message.contains("21") {
                (Some("MME".to_string()), Some("eNB".to_string()))
            } else if message.contains("id-UEContextReleaseRequest") || message.contains("18") {
                (Some("eNB".to_string()), Some("MME".to_string()))
            } else if message.contains("id-UEContextRelease")
                || message.contains("23")
                || message.contains("id-E-RABSetup")
                || message.contains("5")
                || message.contains("id-E-RABRelease")
                || message.contains("7")
            {
                (Some("MME".to_string()), Some("eNB".to_string()))
            } else {
                (
                    Some(
                        src_ip
                            .and_then(|ip| ip_to_entity.get(ip))
                            .cloned()
                            .unwrap_or_else(|| src_ip.unwrap_or("Unknown_IP").to_string()),
                    ),
                    Some(
                        dst_ip
                            .and_then(|ip| ip_to_entity.get(ip))
                            .cloned()
                            .unwrap_or_else(|| dst_ip.unwrap_or("Unknown_IP").to_string()),
                    ),
                )
            }
        } else if protocol == "GTPv2" {
            let original_src = src_ip
                .and_then(|ip| ip_to_entity.get(ip))
                .cloned()
                .unwrap_or_else(|| src_ip.unwrap_or("Unknown_IP").to_string());
            let original_dst = dst_ip
                .and_then(|ip| ip_to_entity.get(ip))
                .cloned()
                .unwrap_or_else(|| dst_ip.unwrap_or("Unknown_IP").to_string());
            if original_src == "SGW" || original_dst == "SGW" {
                let is_request = message.contains("Request") && !message.contains("Response");
                let is_response = message.contains("Response");
                if is_request {
                    (Some("MME".to_string()), Some("PGW".to_string()))
                } else if is_response {
                    (Some("PGW".to_string()), Some("MME".to_string()))
                } else {
                    (
                        Some(if original_src == "SGW" {
                            "MME".to_string()
                        } else {
                            original_src.clone()
                        }),
                        Some(if original_dst == "SGW" {
                            "PGW".to_string()
                        } else {
                            original_dst.clone()
                        }),
                    )
                }
            } else {
                (Some(original_src), Some(original_dst))
            }
        } else {
            (
                Some(
                    src_ip
                        .and_then(|ip| ip_to_entity.get(ip))
                        .cloned()
                        .unwrap_or_else(|| src_ip.unwrap_or("Unknown_IP").to_string()),
                ),
                Some(
                    dst_ip
                        .and_then(|ip| ip_to_entity.get(ip))
                        .cloned()
                        .unwrap_or_else(|| dst_ip.unwrap_or("Unknown_IP").to_string()),
                ),
            )
        };

        let mut src_entity = src_entity.unwrap_or_else(|| "Unknown_IP".to_string());
        let mut dst_entity = dst_entity.unwrap_or_else(|| "Unknown_IP".to_string());

        if protocol == "SIP" {
            if dst_entity == "AS" && src_entity != "S-CSCF" {
                src_entity = "S-CSCF".to_string();
            }
            if src_entity == "AS" && dst_entity != "S-CSCF" {
                dst_entity = "S-CSCF".to_string();
            }
        }

        if src_entity == dst_entity && src_entity != "Unknown_IP" {
            if protocol == "S1AP" {
                if src_entity == "eNB" {
                    dst_entity = "MME".to_string();
                } else if src_entity == "MME" {
                    dst_entity = "eNB".to_string();
                }
            } else if protocol == "GTPv2" {
                if src_entity == "MME" {
                    dst_entity = "PGW".to_string();
                } else if src_entity == "PGW" {
                    dst_entity = "MME".to_string();
                }
            } else if protocol == "SIP" {
                if src_ip != dst_ip {
                    if let Some(ip) = src_ip {
                        src_entity = ip.to_string();
                    }
                    if let Some(ip) = dst_ip {
                        dst_entity = ip.to_string();
                    }
                }
            }
        }
        if src_entity == dst_entity && src_entity != "Unknown_IP" {
            continue;
        }

        if protocol == "S1AP" {
            if !is_response {
                if dst_entity != "MME" {
                    let old_dst = dst_entity;
                    dst_entity = "MME".to_string();
                    src_entity = old_dst;
                }
            } else if src_entity != "MME" {
                dst_entity = src_entity.clone();
                src_entity = "MME".to_string();
            }
        } else if protocol == "NGAP" {
            if !is_response {
                if dst_entity != "AMF" {
                    let old_dst = dst_entity;
                    dst_entity = "AMF".to_string();
                    src_entity = old_dst;
                }
            } else if src_entity != "AMF" {
                dst_entity = src_entity.clone();
                src_entity = "AMF".to_string();
            }
        } else if protocol == "GTPv2" {
            if !is_response {
                if dst_entity != "PGW" && dst_entity != "UPF" {
                    let old_dst = dst_entity;
                    dst_entity = "PGW".to_string();
                    src_entity = old_dst;
                }
            } else if src_entity != "PGW" && src_entity != "UPF" {
                dst_entity = src_entity.clone();
                src_entity = "PGW".to_string();
            }
        } else if protocol != "SIP" && is_response && !sip_forced_leg {
            std::mem::swap(&mut src_entity, &mut dst_entity);
        }

        if protocol == "SIP" {
            let conf = if sip_forced_leg {
                3
            } else if packet
                .underlying_protocols
                .iter()
                .any(|p| p == "GTP-U" || p == "GTP")
            {
                2
            } else {
                1
            };

            if let Some(ip) = src_ip {
                set_sip_ip_role(
                    &mut sip_access_ip_role,
                    &mut sip_access_ip_conf,
                    ip,
                    &src_entity,
                    conf,
                );
            }
            if let Some(ip) = dst_ip {
                set_sip_ip_role(
                    &mut sip_access_ip_role,
                    &mut sip_access_ip_conf,
                    ip,
                    &dst_entity,
                    conf,
                );
            }
        }

        let arrow = if is_response { "-->>" } else { "->>" };
        let ts = packet.timestamp.clone().unwrap_or_default();

        let ts_txt = sanitize_mermaid_label(&format_timestamp(&ts));
        let msg_txt = sanitize_mermaid_quoted(
            &packet
                .message
                .clone()
                .unwrap_or_else(|| protocol.to_string()),
        );
        let mut message_text = format!("{} {}", ts_txt, msg_txt).trim().to_string();

        if let Some(c) = packet.cause.as_deref() {
            let cleaned = strip_sip_reason_text_param(c);
            let cause_txt = sanitize_mermaid_quoted(&cleaned);
            if !cause_txt.is_empty() {
                message_text.push_str(&format!(" ({cause_txt})"));
            }
        }

        let src_id = get_id(&src_entity);
        let dst_id = get_id(&dst_entity);
        mermaid.push(format!("    {src_id}{arrow}{dst_id}: {message_text}"));
    }

    mermaid.join("\n")
}

fn build_entity_debug(
    packets: &[Packet],
    ip_to_entity: &HashMap<String, String>,
) -> serde_json::Value {
    let mut role_count: HashMap<String, usize> = HashMap::new();
    let mut ue_ips: Vec<String> = vec![];
    let mut sbc_ips: Vec<String> = vec![];
    let mut ims_ips: Vec<String> = vec![];

    for (ip, role) in ip_to_entity {
        *role_count.entry(role.clone()).or_insert(0) += 1;
        if role == "UE" {
            ue_ips.push(ip.clone());
        } else if role == "SBC" {
            sbc_ips.push(ip.clone());
        } else if role == "IMS" {
            ims_ips.push(ip.clone());
        }
    }

    ue_ips.sort();
    sbc_ips.sort();
    ims_ips.sort();

    let mut proto_count: HashMap<String, usize> = HashMap::new();
    let mut sip_total = 0usize;
    let mut sip_missing_src_dst = 0usize;
    let mut sip_has_ipv6 = 0usize;
    let mut sip_has_gtp = 0usize;
    let mut access_sip_total = 0usize;

    let mut sip_samples: Vec<serde_json::Value> = vec![];
    let mut ue_peer_not_sbc: Vec<serde_json::Value> = vec![];

    for p in packets {
        let proto = p.protocol.as_deref().unwrap_or("");
        if !proto.is_empty() {
            *proto_count.entry(proto.to_string()).or_insert(0) += 1;
        }

        if proto != "SIP" {
            continue;
        }

        sip_total += 1;

        let src = p.src.as_deref();
        let dst = p.dst.as_deref();
        if src.is_none() || dst.is_none() {
            sip_missing_src_dst += 1;
        }

        let src_s = src.unwrap_or("");
        let dst_s = dst.unwrap_or("");

        let has_ipv6 = p.underlying_protocols.iter().any(|x| x == "IPv6")
            || src_s.contains(':')
            || dst_s.contains(':');
        let has_gtp = p
            .underlying_protocols
            .iter()
            .any(|x| x == "GTP-U" || x == "GTP" || x == "GTPv1");

        if has_ipv6 {
            sip_has_ipv6 += 1;
        }
        if has_gtp {
            sip_has_gtp += 1;
        }

        let is_access = has_ipv6 || has_gtp;
        if is_access {
            access_sip_total += 1;
        }

        if sip_samples.len() < 30 {
            sip_samples.push(serde_json::json!({
                "frame": p.frame,
                "timestamp": p.timestamp,
                "message": p.message,
                "src": src,
                "dst": dst,
                "underlying_protocols": p.underlying_protocols,
                "is_access": is_access,
                "src_role": src.and_then(|ip| ip_to_entity.get(ip)).cloned(),
                "dst_role": dst.and_then(|ip| ip_to_entity.get(ip)).cloned(),
            }));
        }

        if !is_access {
            continue;
        }

        if src_s.is_empty() || dst_s.is_empty() {
            continue;
        }

        let src_role = ip_to_entity
            .get(src_s)
            .cloned()
            .unwrap_or_else(|| "Unknown_IP".to_string());
        let dst_role = ip_to_entity
            .get(dst_s)
            .cloned()
            .unwrap_or_else(|| "Unknown_IP".to_string());

        let ue_side = if src_role == "UE" {
            Some("src")
        } else if dst_role == "UE" {
            Some("dst")
        } else {
            None
        };

        let peer_is_sbc = (src_role == "UE" && dst_role == "SBC") || (dst_role == "UE" && src_role == "SBC");
        if ue_side.is_some() && !peer_is_sbc {
            ue_peer_not_sbc.push(serde_json::json!({
                "frame": p.frame,
                "timestamp": p.timestamp,
                "message": p.message,
                "cause": p.cause,
                "src": src_s,
                "dst": dst_s,
                "src_role": src_role,
                "dst_role": dst_role,
                "underlying_protocols": p.underlying_protocols,
            }));
        }
    }

    serde_json::json!({
        "protocol_count": proto_count,
        "ip_role_count": role_count,
        "ue_ips": ue_ips,
        "sbc_ips": sbc_ips,
        "ims_ips": ims_ips,
        "sip_total": sip_total,
        "sip_missing_src_dst": sip_missing_src_dst,
        "sip_has_ipv6": sip_has_ipv6,
        "sip_has_gtp": sip_has_gtp,
        "access_sip_total": access_sip_total,
        "sip_samples": sip_samples,
        "access_sip_ue_peer_not_sbc": ue_peer_not_sbc,
    })
}

fn main() -> Result<()> {
    let args = Args::parse();

    if let Some(lp) = args
        .license
        .as_deref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        let vr = llm_license::verify_license(Path::new(lp))
            .map_err(|e| anyhow!("未授权：{e}"))?;
        if !vr.ok {
            let reason = vr
                .reason
                .unwrap_or_else(|| "license verify failed".to_string());
            return Err(anyhow!("未授权：{reason}"));
        }
    }

    if args.summary {
        let pcap = args
            .pcap
            .as_deref()
            .ok_or_else(|| anyhow!("--summary 模式必须提供PCAP文件"))?;
        // TODO: fshark 模式暂时禁用，待 ip_to_entity 映射等问题修复后恢复
        let use_fshark = false;
        if use_fshark {
            // fshark summary: decode then build summary from packets
            let size_bytes = fs::metadata(pcap).map(|m| m.len()).unwrap_or(0);
            if size_bytes > args.max_size_kb.saturating_mul(1024) {
                println!("{}", serde_json::to_string_pretty(&serde_json::json!({"too_large": true}))?);
                return Ok(());
            }
            let xdr_file = args.xdr.clone().unwrap_or_else(|| {
                let dir = std::env::temp_dir().join(format!("fshark_summary_{}", std::process::id()));
                let _ = fs::create_dir_all(&dir);
                dir.join("summary_xdr.txt").to_string_lossy().to_string()
            });
            if args.xdr.is_none() {
                run_fshark(pcap, &xdr_file, args.fshark.as_deref())?;
            }
            let packets = parse_fshark_xdr(&xdr_file)?;
            let summary = build_fshark_summary(pcap, &packets, args.max_size_kb, args.fshark.as_deref());
            println!("{}", serde_json::to_string_pretty(&summary)?);
            return Ok(());
        } else {
            let summary = get_pcap_summary(
                pcap,
                &args.filter,
                args.max_size_kb,
                args.tshark.as_deref(),
                args.debug_tshark,
            )?;
            println!("{}", serde_json::to_string_pretty(&summary)?);
            return Ok(());
        }
    }

    // TODO: fshark 模式暂时禁用，待 ip_to_entity 映射等问题修复后恢复
    let use_fshark = false;

    if !use_fshark && args.pcap.is_none() && args.text.is_none() {
        return Err(anyhow!("必须提供PCAP文件或Wireshark文本输出文件"));
    }
    if use_fshark && args.pcap.is_none() && args.xdr.is_none() {
        return Err(anyhow!("fshark模式必须提供 --pcap 或 --xdr"));
    }

    if let Some(pcap) = args.pcap.as_deref() {
        let size_bytes = fs::metadata(pcap).map(|m| m.len()).unwrap_or(0);
        if size_bytes > args.max_size_kb.saturating_mul(1024) {
            return Ok(());
        }
    }

    let base_name = if let Some(pcap) = args.pcap.as_deref() {
        Path::new(pcap)
            .with_extension("")
            .to_string_lossy()
            .to_string()
    } else if args.xdr.is_some() {
        "fshark_output".to_string()
    } else {
        "wireshark_output".to_string()
    };

    let csv_output = args.csv.clone();
    let json_output = args
        .json
        .clone()
        .unwrap_or_else(|| format!("{base_name}_signaling.json"));
    let mermaid_output = args
        .mermaid
        .clone()
        .unwrap_or_else(|| format!("{base_name}_mermaid.txt"));

    let (packets, decoded_text_label) = if use_fshark {
        // fshark 模式
        let xdr_file = if let Some(xdr) = args.xdr.as_deref() {
            xdr.to_string()
        } else if let Some(pcap) = args.pcap.as_deref() {
            let xdr_output = format!("{base_name}_xdr.txt");
            run_fshark(pcap, &xdr_output, args.fshark.as_deref())?;
            xdr_output
        } else {
            return Err(anyhow!("fshark模式必须提供 --pcap 或 --xdr"));
        };
        let pkts = parse_fshark_xdr(&xdr_file)?;
        (pkts, xdr_file)
    } else {
        // tshark 模式（原有逻辑）
        let text_output = if let Some(pcap) = args.pcap.as_deref() {
            let t = args
                .text
                .clone()
                .unwrap_or_else(|| format!("{base_name}_decoded.txt"));
            run_tshark(pcap, &t, Some(&args.filter), args.tshark.as_deref())?;
            t
        } else {
            args.text.clone().unwrap()
        };
        let pkts = parse_wireshark_output(&text_output, None, None)?;
        (pkts, text_output)
    };
    let ip_to_entity = identify_entities(&packets);

    let mut out_packets = packets.clone();
    for p in &mut out_packets {
        if let Some(ts) = p.timestamp.clone() {
            p.timestamp = Some(format_timestamp(&ts));
        }

        if let Some(ip) = p.src.as_deref() {
            if let Some(v) = ip_to_entity.get(ip) {
                p.src_entity = Some(v.clone());
            }
        }
        if let Some(ip) = p.dst.as_deref() {
            if let Some(v) = ip_to_entity.get(ip) {
                p.dst_entity = Some(v.clone());
            }
        }
    }

    if let Some(p) = csv_output.as_deref() {
        let mut file = fs::File::create(p)?;
        writeln!(
            file,
            "frame,timestamp,protocol,message,cause,src,src_entity,dst,dst_entity,details,underlying_protocols"
        )?;
        for p in &out_packets {
            let details_s = python_repr_details(&p.details);
            let underlying_s = python_repr_list(&p.underlying_protocols);
            let row = vec![
                p.frame.map(|v| v.to_string()).unwrap_or_default(),
                p.timestamp.as_deref().unwrap_or("").to_string(),
                p.protocol.as_deref().unwrap_or("").to_string(),
                p.message.as_deref().unwrap_or("").to_string(),
                p.cause.as_deref().unwrap_or("").to_string(),
                p.src.as_deref().unwrap_or("").to_string(),
                p.src_entity.as_deref().unwrap_or("").to_string(),
                p.dst.as_deref().unwrap_or("").to_string(),
                p.dst_entity.as_deref().unwrap_or("").to_string(),
                details_s,
                underlying_s,
            ];
            writeln!(
                file,
                "{}",
                row.into_iter()
                    .map(csv_escape)
                    .collect::<Vec<_>>()
                    .join(",")
            )?;
        }
    }

    fs::write(&json_output, serde_json::to_string_pretty(&out_packets)?)?;

    let key_signals = extract_key_signaling(out_packets.clone(), args.limit);
    let analysis = analyze_signaling(&out_packets);
    let mermaid_text = generate_mermaid(&key_signals, &ip_to_entity, analysis.call_side.as_deref());
    fs::write(&mermaid_output, &mermaid_text)?;

    if let Some(p) = args.analysis_json.as_deref() {
        let payload = serde_json::json!({
            "analysis": &analysis,
            "entity_debug": build_entity_debug(&out_packets, &ip_to_entity),
        });
        fs::write(p, serde_json::to_string_pretty(&payload)?)?;
    }

    let query = extract_query(&packets, &analysis);
    let kb = if args.no_kb {
        None
    } else {
        let mut warnings: Vec<String> = vec![];
        let mut sources: Vec<KbSourceInfo> = vec![];

        let builtin = kb_load_builtin_cases(args.ui_lang.as_deref())?;
        warnings.extend(builtin.warnings);
        let mut all_cases: Vec<KbCase> = vec![];
        if let Some(cases) = builtin.cases {
            all_cases = cases;
            if let Some(source) = builtin.source {
                sources.push(source);
            }
        }

        if let Some(p) = args
            .kb_user_path
            .as_deref()
            .map(|v| v.trim())
            .filter(|v| !v.is_empty())
        {
            match kb_load_cases_from_file(p, KbSourceType::User, "user_cases") {
                Ok(mut user_cases) => {
                    sources.push(KbSourceInfo {
                        source_type: KbSourceType::User,
                        name: "user_cases".to_string(),
                        path: Some(p.to_string()),
                        total: user_cases.len(),
                    });
                    all_cases.append(&mut user_cases);
                }
                Err(e) => {
                    warnings.push(format!("user kb load failed: {e}"));
                }
            }
        }

        let mut merged: Vec<KbCase> = vec![];
        let mut seen: HashSet<String> = HashSet::new();
        let mut dup = 0usize;
        for c in all_cases {
            if seen.insert(c.id.clone()) {
                merged.push(c);
            } else {
                dup += 1;
            }
        }
        if dup > 0 {
            warnings.push(format!("kb duplicate dropped: {dup}"));
        }

        let (hits, trace) = kb_search(&merged, &query, args.kb_max);

        let base_dir = args
            .report_json
            .as_deref()
            .and_then(|p| Path::new(p).parent().map(|d| d.to_path_buf()))
            .or_else(|| {
                args.analysis_json
                    .as_deref()
                    .and_then(|p| Path::new(p).parent().map(|d| d.to_path_buf()))
            })
            .unwrap_or_else(|| env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
        fs::write(
            base_dir.join("kb_trace.json"),
            serde_json::to_string_pretty(&trace)?,
        )?;

        let out_hits: Vec<KbHit> = hits
            .iter()
            .map(|c| KbHit {
                id: c.id.clone(),
                source_type: c.source_type.clone(),
                source_name: c.source_name.clone(),
                dna_id: c.dna_id.clone(),
                case_numbers: c.case_numbers.clone(),
                signal_count: kb_case_signal_count(c),
                has_180: kb_case_has_180(c),
                call_type: kb_case_call_type(c),
                issue_location: c.issue_location.clone(),
                diagnosis: c.diagnosis.clone(),
                root_cause: c.root_cause.clone(),
                call_process: c.call_process.clone(),
            })
            .collect();

        Some(KbPayload {
            notice: "kb.sources/kb.trace/kb.warnings 仅开发测试用途，不应发送给 LLM".to_string(),
            enabled: true,
            sources,
            total_merged: merged.len(),
            query: query.clone(),
            trace,
            hits: out_hits,
            warnings,
        })
    };

    let summary = if let Some(pcap) = args.pcap.as_deref() {
        if use_fshark {
            Some(build_fshark_summary(pcap, &packets, args.max_size_kb, args.fshark.as_deref()))
        } else {
            get_pcap_summary(
                pcap,
                &args.filter,
                args.max_size_kb,
                args.tshark.as_deref(),
                args.debug_tshark,
            )
            .ok()
        }
    } else {
        None
    };

    let report = Report {
        summary,
        analysis,
        kb,
        outputs: Outputs {
            decoded_text: Some(decoded_text_label),
            signaling_csv: csv_output,
            signaling_json: Some(json_output),
            mermaid: Some(mermaid_output),
        },
        mermaid_text: Some(mermaid_text),
        ip_to_entity: Some(ip_to_entity),
    };

    let out = serde_json::to_string_pretty(&report)?;
    if let Some(p) = args.report_json.as_deref() {
        fs::write(p, out)?;
    } else {
        println!("{out}");
    }
    Ok(())
}
