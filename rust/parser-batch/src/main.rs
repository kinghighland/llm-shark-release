use anyhow::{anyhow, bail, Context, Result};
use chrono::Local;
use clap::Parser;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Parser, Debug)]
#[command(name = "parser-batch", about = "Build evidence_report.json from a PCAP file")]
struct Args {
    #[arg(long)]
    pcap: String,

    #[arg(long)]
    parser: Option<String>,

    #[arg(long)]
    tshark: Option<String>,

    #[arg(
        long,
        default_value = "(sip || gtpv2 || s1ap || ngap || diameter || gtp || rtcp || bicc || isup || bssap || ranap) && !(tcp.analysis.retransmission)"
    )]
    filter: String,

    #[arg(long, default_value_t = 10240)]
    max_size_kb: u64,

    #[arg(long)]
    kb_user_path: Option<String>,

    #[arg(long, default_value_t = 5)]
    kb_max: usize,

    #[arg(long)]
    no_kb: bool,

    #[arg(long)]
    evidence_json: String,

    #[arg(long)]
    timeline_json: Option<String>,

    #[arg(long)]
    analysis_json: Option<String>,

    #[arg(long)]
    csv: Option<String>,

    #[arg(long)]
    decoded_text: Option<String>,

    #[arg(long)]
    mermaid: Option<String>,

    #[arg(long, default_value_t = 80)]
    limit: usize,

    #[arg(long, default_value_t = 3)]
    context_before: usize,

    #[arg(long, default_value_t = 3)]
    context_after: usize,

    #[arg(long)]
    pretty: bool,

    #[arg(long)]
    fshark: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Packet {
    #[serde(default)]
    frame: Option<u64>,
    #[serde(default)]
    timestamp: Option<String>,
    #[serde(default)]
    src: Option<String>,
    #[serde(default)]
    dst: Option<String>,
    #[serde(default)]
    src_entity: Option<String>,
    #[serde(default)]
    dst_entity: Option<String>,
    #[serde(default)]
    protocol: Option<String>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    cause: Option<String>,
    #[serde(default)]
    details: Details,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct SipDetails {
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    status_code: Option<i64>,
    #[serde(default)]
    reason_phrase: Option<String>,
    #[serde(default)]
    cseq_method: Option<String>,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct Details {
    #[serde(default)]
    sip: Option<SipDetails>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct FailurePoint {
    #[serde(default)]
    protocol: Option<String>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    cause: Option<String>,
    #[serde(default)]
    timestamp: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AnalysisReport {
    #[serde(default)]
    call_flow_type: String,
    #[serde(default)]
    call_status: String,
    #[serde(default)]
    call_side: Option<String>,
    #[serde(default)]
    failure_reason: Option<String>,
    #[serde(default)]
    failure_point: Option<FailurePoint>,
    #[serde(default)]
    error_frames: Vec<u64>,
}

#[derive(Debug, Deserialize)]
struct KbHit {
    #[serde(default)]
    dna_id: Option<String>,
    #[serde(default)]
    case_numbers: Option<String>,
    #[serde(default)]
    signal_count: Option<usize>,
    #[serde(default)]
    issue_location: Option<String>,
    #[serde(default)]
    diagnosis: Option<String>,
    #[serde(default)]
    root_cause: Option<String>,
}

#[derive(Debug, Deserialize)]
struct KbPayload {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    kb_total: Option<u64>,
    #[serde(default)]
    query: Value,
    #[serde(default)]
    trace: Vec<Value>,
    #[serde(default)]
    hits: Vec<KbHit>,
}

#[derive(Debug, Deserialize)]
struct BaseReport {
    #[serde(default)]
    summary: Option<Value>,
    analysis: AnalysisReport,
    #[serde(default)]
    kb: Option<KbPayload>,
    #[serde(default)]
    ip_to_entity: Option<HashMap<String, String>>,
}

#[derive(Debug, Serialize, Clone)]
struct TimelineItem {
    frame: Option<u64>,
    timestamp: Option<String>,
    protocol: Option<String>,
    interface: Option<String>,
    src: Option<String>,
    dst: Option<String>,
    network_element: Option<String>,
    message: Option<String>,
    cause: Option<String>,
    tags: Vec<String>,
}

#[derive(Debug, Serialize, Clone)]
struct AbnormalCandidate {
    candidate_id: String,
    frame: Option<u64>,
    timestamp: Option<String>,
    protocol: Option<String>,
    interface: Option<String>,
    network_element: Option<String>,
    message: Option<String>,
    cause: Option<String>,
    reason_tags: Vec<String>,
    score_hint: f64,
}

#[derive(Debug, Serialize, Clone)]
struct SlimSignal {
    frame: Option<u64>,
    timestamp: Option<String>,
    protocol: Option<String>,
    message: Option<String>,
    cause: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
struct ContextWindow {
    candidate_id: String,
    center_frame: Option<u64>,
    before: Vec<SlimSignal>,
    center: SlimSignal,
    after: Vec<SlimSignal>,
}

#[derive(Debug, Serialize, Clone)]
struct FlowCandidate {
    flow_type: String,
    evidence: Vec<String>,
    score_hint: f64,
}

#[derive(Debug, Serialize, Clone)]
struct FlowHints {
    candidates: Vec<FlowCandidate>,
    parser_note: String,
}

#[derive(Debug, Serialize)]
struct KbHitSummary {
    dna_id: Option<String>,
    case_numbers: Option<String>,
    issue_location: Option<String>,
    diagnosis: Option<String>,
    root_cause: Option<String>,
    signal_count: Option<usize>,
}

#[derive(Debug, Serialize)]
struct KbSummary {
    enabled: bool,
    kb_total_hint: Option<u64>,
    query_summary: Value,
    hits: Vec<KbHitSummary>,
    trace: Vec<Value>,
}

#[derive(Debug, Serialize)]
struct EvidenceMeta {
    parser_profile: String,
    generated_at: String,
    base_parser_mode: String,
    filter: String,
    max_size_kb: u64,
    tshark_path: Option<String>,
}

#[derive(Debug, Serialize)]
struct EvidenceReport {
    schema_version: String,
    pcap_file: String,
    summary: Value,
    timeline_compact: Vec<TimelineItem>,
    abnormal_candidates: Vec<AbnormalCandidate>,
    context_windows: Vec<ContextWindow>,
    flow_hints: FlowHints,
    kb_hits: KbSummary,
    meta: EvidenceMeta,
}

enum ParserExec {
    Direct(PathBuf),
    CargoManifest(PathBuf),
}

fn main() {
    if let Err(err) = run() {
        eprintln!("parser-batch failed: {err:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args = Args::parse();
    let pcap = PathBuf::from(&args.pcap);
    if !pcap.is_file() {
        bail!("找不到 PCAP 文件: {}", pcap.display());
    }

    let base_parser = resolve_base_parser(args.parser.as_deref())?;
    let temp_dir = build_temp_dir("parser-batch")?;
    fs::create_dir_all(&temp_dir)?;

    let decoded_text = args
        .decoded_text
        .clone()
        .map(PathBuf::from)
        .unwrap_or_else(|| temp_dir.join("decoded.txt"));
    let signaling_json = temp_dir.join("signaling.json");
    let report_json = temp_dir.join("report.json");
    let analysis_json_internal = temp_dir.join("analysis.json");
    let csv_output = args
        .csv
        .clone()
        .map(PathBuf::from)
        .unwrap_or_else(|| temp_dir.join("signaling.csv"));
    let mermaid_output = args
        .mermaid
        .clone()
        .map(PathBuf::from)
        .unwrap_or_else(|| temp_dir.join("mermaid.txt"));

    run_base_parser(
        &base_parser,
        &args,
        &pcap,
        &decoded_text,
        &signaling_json,
        &report_json,
        &analysis_json_internal,
        &csv_output,
        &mermaid_output,
    )?;

    let report: BaseReport =
        serde_json::from_str(&fs::read_to_string(&report_json).context("读取 report.json 失败")?)
            .context("解析 report.json 失败")?;
    let packets: Vec<Packet> = serde_json::from_str(
        &fs::read_to_string(&signaling_json).context("读取 signaling.json 失败")?,
    )
    .context("解析 signaling.json 失败")?;

    let timeline = build_timeline_compact(&packets, &report, args.limit);
    let abnormal = build_abnormal_candidates(&packets, &report);
    let contexts = build_context_windows(&packets, &abnormal, args.context_before, args.context_after);
    let flow_hints = build_flow_hints(&packets, &report);
    let kb_summary = build_kb_summary(report.kb.as_ref());
    let summary_value = build_summary(&report, &packets, &abnormal, &contexts, &flow_hints);
    let tshark_path = summary_value
        .get("tshark_path")
        .and_then(Value::as_str)
        .map(|s| s.to_string());

    let evidence = EvidenceReport {
        schema_version: "evidence_report_v1".to_string(),
        pcap_file: pcap.to_string_lossy().to_string(),
        summary: summary_value,
        timeline_compact: timeline.clone(),
        abnormal_candidates: abnormal.clone(),
        context_windows: contexts.clone(),
        flow_hints: flow_hints.clone(),
        kb_hits: kb_summary,
        meta: EvidenceMeta {
            parser_profile: "batch_v1".to_string(),
            generated_at: Local::now().to_rfc3339(),
            base_parser_mode: match base_parser {
                ParserExec::Direct(_) => "direct_exe".to_string(),
                ParserExec::CargoManifest(_) => "cargo_run".to_string(),
            },
            filter: args.filter.clone(),
            max_size_kb: args.max_size_kb,
            tshark_path,
        },
    };

    write_json(Path::new(&args.evidence_json), &evidence, args.pretty)?;
    if let Some(path) = args.timeline_json.as_deref() {
        write_json(Path::new(path), &timeline, args.pretty)?;
    }
    if let Some(path) = args.analysis_json.as_deref() {
        let payload = json!({
            "abnormal_candidates": abnormal,
            "context_windows": contexts,
            "flow_hints": flow_hints,
            "failure_point": report.analysis.failure_point,
            "failure_reason": report.analysis.failure_reason,
            "call_status": report.analysis.call_status,
            "call_side": report.analysis.call_side,
        });
        write_json_value(Path::new(path), &payload, args.pretty)?;
    }

    let _ = fs::remove_dir_all(&temp_dir);
    Ok(())
}

fn build_temp_dir(prefix: &str) -> Result<PathBuf> {
    let dir = std::env::temp_dir().join("llmshark").join(format!(
        "{}_{}_{}",
        prefix,
        Local::now().format("%Y%m%d_%H%M%S"),
        std::process::id()
    ));
    Ok(dir)
}

fn write_json<T: Serialize>(path: &Path, value: &T, pretty: bool) -> Result<()> {
    let txt = if pretty {
        serde_json::to_string_pretty(value)?
    } else {
        serde_json::to_string(value)?
    };
    write_text(path, &txt)
}

fn write_json_value(path: &Path, value: &Value, pretty: bool) -> Result<()> {
    let txt = if pretty {
        serde_json::to_string_pretty(value)?
    } else {
        serde_json::to_string(value)?
    };
    write_text(path, &txt)
}

fn write_text(path: &Path, text: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, text)?;
    Ok(())
}

fn resolve_base_parser(input: Option<&str>) -> Result<ParserExec> {
    if let Some(raw) = input.map(str::trim).filter(|s| !s.is_empty()) {
        let p = PathBuf::from(raw);
        if p.is_file() {
            return Ok(ParserExec::Direct(p));
        }
        if p.ends_with("Cargo.toml") {
            return Ok(ParserExec::CargoManifest(p));
        }
        bail!("指定的 parser 路径无效: {raw}");
    }

    let mut bases: Vec<PathBuf> = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            bases.push(dir.to_path_buf());
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        bases.push(cwd);
    }

    let exe_name = if cfg!(windows) { "parser.exe" } else { "parser" };
    for base in &bases {
        let direct_candidates = [
            base.join(exe_name),
            base.join("bin").join(exe_name),
        ];
        for candidate in direct_candidates {
            if candidate.is_file() {
                return Ok(ParserExec::Direct(candidate));
            }
        }
    }

    for base in bases {
        if let Some(repo_root) = find_repo_root_from(&base) {
            let direct_candidates = [
                repo_root.join("rust").join("parser").join("target").join("release").join(exe_name),
                repo_root.join("rust").join("parser").join("target").join("debug").join(exe_name),
            ];
            for candidate in direct_candidates {
                if candidate.is_file() {
                    return Ok(ParserExec::Direct(candidate));
                }
            }

            let manifest = repo_root.join("rust").join("parser").join("Cargo.toml");
            if manifest.is_file() {
                return Ok(ParserExec::CargoManifest(manifest));
            }
        }
    }

    Err(anyhow!("找不到基础 parser，可通过 --parser 显式指定"))
}

fn find_repo_root_from(start: &Path) -> Option<PathBuf> {
    let mut cur = Some(start);
    while let Some(path) = cur {
        if path.join("app").join("prompt.md").is_file() && path.join("rust").join("parser").join("Cargo.toml").is_file() {
            return Some(path.to_path_buf());
        }
        cur = path.parent();
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn run_base_parser(
    exec: &ParserExec,
    args: &Args,
    pcap: &Path,
    decoded_text: &Path,
    signaling_json: &Path,
    report_json: &Path,
    analysis_json: &Path,
    csv_output: &Path,
    mermaid_output: &Path,
) -> Result<()> {
    let mut pass_args = vec![
        "--pcap".to_string(),
        pcap.to_string_lossy().to_string(),
        "--text".to_string(),
        decoded_text.to_string_lossy().to_string(),
        "--json".to_string(),
        signaling_json.to_string_lossy().to_string(),
        "--report-json".to_string(),
        report_json.to_string_lossy().to_string(),
        "--analysis-json".to_string(),
        analysis_json.to_string_lossy().to_string(),
        "--csv".to_string(),
        csv_output.to_string_lossy().to_string(),
        "--mermaid".to_string(),
        mermaid_output.to_string_lossy().to_string(),
        "--max-size-kb".to_string(),
        args.max_size_kb.to_string(),
        "--limit".to_string(),
        args.limit.to_string(),
        "--filter".to_string(),
        args.filter.clone(),
        "--kb-max".to_string(),
        args.kb_max.to_string(),
    ];

    if let Some(tshark) = args.tshark.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        pass_args.push("--tshark".to_string());
        pass_args.push(tshark.to_string());
    }
    if let Some(kb) = args.kb_user_path.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        pass_args.push("--kb-user-path".to_string());
        pass_args.push(kb.to_string());
    }
    if args.no_kb {
        pass_args.push("--no-kb".to_string());
    }
    if let Some(fshark) = args.fshark.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        pass_args.push("--fshark".to_string());
        pass_args.push(fshark.to_string());
    }

    let mut cmd = match exec {
        ParserExec::Direct(path) => Command::new(path),
        ParserExec::CargoManifest(manifest) => {
            let mut c = Command::new("cargo");
            c.arg("run")
                .arg("--quiet")
                .arg("--manifest-path")
                .arg(manifest)
                .arg("--");
            c
        }
    };
    cmd.args(&pass_args);
    let output = cmd.output().context("执行基础 parser 失败")?;
    if !output.status.success() {
        bail!(
            "基础 parser 执行失败: code={:?}, stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

fn build_timeline_compact(packets: &[Packet], report: &BaseReport, limit: usize) -> Vec<TimelineItem> {
    if packets.is_empty() {
        return Vec::new();
    }
    let important_keywords = [
        "invite",
        "register",
        "registration",
        "paging",
        "handover",
        "pdu session",
        "service request",
        "extended service request",
        "release",
        "deactivate",
        "delete bearer",
        "create bearer",
        "initialcontext",
        "security",
        "authentication",
        "reject",
        "failure",
        "decline",
    ];
    let failure_frames: HashSet<u64> = report.analysis.error_frames.iter().copied().collect();
    let mut scored: Vec<(usize, i32)> = Vec::with_capacity(packets.len());
    for (idx, packet) in packets.iter().enumerate() {
        let mut score = 0;
        if idx < 3 || idx + 3 >= packets.len() {
            score += 3;
        }
        if packet.protocol.as_deref() == Some("SIP") {
            score += 4;
        }
        if packet_cause(packet).is_some() {
            score += 3;
        }
        if is_abnormal_packet(packet) {
            score += 8;
        }
        if packet_message(packet)
            .as_deref()
            .map(|v| contains_any(v, &important_keywords))
            .unwrap_or(false)
        {
            score += 2;
        }
        if packet
            .frame
            .map(|frame| failure_frames.contains(&frame))
            .unwrap_or(false)
        {
            score += 6;
        }
        scored.push((idx, score));
    }

    let mut selected: BTreeSet<usize> = BTreeSet::new();
    for (idx, score) in &scored {
        if *score >= 8 {
            selected.insert(*idx);
        }
    }
    let target_len = limit.min(packets.len()).min(24);
    while selected.len() < target_len {
        if let Some((idx, _)) = scored
            .iter()
            .filter(|(idx, _)| !selected.contains(idx))
            .max_by_key(|(_, score)| *score)
        {
            selected.insert(*idx);
        } else {
            break;
        }
    }

    let ip_roles = report.ip_to_entity.as_ref();
    selected
        .into_iter()
        .take(limit)
        .map(|idx| timeline_item_from_packet(&packets[idx], ip_roles))
        .collect()
}

fn build_abnormal_candidates(packets: &[Packet], report: &BaseReport) -> Vec<AbnormalCandidate> {
    let failure_frames: HashSet<u64> = report.analysis.error_frames.iter().copied().collect();
    let mut out = Vec::new();
    for packet in packets {
        let mut reason_tags = abnormal_reason_tags(packet);
        if packet
            .frame
            .map(|frame| failure_frames.contains(&frame))
            .unwrap_or(false)
        {
            reason_tags.push("analysis_error_frame".to_string());
        }
        if reason_tags.is_empty() {
            continue;
        }

        let score_hint = abnormal_score(&reason_tags);
        out.push(AbnormalCandidate {
            candidate_id: format!("abn-{:03}", out.len() + 1),
            frame: packet.frame,
            timestamp: packet.timestamp.clone(),
            protocol: packet.protocol.clone(),
            interface: derive_interface(packet),
            network_element: derive_network_element(packet, report.ip_to_entity.as_ref()),
            message: packet_message(packet),
            cause: packet_cause(packet),
            reason_tags,
            score_hint,
        });
    }
    out.sort_by(|a, b| {
        b.score_hint
            .partial_cmp(&a.score_hint)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.frame.cmp(&b.frame))
    });
    out
}

fn build_context_windows(
    packets: &[Packet],
    abnormal: &[AbnormalCandidate],
    before: usize,
    after: usize,
) -> Vec<ContextWindow> {
    let index_by_frame: HashMap<u64, usize> = packets
        .iter()
        .enumerate()
        .filter_map(|(idx, packet)| packet.frame.map(|frame| (frame, idx)))
        .collect();

    let mut out = Vec::new();
    for candidate in abnormal {
        let Some(frame) = candidate.frame else {
            continue;
        };
        let Some(center_idx) = index_by_frame.get(&frame).copied() else {
            continue;
        };
        let start = center_idx.saturating_sub(before);
        let end = (center_idx + after + 1).min(packets.len());
        let before_signals = packets[start..center_idx]
            .iter()
            .map(slim_signal_from_packet)
            .collect();
        let after_signals = packets[center_idx + 1..end]
            .iter()
            .map(slim_signal_from_packet)
            .collect();
        out.push(ContextWindow {
            candidate_id: candidate.candidate_id.clone(),
            center_frame: candidate.frame,
            before: before_signals,
            center: slim_signal_from_packet(&packets[center_idx]),
            after: after_signals,
        });
    }
    out
}

fn build_flow_hints(packets: &[Packet], report: &BaseReport) -> FlowHints {
    let mut candidates: BTreeMap<String, FlowCandidate> = BTreeMap::new();
    let protocols: HashSet<String> = packets
        .iter()
        .filter_map(|p| p.protocol.clone())
        .collect();
    let messages: Vec<String> = packets
        .iter()
        .filter_map(|p| packet_message(p).map(|m| m.to_ascii_lowercase()))
        .collect();

    let has = |needle: &str| messages.iter().any(|m| m.contains(needle));
    let push = |map: &mut BTreeMap<String, FlowCandidate>, flow_type: &str, score_hint: f64, evidence: Vec<String>| {
        match map.get(flow_type) {
            Some(existing) if existing.score_hint >= score_hint => {}
            _ => {
                map.insert(
                    flow_type.to_string(),
                    FlowCandidate {
                        flow_type: flow_type.to_string(),
                        evidence,
                        score_hint,
                    },
                );
            }
        }
    };

    if protocols.contains("SIP") && protocols.contains("NGAP") && protocols.contains("S1AP") {
        push(
            &mut candidates,
            "EPSFB",
            0.92,
            vec!["同时检测到 SIP、NGAP、S1AP".to_string()],
        );
    }
    if protocols.contains("SIP") && protocols.contains("NGAP") {
        push(
            &mut candidates,
            "VoNR业务",
            0.88,
            vec!["检测到 SIP 与 NGAP 联合出现".to_string()],
        );
    }
    if protocols.contains("SIP") && protocols.contains("S1AP") {
        push(
            &mut candidates,
            "VoLTE业务",
            0.86,
            vec!["检测到 SIP 与 S1AP 联合出现".to_string()],
        );
    }
    if has("register") || has("registration") {
        push(
            &mut candidates,
            "注册",
            0.85,
            vec!["检测到 REGISTER 或 Registration 类消息".to_string()],
        );
    }
    if has("tracking area update") || has("tau") {
        push(
            &mut candidates,
            "TA更新",
            0.85,
            vec!["检测到 TAU/Tracking Area Update 线索".to_string()],
        );
    }
    if has("paging") {
        push(
            &mut candidates,
            "寻呼",
            0.82,
            vec!["检测到 Paging 类消息".to_string()],
        );
    }
    if has("handover") {
        push(
            &mut candidates,
            "切换流程",
            0.84,
            vec!["检测到 Handover 类消息".to_string()],
        );
    }
    if has("pdu session") {
        push(
            &mut candidates,
            "PDU会话全流程",
            0.84,
            vec!["检测到 PDU Session 类消息".to_string()],
        );
    }
    if has("authentication") {
        push(
            &mut candidates,
            "鉴权",
            0.76,
            vec!["检测到 Authentication 类消息".to_string()],
        );
    }
    if has("security mode") || has("security") {
        push(
            &mut candidates,
            "NAS安全",
            0.74,
            vec!["检测到 Security Mode 类消息".to_string()],
        );
    }
    if has("service request") || has("extended service request") {
        push(
            &mut candidates,
            "服务请求",
            0.78,
            vec!["检测到 Service Request 或 Extended Service Request".to_string()],
        );
    }
    if report.analysis.call_status == "failure" {
        push(
            &mut candidates,
            "异常释放",
            0.68,
            vec!["分析结果显示当前流程失败并进入释放相关阶段".to_string()],
        );
    }

    if candidates.is_empty() {
        let mut evidence = Vec::new();
        if !report.analysis.call_flow_type.is_empty() {
            evidence.push(format!("基础 parser 输出 call_flow_type={}", report.analysis.call_flow_type));
        }
        candidates.insert(
            "其他".to_string(),
            FlowCandidate {
                flow_type: "其他".to_string(),
                evidence,
                score_hint: 0.3,
            },
        );
    }

    let mut ordered: Vec<FlowCandidate> = candidates.into_values().collect();
    ordered.sort_by(|a, b| {
        b.score_hint
            .partial_cmp(&a.score_hint)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.flow_type.cmp(&b.flow_type))
    });

    FlowHints {
        candidates: ordered,
        parser_note: "仅为候选线索，不代表最终判断".to_string(),
    }
}

fn build_kb_summary(kb: Option<&KbPayload>) -> KbSummary {
    match kb {
        Some(kb_payload) => KbSummary {
            enabled: kb_payload.enabled,
            kb_total_hint: kb_payload.kb_total,
            query_summary: summarize_kb_query(&kb_payload.query),
            hits: kb_payload
                .hits
                .iter()
                .take(5)
                .map(|hit| KbHitSummary {
                    dna_id: hit.dna_id.clone(),
                    case_numbers: hit.case_numbers.clone(),
                    issue_location: hit.issue_location.clone(),
                    diagnosis: hit.diagnosis.clone(),
                    root_cause: hit.root_cause.clone(),
                    signal_count: hit.signal_count,
                })
                .collect(),
            trace: kb_payload.trace.clone(),
        },
        None => KbSummary {
            enabled: false,
            kb_total_hint: None,
            query_summary: json!({}),
            hits: Vec::new(),
            trace: Vec::new(),
        },
    }
}

fn summarize_kb_query(query: &Value) -> Value {
    let mut obj = Map::new();
    for key in ["error_code", "call_side", "call_type", "has_cancel", "has_180"] {
        if let Some(value) = query.get(key) {
            obj.insert(key.to_string(), value.clone());
        }
    }
    Value::Object(obj)
}

fn build_summary(
    report: &BaseReport,
    packets: &[Packet],
    abnormal: &[AbnormalCandidate],
    contexts: &[ContextWindow],
    flow_hints: &FlowHints,
) -> Value {
    let mut summary = match report.summary.clone() {
        Some(Value::Object(map)) => map,
        Some(other) => {
            let mut map = Map::new();
            map.insert("base_summary".to_string(), other);
            map
        }
        None => Map::new(),
    };

    let mut protocols: Vec<String> = packets
        .iter()
        .filter_map(|p| p.protocol.as_ref().map(|s| s.trim().to_string()))
        .filter(|s| !s.is_empty())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    protocols.sort();

    summary.insert("packet_count".to_string(), json!(packets.len()));
    if !summary.contains_key("signaling_count") {
        summary.insert("signaling_count".to_string(), json!(packets.len()));
    }
    summary.insert("protocols".to_string(), json!(protocols));
    summary.insert(
        "parser_observation".to_string(),
        json!({
            "has_failure_signal": !abnormal.is_empty() || report.analysis.call_status == "failure",
            "abnormal_candidate_count": abnormal.len(),
            "context_window_count": contexts.len(),
            "flow_hint_count": flow_hints.candidates.len(),
            "call_status": report.analysis.call_status,
            "failure_reason": report.analysis.failure_reason,
        }),
    );

    Value::Object(summary)
}

fn timeline_item_from_packet(packet: &Packet, ip_roles: Option<&HashMap<String, String>>) -> TimelineItem {
    TimelineItem {
        frame: packet.frame,
        timestamp: packet.timestamp.clone(),
        protocol: packet.protocol.clone(),
        interface: derive_interface(packet),
        src: packet.src.clone(),
        dst: packet.dst.clone(),
        network_element: derive_network_element(packet, ip_roles),
        message: packet_message(packet),
        cause: packet_cause(packet),
        tags: packet_tags(packet),
    }
}

fn slim_signal_from_packet(packet: &Packet) -> SlimSignal {
    SlimSignal {
        frame: packet.frame,
        timestamp: packet.timestamp.clone(),
        protocol: packet.protocol.clone(),
        message: packet_message(packet),
        cause: packet_cause(packet),
    }
}

fn derive_interface(packet: &Packet) -> Option<String> {
    match packet.protocol.as_deref() {
        Some("NGAP") => Some("N2".to_string()),
        Some("S1AP") => Some("S1".to_string()),
        Some("SIP") => Some("SIP".to_string()),
        Some("GTPv2") => Some("GTPv2".to_string()),
        Some("Diameter") | Some("DIAMETER") => Some("Diameter".to_string()),
        other => other.map(|s| s.to_string()),
    }
}

fn derive_network_element(packet: &Packet, ip_roles: Option<&HashMap<String, String>>) -> Option<String> {
    if let (Some(src_entity), Some(dst_entity)) = (packet.src_entity.as_deref(), packet.dst_entity.as_deref()) {
        return Some(format!("{src_entity}->{dst_entity}"));
    }

    if let Some(map) = ip_roles {
        let src = packet.src.as_deref().and_then(|ip| map.get(ip)).cloned();
        let dst = packet.dst.as_deref().and_then(|ip| map.get(ip)).cloned();
        return match (src, dst) {
            (Some(a), Some(b)) => Some(format!("{a}->{b}")),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };
    }
    None
}

fn packet_tags(packet: &Packet) -> Vec<String> {
    let mut tags = Vec::new();
    let message = packet_message(packet).unwrap_or_default().to_ascii_lowercase();
    let protocol = packet.protocol.as_deref().unwrap_or("");

    if is_abnormal_packet(packet) {
        tags.push("abnormal".to_string());
    }
    if message.contains("release")
        || message.contains("deactivate")
        || message.contains("delete bearer")
        || message.contains("decline")
        || message.contains("cancel")
    {
        tags.push("release_related".to_string());
    }
    if message.contains("invite")
        || message.contains("register")
        || message.contains("create bearer")
        || message.contains("pdu session")
        || message.contains("initialcontext")
    {
        tags.push("setup_related".to_string());
    }
    if message.contains("handover") {
        tags.push("handover_related".to_string());
    }
    if message.contains("paging") {
        tags.push("paging_related".to_string());
    }
    if message.contains("authentication") || message.contains("security") {
        tags.push("security_related".to_string());
    }
    if protocol == "GTPv2" {
        tags.push("control_plane_tunnel".to_string());
    }
    tags.sort();
    tags.dedup();
    tags
}

fn abnormal_reason_tags(packet: &Packet) -> Vec<String> {
    let mut tags = Vec::new();
    let message = packet_message(packet).unwrap_or_default().to_ascii_lowercase();
    let cause = packet_cause(packet).unwrap_or_default().to_ascii_lowercase();

    if let Some(status) = packet
        .details
        .sip
        .as_ref()
        .and_then(|sip| sip.status_code)
        .or_else(|| packet_message(packet).as_deref().and_then(parse_leading_status_code))
        .filter(|status| *status >= 400)
    {
        let _ = status;
        tags.push("status_code_error".to_string());
    }
    if !cause.is_empty() && !is_success_cause(&cause) {
        tags.push("explicit_cause".to_string());
    }
    if contains_any(&message, &["reject", "failure", "error", "abort", "decline"]) {
        tags.push("failure_message".to_string());
    }
    if contains_any(&message, &["release", "deactivate", "delete bearer", "cancel"]) {
        tags.push("release_message".to_string());
    }
    if contains_any(&cause, &["timeout", "no user", "unavailable", "not-available", "forbidden"]) {
        tags.push("cause_keyword".to_string());
    }
    tags.sort();
    tags.dedup();
    tags
}

fn abnormal_score(tags: &[String]) -> f64 {
    let mut score: f64 = 0.45;
    for tag in tags {
        score += match tag.as_str() {
            "status_code_error" => 0.2,
            "explicit_cause" => 0.15,
            "failure_message" => 0.15,
            "release_message" => 0.05,
            "analysis_error_frame" => 0.1,
            _ => 0.03,
        };
    }
    score.min(0.99)
}

fn is_abnormal_packet(packet: &Packet) -> bool {
    !abnormal_reason_tags(packet).is_empty()
}

fn contains_any(text: &str, needles: &[&str]) -> bool {
    let lower = text.to_ascii_lowercase();
    needles.iter().any(|needle| lower.contains(needle))
}

fn parse_leading_status_code(message: &str) -> Option<i64> {
    let trimmed = message.trim();
    let code = trimmed.split_whitespace().next()?;
    if code.len() == 3 && code.chars().all(|c| c.is_ascii_digit()) {
        return code.parse::<i64>().ok();
    }
    None
}

fn packet_message(packet: &Packet) -> Option<String> {
    let raw_message = packet
        .message
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    if packet.protocol.as_deref() != Some("SIP") {
        return raw_message.map(|s| s.to_string());
    }

    if let Some(sip) = packet.details.sip.as_ref() {
        if let Some(status_code) = sip.status_code {
            return Some(format_sip_status(status_code, sip.reason_phrase.as_deref()));
        }
        if let Some(method) = sip
            .method
            .as_deref()
            .or(sip.cseq_method.as_deref())
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            return Some(method.to_string());
        }
    }

    raw_message
        .filter(|message| *message != "T-PDU (0xff)")
        .map(|s| s.to_string())
}

fn packet_cause(packet: &Packet) -> Option<String> {
    let raw_cause = packet
        .cause
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty() && !is_transport_placeholder(s));

    if packet.protocol.as_deref() == Some("SIP") {
        if let Some(cause) = raw_cause {
            if !is_success_cause(cause) {
                return Some(cause.to_string());
            }
        }
        if let Some(sip) = packet.details.sip.as_ref() {
            if let Some(status_code) = sip.status_code.filter(|code| *code >= 300) {
                return Some(format!("SIP {}", format_sip_status(status_code, sip.reason_phrase.as_deref())));
            }
        }
        return None;
    }

    raw_cause.map(|s| s.to_string())
}

fn format_sip_status(status_code: i64, reason_phrase: Option<&str>) -> String {
    let reason = reason_phrase.unwrap_or("").trim();
    if reason.is_empty() {
        status_code.to_string()
    } else {
        format!("{status_code} {reason}")
    }
}

fn is_transport_placeholder(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower == "transport: udp"
        || lower == "transport: tcp"
        || lower == "transport: sctp"
        || lower == "udp"
        || lower == "tcp"
        || lower == "sctp"
}

fn is_success_cause(cause: &str) -> bool {
    let lower = cause.to_ascii_lowercase();
    lower.contains("request accepted")
        || lower.contains("accepted (16)")
        || lower.contains("normal-release")
        || lower.contains("normal release")
        || lower.contains("regular deactivation")
        || lower.contains("normal call clearing")
}
