use anyhow::{anyhow, bail, Context, Result};
use chrono::Local;
use clap::Parser;
use glob::Pattern;
use reqwest::blocking::Client;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use std::time::Instant;

#[derive(Parser, Debug, Clone)]
#[command(name = "llmshark-batch", about = "Batch diagnose PCAP files and emit same-name JSON results")]
struct Args {
    #[arg(long)]
    input_dir: String,

    #[arg(long, default_value = "*.pcap")]
    glob: String,

    #[arg(long)]
    recursive: bool,

    #[arg(long)]
    skip_existing: bool,

    #[arg(long)]
    overwrite: bool,

    #[arg(long)]
    summary_json: Option<String>,

    #[arg(long)]
    keep_temp: bool,

    #[arg(long, default_value_t = 1)]
    jobs: usize,

    #[arg(long)]
    fail_fast: bool,

    #[arg(long)]
    max_files: Option<usize>,

    #[arg(long)]
    parser: Option<String>,

    #[arg(long)]
    base_parser: Option<String>,

    #[arg(long)]
    tshark: Option<String>,

    #[arg(long)]
    filter: Option<String>,

    #[arg(long)]
    kb_user_path: Option<String>,

    #[arg(long)]
    no_kb: bool,

    #[arg(long)]
    endpoint: Option<String>,

    #[arg(long)]
    api_key: Option<String>,

    #[arg(long)]
    model: Option<String>,

    #[arg(long, default_value_t = 0.2)]
    temperature: f64,

    #[arg(long)]
    prompt_path: Option<String>,

    #[arg(long)]
    llm_input_config: Option<String>,

    #[arg(long)]
    models_config: Option<String>,

    #[arg(long)]
    config_dir: Option<String>,

    #[arg(long, default_value = "zh-CN")]
    ui_lang: String,

    #[arg(long)]
    debug: bool,

    #[arg(long)]
    dump_llm_request: bool,
}

#[derive(Debug, Serialize)]
struct BatchSummaryItem {
    pcap_file: String,
    output_json: String,
    status: String,
    duration_ms: u128,
    #[serde(skip_serializing_if = "Option::is_none")]
    temp_dir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    llm_retry_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_stage: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_message: Option<String>,
}

#[derive(Debug, Serialize)]
struct BatchSummary {
    run_id: String,
    input_dir: String,
    total: usize,
    success: usize,
    failed: usize,
    skipped: usize,
    duration_ms: u128,
    items: Vec<BatchSummaryItem>,
}

#[derive(Debug, Clone)]
enum ToolExec {
    Direct(PathBuf),
    CargoManifest(PathBuf),
}

#[derive(Debug)]
struct TaskRunReport {
    llm_retry_count: u64,
}

#[derive(Debug, Clone)]
struct LlmProvider {
    name: String,
    endpoint: String,
    api_key: String,
    model: String,
}

#[derive(Debug, Deserialize)]
struct LlmProviderConfigFileItem {
    #[serde(rename = "API")]
    api: String,
    #[serde(rename = "KEY")]
    key: String,
    #[serde(rename = "Model")]
    model: String,
}

#[derive(Debug, Clone)]
struct PendingTask {
    idx: usize,
    pcap: PathBuf,
    output_json: PathBuf,
    temp_dir: PathBuf,
}

#[derive(Debug)]
struct IndexedSummaryItem {
    idx: usize,
    item: BatchSummaryItem,
}

#[derive(Debug)]
struct TaskFailure {
    stage: &'static str,
    message: String,
    llm_retry_count: u64,
}

impl TaskFailure {
    fn new(stage: &'static str, err: anyhow::Error, llm_retry_count: u64) -> Self {
        Self {
            stage,
            message: format!("{err:#}"),
            llm_retry_count,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
struct LlmInputConfig {
    #[serde(default)]
    llm: LlmRuntimeConfig,
    #[serde(default)]
    summary: SummaryCompactConfig,
    #[serde(default)]
    timeline_compact: TimelineCompactConfig,
    #[serde(default)]
    abnormal_candidates: AbnormalCandidatesConfig,
    #[serde(default)]
    context_windows: ContextWindowsConfig,
    #[serde(default)]
    flow_hints: FlowHintsCompactConfig,
    #[serde(default)]
    kb_hits: KbHitsCompactConfig,
    #[serde(default)]
    meta: MetaCompactConfig,
}

impl Default for LlmInputConfig {
    fn default() -> Self {
        Self {
            llm: LlmRuntimeConfig::default(),
            summary: SummaryCompactConfig::default(),
            timeline_compact: TimelineCompactConfig::default(),
            abnormal_candidates: AbnormalCandidatesConfig::default(),
            context_windows: ContextWindowsConfig::default(),
            flow_hints: FlowHintsCompactConfig::default(),
            kb_hits: KbHitsCompactConfig::default(),
            meta: MetaCompactConfig::default(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
struct LlmRuntimeConfig {
    #[serde(default = "default_llm_timeout_seconds")]
    timeout_seconds: u64,
}

impl Default for LlmRuntimeConfig {
    fn default() -> Self {
        Self {
            timeout_seconds: default_llm_timeout_seconds(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
struct SummaryCompactConfig {
    #[serde(default = "default_summary_include_keys")]
    include_keys: Vec<String>,
}

impl Default for SummaryCompactConfig {
    fn default() -> Self {
        Self {
            include_keys: default_summary_include_keys(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
struct TimelineCompactConfig {
    #[serde(default = "default_timeline_max_items")]
    max_items: usize,
    #[serde(default = "default_timeline_fields")]
    fields: Vec<String>,
}

impl Default for TimelineCompactConfig {
    fn default() -> Self {
        Self {
            max_items: default_timeline_max_items(),
            fields: default_timeline_fields(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
struct AbnormalCandidatesConfig {
    #[serde(default = "default_abnormal_max_items")]
    max_items: usize,
    #[serde(default = "default_abnormal_fields")]
    fields: Vec<String>,
    #[serde(default = "default_reason_tags_max_items")]
    reason_tags_max_items: usize,
}

impl Default for AbnormalCandidatesConfig {
    fn default() -> Self {
        Self {
            max_items: default_abnormal_max_items(),
            fields: default_abnormal_fields(),
            reason_tags_max_items: default_reason_tags_max_items(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
struct ContextWindowsConfig {
    #[serde(default = "default_context_max_items")]
    max_items: usize,
    #[serde(default = "default_context_before_max_items")]
    before_max_items: usize,
    #[serde(default = "default_context_after_max_items")]
    after_max_items: usize,
    #[serde(default = "default_context_signal_fields")]
    signal_fields: Vec<String>,
}

impl Default for ContextWindowsConfig {
    fn default() -> Self {
        Self {
            max_items: default_context_max_items(),
            before_max_items: default_context_before_max_items(),
            after_max_items: default_context_after_max_items(),
            signal_fields: default_context_signal_fields(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
struct FlowHintsCompactConfig {
    #[serde(default = "default_flow_hints_max_items")]
    max_items: usize,
    #[serde(default = "default_include_parser_note")]
    include_parser_note: bool,
    #[serde(default = "default_flow_candidate_fields")]
    candidate_fields: Vec<String>,
    #[serde(default = "default_flow_evidence_max_items")]
    evidence_max_items: usize,
}

impl Default for FlowHintsCompactConfig {
    fn default() -> Self {
        Self {
            max_items: default_flow_hints_max_items(),
            include_parser_note: default_include_parser_note(),
            candidate_fields: default_flow_candidate_fields(),
            evidence_max_items: default_flow_evidence_max_items(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
struct KbHitsCompactConfig {
    #[serde(default = "default_kb_enabled")]
    enabled: bool,
    #[serde(default = "default_include_trace")]
    include_trace: bool,
    #[serde(default = "default_kb_max_hits")]
    max_hits: usize,
    #[serde(default = "default_kb_query_summary_fields")]
    query_summary_fields: Vec<String>,
    #[serde(default = "default_kb_hit_fields")]
    hit_fields: Vec<String>,
}

impl Default for KbHitsCompactConfig {
    fn default() -> Self {
        Self {
            enabled: default_kb_enabled(),
            include_trace: default_include_trace(),
            max_hits: default_kb_max_hits(),
            query_summary_fields: default_kb_query_summary_fields(),
            hit_fields: default_kb_hit_fields(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
struct MetaCompactConfig {
    #[serde(default = "default_meta_include_keys")]
    include_keys: Vec<String>,
}

impl Default for MetaCompactConfig {
    fn default() -> Self {
        Self {
            include_keys: default_meta_include_keys(),
        }
    }
}

fn main() {
    if let Err(err) = run() {
        eprintln!("llmshark-batch failed: {err:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args = Args::parse();
    if !(0.0..=2.0).contains(&args.temperature) {
        bail!("temperature 必须在 [0,2] 范围内");
    }

    let input_dir = PathBuf::from(&args.input_dir);
    if !input_dir.is_dir() {
        bail!("输入目录不存在: {}", input_dir.display());
    }

    let config_dir = resolve_config_dir(args.config_dir.as_deref())?;

    let started = Instant::now();
    let run_id = Local::now().format("%Y%m%d_%H%M%S").to_string();
    let pattern = Pattern::new(&args.glob).with_context(|| format!("无效 glob: {}", args.glob))?;
    let parser_exec = resolve_parser_batch(args.parser.as_deref())?;
    let prompt_template = read_prompt_template(
        config_dir.as_deref(),
        args.prompt_path.as_deref(),
    )?;
    let llm_input_config = read_llm_input_config(
        config_dir.as_deref(),
        args.llm_input_config.as_deref(),
    )?;
    let llm_pool = load_llm_provider_pool(
        config_dir.as_deref(),
        args.models_config.as_deref(),
    )?;
    let llm_providers = if llm_pool.is_empty() {
        build_single_provider_from_args(&args)?
            .map(|p| vec![p])
            .unwrap_or_default()
    } else {
        llm_pool
    };
    if llm_providers.is_empty() {
        bail!("未配置 LLM provider，请通过 --models-config 或 --endpoint/--api-key/--model 指定");
    }

    let mut files = Vec::new();
    collect_files(&input_dir, args.recursive, &pattern, &mut files)?;
    files.sort();
    if let Some(max_files) = args.max_files {
        files.truncate(max_files);
    }

    let mut indexed_items = Vec::new();
    let mut pending_tasks = Vec::new();

    for (idx, pcap) in files.iter().enumerate() {
        let task_started = Instant::now();
        let output_json = pcap.with_extension("json");
        let output_json_str = output_json.to_string_lossy().to_string();
        let pcap_str = pcap.to_string_lossy().to_string();

        if output_json.exists() && args.skip_existing {
            indexed_items.push(IndexedSummaryItem {
                idx,
                item: BatchSummaryItem {
                    pcap_file: pcap_str,
                    output_json: output_json_str,
                    status: "skipped".to_string(),
                    duration_ms: task_started.elapsed().as_millis(),
                    temp_dir: None,
                    llm_retry_count: None,
                    error_stage: None,
                    error_message: None,
                },
            });
            continue;
        }
        if output_json.exists() && !args.overwrite && !args.skip_existing {
            indexed_items.push(IndexedSummaryItem {
                idx,
                item: BatchSummaryItem {
                    pcap_file: pcap_str.clone(),
                    output_json: output_json_str.clone(),
                    status: "failed".to_string(),
                    duration_ms: task_started.elapsed().as_millis(),
                    temp_dir: None,
                    llm_retry_count: None,
                    error_stage: Some("output_check".to_string()),
                    error_message: Some("输出 JSON 已存在，请使用 --skip-existing 或 --overwrite".to_string()),
                },
            });
            if args.fail_fast {
                break;
            }
            continue;
        }

        let temp_dir = build_task_temp_dir(&run_id, idx, pcap)?;
        pending_tasks.push(PendingTask {
            idx,
            pcap: pcap.clone(),
            output_json,
            temp_dir,
        });
    }

    if !pending_tasks.is_empty() {
        let requested_jobs = args.jobs.max(1);
        let worker_count = requested_jobs
            .min(pending_tasks.len())
            .min(llm_providers.len().max(1));
        if requested_jobs != worker_count {
            eprintln!(
                "并发度已收敛为 {}（requested_jobs={}, llm_pool_size={}）",
                worker_count,
                requested_jobs,
                llm_providers.len()
            );
        }

        let shared_tasks = Arc::new(Mutex::new(VecDeque::from(pending_tasks)));
        let shared_results: Arc<Mutex<Vec<IndexedSummaryItem>>> = Arc::new(Mutex::new(Vec::new()));
        let stop_flag = Arc::new(AtomicBool::new(false));
        let shared_args = Arc::new(args.clone());
        let shared_parser_exec = Arc::new(parser_exec);
        let shared_prompt_template = Arc::new(prompt_template);
        let shared_llm_input_config = Arc::new(llm_input_config);

        let mut handles = Vec::new();
        for worker_idx in 0..worker_count {
            let tasks = Arc::clone(&shared_tasks);
            let results = Arc::clone(&shared_results);
            let stop = Arc::clone(&stop_flag);
            let args = Arc::clone(&shared_args);
            let parser_exec = Arc::clone(&shared_parser_exec);
            let prompt_template = Arc::clone(&shared_prompt_template);
            let llm_input_config = Arc::clone(&shared_llm_input_config);
            let provider = llm_providers[worker_idx % llm_providers.len()].clone();

            handles.push(thread::spawn(move || {
                loop {
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }

                    let Some(task) = ({
                        let mut queue = tasks.lock().expect("pending task queue poisoned");
                        queue.pop_front()
                    }) else {
                        break;
                    };

                    let task_started = Instant::now();
                    let pcap_str = task.pcap.to_string_lossy().to_string();
                    let output_json_str = task.output_json.to_string_lossy().to_string();
                    let result = process_one(
                        &args,
                        &parser_exec,
                        &provider,
                        &prompt_template,
                        &llm_input_config,
                        &task.pcap,
                        &task.output_json,
                        &task.temp_dir,
                    );

                    let item = match result {
                        Ok(report) => {
                            if !args.keep_temp {
                                let _ = fs::remove_dir_all(&task.temp_dir);
                            }
                            BatchSummaryItem {
                                pcap_file: pcap_str,
                                output_json: output_json_str,
                                status: "success".to_string(),
                                duration_ms: task_started.elapsed().as_millis(),
                                temp_dir: args
                                    .keep_temp
                                    .then(|| task.temp_dir.to_string_lossy().to_string()),
                                llm_retry_count: Some(report.llm_retry_count),
                                error_stage: None,
                                error_message: None,
                            }
                        }
                        Err(err) => {
                            if args.fail_fast {
                                stop.store(true, Ordering::Relaxed);
                            }
                            BatchSummaryItem {
                                pcap_file: pcap_str,
                                output_json: output_json_str,
                                status: "failed".to_string(),
                                duration_ms: task_started.elapsed().as_millis(),
                                temp_dir: Some(task.temp_dir.to_string_lossy().to_string()),
                                llm_retry_count: Some(err.llm_retry_count),
                                error_stage: Some(err.stage.to_string()),
                                error_message: Some(err.message),
                            }
                        }
                    };

                    results
                        .lock()
                        .expect("batch summary result list poisoned")
                        .push(IndexedSummaryItem { idx: task.idx, item });
                }
            }));
        }

        for handle in handles {
            handle
                .join()
                .map_err(|_| anyhow!("并发 worker 线程异常退出"))?;
        }

        if stop_flag.load(Ordering::Relaxed) {
            let mut leftovers = shared_tasks
                .lock()
                .map_err(|_| anyhow!("读取未处理任务队列失败"))?;
            while let Some(task) = leftovers.pop_front() {
                indexed_items.push(IndexedSummaryItem {
                    idx: task.idx,
                    item: BatchSummaryItem {
                        pcap_file: task.pcap.to_string_lossy().to_string(),
                        output_json: task.output_json.to_string_lossy().to_string(),
                        status: "skipped".to_string(),
                        duration_ms: 0,
                        temp_dir: Some(task.temp_dir.to_string_lossy().to_string()),
                        llm_retry_count: None,
                        error_stage: Some("fail_fast".to_string()),
                        error_message: Some("前序任务失败，剩余任务因 --fail-fast 被跳过".to_string()),
                    },
                });
            }
        }

        let mut worker_items = shared_results
            .lock()
            .map_err(|_| anyhow!("读取并发处理结果失败"))?;
        indexed_items.extend(worker_items.drain(..));
    }

    indexed_items.sort_by_key(|item| item.idx);
    let items: Vec<BatchSummaryItem> = indexed_items.into_iter().map(|item| item.item).collect();
    let success = items.iter().filter(|item| item.status == "success").count();
    let failed = items.iter().filter(|item| item.status == "failed").count();
    let skipped = items.iter().filter(|item| item.status == "skipped").count();

    let summary = BatchSummary {
        run_id: run_id.clone(),
        input_dir: input_dir.to_string_lossy().to_string(),
        total: files.len(),
        success,
        failed,
        skipped,
        duration_ms: started.elapsed().as_millis(),
        items,
    };

    let summary_path = args
        .summary_json
        .as_deref()
        .map(PathBuf::from)
        .unwrap_or_else(|| input_dir.join("batch_summary.json"));
    write_pretty_json(&summary_path, &serde_json::to_value(summary)?)?;
    Ok(())
}

fn process_one(
    args: &Args,
    parser_exec: &ToolExec,
    llm_provider: &LlmProvider,
    prompt_template: &str,
    llm_input_config: &LlmInputConfig,
    pcap: &Path,
    output_json: &Path,
    temp_dir: &Path,
) -> std::result::Result<TaskRunReport, TaskFailure> {
    fs::create_dir_all(temp_dir).map_err(|err| TaskFailure::new("temp_dir", err.into(), 0))?;
    let evidence_path = temp_dir.join("evidence_report.json");
    let timeline_path = temp_dir.join("timeline.json");
    let analysis_path = temp_dir.join("analysis.json");
    let parser_stdout_path = temp_dir.join("parser_stdout.txt");
    let parser_stderr_path = temp_dir.join("parser_stderr.txt");
    let parser_command_path = temp_dir.join("parser_command.json");
    let raw_response_path = temp_dir.join("llm_response.txt");
    let repair_response_path = temp_dir.join("llm_repair_response.txt");
    let request_path = temp_dir.join("llm_request.json");
    let compact_evidence_path = temp_dir.join("llm_evidence_input.json");
    let validation_error_path = temp_dir.join("validation_error.txt");
    let final_debug_json = temp_dir.join("validated_output.json");

    run_parser_batch(
        parser_exec,
        args,
        pcap,
        &evidence_path,
        &timeline_path,
        &analysis_path,
        &parser_stdout_path,
        &parser_stderr_path,
        &parser_command_path,
    )
    .map_err(|err| TaskFailure::new("parser_run", err, 0))?;
    let evidence_text = fs::read_to_string(&evidence_path)
        .context("读取 evidence_report.json 失败")
        .map_err(|err| TaskFailure::new("evidence_read", err, 0))?;
    let evidence: Value = serde_json::from_str(&evidence_text)
        .context("解析 evidence_report.json 失败")
        .map_err(|err| TaskFailure::new("evidence_read", err, 0))?;
    let compact_evidence = build_llm_evidence_input(&evidence, llm_input_config);
    write_pretty_json(&compact_evidence_path, &compact_evidence)
        .map_err(|err| TaskFailure::new("compact_evidence_write", err, 0))?;

    let generated_at = Local::now().to_rfc3339();
    let prompt = build_prompt(
        prompt_template,
        pcap,
        &compact_evidence,
        &llm_provider.model,
        &args.ui_lang,
        &generated_at,
    )
    .map_err(|err| TaskFailure::new("prompt_build", err, 0))?;
    if args.dump_llm_request || args.debug {
        write_pretty_json(&request_path, &json!({ "prompt": &prompt }))
            .map_err(|err| TaskFailure::new("request_dump", err, 0))?;
    }

    let response_text = call_llm(
        &llm_provider.endpoint,
        &llm_provider.api_key,
        &llm_provider.model,
        args.temperature,
        llm_input_config.llm.timeout_seconds,
        &prompt,
    )
    .map_err(|err| TaskFailure::new("llm_call", err, 0))?;
    write_text(&raw_response_path, &response_text)
        .map_err(|err| TaskFailure::new("llm_response_write", err, 0))?;

    let started = Instant::now();
    let mut llm_retry_count = 0u64;
    let mut normalized = match validate_and_normalize(
        &response_text,
        pcap,
        &evidence,
        &llm_provider.model,
        &generated_at,
        0,
        started,
    ) {
        Ok(value) => value,
        Err(first_err) => {
            let _ = write_text(&validation_error_path, &format!("{first_err:#}"));
            let repair_prompt = build_repair_prompt(&response_text, &first_err.to_string());
            let repaired = call_llm(
                &llm_provider.endpoint,
                &llm_provider.api_key,
                &llm_provider.model,
                0.0,
                llm_input_config.llm.timeout_seconds,
                &repair_prompt,
            )
            .context("LLM 二次纠错失败")
            .map_err(|err| TaskFailure::new("llm_repair_call", err, 1))?;
            llm_retry_count = 1;
            write_text(&repair_response_path, &repaired)
                .map_err(|err| TaskFailure::new("llm_repair_write", err, llm_retry_count))?;
            validate_and_normalize(
                &repaired,
                pcap,
                &evidence,
                &llm_provider.model,
                &generated_at,
                llm_retry_count,
                started,
            )
            .context("LLM 输出在纠错后仍不符合要求")
            .map_err(|err| TaskFailure::new("llm_repair_validate", err, llm_retry_count))?
        }
    };

    inject_llm_provider_meta(&mut normalized, llm_provider);

    write_pretty_json(&final_debug_json, &normalized)
        .map_err(|err| TaskFailure::new("output_write", err, llm_retry_count))?;
    atomic_write_json(output_json, &normalized)
        .map_err(|err| TaskFailure::new("output_write", err, llm_retry_count))?;
    Ok(TaskRunReport { llm_retry_count })
}

fn build_task_temp_dir(run_id: &str, idx: usize, pcap: &Path) -> Result<PathBuf> {
    let stem = pcap
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| anyhow!("无效文件名: {}", pcap.display()))?;
    let safe_stem: String = stem
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();
    Ok(std::env::temp_dir()
        .join("llmshark")
        .join("batch")
        .join(run_id)
        .join(format!("{:04}_{}", idx + 1, safe_stem)))
}

fn default_summary_include_keys() -> Vec<String> {
    vec![
        "analyzable".to_string(),
        "call".to_string(),
        "packet_count".to_string(),
        "parser_observation".to_string(),
        "protocols".to_string(),
        "signaling_count".to_string(),
        "sip".to_string(),
        "time_range".to_string(),
        "too_large".to_string(),
    ]
}

fn default_llm_timeout_seconds() -> u64 {
    180
}

fn default_timeline_max_items() -> usize {
    10
}

fn default_timeline_fields() -> Vec<String> {
    vec![
        "frame".to_string(),
        "timestamp".to_string(),
        "protocol".to_string(),
        "interface".to_string(),
        "network_element".to_string(),
        "message".to_string(),
        "cause".to_string(),
    ]
}

fn default_abnormal_max_items() -> usize {
    3
}

fn default_abnormal_fields() -> Vec<String> {
    vec![
        "candidate_id".to_string(),
        "frame".to_string(),
        "timestamp".to_string(),
        "protocol".to_string(),
        "interface".to_string(),
        "network_element".to_string(),
        "message".to_string(),
        "cause".to_string(),
        "reason_tags".to_string(),
        "score_hint".to_string(),
    ]
}

fn default_reason_tags_max_items() -> usize {
    3
}

fn default_context_max_items() -> usize {
    2
}

fn default_context_before_max_items() -> usize {
    2
}

fn default_context_after_max_items() -> usize {
    2
}

fn default_context_signal_fields() -> Vec<String> {
    vec![
        "frame".to_string(),
        "timestamp".to_string(),
        "protocol".to_string(),
        "message".to_string(),
        "cause".to_string(),
    ]
}

fn default_flow_hints_max_items() -> usize {
    3
}

fn default_include_parser_note() -> bool {
    true
}

fn default_flow_candidate_fields() -> Vec<String> {
    vec![
        "flow_type".to_string(),
        "evidence".to_string(),
        "score_hint".to_string(),
    ]
}

fn default_flow_evidence_max_items() -> usize {
    2
}

fn default_kb_enabled() -> bool {
    true
}

fn default_include_trace() -> bool {
    false
}

fn default_kb_max_hits() -> usize {
    2
}

fn default_kb_query_summary_fields() -> Vec<String> {
    vec![
        "error_code".to_string(),
        "call_side".to_string(),
        "call_type".to_string(),
        "has_cancel".to_string(),
        "has_180".to_string(),
    ]
}

fn default_kb_hit_fields() -> Vec<String> {
    vec![
        "dna_id".to_string(),
        "case_numbers".to_string(),
        "issue_location".to_string(),
        "diagnosis".to_string(),
        "root_cause".to_string(),
        "signal_count".to_string(),
    ]
}

fn default_meta_include_keys() -> Vec<String> {
    vec![
        "parser_profile".to_string(),
        "generated_at".to_string(),
        "filter".to_string(),
        "max_size_kb".to_string(),
    ]
}

fn collect_files(dir: &Path, recursive: bool, pattern: &Pattern, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("读取目录失败: {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            if recursive {
                collect_files(&path, recursive, pattern, out)?;
            }
            continue;
        }
        let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if pattern.matches(name) {
            out.push(path);
        }
    }
    Ok(())
}

fn read_llm_input_config(config_dir: Option<&Path>, input: Option<&str>) -> Result<LlmInputConfig> {
    if let Some(path) = resolve_config_file_path(config_dir, input, "batch-llm-input-config.json") {
        let text = fs::read_to_string(&path)
            .with_context(|| format!("读取 llm input config 失败: {}", path.display()))?;
        return serde_json::from_str(&text)
            .with_context(|| format!("解析 llm input config 失败: {}", path.display()));
    }

    let mut bases = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            bases.push(dir.to_path_buf());
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        bases.push(cwd);
    }

    for base in bases {
        if let Some(repo_root) = find_repo_root_from(&base) {
            let path = repo_root
                .join("app")
                .join("config")
                .join("batch-llm-input-config.json");
            if path.is_file() {
                let text = fs::read_to_string(&path).context("读取默认 llm input config 失败")?;
                return serde_json::from_str(&text).context("解析默认 llm input config 失败");
            }
        }
    }

    Err(anyhow!(
        "找不到 batch-llm-input-config.json，请通过 --config-dir 或 --llm-input-config 指定"
    ))
}

fn resolve_parser_batch(input: Option<&str>) -> Result<ToolExec> {
    if let Some(raw) = input.map(str::trim).filter(|s| !s.is_empty()) {
        let path = PathBuf::from(raw);
        if path.is_file() {
            return Ok(ToolExec::Direct(path));
        }
        if path.ends_with("Cargo.toml") {
            return Ok(ToolExec::CargoManifest(path));
        }
        bail!("指定的 parser-batch 路径无效: {raw}");
    }

    let mut bases = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            bases.push(dir.to_path_buf());
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        bases.push(cwd);
    }

    let exe_name = if cfg!(windows) {
        "parser-batch.exe"
    } else {
        "parser-batch"
    };
    for base in &bases {
        let candidate = base.join(exe_name);
        if candidate.is_file() {
            return Ok(ToolExec::Direct(candidate));
        }
    }

    for base in bases {
        if let Some(repo_root) = find_repo_root_from(&base) {
            let exe_name = if cfg!(windows) {
                "parser-batch.exe"
            } else {
                "parser-batch"
            };
            let direct = [
                repo_root
                    .join("rust")
                    .join("parser-batch")
                    .join("target")
                    .join("release")
                    .join(exe_name),
                repo_root
                    .join("rust")
                    .join("parser-batch")
                    .join("target")
                    .join("debug")
                    .join(exe_name),
            ];
            for candidate in direct {
                if candidate.is_file() {
                    return Ok(ToolExec::Direct(candidate));
                }
            }
            let manifest = repo_root.join("rust").join("parser-batch").join("Cargo.toml");
            if manifest.is_file() {
                return Ok(ToolExec::CargoManifest(manifest));
            }
        }
    }

    Err(anyhow!("找不到 parser-batch，可通过 --parser 指定"))
}

fn load_llm_provider_pool(config_dir: Option<&Path>, input: Option<&str>) -> Result<Vec<LlmProvider>> {
    let Some(path) = resolve_models_config_path(config_dir, input)? else {
        return Ok(Vec::new());
    };
    let text = fs::read_to_string(&path)
        .with_context(|| format!("读取 models_config 失败: {}", path.display()))?;
    let raw: Map<String, Value> = serde_json::from_str(&text)
        .with_context(|| format!("解析 models_config 失败: {}", path.display()))?;

    let mut pool = Vec::new();
    for (name, value) in raw {
        let item: LlmProviderConfigFileItem = serde_json::from_value(value)
            .with_context(|| format!("解析 models_config 条目失败: {}", name))?;
        if item.api.trim().is_empty() || item.model.trim().is_empty() {
            continue;
        }
        pool.push(LlmProvider {
            name,
            endpoint: item.api.trim().to_string(),
            api_key: item.key.trim().to_string(),
            model: item.model.trim().to_string(),
        });
    }
    Ok(pool)
}

fn resolve_models_config_path(config_dir: Option<&Path>, input: Option<&str>) -> Result<Option<PathBuf>> {
    if let Some(path) = resolve_config_file_path(config_dir, input, "models_config.json") {
        if !path.is_file() {
            bail!("指定的 models_config 路径不存在: {}", path.display());
        }
        return Ok(Some(path));
    }

    let mut bases = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            bases.push(dir.to_path_buf());
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        bases.push(cwd);
    }

    for base in bases {
        if let Some(repo_root) = find_repo_root_from(&base) {
            let path = repo_root.join("app").join("config").join("models_config.json");
            if path.is_file() {
                return Ok(Some(path));
            }
        }
    }
    Ok(None)
}

fn build_single_provider_from_args(args: &Args) -> Result<Option<LlmProvider>> {
    let Some(endpoint) = args.endpoint.as_deref().map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let Some(model) = args.model.as_deref().map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let api_key = args.api_key.as_deref().unwrap_or("");

    Ok(Some(LlmProvider {
        name: "cli-default".to_string(),
        endpoint: endpoint.to_string(),
        api_key: api_key.to_string(),
        model: model.to_string(),
    }))
}

fn read_prompt_template(config_dir: Option<&Path>, input: Option<&str>) -> Result<String> {
    if let Some(path) = resolve_config_file_path(config_dir, input, "prompt-batch-json.md") {
        return fs::read_to_string(&path)
            .with_context(|| format!("读取 prompt 失败: {}", path.display()));
    }

    let mut bases = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            bases.push(dir.to_path_buf());
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        bases.push(cwd);
    }

    for base in bases {
        if let Some(repo_root) = find_repo_root_from(&base) {
            let path = repo_root.join("app").join("prompt-batch-json.md");
            if path.is_file() {
                return fs::read_to_string(path).context("读取默认 prompt 失败");
            }
        }
    }

    Err(anyhow!(
        "找不到 prompt-batch-json.md，请通过 --config-dir 或 --prompt-path 指定"
    ))
}



fn resolve_config_dir(input: Option<&str>) -> Result<Option<PathBuf>> {
    let Some(raw) = input.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let path = PathBuf::from(raw);
    if !path.is_dir() {
        bail!("指定的 config_dir 目录不存在: {}", path.display());
    }
    Ok(Some(path))
}

fn resolve_config_file_path(
    config_dir: Option<&Path>,
    input: Option<&str>,
    default_name: &str,
) -> Option<PathBuf> {
    if let Some(raw) = input.map(str::trim).filter(|s| !s.is_empty()) {
        let path = PathBuf::from(raw);
        if path.is_absolute() {
            return Some(path);
        }
        return Some(
            config_dir
                .map(|dir| dir.join(&path))
                .unwrap_or(path),
        );
    }

    config_dir.map(|dir| dir.join(default_name))
}

fn find_repo_root_from(start: &Path) -> Option<PathBuf> {
    let mut cur = Some(start);
    while let Some(path) = cur {
        if path.join("app").join("prompt-batch-json.md").is_file()
            && path.join("rust").join("parser-batch").join("Cargo.toml").is_file()
        {
            return Some(path.to_path_buf());
        }
        cur = path.parent();
    }
    None
}

fn run_parser_batch(
    exec: &ToolExec,
    args: &Args,
    pcap: &Path,
    evidence_path: &Path,
    timeline_path: &Path,
    analysis_path: &Path,
    stdout_path: &Path,
    stderr_path: &Path,
    command_path: &Path,
) -> Result<()> {
    let mut pass_args = vec![
        "--pcap".to_string(),
        pcap.to_string_lossy().to_string(),
        "--evidence-json".to_string(),
        evidence_path.to_string_lossy().to_string(),
        "--timeline-json".to_string(),
        timeline_path.to_string_lossy().to_string(),
        "--analysis-json".to_string(),
        analysis_path.to_string_lossy().to_string(),
        "--pretty".to_string(),
    ];

    if let Some(tshark) = args.tshark.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        pass_args.push("--tshark".to_string());
        pass_args.push(tshark.to_string());
    }
    if let Some(filter) = args.filter.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        pass_args.push("--filter".to_string());
        pass_args.push(filter.to_string());
    }
    if let Some(kb) = args.kb_user_path.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        pass_args.push("--kb-user-path".to_string());
        pass_args.push(kb.to_string());
    }
    if let Some(parser) = args
        .base_parser
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        pass_args.push("--parser".to_string());
        pass_args.push(parser.to_string());
    }
    if args.no_kb {
        pass_args.push("--no-kb".to_string());
    }

    let mut cmd = match exec {
        ToolExec::Direct(path) => Command::new(path),
        ToolExec::CargoManifest(manifest) => {
            let mut command = Command::new("cargo");
            command
                .arg("run")
                .arg("--quiet")
                .arg("--manifest-path")
                .arg(manifest)
                .arg("--");
            command
        }
    };
    let command_program = match exec {
        ToolExec::Direct(path) => path.to_string_lossy().to_string(),
        ToolExec::CargoManifest(_) => "cargo".to_string(),
    };
    cmd.args(&pass_args);
    let output = cmd.output().context("执行 parser-batch 失败")?;
    let _ = write_pretty_json(
        command_path,
        &json!({
            "program": command_program,
            "args": pass_args,
        }),
    );
    let _ = write_text(stdout_path, &String::from_utf8_lossy(&output.stdout));
    let _ = write_text(stderr_path, &String::from_utf8_lossy(&output.stderr));
    if !output.status.success() {
        bail!(
            "parser-batch 执行失败: code={:?}, stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

fn build_prompt(
    template: &str,
    pcap: &Path,
    evidence: &Value,
    model: &str,
    ui_lang: &str,
    generated_at: &str,
) -> Result<String> {
    let injected = json!({
        "pcap_file": pcap.to_string_lossy().to_string(),
        "current_time_iso": generated_at,
        "output_language": ui_lang,
        "model": model,
        "evidence_report": evidence,
    });
    let payload = serde_json::to_string_pretty(&injected)?;
    Ok(template.replace("{程序插入}", &payload))
}

fn build_llm_evidence_input(evidence: &Value, config: &LlmInputConfig) -> Value {
    let mut out = Map::new();
    copy_if_present(evidence, &mut out, "schema_version");
    copy_if_present(evidence, &mut out, "pcap_file");

    if let Some(summary) = evidence.get("summary").and_then(Value::as_object) {
        out.insert(
            "summary".to_string(),
            Value::Object(filter_object_fields(summary, &config.summary.include_keys)),
        );
    }

    if let Some(items) = evidence.get("timeline_compact").and_then(Value::as_array) {
        let compact = items
            .iter()
            .take(config.timeline_compact.max_items)
            .filter_map(Value::as_object)
            .map(|item| Value::Object(filter_object_fields(item, &config.timeline_compact.fields)))
            .collect();
        out.insert("timeline_compact".to_string(), Value::Array(compact));
    }

    if let Some(items) = evidence.get("abnormal_candidates").and_then(Value::as_array) {
        let compact = items
            .iter()
            .take(config.abnormal_candidates.max_items)
            .filter_map(Value::as_object)
            .map(|item| {
                let mut filtered = filter_object_fields(item, &config.abnormal_candidates.fields);
                truncate_array_field(
                    &mut filtered,
                    "reason_tags",
                    config.abnormal_candidates.reason_tags_max_items,
                );
                Value::Object(filtered)
            })
            .collect();
        out.insert("abnormal_candidates".to_string(), Value::Array(compact));
    }

    if let Some(items) = evidence.get("context_windows").and_then(Value::as_array) {
        let compact = items
            .iter()
            .take(config.context_windows.max_items)
            .filter_map(Value::as_object)
            .map(|item| {
                let mut filtered = Map::new();
                copy_if_present_from_object(item, &mut filtered, "candidate_id");
                copy_if_present_from_object(item, &mut filtered, "center_frame");
                if let Some(center) = item.get("center").and_then(Value::as_object) {
                    filtered.insert(
                        "center".to_string(),
                        Value::Object(filter_object_fields(center, &config.context_windows.signal_fields)),
                    );
                }
                if let Some(before) = item.get("before").and_then(Value::as_array) {
                    filtered.insert(
                        "before".to_string(),
                        Value::Array(
                            before
                                .iter()
                                .take(config.context_windows.before_max_items)
                                .filter_map(Value::as_object)
                                .map(|signal| {
                                    Value::Object(filter_object_fields(
                                        signal,
                                        &config.context_windows.signal_fields,
                                    ))
                                })
                                .collect(),
                        ),
                    );
                }
                if let Some(after) = item.get("after").and_then(Value::as_array) {
                    filtered.insert(
                        "after".to_string(),
                        Value::Array(
                            after
                                .iter()
                                .take(config.context_windows.after_max_items)
                                .filter_map(Value::as_object)
                                .map(|signal| {
                                    Value::Object(filter_object_fields(
                                        signal,
                                        &config.context_windows.signal_fields,
                                    ))
                                })
                                .collect(),
                        ),
                    );
                }
                Value::Object(filtered)
            })
            .collect();
        out.insert("context_windows".to_string(), Value::Array(compact));
    }

    if let Some(flow_hints) = evidence.get("flow_hints").and_then(Value::as_object) {
        let mut filtered = Map::new();
        if config.flow_hints.include_parser_note {
            copy_if_present_from_object(flow_hints, &mut filtered, "parser_note");
        }
        if let Some(candidates) = flow_hints.get("candidates").and_then(Value::as_array) {
            let compact = candidates
                .iter()
                .take(config.flow_hints.max_items)
                .filter_map(Value::as_object)
                .map(|candidate| {
                    let mut item = filter_object_fields(candidate, &config.flow_hints.candidate_fields);
                    truncate_array_field(&mut item, "evidence", config.flow_hints.evidence_max_items);
                    Value::Object(item)
                })
                .collect();
            filtered.insert("candidates".to_string(), Value::Array(compact));
        }
        out.insert("flow_hints".to_string(), Value::Object(filtered));
    }

    if config.kb_hits.enabled {
        if let Some(kb_hits) = evidence.get("kb_hits").and_then(Value::as_object) {
            let mut filtered = Map::new();
            copy_if_present_from_object(kb_hits, &mut filtered, "enabled");
            copy_if_present_from_object(kb_hits, &mut filtered, "kb_total_hint");
            if let Some(query_summary) = kb_hits.get("query_summary").and_then(Value::as_object) {
                filtered.insert(
                    "query_summary".to_string(),
                    Value::Object(filter_object_fields(
                        query_summary,
                        &config.kb_hits.query_summary_fields,
                    )),
                );
            }
            if let Some(hits) = kb_hits.get("hits").and_then(Value::as_array) {
                let compact = hits
                    .iter()
                    .take(config.kb_hits.max_hits)
                    .filter_map(Value::as_object)
                    .map(|hit| Value::Object(filter_object_fields(hit, &config.kb_hits.hit_fields)))
                    .collect();
                filtered.insert("hits".to_string(), Value::Array(compact));
            }
            if config.kb_hits.include_trace {
                copy_if_present_from_object(kb_hits, &mut filtered, "trace");
            }
            out.insert("kb_hits".to_string(), Value::Object(filtered));
        }
    } else if let Some(enabled) = evidence
        .get("kb_hits")
        .and_then(|v| v.get("enabled"))
        .cloned()
    {
        out.insert("kb_hits".to_string(), json!({ "enabled": enabled }));
    }

    if let Some(meta) = evidence.get("meta").and_then(Value::as_object) {
        out.insert(
            "meta".to_string(),
            Value::Object(filter_object_fields(meta, &config.meta.include_keys)),
        );
    }

    Value::Object(out)
}

fn filter_object_fields(source: &Map<String, Value>, fields: &[String]) -> Map<String, Value> {
    let mut out = Map::new();
    for field in fields {
        if let Some(value) = source.get(field) {
            out.insert(field.clone(), value.clone());
        }
    }
    out
}

fn truncate_array_field(target: &mut Map<String, Value>, field: &str, max_items: usize) {
    let Some(Value::Array(items)) = target.get_mut(field) else {
        return;
    };
    if items.len() > max_items {
        items.truncate(max_items);
    }
}

fn copy_if_present(source: &Value, target: &mut Map<String, Value>, field: &str) {
    if let Some(value) = source.get(field) {
        target.insert(field.to_string(), value.clone());
    }
}

fn copy_if_present_from_object(source: &Map<String, Value>, target: &mut Map<String, Value>, field: &str) {
    if let Some(value) = source.get(field) {
        target.insert(field.to_string(), value.clone());
    }
}

fn call_llm(
    endpoint: &str,
    api_key: &str,
    model: &str,
    temperature: f64,
    timeout_seconds: u64,
    prompt: &str,
) -> Result<String> {
    let url = normalize_chat_completions_url(endpoint);
    let client = Client::builder()
        .timeout(Duration::from_secs(timeout_seconds.max(1)))
        .build()?;
    let body = json!({
        "model": model,
        "temperature": temperature,
        "stream": false,
        "messages": [
            {
                "role": "user",
                "content": prompt
            }
        ]
    });
    let mut request = client.post(url).header(CONTENT_TYPE, "application/json");
    if !api_key.trim().is_empty() {
        request = request.header(AUTHORIZATION, format!("Bearer {}", api_key.trim()));
    }
    let response = request.json(&body).send().context("发送 LLM 请求失败")?;
    let status = response.status();
    let text = response.text().context("读取 LLM 响应失败")?;
    if !status.is_success() {
        bail!("LLM 请求失败: {} {}", status.as_u16(), text);
    }
    let value: Value = serde_json::from_str(&text).context("解析 LLM 响应 JSON 失败")?;
    value["choices"][0]["message"]["content"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("LLM 响应中缺少 message.content"))
}

fn normalize_chat_completions_url(endpoint: &str) -> String {
    let trimmed = endpoint.trim().trim_end_matches('/');
    if trimmed.ends_with("/chat/completions") {
        trimmed.to_string()
    } else if trimmed.ends_with("/v1") {
        format!("{trimmed}/chat/completions")
    } else {
        format!("{trimmed}/v1/chat/completions")
    }
}

fn build_repair_prompt(raw_output: &str, error_message: &str) -> String {
    format!(
        "你上一次的输出不符合要求，请在不引入新事实的前提下，将下面内容修正为一个合法 JSON 对象。\n\
要求：\n\
- 只输出 JSON\n\
- 不要输出 Markdown\n\
- 不要输出解释\n\
- 必须包含字段：时序信令摘要、流程类型、custom_flow_type、导致故障的关键信令与Cause、诊断结论、信令失败过程概要描述\n\
- 如无法完全修正，至少保证 JSON 合法且字段完整\n\n\
错误信息：{error_message}\n\n原始输出：\n{raw_output}"
    )
}

fn inject_llm_provider_meta(output: &mut Value, provider: &LlmProvider) {
    let Some(obj) = output.as_object_mut() else {
        return;
    };
    let Some(meta) = obj.get_mut("meta").and_then(Value::as_object_mut) else {
        return;
    };
    meta.insert(
        "llm_provider".to_string(),
        Value::String(provider.name.clone()),
    );
    meta.insert(
        "model".to_string(),
        Value::String(provider.model.clone()),
    );
}

fn validate_and_normalize(
    raw: &str,
    pcap: &Path,
    evidence: &Value,
    model: &str,
    generated_at: &str,
    llm_retry_count: u64,
    started: Instant,
) -> Result<Value> {
    let json_text = extract_json_object_text(raw)?;
    let mut value: Value = serde_json::from_str(&json_text).context("输出不是合法 JSON 对象")?;
    let obj = value
        .as_object_mut()
        .ok_or_else(|| anyhow!("输出必须是 JSON 对象"))?;

    if !obj.contains_key("时序信令摘要") {
        obj.insert(
            "时序信令摘要".to_string(),
            build_default_timeline_from_evidence(evidence),
        );
    }
    if !obj.contains_key("流程类型") {
        if let Some(flow_type) = evidence
            .get("flow_hints")
            .and_then(|v| v.get("candidates"))
            .and_then(Value::as_array)
            .and_then(|arr| arr.first())
            .and_then(|v| v.get("flow_type"))
            .and_then(Value::as_str)
        {
            obj.insert("流程类型".to_string(), Value::String(flow_type.to_string()));
        }
    }
    if !obj.contains_key("custom_flow_type") {
        obj.insert("custom_flow_type".to_string(), Value::Null);
    }
    if !obj.contains_key("导致故障的关键信令与Cause") {
        obj.insert(
            "导致故障的关键信令与Cause".to_string(),
            build_default_key_signal_from_evidence(evidence),
        );
    }

    ensure_non_empty_string(obj.get("流程类型"), "流程类型")?;
    ensure_array(obj.get("时序信令摘要"), "时序信令摘要")?;
    ensure_non_empty_string(obj.get("诊断结论"), "诊断结论")?;
    ensure_non_empty_string(obj.get("信令失败过程概要描述"), "信令失败过程概要描述")?;

    if obj
        .get("流程类型")
        .and_then(Value::as_str)
        .map(|v| v != "其他")
        .unwrap_or(false)
    {
        obj.insert("custom_flow_type".to_string(), Value::Null);
    }

    let key_signal = obj
        .get_mut("导致故障的关键信令与Cause")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| anyhow!("导致故障的关键信令与Cause 必须为对象"))?;
    if !key_signal.contains_key("related_signals") {
        key_signal.insert("related_signals".to_string(), Value::Array(Vec::new()));
    }
    ensure_non_empty_string(key_signal.get("message"), "导致故障的关键信令与Cause.message")?;

    obj.insert(
        "schema_version".to_string(),
        Value::String("batch_diagnosis_v1".to_string()),
    );
    obj.insert(
        "pcap_file".to_string(),
        Value::String(pcap.to_string_lossy().to_string()),
    );
    obj.insert(
        "generated_at".to_string(),
        Value::String(generated_at.to_string()),
    );

    let mut meta = match obj.remove("meta") {
        Some(Value::Object(map)) => map,
        _ => Map::new(),
    };
    meta.insert("model".to_string(), Value::String(model.to_string()));
    meta.insert(
        "kb_used".to_string(),
        Value::Bool(
            evidence
                .get("kb_hits")
                .and_then(|v| v.get("enabled"))
                .and_then(Value::as_bool)
                .unwrap_or(false),
        ),
    );
    meta.insert(
        "kb_hit_count".to_string(),
        Value::Number(
            serde_json::Number::from(
                evidence
                    .get("kb_hits")
                    .and_then(|v| v.get("hits"))
                    .and_then(Value::as_array)
                    .map(|arr| arr.len() as u64)
                    .unwrap_or(0),
            ),
        ),
    );
    meta.insert(
        "parser_profile".to_string(),
        evidence
            .get("meta")
            .and_then(|v| v.get("parser_profile"))
            .cloned()
            .unwrap_or_else(|| Value::String("batch_v1".to_string())),
    );
    meta.insert(
        "prompt_profile".to_string(),
        Value::String("batch_json_v1".to_string()),
    );
    meta.insert(
        "llm_retry_count".to_string(),
        Value::Number(serde_json::Number::from(llm_retry_count)),
    );
    meta.insert(
        "duration_ms".to_string(),
        Value::Number(serde_json::Number::from(started.elapsed().as_millis() as u64)),
    );
    obj.insert("meta".to_string(), Value::Object(meta));

    let ordered = reorder_final_output_object(std::mem::take(obj));
    Ok(Value::Object(ordered))
}

fn reorder_final_output_object(mut obj: Map<String, Value>) -> Map<String, Value> {
    let mut ordered = Map::new();
    for key in [
        "时序信令摘要",
        "流程类型",
        "custom_flow_type",
        "导致故障的关键信令与Cause",
        "诊断结论",
        "信令失败过程概要描述",
        "schema_version",
        "pcap_file",
        "generated_at",
        "meta",
    ] {
        if let Some(value) = obj.remove(key) {
            ordered.insert(key.to_string(), value);
        }
    }
    for (key, value) in obj {
        ordered.insert(key, value);
    }
    ordered
}

fn build_default_timeline_from_evidence(evidence: &Value) -> Value {
    let Some(items) = evidence
        .get("timeline_compact")
        .and_then(Value::as_array)
    else {
        return Value::Array(Vec::new());
    };

    let summarized: Vec<Value> = items
        .iter()
        .take(8)
        .enumerate()
        .map(|(idx, item)| {
            json!({
                "seq": idx + 1,
                "timestamp": item.get("timestamp").cloned().unwrap_or(Value::Null),
                "protocol": item.get("protocol").cloned().unwrap_or(Value::Null),
                "interface": item.get("interface").cloned().unwrap_or(Value::Null),
                "network_element": item.get("network_element").cloned().unwrap_or(Value::Null),
                "message": item.get("message").cloned().unwrap_or(Value::Null),
                "cause": item.get("cause").cloned().unwrap_or(Value::Null),
            })
        })
        .collect();
    Value::Array(summarized)
}

fn build_default_key_signal_from_evidence(evidence: &Value) -> Value {
    if let Some(first) = evidence
        .get("abnormal_candidates")
        .and_then(Value::as_array)
        .and_then(|arr| arr.first())
    {
        return json!({
            "timestamp": first.get("timestamp").cloned().unwrap_or(Value::Null),
            "protocol": first.get("protocol").cloned().unwrap_or(Value::Null),
            "interface": first.get("interface").cloned().unwrap_or(Value::Null),
            "network_element": first.get("network_element").cloned().unwrap_or(Value::Null),
            "message": first.get("message").cloned().unwrap_or(Value::Null),
            "cause": first.get("cause").cloned().unwrap_or(Value::Null),
            "frame": first.get("frame").cloned().unwrap_or(Value::Null),
            "related_signals": []
        });
    }
    if let Some(item) = evidence
        .get("timeline_compact")
        .and_then(Value::as_array)
        .and_then(|arr| arr.iter().rev().find(|item| {
            item.get("message")
                .and_then(Value::as_str)
                .map(|s| !s.trim().is_empty())
                .unwrap_or(false)
        }))
    {
        return json!({
            "timestamp": item.get("timestamp").cloned().unwrap_or(Value::Null),
            "protocol": item.get("protocol").cloned().unwrap_or(Value::Null),
            "interface": item.get("interface").cloned().unwrap_or(Value::Null),
            "network_element": item.get("network_element").cloned().unwrap_or(Value::Null),
            "message": item.get("message").cloned().unwrap_or(Value::Null),
            "cause": item.get("cause").cloned().unwrap_or(Value::Null),
            "frame": item.get("frame").cloned().unwrap_or(Value::Null),
            "related_signals": []
        });
    }
    json!({
        "timestamp": null,
        "protocol": null,
        "interface": null,
        "network_element": null,
        "message": null,
        "cause": null,
        "frame": null,
        "related_signals": []
    })
}

fn ensure_non_empty_string(value: Option<&Value>, field_name: &str) -> Result<()> {
    let ok = value
        .and_then(Value::as_str)
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false);
    if ok {
        Ok(())
    } else {
        Err(anyhow!("{field_name} 不能为空"))
    }
}

fn ensure_array(value: Option<&Value>, field_name: &str) -> Result<()> {
    if value.and_then(Value::as_array).is_some() {
        Ok(())
    } else {
        Err(anyhow!("{field_name} 必须为数组"))
    }
}

fn extract_json_object_text(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        bail!("LLM 返回为空");
    }

    let without_fence = if trimmed.starts_with("```") {
        let mut lines = trimmed.lines();
        let _ = lines.next();
        let rest = lines.collect::<Vec<_>>().join("\n");
        rest.trim_end_matches("```").trim().to_string()
    } else {
        trimmed.to_string()
    };

    if without_fence.starts_with('{') && without_fence.ends_with('}') {
        return Ok(without_fence);
    }

    let start = without_fence
        .find('{')
        .ok_or_else(|| anyhow!("输出中未找到 JSON 对象起始"))?;
    let end = without_fence
        .rfind('}')
        .ok_or_else(|| anyhow!("输出中未找到 JSON 对象结束"))?;
    if start >= end {
        bail!("无法提取合法 JSON 对象");
    }
    Ok(without_fence[start..=end].to_string())
}

fn atomic_write_json(path: &Path, value: &Value) -> Result<()> {
    let tmp_path = path.with_extension("json.tmp");
    write_pretty_json(&tmp_path, value)?;
    if path.exists() {
        fs::remove_file(path).with_context(|| format!("删除旧文件失败: {}", path.display()))?;
    }
    fs::rename(&tmp_path, path).with_context(|| {
        format!(
            "原子替换失败: {} -> {}",
            tmp_path.display(),
            path.display()
        )
    })?;
    Ok(())
}

fn write_pretty_json(path: &Path, value: &Value) -> Result<()> {
    let text = serde_json::to_string_pretty(value)?;
    write_text(path, &text)
}

fn write_text(path: &Path, text: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, text)?;
    Ok(())
}
