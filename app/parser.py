#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import csv
import json
import os
import re
import shutil
import subprocess
from datetime import datetime

# 预编译正则表达式
# 添加异常处理的正则表达式编译
try:
    frame_re = re.compile(r"^Frame (\d+):")
    arrival_time_re = re.compile(r"(\d{2}):(\d{2}):(\d{2})\.(\d+)")
    ip_re = re.compile(r"Src: ([\d\.]+), Dst: ([\d\.]+)")
    sip_request_re = re.compile(
        r"^(INVITE|ACK|BYE|CANCEL|REGISTER|OPTIONS|SUBSCRIBE|NOTIFY|REFER|INFO|MESSAGE|UPDATE|PRACK)\s"
    )
    # Status-Line: Status Code
    sip_status_re = re.compile(r'SIP/2\.0\s+(\d{3})\s+(.+)')
    # 扩展的cause匹配模式
    cause_patterns = [
        # ESM cause
        re.compile(r"ESM\s+cause\s*:?\s*([^,\n\r]+)", re.IGNORECASE),
        # NAS cause
        re.compile(r"nas\s*:\s*([^,\n\r\(]+(?:\([^)]+\))?)", re.IGNORECASE),
        # Radio Network cause
        re.compile(r"radioNetwork\s*:\s*([^,\n\r\(]+(?:\([^)]+\))?)", re.IGNORECASE),
        # S1AP/NGAP Cause
        re.compile(r"Cause\s*:\s*([^,\n\r]+)", re.IGNORECASE),
        # GTPv2 Cause
        re.compile(r"Cause\s+Value\s*:\s*([^,\n\r\(]+(?:\([^)]+\))?)", re.IGNORECASE),
        # Diameter Result-Code
        re.compile(r"Result-Code\s*:\s*([^,\n\r\(]+(?:\([^)]+\))?)", re.IGNORECASE),
        # Diameter Experimental-Result
        re.compile(r"Experimental-Result(?:-Code)?\s*:\s*([^,\n\r\(]+(?:\([^)]+\))?)", re.IGNORECASE),
        # 通用Reason
        re.compile(r"Reason\s*:?\s*([^,\n\r]+)", re.IGNORECASE),
        # Error-Cause
        re.compile(r"Error-Cause\s*:?\s*([^,\n\r]+)", re.IGNORECASE),
        # Protocol Error Cause
        re.compile(r"Protocol\s+Error\s+Cause\s*:\s*([^,\n\r]+)", re.IGNORECASE),
        # Transport cause
        re.compile(r"transport\s*:\s*([^,\n\r\(]+(?:\([^)]+\))?)", re.IGNORECASE),
        # Miscellaneous cause
        re.compile(r"misc\s*:\s*([^,\n\r\(]+(?:\([^)]+\))?)", re.IGNORECASE),
        # Failed-AVP (Diameter)
        re.compile(r"Failed-AVP\s*:\s*([^,\n\r]+)", re.IGNORECASE),
        # Error-Message (Diameter)
        re.compile(r"Error-Message\s*:\s*([^,\n\r]+)", re.IGNORECASE),
        # 5GC specific causes
        re.compile(r"5GMM\s+cause\s*:\s*([^,\n\r]+)", re.IGNORECASE),
        re.compile(r"5GSM\s+cause\s*:\s*([^,\n\r]+)", re.IGNORECASE),
    ]
    detailed_pattern = re.compile(
        r"(?:([\w\s-]+?):\s*)?([\w\s-]+?\s*\(\d+\))", re.IGNORECASE
    )
    indent_pattern = re.compile(r"\s+")
except re.error as e:
    print(f"正则表达式编译错误: {e}")
    raise


def detect_encoding(file_path):
    """检测文件编码，改进版本"""
    encodings = ["utf-8", "utf-8-sig", "latin-1", "utf-16", "cp1252"]
    
    for encoding in encodings:
        try:
            with open(file_path, "r", encoding=encoding) as f:
                # 读取更多内容确保准确检测
                content = f.read(1024)
                if content:  # 确保文件不为空
                    return encoding
        except UnicodeDecodeError:
            continue
        except Exception:
            continue
    
    return "latin-1"  # 默认回退编码


def resolve_tshark_path(tshark_path=None):
    env_path = os.environ.get("TSHARK_PATH")

    candidates = []
    if tshark_path:
        candidates.append(tshark_path)
    if env_path:
        candidates.append(env_path)

    for c in candidates:
        if not c:
            continue
        if os.path.isfile(c):
            return c
        found = shutil.which(c)
        if found:
            return found

    found = shutil.which("tshark")
    if found:
        return found

    common_paths = [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
    ]
    for p in common_paths:
        if os.path.isfile(p):
            return p

    raise RuntimeError("tshark.exe not found. Install Wireshark or set TSHARK_PATH/--tshark")


def run_tshark(pcap_file, output_file, filter_str=None, tshark_path=None):
    """使用tshark处理pcap文件并生成详细输出，增强错误处理"""
    if not os.path.exists(pcap_file):
        raise FileNotFoundError(f"PCAP file not found: {pcap_file}")

    tshark_bin = resolve_tshark_path(tshark_path)
    cmd = [tshark_bin, "-r", pcap_file, "-V"]

    if filter_str:
        cmd.extend(["-Y", filter_str])

    try:
        with open(output_file, "w", encoding="utf-8") as f:
            subprocess.run(
                cmd,
                stdout=f,
                stderr=subprocess.PIPE,
                check=True,
                timeout=300,
            )
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"tshark failed: {e.stderr.decode(errors='replace')}")
    except subprocess.TimeoutExpired:
        raise RuntimeError("tshark timed out")

    return output_file


def iter_tshark_fields(
    pcap_file, display_filter, fields, tshark_path=None, max_packets=None, debug=False
):
    tshark_bin = resolve_tshark_path(tshark_path)
    cmd = [tshark_bin, "-r", pcap_file]
    if display_filter:
        cmd.extend(["-Y", display_filter])
    cmd.extend(["-T", "fields"])
    for f in fields:
        cmd.extend(["-e", f])
    cmd.extend(["-E", "separator=\t", "-E", "occurrence=f", "-E", "quote=n"])

    max_lines = max_packets

    if debug:
        print(f"[tshark] {subprocess.list2cmdline(cmd)}")

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    lines_emitted = 0
    early_stop = False

    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            yield line.rstrip("\n")
            lines_emitted += 1
            if max_lines is not None and lines_emitted >= int(max_lines):
                early_stop = True
                break
    finally:
        if early_stop and proc.poll() is None:
            proc.terminate()

    stderr = ""
    if proc.stderr is not None:
        try:
            stderr = proc.stderr.read()
        except Exception:
            stderr = ""

    if early_stop:
        if debug and stderr.strip():
            print(f"[tshark-stderr] {stderr.strip()[:2000]}")
        return

    rc = proc.wait()
    if rc != 0:
        msg = stderr.strip()
        if debug and msg:
            print(f"[tshark-stderr] {msg[:2000]}")
        raise RuntimeError(f"tshark failed (exit code {rc}): {msg}")


def _parse_reason_has_error(reason_value: str):
    if not reason_value:
        return False
    v = str(reason_value).strip()

    m_sip = re.search(r"(?i)sip\s*;\s*cause\s*=\s*(\d+)", v)
    if m_sip:
        try:
            sc = int(m_sip.group(1))
            return sc >= 400
        except ValueError:
            return False

    m_q850 = re.search(r"(?i)q\.?850\s*;\s*cause\s*=\s*(\d+)", v)
    if m_q850:
        try:
            q850 = int(m_q850.group(1))
            return q850 != 16
        except ValueError:
            return False

    return False


def _epoch_to_local_iso(epoch):
    if epoch is None:
        return None
    try:
        return datetime.fromtimestamp(float(epoch)).isoformat(sep=" ", timespec="milliseconds")
    except (ValueError, OSError, TypeError):
        return None


def get_pcap_summary(
    pcap_file, filter_str, max_size_kb=500, tshark_path=None, debug_tshark=False
):
    size_bytes = os.path.getsize(pcap_file) if os.path.exists(pcap_file) else None
    max_bytes = None if max_size_kb is None else int(max_size_kb) * 1024

    summary = {
        "pcap_file": pcap_file,
        "file_size_bytes": size_bytes,
        "max_size_kb": max_size_kb,
        "too_large": False,
        "stop_reason": None,
        "tshark_path": None,
        "time_range": {
            "start_epoch": None,
            "end_epoch": None,
            "start_local": None,
            "end_local": None,
            "duration_ms": None,
        },
        "packet_count": None,
        "signaling_count": None,
        "sip": {
            "from": None,
            "to": None,
            "has_invite": False,
            "has_response": False,
            "has_180": False,
            "has_200_invite": False,
            "has_ack_200": False,
            "has_200": False,
            "has_error_response": False,
            "has_cancel": False,
            "bye_has_error_code": False,
        },
        "call": {
            "analyzable_voice_call": False,
            "analyzable_reason": None,
            "status": "unknown",
            "failure_trigger": None,
        },
    }

    if size_bytes is None:
        return summary

    if max_bytes is not None and size_bytes > max_bytes:
        summary["too_large"] = True
        summary["stop_reason"] = "too_large"
        summary["call"]["status"] = "unknown"
        return summary

    summary["tshark_path"] = resolve_tshark_path(tshark_path)

    first_epoch = None
    last_epoch = None
    packet_count = 0
    for line in iter_tshark_fields(
        pcap_file,
        None,
        ["frame.time_epoch"],
        tshark_path=summary["tshark_path"],
        debug=debug_tshark,
    ):
        v = line.strip()
        if not v:
            continue
        try:
            epoch = float(v.split("\t", 1)[0])
        except ValueError:
            continue
        if first_epoch is None:
            first_epoch = epoch
        last_epoch = epoch
        packet_count += 1

    summary["time_range"]["start_epoch"] = first_epoch
    summary["time_range"]["end_epoch"] = last_epoch
    summary["time_range"]["start_local"] = _epoch_to_local_iso(first_epoch)
    summary["time_range"]["end_local"] = _epoch_to_local_iso(last_epoch)
    if first_epoch is not None and last_epoch is not None:
        try:
            summary["time_range"]["duration_ms"] = int(round((float(last_epoch) - float(first_epoch)) * 1000))
        except (ValueError, TypeError):
            pass
    summary["packet_count"] = packet_count

    signaling_count = 0
    for _ in iter_tshark_fields(
        pcap_file,
        filter_str,
        ["frame.number"],
        tshark_path=summary["tshark_path"],
        debug=debug_tshark,
    ):
        signaling_count += 1
    summary["signaling_count"] = signaling_count

    def _exists(display_filter):
        try:
            for _ in iter_tshark_fields(
                pcap_file,
                display_filter,
                ["frame.number"],
                tshark_path=summary["tshark_path"],
                max_packets=1,
                debug=debug_tshark,
            ):
                return True
        except RuntimeError:
            return False
        return False

    summary["sip"]["has_invite"] = _exists('sip.Method == "INVITE"')
    summary["sip"]["has_response"] = _exists("sip && sip.Status-Code")
    summary["sip"]["has_180"] = _exists("sip.Status-Code == 180")

    has_200_invite = _exists('sip.Status-Code == 200 && sip.CSeq.method == "INVITE"')
    summary["sip"]["has_200_invite"] = has_200_invite

    has_ack = _exists('sip.Method == "ACK"')
    has_ack_200 = False

    if has_200_invite and has_ack:
        first_200_invite_ts = None
        try:
            for line in iter_tshark_fields(
                pcap_file,
                'sip.Status-Code == 200 && sip.CSeq.method == "INVITE"',
                ["frame.time_epoch"],
                tshark_path=summary["tshark_path"],
                max_packets=1,
                debug=debug_tshark,
            ):
                v = line.strip().split("\t", 1)[0].strip()
                if not v:
                    continue
                try:
                    first_200_invite_ts = float(v)
                except ValueError:
                    first_200_invite_ts = None
                break
        except RuntimeError:
            first_200_invite_ts = None

        if first_200_invite_ts is None:
            has_ack_200 = True
        else:
            try:
                for line in iter_tshark_fields(
                    pcap_file,
                    'sip.Method == "ACK"',
                    ["frame.time_epoch"],
                    tshark_path=summary["tshark_path"],
                    max_packets=200,
                    debug=debug_tshark,
                ):
                    v = line.strip().split("\t", 1)[0].strip()
                    if not v:
                        continue
                    try:
                        ts = float(v)
                    except ValueError:
                        continue
                    if ts >= first_200_invite_ts:
                        has_ack_200 = True
                        break
            except RuntimeError:
                pass

    summary["sip"]["has_ack_200"] = has_ack_200
    summary["sip"]["has_200"] = has_ack_200

    summary["sip"]["has_error_response"] = _exists("sip.Status-Code >= 400")
    summary["sip"]["has_cancel"] = _exists('sip.Method == "CANCEL"')

    if summary["sip"]["has_invite"]:
        invite_from = None
        invite_to = None

        invite_attempts = [
            (["sip.from.display", "sip.to.display"], "display"),
            (["sip.from.user", "sip.from.host", "sip.to.user", "sip.to.host"], "user_host"),
            (["sip.from", "sip.to"], "raw"),
        ]

        for fields, mode in invite_attempts:
            try:
                for line in iter_tshark_fields(
                    pcap_file,
                    'sip.Method == "INVITE"',
                    fields,
                    tshark_path=summary["tshark_path"],
                    max_packets=1,
                ):
                    parts = line.split("\t")
                    if mode in ("display", "raw"):
                        if len(parts) >= 1 and parts[0].strip():
                            invite_from = parts[0].strip()
                        if len(parts) >= 2 and parts[1].strip():
                            invite_to = parts[1].strip()
                    else:
                        from_user = parts[0].strip() if len(parts) >= 1 else ""
                        from_host = parts[1].strip() if len(parts) >= 2 else ""
                        to_user = parts[2].strip() if len(parts) >= 3 else ""
                        to_host = parts[3].strip() if len(parts) >= 4 else ""
                        if from_user or from_host:
                            invite_from = f"{from_user}@{from_host}".strip("@")
                        if to_user or to_host:
                            invite_to = f"{to_user}@{to_host}".strip("@")
                    break
            except RuntimeError:
                continue

            if invite_from or invite_to:
                break

        if invite_from:
            summary["sip"]["from"] = invite_from
        if invite_to:
            summary["sip"]["to"] = invite_to

    if _exists('sip.Method == "BYE" && sip.Reason'):
        try:
            for line in iter_tshark_fields(
                pcap_file,
                'sip.Method == "BYE" && sip.Reason',
                ["sip.Reason"],
                tshark_path=summary["tshark_path"],
                max_packets=50,
            ):
                if _parse_reason_has_error(line):
                    summary["sip"]["bye_has_error_code"] = True
                    break
        except RuntimeError:
            pass

    analyzable = summary["sip"]["has_invite"] and summary["sip"]["has_response"]
    summary["call"]["analyzable_voice_call"] = analyzable
    if not summary["sip"]["has_invite"]:
        summary["call"]["analyzable_reason"] = "missing_invite"
    elif not summary["sip"]["has_response"]:
        summary["call"]["analyzable_reason"] = "missing_response"

    if summary["sip"]["has_cancel"]:
        summary["call"]["status"] = "failure"
        summary["call"]["failure_trigger"] = "CANCEL"
    elif summary["sip"]["has_error_response"]:
        summary["call"]["status"] = "failure"
        summary["call"]["failure_trigger"] = "4xx/5xx/6xx"
    elif summary["sip"]["bye_has_error_code"]:
        summary["call"]["status"] = "failure"
        summary["call"]["failure_trigger"] = "BYE Reason"
    elif summary["sip"]["has_ack_200"]:
        summary["call"]["status"] = "success"

    return summary



def _read_text_file(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def load_kb_cases(kb_path):
    text = _read_text_file(kb_path)
    parts = [p.strip() for p in text.split("<!-- split -->") if p.strip()]

    cases = []
    for block in parts:
        dna_id = None
        flag = None
        call_process = []
        issue_location = None
        diagnosis = None
        root_cause = None
        case_numbers = None

        m = re.search(r"DNA ID\s*=\s*(\d+)", block)
        if m:
            dna_id = m.group(1)

        m = re.search(r"Flag(?:\s*值)?\s*=\s*(.+)", block)
        if m:
            flag = m.group(1).strip()

        def _section(*names):
            for name in names:
                mm = re.search(rf"##\s*{re.escape(name)}\s*\n([\s\S]*?)(?=\n##\s|\Z)", block, re.IGNORECASE)
                if mm:
                    body = mm.group(1).strip()
                    if body:
                        return body
            return None

        cp = _section("呼叫过程", "Call Process")
        if cp:
            call_process = [l.strip() for l in cp.splitlines() if l.strip()]

        issue_location = _section("问题定位", "Problem location")
        diagnosis = _section("诊断结论", "Diagnosis")
        root_cause = _section("根因分析", "Root cause")
        case_numbers = _section("案例编号", "Case IDs")

        cases.append(
            {
                "dna_id": dna_id,
                "flag": flag,
                "call_process": call_process,
                "issue_location": issue_location,
                "diagnosis": diagnosis,
                "root_cause": root_cause,
                "case_numbers": case_numbers,
            }
        )

    return cases


def _case_has_180(case):
    for l in case.get("call_process") or []:
        if "180" in l or "回铃" in l or "回鈴" in l or re.search(r"\b(ringback|ringing)\b", l, re.IGNORECASE):
            return True
    return False


def _case_has_200_invite(case):
    for l in case.get("call_process") or []:
        s = str(l)
        if re.search(r"(?<!\d)200(?!\d)", s) and re.search(r"\bOK\b", s, re.IGNORECASE) and re.search(
            r"Invite", s, re.IGNORECASE
        ):
            return True
    return False


def _case_has_ack_200(case):
    for l in case.get("call_process") or []:
        s = str(l)
        if re.search(r"\bACK\b", s, re.IGNORECASE) and re.search(r"(?<!\d)200(?!\d)", s):
            return True
    return False


def _case_has_cancel(case):
    for l in case.get("call_process") or []:
        s = str(l)
        if "取消" in s or re.search(r"\bCANCEL\b", s, re.IGNORECASE) or re.search(r"\bcancell?ed\b", s, re.IGNORECASE):
            return True
    return False


def _case_call_side(case):
    for l in case.get("call_process") or []:
        s = str(l)
        if "主叫" in s or re.search(r"\b(MO|caller|calling party)\b", s, re.IGNORECASE):
            return "caller"
        if "被叫" in s or re.search(r"\b(MT|callee|called party)\b", s, re.IGNORECASE):
            return "callee"
    return None


def _case_call_type(case):
    for l in case.get("call_process") or []:
        for pattern in [r"呼叫类型\s*:\s*([A-Za-z0-9_-]+)", r"\bscenario\s*:\s*([A-Za-z0-9_-]+)", r"\bcall\s*type\s*:\s*([A-Za-z0-9_-]+)"]:
            m = re.search(pattern, l, re.IGNORECASE)
            if m:
                return m.group(1)
    return None


def _case_signal_count(case):
    n = 0
    for l in case.get("call_process") or []:
        if re.match(r"^\d+\.", l):
            n += 1
    return n


def _infer_call_type(results):
    protocols = {p.get("protocol") for p in results if p.get("protocol")}
    has_sip = "SIP" in protocols
    has_s1ap = "S1AP" in protocols
    has_ngap = "NGAP" in protocols

    if has_sip and has_ngap and has_s1ap:
        return "EPSFB"

    if has_sip and has_ngap:
        return "VoNR"

    if has_sip and has_s1ap:
        for p in results:
            if p.get("protocol") != "S1AP":
                continue
            msg = str(p.get("message") or "")
            if re.search(r"CSFB|CS\s*Fallback|Circuit\s*Switched", msg, re.IGNORECASE):
                return "CSFB"
            if re.search(r"Extended\s+service\s+request", msg, re.IGNORECASE):
                return "EPSFB"
        return "VoLTE"

    if has_sip:
        return "VoLTE"

    return None


def _infer_call_side(results):
    for p in results:
        if p.get("protocol") != "SIP":
            continue
        sip = (p.get("details") or {}).get("sip") or {}
        method = sip.get("method") or p.get("message")
        if method != "INVITE":
            continue

        if sip.get("p_called_party_id"):
            return "callee"

        via_count = sip.get("via_count")
        if via_count == 1:
            underlying = p.get("underlying_protocols") or []
            src = p.get("src")
            dst = p.get("dst")
            is_ipv6 = ("IPv6" in underlying) or (":" in str(src or "")) or (":" in str(dst or ""))
            if is_ipv6:
                return "caller"
        if isinstance(via_count, int) and via_count > 1:
            return "callee"

        break

    for p in results:
        if p.get("protocol") not in ("S1AP", "NGAP"):
            continue
        msg = str(p.get("message") or "")
        if not re.search(r"Extended\s+service\s+request", msg, re.IGNORECASE):
            continue
        svc = ((p.get("details") or {}).get("s1ap") or {}).get("service_type")
        s = str(svc or "").lower()
        if "mobile originating" in s or re.search(r"\bmo\b", s):
            return "caller"
        if "mobile terminated" in s or re.search(r"\bmt\b", s):
            return "callee"

    for p in results:
        if p.get("protocol") not in ("S1AP", "NGAP"):
            continue
        msg = str(p.get("message") or "")
        if re.search(r"Service\s+notification", msg, re.IGNORECASE):
            return "callee"

    return None


def _extract_query_features(results, analysis):
    sip_packets = [p for p in results if p.get("protocol") == "SIP"]

    def _sip_info(p):
        sip = (p.get("details") or {}).get("sip") or {}
        msg = p.get("message") or ""
        method = sip.get("method")
        status_code = sip.get("status_code")
        cseq_method = sip.get("cseq_method")

        if not method and msg and not (len(str(msg)) >= 3 and str(msg)[:3].isdigit()):
            method = str(msg)

        if status_code is None and msg and len(str(msg)) >= 3 and str(msg)[:3].isdigit():
            try:
                status_code = int(str(msg)[:3])
            except ValueError:
                status_code = None

        return sip, method, status_code, cseq_method

    has_180 = False
    has_cancel = False
    has_200_invite = False
    has_ack = False

    first_200_invite_ts = None
    for p in sip_packets:
        sip, method, status_code, cseq_method = _sip_info(p)

        if method == "CANCEL":
            has_cancel = True

        if status_code == 180 or (str(p.get("message") or "").startswith("180")):
            has_180 = True

        if status_code == 200:
            cseq = str(sip.get("cseq") or "")
            if (cseq_method == "INVITE") or ("INVITE" in cseq):
                has_200_invite = True
                try:
                    ts = float(str(p.get("timestamp") or "").strip())
                except ValueError:
                    ts = None
                if ts is not None and (first_200_invite_ts is None or ts < first_200_invite_ts):
                    first_200_invite_ts = ts

        if method == "ACK":
            has_ack = True

    has_ack_200 = False
    if has_200_invite and has_ack:
        if first_200_invite_ts is None:
            has_ack_200 = True
        else:
            for p in sip_packets:
                _, method, _, _ = _sip_info(p)
                if method != "ACK":
                    continue
                try:
                    ts = float(str(p.get("timestamp") or "").strip())
                except ValueError:
                    ts = None
                if ts is None or ts >= first_200_invite_ts:
                    has_ack_200 = True
                    break

    error_code = None
    fp = (analysis or {}).get("failure_point") or {}
    msg = fp.get("message") or ""
    m = re.match(r"^(\d{3})\b", str(msg).strip())
    if m:
        error_code = m.group(1)
    else:
        cause = fp.get("cause") or ""
        m = re.search(r"\b(\d{3})\b", str(cause))
        if m:
            error_code = m.group(1)

    call_type = _infer_call_type(results)
    call_side = _infer_call_side(results)

    return {
        "error_code": error_code,
        "has_180": has_180,
        "has_200_invite": has_200_invite,
        "has_ack_200": has_ack_200,
        "has_cancel": has_cancel,
        "call_side": call_side,
        "call_type": call_type,
    }


def search_kb(cases, query, max_results=10):
    candidates = list(cases)

    error_code = query.get("error_code")
    if error_code:
        error_code = str(error_code).strip()
        pat = re.compile(rf"(?<!\d){re.escape(error_code)}(?!\d)")

        def _match_err_in_call_process(c):
            for l in c.get("call_process") or []:
                if pat.search(str(l)):
                    return True
            return False

        filtered = [c for c in candidates if _match_err_in_call_process(c)]
        if not filtered:
            return []
        candidates = filtered

    if len(candidates) > max_results and query.get("has_180") is not None:
        want_180 = bool(query.get("has_180"))
        filtered = [c for c in candidates if _case_has_180(c) == want_180]
        if filtered:
            candidates = filtered

    call_side = query.get("call_side")
    if len(candidates) >= max_results and call_side:
        filtered = [c for c in candidates if (_case_call_side(c) == call_side)]
        if filtered:
            candidates = filtered

    if len(candidates) > max_results and query.get("has_200_invite") is not None:
        want_200_invite = bool(query.get("has_200_invite"))
        filtered = [c for c in candidates if _case_has_200_invite(c) == want_200_invite]
        if filtered:
            candidates = filtered

    if len(candidates) > max_results and query.get("has_ack_200") is not None:
        want_ack_200 = bool(query.get("has_ack_200"))
        filtered = [c for c in candidates if _case_has_ack_200(c) == want_ack_200]
        if filtered:
            candidates = filtered

    if len(candidates) > max_results and query.get("has_cancel") is not None:
        want_cancel = bool(query.get("has_cancel"))
        filtered = [c for c in candidates if _case_has_cancel(c) == want_cancel]
        if filtered:
            candidates = filtered

    def _call_type_set(v):
        s = str(v or "").strip()
        if not s:
            return set()
        u = s.upper()
        if u == "VOPS":
            return {"VOLTE", "VONR", "EPSFB", "VOPS"}
        return {u}

    call_type = query.get("call_type")
    if len(candidates) > max_results and call_type:
        want = _call_type_set(call_type)

        def _match_call_type(c):
            got = _call_type_set(_case_call_type(c))
            return bool(want & got)

        filtered = [c for c in candidates if _match_call_type(c)]
        if filtered:
            candidates = filtered

    candidates.sort(key=lambda c: _case_signal_count(c), reverse=True)
    return candidates[:max_results]



def format_timestamp(ts):
    """格式化时间戳，增加异常处理"""
    try:
        # 优先匹配 HH:MM:SS.mmm...
        match = re.search(r"(\d{2}):(\d{2}):(\d{2})\.(\d+)", str(ts))
        if match:
            h, m, s, ms = match.groups()
            ms = ms[:3].ljust(3, '0')  # 确保毫秒位数为3位
            return f"{h}:{m}:{s}.{ms}"
        
        # 匹配 epoch 秒
        match_epoch = re.match(r"^(\d+)\.(\d+)$", str(ts))
        if match_epoch:
            sec, ms = match_epoch.groups()
            dt = datetime.fromtimestamp(float(sec))
            ms = ms[:3].ljust(3, '0')
            return dt.strftime(f"%H:%M:%S.{ms}")
        
        # 兜底
        return str(ts)
    except (ValueError, OSError) as e:
        return str(ts)  # 返回原始字符串作为fallback


def extract_cause(line):
    """提取原因码信息"""
    for pattern in cause_patterns:
        match = pattern.search(line)
        if match:
            # 确保返回完整匹配内容
            return match.group(0).strip()
    return None

def handle_protocol_sip(line, current_packet, lines_iter):
    """处理SIP协议：提取方法/响应码，并补充关键头字段到 details.sip"""
    current_packet["protocol"] = "SIP"
    message_found = False
    sip_buffer = []
    max_buffer = 60

    try:
        sip_buffer.append(line)
        for _ in range(max_buffer):
            next_line = next(lines_iter)
            sip_buffer.append(next_line)
            if (
                next_line.strip() == ""
                or next_line.startswith("Frame ")
                or "Internet Protocol" in next_line
            ):
                break
    except StopIteration:
        pass

    def find_header(name: str):
        prefix = name.lower() + ":"
        for l in sip_buffer:
            ls = l.strip()
            if ls.lower().startswith(prefix):
                return ls[len(prefix) :].strip()
        return None

    def find_headers(name: str):
        prefix = name.lower() + ":"
        out = []
        for l in sip_buffer:
            ls = l.strip()
            if ls.lower().startswith(prefix):
                out.append(ls[len(prefix) :].strip())
        return out

    status_code = None
    reason_phrase = None
    for buf_line in sip_buffer:
        ls = buf_line.strip()
        if "Status-Line:" in ls:
            status_line = ls.split("Status-Line:", 1)[1].strip()
            match = sip_status_re.match(status_line)
            if match:
                status_code = match.group(1)
                reason_phrase = match.group(2)
                current_packet["message"] = f"{status_code} {reason_phrase}"
                message_found = True
                break

    if not message_found:
        for buf_line in sip_buffer:
            ls = buf_line.strip()
            if ls.startswith("SIP/2.0"):
                match = sip_status_re.match(ls)
                if match:
                    status_code = match.group(1)
                    reason_phrase = match.group(2)
                    current_packet["message"] = f"{status_code} {reason_phrase}"
                    message_found = True
                    break

    method = None
    if not message_found:
        for buf_line in sip_buffer:
            ls = buf_line.strip()
            if "Request-Line:" in ls:
                try:
                    method = ls.split("Request-Line:", 1)[1].strip().split()[0]
                    current_packet["message"] = method
                    message_found = True
                    break
                except (IndexError, AttributeError):
                    pass
            elif "Method:" in ls:
                try:
                    method = ls.split("Method:", 1)[1].strip()
                    current_packet["message"] = method
                    message_found = True
                    break
                except (IndexError, AttributeError):
                    pass
            elif sip_request_re.search(ls) and "CSeq:" not in ls:
                match = sip_request_re.search(ls)
                if match:
                    method = match.group(1)
                    current_packet["message"] = method
                    message_found = True
                    break

    sip_details = {}

    from_h = find_header("From")
    to_h = find_header("To")
    call_id = find_header("Call-ID")
    cseq = find_header("CSeq")
    reason_h = find_header("Reason")
    p_called_party_id = find_header("P-Called-Party-ID")
    vias = find_headers("Via")

    if from_h:
        sip_details["from"] = from_h
    if to_h:
        sip_details["to"] = to_h
    if call_id:
        sip_details["call_id"] = call_id
    if cseq:
        sip_details["cseq"] = cseq
        cseq_parts = cseq.split()
        if len(cseq_parts) >= 2:
            sip_details["cseq_method"] = cseq_parts[1]
            try:
                sip_details["cseq_number"] = int(cseq_parts[0])
            except ValueError:
                pass

    if method:
        sip_details["method"] = method

    if status_code:
        try:
            sip_details["status_code"] = int(status_code)
        except ValueError:
            pass
        if reason_phrase:
            sip_details["reason_phrase"] = reason_phrase

    if p_called_party_id:
        sip_details["p_called_party_id"] = p_called_party_id

    if vias:
        sip_details["via_count"] = len(vias)

    if reason_h:
        sip_details["reason"] = reason_h
        if not current_packet.get("cause"):
            current_packet["cause"] = f"SIP Reason: {reason_h}"

    if (
        not current_packet.get("cause")
        and status_code
        and str(status_code).isdigit()
        and int(status_code) >= 400
    ):
        current_packet["cause"] = f"SIP {status_code} {reason_phrase or ''}".strip()

    if not current_packet.get("cause") and method == "CANCEL":
        current_packet["cause"] = "SIP CANCEL"

    if sip_details:
        current_packet.setdefault("details", {})
        current_packet["details"].setdefault("sip", {}).update(sip_details)

def handle_protocol_s1ap(line, current_packet, lines_iter):
    """处理S1AP协议，优先提取NAS Mobility Management和Session Management的信令名"""
    current_packet['protocol'] = 'S1AP'
    nas_message = None
    s1ap_message = None
    s1ap_details = {}

    try:
        lines_checked = 0
        for next_line in lines_iter:
            lines_checked += 1
            if lines_checked > 60:  # 避免过多扫描
                break

            # 优先查找内层NAS信令类型
            if 'NAS EPS Mobility Management Message Type:' in next_line:
                try:
                    mm_msg = next_line.split('NAS EPS Mobility Management Message Type:')[1].strip()
                    if '(' in mm_msg:
                        mm_msg = mm_msg.split('(')[0].strip()
                    nas_message = mm_msg
                except (IndexError, AttributeError):
                    pass

            elif nas_message and nas_message.lower() == 'extended service request' and 'Service type:' in next_line:
                try:
                    svc = next_line.split('Service type:', 1)[1].strip()
                    if '(' in svc:
                        svc = svc.split('(')[0].strip()
                    if svc:
                        s1ap_details['service_type'] = svc
                except (IndexError, AttributeError):
                    pass
            elif 'NAS EPS session management messages:' in next_line:
                try:
                    sm_msg = next_line.split('NAS EPS session management messages:')[1].strip()
                    if '(' in sm_msg:
                        sm_msg = sm_msg.split('(')[0].strip()
                    nas_message = sm_msg
                except (IndexError, AttributeError):
                    pass

            # 查找S1AP消息类型作为后备
            elif 'procedureCode:' in next_line:
                if 'id-uplinkNASTransport' in next_line or '(13)' in next_line:
                    s1ap_message = 'UplinkNASTransport'
                elif 'id-downlinkNASTransport' in next_line or '(11)' in next_line:
                    s1ap_message = 'DownlinkNASTransport'
                elif 'id-UEContextModification' in next_line or '(21)' in next_line:
                    s1ap_message = 'UEContextModificationRequest'
                elif 'id-UEContextReleaseRequest' in next_line or '(18)' in next_line:
                    s1ap_message = 'UEContextReleaseRequest'
                elif 'id-UEContextRelease' in next_line or '(23)' in next_line:
                    s1ap_message = 'UEContextReleaseCommand'
                elif 'id-E-RABSetup' in next_line or '(5)' in next_line:
                    s1ap_message = 'E-RABSetupRequest'
                elif 'id-E-RABRelease' in next_line or '(7)' in next_line:
                    s1ap_message = 'E-RABReleaseCommand'
                else:
                    try:
                        proc_part = next_line.split('procedureCode:')[1].strip()
                        if '(' in proc_part:
                            proc_name = proc_part.split('(')[0].strip()
                        else:
                            proc_name = proc_part.split()[0] if proc_part else "Unknown"
                        s1ap_message = proc_name
                    except (IndexError, AttributeError):
                        pass

            # 查找Cause信息
            elif 'Cause:' in next_line:
                cause = extract_cause(next_line)
                if cause:
                    current_packet['cause'] = cause
            elif 'radioNetwork:' in next_line:
                try:
                    cause_info = next_line.split('radioNetwork:')[1].strip()
                    if '(' in cause_info:
                        cause_info = cause_info.split('(')[0].strip()
                    current_packet['cause'] = f"radioNetwork: {cause_info}"
                except (IndexError, AttributeError):
                    pass
            elif 'nas:' in next_line:
                try:
                    cause_info = next_line.split('nas:')[1].strip()
                    if '(' in cause_info:
                        cause_info = cause_info.split('(')[0].strip()
                    current_packet['cause'] = f"nas: {cause_info}"
                except (IndexError, AttributeError):
                    pass

            if (next_line.strip() == "" or
                next_line.startswith("Frame ") or
                "Internet Protocol" in next_line):
                break
    except StopIteration:
        pass

    if nas_message:
        current_packet['message'] = nas_message
    elif s1ap_message:
        current_packet['message'] = s1ap_message

    if s1ap_details:
        current_packet.setdefault('details', {})
        current_packet['details'].setdefault('s1ap', {}).update(s1ap_details)


def handle_protocol_gtpv2(line, current_packet, lines_iter):
    """处理GTPv2协议"""
    current_packet["protocol"] = "GTPv2"
    j = 0
    while j < 15:
        try:
            next_line = next(lines_iter)
            if "Message Type:" in next_line:
                msg = next_line.split("Message Type:")[1].strip()
                current_packet["message"] = msg
                break
        except StopIteration:
            break
        j += 1
    # 处理后续行找原因码
    for next_line in lines_iter:
        cause = extract_cause(next_line)
        if cause:
            current_packet["cause"] = cause
            break
        if next_line.strip() == "":
            break


def handle_protocol_ngap(line, current_packet, lines_iter=None):
    """处理NGAP协议 - 修正版"""
    current_packet["protocol"] = "NGAP"
    
    # 提取NGAP消息类型
    if "procedureCode:" in line.lower():
        proc_match = re.search(r"procedureCode:\s*(\w+)\s*\((\d+)\)", line, re.IGNORECASE)
        if proc_match:
            proc_name = proc_match.group(1)
            current_packet["message"] = proc_name
    
    # 提取NGAP消息名称
    elif any(msg_type in line for msg_type in [
        "NGSetupRequest", "NGSetupResponse", "NGSetupFailure",
        "InitialUEMessage", "DownlinkNASTransport", "UplinkNASTransport",
        "InitialContextSetupRequest", "InitialContextSetupResponse", "InitialContextSetupFailure",
        "UEContextReleaseRequest", "UEContextReleaseCommand", "UEContextReleaseComplete",
        "PDUSessionResourceSetupRequest", "PDUSessionResourceSetupResponse",
        "HandoverRequired", "HandoverCommand", "HandoverPreparationFailure"
    ]):
        for msg_type in ["NGSetupRequest", "NGSetupResponse", "NGSetupFailure",
                        "InitialUEMessage", "DownlinkNASTransport", "UplinkNASTransport",
                        "InitialContextSetupRequest", "InitialContextSetupResponse", "InitialContextSetupFailure",
                        "UEContextReleaseRequest", "UEContextReleaseCommand", "UEContextReleaseComplete",
                        "PDUSessionResourceSetupRequest", "PDUSessionResourceSetupResponse",
                        "HandoverRequired", "HandoverCommand", "HandoverPreparationFailure"]:
            if msg_type in line:
                current_packet["message"] = msg_type
                break
    
    # 直接从当前行提取cause
    cause = extract_cause(line)
    if cause:
        current_packet["cause"] = f"NGAP: {cause}"
    
    # 检查后续行
    if lines_iter:
        try:
            lines_checked = 0
            for next_line in lines_iter:
                lines_checked += 1
                if lines_checked > 35:  # NGAP消息通常比较长
                    break
                
                # NGAP特定的cause字段
                if "Cause:" in next_line and "Value" in next_line:
                    cause_match = re.search(r"Cause.*?Value:\s*([^,\n\r\(]+)(?:\((\d+)\))?", next_line)
                    if cause_match:
                        cause_value = cause_match.group(1).strip()
                        if cause_match.group(2):
                            cause_value += f" ({cause_match.group(2)})"
                        current_packet["cause"] = f"NGAP Cause: {cause_value}"
                        break
                
                # 5G相关的cause类型
                elif any(cause_type in next_line.lower() for cause_type in [
                    "radionetwork", "transport", "nas", "protocol", "misc"
                ]):
                    # radioNetwork, transport, nas, protocol, misc cause
                    ng_cause_match = re.search(
                        r"(radioNetwork|transport|nas|protocol|misc)\s*:\s*([^,\n\r\(]+(?:\([^)]+\))?)", 
                        next_line, re.IGNORECASE
                    )
                    if ng_cause_match:
                        cause_type = ng_cause_match.group(1)
                        cause_value = ng_cause_match.group(2).strip()
                        current_packet["cause"] = f"NGAP {cause_type}: {cause_value}"
                        break
                
                # PDU Session相关错误
                elif "PDU Session" in next_line and any(keyword in next_line.lower() for keyword in ["cause", "error", "failure"]):
                    pdu_match = re.search(r"PDU Session.*?(?:Cause|Error|Failure):\s*([^,\n\r]+)", next_line, re.IGNORECASE)
                    if pdu_match:
                        current_packet["cause"] = f"NGAP PDU Session: {pdu_match.group(1).strip()}"
                        break
                
                # AMF相关错误
                elif "AMF" in next_line and any(keyword in next_line.lower() for keyword in ["cause", "error", "overload"]):
                    amf_match = re.search(r"AMF.*?(?:Cause|Error|Overload):\s*([^,\n\r]+)", next_line, re.IGNORECASE)
                    if amf_match:
                        current_packet["cause"] = f"NGAP AMF: {amf_match.group(1).strip()}"
                        break
                
                # 通用cause提取
                cause = extract_cause(next_line)
                if cause:
                    current_packet["cause"] = f"NGAP: {cause}"
                    break
                
                # 停止条件
                if (next_line.strip() == "" or 
                    next_line.startswith("Frame ") or
                    "Internet Protocol" in next_line or
                    next_line.startswith("Ethernet")):
                    break
        except StopIteration:
            pass

def handle_protocol_diameter(line, current_packet, lines_iter=None):
    """处理Diameter协议 - 修正版"""
    current_packet["protocol"] = "Diameter"
    
    # 提取Diameter命令代码和应用ID
    if "Command Code:" in line:
        cmd_match = re.search(r"Command Code:\s*([^,\n\r\(]+)(?:\((\d+)\))?", line)
        if cmd_match:
            cmd_name = cmd_match.group(1).strip()
            current_packet["message"] = cmd_name
    
    # 提取Application ID
    elif "Application-Id:" in line or "Application ID:" in line:
        app_match = re.search(r"Application[-\s]Id:\s*([^,\n\r\(]+)(?:\((\d+)\))?", line, re.IGNORECASE)
        if app_match:
            app_name = app_match.group(1).strip()
            if "message" not in current_packet:
                current_packet["message"] = f"App: {app_name}"
            else:
                current_packet["message"] += f" ({app_name})"
    
    # 直接从当前行提取cause
    cause = extract_cause(line)
    if cause:
        current_packet["cause"] = f"Diameter: {cause}"
    
    # 检查Diameter特定的Result-Code
    if "Result-Code:" in line:
        result_match = re.search(r"Result-Code:\s*([^,\n\r\(]+)(?:\((\d+)\))?", line)
        if result_match:
            result_code = result_match.group(1).strip()
            if result_match.group(2):
                result_code += f" ({result_match.group(2)})"
            current_packet["cause"] = f"Diameter Result-Code: {result_code}"
    
    # 检查后续行
    if lines_iter:
        try:
            lines_checked = 0
            for next_line in lines_iter:
                lines_checked += 1
                if lines_checked > 40:  # Diameter消息可能很长
                    break
                
                # Diameter特定的cause字段
                if "Result-Code:" in next_line:
                    result_match = re.search(r"Result-Code:\s*([^,\n\r\(]+)(?:\((\d+)\))?", next_line)
                    if result_match:
                        result_code = result_match.group(1).strip()
                        if result_match.group(2):
                            result_code += f" ({result_match.group(2)})"
                        current_packet["cause"] = f"Diameter Result-Code: {result_code}"
                        break
                
                # Experimental-Result
                elif "Experimental-Result:" in next_line or "Experimental-Result-Code:" in next_line:
                    exp_match = re.search(r"Experimental-Result(?:-Code)?:\s*([^,\n\r\(]+)(?:\((\d+)\))?", next_line)
                    if exp_match:
                        exp_code = exp_match.group(1).strip()
                        if exp_match.group(2):
                            exp_code += f" ({exp_match.group(2)})"
                        current_packet["cause"] = f"Diameter Experimental: {exp_code}"
                        break
                
                # Failed-AVP或Error相关
                elif any(keyword in next_line.lower() for keyword in ["failed-avp", "error-message", "error-reporting"]):
                    error_match = re.search(r"(?:Failed-AVP|Error-Message|Error-Reporting):\s*([^,\n\r]+)", next_line, re.IGNORECASE)
                    if error_match:
                        current_packet["cause"] = f"Diameter Error: {error_match.group(1).strip()}"
                        break
                
                # 通用cause提取
                cause = extract_cause(next_line)
                if cause:
                    current_packet["cause"] = f"Diameter: {cause}"
                    break
                
                # 停止条件
                if (next_line.strip() == "" or 
                    next_line.startswith("Frame ") or
                    "Internet Protocol" in next_line or
                    next_line.startswith("Ethernet")):
                    break
        except StopIteration:
            pass

def parse_wireshark_output(input_file, output_csv=None, output_json=None):
    """解析Wireshark详细输出文件，提取关键信令信息，并标注SIP是否封装在GTP协议内"""
    encoding = detect_encoding(input_file)
    print(f"使用编码 {encoding} 读取文件")

    results = []
    current_packet = None
    protocols_stack = []  # 当前解析时协议层堆栈，按出现顺序记录用于封装判定

    with open(input_file, "r", encoding=encoding, errors="replace") as f:
        lines_iter = iter(f)
        for line in lines_iter:
            line = line.strip()
            if frame_re.match(line):
                # 遇到新包，保存上一个包
                if current_packet and current_packet.get("protocol"):
                    results.append(current_packet)
                frame_match = frame_re.match(line)
                frame_number = int(frame_match.group(1)) if frame_match else None
                current_packet = {
                    "frame": frame_number,
                    "timestamp": None,
                    "src": None,
                    "dst": None,
                    "protocol": None,
                    "message": None,
                    "cause": None,
                    "details": {},
                    "underlying_protocols": [],  # 记录该包协议层级
                }
                protocols_stack = []  # 新包协议栈清空

            elif "Arrival Time:" in line:
                timestamp = line.split("Arrival Time:")[-1].strip()
                match = arrival_time_re.search(timestamp)
                if match:
                    h, m, s, ms = match.groups()
                    ms = ms[:3]
                    formatted = f"{h}:{m}:{s}.{ms}"
                    current_packet["timestamp"] = formatted
                else:
                    current_packet["timestamp"] = timestamp
            #elif line.startswith("Ethernet"):
            #    protocols_stack = ["Ethernet"]
            elif "Internet Protocol Version" in line:
                if line.startswith("Internet Protocol Version 4"):
                    protocols_stack.append("IPv4")
                elif line.startswith("Internet Protocol Version 6"):
                    protocols_stack.append("IPv6")
                ip_match = ip_re.search(line)
                if ip_match and current_packet is not None:
                    current_packet["src"] = ip_match.group(1)
                    current_packet["dst"] = ip_match.group(2)
            elif line.startswith("User Datagram Protocol"):
                protocols_stack.append("UDP")
            elif line.startswith("Transmission Control Protocol"):
                protocols_stack.append("TCP")
            elif "GPRS Tunneling Protocol V2" in line or "GTPv2" in line :
                protocols_stack.append("GTPv2")
            elif "GPRS Tunneling Protocol V1" in line or "GTPv1" in line or "GTP-C" in line :
                protocols_stack.append("GTPv1")
            elif "GPRS Tunneling Protocol" in line or "GTP-U" in line:
                protocols_stack.append("GTP-U")
            elif "Session Initiation Protocol" in line:
                protocols_stack.append("SIP")
            elif "Session Description Protocol" in line:
                protocols_stack.append("SIP")
            elif "S1 Application Protocol" in line or "S1AP" in line:
                protocols_stack.append("S1AP")
            elif "NG Application Protocol" in line or "NGAP" in line:
                protocols_stack.append("NGAP")
            elif "Diameter Protocol" in line or "Diameter" in line:
                protocols_stack.append("DIAMETER")

            # 特殊处理协议，调用相应函数，传入当前协议栈，设置协议字段
            if current_packet is not None:
                if "Session Initiation Protocol" in line or "SIP" in line:                
                    handle_protocol_sip(line, current_packet, lines_iter)
                    current_packet["underlying_protocols"] = protocols_stack.copy()

                elif "GPRS Tunneling Protocol V2" in line or "GTPv2" in line:
                    handle_protocol_gtpv2(line, current_packet, lines_iter)
                    current_packet["underlying_protocols"] = protocols_stack.copy()

                elif "S1 Application Protocol" in line or "S1AP" in line:
                    handle_protocol_s1ap(line, current_packet, lines_iter)
                    current_packet["underlying_protocols"] = protocols_stack.copy()

                elif "NG Application Protocol" in line or "NGAP" in line:
                    handle_protocol_ngap(line, current_packet, lines_iter)
                    current_packet["underlying_protocols"] = protocols_stack.copy()

                elif "Diameter Protocol" in line or "Diameter" in line:
                    handle_protocol_diameter(line, current_packet, lines_iter)
                    current_packet["underlying_protocols"] = protocols_stack.copy()

    if current_packet and current_packet.get("protocol"):
        results.append(current_packet)

    # 按时间戳排序结果
    results.sort(key=lambda x: x["timestamp"] if x["timestamp"] else "")

    # 输出到CSV
    if output_csv:
        with open(output_csv, "w", encoding="utf-8", newline="") as csvfile:
            fieldnames = [
                "frame",
                "timestamp",
                "protocol",
                "message",
                "cause",
                "src",
                "dst",
                "details",
                "underlying_protocols",
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for packet in results:
                writer.writerow(
                    {
                        "frame": packet["frame"],
                        "timestamp": format_timestamp(packet["timestamp"]),
                        "protocol": packet["protocol"],
                        "message": packet["message"],
                        "cause": packet["cause"],
                        "src": packet["src"],
                        "dst": packet["dst"],
                        "details": packet["details"],
                        "underlying_protocols": packet["underlying_protocols"],                    }
                )

    # 输出到JSON
    if output_json:
        with open(output_json, "w", encoding="utf-8") as jsonfile:
            json.dump(
                [
                    {**packet, "timestamp": format_timestamp(packet["timestamp"])}
                    for packet in results
                ],
                jsonfile,
                ensure_ascii=False,
                indent=2,
            )

    return results


def extract_key_signaling(results, max_signals=60):
    """从结果中提取关键信令 - 增强版"""
    
    # 如果总信令数小于等于门限，直接返回（保持原逻辑）
    if len(results) <= max_signals:
        return results, 0  # 返回 0 表示无过滤

    # === 第一阶段：分类 ===
    # 分类 1：所有 SIP 信令（最高优先级）
    sip_packets = [p for p in results if p.get("protocol") == "SIP"]

    # 分类 2：所有携带 cause 的信令（不自动判断，全部保留）
    cause_packets = [p for p in results
                     if p.get("cause") and p.get("protocol") != "SIP"]

    # 分类 3：特定重要消息类型（不带 cause 但消息名重要）
    important_keywords = [
        "error", "reject", "failure", "fail", "denied",
        "release", "detach", "delete", "abort", "cancel", "auth",
        "handover", "redirect", "notify", "service request",
        "tau", "attach", "paging", "service notification"
    ]
    important_packets = [p for p in results
                        if p.get("message")
                        and p.get("protocol") not in ("SIP",)
                        and p not in cause_packets
                        and any(kw in str(p.get("message", "")).lower() for kw in important_keywords)]

    # 分类 4：其他信令（最低优先级，用于填充剩余槽位）
    other_packets = [p for p in results
                     if p not in sip_packets
                     and p not in cause_packets
                     and p not in important_packets]

    # === 第二阶段：强制保留首尾 + 按优先级选择 ===
    MIN_SIGNALS_RESERVED = 8  # 首尾各保留 4 条
    n = len(results)
    head_count = min(MIN_SIGNALS_RESERVED // 2, n // 4)  # 头部保留 4 条
    tail_count = min(MIN_SIGNALS_RESERVED // 2, n // 4)  # 尾部保留 4 条

    # 获取首尾消息（从原始结果中按时间顺序取）
    head_packets = results[:head_count]
    tail_packets = results[-tail_count:] if tail_count > 0 else []

    # 计算剩余槽位
    reserved_count = head_count + tail_count
    remaining_slots = max_signals - reserved_count

    # 按优先级选择：SIP > cause > important > other
    selected = []
    selected_set = set()

    def _add_packet(pkt):
        pkt_id = (pkt.get("frame"), pkt.get("timestamp"), pkt.get("protocol"))
        if pkt_id not in selected_set:
            selected_set.add(pkt_id)
            selected.append(pkt)
            return True
        return False

    # 先加入首尾消息
    for p in head_packets + tail_packets:
        _add_packet(p)

    # 加入 SIP 信令
    for p in sip_packets:
        _add_packet(p)

    # 加入带 cause 的信令
    for p in cause_packets:
        _add_packet(p)

    # 加入重要信令
    for p in important_packets:
        _add_packet(p)

    # 如果还有槽位，从其他信令中均匀采样
    if len(selected) < max_signals and other_packets:
        other_remaining = [p for p in other_packets if p not in selected]
        step = max(1, len(other_remaining) / (max_signals - len(selected)))
        for i in range(int((max_signals - len(selected)) * 1.2)):  # 多取 20% 以防去重后不足
            idx = int(i * step)
            if idx < len(other_remaining):
                _add_packet(other_remaining[idx])

    # 截断到 max_signals
    selected = selected[:max_signals]

    # 计算过滤数量
    filtered_count = len(results) - len(selected)

    # 按时间戳排序
    selected.sort(key=lambda x: x.get("timestamp", ""))

    return selected, filtered_count


def identify_entities(results):
    """根据协议和IP地址识别通信实体"""
    # 按IP地址识别通信实体
    ip_entities = {}

    for packet in results:
        src_ip = packet.get("src")
        dst_ip = packet.get("dst")
        protocol = packet.get("protocol")

        # 即使协议字段为None，也尝试收集IP信息，以防万一
        if src_ip and src_ip not in ip_entities:
            ip_entities[src_ip] = set()
        if dst_ip and dst_ip not in ip_entities:
            ip_entities[dst_ip] = set()

        if src_ip and protocol:
            ip_entities[src_ip].add(protocol)
        if dst_ip and protocol:
            ip_entities[dst_ip].add(protocol)

    # 基于协议模式推断实体角色 (更精细的判断顺序和条件)
    entity_roles = {}
    # print("DEBUG: IP protocols identified:")
    for ip, protocols in ip_entities.items():
        # print(f"  IP: {ip}, Protocols: {protocols}")
        role = "Unknown_IP"  # 默认角色

        # 1. PGW: GTPv2 AND DIAMETER (最明确的组合)
        if "GTPv2" in protocols and "DIAMETER" in protocols:
            role = "PGW"
        # 2. MME: S1AP AND GTPv2 (通用MME交互)
        elif "S1AP" in protocols and "GTPv2" in protocols:
            role = "MME"
        # 3. AMF (for 5G NGAP) - 如果存在，优先级高
        elif "NGAP" in protocols:
            role = "AMF"
        # 4. SGW: GTPv2 BUT NOT DIAMETER AND NOT S1AP (确保不是PGW或MME)
        elif (
            "GTPv2" in protocols
            and "DIAMETER" not in protocols
            and "S1AP" not in protocols
        ):
            role = "SGW"
        # 5. eNB: S1AP BUT NOT GTPv2 (eNB 可能封装 SIP，不应因此被排除)
        elif "S1AP" in protocols and "GTPv2" not in protocols:
            role = "eNB"
        # 6. IMS: SIP BUT NO OTHER CORE NETWORK PROTOCOLS (确保不是 MME, eNB, SGW, PGW, AMF, PCRF/HSS)
        elif "SIP" in protocols and not (
            "S1AP" in protocols
            or "GTPv2" in protocols
            or "DIAMETER" in protocols
            or "NGAP" in protocols
        ):
            role = "IMS"
        # 7. PCRF/HSS: DIAMETER BUT NOT GTPv2 (确保不是PGW)
        elif "DIAMETER" in protocols and "GTPv2" not in protocols:
            role = "PCRF/HSS"

        entity_roles[ip] = role
        # print(f"  Assigned Role: {role}")
    return entity_roles


def analyze_signaling(results):
    """分析信令流程：主被叫基于 SIP From/To；失败基于 CANCEL 或 4xx/5xx/6xx 或 BYE 携带错误码"""
    analysis = {
        "error_signals": [],
        "call_flow_type": "unknown",
        "failure_reason": None,
        "failure_point": None,
        "call_status": "unknown",
        "call_parties": {"from": None, "to": None},
    }

    sip_packets = [p for p in results if p.get("protocol") == "SIP"]

    sip_messages = [p.get("message") for p in sip_packets if p.get("message")]
    if any(m and "INVITE" in str(m) for m in sip_messages):
        analysis["call_flow_type"] = "call_setup"
    elif any(m and "REGISTER" in str(m) for m in sip_messages):
        analysis["call_flow_type"] = "registration"

    def sip_info(packet):
        sip = (packet.get("details") or {}).get("sip") or {}
        msg = packet.get("message") or ""
        method = sip.get("method")
        status_code = sip.get("status_code")
        if not method and msg and not (len(msg) >= 3 and msg[:3].isdigit()):
            method = msg
        if status_code is None and msg and len(msg) >= 3 and msg[:3].isdigit():
            try:
                status_code = int(msg[:3])
            except ValueError:
                status_code = None
        return sip, method, status_code

    for packet in sip_packets:
        sip, method, _ = sip_info(packet)
        if method == "INVITE":
            analysis["call_parties"]["from"] = sip.get("from")
            analysis["call_parties"]["to"] = sip.get("to")
            break

    failure_packet = None
    failure_reason = None

    for packet in sip_packets:
        sip, method, status_code = sip_info(packet)

        if method == "CANCEL":
            analysis["error_signals"].append(packet)
            if not failure_packet:
                failure_packet = packet
                failure_reason = "Detected SIP CANCEL"
            continue

        if status_code is not None and status_code >= 400:
            analysis["error_signals"].append(packet)
            if not failure_packet:
                failure_packet = packet
                failure_reason = f"Detected SIP {status_code} error response"
            continue

        if method == "BYE":
            reason_h = sip.get("reason") or ""
            m_q850 = re.search(r"cause\s*=\s*(\d+)", reason_h, re.IGNORECASE)
            m_sip = re.search(r"sip\s*;\s*cause\s*=\s*(\d+)", reason_h, re.IGNORECASE)

            bye_error = False
            if m_q850:
                try:
                    q850 = int(m_q850.group(1))
                    if q850 != 16:
                        bye_error = True
                except ValueError:
                    pass
            if m_sip:
                try:
                    sc = int(m_sip.group(1))
                    if sc >= 400:
                        bye_error = True
                except ValueError:
                    pass

            if bye_error:
                analysis["error_signals"].append(packet)
                if not failure_packet:
                    failure_packet = packet
                    failure_reason = "Detected BYE with error code"

    if failure_packet:
        analysis["call_status"] = "failure"
        analysis["failure_point"] = {
            "protocol": failure_packet.get("protocol"),
            "message": failure_packet.get("message"),
            "cause": failure_packet.get("cause"),
            "timestamp": failure_packet.get("timestamp"),
        }
        analysis["failure_reason"] = failure_reason
        return analysis

    first_200_idx = None
    for idx, packet in enumerate(sip_packets):
        sip, _, status_code = sip_info(packet)
        if status_code == 200:
            cseq_method = (sip or {}).get("cseq_method")
            cseq = (sip or {}).get("cseq") or ""
            if (cseq_method == "INVITE") or ("INVITE" in str(cseq)):
                first_200_idx = idx
                break

    has_ack_200 = False
    if first_200_idx is not None:
        for j in range(first_200_idx, len(sip_packets)):
            _, method_j, _ = sip_info(sip_packets[j])
            if method_j == "ACK":
                has_ack_200 = True
                break

    analysis["call_status"] = "success" if has_ack_200 else "unknown"
    return analysis


def generate_mermaid(results, analysis=None, ip_to_entity=None, filtered_count=0):
    """生成Mermaid时序图，修正上下行方向和箭头显示 - 增强版"""

    def _sanitize_mermaid_text(v):
        s = str(v or "")
        s = s.replace("\r", " ").replace("\n", " ")
        s = s.replace(";", "；")
        s = re.sub(r"\s+", " ", s).strip()
        return s

    def _parse_timestamp_to_sec(ts_str):
        """解析时间戳为秒数（HH:MM:SS.mmm 格式）"""
        if not ts_str:
            return None
        try:
            match = re.search(r"(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?", str(ts_str))
            if match:
                h, m, s = match.groups()[:3]
                ms = match.group(4) if match.group(4) else "0"
                ms_sec = int(ms[:3].ljust(3, '0')) / 1000.0 if ms else 0
                return int(h) * 3600 + int(m) * 60 + int(s) + ms_sec
        except:
            pass
        return None

    entities = set()
    for packet in results:
        # 这里仍然需要遍历所有包来确定出现了哪些协议相关的实体
        if packet.get("protocol") == "SIP":
            entities.add("UE")
            entities.add("SBC")
            entities.add("IMS")
        elif packet.get("protocol") == "GTPv2":
            entities.add("SGW")  # 尽管SGW不会在最终图上显示，但这里需要它来辅助GTPv2消息判断
            entities.add("PGW")
        elif packet.get("protocol") == "S1AP":
            entities.add("eNB")
            entities.add("MME")
        elif packet.get("protocol") == "DIAMETER":
            entities.add("PCRF")
        elif packet.get("protocol") == "NGAP":  # Add NGAP related entity for 5G
            entities.add("AMF")

    # === 移除 SGW，因为它在消息流中会被替换为 MME ===
    entities.discard("SGW")

    # 固定顺序输出实际出现的实体
    ordered_participants = ["UE", "eNB", "MME", "AMF", "SMF", "PGW", "UPF", "PCRF", "SBC", "IMS"]
    mermaid = ["sequenceDiagram"]
    for p in ordered_participants:
        if p in entities:
            mermaid.append(f"    participant {p}")
    # 兼容原有代码中可能出现的其他实体 (如果不在预定义顺序中)
    for p in sorted(entities):
        if p not in ordered_participants:
            mermaid.append(f"    participant {p}")

    # 添加失败样式定义（如果存在错误信令）
    if analysis and analysis.get("error_signals"):
        mermaid.append("    classDef failure fill:#ff9999,stroke:#333")

    # 添加过滤说明 Note
    if filtered_count > 0:
        total = len(results) + filtered_count
        first_entity = list(entities)[0] if entities else "UE"
        last_entity = "IMS" if "IMS" in entities else (list(entities)[-1] if entities else "UE")
        mermaid.append(f"    Note over {first_entity},{last_entity}: 已过滤 {filtered_count} 条非关键信令 (共{total}条，显示{len(results)}条)")

    # 添加消息流 - 根据IP映射判断方向，带时间间隔检测
    TIME_GAP_THRESHOLD_SEC = 20  # 20 秒，插入时间间隔 Note 的阈值
    last_timestamp_sec = None
    msg_index = 0

    for packet in results:
        src_ip = packet.get("src")
        dst_ip = packet.get("dst")
        protocol = packet.get("protocol")
        message = packet.get("message", "")

        # === 时间间隔检测（20 秒阈值）===
        current_ts_sec = _parse_timestamp_to_sec(packet.get("timestamp", ""))
        if last_timestamp_sec is not None and current_ts_sec is not None:
            gap_sec = current_ts_sec - last_timestamp_sec
            if gap_sec >= TIME_GAP_THRESHOLD_SEC:
                # 格式化时间间隔显示
                if gap_sec >= 3600:
                    gap_str = f"{int(gap_sec // 3600)}小时{int((gap_sec % 3600) // 60)}分{int(gap_sec % 60)}秒"
                elif gap_sec >= 60:
                    gap_str = f"{int(gap_sec // 60)}分{int(gap_sec % 60)}秒"
                else:
                    gap_str = f"{int(gap_sec)}秒"

                first_entity = list(entities)[0] if entities else "UE"
                last_entity = "IMS" if "IMS" in entities else (list(entities)[-1] if entities else "UE")
                mermaid.append(f"    Note over {first_entity},{last_entity}: ⏱ 信令间隔 {gap_str}")
        last_timestamp_sec = current_ts_sec

        src_entity = "Unknown_IP"
        dst_entity = "Unknown_IP"

        # 处理SIP协议的特殊逻辑
        if protocol == "SIP":
            underlying_protocols = packet.get("underlying_protocols", [])
            if "GTP-U" in underlying_protocols or "GTP" in underlying_protocols:
                src_entity = "UE"
                dst_entity = "SBC"
            else:
                if ip_to_entity:
                    src_mapped = ip_to_entity.get(src_ip, None)
                    dst_mapped = ip_to_entity.get(dst_ip, None)
                    if src_mapped and dst_mapped and src_mapped != "Unknown_IP" and dst_mapped != "Unknown_IP":
                        src_entity = src_mapped
                        dst_entity = dst_mapped
                    else:
                        src_entity = "SBC"
                        dst_entity = "IMS"
                else:
                    src_entity = "SBC"
                    dst_entity = "IMS"

        # S1AP中的特定NAS消息流向 (Uplink/Downlink NAS Transport) - 优先级高于通用S1AP
        elif protocol == "S1AP" and (
            re.search(r"Uplink NAS Transport|id-uplinkNASTransport", str(message), re.IGNORECASE)
        ):
            src_entity = "UE"
            dst_entity = "MME"
        elif protocol == "S1AP" and (
            re.search(r"Downlink NAS Transport|id-downlinkNASTransport", str(message), re.IGNORECASE)
        ):
            src_entity = "MME"
            dst_entity = "UE"
        # NAS 消息 (S1AP/NGAP) 强制 UE <-> MME/AMF 的逻辑流 (通用NAS，如果没被上面特定匹配)
        elif protocol == "S1AP" and "NAS" in str(message):
            src_entity = "UE"
            dst_entity = "MME"
        elif protocol == "NGAP" and "NAS" in str(message):
            src_entity = "UE"
            dst_entity = "AMF"

        # S1AP 特定消息流向
        elif protocol == "S1AP":
            if "Extended service request" in str(message) or "0x4c" in str(message):
                src_entity = "eNB"
                dst_entity = "MME"
            elif "id-UEContextModification" in str(message) or "21" in str(message):
                src_entity = "MME"
                dst_entity = "eNB"
            elif "id-UEContextReleaseRequest" in str(message) or "18" in str(message):
                src_entity = "eNB"
                dst_entity = "MME"
            elif "id-UEContextRelease" in str(message) or "23" in str(message):
                src_entity = "MME"
                dst_entity = "eNB"
            elif "id-E-RABSetup" in str(message) or "5" in str(message):
                src_entity = "MME"
                dst_entity = "eNB"
            elif "id-E-RABRelease" in str(message) or "7" in str(message):
                src_entity = "MME"
                dst_entity = "eNB"
            else:
                src_entity = ip_to_entity.get(src_ip, src_ip) if ip_to_entity and src_ip else "Unknown_IP"
                dst_entity = ip_to_entity.get(dst_ip, dst_ip) if ip_to_entity and dst_ip else "Unknown_IP"

        # GTPv2 特定消息流向 - 根据业务逻辑将SGW转换为MME或PGW
        elif protocol == "GTPv2":
            original_src = ip_to_entity.get(src_ip, src_ip) if ip_to_entity and src_ip else "Unknown_IP"
            original_dst = ip_to_entity.get(dst_ip, dst_ip) if ip_to_entity and dst_ip else "Unknown_IP"
            if "SGW" in (original_src, original_dst):
                is_request = "Request" in str(message) and "Response" not in str(message)
                is_response = "Response" in str(message)
                if is_request:
                    src_entity = "MME"
                    dst_entity = "PGW"
                elif is_response:
                    src_entity = "PGW"
                    dst_entity = "MME"
                else:
                    src_entity = original_src if original_src != "SGW" else "MME"
                    dst_entity = original_dst if original_dst != "SGW" else "PGW"
            else:
                src_entity = original_src
                dst_entity = original_dst
        else:
            src_entity = ip_to_entity.get(src_ip, src_ip) if ip_to_entity and src_ip else "Unknown_IP"
            dst_entity = ip_to_entity.get(dst_ip, dst_ip) if ip_to_entity and dst_ip else "Unknown_IP"

        # 检测并修复自环问题
        if src_entity == dst_entity and src_entity != 'Unknown_IP':
            # 根据协议类型和消息内容推断正确的目标实体
            if protocol == "S1AP":
                if src_entity == "eNB":
                    dst_entity = "MME"
                elif src_entity == "MME":
                    dst_entity = "eNB"
            elif protocol == "GTPv2":
                if src_entity == "MME":
                    dst_entity = "PGW"
                elif src_entity == "PGW":
                    dst_entity = "MME"
            elif protocol == "SIP":
                if src_entity == "UE":
                    dst_entity = "IMS"
                elif src_entity == "IMS":
                    dst_entity = "UE"
        
        # 如果仍然是自环且不是Unknown_IP，跳过此消息
        if src_entity == dst_entity and src_entity != 'Unknown_IP':
            continue

        msg = _sanitize_mermaid_text(packet.get("message", packet["protocol"]))
        timestamp = format_timestamp(packet.get("timestamp", ""))
        message_text = _sanitize_mermaid_text(f"{timestamp} {msg}")
        if packet.get("cause"):
            cause = _sanitize_mermaid_text(packet.get("cause"))
            if cause:
                message_text += f" ({cause})"

        # **方向判断和箭头符号区分**
        # 默认箭头与方向（请求/上行，响应/下行）
        # 判断是否是响应：SIP响应以3位数字开头，GTPv2用原有判定，NAS等协议暂用默认方向
        is_response = False
        if protocol == "SIP":
            # 如果message开头为数字（状态码），一般是响应
            if message and len(message) >= 3 and message[:3].isdigit():
                is_response = True
        elif protocol == "GTPv2":
            # 结合消息中是否包含“Response”判定响应/请求
            is_response = "Request" not in message
        elif protocol == "S1AP":
            # 以你对S1AP消息的了解自行决定是否判响应（此处简化：若包含“Response”）
            is_response = "Request" not in message and "request" not in message
        elif protocol == "NGAP":
            is_response = "Request" not in message
        elif protocol == "DIAMETER":
            is_response = "Answer" in message or "Response" in message


        # 处理箭头和src_dst实际方向：
        # 对于响应，箭头反转，同时箭头显示为虚线; 请求方向保持src->>dst的实线箭头
        # MME/AMF相关协议重定义方向
        if protocol =="S1AP":
            if not is_response:
                # 请求总是发给 MME                
                if dst_entity != "MME": 
                    dst_entity, src_entity = "MME", dst_entity
            elif src_entity != "MME":
                # 响应总是由 MME发出，目标为之前请求发起者
                src_entity, dst_entity = "MME", src_entity
        elif protocol == "NGAP":
            if not is_response:
                if dst_entity != "AMF":
                    dst_entity, src_entity = "AMF", dst_entity
            elif src_entity != "AMF":
                src_entity, dst_entity = "AMF", src_entity
        elif protocol =="GTPv2":
            if not is_response:
                if dst_entity not in ("PGW","UPF"):
                    dst_entity, src_entity = "PGW", dst_entity
            elif src_entity not in ("PGW","UPF"):
                src_entity, dst_entity = "PGW", src_entity

        # SIP和其它协议方向不变，响应方向交换源目标
        elif is_response:
            src_entity, dst_entity = dst_entity, src_entity

        arrow = "-->>" if is_response else "->>"

        if analysis and packet in analysis.get("error_signals", []):
            message_text += " (ERROR)"
            mermaid.append(f"    classMsg{msg_index} failure")
            mermaid.append(f"    {src_entity}{arrow}{dst_entity}: {message_text}%%msg{msg_index}")
        else:
            mermaid.append(f"    {src_entity}{arrow}{dst_entity}: {message_text}")

        msg_index += 1

    return "\n".join(mermaid)


def main():
    parser = argparse.ArgumentParser(description="解析Wireshark PCAP文件并提取信令信息")
    parser.add_argument("-p", "--pcap", help="PCAP文件路径")
    parser.add_argument("-t", "--text", help="Wireshark详细输出文本文件路径")
    parser.add_argument(
        "-f",
        "--filter",
        default="(sip || gtpv2 || s1ap || ngap || diameter || gtp || rtcp) && !(tcp.analysis.retransmission)",
        help="Wireshark显示过滤器",
    )
    parser.add_argument("-j", "--json", help="输出JSON文件路径")
    parser.add_argument("-m", "--mermaid", help="输出Mermaid时序图文件路径")
    parser.add_argument(
        "-l", "--limit", type=int, default=60, help="时序图中显示的最大信令数量（默认 60，超过时自动筛选关键信令）"
    )
    parser.add_argument("--tshark", help="tshark.exe路径，默认自动探测")
    parser.add_argument(
        "--max-size-kb", type=int, default=500, help="pcap文件大小门限(KB)，超过则提示后结束"
    )
    parser.add_argument(
        "--summary", action="store_true", help="快速输出pcap摘要(JSON)后退出"
    )
    parser.add_argument("--analysis-json", help="输出分析结果JSON文件路径(可选)")
    parser.add_argument("--report-json", help="输出UI报告JSON(可选)")
    parser.add_argument(
        "--kb-path",
        default=os.path.normpath(
            os.path.join(os.path.dirname(__file__), "..", "kb", "flowshark.cases.kb.md")
        ),
        help="知识库md路径",
    )
    parser.add_argument("--kb-max", type=int, default=10, help="知识库候选返回条数")
    parser.add_argument("--no-kb", action="store_true", help="禁用知识库检索")
    parser.add_argument(
        "--debug-tshark", action="store_true", help="打印tshark实际命令与stderr(用于排错)"
    )

    args = parser.parse_args()

    # 处理输入选项
    if not args.pcap and not args.text:
        parser.error("必须提供PCAP文件或Wireshark文本输出文件")

    if args.summary:
        if not args.pcap:
            parser.error("--summary 模式必须提供PCAP文件")
        summary = get_pcap_summary(
            args.pcap,
            filter_str=args.filter,
            max_size_kb=args.max_size_kb,
            tshark_path=args.tshark,
            debug_tshark=args.debug_tshark,
        )
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return

    if args.pcap and args.max_size_kb is not None:
        size_bytes = os.path.getsize(args.pcap)
        if size_bytes > int(args.max_size_kb) * 1024:
            print(f"文件尺寸超过门限({args.max_size_kb}KB)，结束分析")
            return

    base_name = os.path.splitext(args.pcap)[0] if args.pcap else "wireshark_output"
    csv_output = f"{base_name}_signaling.csv"
    json_output = args.json or f"{base_name}_signaling.json"
    mermaid_output = args.mermaid or f"{base_name}_mermaid.txt"

    if args.pcap:
        text_output = args.text or f"{base_name}_decoded.txt"
        run_tshark(args.pcap, text_output, args.filter, tshark_path=args.tshark)
        print(f"已将PCAP文件转换为文本: {text_output}")
    else:
        text_output = args.text

    # 解析文本文件
    results = parse_wireshark_output(text_output, csv_output, json_output)
    print(f"已解析 {len(results)} 个信令包")

    # 提取关键信令
    key_signals, filtered_count = extract_key_signaling(results, args.limit)
    print(f"已提取 {len(key_signals)} 个关键信令")
    if filtered_count > 0:
        print(f"已过滤 {filtered_count} 条非关键信令")

    # 识别通信实体角色
    ip_to_entity = identify_entities(results)

    # 分析信令
    analysis = analyze_signaling(results)
    print(f"呼叫类型: {analysis['call_flow_type']}")
    if analysis["failure_reason"]:
        print(f"失败原因: {analysis['failure_reason']}")

    if args.analysis_json:
        error_frames = []
        for p in analysis.get("error_signals", []):
            if isinstance(p, dict) and p.get("frame") is not None:
                error_frames.append(p.get("frame"))
        analysis_report = {
            "call_flow_type": analysis.get("call_flow_type"),
            "call_status": analysis.get("call_status"),
            "call_parties": analysis.get("call_parties"),
            "failure_reason": analysis.get("failure_reason"),
            "failure_point": analysis.get("failure_point"),
            "error_frames": error_frames,
        }
        with open(args.analysis_json, "w", encoding="utf-8") as f:
            json.dump(analysis_report, f, ensure_ascii=False, indent=2)
        print(f"已输出分析结果: {args.analysis_json}")

    # 生成Mermaid图
    mermaid_content = generate_mermaid(key_signals, analysis, ip_to_entity, filtered_count)
    with open(mermaid_output, "w", encoding="utf-8") as f:
        f.write(mermaid_content)
    print(f"已生成Mermaid时序图: {mermaid_output}")

    if args.report_json:
        error_frames = []
        for p in analysis.get("error_signals", []):
            if isinstance(p, dict) and p.get("frame") is not None:
                error_frames.append(p.get("frame"))

        analysis_report = {
            "call_flow_type": analysis.get("call_flow_type"),
            "call_status": analysis.get("call_status"),
            "call_parties": analysis.get("call_parties"),
            "failure_reason": analysis.get("failure_reason"),
            "failure_point": analysis.get("failure_point"),
            "error_frames": error_frames,
        }

        summary = None
        if args.pcap:
            try:
                summary = get_pcap_summary(
                    args.pcap,
                    filter_str=args.filter,
                    max_size_kb=args.max_size_kb,
                    tshark_path=args.tshark,
                    debug_tshark=args.debug_tshark,
                )
            except Exception as e:
                summary = {"pcap_file": args.pcap, "error": str(e)}

        kb_payload = None
        if not args.no_kb:
            try:
                cases = load_kb_cases(args.kb_path)
                query = _extract_query_features(results, analysis)
                hits = search_kb(cases, query, max_results=args.kb_max)
                kb_payload = {
                    "kb_path": args.kb_path,
                    "kb_total": len(cases),
                    "query": query,
                    "hits": [
                        {
                            "dna_id": c.get("dna_id"),
                            "case_numbers": c.get("case_numbers"),
                            "signal_count": _case_signal_count(c),
                            "has_180": _case_has_180(c),
                            "call_type": _case_call_type(c),
                            "issue_location": c.get("issue_location"),
                            "diagnosis": c.get("diagnosis"),
                            "root_cause": c.get("root_cause"),
                            "call_process": c.get("call_process"),
                        }
                        for c in hits
                    ],
                }
            except Exception as e:
                kb_payload = {"kb_path": args.kb_path, "error": str(e)}

        report = {
            "summary": summary,
            "analysis": analysis_report,
            "kb": kb_payload,
            "outputs": {
                "decoded_text": text_output,
                "signaling_csv": csv_output,
                "signaling_json": json_output,
                "mermaid": mermaid_output,
            },
            "mermaid_text": mermaid_content,
        }

        with open(args.report_json, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        print(f"已输出UI报告: {args.report_json}")


if __name__ == "__main__":
    main()
