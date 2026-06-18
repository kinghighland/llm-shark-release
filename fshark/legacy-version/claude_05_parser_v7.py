#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import csv
import json
import os
import re
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


def run_tshark(pcap_file, output_file, filter_str=None):
    """使用tshark处理pcap文件并生成详细输出，增强错误处理"""
    if not os.path.exists(pcap_file):
        raise FileNotFoundError(f"找不到PCAP文件: {pcap_file}")
    
    cmd = ["tshark", "-r", pcap_file, "-V"]
    
    if filter_str:
        cmd.extend(["-Y", filter_str])
    
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            result = subprocess.run(
                cmd, 
                stdout=f, 
                stderr=subprocess.PIPE,
                check=True,
                timeout=300  # 5分钟超时
            )
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"tshark执行失败: {e.stderr.decode()}")
    except subprocess.TimeoutExpired:
        raise RuntimeError("tshark执行超时")
    except FileNotFoundError:
        raise RuntimeError("找不到tshark命令，请确保已安装Wireshark")
    
    return output_file



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
    """处理SIP协议，稳健提取所有响应类信令，如180/183/603等"""
    current_packet["protocol"] = "SIP"
    message_found = False
    sip_buffer = []
    max_buffer = 40  # 最多查找40行以兼容超大SIP包

    # 先把后续内容缓存下来便于多轮判别
    try:
        sip_buffer.append(line)
        for _ in range(max_buffer):
            next_line = next(lines_iter)
            sip_buffer.append(next_line)
            if (next_line.strip() == "" or 
                next_line.startswith("Frame ") or 
                "Internet Protocol" in next_line):
                break
    except StopIteration:
        pass

    # 优先全缓冲区查找 response
    for buf_line in sip_buffer:
        if "Status-Line:" in buf_line:
            status_line = buf_line.split("Status-Line:")[1].strip()
            match = sip_status_re.match(status_line)
            if match:
                status_code = match.group(1)
                reason = match.group(2)
                current_packet["message"] = f"{status_code} {reason}"
                message_found = True
                break
    # 若无，再找直接"SIP/2.0"（极少见裸行，不常用，但加一下兜底）
    if not message_found:
        for buf_line in sip_buffer:
            if buf_line.strip().startswith("SIP/2.0"):
                match = sip_status_re.match(buf_line.strip())
                if match:
                    status_code = match.group(1)
                    reason = match.group(2)
                    current_packet["message"] = f"{status_code} {reason}"
                    message_found = True
                    break
    # 请求方法
    if not message_found:
        for buf_line in sip_buffer:
            if "Request-Line:" in buf_line:
                try:
                    method = buf_line.split("Request-Line:")[1].strip().split()[0]
                    current_packet["message"] = method
                    message_found = True
                    break
                except (IndexError, AttributeError):
                    pass
            elif "Method:" in buf_line:
                try:
                    method = buf_line.split("Method:")[1].strip()
                    current_packet["message"] = method
                    message_found = True
                    break
                except (IndexError, AttributeError):
                    pass
            elif sip_request_re.search(buf_line) and "CSeq:" not in buf_line:
                match = sip_request_re.search(buf_line)
                if match:
                    current_packet["message"] = match.group(1)
                    message_found = True
                    break

    # 可选：拿 Reason 字段作为cause
    for buf_line in sip_buffer:
        if "Reason:" in buf_line:
            try:
                reason = buf_line.split("Reason:")[1].strip()
                if not current_packet.get("cause"):
                    current_packet["cause"] = f"SIP Reason: {reason}"
            except (IndexError, AttributeError):
                pass
            break
        

def handle_protocol_s1ap(line, current_packet, lines_iter):
    """处理S1AP协议，优先提取NAS Mobility Management和Session Management的信令名"""
    current_packet['protocol'] = 'S1AP'
    nas_message = None
    s1ap_message = None

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


def extract_key_signaling(results, max_signals=100):
    """从结果中提取关键信令"""
    # 如果总信令数小于等于max_signals，直接返回所有信令
    if len(results) <= max_signals:
        return results

    # 否则提取重要信令
    key_signals = []

    for packet in results:
        # 包含SIP信令
        if packet["protocol"] == "SIP":
            key_signals.append(packet)

        # 包含错误码的信令
        elif packet["cause"]:
            key_signals.append(packet)

        # 特定重要消息类型
        elif packet["message"] and any(
            keyword in str(packet["message"]).lower()
            for keyword in [
                "error",
                "reject",
                "failure",
                "fail",
                "denied",
                "release",
                "detach",
                "delete",
                "abort",
                "cancel",
                "auth",
            ]
        ):
            key_signals.append(packet)

    # 如果关键信令仍然超过max_signals，进一步筛选
    if len(key_signals) > max_signals:
        # 保留所有SIP信令和带错误码的信令
        must_keep = [p for p in key_signals if p["protocol"] == "SIP" or p["cause"]]

        # 选择剩余信令直到达到max_signals
        remaining_slots = max_signals - len(must_keep)
        if remaining_slots > 0:
            other_signals = [p for p in key_signals if p not in must_keep]
            # 均匀选择
            step = len(other_signals) / remaining_slots if remaining_slots > 0 else 0
            indices = [int(i * step) for i in range(remaining_slots)]
            selected_others = [
                other_signals[i] for i in indices if i < len(other_signals)
            ]
            key_signals = must_keep + selected_others
        else:
            key_signals = must_keep[:max_signals]

    # 重新按时间戳排序
    key_signals.sort(key=lambda x: x["timestamp"] if x["timestamp"] else "")
    return key_signals


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
    """分析信令流程，找出失败原因"""
    analysis = {
        "error_signals": [],
        "call_flow_type": "unknown",
        "failure_reason": None,
        "failure_point": None,
    }

    # 收集错误信令
    for packet in results:
        if packet["cause"] and any(
            err in str(packet["cause"]).lower()
            for err in [
                "error",
                "reject",
                "failure",
                "fail",
                "denied",
                "not acceptable",
            ]
        ):
            analysis["error_signals"].append(packet)

    # 确定呼叫流程类型
    sip_methods = [
        p["message"] for p in results if p["protocol"] == "SIP" and p["message"]
    ]

    if any(m and "INVITE" in str(m) for m in sip_methods):
        analysis["call_flow_type"] = "call_setup"
    elif any(m and "REGISTER" in str(m) for m in sip_methods):
        analysis["call_flow_type"] = "registration"

    # 判断失败点和原因
    if analysis["error_signals"]:
        # 取第一个错误作为主要失败点
        failure = analysis["error_signals"][0]
        analysis["failure_point"] = {
            "protocol": failure["protocol"],
            "message": failure["message"],
            "cause": failure["cause"],
            "timestamp": failure["timestamp"],
        }

        # 提取人类可读的失败原因
        analysis["failure_reason"] = (
            f"{failure['protocol']} {failure['message'] or ''} 失败: {failure['cause']}"
        )

    return analysis


def generate_mermaid(results, analysis=None, ip_to_entity=None):
    """生成Mermaid时序图，修正上下行方向和箭头显示"""
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

    # 添加消息流 - 根据IP映射判断方向
    for packet in results:
        src_ip = packet.get("src")
        dst_ip = packet.get("dst")
        protocol = packet.get("protocol")
        message = packet.get("message", "")

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

        msg = packet.get("message", packet["protocol"])
        timestamp = format_timestamp(packet.get("timestamp", ""))
        message_text = f"{timestamp} {msg}"
        if packet.get("cause"):
            message_text += f" ({packet['cause']})"

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

        timestamp = format_timestamp(packet.get("timestamp", ""))
        msg_text = f"{timestamp} {message}"
        if packet.get("cause"):
            msg_text += f" ({packet['cause']})"
        if analysis and packet in analysis.get("error_signals", []):
            msg_text += " (ERROR)"


        mermaid.append(f"    {src_entity}{arrow}{dst_entity}: {message_text}")

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
        "-l", "--limit", type=int, default=100, help="时序图中显示的最大信令数量"
    )

    args = parser.parse_args()

    # 处理输入选项
    if not args.pcap and not args.text:
        parser.error("必须提供PCAP文件或Wireshark文本输出文件")

    # 默认输出文件名
    base_name = os.path.splitext(args.pcap)[0] if args.pcap else "wireshark_output"
    csv_output = f"{base_name}_signaling.csv"
    json_output = args.json or f"{base_name}_signaling.json"
    mermaid_output = args.mermaid or f"{base_name}_mermaid.txt"

    # 处理PCAP或直接解析文本
    if args.pcap:
        text_output = args.text or f"{base_name}_decoded.txt"
        run_tshark(args.pcap, text_output, args.filter)
        print(f"已将PCAP文件转换为文本: {text_output}")
    else:
        text_output = args.text

    # 解析文本文件
    results = parse_wireshark_output(text_output, csv_output, json_output)
    print(f"已解析 {len(results)} 个信令包")

    # 提取关键信令
    key_signals = extract_key_signaling(results, args.limit)
    print(f"已提取 {len(key_signals)} 个关键信令")

    # 识别通信实体角色
    ip_to_entity = identify_entities(results)

    # 分析信令
    analysis = analyze_signaling(results)
    print(f"呼叫类型: {analysis['call_flow_type']}")
    if analysis["failure_reason"]:
        print(f"失败原因: {analysis['failure_reason']}")

    # 生成Mermaid图
    mermaid_content = generate_mermaid(key_signals, analysis, ip_to_entity)
    with open(mermaid_output, "w", encoding="utf-8") as f:
        f.write(mermaid_content)
    print(f"已生成Mermaid时序图: {mermaid_output}")


if __name__ == "__main__":
    main()
