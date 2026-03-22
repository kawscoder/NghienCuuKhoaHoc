"""
DefLog IDS Parser

Parser hybrid cho hệ thống phân tích log IDS.

Chức năng chính:
- Phân tích log Suricata / Snort / Zeek / Generic IDS
- Rule parser + LLM parser
- Chuẩn hóa dữ liệu về schema thống nhất
- Tính parser_confidence
- Hỗ trợ multi-log
- Không crash khi field thiếu

Lưu ý:
Parser chỉ thực hiện nhiệm vụ PARSE.
Không làm enrichment (geoip, threat intel).
Những việc này sẽ thuộc normalizer.

Tác giả: kawscode 
"""

import re
import json
import os
from datetime import datetime

from app.analysis.llm_analysis import LLMClient


# ==========================================================
# LLM CLIENT
# ==========================================================

from app.config import Config

llm = LLMClient(
    api_key=Config.LLM_API_KEY,
    base_url="https://api.groq.com/openai/v1",
    model="llama-3.1-8b-instant"
)

# ==========================================================
# PARSER SCHEMA (22 FIELD)
# ==========================================================

SCHEMA_FIELDS = [

    # network
    "source_ip",
    "target_ip",

    # transport
    "source_port",
    "target_port",

    # protocol
    "protocol",
    "service",

    # flow
    "flow_id",

    # time
    "timestamp",

    # alert
    "alert_signature",
    "alert_category",
    "attack_indicator",

    # severity
    "severity",
    "priority",

    # traffic
    "bytes",
    "packets",
    "duration",
    "payload_size",

    # behavior
    "traffic_intensity",
    "flow_direction",
    "network_zone",

    # metadata
    "sensor",
    "log_engine",

    # parser result
    "parser_confidence",

]


# ==========================================================
# EMPTY SCHEMA TEMPLATE
# ==========================================================

def empty_schema():
    """
    Tạo object schema rỗng
    đảm bảo mọi field tồn tại
    """

    data = {}

    for field in SCHEMA_FIELDS:
        data[field] = None

    return data


# ==========================================================
# INTERNAL NETWORK RANGE
# ==========================================================

PRIVATE_NETWORKS = [
    "10.",
    "192.168.",
    "172.16.",
    "172.17.",
    "172.18.",
    "172.19.",
    "172.20.",
    "172.21.",
    "172.22.",
    "172.23.",
    "172.24.",
    "172.25.",
    "172.26.",
    "172.27.",
    "172.28.",
    "172.29.",
    "172.30.",
    "172.31."
]


# ==========================================================
# SERVICE PORT MAP
# ==========================================================

SERVICE_MAP = {

    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    1434: "MSSQL",
    3306: "MYSQL",
    3389: "RDP"

}


# ==========================================================
# REGEX PATTERN
# ==========================================================

IP_PATTERN = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"

PORT_PATTERN = r":(\d{1,5})"

TIMESTAMP_PATTERN = r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}"

FLOW_ID_PATTERN = r"flow[_ ]?id[:= ](\d+)"

ALERT_PATTERN = r"alert[:= ](.+?)(?:,|$)"

DURATION_PATTERN = r"duration[:= ](\d+)"

SEVERITY_PATTERN = r"severity[:= ](\d+)"
PRIORITY_PATTERN = r"priority[:= ](\d+)"

# ==========================================================
# CLEANUP LOG
# ==========================================================

def cleanup_log(log: str):
    """
    Chuẩn hóa log trước khi parse
    loại bỏ khoảng trắng thừa và ký tự control
    """

    if not log:
        return ""

    log = str(log)

    log = log.replace("\n", " ")
    log = log.replace("\r", " ")

    log = re.sub(r"\s+", " ", log)

    return log.strip()


# ==========================================================
# SAFE JSON LOAD
# ==========================================================

def safe_json_load(text):
    """
    Parse JSON an toàn
    tránh crash nếu LLM trả format sai
    """

    if not text:
        return {}

    try:
        # loại bỏ markdown block nếu LLM trả
        text = text.strip()

        if text.startswith("```"):
            text = text.replace("```json", "")
            text = text.replace("```", "")

        return json.loads(text)

    except Exception:
        return {}


# ==========================================================
# VALIDATE IP
# ==========================================================

def is_valid_ip(ip):

    if not ip:
        return False

    parts = ip.split(".")

    if len(parts) != 4:
        return False

    try:
        for p in parts:
            if int(p) < 0 or int(p) > 255:
                return False
    except Exception:
        return False

    return True


# ==========================================================
# VALIDATE PORT
# ==========================================================

def is_valid_port(port):

    try:

        port = int(port)

        if 1 <= port <= 65535:
            return True

    except Exception:
        return False

    return False


# ==========================================================
# DETECT INTERNAL IP
# ==========================================================

def is_internal_ip(ip):

    if not ip:
        return False

    for net in PRIVATE_NETWORKS:

        if ip.startswith(net):
            return True

    return False


# ==========================================================
# DETECT SERVICE
# ==========================================================

def detect_service(port):
    """
    Xác định service từ port
    """

    try:
        port = int(port)
    except Exception:
        return None

    if port in SERVICE_MAP:
        return SERVICE_MAP[port]

    return None


# ==========================================================
# PARSE TIMESTAMP
# ==========================================================

def extract_timestamp(log):

    match = re.search(TIMESTAMP_PATTERN, log)

    if match:
        return match.group(0)

    return None

# ==========================================================
# EXTRACT SEVERITY
# ==========================================================

def extract_severity(log):

    match = re.search(SEVERITY_PATTERN, log.lower())

    if match:
        return int(match.group(1))

    return None

# ==========================================================
# EXTRACT PRIORITY
# ==========================================================

def extract_priority(log):

    match = re.search(PRIORITY_PATTERN, log.lower())

    if match:
        return int(match.group(1))

    return None
# ==========================================================
# PARSE FLOW ID
# ==========================================================

def extract_flow_id(log):

    match = re.search(FLOW_ID_PATTERN, log.lower())

    if match:
        return match.group(1)

    return None

# ==========================================================
# EXTRACT IPS
# ==========================================================

def extract_ips(log):

    ips = re.findall(IP_PATTERN, log)

    src = None
    dst = None

    if len(ips) >= 1:
        if is_valid_ip(ips[0]):
            src = ips[0]

    if len(ips) >= 2:
        if is_valid_ip(ips[1]):
            dst = ips[1]

    return src, dst

# ==========================================================
# EXTRACT PORTS
# ==========================================================

def extract_ports(log):
    """
    Extract port chuẩn từ IP:PORT
    Tránh bắt nhầm timestamp
    """

    matches = re.findall(r"\b\d+\.\d+\.\d+\.\d+:(\d{1,5})", log)

    src_port = None
    dst_port = None

    if len(matches) >= 1:
        try:
            src_port = int(matches[0])
        except:
            pass

    if len(matches) >= 2:
        try:
            dst_port = int(matches[1])
        except:
            pass

    return src_port, dst_port

# ==========================================================
# EXTRACT DURATION
# ==========================================================

def extract_duration(log):

    match = re.search(DURATION_PATTERN, log.lower())

    if match:
        return int(match.group(1))

    return None
    
# ==========================================================
# DETECT PROTOCOL
# ==========================================================

def detect_protocol(log):

    if re.search(r"\bTCP\b", log, re.IGNORECASE):
        return "TCP"

    if re.search(r"\bUDP\b", log, re.IGNORECASE):
        return "UDP"

    if re.search(r"\bICMP\b", log, re.IGNORECASE):
        return "ICMP"

    return None

# ==========================================================
# IDS ENGINE DETECTION
# ==========================================================

def detect_ids_engine(log: str):

    log_lower = log.lower()

    # JSON
    if log.strip().startswith("{"):
        try:
            data = json.loads(log)

            if "event_type" in data:
                return "suricata"

            if "uid" in data:
                return "zeek"

        except:
            pass

    # SNORT
    if re.search(r"\[\d+:\d+:\d+\]", log):
        return "snort"

    # FIREWALL
    if "src=" in log_lower and "dst=" in log_lower:
        return "firewall"

    # CLASSIC IDS
    if "->" in log and ":" in log:
        return "generic_ids"

    return "generic"

# ==========================================================
# RULE PARSER ROUTER
# ==========================================================

def select_rule_parser(engine):
    """
    Chọn rule parser theo IDS engine
    """

    if engine == "suricata":
        return rule_parser_suricata

    elif engine == "snort":
        return rule_parser_snort

    elif engine == "zeek":
        return rule_parser_zeek

    else:
        return rule_parser_generic
    

# ==========================================================
# FLOW DIRECTION (SOC MODEL)
# ==========================================================

def detect_flow_direction(src_ip, dst_ip):
    """
    Phân loại hướng traffic theo mô hình SOC

    external_inbound
    external_outbound
    east_west
    unknown
    """

    if not src_ip or not dst_ip:
        return "unknown"

    src_internal = is_internal_ip(src_ip)
    dst_internal = is_internal_ip(dst_ip)

    # external → internal
    if not src_internal and dst_internal:
        return "external_inbound"

    # internal → external
    if src_internal and not dst_internal:
        return "external_outbound"

    # internal → internal
    if src_internal and dst_internal:
        return "east_west"

    return "unknown"


# ==========================================================
# TRAFFIC INTENSITY
# ==========================================================

def calculate_traffic_intensity(packets, duration):
    """
    Tính mức độ traffic
    packets per second
    """

    try:

        packets = int(packets)
        duration = float(duration)

        if duration <= 0:
            return None

        rate = packets / duration

        # phân loại mức độ
        if rate > 1000:
            return "extreme"

        if rate > 300:
            return "high"

        if rate > 50:
            return "medium"

        return "low"

    except Exception:
        return None


# ==========================================================
# APPLY NETWORK CONTEXT
# ==========================================================

def apply_network_context(data):
    """
    Tính các field network context
    """

    src = data.get("source_ip")
    dst = data.get("target_ip")

    packets = data.get("packets")
    duration = data.get("duration")

    # network zone
    data["network_zone"] = detect_network_zone(src)

    # flow direction
    data["flow_direction"] = detect_flow_direction(src, dst)

    # traffic intensity
    data["traffic_intensity"] = calculate_traffic_intensity(
        packets,
        duration
    )

    return data

# ==========================================================
# RULE PARSER SURICATA
# ==========================================================

def rule_parser_suricata(log: str):
    """
    Parser cho Suricata

    Hỗ trợ:
    - EVE JSON
    - alert text
    """

    data = empty_schema()

    # ======================================================
    # CASE 1 — EVE JSON
    # ======================================================

    try:

        if log.strip().startswith("{"):

            eve = json.loads(log)

            # timestamp
            data["timestamp"] = eve.get("timestamp")

            # flow id
            data["flow_id"] = eve.get("flow_id")

            # network
            data["source_ip"] = eve.get("src_ip")
            data["target_ip"] = eve.get("dest_ip")

            data["source_port"] = eve.get("src_port")
            data["target_port"] = eve.get("dest_port")

            # protocol
            data["protocol"] = eve.get("proto")

            # alert section
            alert = eve.get("alert")

            if alert:

                data["alert_signature"] = alert.get("signature")
                data["alert_category"] = alert.get("category")

                data["severity"] = alert.get("severity")

                data["priority"] = alert.get("severity")

            # payload
            data["bytes"] = eve.get("bytes_toserver")
            data["packets"] = eve.get("packets_toserver")

            data["sensor"] = "suricata"

            return data

    except Exception:
        pass

    # ======================================================
    # CASE 2 — SURICATA ALERT TEXT
    # ======================================================

    src, dst = extract_ips(log)

    src_port, dst_port = extract_ports(log)

    proto = detect_protocol(log)

    data["source_ip"] = src
    data["target_ip"] = dst

    data["source_port"] = src_port
    data["target_port"] = dst_port

    data["protocol"] = proto

    # signature
    sig = re.findall(r"ET\s[A-Z_ ]+", log)

    if sig:
        data["alert_signature"] = sig[0]

    # category
    cat = re.findall(r"\[Classification:\s*(.*?)\]", log)

    if cat:
        data["alert_category"] = cat[0]

    # priority
    pri = re.findall(r"\[Priority:\s*(\d+)\]", log)

    if pri:
        data["priority"] = int(pri[0])

    # timestamp
    ts = extract_timestamp(log)

    if ts:
        data["timestamp"] = ts

    # flow id
    fid = extract_flow_id(log)

    if fid:
        data["flow_id"] = fid

    data["sensor"] = "suricata"

    return data

# ==========================================================
# RULE PARSER SNORT
# ==========================================================

def rule_parser_snort(log: str):
    """
    Parser cho Snort alert log
    """

    data = empty_schema()

    # ======================================================
    # SIGNATURE
    # ======================================================

    sig = re.findall(r"\[\d+:\d+:\d+\]\s*(.+)", log)

    if sig:
        data["alert_signature"] = sig[0].strip()

    # ======================================================
    # CLASSIFICATION
    # ======================================================

    cat = re.findall(r"\[Classification:\s*(.*?)\]", log)

    if cat:
        data["alert_category"] = cat[0]

    # ======================================================
    # PRIORITY
    # ======================================================

    pri = re.findall(r"\[Priority:\s*(\d+)\]", log)

    if pri:
        try:
            data["priority"] = int(pri[0])
            data["severity"] = int(pri[0])
        except Exception:
            pass

    # ======================================================
    # PROTOCOL
    # ======================================================

    proto = re.findall(r"\{(TCP|UDP|ICMP)\}", log)

    if proto:
        data["protocol"] = proto[0]

    # ======================================================
    # IP + PORT
    # ======================================================

    src, dst = extract_ips(log)

    src_port, dst_port = extract_ports(log)

    data["source_ip"] = src
    data["target_ip"] = dst

    data["source_port"] = src_port
    data["target_port"] = dst_port

    # ======================================================
    # TIMESTAMP
    # ======================================================

    ts = extract_timestamp(log)

    if ts:
        data["timestamp"] = ts

    # ======================================================
    # FLOW ID (rare trong Snort)
    # ======================================================

    fid = extract_flow_id(log)

    if fid:
        data["flow_id"] = fid

    # ======================================================
    # SENSOR
    # ======================================================

    data["sensor"] = "snort"

    return data

# ==========================================================
# RULE PARSER ZEEK
# ==========================================================

def rule_parser_zeek(log: str):
    """
    Parser cho Zeek log

    Hỗ trợ:
    - JSON format
    - TSV format
    """

    data = empty_schema()

    # ======================================================
    # CASE 1 — ZEEK JSON
    # ======================================================

    try:

        if log.strip().startswith("{"):

            z = json.loads(log)

            # timestamp
            ts = z.get("ts")

            if ts:
                try:
                    data["timestamp"] = datetime.fromtimestamp(
                        float(ts)
                    ).isoformat()
                except Exception:
                    data["timestamp"] = str(ts)

            # flow id
            data["flow_id"] = z.get("uid")

            # network
            data["source_ip"] = z.get("id.orig_h")
            data["target_ip"] = z.get("id.resp_h")

            data["source_port"] = z.get("id.orig_p")
            data["target_port"] = z.get("id.resp_p")

            # protocol
            data["protocol"] = z.get("proto")

            # traffic
            data["duration"] = z.get("duration")

            data["bytes"] = z.get("orig_bytes")
            data["packets"] = z.get("orig_pkts")

            data["sensor"] = "zeek"

            return data

    except Exception:
        pass

    # ======================================================
    # CASE 2 — ZEEK TSV
    # ======================================================

    # example format:
    # ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto duration

    parts = log.split()

    if len(parts) >= 7:

        try:

            # timestamp
            ts = parts[0]

            try:
                data["timestamp"] = datetime.fromtimestamp(
                    float(ts)
                ).isoformat()
            except Exception:
                data["timestamp"] = ts

            # flow id
            data["flow_id"] = parts[1]

            # network
            data["source_ip"] = parts[2]
            data["source_port"] = int(parts[3])

            data["target_ip"] = parts[4]
            data["target_port"] = int(parts[5])

            # protocol
            data["protocol"] = parts[6]

            # duration (optional)
            if len(parts) > 7:

                try:
                    data["duration"] = float(parts[7])
                except Exception:
                    pass

            data["sensor"] = "zeek"

            return data

        except Exception:
            pass

    # ======================================================
    # FALLBACK
    # ======================================================

    src, dst = extract_ips(log)

    src_port, dst_port = extract_ports(log)

    proto = detect_protocol(log)

    data["source_ip"] = src
    data["target_ip"] = dst

    data["source_port"] = src_port
    data["target_port"] = dst_port

    data["protocol"] = proto

    data["sensor"] = "zeek"

    return data

# ==========================================================
# RULE PARSER GENERIC IDS
# ==========================================================

def rule_parser_generic(log: str):
    """
    Parser cho generic IDS log
    dùng khi không xác định được engine
    """
    
    data = empty_schema()

    # ======================================================
    # IP
    # ======================================================

    src, dst = extract_ips(log)

    data["source_ip"] = src
    data["target_ip"] = dst

    # ======================================================
    # PORT
    # ======================================================

    src_port, dst_port = extract_ports(log)

    data["source_port"] = src_port
    data["target_port"] = dst_port

    # ======================================================
    # PROTOCOL
    # ======================================================

    proto = detect_protocol(log)

    data["protocol"] = proto

    # ======================================================
    # TIMESTAMP
    # ======================================================

    ts = extract_timestamp(log)

    if ts:
        data["timestamp"] = ts

    # ======================================================
    # FLOW ID
    # ======================================================

    fid = extract_flow_id(log)

    if fid:
        data["flow_id"] = fid

    # ======================================================
    # ALERT SIGNATURE
    # ======================================================

    alert = re.findall(ALERT_PATTERN, log, re.IGNORECASE)

    if alert:
        data["alert_signature"] = alert[0]

    # ======================================================
    # SEVERITY
    # ======================================================

    sev = extract_severity(log)

    if sev:
        data["severity"] = sev

    # ======================================================
    # PRIORITY
    # ======================================================

    pri = extract_priority(log)

    if pri:
        data["priority"] = pri

    # ======================================================
    # BYTES
    # ======================================================

    bytes_val = re.findall(r"bytes[:= ](\d+)", log, re.IGNORECASE)

    if bytes_val:
        try:
            data["bytes"] = int(bytes_val[0])
        except Exception:
            pass

    # ======================================================
    # PACKETS
    # ======================================================

    packets = re.findall(r"packets[:= ](\d+)", log, re.IGNORECASE)

    if packets:
        try:
            data["packets"] = int(packets[0])
        except Exception:
            pass

    # ======================================================
    # DURATION
    # ======================================================

    dur = extract_duration(log)

    if dur:
        data["duration"] = dur

    # ======================================================
    # SENSOR
    # ======================================================

    data["sensor"] = "generic_ids"

    # ======================================================
    # SERVICE DETECTION
    #  ======================================================
    if data["target_port"]:
        data["service"] = detect_service(data["target_port"])


    return data

# ==========================================================
# LLM PARSER
# ==========================================================

def llm_parser(log: str):
    """
    Parser AI dùng LLM để extract IDS fields
    luôn trả về schema chuẩn
    """

    try:

        prompt = f"""
You are an IDS log parser.

Extract structured fields from this IDS log.

Return ONLY JSON with these fields:

source_ip
target_ip
source_port
target_port
protocol
service
flow_id
timestamp
alert_signature
alert_category
attack_indicator
severity
priority
bytes
packets
duration
payload_size
traffic_intensity
flow_direction
network_zone
sensor
log_engine

If field does not exist return null.

Log:
{log}
"""

        response = llm.ask(prompt)

        data = safe_json_load(response)

        # ==================================================
        # FIELD MAP (fallback nếu LLM trả schema khác)
        # ==================================================

        FIELD_MAP = {

            # network
            "Source IP": "source_ip",
            "Destination IP": "target_ip",
            "src_ip": "source_ip",
            "dest_ip": "target_ip",

            # ports
            "Source Port": "source_port",
            "Destination Port": "target_port",
            "src_port": "source_port",
            "dest_port": "target_port",

            # protocol/service
            "Protocol": "protocol",
            "Service": "service",

            # alert
            "Event": "alert_signature",
            "Signature": "alert_signature",
            "Category": "alert_category",

            # traffic
            "Packet Count": "packets",
            "Packets": "packets",
            "Bytes": "bytes",
            "Bytes Transferred": "bytes",

            # flow
            "Flow ID": "flow_id",

            # time
            "Time": "timestamp",
            "Timestamp": "timestamp",

            # duration
            "Duration": "duration",

            # severity
            "Severity": "severity",
            "Priority": "priority",

            # behavior
            "Traffic Intensity": "traffic_intensity",
            "Flow Direction": "flow_direction",
            "Network Zone": "network_zone",

            # metadata
            "Sensor": "sensor",
            "Engine": "log_engine"
        }

        # ==================================================
        # INIT RESULT SCHEMA
        # ==================================================

        result = empty_schema()

        # ==================================================
        # MAP FIELD
        # ==================================================

        for key, value in data.items():

            mapped_key = key

            if key in FIELD_MAP:
                mapped_key = FIELD_MAP[key]

            if mapped_key not in result:
                continue

            # convert numeric fields
            if mapped_key in [
                "source_port",
                "target_port",
                "packets",
                "bytes",
                "duration",
                "severity",
                "priority"
            ]:
                try:
                    value = int(value)
                except:
                    pass

            result[mapped_key] = value

        return result

    except Exception as e:

        print("LLM PARSER ERROR:", e)

        return empty_schema()

# ==========================================================
# LLM PARSER PRO (SMART + CONTEXT)
# ==========================================================

def llm_parser_pro(log: str):
    """
    LLM parser nâng cấp:
    - tự detect loại log
    - hiểu context
    - parse chính xác hơn
    """

    try:

        prompt = f"""
You are a SOC analyst and expert IDS log parser.

TASK:
1. Identify log type (Suricata / Snort / Zeek / Firewall / Unknown)
2. Extract structured fields
3. Normalize into standard schema

STRICT RULES:
- Output ONLY JSON
- No explanation
- Missing fields = null
- Ports must be integer
- IP must be valid
- Detect service if possible
- Infer attack_indicator if possible

FIELDS:

source_ip
target_ip
source_port
target_port
protocol
service
flow_id
timestamp
alert_signature
alert_category
attack_indicator
severity
priority
bytes
packets
duration
payload_size
traffic_intensity
flow_direction
network_zone
sensor
log_engine

LOG:
{log}
"""

        response = llm.ask(prompt)

        data = safe_json_load(response)

        result = empty_schema()

        for key, value in data.items():

            if key not in result:
                continue

            # ép kiểu
            if key in ["source_port", "target_port", "packets", "bytes", "duration", "severity", "priority"]:
                try:
                    value = int(value)
                except:
                    pass

            result[key] = value

        return result

    except Exception as e:
        print("LLM PRO ERROR:", e)
        return empty_schema()
        
# ==========================================================
# CONSENSUS ENGINE
# ==========================================================

def consensus_engine(rule_result, llm_result):
    """
    So sánh rule parser và LLM parser
    để tạo kết quả cuối cùng
    """

    merged = empty_schema()

    matches = 0
    conflicts = 0
    nulls = 0
    valid_fields = 0

    for field in SCHEMA_FIELDS:

        if field == "parser_confidence":
            continue

        rule_val = rule_result.get(field)
        llm_val = llm_result.get(field)

        # ==================================================
        # CASE 1: BOTH NULL
        # ==================================================

        if rule_val is None and llm_val is None:

            merged[field] = None
            nulls += 1
            continue

        # ==================================================
        # CASE 2: RULE VALUE ONLY
        # ==================================================

        if rule_val is not None and llm_val is None:

            merged[field] = rule_val
            valid_fields += 1
            continue

        # ==================================================
        # CASE 3: LLM VALUE ONLY
        # ==================================================

        if rule_val is None and llm_val is not None:

            merged[field] = llm_val
            valid_fields += 1
            continue

        # ==================================================
        # CASE 4: MATCH
        # ==================================================

        if rule_val == llm_val:

            merged[field] = rule_val
            matches += 1
            valid_fields += 1
            continue

        # ==================================================
        # CASE 5: CONFLICT
        # ==================================================

        merged[field] = llm_val
        conflicts += 1
        valid_fields += 1

    # ======================================================
    # CONFIDENCE CALCULATION
    # ======================================================

    total_fields = len(SCHEMA_FIELDS) - 1

    base_score = valid_fields / total_fields

    bonus = matches * 0.015
    penalty = conflicts * 0.02

    confidence = base_score + bonus - penalty

    if confidence > 1:
        confidence = 1

    if confidence < 0:
        confidence = 0

    merged["parser_confidence"] = round(confidence, 3)

    return merged

# ==========================================================
# SERVICE DETECTION
# ==========================================================

SERVICE_MAP = {
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    1434: "MSSQL",
    3306: "MYSQL",
    3389: "RDP"
}

def detect_service(port):
    """
    Suy luận service từ port
    """

    try:
        port = int(port)

        if port in SERVICE_MAP:
            return SERVICE_MAP[port]

    except Exception:
        pass

    return None

# ==========================================================
# NETWORK ZONE
# ==========================================================

def detect_network_zone(ip):
    """
    xác định zone của IP
    """

    if not ip:
        return None

    if is_internal_ip(ip):
        return "internal"

    return "external"

# ==========================================================
# FLOW DIRECTION (SOC MODEL)
# ==========================================================

def detect_flow_direction(src_ip, dst_ip):
    """
    xác định hướng traffic
    """

    if not src_ip or not dst_ip:
        return None

    src_internal = is_internal_ip(src_ip)
    dst_internal = is_internal_ip(dst_ip)

    # external → internal
    if not src_internal and dst_internal:
        return "external_inbound"

    # internal → external
    if src_internal and not dst_internal:
        return "external_outbound"

    # internal → internal
    if src_internal and dst_internal:
        return "east_west"

    return "unknown"

# ==========================================================
# TRAFFIC INTENSITY
# ==========================================================

def calculate_traffic_intensity(packets, duration):
    """
    tính packet rate
    """

    try:

        packets = int(packets)
        duration = float(duration)

        if duration <= 0:
            return None

        rate = packets / duration

        if rate > 1000:
            return "extreme"

        if rate > 300:
            return "high"

        if rate > 50:
            return "medium"

        return "low"

    except Exception:
        return None


# ==========================================================
# APPLY ENRICHMENT
# ==========================================================

def apply_enrichment(data):
    """
    bổ sung các field suy luận
    """

    # service
    if not data.get("service"):
        data["service"] = detect_service(
            data.get("target_port")
        )

    # network zone
    data["network_zone"] = detect_network_zone(
        data.get("source_ip")
    )

    # flow direction
    data["flow_direction"] = detect_flow_direction(
        data.get("source_ip"),
        data.get("target_ip")
    )

    # traffic intensity
    data["traffic_intensity"] = calculate_traffic_intensity(
        data.get("packets"),
        data.get("duration")
    )

    return data

# ==========================================================
# MAIN PARSER
# ==========================================================

def parse_log(log: str):
    """
    Parser nâng cấp:
    rule → fallback llm pro → consensus → validation
    """

    log = cleanup_log(log)

    if not log:
        return {
            "error": "empty_log",
            "parser_confidence": 0
        }

    # ======================================================
    # DETECT ENGINE
    # ======================================================

    engine = detect_ids_engine(log)

    parser = select_rule_parser(engine)

    # ======================================================
    # RULE PARSER
    # ======================================================

    try:
        rule_result = parser(log)
    except:
        rule_result = empty_schema()

    # ======================================================
    # CHECK RULE QUALITY
    # ======================================================

    def count_valid(data):
        return sum(1 for v in data.values() if v)

    rule_score = count_valid(rule_result)

    # ======================================================
    # LLM PARSER (SMART TRIGGER)
    # ======================================================

    if rule_score < 5:
        llm_result = llm_parser_pro(log)
    else:
        llm_result = llm_parser(log)

    # ======================================================
    # CONSENSUS (GIỮ NGUYÊN CỦA ANH)
    # ======================================================

    merged = consensus_engine(
        rule_result,
        llm_result
    )

    # ======================================================
    # ENRICH
    # ======================================================

    merged = apply_enrichment(merged)

    # ======================================================
    # VALIDATION (🔥 BỔ SUNG QUAN TRỌNG)
    # ======================================================

    merged = apply_validation(merged)

    # ======================================================
    # ENGINE
    # ======================================================

    merged["log_engine"] = engine

    # ======================================================
    # MINIMUM CHECK (GIỮ)
    # ======================================================

    MIN_REQUIRED_FIELDS = 4

    def count_valid_fields(data):
        return sum(
            1 for k, v in data.items()
            if k != "parser_confidence" and v not in [None, ""]
        )

    if count_valid_fields(merged) < MIN_REQUIRED_FIELDS:
        return {
            "error": "insufficient_log_data",
            "parser_confidence": 0
        }

    return merged

# ==========================================================
# MULTI LOG PARSER
# ==========================================================

def parse_logs(logs):
    """
    Parser cho nhiều log

    logs: list[str]

    return:
    {
        results: [],
        summary: {}
    }
    """

    results = []

    valid = 0
    invalid = 0

    for log in logs:

        try:

            parsed = parse_log(log)

            if "error" in parsed:
                invalid += 1
            else:
                valid += 1

            results.append(parsed)

        except Exception:

            invalid += 1

            results.append({
                "error": "parser_failure",
                "parser_confidence": 0
            })

    summary = {

        "total_logs": len(logs),

        "valid_logs": valid,

        "invalid_logs": invalid

    }

    return {

        "results": results,

        "summary": summary

    }

# ==========================================================
# VALIDATION ENGINE
# ==========================================================

def validate_ip(ip):
    """
    kiểm tra IP hợp lệ
    """

    if not ip:
        return None

    pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"

    if re.match(pattern, ip):
        return ip

    return None

# ==========================================================
# PORT VALIDATION
# ==========================================================

def validate_port(port):
    """
    kiểm tra port hợp lệ
    """

    try:

        port = int(port)

        if 1 <= port <= 65535:
            return port

    except Exception:
        pass

    return None

# ==========================================================
# PROTOCOL VALIDATION
# ==========================================================

VALID_PROTOCOLS = {
    "TCP",
    "UDP",
    "ICMP",
    "HTTP",
    "HTTPS",
    "DNS"
}

def validate_protocol(proto):
    """
    chuẩn hóa protocol
    """

    if not proto:
        return None

    proto = str(proto).upper()

    if proto in VALID_PROTOCOLS:
        return proto

    return None

# ==========================================================
# SEVERITY VALIDATION
# ==========================================================

def validate_severity(sev):
    """
    severity thường 1-5
    """

    try:

        sev = int(sev)

        if 0 <= sev <= 10:
            return sev

    except Exception:
        pass

    return None

# ==========================================================
# TIMESTAMP VALIDATION
# ==========================================================

def validate_timestamp(ts):
    """
    chuẩn hóa timestamp
    """

    if not ts:
        return None

    try:

        if isinstance(ts, float):
            return datetime.fromtimestamp(ts).isoformat()

        if isinstance(ts, int):
            return datetime.fromtimestamp(ts).isoformat()

        return str(ts)

    except Exception:

        return None

# ==========================================================
# APPLY VALIDATION
# ==========================================================

def apply_validation(data):
    """
    validate các field quan trọng
    """

    data["source_ip"] = validate_ip(
        data.get("source_ip")
    )

    data["target_ip"] = validate_ip(
        data.get("target_ip")
    )

    data["source_port"] = validate_port(
        data.get("source_port")
    )

    data["target_port"] = validate_port(
        data.get("target_port")
    )

    data["protocol"] = validate_protocol(
        data.get("protocol")
    )

    data["severity"] = validate_severity(
        data.get("severity")
    )

    data["priority"] = validate_severity(
        data.get("priority")
    )

    data["timestamp"] = validate_timestamp(
        data.get("timestamp")
    )

    return data

