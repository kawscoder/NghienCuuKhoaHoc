"""
DefLog Normalizer

Module: Network Data Normalization & Enrichment

Chức năng:
Chuẩn hóa dữ liệu sau parser và làm giàu thông tin network.

Nhiệm vụ chính:
- protocol normalization
- severity normalization
- service detection
- GeoIP enrichment
- network context detection
- traffic metrics calculation
"""

import os
import ipaddress
import geoip2.database


# ==========================================================
# GEOIP DATABASE LOADER
# ==========================================================

"""
Load GeoLite2 City database

Database path:
backend/data/GeoLite2-City.mmdb
"""

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.dirname(__file__)
    )
)

GEO_DB_PATH = os.path.join(
    BASE_DIR,
    "data",
    "GeoLite2-City.mmdb"
)

geo_reader = None

try:
    geo_reader = geoip2.database.Reader(GEO_DB_PATH)
except Exception:
    geo_reader = None


# ==========================================================
# SERVICE MAP
# ==========================================================

"""
Common network service mapping
Port → Service
"""

PORT_SERVICE_MAP = {

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

    1433: "MSSQL",
    3306: "MYSQL",

    3389: "RDP"
}


# ==========================================================
# SEVERITY MAP
# ==========================================================

"""
IDS severity normalization

IDS thường dùng:

1 → Critical
2 → High
3 → Medium
4 → Low
"""

SEVERITY_MAP = {

    1: ("CRITICAL", 4),
    2: ("HIGH", 3),
    3: ("MEDIUM", 2),
    4: ("LOW", 1)
}


# ==========================================================
# PROTOCOL WHITELIST
# ==========================================================

VALID_PROTOCOLS = {

    "TCP",
    "UDP",
    "ICMP",
    "HTTP",
    "HTTPS",
    "DNS",
    "FTP",
    "SSH",
    "SMTP"
}

# ==========================================================
# PROTOCOL NORMALIZATION
# ==========================================================

def normalize_protocol(protocol):
    """
    Chuẩn hóa protocol và lọc whitelist
    """

    if not protocol:
        return None

    try:
        protocol = str(protocol).upper()
    except Exception:
        return None

    if protocol in VALID_PROTOCOLS:
        return protocol

    return None

# ==========================================================
# SEVERITY NORMALIZATION
# ==========================================================

def normalize_severity(severity):
    """
    Chuẩn hóa severity IDS.

    Input:
        severity = 1..4

    Output:
        severity_label
        severity_score

    Ví dụ:
        1 → ("CRITICAL", 4)
        2 → ("HIGH", 3)
    """

    if severity is None:
        return None, None

    try:
        severity = int(severity)
    except Exception:
        return None, None

    mapped = SEVERITY_MAP.get(severity)

    if mapped:
        return mapped[0], mapped[1]

    return None, None


# ==========================================================
# SERVICE DETECTION
# ==========================================================

def detect_service(port):
    """
    Xác định service từ port.

    Ví dụ:
        80 → HTTP
        443 → HTTPS
        22 → SSH
    """

    if port is None:
        return None

    try:
        port = int(port)
    except Exception:
        return None

    return PORT_SERVICE_MAP.get(port)

# ==========================================================
# ZONE DETECTION
# ==========================================================

def detect_zone(ip):
    """
    Xác định IP thuộc internal hay external network.

    Internal:
        private IP ranges

    External:
        public internet
    """

    if not ip:
        return None

    try:

        ip_obj = ipaddress.ip_address(ip)

        if ip_obj.is_private:
            return "internal"

        return "external"

    except Exception:

        return None


# ==========================================================
# FLOW DIRECTION DETECTION
# ==========================================================

def detect_flow_direction(src_ip, dst_ip):
    """
    Xác định hướng traffic.

    inbound
        external → internal

    outbound
        internal → external

    east_west
        internal → internal

    unknown
        external → external
    """

    if not src_ip or not dst_ip:
        return "unknown"

    src_zone = detect_zone(src_ip)
    dst_zone = detect_zone(dst_ip)

    if src_zone == "external" and dst_zone == "internal":
        return "inbound"

    if src_zone == "internal" and dst_zone == "external":
        return "outbound"

    if src_zone == "internal" and dst_zone == "internal":
        return "east_west"

    return "unknown"


# ==========================================================
# NETWORK ZONE
# ==========================================================

def detect_network_zone(src_ip, dst_ip):
    """
    Xác định zone của flow.

    internal
        internal ↔ internal

    external
        external ↔ external

    mixed
        internal ↔ external
    """

    src_zone = detect_zone(src_ip)
    dst_zone = detect_zone(dst_ip)

    if src_zone == "internal" and dst_zone == "internal":
        return "internal"

    if src_zone == "external" and dst_zone == "external":
        return "external"

    return "mixed"

# ==========================================================
# TRAFFIC INTENSITY CALCULATOR
# ==========================================================

def calculate_traffic_intensity(bytes_count, duration):
    """
    Tính cường độ traffic.

    intensity = bytes / duration

    Ví dụ:
        bytes = 5000
        duration = 5

        intensity = 1000
    """

    # nếu thiếu dữ liệu thì không tính
    if bytes_count is None or duration is None:
        return None

    try:

        bytes_count = int(bytes_count)
        duration = float(duration)

        # tránh chia cho 0
        if duration <= 0:
            return None

        intensity = bytes_count / duration

        return round(intensity, 2)

    except Exception:

        return None
    

# ==========================================================
# PAYLOAD SIZE ESTIMATOR
# ==========================================================

def estimate_payload_size(bytes_count, packets):

    if bytes_count is None or packets is None:
        return None

    try:
        bytes_count = int(bytes_count)
        packets = int(packets)

        if packets <= 0:
            return None

        return round(bytes_count / packets, 2)

    except Exception:
        return None
  
# ==========================================================
# GEO LOOKUP
# ==========================================================

def geo_lookup(ip):
    """
    Tra cứu GeoIP.

    Trả về:
        country
        city
    """

    if not ip:
        return None, None

    if detect_zone(ip) == "internal":
        return None, None
    # nếu database không load được
    if geo_reader is None:
        return None, None

    try:

        response = geo_reader.city(ip)

        country = response.country.name
        city = response.city.name

        return country, city

    except Exception:

        # nhiều IP private sẽ lỗi
        return None, None
    
# ==========================================================
# NORMALIZER CONFIDENCE
# ==========================================================

def calculate_normalizer_confidence(data):
    """
    Tính độ tin cậy của normalizer.

    Score dựa trên:
    network context
    traffic metrics
    enrichment
    metadata
    """

    score = 0.0

    # =========================
    # NETWORK BASE
    # =========================

    if data.get("source_ip"):
        score += 0.08

    if data.get("target_ip"):
        score += 0.08

    if data.get("source_port"):
        score += 0.07

    if data.get("target_port"):
        score += 0.07

    # =========================
    # TRAFFIC
    # =========================

    if data.get("bytes") is not None:
        score += 0.05

    if data.get("packets") is not None:
        score += 0.05

    if data.get("payload_size") is not None:
        score += 0.05

    if data.get("traffic_intensity") is not None:
        score += 0.05

    # =========================
    # FLOW CONTEXT
    # =========================

    if data.get("source_zone"):
        score += 0.05

    if data.get("target_zone"):
        score += 0.05

    if data.get("network_zone"):
        score += 0.05

    if data.get("flow_direction"):
        score += 0.05

    # =========================
    # ENRICHMENT
    # =========================

    if data.get("service"):
        score += 0.06

    if data.get("source_country"):
        score += 0.04

    if data.get("target_country"):
        score += 0.04

    if data.get("severity_label"):
        score += 0.03

    if data.get("severity_score"):
        score += 0.03

    # =========================
    # METADATA
    # =========================

    if data.get("log_engine"):
        score += 0.05

    if data.get("sensor"):
        score += 0.05

    return round(score, 2)

# ==========================================================
# BUILD ENRICHED EVENT
# ==========================================================

def build_enriched_event(parsed_log, raw_log=None):

    # =========================
    # EXTRACT PARSER VALUES
    # =========================

    src_ip = parsed_log.get("source_ip")
    dst_ip = parsed_log.get("target_ip")

    src_port = parsed_log.get("source_port")
    dst_port = parsed_log.get("target_port")

    protocol = parsed_log.get("protocol")
    severity = parsed_log.get("severity")

    bytes_count = parsed_log.get("bytes")
    packets = parsed_log.get("packets")
    duration = parsed_log.get("duration")

    # =========================
    # NORMALIZATION
    # =========================

    protocol = normalize_protocol(protocol)

    severity_label, severity_score = normalize_severity(severity)

    service = parsed_log.get("service") or detect_service(dst_port)

    # =========================
    # GEO ENRICHMENT
    # =========================

    src_country, src_city = geo_lookup(src_ip)
    dst_country, dst_city = geo_lookup(dst_ip)

    # =========================
    # NETWORK CONTEXT
    # =========================

    src_zone = detect_zone(src_ip)
    dst_zone = detect_zone(dst_ip)

    flow_direction = detect_flow_direction(src_ip, dst_ip)

    network_zone = detect_network_zone(src_ip, dst_ip)

    # =========================
    # TRAFFIC METRICS
    # =========================

    traffic_intensity = calculate_traffic_intensity(
        bytes_count,
        duration
    )

    payload_size = estimate_payload_size(
        bytes_count,
        packets
    )

    # =========================
    # CLEAN TEXT
    # =========================

    clean_text = ""

    if isinstance(raw_log, str):
        clean_text = raw_log.lower().strip()

    # =========================
    # BUILD RESULT
    # =========================

    result = {

        # network
        "source_ip": src_ip,
        "target_ip": dst_ip,

        "source_port": src_port,
        "target_port": dst_port,

        # protocol/service
        "protocol": protocol,
        "service": service,

        # traffic
        "bytes": bytes_count,
        "packets": packets,
        "duration": duration,

        "payload_size": payload_size,
        "traffic_intensity": traffic_intensity,

        # geo
        "source_country": src_country,
        "source_city": src_city,

        "target_country": dst_country,
        "target_city": dst_city,

        # zone
        "source_zone": src_zone,
        "target_zone": dst_zone,

        # flow
        "flow_direction": flow_direction,
        "network_zone": network_zone,

        # severity
        "severity_label": severity_label,
        "severity_score": severity_score,

        # detection
        "alert_signature": parsed_log.get("alert_signature"),

        # metadata
        "log_engine": parsed_log.get("log_engine"),
        "sensor": parsed_log.get("sensor"),

        # text
        "clean_text": clean_text
    }

    # =========================
    # CONFIDENCE
    # =========================

    result["normalizer_confidence"] = calculate_normalizer_confidence(result)

    return result

# ==========================================================
# NORMALIZE SINGLE LOG
# ==========================================================

def normalize_log(parsed_log, raw_log=None):

    if not parsed_log:
        return {}

    if "error" in parsed_log:
        return parsed_log

    return build_enriched_event(parsed_log, raw_log)

# ==========================================================
# NORMALIZE MULTI LOG
# ==========================================================

def normalize_logs(parsed_logs, raw_logs=None):

    results = []

    for i, parsed in enumerate(parsed_logs):

        if "error" in parsed:
            results.append(parsed)
            continue

        raw = None

        if raw_logs and i < len(raw_logs):
            raw = raw_logs[i]

        enriched = build_enriched_event(parsed, raw)

        results.append(enriched)

    return results

