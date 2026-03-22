"""
DefLog Flow Builder

Module: Flow Identity & Statistics Layer

Chức năng:
- Xây dựng định danh flow (flow_key, flow_id)
- Khởi tạo thống kê flow
- Quản lý thời gian flow (first_seen, last_seen)
"""

import hashlib
from datetime import datetime

from app.config import Config

FLOW_TIMEOUT = Config.FLOW_TIMEOUT
# ==========================================================
# FLOW KEY (2-WAY NORMALIZATION)
# ==========================================================

def build_flow_key(event):

    src_ip = event.get("source_ip") or "0.0.0.0"
    dst_ip = event.get("target_ip") or "0.0.0.0"

    src_port = event.get("source_port") or 0
    dst_port = event.get("target_port") or 0

    protocol = event.get("protocol") or "UNK"

    src = (str(src_ip), int(src_port))
    dst = (str(dst_ip), int(dst_port))

    # normalize safe compare
    if src <= dst:
        a, b = src, dst
    else:
        a, b = dst, src

    return f"{a[0]}:{a[1]}-{b[0]}:{b[1]}-{protocol}"

# ==========================================================
# FLOW ID (HASH)
# ==========================================================

def generate_flow_id(flow_key):
    """
    Sinh flow_id từ flow_key.

    Sử dụng blake2b:
    - nhanh
    - collision thấp
    """

    if not flow_key:
        return None

    return hashlib.blake2b(flow_key.encode()).hexdigest()


# ==========================================================
# BUILD FLOW IDENTITY
# ==========================================================

def build_flow_identity(event):
    """
    Tạo identity cho flow.

    Output:
    - flow_key
    - flow_id
    """

    flow_key = build_flow_key(event)
    flow_id = generate_flow_id(flow_key)

    return {
        "flow_key": flow_key,
        "flow_id": flow_id
    }


# ==========================================================
# FLOW STATISTICS (INIT)
# ==========================================================

def build_flow_statistics(event):
    """
    Khởi tạo thống kê flow từ event đầu tiên.

    Lưu ý:
    - duration KHÔNG lấy từ event
    - sẽ tính sau dựa trên thời gian thực
    """

    packets = event.get("packets") or 0
    bytes_count = event.get("bytes") or 0

    return {

        # số event trong flow
        "flow_event_count": 1,

        # tổng packets
        "flow_packets_total": packets,

        # tổng bytes
        "flow_bytes_total": bytes_count,

        # duration sẽ cập nhật sau
        "flow_duration": 0
    }


# ==========================================================
# FLOW TIME CONTEXT
# ==========================================================

def build_flow_time_context(event):
    """
    Khởi tạo thông tin thời gian của flow.

    Bao gồm:
    - dạng string (hiển thị)
    - dạng timestamp (tính toán)
    """

    timestamp = event.get("timestamp")

    if timestamp:
        try:
            ts = datetime.fromisoformat(str(timestamp))
        except Exception:
            ts = datetime.utcnow()
    else:
        ts = datetime.utcnow()

    return {

        # hiển thị
        "flow_first_seen": ts.strftime("%Y-%m-%d %H:%M:%S"),
        "flow_last_seen": ts.strftime("%Y-%m-%d %H:%M:%S"),

        # tính toán
        "flow_first_seen_ts": ts.timestamp(),
        "flow_last_seen_ts": ts.timestamp()
    }

"""
DefLog Flow Builder

Module: Flow Update & Behavior Analysis Layer

Chức năng:
- Cập nhật flow theo event mới
- Tính duration thực tế
- Phân tích hành vi (rate, scan, burst)
"""

from datetime import datetime


# ==========================================================
# UPDATE FLOW
# ==========================================================

def update_flow(flow, event):
    """
    Cập nhật flow với event mới.

    Bao gồm:
    - cộng dồn packets / bytes
    - cập nhật last_seen
    - tính lại duration
    """

    packets = event.get("packets") or 0
    bytes_count = event.get("bytes") or 0

    # =========================
    # UPDATE THỐNG KÊ
    # =========================

    flow["flow_event_count"] += 1
    flow["flow_packets_total"] += packets
    flow["flow_bytes_total"] += bytes_count

    # =========================
    # UPDATE THỜI GIAN
    # =========================

    timestamp = event.get("timestamp")

    if timestamp:
        try:
            ts = datetime.fromisoformat(str(timestamp))
        except Exception:
            ts = datetime.utcnow()
    else:
        ts = datetime.utcnow()

    ts_value = ts.timestamp()

    # cập nhật last seen
    flow["flow_last_seen_ts"] = ts_value
    flow["flow_last_seen"] = ts.strftime("%Y-%m-%d %H:%M:%S")

    # =========================
    # TÍNH DURATION
    # =========================

    flow["flow_duration"] = round(
        flow["flow_last_seen_ts"] - flow["flow_first_seen_ts"],
        2
    )

    return flow


# ==========================================================
# FLOW BEHAVIOR METRICS
# ==========================================================

def build_flow_behavior(flow):
    """
    Phân tích hành vi flow (improved version)
    """

    packets = flow.get("flow_packets_total") or 0
    bytes_total = flow.get("flow_bytes_total") or 0
    duration = flow.get("flow_duration") or 0

    event_count = flow.get("flow_event_count", 1)

    # =========================
    # FIX 1: duration tối thiểu
    # =========================

    if duration < 1:
        duration = 1

    # =========================
    # RATE
    # =========================

    packet_rate = packets / duration
    byte_rate = bytes_total / duration

    # =========================
    # AVG PACKET SIZE
    # =========================

    avg_packet_size = (bytes_total / packets) if packets > 0 else 0

    # =========================
    # INDICATORS
    # =========================

    small_payload = avg_packet_size < 120 if packets > 0 else False

    # 🔥 FIX 2: threshold thực tế hơn
    burst_indicator = packet_rate > 300

    scan_indicator = small_payload and packet_rate > 30

    # 🔥 FIX 3: cần đủ event mới detect
    if event_count < 3:
        scan_indicator = False
        burst_indicator = False

    return {
        "flow_packet_rate": round(packet_rate, 2),
        "flow_byte_rate": round(byte_rate, 2),
        "flow_avg_packet_size": round(avg_packet_size, 2),

        "flow_small_payload_indicator": small_payload,
        "flow_burst_indicator": burst_indicator,
        "flow_scan_indicator": scan_indicator
    }

"""
DefLog Flow Builder

Module: Flow Context & Risk Scoring Layer

Chức năng:
- Phân tích ngữ cảnh mạng (zone, attack surface)
- Tính điểm nguy hiểm (risk_score)
- Gán nhãn mức độ (low → critical)
- Tính confidence cho flow
"""

# ==========================================================
# FLOW CONTEXT ENGINE
# ==========================================================

def build_flow_context(event, behavior, multi_flags=None):

    src_zone = event.get("source_zone")
    dst_zone = event.get("target_zone")
    service = event.get("service")

    burst = behavior.get("flow_burst_indicator")
    scan = behavior.get("flow_scan_indicator")

    multi_scan = False
    multi_dos = False

    if multi_flags:
        multi_scan = multi_flags.get("multi_port_scan")
        multi_dos = multi_flags.get("multi_dos")

    # =========================
    # ZONE
    # =========================

    if src_zone == "internal" and dst_zone == "external":
        zone_type = "internal_external"
    elif src_zone == "external" and dst_zone == "internal":
        zone_type = "external_internal"
    elif src_zone == "internal" and dst_zone == "internal":
        zone_type = "internal_internal"
    else:
        zone_type = "unknown"

    mapping = {
        "external_internal": "ingress",
        "internal_external": "egress",
        "internal_internal": "lateral"
    }

    attack_surface = mapping.get(zone_type, "unknown")

    # =========================
    # RISK SCORE (UPGRADE)
    # =========================

    risk_score = 0.0

    # single behavior
    if scan:
        risk_score += 0.3

    if burst:
        risk_score += 0.3

    # 🔥 MULTI-FLOW (QUAN TRỌNG)
    if multi_scan:
        risk_score += 0.5

    if multi_dos:
        risk_score += 0.6

    # ingress nguy hiểm hơn
    if attack_surface == "ingress":
        risk_score += 0.2

    # service nhạy cảm
    if service in ["SSH", "RDP", "SMB"]:
        risk_score += 0.2

    risk_score = min(risk_score, 1.0)

    # =========================
    # LABEL
    # =========================

    if risk_score >= 0.8:
        label = "critical"
    elif risk_score >= 0.6:
        label = "high"
    elif risk_score >= 0.3:
        label = "medium"
    else:
        label = "low"

    return {
        "flow_risk_score": round(risk_score, 2),
        "flow_risk_label": label,
        "flow_attack_surface": attack_surface
    }

# ==========================================================
# FLOW CONFIDENCE
# ==========================================================

def compute_flow_confidence(behavior, context):
    """
    Tính độ tin cậy của flow detection.

    Kết hợp:
    - behavior (scan, burst)
    - context (risk)
    """

    score = 0.4

    # behavior
    if behavior.get("flow_scan_indicator"):
        score += 0.3

    if behavior.get("flow_burst_indicator"):
        score += 0.2

    # context risk
    if context.get("flow_risk_score", 0) > 0.5:
        score += 0.1

    return round(min(score, 1.0), 2)

"""
DefLog Flow Builder

Module: Flow Engine & Multi-Flow Detection Layer

Chức năng:
- Quản lý toàn bộ flow (flow manager)
- Detect tấn công dựa trên nhiều flow
- Phân loại attack
- Xuất kết quả cuối
"""

from datetime import datetime


# ==========================================================
# FLOW STORAGE
# ==========================================================

flows = {}

# ==========================================================
# FLOW MANAGER (CREATE / UPDATE)
# ==========================================================

def process_event(event):
    """
    Xử lý 1 event đầu vào.

    Pipeline:
    event → flow → behavior → context → multi-detect → output
    """

    identity = build_flow_identity(event)
    key = identity["flow_key"]

    # =========================
    # CREATE FLOW
    # =========================

    if key not in flows:

        flow = {
            **identity,
            **build_flow_statistics(event),
            **build_flow_time_context(event)
        }

        flows[key] = flow

    # =========================
    # UPDATE FLOW
    # =========================

    else:
        flow = update_flow(flows[key], event)

    # =========================
    # BEHAVIOR
    # =========================

    behavior = build_flow_behavior(flow)

    # 🔥 ADD SEMANTIC DETECTION
    signature = (event.get("alert_signature") or "").lower()
    service = (event.get("service") or "").lower()

    if "scan" in signature or "nmap" in service:
        behavior["flow_scan_indicator"] = True

    # ==========================================================
    # 🔥 SEMANTIC SCAN DETECTION (VERY IMPORTANT)
    # ==========================================================

    signature = (event.get("alert_signature") or "").lower()
    service = (event.get("service") or "").lower()

    if "scan" in signature or "nmap" in service:
        behavior["flow_scan_indicator"] = True

    # =========================
    # MULTI-FLOW DETECTION
    # =========================

    multi_flags = detect_multi_flow_attacks(flows, event)

    # =========================
    # CONTEXT
    # =========================

    context = build_flow_context(event, behavior, multi_flags)

    # =========================
    # CONFIDENCE
    # =========================

    confidence = compute_flow_confidence(behavior, context)

    # =========================
    # MERGE RESULT
    # =========================

    result = {
        **flow,
        **behavior,
        **context,
        **multi_flags,
        "flow_confidence": confidence
    }

    return result


# ==========================================================
# FLOW EXPIRE (GIẢI PHÓNG MEMORY)
# ==========================================================

def expire_flows():
    """
    Xóa flow không hoạt động.

    Giúp:
    - tránh memory leak
    - giống hệ thống SIEM thật
    """

    now = datetime.utcnow().timestamp()

    keys_to_delete = []

    for key, flow in flows.items():

        last_seen = flow.get("flow_last_seen_ts", now)

        if now - last_seen > FLOW_TIMEOUT:
            keys_to_delete.append(key)

    for key in keys_to_delete:
        del flows[key]


# ==========================================================
# MULTI-FLOW DETECTION
# ==========================================================

def detect_multi_flow_attacks(flows, event):
    """
    Phát hiện tấn công dựa trên nhiều flow.

    Ví dụ:
    - scan nhiều port
    - DoS
    - lateral movement
    """

    src_ip = event.get("source_ip")

    unique_ports = set()
    total_packets = 0
    flow_count = 0

    for f in flows.values():

        if src_ip and f.get("flow_key", "").split(":")[0] == src_ip:

            flow_count += 1
            total_packets += f.get("flow_packets_total", 0)

            try:
                dst_part = f["flow_key"].split("-")[1]
                port = dst_part.split(":")[1]
                unique_ports.add(port)
            except:
                pass

    # =========================
    # DETECTION RULES
    # =========================

    port_scan = len(unique_ports) > 10

    dos_attack = total_packets > 2000

    lateral_movement = flow_count > 15

    return {

        "multi_port_scan": port_scan,
        "multi_dos": dos_attack,
        "multi_lateral": lateral_movement
    }


# ==========================================================
# ATTACK CLASSIFICATION
# ==========================================================

def classify_attack(flow_result):
    """
    Phân loại loại tấn công.
    """

    if flow_result.get("multi_dos"):
        return "DoS"

    if flow_result.get("multi_port_scan"):
        return "Port Scan"

    if flow_result.get("multi_lateral"):
        return "Lateral Movement"

    if flow_result.get("flow_scan_indicator"):
        return "Scan (single flow)"

    if flow_result.get("flow_burst_indicator"):
        return "Traffic Burst"

    return "Normal"


# ==========================================================
# FINAL OUTPUT
# ==========================================================

def build_final_output(result):
    """
    Chuẩn hóa output cho:
    - API
    - dashboard
    - báo cáo
    """

    attack_type = classify_attack(result)

    return {

        "flow_id": result.get("flow_id"),
        "attack_type": attack_type,

        "severity": result.get("flow_risk_label"),
        "risk_score": result.get("flow_risk_score"),

        "confidence": result.get("flow_confidence"),

        "indicators": {
            "scan": result.get("flow_scan_indicator"),
            "burst": result.get("flow_burst_indicator"),
            "multi_scan": result.get("multi_port_scan"),
            "multi_dos": result.get("multi_dos")
        }
    }


# ==========================================================
# RUN ENGINE (MULTI EVENT)
# ==========================================================

def run_engine(events):
    """
    Chạy engine với nhiều event.

    Input:
        list event

    Output:
        list kết quả phân tích
    """

    outputs = []

    for event in events:

        result = process_event(event)

        final = build_final_output(result)

        outputs.append(final)

        expire_flows()

    return outputs

