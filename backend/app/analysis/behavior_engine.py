
from collections import defaultdict
from datetime import datetime
import math

# ==========================================================
# CONFIG
# ==========================================================

CONFIG = {
    "TIME_WINDOW": 60,
    "PORT_SCAN_THRESHOLD": 8,
    "CONNECTION_THRESHOLD": 40,
    "DOS_PACKET_RATE": 800,
    "SLOW_SCAN_INTERVAL": 5,
}

SENSITIVE_SERVICES = ["SSH", "RDP", "SMB"]

# ==========================================================
# STATE
# ==========================================================

class BehaviorState:

    def __init__(self):
        self.ip_ports = defaultdict(list)
        self.ip_connections = defaultdict(list)

    def parse_time(self, ts):
        try:
            return datetime.fromisoformat(str(ts))
        except:
            return datetime.utcnow()

    def clean(self, items, now):
        return [
            item for item in items
            if (now - item[-1]).total_seconds() <= CONFIG["TIME_WINDOW"]
        ]

    def update(self, src_ip, dst_port, timestamp):

        now = self.parse_time(timestamp)

        # =========================
        # RESET nếu gap lớn (FIX ĐÚNG)
        # =========================
        if src_ip and self.ip_connections[src_ip]:
            last_time = self.ip_connections[src_ip][-1]

            if (now - last_time).total_seconds() > CONFIG["TIME_WINDOW"]:
                self.ip_ports[src_ip] = []
                self.ip_connections[src_ip] = []

        # =========================
        # UPDATE PORTS
        # =========================
        if src_ip and dst_port:
            self.ip_ports[src_ip].append((dst_port, now))
            self.ip_ports[src_ip] = self.clean(self.ip_ports[src_ip], now)

        # =========================
        # UPDATE CONNECTIONS
        # =========================
        if src_ip:
            self.ip_connections[src_ip].append(now)
            self.ip_connections[src_ip] = [
                t for t in self.ip_connections[src_ip]
                if (now - t).total_seconds() <= CONFIG["TIME_WINDOW"]
            ]

        return now

# ==========================================================
# FEATURE ENGINEERING
# ==========================================================

def compute_entropy(values):

    if not values:
        return 0

    freq = defaultdict(int)
    for v in values:
        freq[v] += 1

    total = len(values)

    entropy = 0
    for count in freq.values():
        p = count / total
        entropy -= p * math.log2(p)

    return entropy


def extract_features(state, src_ip):

    ports_data = state.ip_ports.get(src_ip, [])
    connections = state.ip_connections.get(src_ip, [])

    ports = [p for p, _ in ports_data]
    times = [t for _, t in ports_data]

    unique_ports = len(set(ports))
    connection_count = len(connections)

    conn_rate = connection_count / CONFIG["TIME_WINDOW"]

    intervals = [
        (times[i+1] - times[i]).total_seconds()
        for i in range(len(times)-1)
    ]

    avg_interval = sum(intervals)/len(intervals) if intervals else 0

    burst = any(i < 0.2 for i in intervals) if intervals else False

    entropy = compute_entropy(ports)

    port_growth_rate = unique_ports / max(connection_count, 1)

    repeat_ratio = 1 - port_growth_rate

    scan_consistency = sum(
        1 for i in intervals if i < 2
    ) / max(len(intervals), 1)

    time_span = (
        (times[-1] - times[0]).total_seconds()
        if len(times) > 1 else 0
    )

    attack_velocity = (
        unique_ports / time_span
        if time_span > 1 else 0
    )

    stability = 1 / (avg_interval + 1)

    # 🔥 NEW FEATURE
    acceleration = attack_velocity / (avg_interval + 1)

    return {
        "unique_ports": unique_ports,
        "connection_count": connection_count,
        "conn_rate": round(conn_rate, 3),
        "avg_interval": round(avg_interval, 3),
        "burst": burst,
        "entropy": round(entropy, 3),

        "port_growth_rate": round(port_growth_rate, 3),
        "repeat_ratio": round(repeat_ratio, 3),
        "scan_consistency": round(scan_consistency, 3),
        "time_span": round(time_span, 2),
        "attack_velocity": round(attack_velocity, 3),
        "stability": round(stability, 3),
        "acceleration": round(acceleration, 3),

        "ports_sequence": ports,
        "timestamps": times
    }

# ==========================================================
# PATTERN DETECTION
# ==========================================================

def detect_pattern(features):
    
    ports = features["ports_sequence"]
    entropy = features["entropy"]
    avg_interval = features["avg_interval"]

    if features["conn_rate"] > 0.3:
        return "flood"
    
    if len(ports) < 3:
        return "none"

    diffs = [ports[i+1] - ports[i] for i in range(len(ports)-1)]

    # 🔥 FIX: cần đủ dữ liệu mới kết luận linear
    if len(diffs) >= 4 and all(abs(d) <= 2 for d in diffs):
        return "linear_scan"

    # random
    if entropy > 2.5 and features["scan_consistency"] > 0.7:
        return "random_scan"

    # slow scan
    if avg_interval > CONFIG["SLOW_SCAN_INTERVAL"]:
        return "slow_scan"

    # hybrid
    if entropy > 1.5 and avg_interval < 2:
        return "hybrid_scan"

    return "unknown"

# ==========================================================
# CONTEXT
# ==========================================================

def build_behavior_context(event):

    src_zone = event.get("source_zone")
    dst_zone = event.get("target_zone")
    service = event.get("service")

    return {
        "internal_target": dst_zone == "internal",
        "lateral_movement": src_zone == "internal" and dst_zone == "internal",
        "sensitive_service": service in SENSITIVE_SERVICES
    }

# ==========================================================
# DETECTION
# ==========================================================

def detect_behavior(features, flow, multi_flags):

    packet_rate = flow.get("flow_packet_rate", 0) if flow else 0

    return {

        # 🔥 FIX: kết hợp FLOW + FEATURE + KEYWORD
        "port_scan": (
            features["unique_ports"] >= CONFIG["PORT_SCAN_THRESHOLD"]
            or (flow and flow.get("flow_scan_indicator"))
            or features.get("scan_strength", 0) >= 2
        ),

        "connection_flood": (
            features["conn_rate"] > 0.2 and features["burst"]
        ),

        "dos": packet_rate >= CONFIG["DOS_PACKET_RATE"]
    }

# ==========================================================
# CONFIDENCE
# ==========================================================

def compute_confidence(behavior, features, pattern, multi_flags, flow=None):

    score = 0

    # ======================================================
    # 1. BEHAVIOR SIGNAL
    # ======================================================
    if behavior.get("port_scan"):
        score += 0.8

    if behavior.get("connection_flood"):
        score += 0.7

    if behavior.get("dos"):
        score += 1

    # ======================================================
    # 2. PATTERN
    # ======================================================
    if pattern not in ["none", "unknown"]:
        score += 0.5

    # ======================================================
    # 3. FLOW (CORE SIGNAL)
    # ======================================================
    if flow:
        if flow.get("flow_scan_indicator"):
            score += 0.8

        if flow.get("flow_burst_indicator"):
            score += 0.5

        score += min(flow.get("flow_risk_score", 0), 0.5)

    # ======================================================
    # 4. FEATURE STRENGTH
    # ======================================================
    scan_strength = features.get("scan_strength", 0)

    if scan_strength >= 2:
        score += 0.5
    if scan_strength >= 3:
        score += 0.5

    if features.get("dos_strength", 0) >= 2:
        score += 0.6

    # ======================================================
    # 5. MULTI FLOW
    # ======================================================
    if multi_flags:
        if multi_flags.get("multi_port_scan"):
            score += 1
        if multi_flags.get("multi_dos"):
            score += 1

    # ======================================================
    # 6. SMART BOOST
    # ======================================================
    if (
        flow and flow.get("flow_scan_indicator")
        and scan_strength >= 2
    ):
        score += 0.5  # 🔥 combo boost

    # ======================================================
    # NORMALIZE (FIX QUAN TRỌNG)
    # ======================================================
    confidence = score / 3   # 🔥 trước là /4 → sai

    return round(min(confidence, 1.0), 2)

# ==========================================================
# SCORING
# ==========================================================

def compute_score(behavior, context, pattern, features, flow=None):

    score = 0

    # ======================================================
    # 1. DoS
    # ======================================================
    if behavior.get("dos"):
        score += 0.6 + min(features.get("conn_rate", 0), 0.3)

    # ======================================================
    # 2. PORT SCAN (STRONG SIGNAL)
    # ======================================================
    if (
        behavior.get("port_scan") or
        (flow and flow.get("flow_scan_indicator")) or
        features.get("scan_strength", 0) >= 2
    ):
        score += 0.3

    # ======================================================
    # 3. PATTERN
    # ======================================================
    if pattern == "random_scan":
        score += 0.3
    elif pattern == "linear_scan":
        score += 0.2
    elif pattern == "hybrid_scan":
        score += 0.4
    elif pattern == "slow_scan":
        score += 0.2

    # ======================================================
    # 4. CONTEXT
    # ======================================================
    if context.get("internal_target"):
        score += 0.2

    if context.get("sensitive_service"):
        score += 0.2

    # ======================================================
    # 5. FLOW RISK
    # ======================================================
    if flow:
        score += min(flow.get("flow_risk_score", 0), 0.3)

    # ======================================================
    # 6. FALSE POSITIVE CONTROL
    # ======================================================
    if features.get("connection_count", 0) <= 2:
        score = min(score, 0.5)

    return max(0, min(round(score, 2), 1.0))

# ==========================================================
# CLASSIFICATION
# ==========================================================

def classify_attack(behavior, pattern, flow, features):

    # 🔥 chỉ trust flow nếu có strength
    if (
        flow.get("flow_scan_indicator")
        and features.get("scan_strength", 0) >= 2
    ):
        return f"Port Scan ({pattern})"

    if behavior.get("dos"):
        return "DoS"

    if behavior.get("port_scan"):
        return f"Scan ({pattern})"

    if behavior.get("connection_flood"):
        return "Flood"

    return "Normal"

def classify_label(score, behavior):

    if behavior.get("dos"):
        return "critical"

    if score >= 0.8:
        return "critical"
    elif score >= 0.6:
        return "high"
    elif score >= 0.3:
        return "medium"
    return "low"

# ==========================================================
# MAIN PIPELINE
# ==========================================================

def analyze_behavior_engine(event, flow, multi_flags, state):

    src_ip = event.get("source_ip")
    dst_port = event.get("target_port")
    timestamp = event.get("timestamp")

    state.update(src_ip, dst_port, timestamp)

    features = extract_features(state, src_ip)

    pattern = detect_pattern(features)

    context = build_behavior_context(event)

    behavior = detect_behavior(features, flow, multi_flags)

    score = compute_score(behavior, context, pattern, features, flow)

    confidence = compute_confidence(
        behavior, features, pattern, multi_flags, flow
    )

    attack_type = classify_attack(behavior, pattern, flow, features)

    label = classify_label(score, behavior)

    return {
        "attack_type": attack_type,
        "behavior_score": score,
        "behavior_label": label,
        "confidence": confidence,
        "pattern": pattern,
        "context": context,
        "features": features,
        "flags": behavior
    }