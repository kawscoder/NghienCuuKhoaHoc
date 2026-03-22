def extract_features(event, flow, behavior=None):

    features = {}

    # ======================================================
    # 1. FLOW METRICS
    # ======================================================
    features["packet_rate"] = flow.get("flow_packet_rate", 0)
    features["byte_rate"] = flow.get("flow_byte_rate", 0)
    features["avg_packet_size"] = flow.get("flow_avg_packet_size", 0)

    # normalize (VERY IMPORTANT for ML)
    features["packet_rate_log"] = round(
        __safe_log(features["packet_rate"]), 3
    )
    features["byte_rate_log"] = round(
        __safe_log(features["byte_rate"]), 3
    )

    # ======================================================
    # 2. FLOW PATTERN
    # ======================================================
    features["scan"] = int(flow.get("flow_scan_indicator", False))
    features["burst"] = int(flow.get("flow_burst_indicator", False))

    # ======================================================
    # 3. MULTI FLOW
    # ======================================================
    features["multi_scan"] = int(flow.get("multi_port_scan", False))
    features["multi_dos"] = int(flow.get("multi_dos", False))
    features["multi_lateral"] = int(flow.get("multi_lateral", False))

    # ======================================================
    # 4. RISK
    # ======================================================
    features["risk_score"] = flow.get("flow_risk_score", 0)

    # ======================================================
    # 5. NETWORK CONTEXT
    # ======================================================
    src_zone = event.get("source_zone")
    dst_zone = event.get("target_zone")

    features["is_internal_src"] = int(src_zone == "internal")
    features["is_internal_dst"] = int(dst_zone == "internal")

    features["is_external"] = int(
        features["is_internal_src"] == 0 or features["is_internal_dst"] == 0
    )

    # 🔥 VERY IMPORTANT (SOC logic)
    attack_surface = flow.get("flow_attack_surface", "unknown")

    features["is_ingress"] = int(attack_surface == "ingress")
    features["is_egress"] = int(attack_surface == "egress")
    features["is_lateral"] = int(attack_surface == "lateral")

    # ======================================================
    # 6. PORT FEATURES
    # ======================================================
    port = event.get("target_port")

    if isinstance(port, int):
        features["target_port"] = port
        features["is_sensitive_port"] = int(port in [21, 22, 23, 25, 3389, 445])
    else:
        features["target_port"] = 0
        features["is_sensitive_port"] = 0

    # ======================================================
    # 7. PROTOCOL & SERVICE
    # ======================================================
    protocol = (event.get("protocol") or "UNK").upper()
    service = (event.get("service") or "UNK").upper()

    features["is_tcp"] = int(protocol == "TCP")
    features["is_udp"] = int(protocol == "UDP")

    # 🔥 semantic service
    features["is_nmap"] = int("NMAP" in service)
    features["is_http"] = int("HTTP" in service)
    features["is_ssh"] = int("SSH" in service)

    # ======================================================
    # 8. SEMANTIC (VERY IMPORTANT)
    # ======================================================
    signature = (event.get("alert_signature") or "").lower()

    features["has_scan_keyword"] = int("scan" in signature)
    features["has_bruteforce_keyword"] = int("brute" in signature)
    features["has_exploit_keyword"] = int("exploit" in signature)

    # ======================================================
    # 9. BEHAVIOR FEATURES
    # ======================================================
    if behavior:
        bf = behavior.get("features", {})

        features["unique_ports"] = bf.get("unique_ports", 0)
        features["conn_rate"] = bf.get("conn_rate", 0)
        features["entropy"] = bf.get("entropy", 0)
        features["repeat_ratio"] = bf.get("repeat_ratio", 0)
        features["scan_consistency"] = bf.get("scan_consistency", 0)

    else:
        features["unique_ports"] = 0
        features["conn_rate"] = 0
        features["entropy"] = 0
        features["repeat_ratio"] = 0
        features["scan_consistency"] = 0

    # ======================================================
    # 10. DERIVED FEATURES
    # ======================================================
    features["is_high_traffic"] = int(features["packet_rate"] > 1000)
    features["is_large_transfer"] = int(features["byte_rate"] > 100000)

    # 🔥 COMPOSITE FEATURES (RẤT QUAN TRỌNG)
    features["scan_strength"] = round(
        features["scan"]
        + features["multi_scan"]
        + features["has_scan_keyword"]
        + features["is_nmap"],
        2
    )

    features["dos_strength"] = round(
        features["burst"]
        + features["multi_dos"]
        + features["is_high_traffic"],
        2
    )

    return features


# ======================================================
# SAFE LOG FUNCTION
# ======================================================

import math

def __safe_log(x):
    if x <= 0:
        return 0
    return math.log(x)