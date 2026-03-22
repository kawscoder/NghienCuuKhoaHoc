# ==========================================================
# DEFLOG MITRE DATABASE (CORE KNOWLEDGE BASE)
# ==========================================================

MITRE_DB = {

    # ======================================================
    # PORT SCAN
    # ======================================================
    "Port Scan": {
        "tactic": [
            ("TA0007", "Discovery")
        ],
        "technique": {
            "id": "T1046",
            "name": "Network Service Discovery",
            "sub": {
                "default": ("T1046", "Network Service Discovery"),
                "fast_scan": ("T1046.001", "Port Scanning"),
                "wide_scan": ("T1046.002", "Service Enumeration")
            }
        },
        "kill_chain": "Reconnaissance",

        "data_sources": [
            "IDS Alerts",
            "Firewall Logs",
            "Netflow",
            "Packet Capture"
        ],

        "mitigation": [
            ("M1030", "Network Segmentation"),
            ("M1031", "Network Intrusion Prevention"),
            ("M1037", "Filter Network Traffic")
        ]
    },

    # ======================================================
    # DOS / DDOS
    # ======================================================
    "DoS": {
        "tactic": [
            ("TA0040", "Impact")
        ],
        "technique": {
            "id": "T1499",
            "name": "Endpoint Denial of Service",
            "sub": {
                "default": ("T1499", "Endpoint DoS"),
                "flood": ("T1498", "Network Denial of Service"),
                "burst": ("T1499.001", "Service Exhaustion Flood")
            }
        },
        "kill_chain": "Impact",

        "data_sources": [
            "Netflow",
            "Firewall Logs",
            "Load Balancer Logs",
            "System Metrics"
        ],

        "mitigation": [
            ("M1037", "Filter Network Traffic"),
            ("M1030", "Network Segmentation"),
            ("M1046", "Rate Limiting"),
            ("M1050", "Intrusion Prevention System")
        ]
    },

    # ======================================================
    # BRUTE FORCE
    # ======================================================
    "Brute Force": {
        "tactic": [
            ("TA0006", "Credential Access"),
            ("TA0001", "Initial Access")
        ],
        "technique": {
            "id": "T1110",
            "name": "Brute Force",
            "sub": {
                "default": ("T1110", "Brute Force"),
                "guessing": ("T1110.001", "Password Guessing"),
                "stuffing": ("T1110.003", "Credential Stuffing")
            }
        },
        "kill_chain": "Exploitation",

        "data_sources": [
            "Authentication Logs",
            "Web Server Logs",
            "Active Directory Logs"
        ],

        "mitigation": [
            ("M1027", "Password Policies"),
            ("M1032", "Multi-factor Authentication"),
            ("M1036", "Account Lockout")
        ]
    },

    # ======================================================
    # SQL INJECTION
    # ======================================================
    "SQL Injection": {
        "tactic": [
            ("TA0001", "Initial Access")
        ],
        "technique": {
            "id": "T1190",
            "name": "Exploit Public-Facing Application",
            "sub": {
                "default": ("T1190", "Exploit Public App"),
                "sqli": ("T1190.001", "SQL Injection")
            }
        },
        "kill_chain": "Exploitation",

        "data_sources": [
            "Nginx Logs",
            "Apache Logs",
            "WAF Logs",
            "Application Logs"
        ],

        "mitigation": [
            ("M1050", "Web Application Firewall"),
            ("M1048", "Input Validation"),
            ("M1036", "Sanitize Inputs")
        ]
    },

    # ======================================================
    # COMMAND INJECTION
    # ======================================================
    "Command Injection": {
        "tactic": [
            ("TA0002", "Execution")
        ],
        "technique": {
            "id": "T1059",
            "name": "Command and Scripting Interpreter",
            "sub": {
                "default": ("T1059", "Command Execution"),
                "shell": ("T1059.004", "Unix Shell"),
                "webshell": ("T1505.003", "Web Shell")
            }
        },
        "kill_chain": "Execution",

        "data_sources": [
            "Application Logs",
            "System Logs",
            "Audit Logs"
        ],

        "mitigation": [
            ("M1048", "Input Validation"),
            ("M1038", "Execution Prevention"),
            ("M1050", "WAF Protection")
        ]
    },

    # ======================================================
    # SUSPICIOUS
    # ======================================================
    "Suspicious": {
        "tactic": [
            ("TA0005", "Defense Evasion")
        ],
        "technique": {
            "id": "T1027",
            "name": "Obfuscated/Encrypted Payload",
            "sub": {
                "default": ("T1027", "Obfuscation")
            }
        },
        "kill_chain": "Unknown",

        "data_sources": [
            "All Logs",
            "SIEM",
            "IDS"
        ],

        "mitigation": [
            ("M1047", "Behavior Monitoring"),
            ("M1031", "Network Intrusion Detection")
        ]
    },

    # ======================================================
    # NORMAL
    # ======================================================
    "Normal": {
        "tactic": [],
        "technique": {
            "id": "N/A",
            "name": "Benign Traffic",
            "sub": {}
        },
        "kill_chain": "None",

        "data_sources": [],
        "mitigation": []
    }
}

# ==========================================================
# DEFLOG MITRE SUB-TECHNIQUE INFERENCE ENGINE
# ==========================================================

def infer_sub_technique(attack_type: str, flow: dict = None, behavior: dict = None):

    """
    Trả về:
    (sub_technique_id, sub_technique_name, confidence_boost)
    """

    # ======================================================
    # DEFAULT
    # ======================================================

    sub_id = None
    sub_name = None
    confidence_boost = 0.0

    # ======================================================
    # PORT SCAN
    # ======================================================

    if attack_type == "Port Scan":

        if flow:

            # scan nhiều port → wide scan
            if flow.get("multi_port_scan"):
                return ("T1046.002", "Service Enumeration", 0.15)

            # scan nhanh → fast scan
            if flow.get("flow_scan_indicator") and flow.get("flow_packet_rate", 0) > 500:
                return ("T1046.001", "Port Scanning", 0.1)

        if behavior:
            if behavior.get("port_scan"):
                return ("T1046.001", "Port Scanning", 0.1)

        return ("T1046", "Network Service Discovery", 0.05)

    # ======================================================
    # DOS / DDOS
    # ======================================================

    if attack_type == "DoS":

        if flow:

            # burst traffic
            if flow.get("flow_burst_indicator"):
                return ("T1499.001", "Service Exhaustion Flood", 0.15)

            # packet rate cực cao → network flood
            if flow.get("flow_packet_rate", 0) > 30000:
                return ("T1498", "Network Denial of Service", 0.1)

        if behavior:
            if behavior.get("connection_flood"):
                return ("T1498", "Network Flooding", 0.1)

        return ("T1499", "Endpoint Denial of Service", 0.05)

    # ======================================================
    # BRUTE FORCE
    # ======================================================

    if attack_type == "Brute Force":

        if behavior:

            # đoán password liên tục
            if behavior.get("high_attempt_rate"):
                return ("T1110.001", "Password Guessing", 0.15)

            # dùng list credential
            if behavior.get("credential_reuse"):
                return ("T1110.003", "Credential Stuffing", 0.15)

        return ("T1110", "Brute Force", 0.05)

    # ======================================================
    # SQL INJECTION
    # ======================================================

    if attack_type == "SQL Injection":

        if behavior:
            if behavior.get("payload_injection"):
                return ("T1190.001", "SQL Injection", 0.15)

        return ("T1190", "Exploit Public Application", 0.05)

    # ======================================================
    # COMMAND INJECTION
    # ======================================================

    if attack_type == "Command Injection":

        if behavior:

            if behavior.get("shell_execution"):
                return ("T1059.004", "Unix Shell", 0.15)

            if behavior.get("webshell_detected"):
                return ("T1505.003", "Web Shell", 0.15)

        return ("T1059", "Command Execution", 0.05)

    # ======================================================
    # SUSPICIOUS
    # ======================================================

    if attack_type == "Suspicious":

        if flow:
            if flow.get("flow_small_payload_indicator"):
                return ("T1027", "Obfuscated Payload", 0.1)

        return ("T1027", "Obfuscation", 0.05)

    # ======================================================
    # NORMAL / UNKNOWN
    # ======================================================

    return (None, None, 0.0)

# ==========================================================
# DEFLOG MITRE ENRICHMENT ENGINE
# ==========================================================

def calculate_detection_priority(attack_type, flow=None, behavior=None, ml=None):

    # ======================================================
    # BASE PRIORITY (QUAN TRỌNG NHẤT)
    # ======================================================

    base_priority = {
        "DoS": 3,
        "Brute Force": 3,
        "SQL Injection": 3,
        "Command Injection": 3,
        "Port Scan": 2,
        "Suspicious": 2,
        "Normal": 0
    }

    score = base_priority.get(attack_type, 1)

    # ======================================================
    # FLOW SIGNAL
    # ======================================================

    if flow:
        if flow.get("flow_risk_score", 0) > 0.8:
            score += 2
        elif flow.get("flow_risk_score", 0) > 0.5:
            score += 1

        if flow.get("flow_burst_indicator"):
            score += 1

        if flow.get("flow_scan_indicator"):
            score += 1

    # ======================================================
    # BEHAVIOR SIGNAL
    # ======================================================

    if behavior:
        if behavior.get("connection_flood"):
            score += 2
        if behavior.get("port_scan"):
            score += 1

    # ======================================================
    # ML CONFIDENCE
    # ======================================================

    if ml:
        conf = ml.get("confidence_ml", 0)
        if conf > 0.9:
            score += 1

    # ======================================================
    # FINAL
    # ======================================================

    if score >= 5:
        return "High"
    elif score >= 3:
        return "Medium"
    else:
        return "Low"
    
# ==========================================================
# DATA SOURCE SELECTOR
# ==========================================================

def get_data_sources(mitre_db_entry):

    """
    Trả về list data sources từ DB
    """

    return mitre_db_entry.get("data_sources", [])


# ==========================================================
# MITIGATION BUILDER
# ==========================================================

def build_mitigation(mitre_db_entry):

    """
    Convert mitigation tuples → dict chuẩn UI
    """

    result = []

    for mid, name in mitre_db_entry.get("mitigation", []):
        result.append({
            "id": mid,
            "name": name,
            "reference": f"https://attack.mitre.org/mitigations/{mid}"
        })

    return result


# ==========================================================
# MITRE CONFIDENCE SCORING
# ==========================================================

def calculate_mitre_confidence(flow=None, behavior=None, sub_boost=0.0):

    """
    Confidence riêng của MITRE mapping
    """

    score = 0.6  # base

    # ======================================================
    # FLOW
    # ======================================================

    if flow:
        risk = flow.get("flow_risk_score", 0)

        if risk > 0.7:
            score += 0.15
        elif risk > 0.4:
            score += 0.1

    # ======================================================
    # BEHAVIOR
    # ======================================================

    if behavior:
        if behavior.get("port_scan"):
            score += 0.1
        if behavior.get("connection_flood"):
            score += 0.1

    # ======================================================
    # SUB-TECHNIQUE BOOST
    # ======================================================

    score += sub_boost

    return round(min(score, 1.0), 2)

# ==========================================================
# MAIN FUNCTION
# ==========================================================

def map_to_mitre(attack_type: str, flow=None, behavior=None, ml=None):

    base = MITRE_DB.get(attack_type)

    # ======================================================
    # FALLBACK
    # ======================================================

    if not base:
        return {
            "mitre": {
                "tactic": {
                    "id": [],
                    "name": [],
                    "description": "Unknown behavior"
                },
                "technique": {
                    "id": "N/A",
                    "name": "Unknown",
                    "sub_technique_id": None,
                    "sub_technique_name": None,
                    "reference": None
                },
                "detection_priority": "Low",
                "data_sources": [],
                "mitigation": [],
                "mapping_confidence": 0.3,
                "kill_chain_phase": "Unknown"
            }
        }

    # ======================================================
    # 1. TACTIC BUILD
    # ======================================================

    tactic_ids = [t[0] for t in base["tactic"]]
    tactic_names = [t[1] for t in base["tactic"]]

    description = _build_tactic_description(tactic_names)

    # ======================================================
    # 2. SUB-TECHNIQUE INFERENCE
    # ======================================================

    sub_id, sub_name, boost = infer_sub_technique(
        attack_type,
        flow,
        behavior
    )

    tech = base["technique"]

    technique_id = tech["id"]
    technique_name = tech["name"]

    # fallback nếu không có sub
    if not sub_id:
        sub_id = None
        sub_name = None

    # ======================================================
    # 3. DATA SOURCES
    # ======================================================

    data_sources = get_data_sources(base)

    # ======================================================
    # 4. MITIGATION
    # ======================================================

    mitigation = build_mitigation(base)

    # ======================================================
    # 5. DETECTION PRIORITY
    # ======================================================

    priority = calculate_detection_priority(attack_type, flow, behavior, ml)

    # ======================================================
    # 6. CONFIDENCE
    # ======================================================

    confidence = calculate_mitre_confidence(flow, behavior, boost)

    # ======================================================
    # 7. FINAL OUTPUT
    # ======================================================

    return {
        "mitre": {
            "tactic": {
                "id": tactic_ids,
                "name": tactic_names,
                "description": description
            },
            "technique": {
                "id": technique_id,
                "name": technique_name,
                "sub_technique_id": sub_id,
                "sub_technique_name": sub_name,
                "reference": f"https://attack.mitre.org/techniques/{technique_id}"
            },
            "detection_priority": priority,
            "data_sources": data_sources,
            "mitigation": mitigation,
            "mapping_confidence": confidence,
            "kill_chain_phase": base["kill_chain"]
        }
    }


# ==========================================================
# HELPER
# ==========================================================

def _build_tactic_description(tactics):

    if "Credential Access" in tactics:
        return "Attacker is attempting to obtain account credentials."

    if "Discovery" in tactics:
        return "Attacker is gathering information about the system."

    if "Impact" in tactics:
        return "Attacker is attempting to disrupt system availability."

    if "Execution" in tactics:
        return "Attacker is executing malicious commands."

    if "Initial Access" in tactics:
        return "Attacker is trying to gain initial foothold."

    return "General suspicious behavior detected."