# ==========================================================
# DEFLOG LLM ANALYZER - FINAL VERSION (PRO MAX)
# ==========================================================


# ==========================================================
# BUILD CONTEXT
# ==========================================================

def build_context(data: dict):
    """
    Chuẩn hóa dữ liệu đầu vào cho LLM analyzer
    """

    return {
        "attack_type": data.get("attack_type_ml"),
        "severity": data.get("severity"),
        "confidence": data.get("confidence_ml"),
        "features": data.get("features", {})
    }


# ==========================================================
# EXPLANATION ENGINE (PRO LEVEL)
# ==========================================================

def generate_explanation(context: dict):
    """
    Sinh giải thích giống SOC analyst
    """

    attack = context["attack_type"]
    f = context["features"]

    packet_rate = f.get("packet_rate", 0)
    risk = f.get("risk_score", 0)
    burst = f.get("burst", 0)
    scan = f.get("scan", 0)

    reasoning = []

    # ================= RULE-BASED REASON =================
    if packet_rate > 10000:
        reasoning.append(f"Abnormally high packet rate ({packet_rate})")

    if burst:
        reasoning.append("Traffic burst pattern detected")

    if scan:
        reasoning.append("Sequential port probing behavior")

    if risk > 0.5:
        reasoning.append(f"Elevated risk score ({risk})")

    # 🔥 FIX QUAN TRỌNG: luôn có reasoning
    if not reasoning:
        reasoning.append("Traffic characteristics fall within normal thresholds")

    # ================= SUMMARY + IMPACT =================
    if attack == "DoS":
        summary = "The system detected a potential Denial-of-Service attack characterized by traffic flooding behavior."

        impact = "This may exhaust server resources, degrade performance, or cause service downtime."

    elif attack == "Port Scan":
        summary = "The system identified a port scanning activity targeting multiple services."

        impact = "This is typically a reconnaissance phase before exploitation."

    elif attack == "Suspicious":
        summary = "The system observed anomalous network behavior that deviates from normal patterns."

        impact = "This may indicate early-stage attack or unknown threat."

    else:
        summary = "Traffic appears to follow normal behavior patterns."

        impact = "No immediate security risk detected."

    return {
        "summary": summary,
        "impact": impact,
        "reasoning": reasoning,
        "confidence_note": f"Model confidence: {context['confidence']}"
    }


# ==========================================================
# PLAYBOOK GENERATOR (SOC STYLE)
# ==========================================================

def generate_playbook(context: dict):
    """
    Sinh playbook xử lý theo từng loại attack
    """

    attack = context["attack_type"]

    if attack == "DoS":
        return [
            {
                "step": 1,
                "action": "Apply rate limiting to incoming traffic",
                "tool": "Firewall",
                "priority": "high",
                "note": "Reduce load to prevent service disruption"
            },
            {
                "step": 2,
                "action": "Block or blacklist source IP",
                "tool": "IDS/IPS",
                "priority": "high",
                "note": "Only if traffic confirmed malicious"
            },
            {
                "step": 3,
                "action": "Scale infrastructure or enable CDN protection",
                "tool": "Cloud",
                "priority": "medium",
                "note": "Mitigate large-scale attack"
            }
        ]

    elif attack == "Port Scan":
        return [
            {
                "step": 1,
                "action": "Block scanning IP temporarily",
                "tool": "Firewall",
                "priority": "high",
                "note": "Prevent further reconnaissance"
            },
            {
                "step": 2,
                "action": "Enable IDS alerting rules",
                "tool": "IDS",
                "priority": "medium",
                "note": "Track repeated scan attempts"
            },
            {
                "step": 3,
                "action": "Review exposed services",
                "tool": "Security Audit",
                "priority": "medium",
                "note": "Ensure no vulnerable ports"
            }
        ]

    elif attack == "Suspicious":
        return [
            {
                "step": 1,
                "action": "Monitor traffic for further anomalies",
                "tool": "SIEM",
                "priority": "medium",
                "note": "Determine if behavior escalates"
            },
            {
                "step": 2,
                "action": "Increase logging level",
                "tool": "System",
                "priority": "low",
                "note": "Collect more data for analysis"
            }
        ]

    else:
        return [
            {
                "step": 1,
                "action": "No action required",
                "tool": "System",
                "priority": "low",
                "note": "Traffic is normal"
            }
        ]


# ==========================================================
# MAIN ANALYZER
# ==========================================================

def analyze_with_llm(data: dict):
    """
    Hàm chính: nhận output ML → trả explanation + playbook
    """

    context = build_context(data)

    explanation = generate_explanation(context)
    playbook = generate_playbook(context)

    return {
        "attack_type": context["attack_type"],
        "severity": context["severity"],
        "confidence": context["confidence"],
        "explanation": explanation,
        "playbook": playbook
    }