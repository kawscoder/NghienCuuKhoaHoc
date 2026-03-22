# ==========================================================
# DEFLOG CORRELATION ENGINE (FINAL - FIXED)
# ==========================================================

from datetime import datetime
import uuid

# ==========================================================
# CONFIG
# ==========================================================

TIME_WINDOW = 120  # seconds

KILL_CHAIN_MAP = {
    "Port Scan": "Recon",
    "Scan": "Recon",
    "Brute Force": "Access",
    "Login Success": "Access",
    "Lateral Movement": "Lateral",
    "DoS": "Impact"
}

# ==========================================================
# STATE
# ==========================================================

correlation_state = {}

# ==========================================================
# HELPERS
# ==========================================================

def now():
    return datetime.utcnow()


def get_stage(attack_type):
    for k, v in KILL_CHAIN_MAP.items():
        if k in attack_type:
            return v
    return "Unknown"


# ==========================================================
# MAIN ENGINE
# ==========================================================

def correlate_event(event):

    src_ip = event.get("source_ip")
    attack = event.get("attack_type", "Normal")
    confidence = event.get("confidence", 0.5)

    if not src_ip:
        return None

    current_time = now()

    # ======================================================
    # INIT
    # ======================================================

    if src_ip not in correlation_state:
        correlation_state[src_ip] = {
            "events": [],
            "first_seen": current_time,
            "last_seen": current_time
        }

    state = correlation_state[src_ip]

    # ======================================================
    # EXPIRE WINDOW
    # ======================================================

    if (current_time - state["last_seen"]).total_seconds() > TIME_WINDOW:
        correlation_state[src_ip] = {
            "events": [],
            "first_seen": current_time,
            "last_seen": current_time
        }
        state = correlation_state[src_ip]

    # ======================================================
    # ADD EVENT
    # ======================================================

    state["events"].append({
        "attack": attack,
        "confidence": confidence,
        "timestamp": current_time
    })

    state["last_seen"] = current_time

    # ======================================================
    # BUILD INCIDENT
    # ======================================================

    return build_incident(src_ip, state)


# ==========================================================
# BUILD INCIDENT
# ==========================================================

def build_incident(src_ip, state):

    events = state["events"]

    if not events:
        return None

    # ======================================================
    # FILTER ATTACKS
    # ======================================================

    attacks = [e["attack"] for e in events if e["attack"] != "Normal"]

    if not attacks:
        return None

    # ======================================================
    # BUILD ATTACK CHAIN
    # ======================================================

    stages = []
    seen = set()

    for attack in attacks:
        stage = get_stage(attack)

        if stage not in seen:
            stages.append({
                "stage": stage,
                "attack": attack
            })
            seen.add(stage)

    # ======================================================
    # METRICS
    # ======================================================

    avg_conf = sum(e["confidence"] for e in events) / len(events)
    chain_len = len(stages)
    event_count = len(events)

    has_impact = any(s["stage"] == "Impact" for s in stages)

    # ======================================================
    # 🔥 CONFIDENCE (FIXED REALISTIC)
    # ======================================================

    score = avg_conf * 0.6 + min(event_count * 0.1, 0.4)

    if has_impact:
        score += 0.2

    score = round(min(score, 1.0), 3)

    # ======================================================
    # 🔥 SEVERITY (FIX QUAN TRỌNG)
    # ======================================================

    if has_impact:
        severity = "critical"

    elif chain_len >= 3:
        severity = "high"

    elif chain_len == 2:
        severity = "medium"

    elif chain_len == 1:
        if event_count >= 5:
            severity = "high"
        elif event_count >= 3:
            severity = "medium"
        else:
            severity = "low"

    else:
        severity = "low"

    # ======================================================
    # BUILD INCIDENT
    # ======================================================

    incident = {
        "incident_id": str(uuid.uuid4())[:8],
        "attacker": src_ip,
        "event_count": event_count,
        "attack_chain": stages,
        "confidence": score,
        "severity": severity,
        "first_seen": state["first_seen"].strftime("%Y-%m-%d %H:%M:%S"),
        "last_seen": state["last_seen"].strftime("%Y-%m-%d %H:%M:%S")
    }

    return incident