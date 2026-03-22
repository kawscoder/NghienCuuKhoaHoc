import sys
import os

# fix path
sys.path.append(
    os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..")
    )
)

from app.intel.mitre_mapper import map_to_mitre


# ==========================================================
# TEST CASES
# ==========================================================

tests = [

    # ======================================================
    # 1. PORT SCAN (FAST)
    # ======================================================
    {
        "name": "Port Scan - Fast",
        "attack_type": "Port Scan",
        "flow": {
            "flow_scan_indicator": True,
            "flow_packet_rate": 800,
            "multi_port_scan": False,
            "flow_risk_score": 0.6
        },
        "behavior": {
            "port_scan": True
        }
    },

    # ======================================================
    # 2. PORT SCAN (WIDE)
    # ======================================================
    {
        "name": "Port Scan - Wide",
        "attack_type": "Port Scan",
        "flow": {
            "multi_port_scan": True,
            "flow_risk_score": 0.7
        },
        "behavior": {}
    },

    # ======================================================
    # 3. DOS - BURST
    # ======================================================
    {
        "name": "DoS - Burst",
        "attack_type": "DoS",
        "flow": {
            "flow_burst_indicator": True,
            "flow_packet_rate": 60000,
            "flow_risk_score": 0.9
        },
        "behavior": {
            "connection_flood": True
        }
    },

    # ======================================================
    # 4. BRUTE FORCE
    # ======================================================
    {
        "name": "Brute Force - Guessing",
        "attack_type": "Brute Force",
        "flow": {},
        "behavior": {
            "high_attempt_rate": True
        }
    },

    # ======================================================
    # 5. SQL INJECTION
    # ======================================================
    {
        "name": "SQL Injection",
        "attack_type": "SQL Injection",
        "flow": {},
        "behavior": {
            "payload_injection": True
        }
    },

    # ======================================================
    # 6. NORMAL
    # ======================================================
    {
        "name": "Normal Traffic",
        "attack_type": "Normal",
        "flow": {},
        "behavior": {}
    },

    # ======================================================
    # 7. SUSPICIOUS
    # ======================================================
    {
        "name": "Suspicious Obfuscation",
        "attack_type": "Suspicious",
        "flow": {
            "flow_small_payload_indicator": True
        },
        "behavior": {}
    }
]


# ==========================================================
# RUN TEST
# ==========================================================

print("\n===== MITRE ENGINE TEST =====\n")

for i, t in enumerate(tests, 1):

    print(f"\n--- TEST {i}: {t['name']} ---\n")

    result = map_to_mitre(
        attack_type=t["attack_type"],
        flow=t.get("flow"),
        behavior=t.get("behavior"),
        ml={"confidence_ml": 0.9}
    )

    print(result)