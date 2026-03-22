import sys
import os
from datetime import datetime, timedelta

sys.path.append(
    os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..")
    )
)

from app.analysis.behavior_engine import (
    BehaviorState,
    analyze_behavior_engine
)

# =========================
# INIT
# =========================

state = BehaviorState()

# =========================
# BASE TIME
# =========================

base_time = datetime(2025, 3, 19, 10, 0, 0)

# =========================
# SCENARIO 1: NORMAL TRAFFIC
# =========================

normal_events = [
    {
        "source_ip": "192.168.1.10",
        "target_port": 80,
        "timestamp": base_time + timedelta(seconds=i * 5),
        "source_zone": "internal",
        "target_zone": "external",
        "service": "HTTP"
    }
    for i in range(3)
]

# =========================
# SCENARIO 2: FAST PORT SCAN
# =========================

scan_ports = [21,22,23,25,53,80,110,143,443,445,3389]

scan_events = [
    {
        "source_ip": "192.168.1.10",
        "target_port": p,
        "timestamp": base_time + timedelta(seconds=10 + i),
        "source_zone": "internal",
        "target_zone": "external",
        "service": "HTTP"
    }
    for i, p in enumerate(scan_ports)
]

# =========================
# SCENARIO 3: BURST TRAFFIC
# =========================

burst_events = [
    {
        "source_ip": "192.168.1.10",
        "target_port": 80,
        "timestamp": base_time + timedelta(seconds=30, milliseconds=i*50),
        "source_zone": "internal",
        "target_zone": "external",
        "service": "HTTP"
    }
    for i in range(5)
]

# =========================
# SCENARIO 4: SLOW SCAN
# =========================

slow_scan_events = [
    {
        "source_ip": "192.168.1.10",
        "target_port": p,
        "timestamp": base_time + timedelta(seconds=60 + i*10),
        "source_zone": "internal",
        "target_zone": "external",
        "service": "HTTP"
    }
    for i, p in enumerate([8080, 3306, 8081, 8443])
]

# =========================
# SCENARIO 5: DOS ATTACK
# =========================

dos_events = [
    {
        "source_ip": "192.168.1.10",
        "target_port": 80,
        "timestamp": base_time + timedelta(seconds=120 + i),
        "source_zone": "internal",
        "target_zone": "external",
        "service": "HTTP"
    }
    for i in range(3)
]

# =========================
# MERGE ALL EVENTS
# =========================

events = (
    normal_events +
    scan_events +
    burst_events +
    slow_scan_events +
    dos_events
)

# =========================
# MULTI FLAGS
# =========================

multi_flags = {
    "multi_port_scan": True,
    "multi_dos": False
}

# =========================
# RUN TEST
# =========================

print("\n===== BEHAVIOR ENGINE FULL TEST =====\n")

for i, e in enumerate(events):

    # =========================
    # FLOW SIMULATION
    # =========================

    if i < 3:
        flow = {"flow_packet_rate": 20, "flow_byte_rate": 200}

    elif i < 14:
        flow = {"flow_packet_rate": 100, "flow_byte_rate": 500}

    elif i < 19:
        flow = {"flow_packet_rate": 300, "flow_byte_rate": 1000}

    else:
        flow = {"flow_packet_rate": 1200, "flow_byte_rate": 5000}

    # =========================
    # ANALYZE
    # =========================

    result = analyze_behavior_engine(
        event=e,
        flow=flow,
        multi_flags=multi_flags,
        state=state
    )

    # =========================
    # OUTPUT
    # =========================

    print(f"TIME: {e['timestamp']}")
    print(f"PORT: {e['target_port']}")
    print(f"FLOW RATE: {flow['flow_packet_rate']}")

    print("ATTACK:", result["attack_type"])
    print("LABEL:", result["behavior_label"])
    print("CONF:", result["confidence"])

    print("PATTERN:", result["pattern"])

    print("FEATURES:", {
        "ports": result["features"]["unique_ports"],
        "rate": result["features"]["conn_rate"],
        "entropy": result["features"]["entropy"],
        "velocity": result["features"]["attack_velocity"]
    })

    print("-" * 60)