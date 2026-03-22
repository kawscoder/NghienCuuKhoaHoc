"""
DefLog Test Flow Engine

Chức năng:
- Test pipeline hoàn chỉnh:
    parser → normalizer → flow engine
- In kết quả phân tích
"""
import sys
import os

sys.path.append(
    os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..")
    )
)

from app.core.parser import parse_logs
from app.core.normalizer import normalize_logs
from app.analysis.flow_builder import run_engine

# ==========================================================
# SAMPLE IDS LOGS
# ==========================================================

logs = [

    # normal traffic
    "2025-03-19 10:00:01 TCP 192.168.1.10:12345 -> 8.8.8.8:80 bytes=500 packets=5",

    # burst traffic (DoS kiểu nhẹ)
    "2025-03-19 10:00:02 TCP 192.168.1.10:12345 -> 8.8.8.8:80 bytes=10000 packets=500",

    # port scan
    "2025-03-19 10:00:03 TCP 192.168.1.10:12345 -> 8.8.8.8:21 packets=2",
    "2025-03-19 10:00:04 TCP 192.168.1.10:12345 -> 8.8.8.8:22 packets=2",
    "2025-03-19 10:00:05 TCP 192.168.1.10:12345 -> 8.8.8.8:23 packets=2",
    "2025-03-19 10:00:06 TCP 192.168.1.10:12345 -> 8.8.8.8:25 packets=2",
    "2025-03-19 10:00:07 TCP 192.168.1.10:12345 -> 8.8.8.8:53 packets=2",
    "2025-03-19 10:00:08 TCP 192.168.1.10:12345 -> 8.8.8.8:110 packets=2",
    "2025-03-19 10:00:09 TCP 192.168.1.10:12345 -> 8.8.8.8:143 packets=2",
    "2025-03-19 10:00:10 TCP 192.168.1.10:12345 -> 8.8.8.8:443 packets=2",
    "2025-03-19 10:00:11 TCP 192.168.1.10:12345 -> 8.8.8.8:445 packets=2",
    "2025-03-19 10:00:12 TCP 192.168.1.10:12345 -> 8.8.8.8:3389 packets=2",
]


# ==========================================================
# MAIN TEST
# ==========================================================

def main():

    print("\n===== RAW LOGS =====")
    for log in logs:
        print(log)

    # =========================
    # PARSER
    # =========================

    parsed = parse_logs(logs)

    print("\n===== PARSED =====")
    for r in parsed["results"]:
        print(r)

    # =========================
    # NORMALIZER
    # =========================

    normalized = normalize_logs(parsed["results"])

    print("\n===== NORMALIZED =====")
    for r in normalized:
        print(r)

    # =========================
    # FLOW ENGINE
    # =========================

    results = run_engine(normalized)

    print("\n===== FLOW ANALYSIS =====")
    for r in results:
        print(r)


# ==========================================================
# RUN
# ==========================================================

if __name__ == "__main__":
    main()