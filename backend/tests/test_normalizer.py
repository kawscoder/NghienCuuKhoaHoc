import sys
import os

sys.path.append(
    os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..")
    )
)

from app.core.parser import parse_log
from app.core.normalizer import normalize_log


# ======================================================
# TEST LOGS
# ======================================================

logs = [

    "ET SCAN NMAP 192.168.1.10:445 -> 10.0.0.5:80 TCP packets=15 bytes=1400 duration=3",

    "ET SCAN NMAP 8.8.8.8:443 -> 1.1.1.1:80 TCP packets=25 bytes=3200 duration=5",

    "ET POLICY Suspicious Traffic 45.33.32.156:22 -> 185.199.108.153:443 TCP packets=40 bytes=5000 duration=8"
]


# ======================================================
# TABLE PRINT
# ======================================================

def print_table(data):

    max_key = max(len(k) for k in data.keys())

    print("-" * (max_key + 30))

    for k, v in data.items():

        print(f"{k.ljust(max_key)} | {v}")

    print("-" * (max_key + 30))


# ======================================================
# TEST NORMALIZER
# ======================================================

def test_normalizer():

    for log in logs:

        print("\n")
        print("=" * 70)
        print("RAW LOG")
        print("=" * 70)

        print(log)

        parsed = parse_log(log)

        print("\n")
        print("=" * 70)
        print("PARSER RESULT")
        print("=" * 70)

        print_table(parsed)

        normalized = normalize_log(parsed, log)

        print("\n")
        print("=" * 70)
        print("NORMALIZER RESULT")
        print("=" * 70)

        print_table(normalized)


# ======================================================
# MAIN
# ======================================================

if __name__ == "__main__":

    test_normalizer()