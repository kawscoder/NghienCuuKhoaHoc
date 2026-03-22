import sys
import os
import json

sys.path.append(
    os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..")
    )
)

from app.core.pipeline import run_pipeline_verbose

if __name__ == "__main__":

    logs = [
    "ET SCAN NMAP 192.168.1.10:445 -> 10.0.0.5:80 TCP packets=10 bytes=800 duration=1",
    "ET SCAN NMAP 192.168.1.10:445 -> 10.0.0.5:22 TCP packets=12 bytes=900 duration=1",
    "ET SCAN NMAP 192.168.1.10:445 -> 10.0.0.5:443 TCP packets=15 bytes=1000 duration=1"
]

    for log in logs:
        run_pipeline_verbose(log)