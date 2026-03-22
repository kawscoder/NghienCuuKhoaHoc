import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.core.pipeline import run_pipeline

log = "Network flow with duration 1303488 and 41 packets detected with label BENIGN"

result = run_pipeline(log)

print(result)