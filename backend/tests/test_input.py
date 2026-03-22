import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.input.text_handler import analyze_text

log = "Network flow with duration 1303488 and 41 packets detected with label BENIGN"

result = analyze_text(log)

print(result)