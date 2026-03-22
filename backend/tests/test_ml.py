import sys
import os

sys.path.append(
    os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..")
    )
)

from app.analysis.ml_detector import predict

# =========================
# TEST FEATURES (GIẢ LẬP)
# =========================

test_features = {
    "unique_ports": 12,
    "connection_count": 50,
    "conn_rate": 0.8,
    "avg_interval": 0.5,
    "entropy": 3.2,
    "port_growth_rate": 0.9,
    "repeat_ratio": 0.1,
    "scan_consistency": 0.9,
    "time_span": 10,
    "attack_velocity": 1.2,
    "stability": 0.8,
    "acceleration": 0.7
}

# =========================
# RUN TEST
# =========================

print("\n===== ML DETECTOR TEST =====\n")

result = predict(test_features)

print("INPUT FEATURES:")
print(test_features)

print("\nML RESULT:")
print(result)

print("\n============================\n")