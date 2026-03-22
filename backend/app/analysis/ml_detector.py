import joblib
import os
import pandas as pd

# ==========================================================
# CONFIG
# ==========================================================

MODEL_PATH = "backend/app/models/behavior_model.pkl"

FEATURE_COLUMNS = [
    "packet_rate",
    "byte_rate",
    "flow_speed",
    "packet_density",
    "byte_per_second",
    "scan",
    "burst",
    "dos_flag",
    "risk_score",
    "is_internal_src",
    "is_internal_dst"
]

model = None


# ==========================================================
# LOAD MODEL (lazy)
# ==========================================================

def load_model():
    global model

    if model is None:
        if not os.path.exists(MODEL_PATH):
            print("❌ Model not found")
            return None

        model = joblib.load(MODEL_PATH)
        print("✅ ML model loaded")

    return model


# ==========================================================
# BUILD FEATURE VECTOR
# ==========================================================

def build_feature_vector(features: dict):
    vector = []

    for col in FEATURE_COLUMNS:
        value = features.get(col, 0)

        if isinstance(value, bool):
            value = int(value)

        try:
            value = float(value)
        except:
            value = 0

        vector.append(value)

    return vector


# ==========================================================
# RULE ENGINE PRO MAX (SOFT SCORING)
# ==========================================================

def rule_engine(features: dict):

    packet_rate = features.get("packet_rate", 0)
    density = features.get("packet_density", 0)
    bps = features.get("byte_per_second", 0)

    scan = features.get("scan", 0)
    burst = features.get("burst", 0)
    dos_flag = features.get("dos_flag", 0)
    risk = features.get("risk_score", 0)

    dos_score = 0
    scan_score = 0

    # ================= DoS =================
    if packet_rate > 10000:
        dos_score += 2
    if packet_rate > 30000:
        dos_score += 2

    if bps > 3000:
        dos_score += 2

    if burst:
        dos_score += 1

    if dos_flag:
        dos_score += 3

    if density > 50000:
        dos_score += 1

    if risk > 0.6:
        dos_score += 2

    # ================= Scan =================
    if scan:
        scan_score += 4

    if packet_rate < 500 and density > 20000:
        scan_score += 2

    if risk > 0.4:
        scan_score += 1

    # ================= Decision =================

    if dos_score >= 6:
        return "DoS", min(1.0, dos_score / 10), "high", "rule"

    if scan_score >= 4:
        return "Port Scan", min(1.0, scan_score / 8), "medium", "rule"

    # suspicious → ML xử lý tiếp
    if dos_score >= 3 or scan_score >= 2:
        return None, 0, "medium", "ml"

    return None, 0, "low", "ml"


# ==========================================================
# MAIN PREDICT
# ==========================================================

def predict(features: dict):

    # ================= RULE FIRST =================
    rule_pred, rule_conf, severity, source = rule_engine(features)

    if rule_pred is not None:
        return {
            "attack_type_ml": rule_pred,
            "confidence_ml": round(rule_conf, 3),
            "severity": severity,
            "source": source
        }

    # ================= ML =================
    model = load_model()

    if model is None:
        return None

    try:
        vector = build_feature_vector(features)

        # 🔥 FIX WARNING (rất quan trọng)
        df = pd.DataFrame([vector], columns=FEATURE_COLUMNS)

        prediction = model.predict(df)[0]
        probability = float(max(model.predict_proba(df)[0]))

        risk = features.get("risk_score", 0)
        burst = features.get("burst", 0)
        scan = features.get("scan", 0)

        # ================================
        # SUSPICIOUS LOGIC FINAL
        # ================================

        risk = features.get("risk_score", 0)
        burst = features.get("burst", 0)
        scan = features.get("scan", 0)
        packet_rate = features.get("packet_rate", 0)

        if prediction == "Normal":

            suspicious_score = 0

            if risk > 0.5:
                suspicious_score += 2

            if burst:
                suspicious_score += 1

            if scan:
                suspicious_score += 2

            if packet_rate > 8000:
                suspicious_score += 1

            # 🔥 chỉ khi đủ tín hiệu mới flag
            if suspicious_score >= 3:
                return {
                    "attack_type_ml": "Suspicious",
                    "confidence_ml": round(probability, 3),
                    "severity": "medium",
                    "source": "ml+logic"
                }

        # ==================================================
        # SEVERITY LOGIC
        # ==================================================
        if probability > 0.9:
            severity = "medium"
        elif probability > 0.7:
            severity = "low"
        else:
            severity = "low"

        return {
            "attack_type_ml": str(prediction),
            "confidence_ml": round(probability, 3),
            "severity": severity,
            "source": "ml"
        }

    except Exception as e:
        return {
            "attack_type_ml": "error",
            "confidence_ml": 0,
            "severity": "unknown",
            "error": str(e)
        }