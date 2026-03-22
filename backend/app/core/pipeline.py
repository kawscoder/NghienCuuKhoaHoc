# ==========================================================
# DEFLOG PIPELINE - FINAL (SOC + CORRELATION)
# ==========================================================

from app.core.parser import parse_log
from app.core.normalizer import normalize_log
from app.analysis.flow_builder import process_event
from app.analysis.feature_extractor import extract_features
from app.analysis.behavior_engine import analyze_behavior_engine, BehaviorState
from app.analysis.ml_detector import predict
from app.intel.mitre_mapper import map_to_mitre
from app.analysis.llm_analyzer import analyze_with_llm
from app.core.confidence import calculate_confidence

# 🔥 NEW
from app.analysis.correlation_engine import correlate_event


behavior_state = BehaviorState()


# ==========================================================
# PIPELINE
# ==========================================================

def run_pipeline_verbose(raw_log: str):

    print("\n💀 DEFLOG PIPELINE EXECUTION 💀\n")

    # ======================================================
    # 1. PARSER
    # ======================================================

    print("⏳ Parser đang phân tích...")

    parsed = parse_log(raw_log)


    # ======================================================
    # 2. NORMALIZER
    # ======================================================

    print("⏳ Normalizer đang xử lý...")

    normalized = normalize_log(parsed, raw_log)


    # ======================================================
    # 3. FLOW
    # ======================================================

    print("⏳ Flow đang build...")

    flow = process_event(normalized)

    # ======================================================
    # 4. FEATURE (RAW)
    # ======================================================

    features = extract_features(normalized, flow)

    # ======================================================
    # 5. BEHAVIOR
    # ======================================================

    behavior = analyze_behavior_engine(
        normalized,
        flow,
        {},
        behavior_state
    )


    # ======================================================
    # 6. FEATURE ENRICH
    # ======================================================

    features = extract_features(normalized, flow, behavior)


    # ======================================================
    # 7. ML
    # ======================================================

    ml = predict(features)


    if not ml:
        print("⚠️ ML fallback triggered")

        ml = {
            "attack_type_ml": "Unknown",
            "confidence_ml": 0.3,
            "severity": "low",
            "source": "fallback"
        }
    # ======================================================
    # 8. DECISION ENGINE
    # ======================================================

    try:
        if behavior.get("flags", {}).get("port_scan"):
            attack_type = "Port Scan"

        elif behavior.get("flags", {}).get("dos"):
            attack_type = "DoS"

        elif ml.get("confidence_ml", 0) > 0.9:
            attack_type = ml.get("attack_type_ml")

        else:
            attack_type = behavior.get("attack_type", "Normal")

    except Exception:
        attack_type = "Unknown"


    # ======================================================
    # 9. MITRE
    # ======================================================

    mitre = map_to_mitre(
        attack_type,
        flow=flow,
        behavior=behavior,
        ml=ml
    )


    # ======================================================
    # 10. LLM ANALYZER
    # ======================================================

    llm = analyze_with_llm({
        "attack_type_ml": attack_type,
        "confidence_ml": ml.get("confidence_ml"),
        "severity": ml.get("severity"),
        "features": features
    })


    # ======================================================
    # 11. CONFIDENCE
    # ======================================================

    confidence = calculate_confidence(
        parsed,
        normalized,
        flow,
        behavior,
        ml,
        mitre,
        llm
    )

    # ======================================================
    # 🔥 12. CORRELATION ENGINE (NEW)
    # ======================================================
    incident = correlate_event({
        "source_ip": normalized.get("source_ip"),
        "attack_type": attack_type,
        "confidence": confidence.get("score")
    })

    # ======================================================
    # FINAL RESULT (🔥 FIX FULL DEBUG)
    # ======================================================

    result = {
        "attack_type": attack_type,
        "summary": llm.get("explanation", {}).get("summary"),
        "confidence": confidence.get("score"),
        "incident": incident,

        # LLM OUTPUT
        "playbook": llm.get("playbook"),
        "explanation": llm.get("explanation"),

        # 🔥 QUAN TRỌNG NHẤT (THIẾU CÁI NÀY NÊN UI KHÔNG HIỂN THỊ)
        "debug": {
            "raw_log": raw_log,
            "parser": parsed,
            "normalizer": normalized,
            "flow": flow,
            "features": features,
            "behavior": behavior,
            "ml": ml,
            "mitre": mitre,
            "llm": llm,
            "confidence": confidence,
            "incident": incident
        }
    }

    return result