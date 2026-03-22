def calculate_confidence(
    parsed=None,
    normalized=None,
    flow=None,
    behavior=None,
    ml=None,
    mitre=None,
    llm=None
):

    # ======================================================
    # WEIGHTS (SOC-BASED)
    # ======================================================
    WEIGHTS = {
        "behavior": 0.3,
        "flow": 0.25,
        "ml": 0.1,
        "mitre": 0.1,
        "normalizer": 0.1,
        "parser": 0.075,
        "llm": 0.075
    }

    scores = {}

    # ======================================================
    # PARSER
    # ======================================================
    scores["parser"] = parsed.get("parser_confidence", 0.5) if parsed else 0.5

    # ======================================================
    # NORMALIZER
    # ======================================================
    scores["normalizer"] = normalized.get("normalizer_confidence", 0.7) if normalized else 0.7

    # ======================================================
    # FLOW
    # ======================================================
    if flow:
        flow_score = flow.get("flow_confidence", 0.5)

        # 🔥 boost nếu detect scan
        if flow.get("flow_scan_indicator"):
            flow_score += 0.2

        scores["flow"] = min(flow_score, 1.0)
    else:
        scores["flow"] = 0.5

    # ======================================================
    # BEHAVIOR (FIX QUAN TRỌNG)
    # ======================================================
    if behavior:

        flags = behavior.get("flags", {})

        score = behavior.get("confidence", 0.5)

        # 🔥 boost theo flags
        if flags.get("port_scan"):
            score += 0.2
        if flags.get("connection_flood"):
            score += 0.2
        if flags.get("dos"):
            score += 0.3

        scores["behavior"] = min(score, 1.0)

    else:
        scores["behavior"] = 0.5

    # ======================================================
    # ML (GIẢM TẦM QUAN TRỌNG)
    # ======================================================
    if ml:
        ml_score = ml.get("confidence_ml", 0.5)

        # 🔥 giảm influence nếu thấp
        if ml_score < 0.5:
            ml_score *= 0.8

        scores["ml"] = ml_score
    else:
        scores["ml"] = 0.5

    # ======================================================
    # MITRE
    # ======================================================
    if mitre:
        scores["mitre"] = mitre.get("mitre", {}).get("mapping_confidence", 0.5)
    else:
        scores["mitre"] = 0.5

    # ======================================================
    # LLM
    # ======================================================
    if llm and isinstance(llm, dict):
        scores["llm"] = llm.get("confidence", 0.6)
    else:
        scores["llm"] = 0.5

    # ======================================================
    # FINAL SCORE (WEIGHTED)
    # ======================================================
    total = 0

    for key in WEIGHTS:
        total += WEIGHTS[key] * scores[key]

    final_score = round(min(total, 1.0), 3)

    # ======================================================
    # LABEL
    # ======================================================
    if final_score >= 0.85:
        label = "very_high"
    elif final_score >= 0.7:
        label = "high"
    elif final_score >= 0.5:
        label = "medium"
    else:
        label = "low"

    return {
        "score": final_score,
        "label": label,
        "breakdown": scores
    }