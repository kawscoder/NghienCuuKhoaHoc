import sys
import os

sys.path.append(
    os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..")
    )
)

from app.core.pipeline_debug import run_pipeline_debug


# ==========================================================
# TABLE RENDER
# ==========================================================

def render_table(title, data):

    print("\n" + "=" * 80)
    print(f"📊 {title.upper()}")
    print("=" * 80)

    if not isinstance(data, dict):
        print(data)
        return

    max_key = max(len(str(k)) for k in data.keys())

    for k, v in data.items():
        v_str = str(v)

        if len(v_str) > 60:
            v_str = v_str[:60] + "..."

        print(f"{k.ljust(max_key)} : {v_str}")


# ==========================================================
# STAGE RENDER (UI READY)
# ==========================================================

def render_stage(stage_name, data):

    print("\n" + "🔥" * 20)
    print(f"🚀 STAGE: {stage_name.upper()}")
    print("🔥" * 20)

    if isinstance(data, dict):

        # nếu có nested (parser)
        if stage_name == "parser":

            for sub in ["rule", "llm", "final"]:
                print(f"\n🔹 {sub.upper()}")
                render_table(sub, data.get(sub, {}))

        else:
            render_table(stage_name, data)

    else:
        print(data)


# ==========================================================
# SOC SUMMARY
# ==========================================================

def render_summary(result):

    final = result.get("final", {})
    confidence = result.get("confidence", {})
    mitre = result.get("mitre", {}).get("mitre", {})

    print("\n" + "=" * 80)
    print("🚨 FINAL INCIDENT SUMMARY")
    print("=" * 80)

    print(f"🎯 Attack Type : {final.get('attack_type')}")
    print(f"🧠 Confidence  : {confidence.get('score')}")
    print(f"⚠️ Severity    : {confidence.get('label')}")

    print("\n🧬 MITRE")
    print(f"  Tactic     : {mitre.get('tactic', {}).get('name')}")
    print(f"  Technique  : {mitre.get('technique', {}).get('name')}")
    print(f"  Sub-tech   : {mitre.get('technique', {}).get('sub_technique_name')}")
    print(f"  Priority   : {mitre.get('detection_priority')}")


# ==========================================================
# EXPORT STRUCTURE (CHO UI)
# ==========================================================

def build_ui_data(result):

    return {
        "stages": [

            {"name": "parser", "data": result.get("parser")},
            {"name": "normalizer", "data": result.get("normalizer")},
            {"name": "flow", "data": result.get("flow")},
            {"name": "behavior", "data": result.get("behavior")},
            {"name": "ml", "data": result.get("ml")},
            {"name": "mitre", "data": result.get("mitre")},
            {"name": "confidence", "data": result.get("confidence")},
            {"name": "final", "data": result.get("final")},

        ]
    }


# ==========================================================
# MAIN TEST
# ==========================================================

def test_one_log():

    log = "ET SCAN NMAP 192.168.1.10:445 -> 10.0.0.5:80 TCP packets=15 bytes=1400 duration=3"

    print("\n💀 DEFLOG SOC DEBUG TABLE 💀\n")

    print("📥 INPUT LOG:")
    print(log)

    result = run_pipeline_debug(log)

    # ======================================================
    # RENDER ALL STAGES
    # ======================================================

    for stage in [
        "parser",
        "normalizer",
        "flow",
        "behavior",
        "ml",
        "mitre",
        "confidence",
        "final"
    ]:
        render_stage(stage, result.get(stage))

    # ======================================================
    # SUMMARY
    # ======================================================

    render_summary(result)

    # ======================================================
    # UI DATA (QUAN TRỌNG)
    # ======================================================

    ui_data = build_ui_data(result)

    print("\n" + "=" * 80)
    print("📦 UI DATA STRUCTURE (FOR FRONTEND)")
    print("=" * 80)

    print(ui_data)


# ==========================================================
# RUN
# ==========================================================

if __name__ == "__main__":
    test_one_log()