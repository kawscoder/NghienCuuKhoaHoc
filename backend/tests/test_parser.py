import sys
import os

sys.path.append(
    os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..")
    )
)

from app.core.parser import (
    parse_log,
    llm_parser,
    llm_parser_pro, 
    select_rule_parser,
    detect_ids_engine,
    SCHEMA_FIELDS
)


# ==========================================================
# PRINT TABLE
# ==========================================================

def print_compare_table(rule, llm,llm_pro, final):

    print("\n================ PARSER COMPARISON ================\n")

    header = f"{'FIELD':20} | {'RULE':20} | {'LLM':20} | {'LLM_PRO':20} | {'FINAL'}"
    print(header)
    print("-" * len(header))

    for field in SCHEMA_FIELDS:

        rule_val = str(rule.get(field))
        llm_val = str(llm.get(field))
        llm_pro_val = str(llm_pro.get(field))
        final_val = str(final.get(field))

        print(f"{field:20} | {rule_val:25} | {llm_val:25} | {llm_pro_val:25} | {final_val}")

    print("\n===================================================\n")


# ==========================================================
# TEST SINGLE LOG
# ==========================================================

def test_single_log():

    log = "random suspicious connection from host A to server B port 22 repeated"

    print("\n==============================")
    print("RAW LOG")
    print("==============================\n")

    print(log)

    # ======================================================
    # LLM PARSER
    # ======================================================

    llm_result = llm_parser(log)

    llm_result_pro = llm_parser_pro(log)
    # ======================================================
    # RULE PARSER
    # ======================================================

    engine = detect_ids_engine(log)

    rule_parser = select_rule_parser(engine)

    rule_result = rule_parser(log)

    # ======================================================
    # FINAL PARSER (CONSENSUS)
    # ======================================================

    final_result = parse_log(log)

    # ======================================================
    # PRINT TABLE
    # ======================================================

    print_compare_table(
        rule_result,
        llm_result,
        llm_result_pro,
        final_result
    )


# ==========================================================
# MAIN
# ==========================================================

if __name__ == "__main__":

    test_single_log()