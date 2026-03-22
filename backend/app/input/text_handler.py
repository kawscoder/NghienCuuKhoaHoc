from app.core.pipeline import run_pipeline_verbose


def analyze_text(log_text: str):

    result = run_pipeline_verbose(log_text)

    return result