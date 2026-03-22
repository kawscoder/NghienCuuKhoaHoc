from app.core.pipeline import run_pipeline_verbose


def analyze_file(file_path):

    results = []

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:

        content = f.read()

    lines = content.splitlines()

    for line in lines:

        line = line.strip()

        if not line:
            continue

        result = run_pipeline_verbose(line)

        results.append(result)

    return results