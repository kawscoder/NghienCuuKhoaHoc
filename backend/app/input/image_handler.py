from app.input.ocr_reader import read_image_text
from app.core.pipeline import run_pipeline_verbose


def analyze_image(image_path):

    text = read_image_text(image_path)

    results = []

    for line in text.split("\n"):

        line = line.strip()

        if line:

            result = run_pipeline_verbose(line)

            results.append(result)

    return results