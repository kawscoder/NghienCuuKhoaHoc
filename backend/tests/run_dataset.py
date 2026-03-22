import sys
import os

# Script để chạy thử pipeline trên một số log mẫu từ dataset đã xử lý

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.core.pipeline import run_pipeline

LOG_FILE = "dataset/processed/logs.txt"

def run_dataset():

    with open(LOG_FILE, "r", encoding="utf-8") as f:
        logs = f.readlines()

    print(f"Total logs: {len(logs)}")

    for log in logs[:5]:

        result = run_pipeline(log.strip())

        print("\nINPUT LOG:")
        print(log.strip())

        print("RESULT:")
        print(result)


if __name__ == "__main__":
    run_dataset()