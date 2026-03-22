import pandas as pd
import os

# ==========================================================
# PATH CHUẨN (CHẠY Ở MỌI NƠI)
# ==========================================================
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))

csv_path = os.path.join(
    BASE_DIR,
    "dataset/processed/behavior_dataset.csv"
)

# ==========================================================
# LOAD DATASET
# ==========================================================
df = pd.read_csv(csv_path)

print("===================================")
print("TOTAL SAMPLES:", len(df))

print("\n=== SAMPLE ===")
print(df.head())

print("\n=== LABEL DISTRIBUTION ===")
print(df["label"].value_counts())

print("\n=== STATS ===")
print(df.describe())

print("\n=== MISSING ===")
print(df.isnull().sum())