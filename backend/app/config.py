import os
from dotenv import load_dotenv

# load biến môi trường
load_dotenv()


class Config:

    # =========================
    # ENV
    # =========================
    ENV = os.getenv("DEFLOG_ENV", "development")

    # =========================
    # LLM
    # =========================
    LLM_API_KEY = os.getenv("DEFLOG_LLM_API_KEY")

    # =========================
    # FLOW ENGINE
    # =========================
    FLOW_TIMEOUT = int(os.getenv("FLOW_TIMEOUT", 60))