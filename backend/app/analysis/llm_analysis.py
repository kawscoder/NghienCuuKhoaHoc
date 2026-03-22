import requests
import json
from typing import Dict

# LLM client để gửi log đến LLM và nhận kết quả phân tích

class LLMClient:

    def __init__(self, api_key: str, base_url: str, model: str):
        self.api_key = api_key
        self.base_url = base_url
        self.model = model

    def analyze_log(self, log_text: str) -> Dict:
        """
        Send log to LLM for security analysis
        """

        prompt = self._build_prompt(log_text)

        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": "You are a cybersecurity analyst specialized in IDS and network security log analysis."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "temperature": 0.2
        }

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        try:

            response = requests.post(
                f"{self.base_url}/chat/completions",
                json=payload,
                headers=headers,
                timeout=30
            )

            print("LLM STATUS:", response.status_code)
            print("LLM RESPONSE:", response.text)

            response.raise_for_status()

            data = response.json()

            return self._parse_response(data)

        except Exception as e:

            return {
                "raw_llm_output": "LLM analysis failed",
                "error": str(e)
            }

    def _build_prompt(self, log_text: str) -> str:

        return f"""
    You are a SOC (Security Operation Center) analyst.

    Analyze the IDS log and produce STRICT JSON output.

    DO NOT explain outside JSON.
    DO NOT add extra text.

    OUTPUT FORMAT:

    {{
    "attack_type": "DoS | Port Scan | Brute Force | Normal | Suspicious",
    "severity": "low | medium | high | critical",

    "reasoning": [
        "short technical reason 1",
        "short technical reason 2"
    ],

    "indicators": {{
        "packet_rate": "...",
        "pattern": "...",
        "risk_signal": "..."
    }},

    "impact": "short impact description",

    "recommended_actions": [
        "action 1",
        "action 2"
    ]
    }}

    RULES:
    - Keep reasoning technical and short
    - No storytelling
    - No markdown
    - If unsure → return "Suspicious"

    LOG:
    {log_text}
    """
    def _parse_response(self, data) -> Dict:
        """
        Parse response from LLM
        """

        try:

            content = data["choices"][0]["message"]["content"]

            # attempt to parse JSON from model output
            parsed = json.loads(content)

            return parsed

        except Exception:

            return {
                "raw_llm_output": data["choices"][0]["message"]["content"]
            }
        
    def ask(self, prompt: str) -> str:
        """
        Generic LLM call used by parser
        Return raw text response
        """

        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": "You extract structured data from IDS logs."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "temperature": 0
        }

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        try:

            response = requests.post(
                f"{self.base_url}/chat/completions",
                json=payload,
                headers=headers,
                timeout=30
            )

            response.raise_for_status()

            data = response.json()

            return data["choices"][0]["message"]["content"]

        except Exception as e:

            print("LLM ERROR:", e)

            return ""