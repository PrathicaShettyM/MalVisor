import json
import uuid
import os

REPORT_DIR = 'server/reports'
os.makedirs(REPORT_DIR, exist_ok=True)

def save_report(data: dict) -> str:
    report_id = str(uuid.uuid4())
    path = os.path.join(REPORT_DIR, f"{report_id}.json")
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    return report_id

def load_report(report_id: str) -> dict:
    path = os.path.join(REPORT_DIR, f"{report_id}.json")
    if not os.path.exists(path):
        return {"error": "Report not found."}
    with open(path, "r") as f:
        return json.load(f)
