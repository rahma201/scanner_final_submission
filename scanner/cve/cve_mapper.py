import json
from pathlib import Path
from typing import Dict, List, Optional


# ==============================
# Path to local CVE database
# ==============================
DB_PATH = Path(__file__).with_name("cve_db.json")


# ==============================
# Severity ranking system
# ==============================
SEVERITY_ORDER = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


# ==============================
# Helper: normalize text
# ==============================
def _norm(s: str) -> str:
    """
    Normalize string:
    - Lowercase
    - Remove extra spaces
    - Protect against None
    """
    return (s or "").strip().lower()


# ==============================
# Load CVE database
# ==============================
def load_db(db_path: Path = DB_PATH) -> Dict:
    """
    Loads the JSON CVE database
    """
    with db_path.open("r", encoding="utf-8") as f:
        return json.load(f)


# ==============================
# Sort CVEs by severity (high -> low)
# ==============================
def sort_cves_by_severity(cves: List[Dict]) -> List[Dict]:
    """
    Sort CVEs from highest severity to lowest:
    CRITICAL -> HIGH -> MEDIUM -> LOW
    Unknown severities go last.
    """
    def sev_score(c: Dict) -> int:
        sev = str(c.get("severity", "")).strip().upper()
        return SEVERITY_ORDER.get(sev, 0)

    return sorted(cves, key=sev_score, reverse=True)


# ==============================
# Main CVE Mapping Function
# ==============================
def map_cves(service: str, version: str, db: Optional[Dict] = None) -> List[Dict]:
    """
    Maps service + version to known CVEs (exact match).

    Returns list of:
    [
        {
            "cve_id": "...",
            "description": "...",
            "severity": "...",
            "reference": "..."
        }
    ]
    """
    service_n = _norm(service)
    version_n = (version or "").strip()

    if not service_n or not version_n:
        return []

    if db is None:
        db = load_db()

    entries = db.get("entries", [])

    for entry in entries:
        if (
            _norm(entry.get("service")) == service_n
            and (entry.get("version") or "").strip() == version_n
        ):
            results: List[Dict] = []
            for cve in entry.get("cves", []):
                results.append(
                    {
                        "cve_id": cve.get("cve_id", ""),
                        "description": cve.get("description", ""),
                        "severity": cve.get("severity", ""),
                        "reference": cve.get("reference", ""),
                    }
                )

            # ✅ مهم: نرجعها مرتبة حسب الخطورة
            return sort_cves_by_severity(results)

    return []


# ==============================
# Get Highest Severity
# ==============================
def max_severity(cves: List[Dict]) -> str:
    """
    Returns highest severity from CVE list.
    If empty -> "NONE"
    """
    highest_score = 0
    highest_name = "NONE"

    for cve in cves:
        severity = str(cve.get("severity", "")).strip().upper()
        score = SEVERITY_ORDER.get(severity, 0)

        if score > highest_score:
            highest_score = score
            highest_name = severity

    return highest_name
