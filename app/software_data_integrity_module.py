import re
from typing import List, Dict

class SoftwareDataIntegrityDetector:
    def __init__(self):
        self.PATTERNS = {
            'untrusted_imports': re.compile(r'(require|import)\s*\(?[\'"]http[s]?://', re.IGNORECASE),
            'insecure_deserialization': re.compile(r'(pickle\.load|yaml\.load|eval\()', re.IGNORECASE),
            'missing_integrity_check': re.compile(r'(download|fetch|get).*(http|https)', re.IGNORECASE),
            'auto_update_without_verification': re.compile(r'(auto_update|update).*(http|https)', re.IGNORECASE),
        }

    def detect(self, code: str) -> List[Dict]:
        findings = []
        lines = code.splitlines()
        for idx, line in enumerate(lines, 1):
            for category, pattern in self.PATTERNS.items():
                if pattern.search(line):
                    findings.append({
                        "description": category,
                        "line": idx,
                        "code": line.strip()
                    })
        return findings

def analyze_software_data_integrity(code: str) -> List[Dict]:
    """
    Analyze a code snippet for software and data integrity failures.
    Returns a list of dicts: {description, line, code, message}
    """
    detector = SoftwareDataIntegrityDetector()
    findings = detector.detect(code)
    if not findings:
        return [{"message": "No software or data integrity vulnerabilities detected."}]
    for f in findings:
        f["message"] = (
            f"Line {f['line']}: Detected {f['description'].replace('_', ' ')} issue. "
            f"The code \"{f['code']}\" may indicate a software or data integrity vulnerability."
        )
    return findings