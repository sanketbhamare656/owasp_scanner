import re
from typing import List, Dict

class LoggingMonitoringDetector:
    def __init__(self):
        self.PATTERNS = {
            # Logging disabled in Python, Java, JS, PHP, Go
            'logging_disabled': re.compile(
                r'('
                r'logging\.disable\s*\(|'  # Python
                r'logger\.setLevel\s*\(\s*logging\.CRITICAL\s*\)|'
                r'logger\.setLevel\s*\(\s*Level\.OFF\s*\)|'  # Java
                r'Logger\.getLogger\s*\(\s*["\'].*["\']?\s*\)\.setLevel\s*\(\s*Level\.OFF\s*\)|'
                r'console\.log\s*=\s*function\s*\(\)\s*\{\s*\}|'
                r'ini_set\s*\(\s*[\'"]log_errors[\'"]\s*,\s*[\'"]off[\'"]\s*\)|'
                r'logrus\.SetOutput\(ioutil\.Discard\)|'
                r'log\.SetOutput\(ioutil\.Discard\)'
                r')',
                re.IGNORECASE
            ),
            # File logging to logs/ or web-accessible directories
            'file_logging': re.compile(
                r'('
                r'open\s*\(.*/logs?/.*\)|'
                r'FileHandler\s*\(.*/logs?/.*\)|'
                r'fs\.writeFileSync\s*\(.*/logs?/.*\)|'
                r'fopen\s*\(.*/logs?/.*\)|'
                r'log4j\.FileAppender|'
                r'logging\.FileHandler|'
                r'log_file\s*=\s*[\'"].*/logs?/.*[\'"]'
                r')',
                re.IGNORECASE
            ),
            # Logging sensitive data (password, token, secret, credit card, ssn, etc.)
            'sensitive_in_logs': re.compile(
                r'('
                r'(log|logger|logging|console|print|System\.out\.println|fmt\.Print|fmt\.Printf|echo)\.?(info|debug|log|warn|error|println|printf)?\s*\(.*'
                r'(password|passwd|pwd|secret|token|credit[_ ]?card|ssn|cvv|pin|api[_ ]?key|auth|session|cookie)'
                r'.*',
                re.IGNORECASE
            ),
            # Missing logging in authentication functions (Python, Java, JS, PHP)
            'missing_log_in_auth': re.compile(
                r'('
                r'(def|function|public\s+void|void|func|function)\s+(login|authenticate|auth|signin|sign_in|signIn|log_in|logIn)\s*\(.*\)\s*[:{][^#\n]*$'
                r')',
                re.IGNORECASE
            ),
            # Logging exceptions without context (Python, Java, JS)
            'exception_logging': re.compile(
                r'('
                r'(log|logger|logging|console|System\.out\.println|fmt\.Print|fmt\.Printf)\.?(error|exception|warn|debug|info|log|println|printf)?\s*\(\s*e[x]?(c(eption)?)?\s*\)'
                r')',
                re.IGNORECASE
            ),
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

def analyze_logging_monitoring(code: str) -> List[Dict]:
    """
    Analyze a code snippet for logging and monitoring failures.
    Returns a list of dicts: {description, line, code, message}
    """
    detector = LoggingMonitoringDetector()
    findings = detector.detect(code)
    if not findings:
        return [{"message": "No logging or monitoring vulnerabilities detected."}]
    for f in findings:
        f["message"] = (
            f"Line {f['line']}: Detected {f['description'].replace('_', ' ')} issue. "
            f"The code \"{f['code']}\" may indicate a logging or monitoring vulnerability."
        )
    return findings