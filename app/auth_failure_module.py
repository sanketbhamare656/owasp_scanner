import re
from typing import List, Dict, Optional

class AuthFailureDetector:
    def __init__(self):
        self.PATTERNS = {
            'js': {
                'hardcoded_credentials': [
                    re.compile(r'(password|passwd|pwd|secret|token|username|user)\s*[:=]\s*[\'"].{3,}[\'"]', re.IGNORECASE),
                ],
                'insecure_hashing': [
                    re.compile(r'(md5|sha1)\s*\(', re.IGNORECASE),
                    re.compile(r'crypto\.createHash\s*\(\s*[\'"](md5|sha1)[\'"]', re.IGNORECASE),
                ],
                'missing_mfa': [
                    re.compile(r'(login|authenticate)\s*\(.*\)', re.IGNORECASE),
                ],
                'session_management': [
                    re.compile(r'(set_cookie|create_session|sessionStorage|localStorage|cookie)\s*\(?.*', re.IGNORECASE),
                ],
                'brute_force_protection': [
                    re.compile(r'(login_attempts|failed_attempts)\s*[:=]', re.IGNORECASE),
                ],
                'jwt_missing_verification': [
                    re.compile(r'jwt\.decode\s*\(', re.IGNORECASE),
                    re.compile(r'jwt_decode\s*\(', re.IGNORECASE),
                ],
                'csrf_protection_disabled': [
                    re.compile(r'(csrf_protect\s*=\s*False|csrf_exempt|@csrf_exempt)', re.IGNORECASE),
                ],
            },
            'java': {
                'hardcoded_credentials': [
                    re.compile(r'(password|passwd|pwd|secret|token|username|user)\s*=\s*[\'"].{3,}[\'"]', re.IGNORECASE),
                ],
                'insecure_hashing': [
                    re.compile(r'(md5|sha1)\s*\(', re.IGNORECASE),
                    re.compile(r'MessageDigest\.getInstance\s*\(\s*[\'"](MD5|SHA1)[\'"]', re.IGNORECASE),
                ],
                'missing_mfa': [
                    re.compile(r'(login|authenticate)\s*\(.*\)', re.IGNORECASE),
                ],
                'session_management': [
                    re.compile(r'(session_start|create_session|HttpSession|setAttribute|getSession)\s*\(?.*', re.IGNORECASE),
                ],
                'brute_force_protection': [
                    re.compile(r'(login_attempts|failed_attempts)\s*=', re.IGNORECASE),
                ],
                'jwt_missing_verification': [
                    re.compile(r'jwt\.decode\s*\(', re.IGNORECASE),
                    re.compile(r'jwt_decode\s*\(', re.IGNORECASE),
                ],
                'csrf_protection_disabled': [
                    re.compile(r'(csrf\(\)\.disable\(\)|@PermitAll|permitAll\(\))', re.IGNORECASE),
                ],
            },
            'go': {
                'hardcoded_credentials': [
                    re.compile(r'(password|passwd|pwd|secret|token|username|user)\s*:?=\s*[\'"].{3,}[\'"]', re.IGNORECASE),
                ],
                'insecure_hashing': [
                    re.compile(r'(md5|sha1)\.New\(', re.IGNORECASE),
                ],
                'missing_mfa': [
                    re.compile(r'(login|authenticate)\s*\(.*\)', re.IGNORECASE),
                ],
                'session_management': [
                    re.compile(r'(set_cookie|create_session|http\.SetCookie|sessions\.NewCookie)\s*\(?.*', re.IGNORECASE),
                ],
                'brute_force_protection': [
                    re.compile(r'(login_attempts|failed_attempts)\s*:?=', re.IGNORECASE),
                ],
                'jwt_missing_verification': [
                    re.compile(r'jwt\.Decode\s*\(', re.IGNORECASE),
                ],
                'csrf_protection_disabled': [
                    re.compile(r'(csrf\s*:=\s*false)', re.IGNORECASE),
                ],
            },
            'py': {
                'hardcoded_credentials': [
                    re.compile(r'(password|passwd|pwd|secret|token|username|user)\s*=\s*[\'"].{3,}[\'"]', re.IGNORECASE),
                ],
                'insecure_hashing': [
                    re.compile(r'(md5|sha1)\s*\(', re.IGNORECASE),
                    re.compile(r'hashlib\.(md5|sha1)\s*\(', re.IGNORECASE),
                ],
                'missing_mfa': [
                    re.compile(r'def\s+(login|authenticate)\s*\(.*\):', re.IGNORECASE),
                ],
                'session_management': [
                    re.compile(r'(set_cookie|session_start|create_session|session\[|flask\.session|request\.session)\s*\(?.*', re.IGNORECASE),
                ],
                'brute_force_protection': [
                    re.compile(r'(login_attempts|failed_attempts)\s*=', re.IGNORECASE),
                ],
                'jwt_missing_verification': [
                    re.compile(r'jwt\.decode\s*\(.*options\s*=\s*{[^}]*verify_signature\s*:\s*False', re.IGNORECASE),
                    re.compile(r'jwt\.decode\s*\(', re.IGNORECASE),
                    re.compile(r'jwt_decode\s*\(', re.IGNORECASE),
                ],
                'csrf_protection_disabled': [
                    re.compile(r'(csrf_protect\s*=\s*False|csrf_exempt|@csrf_exempt)', re.IGNORECASE),
                ],
            },
            'php': {
                'hardcoded_credentials': [
                    re.compile(r'(password|passwd|pwd|secret|token|username|user)\s*=\s*[\'"].{3,}[\'"]', re.IGNORECASE),
                ],
                'insecure_hashing': [
                    re.compile(r'(md5|sha1)\s*\(', re.IGNORECASE),
                ],
                'missing_mfa': [
                    re.compile(r'(login|authenticate)\s*\(.*\)', re.IGNORECASE),
                ],
                'session_management': [
                    re.compile(r'(set_cookie|session_start|create_session|session_id|session_name)\s*\(?.*', re.IGNORECASE),
                ],
                'brute_force_protection': [
                    re.compile(r'(login_attempts|failed_attempts)\s*=', re.IGNORECASE),
                ],
                'jwt_missing_verification': [
                    re.compile(r'jwt\.decode\s*\(', re.IGNORECASE),
                    re.compile(r'jwt_decode\s*\(', re.IGNORECASE),
                ],
                'csrf_protection_disabled': [
                    re.compile(r'(csrf_protect\s*=\s*False|csrf_exempt|@csrf_exempt)', re.IGNORECASE),
                ],
            }
        }

    def detect(self, code: str, lang: str) -> List[Dict]:
        findings = []
        patterns = self.PATTERNS.get(lang, {})
        lines = code.splitlines()
        for idx, line in enumerate(lines, 1):
            for category, regex_list in patterns.items():
                for pattern in regex_list:
                    for match in pattern.finditer(line):
                        findings.append({
                            "description": category,
                            "line": idx,
                            "code": line.strip(),
                            "matched": match.group()
                        })
        return findings

def guess_language(code: str) -> Optional[str]:
    heuristics = [
        ('js', [r'\bfunction\b', r'require\(', r'router\.', r'passport', r'const ', r'let ', r'=>']),
        ('java', [r'\bpublic class\b', r'@RequestMapping', r'@GetMapping', r'SecurityContextHolder', r'import java\.']),
        ('go', [r'\bpackage main\b', r'func ', r'import \(', r'http\.HandleFunc', r'mux\.Vars']),
        ('py', [r'def ', r'import ', r'@app\.route', r'@login_required', r'class ', r'print\(']),
        ('php', [r'<\?php', r'->', r'Route::', r'\$_(GET|POST|REQUEST)', r'Auth::']),
    ]
    code_sample = code[:2000]
    for lang, patterns in heuristics:
        for pat in patterns:
            if re.search(pat, code_sample, re.IGNORECASE):
                return lang
    return None

def analyze_auth_failure(code: str) -> List[Dict]:
    """
    Analyzes a given code snippet for identification and authentication vulnerabilities.
    Returns a list of dictionaries, each with a user-friendly message.
    """
    lang = guess_language(code)
    if not lang:
        return [{"error": "Could not automatically detect the language."}]
    detector = AuthFailureDetector()
    findings = detector.detect(code, lang)
    if not findings:
        return [{"message": "No authentication or identification vulnerabilities detected."}]
    for f in findings:
        f["message"] = (
            f"Line {f['line']}: Detected {f['description'].replace('_', ' ')} vulnerability. "
            f"The code \"{f['code']}\" contains \"{f['matched']}\" which may be insecure."
        )
    return findings