import re
from typing import List, Dict, Optional

class InsecureDesignDetector:
    def __init__(self):
        self.PATTERNS = {
            'js': {
                'no_input_validation': [
                    r'input\s*=\s*req\.body',
                    r'input\s*=\s*req\.query',
                    r'input\s*=\s*req\.params',
                    r'let\s+\w+\s*=\s*req\.body',
                    r'let\s+\w+\s*=\s*req\.query',
                    r'let\s+\w+\s*=\s*req\.params',
                ],
                'no_rate_limiting': [
                    r'app\.use\s*\(\s*[\'"]/?[\'"]\s*,\s*.*\)',
                    r'router\.use\s*\(\s*[\'"]/?[\'"]\s*,\s*.*\)',
                ],
                'no_csrf_protection': [
                    r'csrf\s*=\s*false',
                    r'csrfProtection\s*=\s*false',
                ],
                'no_authentication': [
                    r'//\s*no authentication',
                    r'//\s*public endpoint',
                ]
            },
            'java': {
                'no_input_validation': [
                    r'String\s+\w+\s*=\s*request\.getParameter\s*\(',
                    r'@RequestParam\s+\w+',
                ],
                'no_rate_limiting': [
                    r'@RequestMapping',
                    r'@GetMapping',
                    r'@PostMapping',
                ],
                'no_csrf_protection': [
                    r'csrf\(\)\.disable\(\)',
                ],
                'no_authentication': [
                    r'@PermitAll',
                    r'permitAll\(\)',
                ]
            },
            'go': {
                'no_input_validation': [
                    r'r\.FormValue\s*\(',
                    r'r\.URL\.Query\(\)\.Get\s*\(',
                ],
                'no_rate_limiting': [
                    r'http\.HandleFunc',
                ],
                'no_csrf_protection': [
                    r'csrf\s*:=\s*false',
                ],
                'no_authentication': [
                    r'//\s*no authentication',
                ]
            },
            'py': {
                'no_input_validation': [
                    r'request\.GET\.get\s*\(',
                    r'request\.POST\.get\s*\(',
                    r'request\.args\.get\s*\(',
                    r'request\.form\.get\s*\(',
                ],
                'no_rate_limiting': [
                    r'@app\.route',
                ],
                'no_csrf_protection': [
                    r'csrf_exempt',
                    r'@csrf_exempt',
                ],
                'no_authentication': [
                    r'@allow_any',
                    r'permission_classes\s*=\s*\[\s*AllowAny\s*\]',
                ]
            },
            'php': {
                'no_input_validation': [
                    r'\$_(GET|POST|REQUEST)\s*\[\s*[\'"]\w+[\'"]\s*\]',
                ],
                'no_rate_limiting': [
                    r'Route::(get|post|put|delete)\s*\(',
                ],
                'no_csrf_protection': [
                    r'csrf_field\s*\(\s*\)\s*;',
                    r'csrf_token\s*\(\s*\)\s*;',
                ],
                'no_authentication': [
                    r'//\s*no authentication',
                    r'public function',
                ]
            }
        }

    def detect(self, code: str, lang: str) -> List[Dict]:
        findings = []
        patterns = self.PATTERNS.get(lang, {})
        for category, regex_list in patterns.items():
            for pattern in regex_list:
                for match in re.finditer(pattern, code, re.IGNORECASE):
                    line_number = code[:match.start()].count('\n') + 1
                    findings.append({
                        "description": category,
                        "line": line_number,
                        "code": match.group()
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

def analyze_insecure_design(code: str) -> List[Dict]:
    """
    Analyze a code snippet for insecure design vulnerabilities.
    Returns a list of dicts: {description, line, code, message}
    """
    lang = guess_language(code)
    if not lang:
        return [{"error": "Could not automatically detect the language."}]
    detector = InsecureDesignDetector()
    findings = detector.detect(code, lang)
    if not findings:
        return [{"message": "No insecure design vulnerabilities detected."}]
    for f in findings:
        f["message"] = (
            f"Line {f['line']}: Detected {f['description'].replace('_', ' ')} issue. "
            f"The code \"{f['code']}\" may indicate an insecure design vulnerability."
        )
    return findings