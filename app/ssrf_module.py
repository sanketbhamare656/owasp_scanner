import re
from typing import List, Dict, Optional

class SSRFDetector:
    def __init__(self):
        self.PATTERNS = {
            'js': {
                'unvalidated_url_fetch': [
                    r'request\s*\(\s*req\.(body|query|params)\.url',  # request(req.body.url)
                    r'axios\.\w+\s*\(\s*req\.(body|query|params)\.url',
                    r'fetch\s*\(\s*req\.(body|query|params)\.url',
                    r'request\s*\(\s*userInput',
                    r'axios\.\w+\s*\(\s*userInput',
                    r'fetch\s*\(\s*userInput',
                    r'request\s*\(\s*\w+\s*\)',  # request(variable)
                    r'axios\.\w+\s*\(\s*\w+\s*\)',  # axios.get(variable)
                    r'fetch\s*\(\s*\w+\s*\)',  # fetch(variable)
                    r'\.open\s*\(\s*["\']GET["\']\s*,\s*\w+',  # xhr.open("GET", variable)
                ]
            },
            'java': {
                'unvalidated_url_fetch': [
                    r'new\s+URL\s*\(\s*request\.getParameter\s*\(',
                    r'HttpURLConnection\s+\w+\s*=\s*\(HttpURLConnection\)\s*url\.openConnection\(',
                    r'new\s+URL\s*\(\s*userInput',
                    r'new\s+URL\s*\(\s*\w+\s*\)',         # generic new URL(variable)
                    r'\w+\.openStream\s*\(\s*\)',         # variable.openStream()
                    r'URLConnection\s+\w+\s*=\s*new\s+URL\s*\(\s*\w+\s*\)\.openConnection\s*\(',
                    r'InputStream\s+\w+\s*=\s*new\s+URL\s*\(\s*\w+\s*\)\.openStream\s*\(',
                    r'getInputStream\s*\(\s*\)',          # url.getInputStream()
                ]
            },
            'go': {
                'unvalidated_url_fetch': [
                    r'http\.Get\s*\(\s*r\.FormValue\s*\(',
                    r'http\.Post\s*\(\s*r\.FormValue\s*\(',
                    r'http\.Get\s*\(\s*userInput',
                    r'http\.Post\s*\(\s*userInput',
                    r'http\.Get\s*\(\s*\w+\s*\)',  # http.Get(variable)
                    r'http\.Post\s*\(\s*\w+\s*,',  # http.Post(variable, ...)
                    r'client\.Get\s*\(\s*\w+\s*\)',  # client.Get(variable)
                    r'client\.Post\s*\(\s*\w+\s*,',  # client.Post(variable, ...)
                ]
            },
            'py': {
                'unvalidated_url_fetch': [
                    r'requests\.\w+\s*\(\s*request\.GET\.get\s*\(',
                    r'requests\.\w+\s*\(\s*request\.POST\.get\s*\(',
                    r'requests\.\w+\s*\(\s*request\.args\.get\s*\(',
                    r'requests\.\w+\s*\(\s*request\.form\.get\s*\(',
                    r'requests\.\w+\s*\(\s*user_input',
                    r'urllib\.request\.urlopen\s*\(\s*request\.GET\.get\s*\(',
                    r'urllib\.request\.urlopen\s*\(\s*user_input',
                    r'urllib\.request\.urlopen\s*\(\s*\w+',
                    r'requests\.\w+\s*\(\s*\w+\s*\)',     # requests.get(variable)
                    r'http\.client\.HTTPConnection\s*\(\s*\w+\s*\)',  # HTTPConnection(variable)
                    r'httplib\.HTTPConnection\s*\(\s*\w+\s*\)',  # httplib (Python2)
                    r'web\.browser\.open\s*\(\s*\w+\s*\)',  # webbrowser.open(variable)
                ]
            },
            'php': {
                'unvalidated_url_fetch': [
                    r'file_get_contents\s*\(\s*\$_(GET|POST|REQUEST)\s*\[\s*[\'"]url[\'"]\s*\]',
                    r'curl_setopt\s*\(\s*\$ch\s*,\s*CURLOPT_URL\s*,\s*\$_(GET|POST|REQUEST)\s*\[\s*[\'"]url[\'"]\s*\]',
                    r'file_get_contents\s*\(\s*\$userInput',
                    r'curl_setopt\s*\(\s*\$ch\s*,\s*CURLOPT_URL\s*,\s*\$userInput',
                    r'file_get_contents\s*\(\s*\$[a-zA-Z_][a-zA-Z0-9_]*\s*\)',  # file_get_contents($variable)
                    r'curl_setopt\s*\(\s*\$ch\s*,\s*CURLOPT_URL\s*,\s*\$[a-zA-Z_][a-zA-Z0-9_]*\s*\)',  # curl_setopt($ch, CURLOPT_URL, $variable)
                    r'fopen\s*\(\s*\$[a-zA-Z_][a-zA-Z0-9_]*\s*,',  # fopen($variable, ...)
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

def analyze_ssrf(code: str) -> List[Dict]:
    """
    Analyze a code snippet for SSRF vulnerabilities.
    Returns a list of dicts: {description, line, code, message}
    """
    lang = guess_language(code)
    if not lang:
        return [{"error": "Could not automatically detect the language."}]
    detector = SSRFDetector()
    findings = detector.detect(code, lang)
    if not findings:
        return [{"message": "No SSRF vulnerabilities detected."}]
    for f in findings:
        f["message"] = (
            f"Line {f['line']}: Detected {f['description'].replace('_', ' ')} issue. "
            f"The code \"{f['code']}\" may indicate a server-side request forgery vulnerability."
        )
    return findings