import re
from typing import List, Dict, Tuple, Optional

class VulnerableOutdatedComponentsDetector:
    def __init__(self):
        self.PATTERNS: Dict[str, List[re.Pattern]] = {
            'js': [
                re.compile(r'"(jquery|lodash|minimist|event-stream|marked|handlebars|express)"\s*:\s*"(0\.[^"]+|1\.[^"]+|2\.[^"]+|<4\.17\.21|<1\.2\.3|<1\.2\.4|<4\.17\.1)"', re.IGNORECASE),
                re.compile(r'"(left-pad|request|core-js|vulnerable|deprecated)"', re.IGNORECASE),
            ],
            'py': [
                re.compile(r'(django|flask|requests|pyyaml|jinja2|cryptography|urllib3|pillow|numpy|setuptools|pip)\s*==\s*(0\.[0-9]+|1\.[0-9]+|2\.[0-9]+|<2\.2\.24|<1\.1\.0|<1\.24\.2|<3\.2\.1|<1\.16\.0|<40\.0\.0|<19\.2)', re.IGNORECASE),
                re.compile(r'(vulnerable|deprecated)', re.IGNORECASE),
            ],
            'java': [
                re.compile(r'<dependency>.*?<groupId>(org\.springframework|commons-collections|log4j|struts|jackson|bouncycastle)</groupId>.*?<version>(1\.[^<]+|2\.[^<]+|<2\.3\.34|<1\.2\.17|<2\.9\.10\.8|<1\.68)</version>', re.DOTALL | re.IGNORECASE),
                re.compile(r'(vulnerable|deprecated)', re.IGNORECASE),
            ],
            'go': [
                re.compile(r'(github\.com/gorilla/websocket|github\.com/dgrijalva/jwt-go|github\.com/miekg/dns)\s+v(0\.[0-9]+|1\.[0-9]+|<1\.4\.2|<3\.0\.0)', re.IGNORECASE),
                re.compile(r'(vulnerable|deprecated)', re.IGNORECASE),
            ],
            'php': [
                re.compile(r'"(symfony/symfony|laravel/framework|zendframework/zendframework|monolog/monolog)"\s*:\s*"(2\.[^"]+|3\.[^"]+|<4\.4\.0|<6\.20\.26|<2\.0\.2)"', re.IGNORECASE),
                re.compile(r'(vulnerable|deprecated)', re.IGNORECASE),
            ]
        }

        self.IGNORE_CONTEXT = [
            re.compile(r'#\s*test', re.IGNORECASE),
            re.compile(r'//\s*test', re.IGNORECASE),
            re.compile(r'#\s*not\s*for\s*production', re.IGNORECASE),
            re.compile(r'//\s*not\s*for\s*production', re.IGNORECASE),
            re.compile(r'@Test', re.IGNORECASE),
            re.compile(r'function\s+test', re.IGNORECASE),
        ]

    def is_ignored_context(self, line: str) -> bool:
        return any(p.search(line) for p in self.IGNORE_CONTEXT)

    def detect(self, code: str, lang: str) -> List[Dict]:
        findings = []
        patterns = self.PATTERNS.get(lang, [])
        lines = code.splitlines()
        for idx, line in enumerate(lines, 1):
            if self.is_ignored_context(line):
                continue
            for pattern in patterns:
                for match in pattern.finditer(line):
                    findings.append({
                        "line": idx,
                        "matched": match.group(),
                        "code": line.strip()
                    })
        return findings

def guess_language(code: str) -> Optional[str]:
    heuristics = [
        ('js', [r'"dependencies"', r'"devDependencies"', r'"name"', r'"version"']),
        ('py', [r'django', r'flask', r'requests', r'pyyaml', r'jinja2', r'cryptography', r'urllib3', r'pillow', r'numpy', r'setuptools', r'pip']),
        ('java', [r'<dependency>', r'<groupId>', r'<artifactId>', r'<version>']),
        ('go', [r'module ', r'require ', r'github\.com/']),
        ('php', [r'"require"', r'"autoload"', r'"psr-4"', r'"composer.json"']),
    ]
    code_sample = code[:2000]
    for lang, patterns in heuristics:
        for pat in patterns:
            if re.search(pat, code_sample, re.IGNORECASE):
                return lang
    return None

def analyze_vulnerable_outdated_components(code: str) -> List[Dict]:
    """
    Analyze a dependency file snippet for vulnerable or outdated components.
    Returns a list of dicts: {line, matched, code, message}
    """
    lang = guess_language(code)
    if not lang:
        return [{"error": "Could not automatically detect the language."}]
    detector = VulnerableOutdatedComponentsDetector()
    findings = detector.detect(code, lang)
    if not findings:
        return [{"message": "No vulnerable or outdated components detected."}]
    for f in findings:
        f["message"] = (
            f"Line {f['line']}: Detected vulnerable or outdated component. "
            f"The code \"{f['code']}\" contains \"{f['matched']}\" which may be insecure."
        )
    return findings