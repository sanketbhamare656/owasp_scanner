import re
from typing import List, Dict, Tuple, Optional

class CryptoFailureDetector:
    def __init__(self):
        self.PATTERNS: Dict[str, Dict[str, List[re.Pattern]]] = {
            'js': {
                'weak_algorithms': [
                    re.compile(r'crypto\.createHash\s*\(\s*[\'"](md5|sha1)[\'"]', re.IGNORECASE),
                    re.compile(r'crypto\.createCipheriv?\s*\(\s*[\'"](des|rc4|ecb)[\'"]', re.IGNORECASE),
                ],
                'hardcoded_secret': [
                    re.compile(r'(secret|key|password|token)\s*[:=]\s*[\'"][^\'"]{8,}[\'"]', re.IGNORECASE),
                ],
                'insecure_random': [
                    re.compile(r'Math\.random\s*\(', re.IGNORECASE),
                ],
                'base64_as_encryption': [
                    re.compile(r'\.toString\s*\(\s*[\'"]base64[\'"]\s*\)', re.IGNORECASE),
                ],
                'insecure_library': [
                    re.compile(r'require\s*\(\s*[\'"]crypto-js/md5[\'"]\s*\)', re.IGNORECASE),
                ]
            },
            'java': {
                'weak_algorithms': [
                    re.compile(r'MessageDigest\.getInstance\s*\(\s*[\'"](MD5|SHA1)[\'"]', re.IGNORECASE),
                    re.compile(r'Cipher\.getInstance\s*\(\s*[\'"](DES|RC4|ECB)[^\'"]*[\'"]', re.IGNORECASE),
                ],
                'hardcoded_secret': [
                    re.compile(r'(String\s+)?(secret|key|password|token)\s*=\s*[\'"][^\'"]{8,}[\'"]', re.IGNORECASE),
                ],
                'insecure_random': [
                    re.compile(r'new\s+Random\s*\(', re.IGNORECASE),
                ],
                'insecure_library': [
                    re.compile(r'import\s+org\.apache\.commons\.codec\.digest\.DigestUtils', re.IGNORECASE),
                ]
            },
            'go': {
                'weak_algorithms': [
                    re.compile(r'md5\.New\(', re.IGNORECASE),
                    re.compile(r'sha1\.New\(', re.IGNORECASE),
                    re.compile(r'des\.NewCipher\(', re.IGNORECASE),
                    re.compile(r'rc4\.NewCipher\(', re.IGNORECASE),
                ],
                'hardcoded_secret': [
                    re.compile(r'(secret|key|password|token)\s*:=\s*[\'"][^\'"]{8,}[\'"]', re.IGNORECASE),
                ],
                'insecure_random': [
                    re.compile(r'rand\.Intn\(', re.IGNORECASE),
                    re.compile(r'rand\.Int\(', re.IGNORECASE),
                ]
            },
            'py': {
                'weak_algorithms': [
                    re.compile(r'hashlib\.(md5|sha1)\s*\(', re.IGNORECASE),
                    re.compile(r'DES\.new\(', re.IGNORECASE),
                    re.compile(r'ARC4\.new\(', re.IGNORECASE),
                    re.compile(r'Crypto\.Cipher\.DES', re.IGNORECASE),
                    re.compile(r'Crypto\.Cipher\.ARC4', re.IGNORECASE),
                ],
                'hardcoded_secret': [
                    re.compile(r'(secret|key|password|token)\s*=\s*[\'"][^\'"]{8,}[\'"]', re.IGNORECASE),
                ],
                'insecure_random': [
                    re.compile(r'random\.random\s*\(', re.IGNORECASE),
                    re.compile(r'random\.randint\s*\(', re.IGNORECASE),
                ],
                'insecure_library': [
                    re.compile(r'import\s+md5', re.IGNORECASE),
                ]
            },
            'php': {
                'weak_algorithms': [
                    re.compile(r'md5\s*\(', re.IGNORECASE),
                    re.compile(r'sha1\s*\(', re.IGNORECASE),
                    re.compile(r'openssl_encrypt\s*\(\s*.*[\'"](des|rc4|ecb)[\'"]', re.IGNORECASE),
                ],
                'hardcoded_secret': [
                    re.compile(r'\$(secret|key|password|token)\s*=\s*[\'"][^\'"]{8,}[\'"]', re.IGNORECASE),
                ],
                'insecure_random': [
                    re.compile(r'rand\s*\(', re.IGNORECASE),
                    re.compile(r'mt_rand\s*\(', re.IGNORECASE),
                ]
            }
        }

        self.IGNORE_CONTEXT = [
            re.compile(r'//\s*not\s*for\s*production', re.IGNORECASE),
            re.compile(r'#\s*not\s*for\s*production', re.IGNORECASE),
            re.compile(r'//\s*test', re.IGNORECASE),
            re.compile(r'#\s*test', re.IGNORECASE),
            re.compile(r'@Test', re.IGNORECASE),
            re.compile(r'function\s+test', re.IGNORECASE),
        ]

    def is_ignored_context(self, line: str) -> bool:
        return any(p.search(line) for p in self.IGNORE_CONTEXT)

    def detect(self, code: str, lang: str) -> List[Dict]:
        findings = []
        patterns = self.PATTERNS.get(lang, {})
        lines = code.splitlines()
        for idx, line in enumerate(lines, 1):
            if self.is_ignored_context(line):
                continue
            for category, regex_list in patterns.items():
                for pattern in regex_list:
                    for match in pattern.finditer(line):
                        findings.append({
                            "description": category,
                            "line": idx,
                            "matched": match.group(),
                            "code": line.strip()
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

def analyze_crypto_failure(code: str) -> List[Dict]:
    """
    Analyze a code snippet for cryptographic failure vulnerabilities.
    Returns a list of dicts: {description, line, matched, code, message}
    """
    lang = guess_language(code)
    if not lang:
        return [{"error": "Could not automatically detect the language."}]
    detector = CryptoFailureDetector()
    findings = detector.detect(code, lang)
    if not findings:
        return [{"message": "No cryptographic vulnerabilities detected."}]
    for f in findings:
        f["message"] = (
            f"Line {f['line']}: Detected {f['description'].replace('_', ' ')} issue. "
            f"The code \"{f['code']}\" contains \"{f['matched']}\" which may be insecure."
        )
    return findings