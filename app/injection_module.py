import re
from typing import List, Dict, Tuple, Optional

class InjectionDetector:
    def __init__(self):
        self.PATTERNS: Dict[str, Dict[str, List[re.Pattern]]] = {
            'js': {
                'sql_injection': [
                    re.compile(r'\.query\s*\(\s*["\'].*\+.*["\']', re.IGNORECASE),
                    re.compile(r'execute\s*\(\s*["\'].*\+.*["\']', re.IGNORECASE),
                    re.compile(r'`.*\$\{.*req\..*?\}.*`', re.IGNORECASE),
                    re.compile(r'\.query\s*\(\s*\w+\s*\)', re.IGNORECASE),  # .query(variable)
                ],
                'command_injection': [
                    re.compile(r'child_process\.exec\s*\(', re.IGNORECASE),
                    re.compile(r'child_process\.execSync\s*\(', re.IGNORECASE),
                    re.compile(r'child_process\.spawn\s*\(', re.IGNORECASE),
                    re.compile(r'child_process\.\w+\s*\(\s*\w+\s*\)', re.IGNORECASE),  # exec(variable)
                ],
                'eval_injection': [
                    re.compile(r'eval\s*\(', re.IGNORECASE),
                    re.compile(r'Function\s*\(', re.IGNORECASE),
                ],
                'nosql_injection': [
                    # MongoDB/Mongoose patterns
                    re.compile(r'\.find\s*\(\s*\{[^}]*req\.(body|query|params)\.[^}]*\}\s*\)', re.IGNORECASE),
                    re.compile(r'\.findOne\s*\(\s*\{[^}]*req\.(body|query|params)\.[^}]*\}\s*\)', re.IGNORECASE),
                    re.compile(r'\.find\s*\(\s*\w+\s*\)', re.IGNORECASE),  # .find(variable)
                    re.compile(r'\.findOne\s*\(\s*\w+\s*\)', re.IGNORECASE),  # .findOne(variable)
                    re.compile(r'\.find\s*\(\s*\{[^}]*userInput[^}]*\}\s*\)', re.IGNORECASE),
                    re.compile(r'\.findOne\s*\(\s*\{[^}]*userInput[^}]*\}\s*\)', re.IGNORECASE),
                    # Generic: any find/findOne with object containing req.body/req.query/req.params
                    re.compile(r'\.find(?:One)?\s*\(\s*\{[^}]*\b(req|userInput)\b[^}]*\}\s*\)', re.IGNORECASE),
                ]
            },
            'java': {
                'sql_injection': [
                    re.compile(r'Statement\s+\w+\s*=\s*conn\.createStatement\s*\(', re.IGNORECASE),
                    re.compile(r'executeQuery\s*\(\s*".*"\s*\+\s*\w+', re.IGNORECASE),
                    re.compile(r'prepareStatement\s*\(\s*".*"\s*\+\s*\w+', re.IGNORECASE),
                    re.compile(r'executeQuery\s*\(\s*\w+\s*\)', re.IGNORECASE),  # executeQuery(variable)
                ],
                'command_injection': [
                    re.compile(r'Runtime\.getRuntime\(\)\.exec\s*\(', re.IGNORECASE),
                    re.compile(r'ProcessBuilder\s*\(', re.IGNORECASE),
                    re.compile(r'Runtime\.getRuntime\(\)\.exec\s*\(\s*\w+\s*\)', re.IGNORECASE),  # exec(variable)
                ],
                'eval_injection': [
                    re.compile(r'ScriptEngineManager', re.IGNORECASE),
                ],
                'nosql_injection': [
                    re.compile(r'getCollection\s*\(\s*".*"\s*\)\.find\s*\(\s*\w+\s*\)', re.IGNORECASE),
                    re.compile(r'find\s*\(\s*\w+\s*\)', re.IGNORECASE),
                ]
            },
            'go': {
                'sql_injection': [
                    re.compile(r'Db\.Query\s*\(\s*".*"\s*\+\s*\w+', re.IGNORECASE),
                    re.compile(r'Db\.Exec\s*\(\s*".*"\s*\+\s*\w+', re.IGNORECASE),
                    re.compile(r'Db\.(Query|Exec)\s*\(\s*\w+\s*\)', re.IGNORECASE),  # Query(variable)
                ],
                'command_injection': [
                    re.compile(r'exec\.Command\s*\(', re.IGNORECASE),
                    re.compile(r'exec\.Command\s*\(\s*\w+\s*\)', re.IGNORECASE),  # exec.Command(variable)
                ],
                'nosql_injection': [
                    re.compile(r'Find\s*\(\s*\w+\s*\)', re.IGNORECASE),
                ]
            },
            'py': {
                'sql_injection': [
                    re.compile(r'execute\s*\(\s*f?["\'].*\+.*["\']', re.IGNORECASE),
                    re.compile(r'execute\s*\(\s*f?["\'].*%s.*["\']\s*%', re.IGNORECASE),
                    re.compile(r'cursor\.execute\s*\(\s*request\.', re.IGNORECASE),
                    re.compile(r'execute\s*\(\s*\w+\s*\)', re.IGNORECASE),  # cursor.execute(query)
                    re.compile(r'["\']\s*%\s*\w+', re.IGNORECASE),          # "..." % var
                    re.compile(r'f["\'].*{.*}.*["\']', re.IGNORECASE),      # f"...{...}..."
                ],
                'command_injection': [
                    re.compile(r'os\.system\s*\(', re.IGNORECASE),
                    re.compile(r'subprocess\.Popen\s*\(', re.IGNORECASE),
                    re.compile(r'subprocess\.call\s*\(', re.IGNORECASE),
                    re.compile(r'subprocess\.run\s*\(', re.IGNORECASE),
                    re.compile(r'os\.system\s*\(\s*\w+\s*\)', re.IGNORECASE),  # os.system(variable)
                ],
                'eval_injection': [
                    re.compile(r'eval\s*\(', re.IGNORECASE),
                    re.compile(r'exec\s*\(', re.IGNORECASE),
                ],
                'nosql_injection': [
                    re.compile(r'find\s*\(\s*request\.(GET|POST|args|form)\.', re.IGNORECASE),
                    re.compile(r'find\s*\(\s*\w+\s*\)', re.IGNORECASE),  # find(variable)
                    re.compile(r'find_one\s*\(\s*\w+\s*\)', re.IGNORECASE),  # find_one(variable)
                ]
            },
            'php': {
                'sql_injection': [
                    re.compile(r'mysql_query\s*\(\s*".*"\s*\.\s*\$_(GET|POST|REQUEST)', re.IGNORECASE),
                    re.compile(r'pg_query\s*\(\s*".*"\s*\.\s*\$_(GET|POST|REQUEST)', re.IGNORECASE),
                    re.compile(r'".*"\s*\.\s*\$_(GET|POST|REQUEST)', re.IGNORECASE),
                    re.compile(r'mysql_query\s*\(\s*\$[a-zA-Z_][a-zA-Z0-9_]*\s*\)', re.IGNORECASE),  # mysql_query($var)
                    re.compile(r'pg_query\s*\(\s*\$[a-zA-Z_][a-zA-Z0-9_]*\s*\)', re.IGNORECASE),     # pg_query($var)
                ],
                'command_injection': [
                    re.compile(r'system\s*\(', re.IGNORECASE),
                    re.compile(r'passthru\s*\(', re.IGNORECASE),
                    re.compile(r'shell_exec\s*\(', re.IGNORECASE),
                    re.compile(r'`.*\$_(GET|POST|REQUEST).*`', re.IGNORECASE),
                    re.compile(r'system\s*\(\s*\$[a-zA-Z_][a-zA-Z0-9_]*\s*\)', re.IGNORECASE),  # system($var)
                ],
                'eval_injection': [
                    re.compile(r'eval\s*\(', re.IGNORECASE),
                    re.compile(r'create_function\s*\(', re.IGNORECASE),
                ],
                'nosql_injection': [
                    re.compile(r'find\s*\(\s*\$_(GET|POST|REQUEST)', re.IGNORECASE),
                    re.compile(r'find\s*\(\s*\$[a-zA-Z_][a-zA-Z0-9_]*\s*\)', re.IGNORECASE),  # find($var)
                    re.compile(r'findOne\s*\(\s*\$[a-zA-Z_][a-zA-Z0-9_]*\s*\)', re.IGNORECASE),  # findOne($var)
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

def analyze_injection(code: str) -> List[Dict]:
    """
    Analyze a code snippet for injection vulnerabilities.
    Returns a list of dicts: {description, line, matched, code, message}
    """
    lang = guess_language(code)
    if not lang:
        return [{"error": "Could not automatically detect the language."}]
    detector = InjectionDetector()
    findings = detector.detect(code, lang)
    if not findings:
        return [{"message": "No injection vulnerabilities detected."}]
    for f in findings:
        f["message"] = (
            f"Line {f['line']}: Detected {f['description'].replace('_', ' ')} vulnerability. "
            f"The code \"{f['code']}\" contains \"{f['matched']}\" which may be insecure."
        )
    return findings