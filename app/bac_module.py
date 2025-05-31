import re
from typing import List, Dict, Optional

class BACDetector:
    def __init__(self):
        self.SECURITY_INDICATORS = {
            'js': [
                r'@RequireAuth', r'@Authenticated', r'requireAuth\(',
                r'isAuthenticated\(', r'checkAuth\(', r'verifyToken\(',
                r'passport\.authenticate', r'jwt\.verify',
                r'middleware.*auth', r'ensureAuthenticated'
            ],
            'java': [
                r'@PreAuthorize', r'@Secured', r'@RolesAllowed',
                r'@EnableGlobalMethodSecurity', r'SecurityContextHolder',
                r'hasRole\(', r'hasAuthority\(', r'@PostAuthorize'
            ],
            'go': [
                r'RequireAuth', r'CheckPermission', r'VerifyToken',
                r'middleware\.Auth', r'jwt\.Parse', r'AuthRequired'
            ],
            'py': [
                r'@login_required', r'@permission_required', r'@user_passes_test',
                r'require_http_methods', r'@staff_member_required',
                r'IsAuthenticated', r'@api_view.*permission_classes'
            ],
            'php': [
                r'Auth::check\(\)', r'Auth::user\(\)', r'middleware.*auth',
                r'can\(', r'authorize\(', r'Gate::allows'
            ]
        }

        self.PATTERNS = {
            'js': {
                'missing_authz_routes': [
                    r'router\.(get|post|put|delete)\s*\(\s*[\'"][^\'"]*(admin|config|settings|dashboard)[^\'"]*[\'"]',
                    r'app\.(get|post|put|delete)\s*\(\s*[\'"][^\'"]*(admin|config|settings|dashboard)[^\'"]*[\'"]',
                ],
                'hardcoded_roles': [
                    r'user\.role\s*===?\s*[\'"](admin|root|superuser)[\'"]',
                    r'role\s*===?\s*[\'"](admin|root|superuser)[\'"]',
                ],
                'insecure_endpoints': [
                    r'[\'\"]/(admin|config|settings|dashboard|users?/\d+|delete)[\'\"]',
                ],
                'direct_object_reference': [
                    r'req\.params\.(id|userId|accountId)',
                    r'findById\s*\(\s*req\.params\.id\s*\)'
                ]
            },
            'java': {
                'missing_authz_methods': [
                    r'@RequestMapping.*(admin|config|settings)',
                    r'@GetMapping.*(admin|config|settings)',
                    r'@PostMapping.*(admin|config|settings)'
                ],
                'hardcoded_roles': [
                    r'user\.getRole\(\)\.equals\s*\(\s*[\'"](ADMIN|ROOT|SUPERUSER)[\'"]',
                    r'hasRole\s*\(\s*[\'"](ADMIN|ROOT|SUPERUSER)[\'"]',
                    r'role\s*==\s*[\'"](ADMIN|ROOT|SUPERUSER)[\'"]'
                ],
                'permit_all_usage': [
                    r'@PermitAll',
                    r'permitAll\(\)'
                ],
                'direct_object_reference': [
                    r'@PathVariable.*(id|userId|accountId)',
                    r'findById\s*\(\s*\w*[Ii]d\s*\)'
                ]
            },
            'go': {
                'missing_authz_handlers': [
                    r'func\s+\w*(Admin|Config|Settings|Dashboard)\w*\s*\([^)]*\)\s*{',
                    r'http\.HandleFunc\s*\(\s*[\'"][^\'"]*(admin|config|settings)[^\'"]*[\'"]'
                ],
                'hardcoded_roles': [
                    r'user\.Role\s*==\s*[\'"](admin|root|superuser)[\'"]',
                    r'role\s*:=\s*[\'"](admin|root|superuser)[\'"]'
                ],
                'direct_object_reference': [
                    r'mux\.Vars\s*\(\s*r\s*\)\s*\[\s*[\'"]id[\'"]',
                    r'r\.URL\.Query\(\)\.Get\s*\(\s*[\'"](id|userId)[\'"]'
                ]
            },
            'py': {
                'missing_authz_views': [
                    r'def\s+\w*(admin|config|settings|dashboard)\w*\s*\([^)]*\):',
                    r'@app\.route\s*\(\s*[\'"][^\'"]*(admin|config|settings)[^\'"]*[\'"]'
                ],
                'hardcoded_roles': [
                    r'user\.role\s*==\s*[\'"](admin|root|superuser)[\'"]',
                    r'if\s+user\.is_(admin|superuser|staff)'
                ],
                'django_permit_all': [
                    r'permission_classes\s*=\s*\[\s*AllowAny\s*\]',
                    r'@permission_classes\s*\(\s*\[\s*AllowAny\s*\]\s*\)'
                ],
                'direct_object_reference': [
                    r'get_object_or_404\s*\(\s*\w+\s*,\s*pk\s*=\s*\w+',
                    r'\.objects\.get\s*\(\s*id\s*=\s*request\..*\.get\s*\(\s*[\'"]id[\'"]',
                    # NEW: generic pattern for Flask routes exposing IDs
                    r'@app\.route\s*\(\s*[\'"][^\'"]*<.*id.*>[\'"]'
                ]
            },
            'php': {
                'missing_authz_routes': [
                    r'Route::(get|post|put|delete)\s*\(\s*[\'"][^\'"]*(admin|config|settings|dashboard)[^\'"]*[\'"]',
                ],
                'hardcoded_roles': [
                    r'if\s*\(\s*\$user->role\s*==\s*[\'"](admin|root|superuser)[\'"]\s*\)',
                ],
                'direct_object_reference': [
                    r'\$_(GET|POST)\s*\[\s*[\'"](id|userId|accountId)[\'"]\s*\]',
                    r'find\(\s*\$request->input\s*\(\s*[\'"](id|userId)[\'"]\s*\)\s*\)'
                ]
            }
        }

    def detect(self, code: str, lang: str) -> List[Dict]:
        findings = []
        patterns = self.PATTERNS.get(lang, {})
        indicators = self.SECURITY_INDICATORS.get(lang, [])
        
        lines = code.split('\n')
        for category, regex_list in patterns.items():
            for pattern in regex_list:
                for match in re.finditer(pattern, code, re.IGNORECASE):
                    line_number = code[:match.start()].count('\n') + 1
                    
                    # Grab a few lines before the match to check for auth indicators
                    context_start_line = max(0, line_number - 6)
                    context_end_line = min(len(lines), line_number + 1)
                    context = '\n'.join(lines[context_start_line:context_end_line])
                    
                    secure = any(re.search(ind, context, re.IGNORECASE) for ind in indicators)
                    if not secure:
                        findings.append({
                            "line": line_number,
                            "description": category,
                            "code": match.group().strip()
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


def analyze_code(code: str) -> List[Dict]:
    lang = guess_language(code)
    if not lang:
        return [{"error": "Could not automatically detect the programming language."}]
    detector = BACDetector()
    findings = detector.detect(code, lang)
    if not findings:
        return [{"message": "No BAC issues detected."}]
    for f in findings:
        f["message"] = (
            f"Line {f['line']}: Detected {f['description'].replace('_', ' ')} issue. "
            f"The code \"{f['code']}\" may indicate a broken access control vulnerability."
        )
    return findings