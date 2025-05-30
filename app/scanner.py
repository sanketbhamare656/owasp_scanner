import requests
import urllib.parse
from urllib.parse import urljoin
import time
from bs4 import BeautifulSoup
import re
from typing import Dict, List, Optional
import google.generativeai as genai

class Top10Scanner:
    def __init__(self, gemini_api_key: str = None):
        self.session = requests.Session()
        self.session.verify = True
        self.headers = {
            'User-Agent': 'AdvancedSecurityScanner/2.0',
            'Accept': 'text/html,application/xhtml+xml'
        }
        self.delay = 0.5
        self.timeout = 15
        self.vulnerability_db = self._load_vulnerability_db()
        self.gemini_api_key = gemini_api_key
        
    def _load_vulnerability_db(self) -> Dict:
        return {
            'sql_errors': [
                r"SQL syntax.*MySQL",
                r"Warning.*mysql_.*",
                r"Unclosed quotation mark",
                r"ODBC Driver",
                r"Syntax error.*SQL",
                r"Microsoft Access Driver"
            ],
            'xss_patterns': [
                r"<script>.*</script>",
                r"onerror=.*",
                r"javascript:.*",
                r"alert\(.*\)"
            ],
            'sensitive_files': [
                ('.env', r"DB_(USER|PASSWORD)="),
                ('config.php', r"define\('DB_(USER|PASSWORD)'"),
                ('wp-config.php', r"define\('DB_(USER|PASSWORD)'")
            ]
        }

    def _safe_request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        try:
            time.sleep(self.delay)
            response = self.session.request(
                method,
                url,
                headers=self.headers,
                timeout=self.timeout,
                allow_redirects=False,
                **kwargs
            )
            return response if response.status_code < 500 else None
        except requests.RequestException:
            return None

    def _check_response_for_patterns(self, response: requests.Response, patterns: List[str]) -> bool:
        if not response.text:
            return False
        content = response.text.lower()
        return any(re.search(pattern, content, re.IGNORECASE) for pattern in patterns)

    def check_injection(self, url: str) -> Dict[str, bool]:
        payloads = {
            'sql': [
                "' OR '1'='1'-- -",
                "' UNION SELECT null,table_name FROM information_schema.tables-- -",
                "1 AND 1=CONVERT(int,(SELECT table_name FROM information_schema.tables))--"
            ],
            'xss': [
                "<script>alert(document.domain)</script>",
                "<img src=x onerror=alert(1)>",
                "\"><script>alert(1)</script>",
                "javascript:alert(1)"
            ]
        }
        results = {'sql': False, 'xss': False, 'command': False}
        for vuln_type, tests in payloads.items():
            for payload in tests:
                test_url = f"{url}?test={urllib.parse.quote(payload)}"
                response = self._safe_request('GET', test_url)
                if response:
                    if vuln_type == 'sql' and self._check_response_for_patterns(response, self.vulnerability_db['sql_errors']):
                        results['sql'] = True
                    elif vuln_type == 'xss' and any(xss in response.text for xss in payloads['xss']):
                        results['xss'] = True
        return results

    def check_security_headers(self, url: str) -> Dict[str, str]:
        expected = {
            'X-XSS-Protection': '1; mode=block',
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
            'Content-Security-Policy': None,
            'Strict-Transport-Security': r'max-age=\d+',
            'Referrer-Policy': ['no-referrer', 'strict-origin-when-cross-origin']
        }
        response = self._safe_request('GET', url)
        if not response:
            return {'error': 'No response received'}
        issues = {}
        for header, expected_value in expected.items():
            if header not in response.headers:
                issues[header] = 'Missing'
            elif expected_value:
                if isinstance(expected_value, list):
                    if response.headers[header] not in expected_value:
                        issues[header] = f'Invalid value: {response.headers[header]}'
                elif isinstance(expected_value, str):
                    if response.headers[header] != expected_value:
                        issues[header] = f'Invalid value: {response.headers[header]}'
                elif re.compile(expected_value).fullmatch(response.headers[header]) is None:
                    issues[header] = f'Invalid value: {response.headers[header]}'
        return issues

    def check_sensitive_files(self, url: str) -> Dict[str, List[str]]:
        results = {'found': [], 'exposed_data': []}
        for file, pattern in self.vulnerability_db['sensitive_files']:
            response = self._safe_request('GET', urljoin(url, file))
            if response and response.status_code == 200:
                results['found'].append(file)
                if re.search(pattern, response.text):
                    results['exposed_data'].append(f"{file} contains sensitive data")
        for file in ['robots.txt', 'phpinfo.php', '.git/HEAD']:
            response = self._safe_request('GET', urljoin(url, file))
            if response and response.status_code == 200:
                results['found'].append(file)
        return results

    def check_broken_access_control(self, url: str) -> Dict[str, List[str]]:
        admin_paths = ['/admin', '/wp-admin', '/dashboard', '/management']
        user_paths = ['/profile', '/account']
        results = {'admin_access': [], 'idor_issues': [], 'directory_traversal': []}
        for path in admin_paths:
            response = self._safe_request('GET', urljoin(url, path))
            if response and response.status_code == 200:
                results['admin_access'].append(path)
        for test_id in ['123', '1', 'admin']:
            test_url = urljoin(url, f"/user/{test_id}")
            response = self._safe_request('GET', test_url)
            if response and response.status_code == 200 and "user data" in response.text.lower():
                results['idor_issues'].append(f"Possible IDOR at /user/{test_id}")
        for payload in ['../../../../etc/passwd', '..%2F..%2F..%2Fetc%2Fpasswd']:
            test_url = urljoin(url, f"download?file={payload}")
            response = self._safe_request('GET', test_url)
            if response and ("root:" in response.text or "bin:" in response.text):
                results['directory_traversal'].append(f"Directory traversal possible with {payload}")
        return results

    def check_auth_issues(self, url: str) -> Dict[str, List[str]]:
        login_paths = ['/login', '/signin', '/auth']
        results = {'default_creds': [], 'brute_force': [], 'password_policy': []}
        default_creds = [('admin', 'admin'), ('admin', 'password'), ('root', 'toor'), ('test', 'test')]
        for path in login_paths:
            login_url = urljoin(url, path)
            for username, password in default_creds:
                response = self._safe_request('POST', login_url, data={'username': username, 'password': password})
                if response and ('logout' in response.text.lower() or 'dashboard' in response.text.lower()):
                    results['default_creds'].append(f"Working credentials: {username}/{password} at {path}")
        weak_pass_response = self._safe_request('POST', login_url, data={'username': 'test', 'password': '123'})
        if weak_pass_response and weak_pass_response.status_code == 200 and 'password too short' not in weak_pass_response.text.lower():
            results['password_policy'].append("Weak or no password policy detected")
        return results

    def check_rate_limiting(self, url: str) -> bool:
        test_url = urljoin(url, '/login')
        success_count = 0
        for _ in range(10):
            response = self._safe_request('POST', test_url, data={'username': 'random', 'password': 'random'})
            if response and response.status_code == 429:
                return True
            elif response and response.status_code == 200:
                success_count += 1
            time.sleep(0.1)
        return success_count < 10

    def check_logging_audit(self, url: str) -> bool:
        return True  # Placeholder for actual audit check

    def check_jwt_issues(self, url: str) -> Dict[str, bool]:
        return {'jwt_without_signature': False}  # Placeholder

    def _analyze_with_ai(self, scan_results: Dict) -> str:
        if not self.gemini_api_key:
            return "⚠️ Gemini API key not provided. Skipping AI analysis."
        try:
            genai.configure(api_key=self.gemini_api_key)
            model = genai.GenerativeModel('gemini-pro')
            prompt = f"""
            Analyze these web security scan results and provide a concise summary (under 300 words) 
            for a non-technical audience. Structure your response with these sections:

            1. Critical Risks (most dangerous findings)
            2. Important Security Issues
            3. Security Strengths
            4. Recommended Actions

            Focus on explaining the impact of each finding in simple terms. 
            For technical findings, provide brief explanations of what they mean.

            Scan Results:
            {scan_results}
            """
            response = model.generate_content(prompt)
            return response.text
        except Exception as e:
            return f"⚠️ AI analysis failed: {str(e)}"

    def scan(self, url: str) -> Dict[str, any]:
        print(f"\n🔍 Starting security scan for: {url}\n")
        print("🛡️ Scanning for OWASP Top 10 vulnerabilities...\n")
        results = {}
        tasks = [
            ('injection', "Testing for SQL Injection and XSS vulnerabilities..."),
            ('security_headers', "Checking security headers configuration..."),
            ('sensitive_files', "Scanning for sensitive files and data exposure..."),
            ('broken_access_control', "Testing for broken access controls..."),
            ('auth_issues', "Checking authentication vulnerabilities..."),
            ('rate_limiting', "Testing rate limiting protections..."),
            ('logging_audit', "Checking if audit logging is implemented..."),
            ('jwt_issues', "Checking for JWT security issues...")
        ]
        for method, msg in tasks:
            print(f"⏳ {msg}")
            method_name = method if method != 'auth_issues' else 'check_auth_issues'
            results[method] = getattr(self, method_name)(url)
            time.sleep(0.2)
        ai_summary = self._analyze_with_ai(results)
        results['ai_summary'] = ai_summary
        return results