import re
from typing import List, Dict

class SecurityMisconfigurationDetector:
    def __init__(self):
        self.PATTERNS = {
            # Debug mode enabled (Python, JS, Java, PHP, Go, config)
            'debug_mode_enabled': re.compile(
                r'(DEBUG\s*=\s*True|debug\s*:\s*true|app\.debug\s*=\s*True|app\.run\(.*debug\s*=\s*True|'
                r'process\.env\.NODE_ENV\s*!==\s*[\'"]production[\'"]|'
                r'process\.env\.DEBUG\s*=\s*true|'
                r'enableDebug\s*=\s*true|'
                r'logLevel\s*:\s*[\'"]debug[\'"]|'
                r'logging\.level\s*=\s*DEBUG|'
                r'php_flag\s+display_errors\s+on|'
                r'display_errors\s*=\s*On|'
                r'GIN_MODE\s*=\s*debug|'
                r'ENV\s*=\s*development|'
                r'ASPNETCORE_ENVIRONMENT\s*=\s*Development|'
                r'ENVIRONMENT\s*=\s*Development|'
                r'ENV\s*:\s*development|'
                r'ENVIRONMENT\s*:\s*development'
                r')', re.IGNORECASE),
            # Directory listing enabled (Apache, Nginx, IIS, Node.js)
            'directory_listing_enabled': re.compile(
                r'(Options\s+Indexes|autoindex\s+on|DirectoryIndex\s+|'
                r'AddDefaultCharset\s+Off|'
                r'Indexes\s+on|'
                r'directory_listing\s*=\s*true|'
                r'directoryListing\s*:\s*true|'
                r'listing\s*:\s*true|'
                r'web\.config.*<directoryBrowse enabled="true"|'
                r'fs\.readdir|'
                r'fs\.readdirSync'
                r')', re.IGNORECASE),
            # Default/weak passwords
            'default_password': re.compile(
                r'(password\s*=\s*[\'"](admin|password|123456|root|test|guest)[\'"]|'
                r'pass\s*:\s*[\'"](admin|password|123456|root|test|guest)[\'"]|'
                r'pwd\s*=\s*[\'"](admin|password|123456|root|test|guest)[\'"]|'
                r'passwd\s*=\s*[\'"](admin|password|123456|root|test|guest)[\'"]|'
                r'login\s*=\s*[\'"](admin|root|test|guest)[\'"]'
                r')', re.IGNORECASE),
            # Exposed admin interfaces (URLs, tools, ports)
            'exposed_admin_interface': re.compile(
                r'(/admin\b|/phpmyadmin\b|/adminer\b|/manage\b|/metrics\b|/actuator\b|'
                r'adminer|phpmyadmin|mongo-express|redis-commander|'
                r':8080\b|:8000\b|:8888\b|:5000\b|:3306\b|:27017\b|:6379\b|:15672\b|'
                r'Jupyter\b|Jenkins\b|Grafana\b|Kibana\b|Prometheus\b|'
                r'admin_panel|admin_dashboard|superuser|root_panel'
                r')', re.IGNORECASE),
            # Unrestricted CORS
            'unrestricted_cors': re.compile(
                r'(Access-Control-Allow-Origin\s*:\s*\*|'
                r'CORS_ORIGIN_ALLOW_ALL\s*=\s*True|'
                r'cors\s*=\s*true|'
                r'allow_origin\s*=\s*\*|'
                r'allowedOrigins\s*:\s*\[?\s*["\']\*["\']\s*\]?|'
                r'origins\s*:\s*\*|'
                r'add_header\s+Access-Control-Allow-Origin\s+\*|'
                r'res\.header\s*\(\s*[\'"]Access-Control-Allow-Origin[\'"]\s*,\s*[\'"]\*[\'"]\s*\)'
                r')', re.IGNORECASE),
            # Insecure headers
            'insecure_headers': re.compile(
                r'(X-Frame-Options\s*:\s*ALLOWALL|'
                r'X-XSS-Protection\s*:\s*0|'
                r'X-Content-Type-Options\s*:\s*none|'
                r'Content-Security-Policy\s*:\s*unsafe-inline|'
                r'add_header\s+X-Frame-Options\s+ALLOWALL|'
                r'add_header\s+X-XSS-Protection\s+0|'
                r'add_header\s+X-Content-Type-Options\s+none'
                r')', re.IGNORECASE),
            # No HTTPS
            'no_https': re.compile(
                r'(http://[^\s\'"]+|'
                r'url\s*=\s*[\'"]http://|'
                r'proxy_pass\s+http://|'
                r'REMOTE_URL\s*=\s*[\'"]http://|'
                r'base_url\s*=\s*[\'"]http://|'
                r'location\s*=\s*[\'"]http://'
                r')', re.IGNORECASE),
            # Insecure cookie
            'insecure_cookie': re.compile(
                r'(Set-Cookie:.*(secure\s*=\s*false|httponly\s*=\s*false|SameSite\s*=\s*None)|'
                r'session\.cookie_secure\s*=\s*False|'
                r'session\.cookie_httponly\s*=\s*False|'
                r'cookie\s*=\s*new\s+Cookie\([^\)]*\)|'
                r'cookie\s*:\s*\{[^\}]*secure\s*:\s*false|'
                r'cookie\s*:\s*\{[^\}]*httpOnly\s*:\s*false'
                r')', re.IGNORECASE),
            # Open S3 bucket or cloud storage
            'open_s3_bucket': re.compile(
                r'("Effect"\s*:\s*"Allow".*"Principal"\s*:\s*\*|'
                r's3:GetObject|'
                r'gsutil\s+acl\s+ch\s+-u\s+AllUsers:READ|'
                r'cloudfront\.net|'
                r'blob\.core\.windows\.net|'
                r'public-read|'
                r'publicly accessible'
                r')', re.IGNORECASE),
            # World-writable files/dirs
            'world_writable': re.compile(
                r'(chmod\s+[0-7]*7[0-7][0-7]|chmod\s+777|'
                r'chmod\s+-R\s+777|'
                r'attrib\s+\+w|'
                r'os\.chmod\s*\(.*0o777\)|'
                r'fs\.chmodSync\s*\(.*777\)'
                r')', re.IGNORECASE),
            # Sensitive files exposed
            'sensitive_files_exposed': re.compile(
                r'(\.env|\.git|\.svn|\.hg|\.DS_Store|\.bash_history|\.ssh/|\.aws/|\.azure/|\.gcp/|'
                r'wp-config\.php|config\.php|settings\.py|settings\.js|database\.yml|'
                r'backup|\.bak|\.old|\.swp|\.tmp|\.log|\.pem|\.key|\.crt|\.pfx|\.asc|\.kdbx|\.ldb|\.sqlite|\.db)'
                r'(\s|$|/)', re.IGNORECASE),
            # Dangerous HTTP methods enabled
            'dangerous_http_methods': re.compile(
                r'(Allow:\s*(GET|POST|PUT|DELETE|OPTIONS|HEAD|TRACE|CONNECT|PATCH|PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK|SEARCH|REPORT|MKACTIVITY|CHECKOUT|MERGE|M-SEARCH|NOTIFY|SUBSCRIBE|UNSUBSCRIBE|PURGE|LINK|UNLINK|VIEW|TRACK|DEBUG|TRACE))',
                re.IGNORECASE),
            # Unprotected management endpoints
            'unprotected_management_endpoints': re.compile(
                r'(/actuator\b|/manage\b|/metrics\b|/health\b|/info\b|/admin\b|/console\b|/debug\b|/status\b|/dump\b|/trace\b|/beans\b|/env\b|/configprops\b|/loggers\b|/mappings\b|/threaddump\b|/heapdump\b|/jolokia\b|/prometheus\b)',
                re.IGNORECASE),
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

def analyze_security_misconfiguration(code: str) -> List[Dict]:
    """
    Analyze a code/config snippet for security misconfiguration vulnerabilities.
    Returns a list of dicts: {description, line, code, message}
    """
    detector = SecurityMisconfigurationDetector()
    findings = detector.detect(code)
    if not findings:
        return [{"message": "No security misconfiguration vulnerabilities detected."}]
    for f in findings:
        f["message"] = (
            f"Line {f['line']}: Detected {f['description'].replace('_', ' ')} issue. "
            f"The code \"{f['code']}\" may indicate a security misconfiguration."
        )
    return findings