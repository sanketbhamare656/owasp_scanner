import os
import json
from dotenv import load_dotenv
from flask import Blueprint, render_template, request, jsonify
from .scanner import Top10Scanner
from .models import ScanResult, db
from .bac_module import analyze_code as analyze_bac
from .ssrf_module import analyze_ssrf
from .insecure_design_module import analyze_insecure_design
from .crypto_failure_module import analyze_crypto_failure
from .auth_failure_module import analyze_auth_failure
from .injection_module import analyze_injection
from .logging_monitoring_module import analyze_logging_monitoring
from .software_data_integrity_module import analyze_software_data_integrity
from .vulnerable_outdated_components_module import analyze_vulnerable_outdated_components
from .security_misconfiguration_module import analyze_security_misconfiguration

load_dotenv()  # Load environment variables from .env

bp = Blueprint('routes', __name__)


@bp.route('/')
def index():
    return render_template('index.html')


@bp.route('/services')
def services():
    return render_template('services.html')


@bp.route("/chat")
def chat():
    """Render the Chatbot page."""
    return render_template("chat.html")


@bp.route('/api/chat', methods=['POST'])
def chat_api():
    data = request.get_json()
    user_message = data.get('message')

    # For now, echo back the message or integrate your AI model here
    response_text = f"Echo: {user_message}"

    return jsonify({'response': response_text})


@bp.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    url = data.get('url')
    category = data.get('category')

    if not url:
        return jsonify({'error': 'URL is required'}), 400

    gemini_api_key = os.getenv('GEMINI_API_KEY')
    scanner = Top10Scanner(gemini_api_key=gemini_api_key)
    results = scanner.scan(url)

    def is_vulnerable(scan_results):

        def flatten(d):
            for v in d.values():
                if isinstance(v, dict):
                    yield from flatten(v)
                elif isinstance(v, list):
                    for item in v:
                        if item:
                            yield item
                else:
                    yield v

        return any(bool(x) for x in flatten(scan_results))

    vulnerable = is_vulnerable(results)

    scan_result = ScanResult(url=url,
                             results=json.dumps(results),
                             vulnerable=vulnerable)
    db.session.add(scan_result)
    db.session.commit()

    filtered_results = {
        k: v
        for k, v in results.items() if k == category
    } if category else results

    return jsonify({
        'results': filtered_results,
        'vulnerable': vulnerable,
        'ai_summary': results.get('ai_summary')  # <-- Add AI summary here
    })


VULN_OPTIONS = [
    ("bac", "Broken Access Control (BAC)"),
    ("ssrf", "Server-Side Request Forgery (SSRF)"),
    ("insecure_design", "Insecure Design"),
    ("crypto_failure", "Cryptographic Failures"),
    ("auth_failure", "Identification & Authentication Failures"),
    ("injection", "Injection"),
    ("logging_monitoring", "Logging & Monitoring Failures"),
    ("software_data_integrity", "Software & Data Integrity Failures"),
    ("vulnerable_outdated_components", "Vulnerable & Outdated Components"),
    ("security_misconfiguration", "Security Misconfiguration"),
]

DETECTOR_MAP = {
    "bac": analyze_bac,
    "ssrf": analyze_ssrf,
    "insecure_design": analyze_insecure_design,
    "crypto_failure": analyze_crypto_failure,
    "auth_failure": analyze_auth_failure,
    "injection": analyze_injection,
    "logging_monitoring": analyze_logging_monitoring,
    "software_data_integrity": analyze_software_data_integrity,
    "vulnerable_outdated_components": analyze_vulnerable_outdated_components,
    "security_misconfiguration": analyze_security_misconfiguration,
}


@bp.route('/manual-scan', methods=["GET", "POST"])
def manual_scan():
    findings = None
    selected = VULN_OPTIONS[0][0]
    code = ""
    if request.method == "POST":
        vuln_type = request.form.get("vuln_type")
        code = request.form.get("code", "")
        selected = vuln_type
        detector = DETECTOR_MAP.get(vuln_type)
        if detector and code.strip():
            try:
                findings = detector(code)
            except Exception as e:
                findings = [{"message": f"Error during analysis: {str(e)}"}]
        else:
            findings = []
    return render_template('manual_scan.html',
                           options=VULN_OPTIONS,
                           findings=findings,
                           selected=selected,
                           code=code)
