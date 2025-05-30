import os
import json
from dotenv import load_dotenv
from flask import Blueprint, render_template, request, jsonify
from .scanner import Top10Scanner
from .models import ScanResult, db

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

    scan_result = ScanResult(
        url=url,
        results=json.dumps(results),
        vulnerable=vulnerable
    )
    db.session.add(scan_result)
    db.session.commit()

    filtered_results = {k: v for k, v in results.items() if k == category} if category else results

    return jsonify({
        'results': filtered_results,
        'vulnerable': vulnerable,
        'ai_summary': results.get('ai_summary')  # <-- Add AI summary here
    })
