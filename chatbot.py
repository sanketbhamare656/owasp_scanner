from flask import Blueprint, request, jsonify
from duckduckgo_search import DDGS
from config import model  # Import configured Gemini API
import time
import re

chatbot_bp = Blueprint("chatbot", __name__)

CYBER_SECURITY_CONTEXT = """
You are CyberGuard, an empathetic cybersecurity expert assistant with specialization in OWASP Top 10 vulnerabilities. Your role is to:
1. Help users identify and understand OWASP Top 10 vulnerabilities in web applications
2. Analyze code snippets for common security flaws
3. Explain vulnerabilities in simple terms with remediation advice
4. Provide guidance on secure coding practices
5. Be friendly, simple, and human-like in replies
6. Avoid technical jargon unless specifically asked for details
"""

OWASP_TOP_10_2023 = """
OWASP Top 10 2023 Vulnerabilities:
1. Broken Access Control
2. Cryptographic Failures
3. Injection
4. Insecure Design
5. Security Misconfiguration
6. Vulnerable and Outdated Components
7. Identification and Authentication Failures
8. Software and Data Integrity Failures
9. Security Logging and Monitoring Failures
10. Server-Side Request Forgery (SSRF)
"""

def is_greeting(message):
    return message.lower() in ["hi", "hello", "hey"]

def is_security_related(query):
    prompt = f"""Is this query about cybersecurity, OWASP, web vulnerabilities, or code security? 
    Answer only yes/no. Query: {query}"""
    try:
        response = model.generate_content(prompt)
        return "yes" in response.text.lower()
    except Exception as e:
        print(f"Error checking query: {e}")
        return False

def analyze_code_snippet(code):
    """Analyze code snippets for common OWASP Top 10 vulnerabilities"""
    vulnerabilities = []
    
    # Check for SQL Injection
    if re.search(r"SELECT.*FROM.*WHERE.*\+\s*request\.getParameter", code, re.I):
        vulnerabilities.append(("SQL Injection", "Concatenating user input directly in SQL queries"))
    
    # Check for XSS
    if re.search(r"innerHTML\s*=\s*.*user.*input", code, re.I):
        vulnerabilities.append(("Cross-Site Scripting (XSS)", "Unsanitized user input being rendered in HTML"))
    
    # Check for hardcoded credentials
    if re.search(r"password\s*=\s*['\"].+?['\"]", code, re.I):
        vulnerabilities.append(("Hardcoded Credentials", "Sensitive information stored directly in code"))
    
    # Check for CORS misconfiguration
    if re.search(r"Access-Control-Allow-Origin\s*:\s*\*", code, re.I):
        vulnerabilities.append(("Security Misconfiguration", "Overly permissive CORS policy with wildcard (*)"))
    
    # Check for SSRF patterns
    if re.search(r"new\s+URL\(.*user.*input\)", code, re.I):
        vulnerabilities.append(("Server-Side Request Forgery (SSRF)", "User input used directly in URL construction"))
    
    return vulnerabilities

def generate_response(query):
    try:
        if is_greeting(query):
            return "Hello! I am CyberGuard, your OWASP security assistant. How can I help you with web application security today?"

        if not is_security_related(query):
            return "I specialize in OWASP Top 10 vulnerabilities and web application security. Please ask something in this domain."

        # Check if the query contains code snippet
        if "```" in query:
            code_part = query.split("```")[1]
            vulnerabilities = analyze_code_snippet(code_part)
            
            if vulnerabilities:
                response = ["I found potential vulnerabilities in your code:"]
                for vuln, desc in vulnerabilities:
                    response.append(f"\n🔴 {vuln}: {desc}")
                response.append("\nWould you like remediation advice for any of these?")
                return "\n".join(response)
            else:
                return "I didn't find obvious OWASP Top 10 vulnerabilities in this code snippet. Would you like me to check something specific?"

        # Handle OWASP Top 10 general queries
        if "owasp top 10" in query.lower():
            return OWASP_TOP_10_2023 + "\n\nWhich vulnerability would you like to know more about?"

        # Handle specific vulnerability queries
        chat = model.start_chat(history=[])
        response = chat.send_message(
            f"{CYBER_SECURITY_CONTEXT}\nCurrent OWASP Top 10:\n{OWASP_TOP_10_2023}\n\n"
            f"User Query: {query}\n"
            "Reply in plain simple text (max 5 lines). "
            "For code issues, provide specific remediation steps."
        )

        response_text = response.text.strip()
        time.sleep(1)  # Simulate typing delay
        return response_text
    
    except Exception as e:
        print(f"Error generating response: {e}")
        return "Something went wrong while analyzing your query. Please try again later."

@chatbot_bp.route("/respond", methods=["POST"])
def chatbot_respond():
    data = request.get_json()
    user_message = data.get("message", "").strip()

    if not user_message:
        return jsonify({"response": "Please enter a valid query."}), 400

    response = generate_response(user_message)
    return jsonify({"response": response})