# 🔍 OWASP Top 10 Vulnerability Scanner 🛡️  
![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python)
![License](https://img.shields.io/badge/License-MIT-green)
![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-orange)

A powerful, open-source **Web Vulnerability Scanner** that detects issues from the **OWASP Top 10** list — including SQLi, XSS, Broken Access Control, and more! Designed for students, developers, and cybersecurity learners to **understand real-world security flaws** by actively scanning websites and code.

---

## 🚀 Features

- 🔍 **Injection Detection** – Detects SQL and XSS vulnerabilities.
- 🧱 **Security Headers Check** – Flags missing or misconfigured security headers.
- 🔓 **Sensitive File Exposure** – Scans for leaked `.env`, `config.php`, `robots.txt`, `.git/HEAD`, etc.
- 👤 **Broken Access Control** – Tests for unauthorized admin access, IDOR, and directory traversal.
- 🔐 **Authentication Issues** – Detects weak/default credentials and missing password policies.
- 📉 **Rate Limiting** – Verifies protections against brute-force attacks.
- 📜 **Audit Logging Placeholder** – (Pluggable logic for checking audit trails).
- 🔐 **JWT Issues Placeholder** – (Detects unsigned JWT usage).
- 🤖 **AI Summary via Gemini** – Generates a non-technical summary of findings using Gemini AI. 

---

## 🖼️ Demo (optional)

> 🚀 Add a demo GIF/screenshot of your app in action here  
> Example:  
![Demo](https://your-demo-link.gif)

---

## 🛠️ Setup Instructions

```bash
# 1️⃣ Clone the repository
git clone [https://github.com/yourusername/owasp-scanner.git](https://github.com/sanketbhamare656/owasp_scanner.git)
cd owasp-scanner

# 2️⃣ (Optional) Create a virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate

# 3️⃣ Install dependencies
pip install -r requirements.txt

# 4️⃣ Set your Gemini API key (optional for AI summary)
export GEMINI_API_KEY="your-google-api-key"  # or use .env

# 5️⃣ Run the scanner
python scanner.py
```

---

## 🧪 Example Usage

```python
from scanner import Top10Scanner

scanner = Top10Scanner(gemini_api_key="your-gemini-key")
results = scanner.scan("https://example.com")
print(results['ai_summary'])  # Optional Gemini-based summary
```

---

## 📚 Educational Value

This project helps developers:

- Learn how OWASP Top 10 vulnerabilities manifest
- Understand the importance of headers, access control, and input validation
- Practice secure coding and ethical hacking skills
- Build security awareness into the SDLC

---

## 🤖 Powered by

- [Google Gemini AI](https://deepmind.google/technologies/gemini/)
- [BeautifulSoup](https://www.crummy.com/software/BeautifulSoup/)
- [Requests](https://docs.python-requests.org/en/latest/)
- [Regex](https://docs.python.org/3/library/re.html)

---

## 🤝 Collaborators

This project is proudly built with ❤️ by:

- 👨‍💻 [Sanket Bhamare](https://github.com/sanketbhamare656) — Lead Developer
- 👨‍💻 [Shivam Dhumal](https://github.com/shivamdhumal77) — Core Contributor

Together, we built this to make web security scanning **open, free, and beginner-friendly**!

Want to join us in improving this? Fork the repo or drop a ⭐️ to support.

---
## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

## 🌐 Author

**Sanket | The Developer 🛡️**  
📫 [Connect on LinkedIn](hhttps://www.linkedin.com/in/bhamare-sanket/ttps://www.linkedin.com) • 

