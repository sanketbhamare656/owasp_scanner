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

## 🗂️ Project Structure

OWASP_SCANNER/
│
├── app/
│ ├── init.py
│ ├── models.py
│ ├── routes.py
│ ├── scanner.py
│ ├── modules/
│ │ ├── init.py
│ │ ├── auth_failure.py
│ │ ├── bac.py
│ │ └── ... (other modules)
│ ├── templates/
│ │ ├── base.html
│ │ ├── chat.html
│ │ └── ...
│ └── static/
│ ├── css/
│ └── js/
│
├── instance/
│ └── scanner.db
│
├── main/
│ ├── img1.png
│ ├── img2.png
│ ├── img3.png
│ └── img4.png
│
├── venv/
├── .env
├── .gitignore
├── chatbot.py
├── config.py
├── README.md
├── requirements.txt
└── run.py


---

## 🖼️ Demo

> 📽️ Watch the demo here:  
[![Watch Demo](https://img.youtube.com/vi/c62PoY_IMZM/0.jpg)](https://youtu.be/c62PoY_IMZM)



## 🛠️ Setup Instructions

```bash
# 1️⃣ Clone the repository
git clone https://github.com/sanketbhamare656/owasp_scanner.git
cd owasp_scanner

# 2️⃣ (Optional) Create a virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3️⃣ Install dependencies
pip install -r requirements.txt

# 4️⃣ Set your Gemini API key (optional for AI summary)
export GEMINI_API_KEY="your-google-api-key"  # or use .env

# 5️⃣ Run the scanner
python app/scanner.py
