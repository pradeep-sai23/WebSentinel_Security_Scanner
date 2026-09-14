# WebSentinel_Security_Scanner
Python-based web security scanner for detecting potential XSS, SQL injection, directory listing, and security misconfigurations with URL crawling and automated HTML/JSON reports.
# 🛡️ WebSentinel

**WebSentinel** is a Python-based web security scanner designed to identify common web application security issues in authorized testing environments.

The project combines URL crawling, vulnerability detection, risk assessment, and automated report generation into a simple security-testing workflow.

> ⚠️ **Disclaimer:** WebSentinel is intended only for authorized security testing, educational labs, and applications you own or have explicit permission to test. Do not use it against systems without authorization.

---

## 🚀 Features

- 🔎 **URL Crawling**
  - Discovers internal web pages and GET form endpoints.
  - Restricts crawling to the target host.
  - Configurable maximum number of pages.

- 🧪 **Reflected XSS Detection**
  - Uses a harmless test marker to identify reflected user input.
  - Reports potentially reflected input for further manual validation.

- 💉 **SQL Injection Detection**
  - Uses controlled test inputs.
  - Checks responses for common database error indicators.
  - Provides remediation recommendations.

- 📂 **Directory Listing Detection**
  - Checks common directory paths.
  - Identifies possible directory indexing exposure.

- 🔐 **Security Misconfiguration Detection**
  - Checks for missing security headers.
  - Detects server information disclosure.
  - Checks permissive CORS configuration.
  - Identifies HTTP usage.
  - Checks cookie security attributes.

- 📊 **Risk Assessment**
  - Categorizes findings as:
    - Critical
    - High
    - Medium
    - Low

- 📄 **Automated Reports**
  - JSON report generation.
  - HTML report generation.
  - Includes evidence, severity, affected URL, and recommendations.

---

## 🏗️ Project Architecture


WebSentinel/
│
├── scanner.py
├── report.py
├── html_report.py
├── requirements.txt
├── README.md
│
├── scanner/
│   ├── __init__.py
│   ├── crawler.py
│   ├── xss.py
│   ├── sqli.py
│   ├── directory.py
│   └── misconfig.py
│
├── lab/
│   └── app.py
│
└── reports/

WORKFLOW

                Target Application
                       │
                       ▼
                 URL Crawler
                       │
                       ▼
                Discovered URLs
                       │
        ┌──────────────┼──────────────┐
        ▼              ▼              ▼
       XSS            SQLi       Directory Scan
        │              │              │
        └──────────────┼──────────────┘
                       ▼
              Misconfiguration
                    Scanner
                       │
                       ▼
                 Risk Analysis
                       │
              ┌────────┴────────┐
              ▼                 ▼
         JSON Report       HTML Report

Clone the repository:

git clone https://github.com/YOUR_USERNAME/WebSentinel.git
cd WebSentinel

Create a virtual environment:

python3 -m venv venv

Activate it:

source venv/bin/activate

Install dependencies:

pip install -r requirements.txt
🧪 Running the Local Security Lab

WebSentinel includes a deliberately vulnerable Flask application for safe testing.

Start the lab:

python3 lab/app.py

The application will run at:

http://127.0.0.1:5000

Keep the Flask application running in one terminal.

🔍 Running WebSentinel

Open another terminal and navigate to the project directory.

Run:

python3 scanner.py http://127.0.0.1:5000
