# 🛡️ SentinelShield
### Advanced Intrusion Detection & Web Protection System

> **Detect. Defend. Monitor.**

SentinelShield is a lightweight, Flask-based **Web Application Firewall (WAF) and Intrusion Detection System (IDS)** designed to demonstrate how modern web security controls inspect HTTP traffic, detect malicious patterns, enforce rate limits, generate security logs, and present events through a SOC-style monitoring dashboard.

It provides a practical cybersecurity lab environment for understanding the complete defensive workflow:

**HTTP Request → Inspection → Threat Detection → Security Decision → Logging → Monitoring**

---

## 🚀 Key Features

- 🔍 **HTTP Request Inspection**
  - Analyzes incoming web requests and their parameters.
  - Inspects paths, query parameters, headers, and request bodies.

- 🛡️ **Web Attack Detection**
  - SQL Injection
  - Cross-Site Scripting (XSS)
  - Directory Traversal
  - Local File Inclusion (LFI)
  - Command Injection

- 🚦 **Rate Limiting & Abuse Detection**
  - Sliding-window request monitoring
  - Per-IP request tracking
  - Temporary blocking of excessive traffic
  - HTTP `429 Too Many Requests` response

- 📋 **Security Logging**
  - JSON Lines (`JSONL`) audit logs
  - Timestamped security events
  - Source IP tracking
  - Attack category and severity
  - Allow / Block / Rate-Limit decisions

- 📊 **SOC-Style Security Dashboard**
  - Threat statistics
  - Blocked and allowed requests
  - Attack-category distribution
  - Repeatedly flagged IP addresses
  - Recent security events
  - Rate-limit activity
  - Automatic dashboard refresh

- 🔐 **Dashboard Authentication**
  - HTTP Basic Authentication
  - Configurable credentials through environment variables

- 🧪 **Security Testing Client**
  - Normal traffic simulation
  - Attack simulation
  - Rate-limit/flood testing
  - Automated validation of WAF responses

---

## 🏗️ Architecture

```text
                         ┌─────────────────────┐
                         │   Security Tester   │
                         │ Kali Linux / Client │
                         └──────────┬──────────┘
                                    │
                                    │ HTTP Requests
                                    ▼
                         ┌─────────────────────┐
                         │   SentinelShield    │
                         │     Flask App       │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │   WAF Middleware    │
                         └──────────┬──────────┘
                                    │
                         ┌──────────┴──────────┐
                         ▼                     ▼
                 ┌──────────────┐      ┌──────────────┐
                 │ Rate Limiter │      │Threat Detector│
                 └──────┬───────┘      └──────┬───────┘
                        │                     │
                        └──────────┬──────────┘
                                   ▼
                         ┌─────────────────────┐
                         │ Security Decision   │
                         │ ALLOW / BLOCK / 429 │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │   Security Logger   │
                         │     JSONL Logs      │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │    SOC Dashboard    │
                         │ Monitoring & Analysis│
                         └─────────────────────┘

SentinelShield/
│
├── app.py
├── config.py
├── requirements.txt
├── .env.example
├── test_client.py
│
├── waf/
│   ├── __init__.py
│   ├── detector.py
│   ├── rate_limiter.py
│   ├── logger.py
│   ├── middleware.py
│   └── dashboard.py
│
├── templates/
│   └── dashboard.html
│
├── static/
│   └── js/
│       └── dashboard.js
│
└── logs/
    └── waf.log

| Technology          | Purpose                                 |
| ------------------- | --------------------------------------- |
| Python              | Core programming language               |
| Flask               | Web application framework               |
| HTML5               | Dashboard structure                     |
| CSS3                | SOC dashboard interface                 |
| JavaScript          | Dashboard interaction and live updates  |
| Regular Expressions | Threat signature detection              |
| JSON / JSONL        | Security event logging                  |
| Requests            | Security testing client                 |
| HTTP Basic Auth     | Dashboard authentication                |
| Kali Linux          | Authorized security testing environment |


Testing
1. Create Virtual Environment
Linux / Kali Linux
python3 -m venv .venv
source .venv/bin/activate
Windows
python -m venv .venv
.venv\Scripts\activate
2. Install Dependencies
pip install -r requirements.txt
3. Configure Dashboard Credentials
Linux / Kali
export DASHBOARD_USER="admin"
export DASHBOARD_PASSWORD="SentinelShield-Lab-2026!"
Windows PowerShell
$env:DASHBOARD_USER="admin"
$env:DASHBOARD_PASSWORD="SentinelShield-Lab-2026!"

Use a strong password for environments beyond a local educational lab.

4. Start SentinelShield
python app.py

The application will run locally at:

http://127.0.0.1:5000
5. Open SOC Dashboard

Navigate to:

http://127.0.0.1:5000/dashboard

Authenticate using the configured dashboard credentials.

🧪 Automated Testing

SentinelShield includes a testing client:

test_client.py
Test Normal Traffic
python test_client.py --mode normal
Test Web Attacks
python test_client.py --mode attacks
Test Rate Limiting
python test_client.py --mode flood --count 40
Run All Tests
python test_client.py --mode all
🐉 Kali Linux Testing

SentinelShield can be tested from an isolated and authorized Kali Linux virtual machine.

Recommended lab architecture:

┌─────────────────────┐
│    Kali Linux VM    │
│ Security Testing    │
│                     │
│ curl                │
│ Burp Suite          │
│ Nmap                │
│ Nikto               │
└──────────┬──────────┘
           │
           │ Authorized HTTP Traffic
           ▼
┌─────────────────────┐
│   SentinelShield    │
│   Flask Application  │
│                     │
│ WAF + IDS + Logger  │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│    SOC Dashboard    │
└─────────────────────┘

All security testing should be performed only against systems you own or are explicitly authorized to test.

🔬 Practical Test Matrix
Test ID	Security Scenario	Expected Result
T01	Normal HTTP Request	ALLOW
T02	SQL Injection	BLOCK
T03	XSS	BLOCK
T04	Directory Traversal	BLOCK
T05	LFI	BLOCK
T06	Command Injection	BLOCK
T07	Excessive Request Rate	HTTP 429 / BLOCK
📈 Security Evaluation

The project can be evaluated using standard detection metrics.

True Positive (TP)

Malicious request correctly detected and blocked.

True Negative (TN)

Legitimate request correctly allowed.

False Positive (FP)

Legitimate request incorrectly blocked.

False Negative (FN)

Malicious request incorrectly allowed.

Detection Accuracy
Accuracy =
(TP + TN)
--------------------------- × 100
(TP + TN + FP + FN)
False Positive Rate
FPR =
FP
---------------- × 100
FP + TN
False Negative Rate
FNR =
FN
---------------- × 100
FN + TP

Accuracy should be calculated from actual test results. The project does not claim 100% detection accuracy without sufficient test evidence.

🧠 Security Workflow

SentinelShield demonstrates a simplified SOC/WAF workflow:

1. Incoming HTTP Request
           ↓
2. Request Inspection
           ↓
3. Rate-Limit Check
           ↓
4. Threat Signature Analysis
           ↓
5. Security Decision
           ↓
6. Event Logging
           ↓
7. Dashboard Monitoring
           ↓
8. Security Analysis

This architecture demonstrates the relationship between:

Detection → Prevention → Logging → Monitoring → Analysis

🎯 Learning Objectives

This project was developed to provide practical understanding of:

Web Application Firewall concepts
Intrusion Detection Systems
HTTP request inspection
Web attack signatures
SQL Injection detection
XSS detection
Directory Traversal detection
LFI detection
Command Injection detection
Rate limiting
IP-based traffic monitoring
Security event logging
SOC dashboard development
Security alert analysis
False-positive and false-negative analysis
Defensive security architecture
⚠️ Limitations

SentinelShield is an educational and laboratory security project, not a replacement for enterprise-grade WAF, IDS, IPS, or SIEM platforms.

Current limitations include:

Signature-based detection can miss novel attack techniques.
Regular-expression detection may generate false positives.
Advanced payload obfuscation may bypass simple signatures.
Rate limiting is application-level.
The dashboard is designed for local/lab monitoring.
It does not provide full packet-level network intrusion detection.
It does not replace enterprise SIEM correlation.
It does not perform behavioral machine-learning detection.
🔮 Future Enhancements

Potential future improvements include:

MITRE ATT&CK technique mapping
Machine-learning based anomaly detection
Advanced behavioral analysis
GeoIP-based threat visualization
Email / webhook security alerts
Threat intelligence integration
IP reputation checking
Exportable security reports
PostgreSQL / SQLite event storage
Elasticsearch integration
Splunk integration
Wazuh integration
Role-based dashboard access
Advanced incident investigation interface
Docker deployment
HTTPS/TLS support
API authentication
Automated security test reporting


docs/
├── dashboard.png
├── sql-injection-detection.png
├── xss-detection.png
├── rate-limit.png
├── security-logs.png
└── kali-testing.png

Then add them to this README:

![SentinelShield Dashboard](docs/dashboard.png)
🔐 Security Notice

SentinelShield is intended for:

Educational purposes
Cybersecurity laboratories
Authorized penetration testing
Local security research
Defensive security demonstrations

Do not use the testing functionality against systems, applications, networks, or infrastructure without explicit authorization.

The authors are not responsible for unauthorized or malicious use of this project.

👨‍💻 Author

Ayush Marwadi

Cyber Security | SOC | Network Security | Web Security

⭐ Project Highlights
✔ Lightweight Flask-based WAF/IDS
✔ Real-time security event monitoring
✔ Web attack signature detection
✔ Rate limiting and abuse prevention
✔ Structured JSON security logging
✔ SOC-style security dashboard
✔ Automated security testing
✔ Kali Linux laboratory compatible
✔ Designed for practical cybersecurity learning
⭐ If You Find This Project Useful

Give the repository a ⭐ and feel free to explore, improve, and extend the project.




