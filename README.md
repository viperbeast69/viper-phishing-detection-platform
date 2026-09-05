# 🛡️ Viper Phishing Detection & Analysis Platform

A web-based cybersecurity platform for analyzing URLs and identifying potential phishing threats using **rule-based detection, machine learning, DNS intelligence, domain analysis, and threat reputation data**.

> Built for cybersecurity research, analysis, education, and defensive security experimentation.

## 🚀 Project Overview

Phishing attacks commonly use deceptive URLs, domain impersonation, suspicious paths, excessive subdomains, special characters, URL obfuscation, and other techniques to trick users into visiting malicious websites.

Viper uses multiple independent signals instead of relying on a single detection method.

### Detection Pipeline

```text
Submitted URL
      │
      ▼
URL Validation
      │
      ▼
Feature Extraction
      │
      ├──────────────► DNS Analysis
      ├──────────────► Domain Analysis
      ├──────────────► VirusTotal Reputation
      └──────────────► Machine Learning
                           │
                           ▼
                 Random Forest Classifier
                           │
                           ▼
                 Ensemble Risk Engine
                           │
                           ▼
              Explainable Security Result
                           │
              ┌────────────┼────────────┐
              ▼            ▼            ▼
           SQLite        Reports      Dashboard
                          JSON/TXT/PDF
```

## ✨ Key Features

### 🔎 URL Analysis
- URL structure analysis
- HTTPS detection
- URL, domain, and path length analysis
- Query parameter analysis
- Special-character detection
- Percent-encoding detection
- Suspicious keyword detection
- IP-address detection
- Punycode detection
- URL-shortener detection
- Suspicious TLD detection
- Subdomain analysis

### 🌐 DNS Intelligence
- Hostname resolution
- IPv4/IPv6 resolution
- Public/private IP classification
- DNS resolution status
- DNS error handling

The platform performs DNS analysis without directly requesting the submitted website.

### 🏷️ Domain Intelligence
- Hostname extraction
- Subdomain identification
- Registered domain extraction
- Public suffix/TLD analysis
- Domain structure validation

### 🦠 Threat Reputation
The platform can retrieve existing URL reputation information from VirusTotal using its API.

The implementation retrieves existing analysis information and does **not submit or rescan URLs**.

### 🤖 Machine Learning
A Random Forest classifier estimates the probability that a URL is phishing using engineered URL/domain features.

### ⚖️ Ensemble Risk Engine

| Component | Weight |
|---|---:|
| Rule-based analysis | 40% |
| Machine Learning | 40% |
| Reputation analysis | 20% |

If a component is unavailable, the available component weights are redistributed.

### 📊 Explainable Results
The platform provides indicators explaining why a URL received its risk classification.

### 🗄️ Scan History
SQLite stores submitted URLs, timestamps, scores, classifications, confidence, component scores, reputation information, DNS information, and detection indicators.

### 📄 Security Reports
Reports can be generated in:
- JSON
- TXT
- PDF

### 🖥️ Web Dashboard
The Flask interface provides a URL scanner, risk gauge, component scores, ML analysis, DNS intelligence, domain intelligence, explainable indicators, scan history, statistics, and report generation.

## 🤖 Machine Learning Performance

The Random Forest model was evaluated using a stratified train/test split.

| Metric | Score |
|---|---:|
| Accuracy | **96.48%** |
| Precision | **95.90%** |
| Recall | **95.77%** |
| F1 Score | **95.83%** |
| ROC-AUC | **99.30%** |

### Important Features

Examples of influential features include:
1. Path length
2. Domain length
3. Special character count
4. URL length
5. Slash count
6. Domain hyphen count
7. Hyphen count
8. Digit ratio
9. Domain digit count
10. Subdomain count

Evaluation artifacts are available under `ML/evaluation/`.

## 🧠 Risk Classification

| Score | Classification |
|---:|---|
| 0–29 | 🟢 Likely Safe |
| 30–59 | 🟡 Suspicious |
| 60–100 | 🔴 Likely Phishing |

The system also calculates confidence based on agreement between available detection components.

## 🏗️ Project Structure

```text
viper-phishing-detection-platform/
│
├── detector/
│   ├── dns_analyzer.py
│   ├── domain_analyzer.py
│   ├── feature_extractor.py
│   ├── ml_analyzer.py
│   ├── reputation_analyzer.py
│   ├── risk_engine.py
│   └── url_validator.py
│
├── ML/
│   ├── dataset/
│   │   └── phishing_urls.csv
│   ├── models/
│   │   ├── feature_names.joblib
│   │   └── phishing_model.joblib
│   ├── evaluation/
│   │   ├── confusion_matrix.png
│   │   ├── feature_importance.csv
│   │   ├── feature_importance.png
│   │   ├── model_metrics.csv
│   │   └── model_metrics.json
│   └── train_model.py
│
├── static/
│   ├── css/
│   │   └── style.css
│   └── images/
│       └── viper-logo.png
│
├── templates/
│   └── index.html
│
├── reports/
├── app.py
├── database.py
├── report_generator.py
├── requirements.txt
├── .gitignore
└── README.md
```

## 🛠️ Technology Stack

**Backend:** Python, Flask, SQLite

**Cybersecurity:** DNS analysis, domain intelligence, URL feature engineering, VirusTotal API, rule-based detection, explainable risk scoring

**Machine Learning:** Scikit-learn, Random Forest, Logistic Regression, Pandas, NumPy, Joblib

**Reporting:** ReportLab, JSON, TXT, PDF

**Frontend:** HTML, CSS, JavaScript

## ⚙️ Installation

### 1. Clone the repository

```bash
git clone https://github.com/viperbeast69/viper-phishing-detection-platform.git
cd viper-phishing-detection-platform
```

### 2. Create a virtual environment

Windows:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

Linux/macOS:

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

## 🔐 VirusTotal Configuration

Create a local `.env` file:

```env
VIRUSTOTAL_API_KEY=your_virustotal_api_key
```

Never commit your real API key to GitHub. The `.env` file is excluded through `.gitignore`.

## ▶️ Running the Application

```bash
python app.py
```

Then open:

```text
http://127.0.0.1:5000
```

## 🔌 API Endpoints

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/scan` | POST | Analyze a URL |
| `/api/history` | GET | Retrieve scan history |
| `/api/history/<scan_id>` | GET | Retrieve an individual scan |
| `/api/statistics` | GET | Retrieve scan statistics |
| `/api/report/<scan_id>/json` | GET | Generate JSON report |
| `/api/report/<scan_id>/text` | GET | Generate TXT report |
| `/api/report/<scan_id>/pdf` | GET | Generate PDF report |

## 🧪 Defensive Testing

Use legitimate URLs, synthetic phishing-like URLs, reserved domains, private/test IP addresses, and controlled security-testing environments.

Do not use the platform to interact with or distribute malicious websites.

## 🔒 Security Considerations

The platform is designed as a **defensive analysis tool**.

Important considerations include:
- User input validation
- No direct HTTP browsing of submitted URLs
- DNS-only hostname resolution
- API-key protection through environment variables
- Explainable detection results
- Local scan history
- Report generation
- Separation of detection components

Detection results should be treated as **risk assessments**, not absolute proof that a URL is malicious or safe.

## 📈 Future Improvements

- Real-time threat intelligence feeds
- WHOIS/domain-age intelligence
- Certificate/TLS analysis
- More advanced URL lexical features
- Deep-learning URL classification
- Automated model retraining
- PostgreSQL support
- User authentication and role-based access
- Docker deployment
- Cloud deployment
- Advanced analytics and visualization
- Continuous model evaluation
- IOC export capabilities

## 🎯 Project Goals

The project demonstrates how multiple cybersecurity techniques can be combined into a practical detection system:

```text
Rule-Based Detection
        +
Machine Learning
        +
DNS Intelligence
        +
Domain Analysis
        +
Threat Reputation
        ↓
Explainable Risk Assessment
```

This demonstrates practical concepts in cybersecurity, threat detection, security automation, machine learning, web application development, network intelligence, and risk assessment.

## 👨‍💻 Author

**Avinash Kumar**

Cybersecurity-focused developer and student working on defensive security, threat detection, and security automation projects.

- GitHub: https://github.com/viperbeast69
- LinkedIn: https://www.linkedin.com/in/avinash-kumar-617b49333
- Instagram: https://www.instagram.com/viper_cybersecurity/
- Email: vipercybersecurity@gmail.com

## ⚠️ Disclaimer

This project is developed for **cybersecurity research, education, and defensive security analysis**.

The platform provides automated risk assessments and should not be considered a definitive determination of maliciousness. Always validate important security findings using additional trusted sources and appropriate security procedures.

---

**Viper Phishing Detection & Analysis Platform — Built for cybersecurity research, analysis & education.**
