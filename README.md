# DomainSight 🚀

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**DomainSight** is a one-stop **Red Team** asset discovery and vulnerability analysis platform, powered by AI for classification and professional exploitation advice.

---

## 📋 Table of Contents
- [Features](#features)  
- [Tech Stack](#tech-stack)  
- [Requirements](#requirements)  
- [Installation](#installation)  
- [Configuration](#configuration)  
- [Usage](#usage)  
- [Web UI](#web-ui)  
- [Development](#development)  
- [Contributing](#contributing)  
- [License](#license)  

---

## ✨ Features
- **Subdomain Enumeration**: Subfinder, Assetfinder, Gobuster  
- **Live Checking**: dnsx  
- **Passive Recon**: Shodan & Censys (ports auto-persisted)  
- **Port & Service Scanning**: Nmap  
- **Vuln Scanning**: Nuclei with JSON import  
- **Leak Hunting**: GitHub/GitLab via Gitleaks  
- **AI Fingerprinting**: Tech stack & purpose classification  
- **AI Exploit Advisor**: GPT-4 driven red-team tactics + risk score  
- **Web Dashboard**: Flask + DataTables, themed for red-teamers  
- **One-file DB**: SQLite per TLD for portability  

---

## 🛠 Tech Stack
- **Python 3.8+**  
- **Flask** (web UI)  
- **SQLite** (storage)  
- **HTML/CSS/JS** with DataTables  
- **OpenAI GPT-4 API**  

---

## 📦 Requirements
- Python ≥ 3.8  
- Git  
- CLI tools: `subfinder`,, `assetfinder`, `gobuster`, `dnsx`, `nmap`, `nuclei`  
- **Optional**: Shodan API key or Censys credentials  
- **Required**: OpenAI API key  

---

## 🚀 Installation

```
git clone https://github.com/CilynxGroup/DomainSight.git
cd DomainSight
pip install -r requirements.txt
```

---

## 📝 Configuration

Create a `.env` in the project root (or export env vars):

```
export OPENAI_API_KEY="sk-..."
export SHODAN_KEYS="YOUR_KEY"
export CENSYS_IDS="ID1,ID2"
export CENSYS_SECRETS="SEC1,SEC2"
```

---

## 💻 Usage

### Command-line
```
python DomainSight.py \
  -d example.com \
  -o output \
  --enum-tools subfinder,gobuster \
  --skip-nmap \
  --skip-nuclei \
  --fingerprint \
  --ai-agent \
  --passive-scan shodan \
  --passive-limit 10 \
  --passive-delay 1
```

**Key Flags**  
- `-d`, `--domain` : target base domain  
- `-o`, `--output` : output directory  
- `--enum-tools` : comma-separated tools  
- `--skip-nmap`, `--skip-nuclei`  
- `--fingerprint` : AI classification  
- `--ai-agent` : AI red-team advisor  
- `--passive-scan` : `shodan` or `censys`  
- `--passive-limit`, `--passive-delay`  

---

## 🌐 Web UI

Start the webserver:
```bash
python webserver.py
```
Visit: `http://localhost:5000`

- **Home**: list of TLD projects + Clear DB buttons  
- **Dashboard**: DataTable with ports, vulns, risk scores, “View Advice”  
- **AI Advice**: detailed red-team guidance per subdomain  

---

## 🛠 Development
- Lint: `flake8 .`  
- Format: `black .`  
- Tests: *(coming soon)*  

---

## 🤝 Contributing
1. Fork & branch (`feature/xyz`)  
2. Commit & PR  
3. Code review & merge  

---

## 📄 License
MIT © 2025 Cilynx Red Team Labs 
See [LICENSE](LICENSE)  

