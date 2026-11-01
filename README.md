# 🛡️ KODKAVACH

### AI-Assisted Python Package Security & Supply Chain Threat Detection Platform

**Supply Chain Guardian (SCG)** is a security analysis platform designed to identify suspicious Python packages and potentially malicious behaviour in the PyPI software supply chain.

Traditional vulnerability scanners primarily identify known vulnerabilities. SCG takes a multi-layered approach by examining package identity, source code, version changes and runtime behaviour to help developers make more informed decisions before trusting a package.

Our goal is to make Python package security more transparent, evidence-based and accessible.

---

## 🚀 Key Features

### 1. Name & Lie Detector — Package Identity Analysis
- Examines package metadata and identity information.
- Performs package-name similarity and suspicious-name checks.
- Identifies potential discrepancies between package identity and metadata.
- Uses popular-package reference data to support detection.

### 2. Password & Gibberish Tracker — Static Code Analysis
- Inspects Python source code using Abstract Syntax Trees (AST).
- Identifies suspicious operations and potentially dangerous code patterns.
- Performs basic taint analysis to investigate potentially unsafe data flows.
- Produces evidence associated with detected findings.

### 3. Update Hijack Detector — Version Comparison
- Compares two versions of a Python package.
- Identifies newly introduced, removed and persistent suspicious behaviours.
- Compares package artifact hashes using SHA-256.
- Includes installation-configuration file comparison logic.

### 4. Fake-Bait Sandbox — Runtime Behaviour Monitoring
- Provides a controlled environment for package execution.
- Monitors process, file-system and network-related activities.
- Collects runtime events for further analysis.
- Uses Docker-based sandbox components.

### 5. Smart False-Alarm Filter — Risk Assessment
- Correlates findings and supporting evidence.
- Applies risk-classification and false-positive reduction heuristics.
- Helps prioritise suspicious package behaviours.
- Provides severity and confidence information.

### 6. AI Translator & Reporter — Planned Enhancement
- Intended to provide simplified explanations of technical security findings.
- Planned to make reports easier for developers to understand.
- AI-assisted explanations are part of the future development roadmap.

---

## 🏗️ System Architecture

SCG combines multiple analysis layers into a unified security workflow.

```text
             Python Package (.zip)
                       |
                       v
              Package Extraction
                       |
                       v
          +-------------------------+
          |  Package Identity Check |
          +-------------------------+
                       |
                       v
          +-------------------------+
          |   Static Code Analysis |
          |     AST + Taint         |
          +-------------------------+
                       |
                       v
          +-------------------------+
          |    Version Comparison  |
          +-------------------------+
                       |
                       v
          +-------------------------+
          |    Runtime Sandbox     |
          +-------------------------+
                       |
                       v
          +-------------------------+
          |  False-Alarm Filtering |
          +-------------------------+
                       |
                       v
              Risk Assessment
                       |
                       v
             Security Report
                       |
                       v
              React Dashboard
```

*The individual analysis stages are implemented to different levels of completeness. Not every stage is required to run in every analysis workflow.*

---

## 🛠️ Technology Stack

| Component | Technologies |
|---|---|
| Frontend | React.js, Vite, JavaScript |
| Backend | Python, FastAPI |
| Static Analysis | Python AST |
| Taint Analysis | Custom Python analysis engine |
| Version Comparison | Python, SHA-256 |
| Runtime Monitoring | Docker, Python |
| API Communication | REST API |
| Data Format | JSON |
| Testing | Pytest |

---

## 📂 Project Structure

```text
Supply-Chain-Guardian/
│
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   └── services/
│   │       ├── archive_service.py
│   │       ├── runtime_correlation.py
│   │       └── sandbox_service.py
│   └── requirements.txt
│
├── engines/
│   └── pypi-scanner/
│       ├── run_scan.py
│       ├── compare_versions.py
│       ├── scanner/
│       │   ├── ast_analyzer.py
│       │   ├── false_alarm_filter.py
│       │   ├── file_discovery.py
│       │   ├── models.py
│       │   ├── name_detector.py
│       │   ├── package_metadata.py
│       │   ├── parser.py
│       │   ├── taint_engine.py
│       │   └── version_diff.py
│       ├── examples/
│       └── tests/
│
├── frontend/
│   ├── public/
│   ├── src/
│   │   ├── App.jsx
│   │   ├── App.css
│   │   ├── index.css
│   │   └── main.jsx
│   ├── package.json
│   └── vite.config.js
│
├── sandbox/
│   ├── fixtures/
│   ├── monitoring/
│   └── worker/
│       ├── Dockerfile
│       ├── entrypoint.py
│       └── requirements.txt
│
├── shared/
│   ├── rules/
│   └── schemas/
│
├── stage3_test_archives/
├── test_samples/
├── reports/
├── create_stage3_test_archives.py
├── .gitignore
└── README.md
```

---

## ⚙️ Installation & Setup

### Prerequisites

Make sure the following are installed:

- Python 3.10 or newer
- Node.js and npm
- Git
- Docker Desktop (for sandbox functionality)

### 1. Clone the repository

```bash
git clone https://github.com/Sumitttt-S5/name.git
cd name
```

### 2. Set up the Python environment

```bash
python -m venv .venv
```

Activate the environment.

**Windows (PowerShell):**

```powershell
.venv\Scripts\Activate.ps1
```

**Windows (Git Bash):**

```bash
source .venv/Scripts/activate
```

**Linux / macOS:**

```bash
source .venv/bin/activate
```

### 3. Install backend dependencies

From the project root:

```bash
pip install -r backend/requirements.txt
```

### 4. Start the backend

```bash
cd backend
uvicorn app.main:app --reload
```

Backend address:

```text
http://127.0.0.1:8000
```

### 5. Start the frontend

Open a second terminal from the project root:

```bash
cd frontend
npm install
npm run dev
```

Frontend address:

```text
http://localhost:5173
```

The React dashboard communicates with the FastAPI backend.

---

## 🧪 Testing

The project includes automated tests for the scanner's analysis components.

From the project root, activate the Python virtual environment and run:

```bash
python -m pytest engines/pypi-scanner/tests -q
```

---

## 🎯 Demonstration

The repository includes controlled sample packages for demonstrating security analysis.

### Version Comparison Demo

Two sample package versions are available:

```text
stage3_test_archives/
├── demo-1.0.0.zip
└── demo-1.1.0.zip
```

Upload the archives in the Version Comparison section:

- Baseline: `demo-1.0.0.zip`
- Candidate: `demo-1.1.0.zip`

The demonstration illustrates how SCG can identify newly introduced suspicious behaviour, including operating-system command execution, and compare package hashes.

### Static Analysis Demo

Use the sample Python packages under:

```text
engines/pypi-scanner/examples/
test_samples/
```

These provide controlled inputs for testing package analysis.

**Safety:** Only use trusted, controlled test packages when demonstrating runtime execution. Never execute unknown third-party packages outside an appropriately isolated environment.

---

## 📊 Implementation Status

| Stage | Module | Current Status |
|---|---|---|
| 1 | Name & Lie Detector | Implemented |
| 2 | Password & Gibberish Tracker | Partially implemented |
| 3 | Update Hijack Detector | Partially implemented |
| 4 | Fake-Bait Sandbox | Implemented prototype |
| 5 | Smart False-Alarm Filter | Implemented prototype |
| 6 | AI Translator & Reporter | Planned |

### Current Limitations

- Static analysis and taint tracking are not yet comprehensive or fully interprocedural.
- Version comparison has installation-file comparison logic, but its end-to-end API integration requires further verification.
- Runtime sandboxing requires additional isolation hardening and security testing.
- AI-generated security explanations are not yet implemented.
- Detection results are heuristic and should not be interpreted as proof that a package is safe or malicious.

---

## 🔮 Future Scope

- Advanced interprocedural and data-flow analysis.
- Improved detection of installation-time and build-time attacks.
- Fully integrated installation-configuration change detection.
- Stronger sandbox isolation and runtime monitoring.
- AI-assisted explanations of suspicious findings.
- Improved risk scoring and evidence correlation.
- Expanded test coverage and security benchmarking.

---

## 💡 Our Vision

Software supply-chain attacks can compromise applications through dependencies that developers trust.

Supply Chain Guardian aims to make package security proactive rather than relying only on previously reported vulnerabilities.

**Don't just trust a package because it installs. Investigate what it does.**

---

## 👥 Project

**Project Name:** Supply Chain Guardian (SCG)  
**Repository:** [GitHub — Supply Chain Guardian](https://github.com/Sumitttt-S5/name)

*Built as a security-focused prototype for Python package supply-chain analysis.*

---

### Disclaimer

Supply Chain Guardian is an experimental security-analysis prototype. Its findings are intended to assist security review and do not guarantee detection of all malicious packages or establish that a package is completely safe.
