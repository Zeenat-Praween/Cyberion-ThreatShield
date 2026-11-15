# Cyberion ThreatShield
### Detection Engineering & Threat Hunting Platform

Cyberion ThreatShield is a Python-based defensive security monitoring platform designed to support Security Operations Center (SOC) activities through security log analysis, detection engineering, threat hunting, and incident investigation.

## Project Objectives

- Analyze security event logs.
- Identify suspicious authentication patterns.
- Detect potential brute-force and password-spraying indicators.
- Implement and validate basic detection rules.
- Map selected security findings to MITRE ATT&CK.
- Support incident investigation and documentation.
- Visualize security findings through an interactive dashboard.

## Key Features

1. Security Log Analysis
2. Failed Login Detection
3. Time-Based Detection
4. IP Activity Analysis
5. Alert Prioritization
6. Sigma-Style Detection Rule Management
7. MITRE ATT&CK Mapping
8. Threat Hunting
9. Password Spraying Detection
10. Incident Investigation
11. Incident Classification
12. Streamlit SOC Dashboard
13. Detection Coverage Visualization
14. Security Log Quality Checker
15. Detection Rule Validation
16. SOC Executive Summary Report
17. Alert Investigation and Analyst Notes
18. Investigation Search and Filtering

## Technology Stack

- Python
- Pandas
- NumPy
- Streamlit
- Plotly
- Matplotlib
- PyYAML
- CSV and JSON
- MITRE ATT&CK Framework
- Sigma Detection Rules

## Project Structure

```text
Cyberion_ThreatShield/
│
├── app.py
├── data/
├── detection/
├── incident_response/
├── reports/
├── rules/
├── threat_hunting/
├── utils/
├── requirements.txt
├── validate_all_rules.py
├── validate_sigma.py
├── README.md
└── .gitignore
```

## Installation and Setup

### 1. Clone the repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
```

### 2. Navigate to the project directory

```bash
cd Cyberion-ThreatShield
```

### 3. Create a virtual environment

```bash
python -m venv venv
```

### 4. Activate the environment (Windows PowerShell)

```powershell
.\venv\Scripts\Activate.ps1
```

### 5. Install dependencies

```bash
pip install -r requirements.txt
```

### 6. Run the dashboard

```bash
streamlit run app.py
```

## Testing and Validation

The project includes security log quality checks and detection rule validation scripts.

Run the log quality checker:

```bash
python utils/log_quality_checker.py
```

Run detection rule validation:

```bash
python detection/rule_validation.py
```

Generate the SOC executive summary:

```bash
python detection/soc_summary_report.py
```

## Dataset

The project currently uses synthetic security log data for controlled testing and demonstration.

The dataset includes fields such as:

- Timestamp
- Username
- Source IP
- Event Type
- Status
- Device

## Security Disclaimer

This project is intended for defensive cybersecurity education, security monitoring, detection engineering, and controlled testing.

Detected patterns are potential security indicators and require further investigation. They do not independently confirm malicious activity.

## Author

Developed as part of a cybersecurity internship project.

**Project:** Cyberion ThreatShield  
**Domain:** Cybersecurity | SOC | Threat Hunting | Detection Engineering