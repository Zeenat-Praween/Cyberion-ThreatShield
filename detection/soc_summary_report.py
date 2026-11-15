import os
import pandas as pd
from datetime import datetime


# ==========================================
# DAY 31 - SOC EXECUTIVE SUMMARY REPORT
# ==========================================

print("\n========== SOC EXECUTIVE SUMMARY ==========\n")


# Project root directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

REPORT_DIR = os.path.join(BASE_DIR, "reports")
DATASET_PATH = os.path.join(BASE_DIR, "data", "sample_logs.csv")


# Reports to include in the summary
report_files = {
    "Detected Security Events": "detected_events.csv",
    "Password Spraying Findings": "password_spray_findings.csv",
    "Threat Hunting Findings": "hunt_findings.csv",
    "Incident Classification": "incident_classification.csv",
    "MITRE ATT&CK Mapping": "mitre_attack_mapping.csv",
    "Detection Coverage": "detection_coverage.csv",
    "Log Quality Results": "log_quality_report.csv",
    "Rule Validation Results": "rule_validation_report.csv"
}


summary = []

summary.append("CYBERION THREATSHIELD")
summary.append("SOC EXECUTIVE SUMMARY REPORT")
summary.append("=" * 55)

summary.append(
    f"Generated On: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
)

summary.append("")


# ==========================================
# DATASET SUMMARY
# ==========================================

summary.append("1. SECURITY LOG DATASET")
summary.append("-" * 55)

if os.path.exists(DATASET_PATH):

    logs = pd.read_csv(DATASET_PATH)

    summary.append(f"Total Log Records: {len(logs)}")
    summary.append(f"Total Columns: {len(logs.columns)}")

else:

    summary.append("Dataset file not found.")

summary.append("")


# ==========================================
# INDIVIDUAL REPORT SUMMARIES
# ==========================================

summary.append("2. SECURITY ANALYSIS REPORTS")
summary.append("-" * 55)

for report_name, file_name in report_files.items():

    file_path = os.path.join(REPORT_DIR, file_name)

    summary.append(f"\n{report_name}")

    if os.path.exists(file_path):

        try:

            report = pd.read_csv(file_path)

            summary.append(
                f"Total Records: {len(report)}"
            )

            summary.append(
                f"Available Columns: {', '.join(report.columns)}"
            )

        except Exception as error:

            summary.append(
                f"Could not read report: {error}"
            )

    else:

        summary.append("Report file not available.")


# ==========================================
# RULE VALIDATION SUMMARY
# ==========================================

summary.append("")
summary.append("3. DETECTION RULE VALIDATION")
summary.append("-" * 55)

validation_path = os.path.join(
    REPORT_DIR,
    "rule_validation_report.csv"
)

if os.path.exists(validation_path):

    validation = pd.read_csv(validation_path)

    if "Result" in validation.columns:

        passed = (
            validation["Result"]
            .astype(str)
            .str.upper() == "PASS"
        ).sum()

        failed = (
            validation["Result"]
            .astype(str)
            .str.upper() == "FAIL"
        ).sum()

        summary.append(f"Total Tests: {len(validation)}")
        summary.append(f"Passed Tests: {passed}")
        summary.append(f"Failed Tests: {failed}")

    else:

        summary.append("Validation result column not found.")

else:

    summary.append("Validation report not available.")


# ==========================================
# FINAL PROJECT NOTE
# ==========================================

summary.append("")
summary.append("4. PROJECT OVERVIEW")
summary.append("-" * 55)

summary.append(
    "Cyberion ThreatShield is a defensive security "
    "monitoring and threat hunting platform."
)

summary.append(
    "It analyzes security logs, identifies suspicious "
    "authentication patterns, maps selected findings "
    "to MITRE ATT&CK, and supports incident investigation."
)

summary.append("")
summary.append(
    "Note: Detected patterns are investigation indicators "
    "and do not independently confirm a security attack."
)

summary.append("")
summary.append("=" * 55)
summary.append("END OF SOC EXECUTIVE SUMMARY")


# ==========================================
# SAVE REPORT
# ==========================================

output_path = os.path.join(
    REPORT_DIR,
    "soc_executive_summary.txt"
)

os.makedirs(REPORT_DIR, exist_ok=True)

with open(output_path, "w", encoding="utf-8") as file:

    file.write("\n".join(summary))


print("SOC Executive Summary generated successfully!")
print(f"Report Location: {output_path}")

print("\n========== REPORT GENERATION COMPLETED ==========")