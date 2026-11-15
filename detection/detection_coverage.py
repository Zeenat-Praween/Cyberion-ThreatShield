import pandas as pd
import os

print("\n======================================")
print("       CYBERION THREATSHIELD")
print("       DETECTION COVERAGE MATRIX")
print("======================================")

# Step 1: Define detection coverage
coverage_data = [

    {
        "mitre_tactic": "Credential Access",
        "technique": "Brute Force",
        "technique_id": "T1110",
        "detection_rule": "Multiple Failed Login Detection",
        "detection_status": "Implemented",
        "evidence": "Repeated failed login attempts",
        "coverage": "Covered"
    },

    {
        "mitre_tactic": "Initial Access",
        "technique": "Valid Accounts",
        "technique_id": "T1078",
        "detection_rule": "Not Implemented",
        "detection_status": "Planned",
        "evidence": "No dedicated detection logic",
        "coverage": "Gap"
    },

    {
        "mitre_tactic": "Discovery",
        "technique": "Network Service Discovery",
        "technique_id": "T1046",
        "detection_rule": "Not Implemented",
        "detection_status": "Planned",
        "evidence": "No network discovery logs",
        "coverage": "Gap"
    },

    {
        "mitre_tactic": "Credential Access",
        "technique": "Account Discovery",
        "technique_id": "T1087",
        "detection_rule": "Not Implemented",
        "detection_status": "Planned",
        "evidence": "No account discovery detection",
        "coverage": "Gap"
    }
]

# Step 2: Create DataFrame
coverage_df = pd.DataFrame(coverage_data)

# Step 3: Display coverage matrix
print("\n--- MITRE DETECTION COVERAGE ---")

print(coverage_df.to_string(index=False))

# Step 4: Calculate coverage statistics
total_techniques = len(coverage_df)

covered_techniques = len(
    coverage_df[coverage_df["coverage"] == "Covered"]
)

coverage_percentage = (
    covered_techniques / total_techniques
) * 100

print("\n--- COVERAGE SUMMARY ---")

print("Total Techniques:", total_techniques)
print("Covered Techniques:", covered_techniques)
print("Coverage Gaps:", total_techniques - covered_techniques)

print("Coverage Percentage:", round(coverage_percentage, 2), "%")

# Step 5: Save report
os.makedirs("reports", exist_ok=True)

coverage_df.to_csv(
    "reports/detection_coverage.csv",
    index=False
)

print("\n======================================")
print("Detection Coverage Analysis Completed")
print("Saved: reports/detection_coverage.csv")
print("======================================")