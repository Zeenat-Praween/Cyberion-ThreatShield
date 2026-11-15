import pandas as pd
import os

# Step 1: Load central security findings
data = pd.read_csv("reports/security_findings.csv")

print("\n======================================")
print("       CYBERION THREATSHIELD")
print("       MITRE ATT&CK MAPPING")
print("======================================")

# Step 2: Define MITRE ATT&CK mapping
def map_mitre(row):

    if (
        "Failed Login" in row["finding_type"]
        and row["event_count"] >= 3
    ):

        return pd.Series({
            "mitre_tactic": "Credential Access",
            "mitre_technique": "Brute Force",
            "mitre_technique_id": "T1110",
            "mapping_status": "Potential Technique Match"
        })

    else:

        return pd.Series({
            "mitre_tactic": "Not Assigned",
            "mitre_technique": "Needs Review",
            "mitre_technique_id": "N/A",
            "mapping_status": "Insufficient Evidence"
        })


# Step 3: Apply MITRE mapping
mitre_details = data.apply(
    map_mitre,
    axis=1
)

# Step 4: Add mapping details
mapped_data = pd.concat(
    [data, mitre_details],
    axis=1
)

# Step 5: Display results
print("\n--- MITRE ATT&CK MAPPING RESULTS ---")

print(
    mapped_data[
        [
            "finding_type",
            "source_ip",
            "event_count",
            "mitre_tactic",
            "mitre_technique",
            "mitre_technique_id",
            "mapping_status"
        ]
    ].to_string(index=False)
)

# Step 6: Save report
os.makedirs("reports", exist_ok=True)

mapped_data.to_csv(
    "reports/mitre_attack_mapping.csv",
    index=False
)

print("\n======================================")
print("MITRE Mapping Completed")
print("Report: reports/mitre_attack_mapping.csv")
print("======================================")