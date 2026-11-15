import pandas as pd
import os

# Step 1: Load central security findings
file_path = "reports/security_findings.csv"

data = pd.read_csv(file_path)

print("\n======================================")
print("       CYBERION THREATSHIELD")
print("       ALERT PRIORITISATION")
print("======================================")

# Step 2: Assign numerical values to severity
severity_scores = {
    "High": 3,
    "Medium": 2,
    "Low": 1
}

data["severity_score"] = data["severity"].map(
    severity_scores
)

# Step 3: Calculate risk score
data["risk_score"] = (
    data["severity_score"] * 10
    + data["event_count"]
)

# Step 4: Assign priority
def assign_priority(score):

    if score >= 33:
        return "Critical"

    elif score >= 23:
        return "High"

    elif score >= 12:
        return "Medium"

    else:
        return "Low"


data["priority"] = data["risk_score"].apply(
    assign_priority
)

# Step 5: Sort alerts by risk score
data = data.sort_values(
    by="risk_score",
    ascending=False
)

# Step 6: Display prioritised alerts
print("\n--- PRIORITISED SECURITY ALERTS ---")

print(
    data[
        [
            "finding_type",
            "source_ip",
            "severity",
            "event_count",
            "risk_score",
            "priority"
        ]
    ].to_string(index=False)
)

# Step 7: Save prioritisation report
os.makedirs("reports", exist_ok=True)

data.to_csv(
    "reports/prioritised_alerts.csv",
    index=False
)

print("\n--- PRIORITY SUMMARY ---")

print(data["priority"].value_counts())

print("\n======================================")
print("Alert Prioritisation Completed")
print("Saved: reports/prioritised_alerts.csv")
print("======================================")