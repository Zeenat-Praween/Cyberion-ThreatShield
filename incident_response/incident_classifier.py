import pandas as pd
import os

# Step 1: Load investigation summary

file_path = "reports/investigation_summary.csv"

data = pd.read_csv(file_path)

print("\n======================================")
print("       CYBERION THREATSHIELD")
print("       INCIDENT CLASSIFICATION")
print("======================================")


# Step 2: Extract investigation details

username = data.loc[0, "username"]

source_ip = data.loc[0, "source_ip"]

failed_count = int(data.loc[0, "failed_login_count"])

successful_count = int(data.loc[0, "successful_login_count"])

investigation_result = data.loc[0, "investigation_result"]


# Step 3: Classify the incident

if failed_count >= 3 and successful_count >= 1:

    incident_category = "Authentication Anomaly"

    severity = "High"

    status = "Open - Under Investigation"

    confidence = "Medium"

    recommendation = (
        "Verify the successful login with the account owner, "
        "review additional authentication records, "
        "and check whether the activity was authorized."
    )

elif failed_count >= 3:

    incident_category = "Repeated Failed Login Activity"

    severity = "Medium"

    status = "Open - Under Investigation"

    confidence = "Medium"

    recommendation = (
        "Review the failed login activity and verify "
        "whether the attempts were legitimate."
    )

else:

    incident_category = "General Authentication Activity"

    severity = "Low"

    status = "Review Completed"

    confidence = "Low"

    recommendation = (
        "Continue monitoring authentication activity."
    )


# Step 4: Generate incident ID

incident_id = "CTS-INC-0001"


# Step 5: Create classification report

classification = pd.DataFrame([{

    "incident_id": incident_id,

    "username": username,

    "source_ip": source_ip,

    "incident_category": incident_category,

    "failed_login_count": failed_count,

    "successful_login_count": successful_count,

    "severity": severity,

    "confidence": confidence,

    "status": status,

    "investigation_result": investigation_result,

    "recommendation": recommendation

}])


# Step 6: Display classification

print("\n--- INCIDENT DETAILS ---")

print(classification.to_string(index=False))


# Step 7: Save classification report

os.makedirs("reports", exist_ok=True)

classification.to_csv(
    "reports/incident_classification.csv",
    index=False
)


print("\n======================================")
print("Incident Classification Completed")
print("Report: reports/incident_classification.csv")
print("======================================")