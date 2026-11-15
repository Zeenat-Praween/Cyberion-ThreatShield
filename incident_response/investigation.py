import pandas as pd
import os

# Step 1: Load original security logs
data = pd.read_csv("data/sample_logs.csv")

data["timestamp"] = pd.to_datetime(data["timestamp"])

print("\n======================================")
print("       CYBERION THREATSHIELD")
print("       THREAT INVESTIGATION")
print("======================================")

# Step 2: Define investigation details
TARGET_USERNAME = "admin"
TARGET_IP = "192.168.1.12"

# Step 3: Filter relevant login activities
evidence = data[
    (data["username"] == TARGET_USERNAME) &
    (data["source_ip"] == TARGET_IP) &
    (data["event_type"] == "Login")
].copy()

# Step 4: Sort evidence chronologically
evidence = evidence.sort_values("timestamp")

# Step 5: Calculate activity statistics
failed_count = len(
    evidence[evidence["status"] == "Failed"]
)

successful_count = len(
    evidence[evidence["status"] == "Success"]
)

# Step 6: Display investigation timeline
print("\n--- INVESTIGATION DETAILS ---")

print("Username:", TARGET_USERNAME)
print("Source IP:", TARGET_IP)

print("\n--- EVIDENCE TIMELINE ---")

print(
    evidence[
        ["timestamp", "username", "source_ip", "event_type", "status"]
    ].to_string(index=False)
)

# Step 7: Prepare investigation summary
if failed_count >= 3 and successful_count >= 1:

    investigation_result = "Suspicious Pattern Identified"
    investigation_status = "Requires Further Investigation"

else:

    investigation_result = "No Matching Pattern"
    investigation_status = "Review Completed"

# Step 8: Generate summary
summary = pd.DataFrame([{
    "username": TARGET_USERNAME,
    "source_ip": TARGET_IP,
    "failed_login_count": failed_count,
    "successful_login_count": successful_count,
    "investigation_result": investigation_result,
    "investigation_status": investigation_status,
    "recommendation": (
        "Verify whether the successful login was legitimate "
        "and review additional authentication records."
    )
}])

print("\n--- INVESTIGATION SUMMARY ---")

print(summary.to_string(index=False))

# Step 9: Save investigation evidence
os.makedirs("reports", exist_ok=True)

evidence.to_csv(
    "reports/investigation_evidence.csv",
    index=False
)

summary.to_csv(
    "reports/investigation_summary.csv",
    index=False
)

print("\n======================================")
print("Investigation Completed")
print("Evidence: reports/investigation_evidence.csv")
print("Summary: reports/investigation_summary.csv")
print("======================================")