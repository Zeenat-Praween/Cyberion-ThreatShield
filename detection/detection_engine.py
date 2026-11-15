import pandas as pd
import os

# Step 1: Load security logs
data = pd.read_csv("data/sample_logs.csv")

print("\n================================")
print("   CYBERION THREATSHIELD")
print("   THREAT DETECTION ENGINE")
print("================================")

# Step 2: Filter failed login attempts
failed_logins = data[
    (data["event_type"] == "Login") &
    (data["status"] == "Failed")
]

# Step 3: Count failed attempts
suspicious_activity = (
    failed_logins
    .groupby(["username", "source_ip"])
    .size()
    .reset_index(name="failed_attempts")
)

# Step 4: Define detection threshold
THRESHOLD = 3

# Step 5: Identify suspicious activities
alerts = suspicious_activity[
    suspicious_activity["failed_attempts"] >= THRESHOLD
].copy()

# Step 6: Generate alert details
if not alerts.empty:

    alerts["alert_type"] = "Multiple Failed Login Attempts"
    alerts["severity"] = "High"
    alerts["status"] = "Under Investigation"

    print("\n[!] SUSPICIOUS ACTIVITIES DETECTED")

    for _, row in alerts.iterrows():

        print("\n--------------------------------")
        print("ALERT GENERATED")
        print("Username:", row["username"])
        print("Source IP:", row["source_ip"])
        print("Failed Attempts:", row["failed_attempts"])
        print("Severity:", row["severity"])
        print("Status:", row["status"])

else:

    print("\nNo suspicious activities detected.")

# Step 7: Save alerts
os.makedirs("reports", exist_ok=True)

alerts.to_csv(
    "reports/detected_events.csv",
    index=False
)

print("\n================================")
print("Detection Analysis Completed")
print("Alerts saved in reports folder")
print("================================")