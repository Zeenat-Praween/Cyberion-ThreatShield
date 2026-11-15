import pandas as pd
import os

# Step 1: Load security logs
data = pd.read_csv("data/sample_logs.csv")

print("\n======================================")
print("       CYBERION THREATSHIELD")
print("       UNUSUAL LOGIN DETECTOR")
print("======================================")

# Step 2: Filter successful login events
successful_logins = data[
    (data["event_type"] == "Login") &
    (data["status"] == "Success")
].copy()

# Step 3: Group successful logins by username
user_activity = (
    successful_logins
    .groupby("username")
    .agg(
        total_successful_logins=("username", "count"),
        unique_source_ips=("source_ip", "nunique"),
        source_ips=("source_ip", lambda x: ", ".join(sorted(x.unique())))
    )
    .reset_index()
)

# Step 4: Define detection threshold
IP_THRESHOLD = 2

# Step 5: Identify unusual login activity
suspicious_logins = user_activity[
    user_activity["unique_source_ips"] >= IP_THRESHOLD
].copy()

# Step 6: Add alert information
if not suspicious_logins.empty:

    suspicious_logins["alert_type"] = (
        "Successful Logins From Multiple IPs"
    )

    suspicious_logins["severity"] = "Medium"

    suspicious_logins["investigation_status"] = (
        "Needs Investigation"
    )

# Step 7: Display results
print("\n--- LOGIN ACTIVITY SUMMARY ---")

print(user_activity.to_string(index=False))

print("\n--- UNUSUAL LOGIN ALERTS ---")

if not suspicious_logins.empty:

    print(suspicious_logins.to_string(index=False))

else:

    print("No unusual login activity detected.")

# Step 8: Save report
os.makedirs("reports", exist_ok=True)

suspicious_logins.to_csv(
    "reports/unusual_login_alerts.csv",
    index=False
)

print("\n======================================")
print("Unusual Login Analysis Completed")
print("Report saved: reports/unusual_login_alerts.csv")
print("======================================")