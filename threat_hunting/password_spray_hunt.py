import pandas as pd
import os

# Step 1: Load security logs
data = pd.read_csv("data/sample_logs.csv")

data["timestamp"] = pd.to_datetime(data["timestamp"])

print("\n======================================")
print("       CYBERION THREATSHIELD")
print("       PASSWORD SPRAYING HUNT")
print("======================================")

# Step 2: Select failed login events
failed_logins = data[
    (data["event_type"] == "Login") &
    (data["status"] == "Failed")
].copy()

# Step 3: Sort events by timestamp
failed_logins = failed_logins.sort_values("timestamp")

# Step 4: Define hunting parameters
TIME_WINDOW = 15
USER_THRESHOLD = 3

hunt_findings = []

# Step 5: Analyse each source IP
for ip, group in failed_logins.groupby("source_ip"):

    for _, row in group.iterrows():

        current_time = row["timestamp"]

        start_time = current_time - pd.Timedelta(
            minutes=TIME_WINDOW
        )

        recent_events = group[
            (group["timestamp"] >= start_time) &
            (group["timestamp"] <= current_time)
        ]

        unique_users = recent_events["username"].nunique()

        # Step 6: Check hunting hypothesis
        if unique_users >= USER_THRESHOLD:

            hunt_findings.append({
                "source_ip": ip,
                "unique_usernames": unique_users,
                "usernames": ", ".join(
                    sorted(recent_events["username"].unique())
                ),
                "failed_attempts": len(recent_events),
                "time_window_minutes": TIME_WINDOW,
                "finding": "Multiple Accounts With Failed Logins",
                "severity": "High",
                "investigation_status": "Needs Investigation"
            })

            break

# Step 7: Generate hunting report
findings_df = pd.DataFrame(hunt_findings)

print("\n--- PASSWORD SPRAYING HUNT RESULTS ---")

if not findings_df.empty:

    print(findings_df.to_string(index=False))

else:

    print("No matching activity found.")

# Step 8: Save report
os.makedirs("reports", exist_ok=True)

findings_df.to_csv(
    "reports/password_spray_findings.csv",
    index=False
)

print("\n======================================")
print("Password Spraying Hunt Completed")
print("Report: reports/password_spray_findings.csv")
print("======================================")