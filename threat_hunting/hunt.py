import pandas as pd
import os

# Step 1: Load security logs
data = pd.read_csv("data/sample_logs.csv")

print("\n======================================")
print("       CYBERION THREATSHIELD")
print("       THREAT HUNTING MODULE")
print("======================================")

# Step 2: Convert timestamp
data["timestamp"] = pd.to_datetime(data["timestamp"])

# Step 3: Separate failed and successful logins
failed = data[
    (data["event_type"] == "Login") &
    (data["status"] == "Failed")
]

successful = data[
    (data["event_type"] == "Login") &
    (data["status"] == "Success")
]

# Step 4: Define hunting parameters
TIME_WINDOW = 30
THRESHOLD = 3

hunt_findings = []

# Step 5: Investigate each successful login
for _, success in successful.iterrows():

    username = success["username"]
    ip = success["source_ip"]
    success_time = success["timestamp"]

    start_time = success_time - pd.Timedelta(
        minutes=TIME_WINDOW
    )

    # Find previous failed logins
    previous_failures = failed[
        (failed["username"] == username) &
        (failed["source_ip"] == ip) &
        (failed["timestamp"] >= start_time) &
        (failed["timestamp"] < success_time)
    ]

    # Step 6: Check hunting hypothesis
    if len(previous_failures) >= THRESHOLD:

        hunt_findings.append({
            "username": username,
            "source_ip": ip,
            "failed_attempts": len(previous_failures),
            "successful_login_time": success_time,
            "time_window_minutes": TIME_WINDOW,
            "finding": "Failed Logins Followed By Success",
            "severity": "High",
            "investigation_status": "Needs Investigation"
        })

# Step 7: Display findings
findings_df = pd.DataFrame(hunt_findings)

print("\n--- THREAT HUNTING RESULTS ---")

if not findings_df.empty:

    print(findings_df.to_string(index=False))

else:

    print("No matching activity found.")

# Step 8: Save hunting report
os.makedirs("reports", exist_ok=True)

findings_df.to_csv(
    "reports/hunt_findings.csv",
    index=False
)

print("\n======================================")
print("Threat Hunting Completed")
print("Report: reports/hunt_findings.csv")
print("======================================")