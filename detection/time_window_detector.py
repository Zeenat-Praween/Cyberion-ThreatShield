import pandas as pd
import os

# Step 1: Load security logs
data = pd.read_csv("data/sample_logs.csv")

print("\n====================================")
print("     CYBERION THREATSHIELD")
print("     TIME-BASED THREAT DETECTION")
print("====================================")

# Step 2: Convert timestamp into datetime
data["timestamp"] = pd.to_datetime(data["timestamp"])

# Step 3: Filter failed login events
failed_logins = data[
    (data["event_type"] == "Login") &
    (data["status"] == "Failed")
].copy()

# Step 4: Sort records by timestamp
failed_logins = failed_logins.sort_values("timestamp")

# Step 5: Define detection parameters
THRESHOLD = 3
TIME_WINDOW = 15

alerts = []

# Step 6: Analyse each username and IP
for (username, ip), group in failed_logins.groupby(
    ["username", "source_ip"]
):

    group = group.sort_values("timestamp")

    for _, row in group.iterrows():

        current_time = row["timestamp"]

        start_time = current_time - pd.Timedelta(
            minutes=TIME_WINDOW
        )

        recent_attempts = group[
            (group["timestamp"] >= start_time) &
            (group["timestamp"] <= current_time)
        ]

        if len(recent_attempts) >= THRESHOLD:

            alerts.append({
                "username": username,
                "source_ip": ip,
                "failed_attempts": len(recent_attempts),
                "first_attempt": recent_attempts["timestamp"].min(),
                "last_attempt": current_time,
                "time_window_minutes": TIME_WINDOW,
                "severity": "High",
                "alert_type": "Repeated Failed Login Attempts",
                "status": "Under Investigation"
            })

            break

# Step 7: Generate detection report
alerts_df = pd.DataFrame(alerts)

print("\n--- DETECTION RESULTS ---")

if not alerts_df.empty:

    for _, alert in alerts_df.iterrows():

        print("\n[SUSPICIOUS ACTIVITY DETECTED]")

        print("Username:", alert["username"])
        print("Source IP:", alert["source_ip"])
        print("Failed Attempts:", alert["failed_attempts"])
        print("Time Window:", alert["time_window_minutes"], "minutes")
        print("Severity:", alert["severity"])
        print("Status:", alert["status"])

else:

    print("No suspicious activity detected.")

# Step 8: Save report
os.makedirs("reports", exist_ok=True)

alerts_df.to_csv(
    "reports/time_based_alerts.csv",
    index=False
)

print("\nDetection completed successfully.")
print("Report saved: reports/time_based_alerts.csv")