import pandas as pd
import os

# Step 1: Load security logs
data = pd.read_csv("data/sample_logs.csv")

print("\n====================================")
print("      CYBERION THREATSHIELD")
print("      IP ACTIVITY ANALYZER")
print("====================================")

# Step 2: Filter login events only
login_events = data[
    data["event_type"] == "Login"
].copy()

# Step 3: Group activities by source IP
ip_summary = (
    login_events
    .groupby("source_ip")
    .agg(
        total_events=("source_ip", "count"),
        failed_logins=("status", lambda x: (x == "Failed").sum()),
        successful_logins=("status", lambda x: (x == "Success").sum()),
        unique_users=("username", "nunique")
    )
    .reset_index()
)

# Step 4: Identify IPs needing investigation
ip_summary["investigation_status"] = ip_summary.apply(
    lambda row: "Needs Investigation"
    if row["failed_logins"] >= 3
    else "Normal Review",
    axis=1
)

# Step 5: Display results
print("\n--- IP ACTIVITY SUMMARY ---")

print(ip_summary.to_string(index=False))

# Step 6: Save report
os.makedirs("reports", exist_ok=True)

ip_summary.to_csv(
    "reports/ip_activity_summary.csv",
    index=False
)

print("\n====================================")
print("IP Analysis Completed Successfully")
print("Report saved: reports/ip_activity_summary.csv")
print("====================================")