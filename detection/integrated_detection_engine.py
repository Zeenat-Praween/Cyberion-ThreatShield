import pandas as pd
import os

print("\n==========================================")
print("       CYBERION THREATSHIELD")
print("       INTEGRATED DETECTION ENGINE V2")
print("==========================================")

findings = []


# Function to add findings to the central list
def add_finding(source, finding_type, username,
                source_ip, event_count, severity,
                status, recommendation):

    findings.append({
        "detection_source": source,
        "finding_type": finding_type,
        "username": username,
        "source_ip": source_ip,
        "event_count": event_count,
        "severity": severity,
        "investigation_status": status,
        "recommendation": recommendation
    })


# Step 1: Load basic detection alerts
basic_file = "reports/detected_events.csv"

if os.path.exists(basic_file):

    data = pd.read_csv(basic_file)

    for _, row in data.iterrows():

        add_finding(
            "Basic Detection",
            row["alert_type"],
            row["username"],
            row["source_ip"],
            row["failed_attempts"],
            row["severity"],
            row["status"],
            "Investigate repeated failed login attempts"
        )


# Step 2: Load time-based alerts
time_file = "reports/time_based_alerts.csv"

if os.path.exists(time_file):

    data = pd.read_csv(time_file)

    for _, row in data.iterrows():

        add_finding(
            "Time-Based Detection",
            row["alert_type"],
            row["username"],
            row["source_ip"],
            row["failed_attempts"],
            row["severity"],
            row["status"],
            "Investigate repeated failures within 15 minutes"
        )


# Step 3: Load suspicious IP activity
ip_file = "reports/ip_activity_summary.csv"

if os.path.exists(ip_file):

    data = pd.read_csv(ip_file)

    suspicious_ips = data[
        data["investigation_status"] == "Needs Investigation"
    ]

    for _, row in suspicious_ips.iterrows():

        add_finding(
            "IP Activity Analysis",
            "High Failed Login Activity",
            "Multiple or Unknown",
            row["source_ip"],
            row["failed_logins"],
            "Medium",
            "Needs Investigation",
            "Review IP activity and verify login attempts"
        )


# Step 4: Load unusual login alerts
unusual_file = "reports/unusual_login_alerts.csv"

if os.path.exists(unusual_file):

    data = pd.read_csv(unusual_file)

    for _, row in data.iterrows():

        add_finding(
            "Unusual Login Detection",
            row["alert_type"],
            row["username"],
            row["source_ips"],
            row["total_successful_logins"],
            row["severity"],
            row["investigation_status"],
            "Verify whether logins from multiple IPs are legitimate"
        )


# Step 5: Create master report
master_report = pd.DataFrame(findings)

print("\n--- INTEGRATED SECURITY FINDINGS ---")

if not master_report.empty:

    master_report.insert(
        0,
        "alert_id",
        [f"CTS-{i:04d}" for i in range(1, len(master_report) + 1)]
    )

    print(master_report.to_string(index=False))

else:

    print("No detection findings available.")


# Step 6: Save master report
os.makedirs("reports", exist_ok=True)

master_report.to_csv(
    "reports/integrated_security_report.csv",
    index=False
)


# Step 7: Display summary
print("\n--- DETECTION SUMMARY ---")

print("Total Findings:", len(master_report))

if not master_report.empty:

    print("\nFindings by Severity:")
    print(master_report["severity"].value_counts())

    print("\nFindings by Detection Source:")
    print(master_report["detection_source"].value_counts())


print("\n==========================================")
print("INTEGRATED DETECTION ENGINE COMPLETED")
print("Report: reports/integrated_security_report.csv")
print("==========================================")