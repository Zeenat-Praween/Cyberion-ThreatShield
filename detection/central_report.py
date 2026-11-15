import pandas as pd
import os

print("\n======================================")
print("       CYBERION THREATSHIELD")
print("       CENTRAL FINDINGS REPORT")
print("======================================")

findings = []

# Step 1: Read basic detection report
basic_file = "reports/detected_events.csv"

if os.path.exists(basic_file):

    basic_data = pd.read_csv(basic_file)

    for _, row in basic_data.iterrows():

        findings.append({
            "detection_source": "Basic Detection",
            "finding_type": row["alert_type"],
            "username": row["username"],
            "source_ip": row["source_ip"],
            "event_count": row["failed_attempts"],
            "severity": row["severity"],
            "investigation_status": row["status"],
            "recommendation": "Investigate repeated failed login attempts"
        })


# Step 2: Read time-based detection report
time_file = "reports/time_based_alerts.csv"

if os.path.exists(time_file):

    time_data = pd.read_csv(time_file)

    for _, row in time_data.iterrows():

        findings.append({
            "detection_source": "Time-Based Detection",
            "finding_type": row["alert_type"],
            "username": row["username"],
            "source_ip": row["source_ip"],
            "event_count": row["failed_attempts"],
            "severity": row["severity"],
            "investigation_status": row["status"],
            "recommendation": "Investigate repeated login failures within a short time"
        })


# Step 3: Read IP activity report
ip_file = "reports/ip_activity_summary.csv"

if os.path.exists(ip_file):

    ip_data = pd.read_csv(ip_file)

    suspicious_ips = ip_data[
        ip_data["investigation_status"] == "Needs Investigation"
    ]

    for _, row in suspicious_ips.iterrows():

        findings.append({
            "detection_source": "IP Activity Analysis",
            "finding_type": "High Failed Login Activity",
            "username": "Multiple or Unknown",
            "source_ip": row["source_ip"],
            "event_count": row["failed_logins"],
            "severity": "Medium",
            "investigation_status": "Needs Investigation",
            "recommendation": "Review login activity and verify whether it is legitimate"
        })


# Step 4: Create central report
findings_df = pd.DataFrame(findings)

print("\n--- CENTRAL SECURITY FINDINGS ---")

if not findings_df.empty:

    print(findings_df.to_string(index=False))

else:

    print("No findings available. Run detection scripts first.")


# Step 5: Save central report
os.makedirs("reports", exist_ok=True)

findings_df.to_csv(
    "reports/security_findings.csv",
    index=False
)

# Step 6: Display summary
print("\n--- FINDINGS SUMMARY ---")

print("Total Findings:", len(findings_df))

if not findings_df.empty:

    print("\nFindings by Severity:")
    print(findings_df["severity"].value_counts())

    print("\nFindings by Detection Source:")
    print(findings_df["detection_source"].value_counts())


print("\n======================================")
print("Central Report Generated Successfully")
print("Saved: reports/security_findings.csv")
print("======================================")