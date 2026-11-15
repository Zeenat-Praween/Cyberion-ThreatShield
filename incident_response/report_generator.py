import pandas as pd
import os
from datetime import datetime

# ==========================================
# CYBERION THREATSHIELD
# INCIDENT REPORT GENERATOR
# ==========================================

print("\n======================================")
print("       CYBERION THREATSHIELD")
print("       INCIDENT REPORT GENERATOR")
print("======================================")


# Step 1: Load investigation data

investigation_file = "reports/investigation_summary.csv"

classification_file = "reports/incident_classification.csv"

investigation = pd.read_csv(investigation_file)

classification = pd.read_csv(classification_file)


# Step 2: Extract investigation details

username = investigation.loc[0, "username"]

source_ip = investigation.loc[0, "source_ip"]

failed_count = investigation.loc[0, "failed_login_count"]

successful_count = investigation.loc[0, "successful_login_count"]

investigation_result = investigation.loc[0, "investigation_result"]

investigation_status = investigation.loc[0, "investigation_status"]


# Step 3: Extract classification details

incident_id = classification.loc[0, "incident_id"]

incident_category = classification.loc[0, "incident_category"]

severity = classification.loc[0, "severity"]

confidence = classification.loc[0, "confidence"]

status = classification.loc[0, "status"]

recommendation = classification.loc[0, "recommendation"]


# Step 4: Generate report timestamp

report_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# Step 5: Prepare report content

report = f"""
========================================================
              CYBERION THREATSHIELD
          INCIDENT INVESTIGATION REPORT
========================================================

1. REPORT INFORMATION

Incident ID       : {incident_id}
Report Generated  : {report_time}
Project Name      : Cyberion ThreatShield
Report Type       : Security Incident Investigation


2. INCIDENT DETAILS

Username          : {username}
Source IP         : {source_ip}
Incident Category : {incident_category}
Severity          : {severity}
Confidence        : {confidence}
Incident Status   : {status}


3. AUTHENTICATION ACTIVITY

Failed Login Attempts     : {failed_count}
Successful Login Attempts : {successful_count}


4. INVESTIGATION FINDINGS

Investigation Result : {investigation_result}

Investigation Status : {investigation_status}

The investigation identified a suspicious authentication
pattern involving multiple failed login attempts followed
by a successful login.

This pattern requires further verification and does not
independently confirm unauthorized access.


5. RECOMMENDED ACTIONS

{recommendation}

Additional Recommendations:

- Review related authentication records.
- Verify the activity with the authorized account owner.
- Check for other unusual account activity.
- Document all investigation findings.
- Follow the organization's incident response procedures.


6. CONCLUSION

Cyberion ThreatShield identified a suspicious
authentication pattern and classified it as an
authentication anomaly.

The incident remains under investigation.

Further verification by an authorized security analyst
is required before confirming whether unauthorized
access occurred.


7. DISCLAIMER

This report is generated using synthetic security logs
in a controlled cybersecurity learning environment.

Detection findings are indicators for investigation,
not proof of a confirmed security breach.

========================================================
                 END OF REPORT
========================================================
"""


# Step 6: Create reports folder if needed

os.makedirs("reports", exist_ok=True)


# Step 7: Save report as a text file

report_path = "reports/incident_investigation_report.txt"

with open(report_path, "w", encoding="utf-8") as file:

    file.write(report)


# Step 8: Display completion message

print("\nIncident Report Generated Successfully!")

print("\nIncident ID:", incident_id)

print("Incident Category:", incident_category)

print("Severity:", severity)

print("Status:", status)

print("\nReport Saved At:")

print(report_path)

print("\n======================================")
print("       REPORT GENERATION COMPLETE")
print("======================================")