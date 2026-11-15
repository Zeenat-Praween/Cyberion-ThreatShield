import streamlit as st
import pandas as pd
import os
import plotly.express as px


# ==========================================
# PAGE CONFIGURATION
# ==========================================

st.set_page_config(
    page_title="Cyberion ThreatShield",
    page_icon="🛡️",
    layout="wide"
)


# ==========================================
# TITLE
# ==========================================

st.title("🛡️ Cyberion ThreatShield")

st.subheader(
    "Detection Engineering & Threat Hunting Platform"
)

st.write(
    "Interactive security monitoring and "
    "incident investigation dashboard."
)

st.divider()


# ==========================================
# LOAD REPORT FUNCTION
# ==========================================

def load_report(file_path):

    if os.path.exists(file_path):
        return pd.read_csv(file_path)

    return pd.DataFrame()


# ==========================================
# LOAD DATA
# ==========================================

classification = load_report(
    "reports/incident_classification.csv"
)

investigation = load_report(
    "reports/investigation_summary.csv"
)

findings = load_report(
    "reports/security_findings.csv"
)

password_spray = load_report(
    "reports/password_spray_findings.csv"
)

hunt = load_report(
    "reports/hunt_findings.csv"
)


# ==========================================
# SIDEBAR FILTERS
# ==========================================

st.sidebar.title("🔎 Security Filters")

st.sidebar.write(
    "Filter incidents using the available fields."
)

filtered_classification = classification.copy()


# Severity Filter

if (
    not filtered_classification.empty
    and "severity" in filtered_classification.columns
):

    severity_options = ["All"] + sorted(
        filtered_classification["severity"]
        .dropna()
        .unique()
        .tolist()
    )

    selected_severity = st.sidebar.selectbox(
        "Select Severity",
        severity_options
    )

    if selected_severity != "All":

        filtered_classification = (
            filtered_classification[
                filtered_classification["severity"]
                == selected_severity
            ]
        )


# Incident Category Filter

if (
    not filtered_classification.empty
    and "incident_category" in filtered_classification.columns
):

    category_options = ["All"] + sorted(
        classification["incident_category"]
        .dropna()
        .unique()
        .tolist()
    )

    selected_category = st.sidebar.selectbox(
        "Select Incident Category",
        category_options
    )

    if selected_category != "All":

        filtered_classification = (
            filtered_classification[
                filtered_classification["incident_category"]
                == selected_category
            ]
        )


# Incident Status Filter

if (
    not filtered_classification.empty
    and "status" in filtered_classification.columns
):

    status_options = ["All"] + sorted(
        classification["status"]
        .dropna()
        .unique()
        .tolist()
    )

    selected_status = st.sidebar.selectbox(
        "Select Incident Status",
        status_options
    )

    if selected_status != "All":

        filtered_classification = (
            filtered_classification[
                filtered_classification["status"]
                == selected_status
            ]
        )


# Username and IP Search

search_query = st.sidebar.text_input(
    "Search Username or Source IP"
)

if search_query:

    search_mask = filtered_classification.astype(
        str
    ).apply(
        lambda column: column.str.contains(
            search_query,
            case=False,
            na=False
        )
    ).any(axis=1)

    filtered_classification = (
        filtered_classification[search_mask]
    )


# ==========================================
# DASHBOARD METRICS
# ==========================================

st.header("📊 Security Overview")

total_incidents = len(filtered_classification)

high_severity = 0

if not filtered_classification.empty:

    high_severity = (
        filtered_classification["severity"] == "High"
    ).sum()


failed_logins = 0
successful_logins = 0

if not investigation.empty:

    failed_logins = int(
        investigation["failed_login_count"].sum()
    )

    successful_logins = int(
        investigation["successful_login_count"].sum()
    )


col1, col2, col3, col4 = st.columns(4)

col1.metric(
    "Filtered Incidents",
    total_incidents
)

col2.metric(
    "High Severity",
    high_severity
)

col3.metric(
    "Failed Logins",
    failed_logins
)

col4.metric(
    "Successful Logins",
    successful_logins
)


st.divider()


# ==========================================
# FILTERED INCIDENT TABLE
# ==========================================

st.header("🚨 Incident Classification")

if not filtered_classification.empty:

    st.dataframe(
        filtered_classification,
        use_container_width=True
    )

else:

    st.warning(
        "No incidents match the selected filters."
    )


# ==========================================
# SEVERITY DISTRIBUTION
# ==========================================

st.header("📈 Incident Severity Distribution")

if not filtered_classification.empty:

    severity_data = (
        filtered_classification["severity"]
        .value_counts()
        .reset_index()
    )

    severity_data.columns = [
        "Severity",
        "Count"
    ]

    fig = px.bar(
        severity_data,
        x="Severity",
        y="Count",
        text="Count",
        title="Filtered Incidents by Severity"
    )

    st.plotly_chart(
        fig,
        use_container_width=True
    )

else:

    st.info(
        "No severity data available for the selected filters."
    )


# ==========================================
# INVESTIGATION SUMMARY
# ==========================================

st.header("🔍 Investigation Summary")

if not investigation.empty:

    st.dataframe(
        investigation,
        use_container_width=True
    )

else:

    st.info("Investigation report is not available.")


# ==========================================
# THREAT HUNTING
# ==========================================

st.header("🕵️ Threat Hunting Findings")

tab1, tab2 = st.tabs([
    "Password Spraying Hunt",
    "Authentication Hunt"
])

with tab1:

    if not password_spray.empty:

        st.dataframe(
            password_spray,
            use_container_width=True
        )

    else:

        st.info("No password-spraying findings available.")


with tab2:

    if not hunt.empty:

        st.dataframe(
            hunt,
            use_container_width=True
        )

    else:

        st.info("No authentication hunt findings available.")


# ==========================================
# CENTRAL SECURITY FINDINGS
# ==========================================

st.header("📋 Central Security Findings")

if not findings.empty:

    st.dataframe(
        findings,
        use_container_width=True
    )

else:

    st.info("No central findings available.")

# ==========================================
# SECURITY EVENT TIMELINE
# ==========================================

st.header("🕒 Security Event Timeline")

# Load original security logs

event_logs = load_report(
    "data/sample_logs.csv"
)

if not event_logs.empty:

    # Convert timestamp into datetime format

    event_logs["timestamp"] = pd.to_datetime(
        event_logs["timestamp"],
        errors="coerce"
    )

    # Remove records with invalid timestamps

    event_logs = event_logs.dropna(
        subset=["timestamp"]
    )

    if not event_logs.empty:

        # Event type filter

        event_types = ["All"] + sorted(
            event_logs["event_type"]
            .dropna()
            .unique()
            .tolist()
        )

        selected_event = st.selectbox(
            "Filter Events",
            event_types
        )

        if selected_event != "All":

            timeline_data = event_logs[
                event_logs["event_type"] == selected_event
            ]

        else:

            timeline_data = event_logs.copy()

        # Display event timeline

        if not timeline_data.empty:

            fig = px.scatter(
                timeline_data,
                x="timestamp",
                y="username",
                color="status",
                symbol="event_type",
                hover_data=[
                    "source_ip",
                    "device",
                    "event_type"
                ],
                title="Security Events Over Time"
            )

            fig.update_layout(
                xaxis_title="Event Timestamp",
                yaxis_title="Username"
            )

            st.plotly_chart(
                fig,
                use_container_width=True
            )

            # Display timeline records

            st.subheader("Timeline Event Records")

            st.dataframe(
                timeline_data.sort_values("timestamp"),
                use_container_width=True
            )

        else:

            st.info("No matching events found.")

    else:

        st.warning("No valid timestamps found.")

else:

    st.warning("Security log dataset is unavailable.")

    # ==========================================
# DETECTION RULE MANAGEMENT
# ==========================================

import yaml
import glob

st.header("🛡️ Detection Rule Management")

st.write(
    "Review available Sigma detection rules "
    "and their security information."
)

# Find all YAML rule files

rule_files = glob.glob("rules/*.yml")

if rule_files:

    rules_data = []

    for rule_file in rule_files:

        try:

            with open(
                rule_file,
                "r",
                encoding="utf-8"
            ) as file:

                rule = yaml.safe_load(file)

            if not isinstance(rule, dict):
                st.warning(
                    f"Invalid YAML structure: {rule_file}"
                )
                continue

            rules_data.append({

                "File": os.path.basename(rule_file),

                "Title": rule.get(
                    "title",
                    "Not Available"
                ),

                "Rule ID": rule.get(
                    "id",
                    "Not Available"
                ),

                "Description": rule.get(
                    "description",
                    "Not Available"
                ),

                "Status": rule.get(
                    "status",
                    "Not Available"
                ),

                "Severity": rule.get(
                    "level",
                    "Not Available"
                ),

                "MITRE Tags": ", ".join(
                    rule.get("tags", [])
                )

            })

        except Exception as error:

            st.warning(
                f"Could not read {rule_file}: {error}"
            )

    # Display rule information

    if rules_data:

        rules_df = pd.DataFrame(rules_data)

        st.metric(
            "Available Detection Rules",
            len(rules_df)
        )

        st.dataframe(
            rules_df,
            use_container_width=True
        )

        # Individual rule details

        st.subheader("Rule Details")

        selected_rule = st.selectbox(
            "Select a Detection Rule",
            rules_df["File"].tolist()
        )

        selected_file = os.path.join(
            "rules",
            selected_rule
        )

        with open(
            selected_file,
            "r",
            encoding="utf-8"
        ) as file:

            selected_data = yaml.safe_load(file)

        st.write(
            "###",
            selected_data.get(
                "title",
                "Untitled Rule"
            )
        )

        st.write(
            "**Description:**",
            selected_data.get(
                "description",
                "Not Available"
            )
        )

        st.write(
            "**Severity:**",
            selected_data.get(
                "level",
                "Not Available"
            )
        )

        st.write("**False Positive Possibilities:**")

        false_positives = selected_data.get(
            "falsepositives",
            []
        )

        if false_positives:

            for item in false_positives:

                st.write("- " + str(item))

        else:

            st.write("No information available.")

        st.write("**MITRE ATT&CK Tags:**")

        for tag in selected_data.get("tags", []):

            st.code(tag)

    else:

        st.warning(
            "No valid detection rules could be loaded."
        )

else:

    st.warning(
        "No YAML detection rules found in the rules folder."
    )

   # ==========================================
# MITRE ATT&CK DETECTION COVERAGE
# ==========================================

st.header("🎯 MITRE ATT&CK Detection Coverage")

st.write(
    "Monitor the implementation status of selected "
    "MITRE ATT&CK techniques in Cyberion ThreatShield."
)

coverage = load_report(
    "reports/detection_coverage.csv"
)

if not coverage.empty:

    st.subheader("Detection Coverage Matrix")

    st.dataframe(
        coverage,
        use_container_width=True
    )

    # Read actual coverage column

    if "coverage" in coverage.columns:

        coverage_status = (
            coverage["coverage"]
            .astype(str)
            .str.strip()
            .str.lower()
        )

        covered_count = (
            coverage_status == "covered"
        ).sum()

        total_count = len(coverage)

        gap_count = (
            coverage_status == "gap"
        ).sum()

        coverage_percentage = (
            covered_count / total_count * 100
            if total_count > 0 else 0
        )

        # Display metrics

        col1, col2, col3 = st.columns(3)

        col1.metric(
            "Selected Techniques",
            total_count
        )

        col2.metric(
            "Covered Techniques",
            covered_count
        )

        col3.metric(
            "Coverage Percentage",
            f"{coverage_percentage:.1f}%"
        )

        # Coverage chart

        chart_data = pd.DataFrame({

            "Coverage Status": [
                "Covered",
                "Gap"
            ],

            "Count": [
                covered_count,
                gap_count
            ]

        })

        fig = px.pie(
            chart_data,
            names="Coverage Status",
            values="Count",
            title="MITRE ATT&CK Detection Coverage",
            hole=0.4
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )

        # Display coverage gaps

        st.subheader("Detection Coverage Gaps")

        gaps = coverage[
            coverage_status == "gap"
        ]

        if not gaps.empty:

            st.warning(
                f"{len(gaps)} selected techniques "
                "are not currently covered."
            )

            st.dataframe(
                gaps,
                use_container_width=True
            )

        else:

            st.success(
                "All selected techniques are covered."
            )

    else:

        st.error(
            "The coverage column is missing from the CSV."
        )

else:

    st.warning(
        "Detection coverage report is unavailable."
    )

    # ==========================================
# DAY 26 - SECURITY REPORT DOWNLOAD CENTER
# ==========================================

st.header("📥 Security Report Download Center")

st.write(
    "Download security analysis, incident investigation, "
    "MITRE ATT&CK mapping, and detection coverage reports."
)

st.subheader("Available Reports")

# Report 1: Integrated Security Report

report_path = "reports/integrated_security_report.csv"

if os.path.exists(report_path):

    with open(report_path, "rb") as file:
        report_data = file.read()

    st.download_button(
        label="Download Integrated Security Report",
        data=report_data,
        file_name="integrated_security_report.csv",
        mime="text/csv"
    )

else:
    st.warning("Integrated Security Report is unavailable.")


# Report 2: MITRE ATT&CK Mapping

report_path = "reports/mitre_attack_mapping.csv"

if os.path.exists(report_path):

    with open(report_path, "rb") as file:
        report_data = file.read()

    st.download_button(
        label="Download MITRE ATT&CK Mapping",
        data=report_data,
        file_name="mitre_attack_mapping.csv",
        mime="text/csv"
    )

else:
    st.warning("MITRE ATT&CK Mapping report is unavailable.")


# Report 3: Incident Investigation Report

report_path = "reports/incident_investigation_report.txt"

if os.path.exists(report_path):

    with open(report_path, "rb") as file:
        report_data = file.read()

    st.download_button(
        label="Download Incident Investigation Report",
        data=report_data,
        file_name="incident_investigation_report.txt",
        mime="text/plain"
    )

else:
    st.warning("Incident Investigation Report is unavailable.")


# Report 4: Detection Coverage Report

report_path = "reports/detection_coverage.csv"

if os.path.exists(report_path):

    with open(report_path, "rb") as file:
        report_data = file.read()

    st.download_button(
        label="Download Detection Coverage Report",
        data=report_data,
        file_name="detection_coverage.csv",
        mime="text/csv"
    )

else:
    st.warning("Detection Coverage Report is unavailable.")

    # ==========================================
# DAY 28 - SECURITY LOG QUALITY DASHBOARD
# ==========================================

st.header("🔍 Security Log Quality Monitoring")

st.write(
    "Monitor the quality and reliability of security logs "
    "used by Cyberion ThreatShield."
)

quality_report = load_report(
    "reports/log_quality_report.csv"
)

if not quality_report.empty:

    st.subheader("Log Quality Validation Results")

    # Display complete quality report

    st.dataframe(
        quality_report,
        use_container_width=True
    )

    # Calculate validation metrics

    total_checks = len(quality_report)

    passed_checks = (
        quality_report["Status"]
        .astype(str)
        .str.upper() == "PASS"
    ).sum()

    failed_checks = (
        quality_report["Status"]
        .astype(str)
        .str.upper() == "FAIL"
    ).sum()

    warning_checks = (
        quality_report["Status"]
        .astype(str)
        .str.upper() == "WARNING"
    ).sum()

    # Display metrics

    col1, col2, col3, col4 = st.columns(4)

    col1.metric(
        "Total Checks",
        total_checks
    )

    col2.metric(
        "Passed Checks",
        passed_checks
    )

    col3.metric(
        "Failed Checks",
        failed_checks
    )

    col4.metric(
        "Warnings",
        warning_checks
    )

    # Overall quality status

    st.subheader("Overall Data Quality Status")

    if failed_checks == 0 and warning_checks == 0:

        st.success(
            "All security log quality checks passed."
        )

    elif failed_checks > 0:

        st.error(
            "Critical data quality issues require attention."
        )

    else:

        st.warning(
            "Some data quality warnings require review."
        )

    # Display issue details

    st.subheader("Data Quality Findings")

    issues = quality_report[
        quality_report["Status"].astype(str).str.upper() != "PASS"
    ]

    if not issues.empty:

        st.dataframe(
            issues,
            use_container_width=True
        )

    else:

        st.info(
            "No data quality issues detected."
        )

else:

    st.warning(
        "Log quality report is unavailable. "
        "Run python utils/log_quality_checker.py first."
    )

    # ==========================================
# DAY 30 - DETECTION VALIDATION DASHBOARD
# ==========================================

st.header("🧪 Detection Rule Validation")

st.write(
    "Monitor the testing and validation results "
    "of Cyberion ThreatShield detection rules."
)

validation_report = load_report(
    "reports/rule_validation_report.csv"
)

if not validation_report.empty:

    st.subheader("Validation Test Results")

    st.dataframe(
        validation_report,
        use_container_width=True
    )

    # Calculate validation metrics

    total_tests = len(validation_report)

    passed_tests = (
        validation_report["Result"]
        .astype(str)
        .str.upper() == "PASS"
    ).sum()

    failed_tests = (
        validation_report["Result"]
        .astype(str)
        .str.upper() == "FAIL"
    ).sum()

    # Display metrics

    col1, col2, col3 = st.columns(3)

    col1.metric(
        "Total Tests",
        total_tests
    )

    col2.metric(
        "Passed Tests",
        passed_tests
    )

    col3.metric(
        "Failed Tests",
        failed_tests
    )

    # Overall validation status

    st.subheader("Overall Validation Status")

    if failed_tests == 0:

        st.success(
            "All detection validation tests passed."
        )

    else:

        st.error(
            f"{failed_tests} validation tests failed. "
            "Review the detection logic."
        )

    # Validation chart

    chart_data = pd.DataFrame({
        "Result": ["Passed", "Failed"],
        "Count": [passed_tests, failed_tests]
    })

    fig = px.bar(
        chart_data,
        x="Result",
        y="Count",
        color="Result",
        title="Detection Validation Results",
        text="Count"
    )

    st.plotly_chart(
        fig,
        use_container_width=True
    )

else:

    st.warning(
        "Validation report unavailable. "
        "Run python detection/rule_validation.py first."
    )

    # ==========================================
# DAY 32 - ALERT INVESTIGATION & ANALYST NOTES
# ==========================================

st.header("📝 Alert Investigation & Analyst Notes")

st.write(
    "Record investigation observations, "
    "track incident status, and maintain analyst notes."
)

# CSV file location
analyst_notes_path = "reports/analyst_notes.csv"

# Define columns
note_columns = [
    "Timestamp",
    "Incident ID",
    "Incident Category",
    "Source IP",
    "Investigation Status",
    "Analyst Notes"
]

# Load previously saved notes
if os.path.exists(analyst_notes_path):

    analyst_notes = pd.read_csv(analyst_notes_path)

else:

    analyst_notes = pd.DataFrame(columns=note_columns)


# ==========================================
# INVESTIGATION NOTE FORM
# ==========================================

st.subheader("Add Investigation Record")

with st.form("analyst_notes_form"):

    incident_id = st.text_input(
        "Incident ID",
        placeholder="Example: INC-001"
    )

    incident_category = st.selectbox(
        "Incident Category",
        [
            "Brute Force Indicator",
            "Password Spraying Indicator",
            "Suspicious Login Activity",
            "Unusual Login Activity",
            "Other"
        ]
    )

    source_ip = st.text_input(
        "Source IP",
        placeholder="Example: 192.168.1.20"
    )

    investigation_status = st.selectbox(
        "Investigation Status",
        [
            "Open",
            "Under Investigation",
            "Escalated",
            "Resolved"
        ]
    )

    analyst_observations = st.text_area(
        "Analyst Observations / Notes",
        placeholder="Write your investigation observations here..."
    )

    submit_note = st.form_submit_button(
        "Save Investigation Note"
    )


# ==========================================
# SAVE INVESTIGATION RECORD
# ==========================================

if submit_note:

    if not incident_id.strip():

        st.warning("Please enter an Incident ID.")

    elif not analyst_observations.strip():

        st.warning("Please enter investigation notes.")

    else:

        new_note = pd.DataFrame([{
            "Timestamp": pd.Timestamp.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            "Incident ID": incident_id.strip(),
            "Incident Category": incident_category,
            "Source IP": source_ip.strip(),
            "Investigation Status": investigation_status,
            "Analyst Notes": analyst_observations.strip()
        }])

        # Add new record to existing records
        analyst_notes = pd.concat(
            [analyst_notes, new_note],
            ignore_index=True
        )

        # Save records
        os.makedirs("reports", exist_ok=True)

        analyst_notes.to_csv(
            analyst_notes_path,
            index=False
        )

        st.success(
            "Investigation note saved successfully!"
        )


# ==========================================
# DAY 32 - INVESTIGATION HISTORY
# DAY 33 - SEARCH AND FILTER
# ==========================================

st.subheader("Investigation History")

if not analyst_notes.empty:

    col1, col2 = st.columns(2)

    col1.metric(
        "Total Investigation Records",
        len(analyst_notes)
    )

    active_count = analyst_notes[
        "Investigation Status"
    ].isin(
        ["Open", "Under Investigation", "Escalated"]
    ).sum()

    col2.metric(
        "Active Investigation Records",
        active_count
    )

    # Search and Filter

    st.subheader("Search and Filter Investigations")

    status_options = [
        "All",
        "Open",
        "Under Investigation",
        "Escalated",
        "Resolved"
    ]

    selected_status = st.selectbox(
        "Filter by Investigation Status",
        status_options
    )

    search_incident = st.text_input(
        "Search by Incident ID",
        placeholder="Enter Incident ID"
    )

    filtered_notes = analyst_notes.copy()

    if selected_status != "All":

        filtered_notes = filtered_notes[
            filtered_notes["Investigation Status"]
            == selected_status
        ]

    if search_incident.strip():

        filtered_notes = filtered_notes[
            filtered_notes["Incident ID"]
            .astype(str)
            .str.contains(
                search_incident.strip(),
                case=False,
                na=False
            )
        ]

    st.write(
        f"Matching Investigation Records: {len(filtered_notes)}"
    )

    if not filtered_notes.empty:

        st.dataframe(
            filtered_notes,
            use_container_width=True
        )

    else:

        st.info("No matching investigation records found.")

else:

    st.info(
        "No investigation notes saved yet. "
        "Add your first investigation record above."
    )
# ==========================================
# FOOTER
# ==========================================

st.divider()

st.caption(
    "Cyberion ThreatShield | Security Monitoring Platform"
)

st.caption(
    "All alerts require verification by an authorized "
    "security analyst."
)