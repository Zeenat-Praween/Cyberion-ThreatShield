import pandas as pd
import os
import ipaddress

# Load security logs
file_path = "data/sample_logs.csv"

data = pd.read_csv(file_path)

print("\n========== SECURITY LOG QUALITY CHECK ==========")

# Required columns
required_columns = [
    "timestamp",
    "username",
    "source_ip",
    "event_type",
    "status",
    "device"
]

results = []

# Check 1: Required columns
missing_columns = [
    column for column in required_columns
    if column not in data.columns
]

results.append({
    "Check": "Required Columns",
    "Issue Count": len(missing_columns),
    "Status": "PASS" if not missing_columns else "FAIL",
    "Details": (
        "All required columns are available"
        if not missing_columns
        else ", ".join(missing_columns)
    )
})

# Check 2: Missing values
missing_values = int(data.isnull().sum().sum())

results.append({
    "Check": "Missing Values",
    "Issue Count": missing_values,
    "Status": "PASS" if missing_values == 0 else "WARNING",
    "Details": "Missing values found in dataset"
    if missing_values > 0 else "No missing values"
})

# Check 3: Duplicate records
duplicate_count = int(data.duplicated().sum())

results.append({
    "Check": "Duplicate Records",
    "Issue Count": duplicate_count,
    "Status": "PASS" if duplicate_count == 0 else "WARNING",
    "Details": "Duplicate records detected"
    if duplicate_count > 0 else "No duplicate records"
})

# Check 4: Timestamp validation
if "timestamp" in data.columns:

    timestamps = pd.to_datetime(
        data["timestamp"],
        errors="coerce"
    )

    invalid_timestamps = int(timestamps.isnull().sum())

    results.append({
        "Check": "Timestamp Validation",
        "Issue Count": invalid_timestamps,
        "Status": "PASS" if invalid_timestamps == 0 else "FAIL",
        "Details": "Invalid timestamps found"
        if invalid_timestamps > 0 else "All timestamps are valid"
    })

# Check 5: Login status validation
if "status" in data.columns:

    valid_statuses = ["Success", "Failed"]

    invalid_statuses = int(
        (~data["status"].isin(valid_statuses)).sum()
    )

    results.append({
        "Check": "Login Status Validation",
        "Issue Count": invalid_statuses,
        "Status": "PASS" if invalid_statuses == 0 else "WARNING",
        "Details": "Unexpected status values found"
        if invalid_statuses > 0 else "All status values are valid"
    })

# Check 6: IP address validation
if "source_ip" in data.columns:

    def validate_ip(value):
        try:
            ipaddress.ip_address(str(value))
            return True
        except ValueError:
            return False

    invalid_ips = int(
        (~data["source_ip"].apply(validate_ip)).sum()
    )

    results.append({
        "Check": "IP Address Validation",
        "Issue Count": invalid_ips,
        "Status": "PASS" if invalid_ips == 0 else "WARNING",
        "Details": "Invalid IP addresses found"
        if invalid_ips > 0 else "All IP addresses are valid"
    })

# Create quality report
quality_report = pd.DataFrame(results)

print("\nDATASET SUMMARY")
print("Total Records:", len(data))
print("Total Columns:", len(data.columns))

print("\nQUALITY CHECK RESULTS")
print(quality_report.to_string(index=False))

# Save report
os.makedirs("reports", exist_ok=True)

quality_report.to_csv(
    "reports/log_quality_report.csv",
    index=False
)

print("\nReport saved successfully:")
print("reports/log_quality_report.csv")